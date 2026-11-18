"""Passive TLS-metadata parser for encrypted-OT inventory.

Much OT now rides TLS -- BACnet/SC (WebSocket over mutual TLS), OPC UA over TLS, web HMIs. The data is
encrypted, but the TLS *handshake* is cleartext, and it carries inventory-grade metadata: the ClientHello
SNI (the server hostname/endpoint the client is reaching) and, in TLS 1.2, the server's Certificate
message (subject/SAN -- and for BACnet/SC the device identity). This module parses that metadata without
decrypting anything and without transmitting.

Increment 1 (this file): recognise a TLS handshake record and extract the ClientHello SNI + the
negotiated-version/message type. The X.509 certificate parse (subject CN / SAN / BACnet-SC Device_UUID)
is the documented next increment.
"""
import re
from typing import Optional

_TLS_HANDSHAKE = 0x16
_HS_CLIENT_HELLO = 0x01
_HS_SERVER_HELLO = 0x02
_HS_CERTIFICATE = 0x0B
_EXT_SERVER_NAME = 0x0000
_TLS_VERSIONS = {0x0301: "1.0", 0x0302: "1.1", 0x0303: "1.2", 0x0304: "1.3"}
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _extract_sni(body: bytes) -> Optional[str]:
    """Walk a ClientHello body to its extensions and return the server_name (SNI) host, or None."""
    i = 2 + 32                                               # client_version(2) + random(32)
    if i >= len(body):
        return None
    i += 1 + body[i]                                         # session_id (len + data)
    if i + 2 > len(body):
        return None
    i += 2 + ((body[i] << 8) | body[i + 1])                 # cipher_suites (len2 + data)
    if i >= len(body):
        return None
    i += 1 + body[i]                                         # compression_methods (len1 + data)
    if i + 2 > len(body):
        return None
    ext_end = min(i + 2 + ((body[i] << 8) | body[i + 1]), len(body))
    i += 2
    while i + 4 <= ext_end:
        et = (body[i] << 8) | body[i + 1]
        el = (body[i + 2] << 8) | body[i + 3]
        i += 4
        edata = body[i:i + el]
        i += el
        if et == _EXT_SERVER_NAME and len(edata) >= 5 and edata[2] == 0x00:  # server_name_list, host_name type
            hl = (edata[3] << 8) | edata[4]
            host = edata[5:5 + hl]
            if host:
                return host.decode("latin-1", "replace")
    return None


def _parse_first_cert(body: bytes) -> Optional[dict]:
    """From a TLS Certificate handshake message, parse the FIRST (leaf/server) certificate and return
    {subject CN, SAN, device_uuid}. The leaf cert is the device's own identity; for BACnet/SC the
    Device_UUID appears as a UUID in the subject/SAN. Returns None if the cert is truncated (spans TCP
    segments -- increment 1/2 is per-packet, no reassembly) or `cryptography` is unavailable."""
    if len(body) < 6:
        return None
    first_len = (body[3] << 16) | (body[4] << 8) | body[5]   # Certificate: total_len(3), cert_len(3), DER
    der = body[6:6 + first_len]
    if not der or len(der) < first_len:
        return None                                          # truncated (multi-segment) -> skip
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        cert = x509.load_der_x509_certificate(der)
    except Exception:                                        # noqa: BLE001 - any parse/import failure -> skip
        return None
    out: dict = {}
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn:
            out["tls_cert_subject_cn"] = cn[0].value
    except Exception:                                        # noqa: BLE001
        pass
    names: list = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        for n in san:
            v = getattr(n, "value", None)
            if v is not None:
                names.append(str(v))
        if names:
            out["tls_cert_san"] = names
    except Exception:                                        # noqa: BLE001 - no SAN extension, etc.
        pass
    for s in names + [out.get("tls_cert_subject_cn", "")]:   # BACnet/SC Device_UUID = a UUID in the cert
        m = _UUID_RE.search(s or "")
        if m:
            out["device_uuid"] = m.group(0)
            break
    return out or None


def _handshake_extra(hs_type: int, body: bytes) -> Optional[dict]:
    """Message-level TLS metadata for one handshake message: ClientHello SNI/version, ServerHello
    version, or Certificate subject CN / SAN / BACnet-SC Device_UUID. Returns an extra dict, or None for
    an unhandled handshake type."""
    extra = {"protocol": "tls"}
    if hs_type == _HS_CLIENT_HELLO:
        extra["tls_message"] = "client_hello"
        if len(body) >= 34:
            extra["tls_client_version"] = _TLS_VERSIONS.get((body[0] << 8) | body[1], "unknown")
            sni = _extract_sni(body)
            if sni:
                extra["tls_sni"] = sni
    elif hs_type == _HS_SERVER_HELLO:
        extra["tls_message"] = "server_hello"
        if len(body) >= 2:
            extra["tls_server_version"] = _TLS_VERSIONS.get((body[0] << 8) | body[1], "unknown")
    elif hs_type == _HS_CERTIFICATE:
        extra["tls_message"] = "certificate"
        cert = _parse_first_cert(body)
        if cert:
            extra.update(cert)
    else:
        return None
    return extra


def _tls_result(extra: dict):
    from core.fingerprint import FingerprintResult          # lazy: avoid import cycle
    label = extra.get("tls_cert_subject_cn") or extra.get("tls_sni")   # richest identity first
    model = f"TLS endpoint ({label})" if label else "TLS endpoint"
    return FingerprintResult(vendor="unknown", model=model, confidence="low",
                             method="tls_passive", extra=extra)


def parse_tls_metadata(payload: bytes):
    """Parse a TLS handshake record for passive metadata. Returns a FingerprintResult (TLS presence +
    SNI for a ClientHello, record version for a ServerHello) or None if the bytes are not a TLS handshake
    record. Decrypts nothing."""
    if len(payload) < 9 or payload[0] != _TLS_HANDSHAKE or payload[1] != 0x03:
        return None                                          # not a TLS (major v3) handshake record
    rec_len = (payload[3] << 8) | payload[4]
    hs = payload[5:5 + rec_len]
    if len(hs) < 4:
        return None
    hs_len = (hs[1] << 16) | (hs[2] << 8) | hs[3]
    extra = _handshake_extra(hs[0], hs[4:4 + hs_len])
    if extra is None:
        return None
    extra["tls_record_version"] = _TLS_VERSIONS.get((payload[1] << 8) | payload[2], "unknown")
    return _tls_result(extra)


# ── flow-aware reassembly: a server Certificate / cert chain routinely spans multiple TCP segments ──
_tls_flows: dict = {}          # flow_key -> accumulated handshake-bearing payload (one connection direction)
_TLS_FLOW_CAP = 65536          # per-flow byte cap (a cert chain is tens of KB); give up beyond this
_TLS_MAX_FLOWS = 2048          # bound the number of concurrent flows tracked
_HS_RANK = {"client_hello": 1, "server_hello": 2, "certificate": 3}


def reset_tls_flows() -> None:
    """Clear the TLS reassembly state (called at the start of a passive run)."""
    _tls_flows.clear()


def _iter_complete_handshakes(buf: bytes) -> list:
    """Defragment the TLS handshake records (ContentType 0x16) in `buf` into a handshake byte stream
    (handling a handshake message that spans multiple TLS records), then return [(hs_type, body)] for
    each COMPLETE handshake message."""
    hs = bytearray()
    i = 0
    while i + 5 <= len(buf):
        if buf[i] != _TLS_HANDSHAKE or buf[i + 1] != 0x03:
            break
        rec_len = (buf[i + 3] << 8) | buf[i + 4]
        if i + 5 + rec_len > len(buf):
            break                                            # incomplete record -> wait for more segments
        hs += buf[i + 5:i + 5 + rec_len]
        i += 5 + rec_len
    out = []
    j = 0
    while j + 4 <= len(hs):
        hlen = (hs[j + 1] << 16) | (hs[j + 2] << 8) | hs[j + 3]
        if j + 4 + hlen > len(hs):
            break                                            # incomplete message -> wait for more
        out.append((hs[j], bytes(hs[j + 4:j + 4 + hlen])))
        j += 4 + hlen
    return out


def parse_tls_stream(payload: bytes, flow_key):
    """Flow-aware TLS metadata. Accumulates a connection direction's handshake bytes across TCP segments
    (and across TLS records), and returns the richest COMPLETE message (Certificate > ServerHello >
    ClientHello). The per-flow buffer is evicted once a certificate identity is recovered or at the size
    cap. This recovers cert subject/SAN/Device_UUID even when the cert spans segments, which the
    single-record parse_tls_metadata cannot. Decrypts nothing."""
    if not payload:
        return None
    buf = _tls_flows.get(flow_key, b"") + payload
    if buf[0] != _TLS_HANDSHAKE:                             # not a TLS handshake stream -> don't buffer
        _tls_flows.pop(flow_key, None)
        return None
    best = None
    for hs_type, body in _iter_complete_handshakes(buf):
        extra = _handshake_extra(hs_type, body)
        if extra and (best is None or _HS_RANK.get(extra["tls_message"], 0) > _HS_RANK.get(best["tls_message"], 0)):
            best = extra
    got_cert = (bool(best) and best.get("tls_message") == "certificate"
                and ("device_uuid" in best or "tls_cert_subject_cn" in best))
    if got_cert or len(buf) >= _TLS_FLOW_CAP:
        _tls_flows.pop(flow_key, None)                       # done, or give up (cert too large / absent)
    else:
        if len(_tls_flows) >= _TLS_MAX_FLOWS:
            _tls_flows.pop(next(iter(_tls_flows)), None)     # bound concurrent flows
        _tls_flows[flow_key] = buf
    return _tls_result(best) if best else None
