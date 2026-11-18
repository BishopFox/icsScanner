"""core/passive.py — passive (zero-transmit) capture + ICS protocol dissection.

TSA-requested passive mode: connect to a network SPAN/mirror port (or TAP), capture traffic for a
defined window, dissect ICS/OT identity frames as they naturally occur, and emit a DiscoveredDevice
asset inventory — WITHOUT EVER TRANSMITTING A PACKET. This is the capture-once -> demux -> route
-> parse -> inventory engine that the per-listener model in core/discovery.py lacks.

Design invariants:
  * ZERO TRANSMIT. `capture_live()` opens a receive-only AF_PACKET socket and never calls send(); the
    parsers are pure bytes->identity functions reused from core/fingerprint.py / core/discovery.py.
  * REUSE, don't reinvent. Each protocol's identity is extracted with the SAME parser the active probe
    uses (parse_enip_list_identity, parse_bacnet_iam, _fins_parse, parse_modbus_fc43_mei,
    _mms_parse_identify, parse_fox_hello, parse_codesys_v3_response, _parse_arp_frame).
  * Fail closed. Missing CAP_NET_RAW / non-Linux / missing scapy -> yields nothing, never raises.

Two capture sources feed one dispatch path: live SPAN/TAP (AF_PACKET) and offline .pcap (scapy). The
CVE correlation step (exact vendor+model against the candidate corpus) lives in correlate_cves().
"""
from __future__ import annotations

import copy as _copy
import re
import socket as _socket
import struct
import time
from datetime import datetime, timezone
from typing import Callable, Iterable, Iterator, Optional

from core.discovery import DiscoveredDevice, parse_codesys_v3_response, _parse_arp_frame
from core.version_match import precondition_version_status
from core.roc_plus import parse_roc_plus_response
from core.crestron import parse_crestron_cip_frame, parse_crestron_cip_udp
from core.tls import parse_tls_metadata, parse_tls_stream, reset_tls_flows
from core.opcua import _vendor_from as _opcua_vendor_from, _APP_TYPE as _OPCUA_APP_TYPE
from core.fingerprint import (
    FingerprintResult,
    parse_enip_list_identity,
    parse_modbus_fc43_mei,
    parse_bacnet_iam,
    parse_knxnet_frame,
    parse_fox_hello,
    parse_c37118_frame,
    parse_ge_srtp_frame,
    parse_s7comm_frame,
    parse_proconos_frame,
    parse_saia_sbus_frame,
    parse_pcworx_frame,
    parse_hartip_frame,
    parse_crimson_frame,
    parse_iec104_frame,
    parse_slmp_frame,
    parse_melsoft_frame,
    parse_ads_frame,
    parse_optommp_frame,
    lookup_bacnet_vendor,
    _fins_parse,
    _mms_parse_identify,
)

_ETH_P_ALL = 0x0003
_ETH_P_IP = 0x0800
_ETH_P_ARP = 0x0806
_ETH_P_8021Q = 0x8100
_ETH_P_LLDP = 0x88CC
_CDP_MULTICAST = "01:00:0c:cc:cc:cc"
_ETH_P_PROFINET = 0x8892
_PNDCP_IDENT_RES = 0xFEFE   # DCP Identify response
_PNDCP_HELLO = 0xFEFF       # DCP Hello (unsolicited, on device startup)
_ETH_P_GOOSE = 0x88B8       # IEC 61850 GOOSE (L2 multicast)
_ETH_P_SV = 0x88BA          # IEC 61850 Sampled Values (L2 multicast)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────────── capture sources (RX-only) ───────────────────────────

_DLT_ETHERNET = 1
_DLT_RAW = (12, 14, 101)          # DLT_RAW variants: the frame is a bare IP packet (no link header)
_DLT_LINUX_SLL = 113              # Linux "cooked" capture (16-byte header)
_DLT_LINUX_SLL2 = 276             # Linux cooked v2 (20-byte header)


def _normalize_to_ethernet(raw: bytes, linktype: int) -> Optional[bytes]:
    """Normalise a captured link-layer frame to an Ethernet frame the rest of the engine expects.
    Handles Ethernet (pass-through), raw IP (PCAPdroid / VPN / `tcpdump -i any` sometimes), and Linux
    cooked SLL/SLL2 — by synthesising a zero-MAC Ethernet header with the right EtherType. Returns None
    for an unsupported link type or a frame too short to classify."""
    if linktype == _DLT_ETHERNET:
        return raw
    if linktype in _DLT_RAW:
        if not raw:
            return None
        ver = raw[0] >> 4
        et = b"\x08\x00" if ver == 4 else b"\x86\xdd" if ver == 6 else None
        return (b"\x00" * 12 + et + raw) if et else None
    if linktype == _DLT_LINUX_SLL and len(raw) >= 16:
        return b"\x00" * 12 + raw[14:16] + raw[16:]          # EtherType at SLL offset 14; IP at 16
    if linktype == _DLT_LINUX_SLL2 and len(raw) >= 20:
        return b"\x00" * 12 + raw[0:2] + raw[20:]            # protocol at SLL2 offset 0; IP at 20
    return None


def _iter_pcap_frames(pcap_path: str) -> Iterator[tuple]:
    """Yield (timestamp_or_None, Ethernet-normalised frame) from a pcap across Ethernet / raw-IP / Linux
    cooked link types. Read-only; fail-closed (yields nothing on any error)."""
    try:
        from scapy.utils import RawPcapReader
    except Exception:
        return
    try:
        reader = RawPcapReader(pcap_path)
    except Exception:
        return
    linktype = getattr(reader, "linktype", _DLT_ETHERNET)
    try:
        for raw, meta in reader:
            frame = _normalize_to_ethernet(bytes(raw), linktype)
            if frame is None:
                continue
            try:
                ts = meta.sec + meta.usec / 1e6
            except Exception:
                ts = None
            yield ts, frame
    except Exception:
        return
    finally:
        try:
            reader.close()
        except Exception:
            pass


def capture_pcap(pcap_path: str) -> Iterator[bytes]:
    """Yield Ethernet-normalised frames from an offline capture (Ethernet, raw-IP, or Linux cooked).
    Read-only; needs scapy; yields nothing (never raises) if scapy is missing or the file can't be read."""
    for _ts, frame in _iter_pcap_frames(pcap_path):
        yield frame


def capture_pcap_timed(pcap_path: str) -> Iterator[tuple]:
    """Like capture_pcap but yields (capture_timestamp, frame) so native detection matching can carry
    real packet times into the Observed-Activity window. Read-only; fail-closed (yields nothing)."""
    for ts, frame in _iter_pcap_frames(pcap_path):
        yield (ts if ts is not None else 0.0), frame


def capture_live(iface: str, window: float, snaplen: int = 65535) -> Iterator[bytes]:
    """Yield raw Ethernet frames mirrored to `iface` for `window` seconds, then stop. Opens a
    RECEIVE-ONLY AF_PACKET socket in promiscuous mode and NEVER transmits. Fails closed (yields
    nothing) without CAP_NET_RAW or on non-Linux. Intended for a SPAN/mirror port or TAP."""
    sock = None
    mreq = None
    try:
        try:
            sock = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW, _socket.htons(_ETH_P_ALL))
            sock.bind((iface, 0))
        except (PermissionError, OSError, AttributeError):
            return
        # Best-effort promiscuous mode so we accept frames not addressed to this NIC (SPAN traffic).
        try:
            ifindex = _socket.if_nametoindex(iface)
            mreq = struct.pack("IHH8s", ifindex, 1, 0, b"")  # PACKET_MR_PROMISC = 1
            sock.setsockopt(263, 1, mreq)                     # SOL_PACKET=263, PACKET_ADD_MEMBERSHIP=1
        except (OSError, AttributeError):
            mreq = None
        sock.settimeout(0.5)
        deadline = time.monotonic() + window
        while time.monotonic() < deadline:
            try:
                frame = sock.recv(snaplen)
            except _socket.timeout:
                continue
            except OSError:
                continue
            if frame:
                yield frame
    finally:
        if sock is not None:
            if mreq is not None:
                try:
                    sock.setsockopt(263, 2, mreq)  # PACKET_DROP_MEMBERSHIP = 2
                except OSError:
                    pass
            try:
                sock.close()
            except OSError:
                pass


# ─────────────────────────── decap + dispatch ───────────────────────────

def decap(frame: bytes) -> Optional[dict]:
    """Minimal read-only Ethernet II (+ one VLAN tag) / ARP / IPv4-{TCP,UDP} decap. Returns a dict
    {ethertype, l4, src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload, frame} or None. Bounded,
    no IP/TCP reassembly (each frame parsed independently — enough for the identity frames we read)."""
    try:
        if len(frame) < 14:
            return None
        dst_mac = _fmt_mac(frame[0:6])
        src_mac = _fmt_mac(frame[6:12])
        etype = struct.unpack(">H", frame[12:14])[0]
        off = 14
        if etype == _ETH_P_8021Q:
            if len(frame) < 18:
                return None
            etype = struct.unpack(">H", frame[16:18])[0]
            off = 18
        base = {"src_mac": src_mac, "dst_mac": dst_mac, "ethertype": etype, "frame": frame,
                "l4": None, "src_ip": None, "dst_ip": None, "sport": None, "dport": None,
                "payload": b""}
        if etype == _ETH_P_ARP:
            return base
        if etype != _ETH_P_IP or len(frame) < off + 20:
            return base
        ver_ihl = frame[off]
        if ver_ihl >> 4 != 4:
            return base
        ihl = (ver_ihl & 0x0F) * 4
        if ihl < 20 or len(frame) < off + ihl:
            return base
        proto = frame[off + 9]
        base["src_ip"] = ".".join(str(b) for b in frame[off + 12:off + 16])
        base["dst_ip"] = ".".join(str(b) for b in frame[off + 16:off + 20])
        l4off = off + ihl
        if proto == 17 and len(frame) >= l4off + 8:          # UDP
            base["l4"] = "udp"
            base["sport"] = struct.unpack(">H", frame[l4off:l4off + 2])[0]
            base["dport"] = struct.unpack(">H", frame[l4off + 2:l4off + 4])[0]
            ulen = struct.unpack(">H", frame[l4off + 4:l4off + 6])[0]
            end = min(l4off + max(ulen, 8), len(frame))
            base["payload"] = frame[l4off + 8:end]
        elif proto == 6 and len(frame) >= l4off + 20:        # TCP
            base["l4"] = "tcp"
            base["sport"] = struct.unpack(">H", frame[l4off:l4off + 2])[0]
            base["dport"] = struct.unpack(">H", frame[l4off + 2:l4off + 4])[0]
            doff = (frame[l4off + 12] >> 4) * 4
            if doff >= 20 and len(frame) >= l4off + doff:
                base["payload"] = frame[l4off + doff:]
        return base
    except (struct.error, IndexError):
        return None


def _fmt_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


# ── BACnet/IP: skip BVLC + NPDU to reach the APDU (so parse_bacnet_iam sees an I-Am) ──
def _bacnet_apdu(payload: bytes) -> Optional[bytes]:
    try:
        if len(payload) < 4 or payload[0] != 0x81:   # BVLC type
            return None
        func = payload[1]
        off = 4
        if func == 0x04:         # Forwarded-NPDU: 6-byte originating address after BVLC
            off += 6
        if off + 2 > len(payload):
            return None
        control = payload[off + 1]
        off += 2
        if control & 0x80:       # network-layer message, not an APDU
            return None
        if control & 0x20:       # DNET/DLEN/DADR present
            off += 2
            if off >= len(payload):
                return None
            dlen = payload[off]
            off += 1 + dlen
        if control & 0x08:       # SNET/SLEN/SADR present
            off += 2
            if off >= len(payload):
                return None
            slen = payload[off]
            off += 1 + slen
        if control & 0x20:       # hop count follows when DNET present
            off += 1
        if off >= len(payload):
            return None
        return payload[off:]
    except (IndexError, struct.error):
        return None


# ── per-protocol adapters: pkt dict -> FingerprintResult|None (identity sender = pkt['src_*']) ──
def _pa_enip(pkt: dict) -> Optional[FingerprintResult]:
    return parse_enip_list_identity(pkt["payload"])


def _pa_modbus(pkt: dict) -> Optional[FingerprintResult]:
    p = pkt["payload"]
    if len(p) < 8:
        return None
    return parse_modbus_fc43_mei(p[7:])   # strip the 7-byte MBAP header -> PDU


def _pa_knxnet(pkt: dict) -> Optional[FingerprintResult]:
    return parse_knxnet_frame(pkt["payload"])  # KNXnet/IP SEARCH/DESCRIPTION_RESPONSE -> device-info DIB


def _pa_bacnet(pkt: dict) -> Optional[FingerprintResult]:
    apdu = _bacnet_apdu(pkt["payload"])
    if apdu is None:
        return None
    iam = parse_bacnet_iam(apdu)
    if not iam or iam.get("vendor_id") is None:
        return None
    vid = iam["vendor_id"]
    did = iam.get("device_id")
    return FingerprintResult(
        vendor=lookup_bacnet_vendor(vid),
        model=f"device_{did}" if did is not None else "unknown",
        confidence="high",
        method="bacnet_iam",
        extra={"vendor_id": vid, "device_id": did},
    )


def _pa_fins(pkt: dict) -> Optional[FingerprintResult]:
    p = pkt["payload"]
    offset = 16 if p[:4] == b"FINS" else 0   # FINS/TCP frame header vs raw FINS/UDP
    return _fins_parse(p, offset)


def _pa_mms(pkt: dict) -> Optional[FingerprintResult]:
    ident = _mms_parse_identify(pkt["payload"])
    if not ident:
        return None
    return FingerprintResult(
        vendor=ident.get("vendorName", "unknown") or "unknown",
        model=ident.get("modelName", "unknown") or "unknown",
        firmware=ident.get("revision", "unknown") or "unknown",
        confidence="high",
        method="mms_identify",
        extra={"protocol": "mms"},
    )


def _pa_fox(pkt: dict) -> Optional[FingerprintResult]:
    res = parse_fox_hello(pkt["payload"])
    return res if res.confidence != "none" else None


def _pa_codesys(pkt: dict) -> Optional[FingerprintResult]:
    ident = parse_codesys_v3_response(pkt["payload"])
    if not ident:
        return None
    return FingerprintResult(
        vendor=ident.get("vendor", "unknown") or "unknown",
        model=ident.get("device", "unknown") or "unknown",
        firmware=str(ident.get("target_version", "")) or "unknown",
        confidence="high",
        method="codesys_v3_name_service",
        extra={"node": ident.get("node"), "target_id": ident.get("target_id")},
    )


def _pa_c37118(pkt: dict) -> Optional[FingerprintResult]:
    res = parse_c37118_frame(pkt["payload"])   # CFG frame -> station name; any valid frame -> presence
    return res if res.confidence != "none" else None


def _pa_ge_srtp(pkt: dict) -> Optional[FingerprintResult]:
    res = parse_ge_srtp_frame(pkt["payload"])  # REQ_ACK -> controller id; INIT_ACK -> presence
    return res if res.confidence != "none" else None


def _pa_s7comm(pkt: dict) -> Optional[FingerprintResult]:
    res = parse_s7comm_frame(pkt["payload"])   # S7comm protocol presence (TPKT + COTP + 0x32)
    return res if res.confidence != "none" else None


def _pa_102(pkt: dict) -> Optional[FingerprintResult]:
    """TCP 102 carries both IEC-61850 MMS and S7comm — prefer the richer MMS identity, fall back to
    S7comm protocol presence."""
    return _pa_mms(pkt) or _pa_s7comm(pkt)


def _pa_proconos(pkt: dict) -> Optional[FingerprintResult]:
    res = parse_proconos_frame(pkt["payload"])   # PCCOM info reply -> runtime/PLC-type/project
    return res if res.confidence != "none" else None


def _pa_saia(pkt: dict) -> Optional[FingerprintResult]:
    res = parse_saia_sbus_frame(pkt["payload"])  # Ether-S-Bus response -> Saia PCD + firmware
    return res if res.confidence != "none" else None


def _pa_pcworx(pkt: dict) -> Optional[FingerprintResult]:
    res = parse_pcworx_frame(pkt["payload"])     # 0x81 reply -> Phoenix Contact PCWorx presence
    return res if res.confidence != "none" else None


def _pa_hartip(pkt: dict) -> Optional[FingerprintResult]:
    res = parse_hartip_frame(pkt["payload"])     # HART-IP header -> protocol presence (multi-vendor)
    return res if res.confidence != "none" else None


def _pa_crimson(pkt: dict) -> Optional[FingerprintResult]:
    res = parse_crimson_frame(pkt["payload"])    # 0x0300 reply -> Red Lion identity string
    return res if res.confidence != "none" else None


def _pa_iec104(pkt: dict) -> Optional[FingerprintResult]:
    res = parse_iec104_frame(pkt["payload"])     # IEC 60870-5-104 APDU -> station + common address
    return res if res.confidence != "none" else None


def _pa_melsoft(pkt: dict) -> Optional[FingerprintResult]:
    return parse_melsoft_frame(pkt["payload"])   # MELSOFT 0x5700/0xD700 (TCP/UDP 5562) -> MELSEC PLC


def _pa_slmp(pkt: dict) -> Optional[FingerprintResult]:
    res = parse_slmp_frame(pkt["payload"])       # SLMP/MC subheader 0x5000/0xD000 -> MELSEC/SLMP device
    return res if res.confidence != "none" else None


def _pa_ads(pkt: dict) -> Optional[FingerprintResult]:
    res = parse_ads_frame(pkt["payload"])        # Beckhoff AMS/ADS frame -> TwinCAT device (+ version)
    return res if res.confidence != "none" else None


def _pa_optommp(pkt: dict) -> Optional[FingerprintResult]:
    res = parse_optommp_frame(pkt["payload"])    # Opto 22 OptoMMP (IEEE-1394) -> presence
    return res if res.confidence != "none" else None


def _pa_roc_plus(pkt: dict) -> Optional[FingerprintResult]:
    return parse_roc_plus_response(pkt["payload"])  # CRC-valid ROC Plus frame -> Emerson ROC RTU (+ opcode-6 identity)


# ── BSAP-IP (Bristol/Emerson ControlWave, UDP 1234) ─────────────────────────────────────────────────
_BSAP_SERIAL_SENTINEL = 0x0210
_BSAP_MSG_FUNC = {0x00: "poll", 0x01: "response", 0x05: "response", 0x06: "request",
                  0x84: "request", 0x86: "request"}


def parse_bsap_ip_frame(payload: bytes) -> Optional[FingerprintResult]:
    """BSAP-IP (Bristol Standard Asynchronous Protocol over IP; Emerson/Bristol ControlWave & Network
    3000 RTUs). Header is little-endian: length(2), num_messages(2), message_func(2), then data.
    Validation follows CISA's icsnpp-bsap DPD signature exactly -- the high byte of length,
    num_messages, and message_func are all 0x00, and message_func is one of the known command codes.
    The 0x0210 length value is the BSAP serial-over-ethernet sentinel."""
    if len(payload) < 6:
        return None
    length = int.from_bytes(payload[0:2], "little")
    if length == _BSAP_SERIAL_SENTINEL:
        func = "serial-over-ethernet"
    else:
        if payload[1] != 0 or payload[3] != 0 or payload[5] != 0:   # dpd.sig: bytes 1/3/5 == 0x00
            return None
        if payload[4] not in _BSAP_MSG_FUNC:                        # message function code
            return None
        if not (6 <= length <= len(payload) + 4):                   # length consistent with datagram
            return None
        func = _BSAP_MSG_FUNC[payload[4]]
    return FingerprintResult(vendor="Emerson", model="Emerson/Bristol ControlWave or Network 3000 RTU (BSAP)",
                             confidence="low", method="bsap_ip_passive",
                             extra={"protocol": "bsap_ip", "message_func": func})


def _pa_bsap_ip(pkt: dict) -> Optional[FingerprintResult]:
    return parse_bsap_ip_frame(pkt["payload"])


# ── LonWorks/IP (CEA-852 / IP-852, UDP 1628/1629) ───────────────────────────────────────────────────
def parse_lonworks_ip_frame(payload: bytes) -> Optional[FingerprintResult]:
    """LonWorks/IP (CEA-852 'CN/IP' tunnelling of LonTalk; the #2 building-control transport after
    BACnet). Conservative recognizer: the CEA-852 common header's revision-dependent field offsets are
    not reliably documented, so instead of parsing every field this validates the one robust invariant
    -- the leading packet-length field equals the total datagram length (checked in both byte orders) --
    on the dedicated IP-852 port. That identifies IP-852 presence (a LonWorks router/device) with low
    false-positive risk, without over-claiming deep identity from an unverified layout."""
    n = len(payload)
    if n < 20:                                                      # CNIP common header is ~20 bytes
        return None
    if int.from_bytes(payload[0:2], "big") != n and int.from_bytes(payload[0:2], "little") != n:
        return None
    return FingerprintResult(vendor="unknown", model="LonWorks/IP (CEA-852 / IP-852) router or device",
                             confidence="low", method="lonworks_ip_passive",
                             extra={"protocol": "lonworks_ip", "cnip_packet_type": payload[3]})


def _pa_lonworks_ip(pkt: dict) -> Optional[FingerprintResult]:
    return parse_lonworks_ip_frame(pkt["payload"])


def _pa_crestron(pkt: dict) -> Optional[FingerprintResult]:
    return parse_crestron_cip_frame(pkt["payload"])   # Crestron CIP frame -> control system / touch panel


def _pa_crestron_udp(pkt: dict) -> Optional[FingerprintResult]:
    return parse_crestron_cip_udp(pkt["payload"])     # Crestron UDP device-info response -> model/fw/MAC


# ── CC-Link IE Field Basic (CLPA / Mitsubishi, UDP 61450 cyclic + 61451 NodeSearch) ─────────────────
_CCLINK_IE_FB_COMMANDS = {0x0E70: "cyclic", 0x0E30: "node_search"}


def parse_cclink_ie_fb_frame(payload: bytes) -> Optional[FingerprintResult]:
    """CC-Link IE Field Basic (CCIEFB), the Ethernet/UDP factory-automation protocol from the CC-Link
    Partner Association. The 15-byte cyclic/SLMP header is: SLMP frame type (0x5000 request / 0xD000
    response), network no, node no, dest processor no, reserved, data length, reserved, command (offset
    11, little-endian), subcommand. Recognising command 0x0E70 (cyclic data) or 0x0E30 (NodeSearch) with
    the fixed frame type and zero subcommand is a strong signature. Field offsets and command constants
    are from the port GmbH CC-Link IE Field Basic reference manual."""
    if len(payload) < 15:
        return None
    if payload[0] not in (0x50, 0xD0) or payload[1] != 0x00:        # SLMP frame type
        return None
    command = int.from_bytes(payload[11:13], "little")
    if command not in _CCLINK_IE_FB_COMMANDS:
        return None
    if int.from_bytes(payload[13:15], "little") != 0x0000:          # subcommand is fixed 0x0000
        return None
    return FingerprintResult(vendor="unknown", model="CC-Link IE Field Basic device (CLPA)",
                             confidence="low", method="cclink_ie_fb_passive",
                             extra={"protocol": "cclink_ie_field_basic",
                                    "message": _CCLINK_IE_FB_COMMANDS[command]})


def _pa_cclink_ie_fb(pkt: dict) -> Optional[FingerprintResult]:
    return parse_cclink_ie_fb_frame(pkt["payload"])


# ── BACnet/SC (Secure Connect, ASHRAE 135 Addendum bj) ──────────────────────────────────────────────
# BACnet/SC runs BVLC over a WebSocket inside mutual TLS, so the data frames are normally encrypted. The
# one reliably-identifying cleartext signal is the WebSocket subprotocol in the HTTP Upgrade handshake,
# which is visible for a ws:// deployment or where TLS is terminated at the capture point (SPAN/proxy).
# The subprotocol strings are unique to BACnet/SC (from Steve Karg's bacnet-stack bsc/websocket.h).
_BACNET_SC_SUBPROTOS = {b"hub.bsc.bacnet.org": "hub", b"dc.bsc.bacnet.org": "direct-connect"}


def parse_bacnet_sc_frame(payload: bytes) -> Optional[FingerprintResult]:
    """Identify BACnet/SC from the WebSocket Upgrade handshake subprotocol (hub.bsc.bacnet.org /
    dc.bsc.bacnet.org). Only fires when the WebSocket handshake is in cleartext (ws:// or TLS terminated
    at the capture point); under mandatory mutual TLS the handshake is encrypted and BACnet/SC appears
    only as TLS, where device identity (the certificate's Device_UUID) needs a TLS-metadata parser."""
    if not payload or b"bsc.bacnet.org" not in payload:
        return None
    for sub, role in _BACNET_SC_SUBPROTOS.items():
        if sub in payload:
            return FingerprintResult(vendor="unknown", model=f"BACnet/SC node ({role})",
                                     confidence="low", method="bacnet_sc_ws",
                                     extra={"protocol": "bacnet_sc", "bsc_role": role})
    return None


def _pa_bacnet_sc(pkt: dict) -> Optional[FingerprintResult]:
    # BACnet/SC is WebSocket-over-TLS: catch the cleartext WS subprotocol, else the TLS handshake metadata.
    return parse_bacnet_sc_frame(pkt["payload"]) or parse_tls_metadata(pkt["payload"])


def _pa_tls(pkt: dict) -> Optional[FingerprintResult]:
    # flow-aware so a server Certificate spanning TCP segments is reassembled (SNI/cert/Device_UUID)
    flow_key = (pkt.get("src_ip"), pkt.get("sport"), pkt.get("dst_ip"), pkt.get("dport"))
    return parse_tls_stream(pkt["payload"], flow_key)


_OPCUA_MAGIC = {b"HEL", b"ACK", b"OPN", b"MSG", b"CLO", b"ERR"}


def _pa_opcua(pkt: dict) -> Optional[FingerprintResult]:
    """Native OPC UA (opc.tcp) presence from the message framing (magic + chunk type + sane size).
    Server identity needs the active GetEndpoints probe (core.opcua) or the opcua_binary Zeek pivot."""
    p = pkt["payload"]
    if len(p) < 8 or p[0:3] not in _OPCUA_MAGIC or p[3:4] not in (b"F", b"C", b"A"):
        return None
    size = int.from_bytes(p[4:8], "little")
    if not (8 <= size <= (1 << 20)):
        return None
    return FingerprintResult(vendor="unknown", model="OPC UA server", confidence="low",
                             method="opcua_passive", extra={"protocol": "opcua"})


# ── L2 passive discovery pack (LLDP / CDP / mDNS) — zero-transmit host & topology inventory ──────────
def _l2_payload_off(frame: bytes) -> int:
    """Offset of the L2 payload after the Ethernet header, accounting for a single 802.1Q VLAN tag."""
    return 18 if frame[12:14] == b"\x81\x00" else 14


def parse_lldp_frame(frame: bytes) -> Optional[FingerprintResult]:
    """Parse an LLDP frame (EtherType 0x88CC) TLVs -> system name/description, chassis/port id, and
    management address. LLDP is the sender's OWN advertised identity (switches, APs, PLCs, IP phones,
    some BAS controllers) -- high-value zero-transmit host + topology inventory."""
    off = _l2_payload_off(frame)
    if len(frame) < off + 2:
        return None
    p, i, out = frame[off:], 0, {}
    mgmt_ip = None
    while i + 2 <= len(p):
        hdr = (p[i] << 8) | p[i + 1]
        ttype, tlen = hdr >> 9, hdr & 0x1FF
        i += 2
        if i + tlen > len(p):
            break
        val = p[i:i + tlen]
        i += tlen
        if ttype == 0:                                   # end of LLDPDU
            break
        if ttype == 5:
            out["system_name"] = val.decode("latin-1", "replace").strip("\x00").strip()
        elif ttype == 6:
            out["system_description"] = val.decode("latin-1", "replace").strip("\x00").strip()[:200]
        elif ttype == 1 and len(val) > 1:                # chassis id (subtype + id)
            out["chassis_id"] = (val[1:].decode("latin-1", "replace").strip()
                                 if val[0] in (5, 6, 7) else val[1:].hex())
        elif ttype == 2 and len(val) > 1:                # port id
            out["port_id"] = (val[1:].decode("latin-1", "replace").strip()
                              if val[0] in (5, 7) else val[1:].hex())
        elif ttype == 8 and len(val) >= 6 and val[0] == 5 and val[1] == 1:  # mgmt addr, IPv4
            mgmt_ip = ".".join(str(b) for b in val[2:6])
    if not out and not mgmt_ip:
        return None
    if mgmt_ip:
        out["management_address"] = mgmt_ip
    return FingerprintResult(vendor="unknown", model=out.get("system_name") or "LLDP device",
                             confidence="high", method="lldp_passive", extra={"protocol": "lldp", **out})


def parse_cdp_frame(frame: bytes) -> Optional[FingerprintResult]:
    """Parse a Cisco CDP frame (802.3 LLC/SNAP, multicast 01:00:0c:cc:cc:cc) -> device id, platform,
    software version, port id. CDP advertisers are Cisco (and some OT/industrial switches)."""
    off = _l2_payload_off(frame)
    # LLC(AA AA 03) + SNAP(OUI 00 00 0C + proto 20 00) + CDP ver(1) ttl(1) checksum(2) -> TLVs at +12
    if (len(frame) < off + 12 or frame[off:off + 3] != b"\xaa\xaa\x03"
            or frame[off + 3:off + 8] != b"\x00\x00\x0c\x20\x00"):
        return None
    p, i, out = frame[off + 12:], 0, {}
    while i + 4 <= len(p):
        ttype = (p[i] << 8) | p[i + 1]
        tlen = (p[i + 2] << 8) | p[i + 3]
        if tlen < 4 or i + tlen > len(p):
            break
        val = p[i + 4:i + tlen]
        i += tlen
        if ttype == 0x0001:
            out["device_id"] = val.decode("latin-1", "replace").strip()
        elif ttype == 0x0005:
            out["software_version"] = val.decode("latin-1", "replace").strip()[:200]
        elif ttype == 0x0006:
            out["platform"] = val.decode("latin-1", "replace").strip()
        elif ttype == 0x0003:
            out["port_id"] = val.decode("latin-1", "replace").strip()
    if not out:
        return None
    return FingerprintResult(vendor="Cisco", model=out.get("platform") or out.get("device_id") or "CDP device",
                             confidence="high", method="cdp_passive", extra={"protocol": "cdp", **out})


def _dns_name(data: bytes, off: int) -> tuple:
    """Decode a (possibly compressed) DNS name -> (name, next_offset). Bounded; best-effort."""
    labels, jumped, nxt = [], False, off
    for _ in range(128):
        if off >= len(data):
            break
        ln = data[off]
        if ln == 0:
            off += 1
            if not jumped:
                nxt = off
            break
        if ln & 0xC0 == 0xC0:                            # compression pointer
            if off + 1 >= len(data):
                break
            if not jumped:
                nxt = off + 2
            off, jumped = ((ln & 0x3F) << 8) | data[off + 1], True
            continue
        labels.append(data[off + 1:off + 1 + ln].decode("latin-1", "replace"))
        off += 1 + ln
    return ".".join(labels), nxt


def _pa_mdns(pkt: dict) -> Optional[FingerprintResult]:
    """Parse an mDNS/DNS-SD response (UDP 5353) -> host name + advertised service types + TXT model/
    vendor hints. Rich zero-transmit device discovery (printers, AV/Crestron, Apple, BAS gateways)."""
    data = pkt["payload"]
    if len(data) < 12:
        return None
    try:
        qd, an, ns, ar = struct.unpack_from(">HHHH", data, 4)
        if not (struct.unpack_from(">H", data, 2)[0] & 0x8000) or an == 0:  # responses only
            return None
        off = 12
        for _ in range(min(qd, 32)):                     # skip questions
            _n, off = _dns_name(data, off)
            off += 4
        host, services, txt = None, [], {}
        for _ in range(min(an + ns + ar, 64)):
            name, off = _dns_name(data, off)
            if off + 10 > len(data):
                break
            rtype, _cls, _ttl, rdlen = struct.unpack_from(">HHIH", data, off)
            off += 10
            rdata = data[off:off + rdlen]
            off += rdlen
            if rtype in (1, 28):                         # A / AAAA -> the host
                host = name.rstrip(".")
            elif rtype == 12:                            # PTR -> a service type
                svc = name.rstrip(".")
                if svc.startswith("_") and svc not in services:
                    services.append(svc)
            elif rtype == 16:                            # TXT -> key=value hints
                j = 0
                while j < len(rdata):
                    sl = rdata[j]
                    kv = rdata[j + 1:j + 1 + sl].decode("latin-1", "replace")
                    j += 1 + sl
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        if k.lower() in ("md", "model", "ty", "manufacturer", "usb_mdl", "product"):
                            txt[k.lower()] = v
    except (struct.error, IndexError):
        return None
    if host is None and not services:
        return None
    model = txt.get("md") or txt.get("model") or txt.get("ty") or host or "mDNS host"
    extra = {"protocol": "mdns", "hostname": host, "services": services}
    if txt:
        extra["txt"] = txt
    return FingerprintResult(vendor=txt.get("manufacturer", "unknown") or "unknown",
                             model=model, confidence="low", method="mdns_passive", extra=extra)


def _dcp_str_value(bval: bytes) -> str:
    """A DCP device-property string value, dropping a leading 2-byte BlockInfo only when present (it is
    non-printable, typically 0x0000; a real name/vendor string starts with a printable character)."""
    if len(bval) >= 2 and bval[0] < 0x20:
        bval = bval[2:]
    return bval.decode("latin-1", "replace").strip("\x00").strip()


def _ber_value(data: bytes, want_tag: int) -> Optional[bytes]:
    """Return the value of the first BER-TLV with `want_tag` at the top level of `data`, or None.
    Handles short- and long-form length. Used to walk IEC 61850 GOOSE/SV ASN.1 PDUs."""
    i = 0
    while i + 2 <= len(data):
        tag = data[i]
        ln = data[i + 1]
        i += 2
        if ln & 0x80:                                        # long-form length
            nb = ln & 0x7F
            if nb == 0 or i + nb > len(data):
                return None
            ln = int.from_bytes(data[i:i + nb], "big")
            i += nb
        if i + ln > len(data):
            return None
        if tag == want_tag:
            return data[i:i + ln]
        i += ln
    return None


def parse_sv_frame(frame: bytes) -> Optional[FingerprintResult]:
    """Parse an IEC 61850 Sampled Values frame (EtherType 0x88BA) -> publisher IED keyed by source MAC,
    with the svID. SV is L2 multicast (no IP). PDU = APPID(2) + length(2) + reserved(4), then the BER
    savPdu (0x60) -> seqOfASDU (0xA2) -> ASDU (0x30) -> svID (0x80). Grounded in a real SV capture
    (mgadelha/Sampled_Values) + the libiec61850 sv_publisher encoding."""
    off = _l2_payload_off(frame)
    if len(frame) < off + 10:
        return None
    savpdu = _ber_value(frame[off + 8:], 0x60)               # skip APPID+length+reserved
    if savpdu is None:
        return None
    extra = {"protocol": "iec61850_sv"}
    seq = _ber_value(savpdu, 0xA2)
    asdu = _ber_value(seq, 0x30) if seq is not None else None
    sv_id = _ber_value(asdu, 0x80) if asdu is not None else None
    if sv_id:
        extra["sv_id"] = sv_id.decode("latin-1", "replace").strip("\x00").strip()
    return FingerprintResult(vendor="unknown", model="IEC 61850 Sampled Values publisher (IED)",
                             confidence="high", method="sv_passive", extra=extra)


def parse_goose_frame(frame: bytes) -> Optional[FingerprintResult]:
    """Parse an IEC 61850 GOOSE frame (EtherType 0x88B8) -> publisher IED keyed by source MAC, with the
    control-block/dataset refs. PDU = APPID(2)+length(2)+reserved(4), then the BER goosePdu (0x61) whose
    fields are gocbRef (0x80), timeAllowedtoLive (0x81), datSet (0x82), goID (0x83). L2 multicast."""
    off = _l2_payload_off(frame)
    if len(frame) < off + 10:
        return None
    goosepdu = _ber_value(frame[off + 8:], 0x61)
    if goosepdu is None:
        return None
    extra = {"protocol": "iec61850_goose"}
    for key, tag in (("gocb_ref", 0x80), ("dataset", 0x82), ("go_id", 0x83)):
        v = _ber_value(goosepdu, tag)
        if v:
            extra[key] = v.decode("latin-1", "replace").strip("\x00").strip()
    return FingerprintResult(vendor="unknown", model="IEC 61850 GOOSE publisher (IED)",
                             confidence="high", method="goose_passive", extra=extra)


def parse_profinet_dcp_frame(frame: bytes) -> Optional[FingerprintResult]:
    """Parse a PROFINET DCP frame (EtherType 0x8892) Identify-response / Hello -> station name, device
    type string, PNO vendor/device id, and IP. PROFINET-DCP is L2 (no routing); a passive SPAN catches
    the Hello a device emits on startup and the Identify responses during engineering -- the standard
    zero-transmit PROFINET inventory signal. Only responses/hellos carry identity, so requests are
    ignored. Blocks follow Wireshark's pn_dcp layout (device-property blocks carry a 2-byte BlockInfo)."""
    off = _l2_payload_off(frame)
    if len(frame) < off + 12:
        return None
    frame_id = (frame[off] << 8) | frame[off + 1]
    if frame_id not in (_PNDCP_IDENT_RES, _PNDCP_HELLO):
        return None
    p = frame[off + 2:]                                       # DCP header + blocks
    if len(p) < 10:
        return None
    data_len = (p[8] << 8) | p[9]                             # ServiceID,Type,Xid(4),RespDelay(2),DataLen(2)
    blocks = p[10:10 + data_len]
    out: dict = {}
    vendor_id = device_id = None
    i = 0
    while i + 4 <= len(blocks):
        opt, subopt = blocks[i], blocks[i + 1]
        blen = (blocks[i + 2] << 8) | blocks[i + 3]
        i += 4
        bval = blocks[i:i + blen]
        i += blen + (blen & 1)                               # blocks pad to even length
        # Device-property/IP blocks in an Identify response may or may not carry a 2-byte BlockInfo
        # prefix (seen both ways in real captures). For string values, strip it only when the value does
        # not start with a printable character; for binary values, infer it from the block length.
        if opt == 0x02 and subopt == 0x02:                   # Name of Station
            out["station_name"] = _dcp_str_value(bval)
        elif opt == 0x02 and subopt == 0x01:                 # Device vendor value (manufacturer string)
            out["device_type"] = _dcp_str_value(bval)
        elif opt == 0x02 and subopt == 0x03 and len(bval) >= 4:   # Device ID: [BlockInfo] VendorID DeviceID
            o = 2 if len(bval) >= 6 else 0
            vendor_id = (bval[o] << 8) | bval[o + 1]
            device_id = (bval[o + 2] << 8) | bval[o + 3]
        elif opt == 0x01 and subopt == 0x02 and len(bval) >= 4:   # IP param: [BlockInfo] IP Subnet Gateway
            o = 2 if len(bval) >= 14 else 0
            out["ip"] = ".".join(str(b) for b in bval[o:o + 4])
    if not out and vendor_id is None:
        return None
    if vendor_id is not None:
        out["pn_vendor_id"] = vendor_id
        out["pn_device_id"] = device_id
    model = out.get("device_type") or out.get("station_name") or "PROFINET device"
    return FingerprintResult(vendor="unknown", model=model, confidence="high",
                             method="profinet_dcp_passive", extra={"protocol": "profinet_dcp", **out})


# Dispatch tables: a parser is a candidate when EITHER the src or dst port matches (identity can ride a
# response from the server port or a broadcast). Each adapter self-validates and returns None if the
# frame isn't its identity frame.
_UDP_PORT_PARSERS: dict[int, Callable] = {
    44818: _pa_enip, 2222: _pa_enip,
    47808: _pa_bacnet,
    3671: _pa_knxnet,
    9600: _pa_fins,
    1740: _pa_codesys, 1741: _pa_codesys, 1742: _pa_codesys, 1743: _pa_codesys,
    4712: _pa_c37118, 4713: _pa_c37118,
    5050: _pa_saia,
    5094: _pa_hartip,
    4000: _pa_roc_plus,
    5353: _pa_mdns,
    1234: _pa_bsap_ip, 1235: _pa_bsap_ip,
    1628: _pa_lonworks_ip, 1629: _pa_lonworks_ip,
    61450: _pa_cclink_ie_fb, 61451: _pa_cclink_ie_fb,
    5000: _pa_slmp, 5062: _pa_slmp,
    5562: _pa_melsoft,
    48899: _pa_ads,
    2001: _pa_optommp,
    41794: _pa_crestron_udp,                            # Crestron UDP device-info response (model/fw/MAC)
}
_TCP_PORT_PARSERS: dict[int, Callable] = {
    44818: _pa_enip,
    502: _pa_modbus,
    9600: _pa_fins,
    102: _pa_102,
    1911: _pa_fox,
    4712: _pa_c37118,
    18245: _pa_ge_srtp,
    20547: _pa_proconos,
    1962: _pa_pcworx,
    5094: _pa_hartip,
    789: _pa_crimson,
    2404: _pa_iec104,
    5000: _pa_slmp, 5062: _pa_slmp,
    5562: _pa_melsoft,
    48898: _pa_ads,
    2001: _pa_optommp,
    4000: _pa_roc_plus,
    1234: _pa_bsap_ip,
    1628: _pa_lonworks_ip,
    41794: _pa_crestron,
    4840: _pa_opcua,
    47808: _pa_bacnet_sc, 47809: _pa_bacnet_sc,   # BACnet/SC default/common ports (port-configurable)
    443: _pa_tls, 4843: _pa_tls,                   # TLS handshake metadata (BACnet/SC hub, OPC-UA-over-TLS)
}


def dispatch(pkt: dict) -> Optional[tuple]:
    """Route a decapped packet to the matching passive parser(s). Returns (FingerprintResult, proto)
    attributed to the frame's SENDER (the device), or None."""
    if pkt.get("ethertype") == _ETH_P_ARP:
        arp = _parse_arp_frame(pkt["frame"])
        if arp is not None:
            _op, sender_ip, sender_mac = arp
            vendor = _oui_vendor(sender_mac)
            return (FingerprintResult(vendor=vendor, confidence="low", method="arp_passive",
                                      extra={"protocol": "arp"}), "arp", sender_ip, sender_mac)
        return None
    if pkt.get("ethertype") == _ETH_P_LLDP:                    # LLDP: self-advertised L2 identity
        res = parse_lldp_frame(pkt["frame"])
        return (res, "lldp", res.extra.get("management_address"), pkt.get("src_mac")) if res else None
    if pkt.get("dst_mac") == _CDP_MULTICAST:                   # CDP (Cisco) multicast
        res = parse_cdp_frame(pkt["frame"])
        return (res, "cdp", None, pkt.get("src_mac")) if res else None
    if pkt.get("ethertype") == _ETH_P_PROFINET:               # PROFINET DCP Identify/Hello (L2)
        res = parse_profinet_dcp_frame(pkt["frame"])
        return (res, "profinet_dcp", res.extra.get("ip"), pkt.get("src_mac")) if res else None
    if pkt.get("ethertype") == _ETH_P_GOOSE:                  # IEC 61850 GOOSE publisher (L2)
        res = parse_goose_frame(pkt["frame"])
        return (res, "iec61850_goose", None, pkt.get("src_mac")) if res else None
    if pkt.get("ethertype") == _ETH_P_SV:                     # IEC 61850 Sampled Values publisher (L2)
        res = parse_sv_frame(pkt["frame"])
        return (res, "iec61850_sv", None, pkt.get("src_mac")) if res else None
    table = _UDP_PORT_PARSERS if pkt.get("l4") == "udp" else (_TCP_PORT_PARSERS if pkt.get("l4") == "tcp" else {})
    if not table or not pkt.get("payload"):
        return None
    seen: list = []
    for port in (pkt.get("dport"), pkt.get("sport")):
        parser = table.get(port)
        if parser is not None and parser not in seen:
            seen.append(parser)
            try:
                res = parser(pkt)
            except Exception:
                res = None
            if res is not None and res.confidence != "none":
                return (res, port, pkt.get("src_ip"), pkt.get("src_mac"))
    return None


def _oui_vendor(mac: Optional[str]) -> str:
    if not mac:
        return "unknown"
    try:
        from core.fingerprint import lookup_oui
        return lookup_oui(mac) or "unknown"
    except Exception:
        return "unknown"


# ─────────────────────────── inventory loop ───────────────────────────

def run_passive(pcap: Optional[str] = None, iface: Optional[str] = None,
                window: float = 60.0, frames: Optional[Iterable[bytes]] = None,
                matchers: Optional[dict] = None, detections_out: Optional[list] = None,
                on_progress: Optional[Callable] = None, progress_interval: float = 1.0) -> list:
    """Capture (offline pcap OR live SPAN/TAP OR a supplied frame iterable), dissect passively, and
    return a per-host DiscoveredDevice inventory. Transmits nothing. One of pcap/iface/frames selects
    the source; `window` bounds a live capture (seconds). When `matchers` (from
    core.detect_match.build_matchers) and `detections_out` are both given, each packet's payload is
    also tested against the check corpus' detection_hints and matches are appended to detections_out —
    the native Observed-Activity path, still zero-transmit."""
    reset_tls_flows()   # fresh TLS reassembly state per run
    # (ts, frame) source: real packet time for a pcap, capture time live, None for a frame iterable.
    if frames is not None:
        timed: Iterable[tuple] = ((None, f) for f in frames)
    elif pcap is not None:
        timed = capture_pcap_timed(pcap)
    elif iface is not None:
        timed = ((time.time(), f) for f in capture_live(iface, window))
    else:
        return []

    match_frame = None
    tracker = None
    if matchers is not None and detections_out is not None:
        from core.detect_match import match_frame, BehavioralTracker  # lazy: avoid import cycle
        if matchers.get("behavioral"):
            tracker = BehavioralTracker(matchers["behavioral"])  # volumetric/stateful detections

    inventory: dict = {}
    last_progress = time.time()
    for ts, frame in timed:
        pkt = decap(frame)
        if pkt is None:
            continue
        if match_frame is not None:
            detections_out.extend(match_frame(pkt, ts, matchers))
            if tracker is not None:
                tracker.feed(pkt, ts)
        routed = dispatch(pkt)
        if routed is not None:
            res, proto, src_ip, src_mac = routed
            _upsert(inventory, res, proto, src_ip, src_mac)
        # Stream partial results (live capture): hand the current inventory snapshot to the caller
        # every progress_interval seconds. Behavioral detections are only finalized at emit() below.
        if on_progress is not None and (time.time() - last_progress) >= progress_interval:
            try:
                on_progress(list(inventory.values()), list(detections_out or []))
            except Exception:
                pass
            last_progress = time.time()
    if tracker is not None:
        detections_out.extend(tracker.emit())  # evaluate volumetric thresholds at end of capture
    return list(inventory.values())


def _upsert(inventory: dict, res: FingerprintResult, proto, src_ip, src_mac) -> None:
    """Merge one parsed identity into the per-host asset record (keyed by IP, else MAC)."""
    key = src_ip or src_mac
    if key is None:
        return
    now = _now()
    dev = inventory.get(key)
    protoname = res.extra.get("protocol", proto if isinstance(proto, str) else None) or _proto_label(proto)
    # Protocol-specific keys the parser attached (station_name, object_name, product_code, vendor_id,
    # idcode, instance, ...) are carried onto the asset; "protocol" is consumed above for protoname.
    proto_extra = {k: v for k, v in res.extra.items() if k != "protocol"}
    if dev is None:
        extra = dict(proto_extra)
        extra.update({"model": res.model, "firmware": res.firmware, "serial": res.serial,
                      "confidence": res.confidence, "protocols": [protoname], "matched_cves": []})
        dev = DiscoveredDevice(
            ip=src_ip or "", mac=src_mac, vendor=res.vendor, method=res.method,
            first_seen=now, last_seen=now, extra=extra,
        )
        inventory[key] = dev
        return
    dev.last_seen = now
    protos = dev.extra.setdefault("protocols", [])
    if protoname and protoname not in protos:
        protos.append(protoname)
    # Upgrade identity if this sighting is more informative (known vendor/model beats "unknown").
    if dev.vendor in ("unknown", "") and res.vendor not in ("unknown", ""):
        dev.vendor = res.vendor
        dev.method = res.method
    for fld in ("model", "firmware", "serial"):
        cur = dev.extra.get(fld, "unknown")
        new = getattr(res, fld)
        if cur in ("unknown", "", None) and new not in ("unknown", "", None):
            dev.extra[fld] = new
    for k, v in proto_extra.items():  # fill any protocol-specific key we don't already have
        if k not in dev.extra and v not in (None, "", "unknown"):
            dev.extra[k] = v


def _proto_label(proto) -> str:
    if isinstance(proto, str):
        return proto
    return {44818: "enip", 2222: "enip", 47808: "bacnet", 9600: "fins", 502: "modbus",
            102: "mms", 1911: "fox", 1740: "codesys_v3", 1741: "codesys_v3",
            1742: "codesys_v3", 1743: "codesys_v3", 4712: "c37118", 4713: "c37118",
            18245: "ge_srtp"}.get(proto, str(proto))


# ─────────────────────────── hybrid: ingest ICSNPP / Zeek logs ───────────────────────────
# The hybrid path (approved plan): when a sensor already runs Zeek + CISA/INL ICSNPP (the Malcolm /
# Hedgehog stack), consume its identity logs into the SAME DiscoveredDevice inventory instead of
# re-dissecting raw frames. Read-only. The field map is extensible per ICSNPP log; the ICSNPP ENIP CIP
# identity log is the worked example (its fields are stable across the ICSNPP release).

def read_zeek_tsv(path: str) -> list:
    """Parse a Zeek TSV log (the '#fields'/'#separator' header format) into a list of row dicts.
    Returns [] (never raises) on any read/format error. Handles the \\x09 default separator."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return []
    sep = "\t"
    fields: list = []
    rows: list = []
    for line in lines:
        if line.startswith("#separator"):
            val = line.split(None, 1)[1].strip() if " " in line else "\t"
            sep = val.encode().decode("unicode_escape") if val.startswith("\\x") else val
        elif line.startswith("#fields"):
            fields = line.split(sep)[1:]
        elif line.startswith("#"):
            continue
        elif fields and line:
            parts = line.split(sep)
            rows.append({fields[i]: parts[i] for i in range(min(len(fields), len(parts)))})
    return rows


# ICSNPP identity-log field specs — field NAMES verified against cisagov/ICSNPP real baseline logs +
# READMEs (2026-11-11). Per log: the device-IP field, an optional row filter (field, value), and a spec
# per identity field. A spec is {"field": name} (optional {"id_field": numeric-ODVA fallback}),
# {"const": value}, or {"prefix": p, "field": name}. Device attribution differs by protocol: a
# request/response identity (CIP, synchrophasor CFG) comes from the responder (id.resp_h); a BACnet I-Am
# is broadcast BY the device (source_h). Extend this table for more ICSNPP logs.
_CIP_IDENTITY_SPEC = {
    "ip": "id.resp_h",
    "vendor": {"field": "vendor_name", "id_field": "vendor_id"},  # ICSNPP resolves vendor_name already
    "model": {"field": "product_name"},
    "firmware": {"field": "revision"},
    "serial": {"field": "serial_number"},
}
_ZEEK_IDENTITY_LOGS = {
    "cip_identity": _CIP_IDENTITY_SPEC,     # icsnpp-enip List Identity
    "enip_identity": _CIP_IDENTITY_SPEC,    # alias across ICSNPP releases
    "bacnet_discovery": {                   # icsnpp-bacnet I-Am (device originates the broadcast)
        "ip": "source_h",
        "filter": ("pdu_service", "i-am"),
        "vendor": {"field": "vendor"},      # ICSNPP resolves the vendor name
        "model": {"prefix": "device_", "field": "instance_number"},
    },
    "synchrophasor_cfg_detail": {           # icsnpp-synchrophasor CFG (C37.118) — station name = identity
        "ip": "id.resp_h",
        "vendor": {"const": "unknown"},     # C37.118 is an open, multi-vendor standard
        "model": {"field": "station_name"},
    },
}

_ZEEK_EMPTY = ("-", "(empty)", "")


def _resolve_zeek_field(row: dict, spec, lookup_odva_vendor) -> str:
    if spec is None:
        return "unknown"
    if "const" in spec:
        return spec["const"]
    val = row.get(spec.get("field", ""), "")
    if val in _ZEEK_EMPTY and "id_field" in spec:
        raw = row.get(spec["id_field"], "")
        if raw.isdigit():
            return lookup_odva_vendor(int(raw))
    if val in _ZEEK_EMPTY:
        return "unknown"
    return spec.get("prefix", "") + val


# ── Multi-row (pivot) ICSNPP logs: one row per MEI object / per property -> one device identity ──
# modbus_read_device_identification (FC43/0x0E) and bacnet_property emit a row PER object/property, so
# they must be grouped per device and the identity fields collected ACROSS rows (unlike the single-row
# _ZEEK_IDENTITY_LOGS). Field names verified: bacnet_property vs the cisagov/ICSNPP baseline log; modbus
# RDI vs the icsnpp-modbus main.zeek record + MEI object-id map (object_id_code logged as hex: "0x00"=
# VendorName, "0x02"=MajorMinorRevision, "0x04"=ProductName, "0x05"=ModelName; value in object_id).

def _pivot_bacnet_property(rows: list) -> list:
    """Group bacnet_property rows (object_type==device) by (id.resp_h, instance) into one identity,
    keeping each property's real (non-'-') value. Returns [(FingerprintResult, device_ip), ...]."""
    groups: dict = {}
    for r in rows:
        if r.get("object_type") != "device":
            continue
        ip = r.get("id.resp_h")
        if not ip or ip in _ZEEK_EMPTY:
            continue
        val = r.get("value")
        if val in _ZEEK_EMPTY:
            continue
        groups.setdefault((ip, r.get("instance_number")), {})[r.get("property")] = val
    out = []
    for (ip, inst), props in groups.items():
        out.append((FingerprintResult(
            vendor=props.get("vendor-name", "unknown") or "unknown",
            model=props.get("model-name", "unknown") or "unknown",
            firmware=props.get("firmware-revision", "unknown") or "unknown",
            confidence="high", method="zeek_bacnet_property",
            extra={"protocol": "bacnet", "object_name": props.get("object-name"),
                   "application_software_version": props.get("application-software-version"),
                   "instance": inst}), ip))
    return out


def _pivot_modbus_rdi(rows: list) -> list:
    """Group modbus_read_device_identification response rows by device (id.resp_h) into one identity,
    collecting the MEI objects (object_id_code hex -> object_id value)."""
    groups: dict = {}
    for r in rows:
        if (r.get("request_response") or "").upper() == "REQUEST":
            continue  # only responses carry the object values; requests just name which to read
        ip = r.get("id.resp_h")
        if not ip or ip in _ZEEK_EMPTY:
            continue
        code = (r.get("object_id_code") or "").lower()
        val = r.get("object_id")
        if not code or val in _ZEEK_EMPTY:
            continue
        groups.setdefault(ip, {})[code] = val
    out = []
    for ip, objs in groups.items():
        out.append((FingerprintResult(
            vendor=objs.get("0x00", "unknown") or "unknown",                    # VendorName
            model=objs.get("0x04") or objs.get("0x05", "unknown") or "unknown",  # ProductName / ModelName
            firmware=objs.get("0x02", "unknown") or "unknown",                   # MajorMinorRevision
            confidence="high", method="zeek_modbus_rdi",
            extra={"protocol": "modbus", "product_code": objs.get("0x01")}), ip))
    return out


def _pivot_dce_rpc_opc(rows: list) -> list:
    """Flag OPC Classic (DA/A&E/HDA over DCOM) servers from Zeek dce_rpc.log by their interface UUIDs
    or Zeek-resolved endpoint names. The DCE/RPC responder (id.resp_h) is the OPC server. OPC Classic
    rides DCOM on dynamically-negotiated high ports, so Zeek's protocol-follows dce_rpc.log -- not a
    fixed-port listener -- is the passive vector. Zero-transmit (log-derived). See core/dcom.py."""
    from core.dcom import classify_opc_dcerpc_endpoint
    servers: dict = {}
    for r in rows:
        label = classify_opc_dcerpc_endpoint(r.get("endpoint") or r.get("uuid") or "")
        if not label:
            continue
        ip = r.get("id.resp_h")
        if not ip or ip in _ZEEK_EMPTY:
            continue
        servers.setdefault(ip, set()).add(label)
    out = []
    for ip, labels in servers.items():
        out.append((FingerprintResult(
            vendor="unknown", model="OPC Classic (DCOM) server",
            confidence="high", method="zeek_dce_rpc_opc",
            extra={"protocol": "opc_classic", "opc_interfaces": sorted(labels),
                   "note": "legacy OPC Classic over DCOM (insecure-by-design transport)"}), ip))
    return out


def _make_presence_pivot(model: str, protocol: str):
    """Build a Zeek-log pivot that attributes protocol PRESENCE to each distinct responder (id.resp_h =
    the server/device for client->server ICS protocols). Yields (FingerprintResult, ip, None). Robust
    across ICSNPP releases: needs only the standard id.resp_h conn field, no protocol-specific schema.
    This is the broad passive-depth expansion for protocols that have an active probe but had no passive
    path (DNP3, S7comm, GE-SRTP, Omron-FINS, BSAP, PROFINET, Genisys, HART-IP)."""
    def _pivot(rows: list) -> list:
        seen: dict = {}
        for r in rows:
            ip = r.get("id.resp_h") or r.get("id_resp_h")
            if ip and ip not in _ZEEK_EMPTY:
                seen[ip] = True
        return [(FingerprintResult(vendor="unknown", model=model, confidence="high",
                                   method=f"zeek_{protocol}", extra={"protocol": protocol}), ip, None)
                for ip in seen]
    return _pivot


def _pivot_iec61850_goose(rows: list) -> list:
    """IEC 61850 GOOSE publisher IEDs from a Zeek goose.log. GOOSE is L2 multicast (EtherType 0x88B8),
    has no IP, so the device is keyed by the publisher's SOURCE MAC, with its control-block/dataset refs.
    Yields (FingerprintResult, None, mac). Field names tried across ICSNPP releases."""
    pubs: dict = {}
    for r in rows:
        mac = (r.get("source") or r.get("src") or r.get("source_mac") or r.get("orig_l2_addr") or "").lower()
        if not mac or mac in _ZEEK_EMPTY:
            continue
        info = pubs.setdefault(mac, {})
        for k_out, k_in in (("gocb_ref", "gocbRef"), ("go_id", "goID"), ("dataset", "datSet"),
                            ("conf_rev", "confRev"), ("appid", "gooseAppid")):
            v = r.get(k_in) or r.get(k_in.lower())
            if v is not None and v not in _ZEEK_EMPTY and k_out not in info:
                info[k_out] = v
    return [(FingerprintResult(vendor="unknown", model="IEC 61850 GOOSE publisher (IED)", confidence="high",
                               method="zeek_iec61850_goose", extra={"protocol": "iec61850_goose", **info}), None, mac)
            for mac, info in pubs.items()]


def _pivot_iec61850_sv(rows: list) -> list:
    """IEC 61850 Sampled Values publisher IEDs from a Zeek sv.log (L2 multicast EtherType 0x88BA; MAC-keyed)."""
    pubs: dict = {}
    for r in rows:
        mac = (r.get("source") or r.get("src") or r.get("orig_l2_addr") or "").lower()
        if not mac or mac in _ZEEK_EMPTY:
            continue
        info = pubs.setdefault(mac, {})
        for k_out, k_in in (("sv_id", "svID"), ("appid", "svAppid"), ("conf_rev", "confRev")):
            v = r.get(k_in) or r.get(k_in.lower())
            if v is not None and v not in _ZEEK_EMPTY and k_out not in info:
                info[k_out] = v
    return [(FingerprintResult(vendor="unknown", model="IEC 61850 Sampled Values publisher (IED)",
                               confidence="high", method="zeek_iec61850_sv",
                               extra={"protocol": "iec61850_sv", **info}), None, mac)
            for mac, info in pubs.items()]


def _pivot_opcua_endpoints(rows: list) -> list:
    """OPC UA server identity from a Zeek opcua_binary_create_session_endpoints.log (ICSNPP). The
    server returns its own ApplicationDescription in the CreateSession/GetEndpoints response, so this
    upgrades the plain opcua_binary presence pivot to real identity: applicationName/Uri, productUri,
    endpoint URL, application type -- keyed by the connection responder (the OPC UA server)."""
    servers: dict = {}
    for r in rows:
        ip = r.get("id.resp_h") or r.get("id_resp_h")
        if not ip or ip in _ZEEK_EMPTY:
            continue
        info = servers.setdefault(ip, {})
        for k_out, k_in in (("application_uri", "application_uri"), ("product_uri", "product_uri"),
                            ("application_name", "text"), ("endpoint_url", "endpoint_url")):
            v = r.get(k_in)
            if v and v not in _ZEEK_EMPTY and k_out not in info:
                info[k_out] = v
        at = r.get("application_type")
        if at and at not in _ZEEK_EMPTY and "application_type" not in info:
            try:
                info["application_type"] = _OPCUA_APP_TYPE.get(int(at), at)
            except (TypeError, ValueError):
                info["application_type"] = at
    out = []
    for ip, info in servers.items():
        model = info.get("application_name") or info.get("application_uri") or "OPC UA server"
        out.append((FingerprintResult(vendor=_opcua_vendor_from(info), model=model, confidence="high",
                                      method="zeek_opcua_endpoints", extra={"protocol": "opcua", **info}), ip, None))
    return out


def _pivot_omron_fins(rows: list) -> list:
    """Omron FINS controller identity from a Zeek omron_fins_detail.log (ICSNPP). A FINS Controller Data
    Read response carries the PLC's model + version, so this upgrades the fins presence pivot to real
    identity -- keyed by the connection responder (the PLC)."""
    plcs: dict = {}
    for r in rows:
        ip = r.get("id.resp_h") or r.get("id_resp_h")
        if not ip or ip in _ZEEK_EMPTY:
            continue
        info = plcs.setdefault(ip, {})
        for k_out, k_in in (("model", "controller_model"), ("firmware", "controller_version")):
            v = r.get(k_in)
            if v and v not in _ZEEK_EMPTY and k_out not in info:
                info[k_out] = v
    out = []
    for ip, info in plcs.items():
        out.append((FingerprintResult(vendor="Omron", model=info.get("model") or "Omron FINS device",
                                      firmware=info.get("firmware", "unknown"), confidence="high",
                                      method="zeek_omron_fins", extra={"protocol": "fins", **info}), ip, None))
    return out


def _pivot_roc_sys_cfg(rows: list) -> list:
    """Emerson ROC / ROC Plus identity from a Zeek roc_plus_sys_cfg.log (ICSNPP). The opcode-6 System
    Configuration carries the ROC type, subtype, and opcode revision -- upgrading the roc_plus presence
    pivot to real identity, keyed by the responder (the RTU)."""
    from core.roc_plus import _ROC_TYPE_NAMES
    devs: dict = {}
    for r in rows:
        ip = r.get("id.resp_h") or r.get("id_resp_h")
        if not ip or ip in _ZEEK_EMPTY:
            continue
        info = devs.setdefault(ip, {})
        for k_out, k_in in (("type_of_roc", "type_of_roc"), ("roc_subtype", "subtype"),
                            ("opcode6_revision", "opcode_revision"), ("system_mode", "system_mode")):
            v = r.get(k_in)
            if v and v not in _ZEEK_EMPTY and k_out not in info:
                info[k_out] = v
    out = []
    for ip, info in devs.items():
        raw = info.pop("type_of_roc", None)
        model = "Emerson ROC / ROC Plus RTU"
        if raw:
            name = None
            try:
                name = _ROC_TYPE_NAMES.get(int(raw))
            except (TypeError, ValueError):
                name = raw                                   # ICSNPP already gave a decoded name string
            model = f"Emerson {name} RTU" if name else f"Emerson ROC RTU (type {raw})"
            info["roc_type"] = raw
        out.append((FingerprintResult(vendor="Emerson", model=model,
                                      firmware=info.get("opcode6_revision", "unknown") or "unknown",
                                      confidence="high", method="zeek_roc_sys_cfg",
                                      extra={"protocol": "roc_plus", **info}), ip, None))
    return out


_ZEEK_PIVOT_LOGS = {
    "bacnet_property": _pivot_bacnet_property,
    "opcua_binary_create_session_endpoints": _pivot_opcua_endpoints,  # OPC UA server identity (upgrade)
    "omron_fins_detail": _pivot_omron_fins,                           # Omron FINS controller identity (upgrade)
    "roc_plus_sys_cfg": _pivot_roc_sys_cfg,                           # Emerson ROC identity (upgrade)
    "modbus_read_device_identification": _pivot_modbus_rdi,
    "dce_rpc": _pivot_dce_rpc_opc,
    # ICSNPP protocol-presence ingest (2026-11-16 expansion) — responder attributed as the device:
    "dnp3": _make_presence_pivot("DNP3 outstation", "dnp3"),
    "s7comm": _make_presence_pivot("S7comm PLC", "s7comm"),
    "ge_srtp": _make_presence_pivot("GE SRTP PLC", "ge_srtp"),
    "omron_fins": _make_presence_pivot("Omron FINS device", "fins"),
    "bsap_ip": _make_presence_pivot("BSAP / Emerson ControlWave RTU", "bsap"),
    "bsap": _make_presence_pivot("BSAP / Emerson ControlWave RTU", "bsap"),
    "profinet": _make_presence_pivot("PROFINET device", "profinet"),
    "genisys": _make_presence_pivot("Genisys RTU (rail signaling)", "genisys"),
    "hart_ip": _make_presence_pivot("HART-IP gateway", "hartip"),
    "roc_plus": _make_presence_pivot("Emerson ROC / ROC Plus RTU", "roc_plus"),
    "roc": _make_presence_pivot("Emerson ROC / ROC Plus RTU", "roc_plus"),
    # ICSNPP coverage completion (2026-11-16 research pass) — remaining IP-based parsers:
    "opcua_binary": _make_presence_pivot("OPC UA server", "opcua"),          # fills the OPC-UA passive gap
    "c1222": _make_presence_pivot("ANSI C12.22 smart meter / node", "c1222"),  # AMI / utility metering
    "profinet_io_cm": _make_presence_pivot("PROFINET device", "profinet"),   # PROFINET I/O context manager log
    # IEC 61850 substation (L2 multicast, MAC-keyed IEDs):
    "iec61850_goose": _pivot_iec61850_goose,
    "goose": _pivot_iec61850_goose,
    "iec61850_sv": _pivot_iec61850_sv,
    "iec61850_sampled_values": _pivot_iec61850_sv,
}


def ingest_zeek_logs(log_dir: str) -> list:
    """Read a directory of Zeek/ICSNPP logs and return a DiscoveredDevice inventory, merged the same way
    as run_passive(). Read-only; fails closed (returns []) if the dir or logs are absent. Single-row
    identity logs (CIP/ENIP, BACnet-discovery I-Am, synchrophasor CFG) via `_ZEEK_IDENTITY_LOGS`; the
    multi-row per-object/per-property logs (modbus RDI, bacnet_property) via `_ZEEK_PIVOT_LOGS`, grouped
    into one device each and merged with the rest. (Real operational Zeek logs carry the '#fields'
    header this needs; only the repos' btest-diff baselines strip it.)"""
    import os
    from core.fingerprint import lookup_odva_vendor
    inventory: dict = {}
    for base, spec in _ZEEK_IDENTITY_LOGS.items():
        for ext in (".log", ".tsv"):
            path = os.path.join(log_dir, base + ext)
            if not os.path.exists(path):
                continue
            filt = spec.get("filter")
            for row in read_zeek_tsv(path):
                if filt and row.get(filt[0]) != filt[1]:
                    continue
                ip = row.get(spec["ip"])
                if not ip or ip in _ZEEK_EMPTY:
                    continue
                res = FingerprintResult(
                    vendor=_resolve_zeek_field(row, spec.get("vendor"), lookup_odva_vendor),
                    model=_resolve_zeek_field(row, spec.get("model"), lookup_odva_vendor),
                    firmware=_resolve_zeek_field(row, spec.get("firmware"), lookup_odva_vendor),
                    serial=_resolve_zeek_field(row, spec.get("serial"), lookup_odva_vendor),
                    confidence="high", method=f"zeek_{base}",
                )
                _upsert(inventory, res, base, ip, None)
    for base, pivot_fn in _ZEEK_PIVOT_LOGS.items():
        for ext in (".log", ".tsv"):
            path = os.path.join(log_dir, base + ext)
            if not os.path.exists(path):
                continue
            for item in pivot_fn(read_zeek_tsv(path)):
                # pivots yield (res, ip) [IP-keyed] or (res, ip, mac) [L2/MAC-keyed, e.g. GOOSE/SV]
                res, ip, mac = item if len(item) == 3 else (item[0], item[1], None)
                _upsert(inventory, res, base, ip, mac)
    return list(inventory.values())


# ─────────────────────────── CVE correlation (passive, identity-only) ───────────────────────────

_VENDOR_STOP = {"corporation", "corp", "inc", "incorporated", "ltd", "co", "gmbh", "ag", "llc",
                "company", "the", "and", "systems", "technologies", "technology", "electric",
                "electronics", "automation", "group"}


def _norm(s) -> str:
    return " ".join(str(s or "").split()).casefold()


def _vtokens(s) -> set:
    """Significant vendor tokens (drop corporate-suffix noise) for alias-tolerant vendor matching."""
    return {t for t in re.split(r"[^a-z0-9]+", _norm(s)) if t and t not in _VENDOR_STOP}


def _vendor_alias_match(dev_vendor, cand_vendor) -> bool:
    """True when the two vendor strings denote the same vendor despite format differences
    (e.g. 'Rockwell Automation / Allen-Bradley' vs 'Rockwell Automation'; 'Omron' vs
    'Omron Corporation'). Token-subset either direction, on the significant tokens."""
    dv, cv = _vtokens(dev_vendor), _vtokens(cand_vendor)
    if not dv or not cv:
        return False
    return cv.issubset(dv) or dv.issubset(cv)


def _model_match(dev_model, cand_product) -> bool:
    """A vendor-only candidate (no product) matches on vendor alone; otherwise require the device model
    and the candidate product to contain one another (handles family suffixes like 1756-ENBT/A)."""
    if not cand_product:
        return True
    dm, cm = _norm(dev_model), _norm(cand_product)
    if not dm or dm == "unknown" or not cm:
        return False
    return cm in dm or dm in cm


def correlate_cves(devices: list, registry=None) -> list:
    """Match each discovered asset's vendor+model against the CVE candidate corpus (the 322 stubs the
    4 feeds emit, each `cve_id` + fingerprint_precondition={vendor,product}). Zero packets — pure
    identity correlation. Annotates DiscoveredDevice.extra['matched_cves'] and returns a findings list.
    Candidates needing an active `protocol_probe`/`protocol_only` are skipped (not passive-safe).

    Matching is IDENTITY-ONLY and alias-tolerant (vendor token-subset + model containment) — it does
    NOT do firmware/version-range gating, so an asset's CVE list can include advisories already fixed in
    the running firmware. Version gating is the phase-2 follow-up (see the passive-mode plan)."""
    if registry is None:
        try:
            from core.registry import CheckRegistry
            registry = CheckRegistry().load()
        except Exception:
            return []
    try:
        candidates = registry.candidates()
    except Exception:
        return []

    # Prune by vendor token so matching isn't O(devices * all-candidates): token -> [candidate meta].
    by_token: dict = {}
    usable = []
    for meta in candidates:
        precond = getattr(meta, "fingerprint_precondition", None) or {}
        if precond.get("protocol_only") or "protocol_probe" in precond or not precond.get("vendor"):
            continue
        usable.append(meta)
        for tok in _vtokens(precond.get("vendor")):
            by_token.setdefault(tok, []).append(meta)

    findings: list = []
    for dev in devices:
        if _norm(dev.vendor) in ("", "unknown"):
            continue
        dev_toks = _vtokens(dev.vendor)
        cand_seen = set()
        candset = []
        for tok in dev_toks:
            for meta in by_token.get(tok, ()):
                if id(meta) not in cand_seen:
                    cand_seen.add(id(meta))
                    candset.append(meta)
        model_hits, vendor_hits = [], []
        for meta in candset:
            precond = meta.fingerprint_precondition or {}
            if not _vendor_alias_match(dev.vendor, precond.get("vendor")):
                continue
            product = precond.get("product")
            if product:
                if not _model_match(dev.extra.get("model"), product):
                    continue
                scope = "model"      # product confirmed against the captured model
            elif _norm(dev.extra.get("model")) in ("", "unknown"):
                scope = "vendor"     # vendor-wide candidate, and we have no model to rule it out
            else:
                continue             # vendor-wide candidate but we HAVE a specific model -> don't assert
            # Version narrowing: suppress a candidate whose affected range EXCLUDES this firmware;
            # True = firmware in range (version-confirmed), None = unknown firmware / no version spec.
            vstatus = precondition_version_status(precond, dev.extra.get("firmware"))
            if vstatus is False:
                continue
            ds = getattr(meta, "disclosure_status", None)
            (model_hits if scope == "model" else vendor_hits).append(meta.cve_id or meta.check_id)
            findings.append({
                "ip": dev.ip, "vendor": dev.vendor, "model": dev.extra.get("model"),
                "cve_id": meta.cve_id, "candidate": meta.check_id, "scope": scope,
                "version_confirmed": vstatus is True,
                "disclosure_status": getattr(ds, "value", str(ds)) if ds else None,
                "method": "passive_identity_match",
            })
        if model_hits:
            dev.extra["matched_cves"] = sorted(set(m for m in model_hits if m))
        if vendor_hits:
            dev.extra["vendor_advisories"] = sorted(set(m for m in vendor_hits if m))
    return findings


def findings_to_results(findings: list, devices: Optional[list] = None) -> list:
    """Convert passive CVE findings into FINGERPRINT_ONLY CheckResult objects so they render through the
    SAME findings report as active scan findings (core/reporter.py:build_summary reads any record with a
    check_id + no type; status 'likely-affected-fingerprint-only'). Model-confirmed matches are HIGH
    confidence; vendor-wide (model-not-confirmed) matches are LOW."""
    from core.check import CheckResult, CheckStatus, Confidence
    proto_by_ip: dict = {}
    for d in (devices or []):
        protos = d.extra.get("protocols") or []
        proto_by_ip[d.ip] = protos[0] if protos else "passive"
    out = []
    for f in findings:
        scope = f.get("scope", "model")
        label = f.get("cve_id") or f.get("candidate")
        desc = f"Passive identity match ({scope}): {f.get('vendor')} {f.get('model')} -> {label}"
        if f.get("version_confirmed"):
            desc += " [firmware version confirmed in affected range]"
        elif scope != "model":
            desc += " (vendor-wide; model not confirmed)"
        else:
            desc += " (version not confirmed)"
        out.append(CheckResult(
            check_id=f.get("candidate"),
            protocol=proto_by_ip.get(f.get("ip"), "passive"),
            target=f.get("ip"),
            status=CheckStatus.FINGERPRINT_ONLY,
            confidence=Confidence.HIGH if scope == "model" else Confidence.LOW,
            cve_id=f.get("cve_id"),
            description=desc,
        ))
    return out


# ─────────────────────── bridge: passive inventory -> active target list ───────────────────────
# Hand the zero-transmit inventory to the active scanner as a pre-hinted target list. The identity a
# passive sighting carries (vendor / model / firmware) maps 1:1 onto Target's operator-hint fields
# (vendor_hint / product_hint / version_hint via Target.from_dict's vendor/product/version keys), and
# the active engine already treats those as FALLBACKS a live fingerprint overrides (scan_engine.py
# _apply_vendor_hint_fallback only fills still-unknown fields) — so passive identity is carried as a
# hint, never stamped as a confirmed fingerprint. The payoff: checks that REQUIRE a product_hint become
# runnable, firmware feeds the version gate without the scanner reconnecting to re-fingerprint, and the
# active sweep is scoped to endpoints passive already found.

# Canonical TCP/UDP port per passive protocol label (inverse of _proto_label's numeric map; one port
# per label so the active scanner has a concrete service to probe). Labels with no single service port
# (arp, bare presence) are intentionally absent -> those endpoints emit a host-only target entry.
_LABEL_PORT = {
    "enip": 44818, "bacnet": 47808, "fins": 9600, "modbus": 502, "mms": 102,
    "s7comm": 102, "fox": 1911, "codesys_v3": 1740, "c37118": 4712, "ge_srtp": 18245,
}


def devices_to_target_entries(devices: list) -> list:
    """Convert the passive DiscoveredDevice inventory into active target-list entries (the dict shape
    load_target_inventory/Target.from_dict consume: host/port/protocol + vendor/product/version hints +
    metadata). One entry per (device, port-mappable protocol) so each entry names a concrete service to
    probe; a device whose only protocols have no service port (e.g. ARP-only) emits one host-only entry.
    Unknown vendor/model/firmware are OMITTED (never emitted as a 'unknown' hint). Zero transmit — this
    only reshapes already-captured identity."""
    entries = []
    for d in devices:
        host = (d.ip or "").strip()
        if not host:
            continue  # MAC-only sighting: nothing to scan by host
        base = {"host": host}
        if d.vendor and d.vendor not in ("unknown", ""):
            base["vendor"] = d.vendor
        model = d.extra.get("model")
        if model and model not in ("unknown", "", None):
            base["product"] = model
        fw = d.extra.get("firmware")
        if fw and fw not in ("unknown", "", None):
            base["version"] = fw
        protos = [p for p in (d.extra.get("protocols") or []) if p]
        meta = {"discovered_via": "passive", "method": d.method or "passive"}
        if d.mac:
            meta["mac"] = d.mac
        if protos:
            meta["protocols"] = protos
        conf = d.extra.get("confidence")
        if conf:
            meta["passive_confidence"] = conf
        cves = d.extra.get("matched_cves")
        if cves:
            meta["passive_matched_cves"] = cves

        ports = [(p, _LABEL_PORT[p]) for p in protos if p in _LABEL_PORT]
        if not ports:
            e = dict(base)
            e["metadata"] = _copy.deepcopy(meta)  # own copy per entry (no YAML anchor/alias)
            entries.append(e)
            continue
        for proto, port in ports:
            e = dict(base)
            e["port"] = port
            e["protocol"] = proto
            e["metadata"] = _copy.deepcopy(meta)
            entries.append(e)
    return entries


def write_target_inventory(devices: list, path: str) -> int:
    """Write the passive inventory as a YAML target-inventory file (top-level `targets:` list) that the
    active scanner loads with core/target.py:load_target_inventory. Returns the number of entries
    written. The emitted hints flow into Target.{vendor,product,version}_hint and then the fingerprint/
    version gate. No credentials are ever emitted (the loader forbids plaintext secrets anyway)."""
    import yaml
    entries = devices_to_target_entries(devices)
    header = (
        "# Auto-generated by icsScanner passive mode (discover sniff --emit-targets).\n"
        "# Each entry carries vendor/product/version HINTS observed passively (zero transmit); they seed\n"
        "# Target.{vendor,product,version}_hint and are overridden by any live active fingerprint.\n"
        "# Review before running an ACTIVE scan against these hosts.\n"
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(header)
        yaml.safe_dump({"targets": entries}, fh, default_flow_style=False, sort_keys=False)
    return len(entries)
