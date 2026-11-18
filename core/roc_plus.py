"""Emerson ROC / ROC Plus protocol — active identity probe + passive/response parser.

ROC Plus is Emerson's Remote Operations Controller protocol (ROC800, ROC800L, FloBoss, DL8000) used
across oil & gas and water/wastewater RTUs. Over IP it runs on TCP/UDP port 4000. Each message is:

    roc_unit(1) roc_group(1) host_unit(1) host_group(1) opcode(1) length(1) [data ...] crc16(2, LE)

(minimum 8 bytes, maximum 248). The CRC is CRC-16/MODBUS (poly 0x8005 reflected, init 0xFFFF, no final
xor), appended little-endian — verified against cisagov/icsnpp-roc-plus's own pcap-builder.

Opcode 6 ("System Configuration") is a benign, no-payload READ whose response returns the device's
system mode, security mode, firmware/opcode revision, ROC subtype (series), and ROC type — i.e. device
identity without writing anything or authenticating. That makes it the natural discovery probe: this
module only ever sends an opcode-6 request and parses the reply. It never issues a write/control opcode.

Wire format and opcode-6 request/response layout are grounded in the CISA ICSNPP ROC Plus parser test
tools (testing/tools/pcap-builder.py + payloads/opcode_006.py), not reverse-engineered by guesswork.
"""
import socket

ROC_PLUS_PORT = 4000
_OPCODE_SYSTEM_CONFIG = 6

# roc_type -> a human label where the mapping is well established; otherwise reported numerically.
_ROC_TYPE_NAMES = {
    1: "ROC364", 2: "ROC300", 3: "FloBoss 407", 4: "FloBoss 500-series",
    5: "ROC800-series", 6: "ROC800-series", 7: "FloBoss 107", 8: "DL8000",
    9: "ROC800L", 10: "FB107",
}


def _crc16_modbus(data: bytes) -> int:
    """CRC-16/MODBUS (reflected poly 0xA001, init 0xFFFF, no final xor) — matches ROC Plus framing."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if (crc & 1) else (crc >> 1)
    return crc & 0xFFFF


def build_roc_plus_request(opcode: int, roc_unit: int = 1, roc_group: int = 2,
                           host_unit: int = 1, host_group: int = 0, data: bytes = b"") -> bytes:
    """Assemble a ROC Plus request frame (header + data + little-endian CRC-16/MODBUS)."""
    header = bytes([roc_unit & 0xFF, roc_group & 0xFF, host_unit & 0xFF, host_group & 0xFF,
                    opcode & 0xFF, len(data) & 0xFF])
    msg = header + data
    return msg + _crc16_modbus(msg).to_bytes(2, "little")


def parse_roc_plus_response(data: bytes):
    """Validate a ROC Plus response frame and, for opcode 6, extract device identity.

    Returns a FingerprintResult (ROC presence, plus identity fields when it is an opcode-6 reply) or
    None if the bytes are not a well-formed, CRC-valid ROC Plus frame. Used by both the active probe
    and the passive TCP/4000 sniff adapter."""
    from core.fingerprint import FingerprintResult  # lazy: fingerprint registers this module's probe
    if data is None or len(data) < 8:
        return None
    opcode = data[4]
    length = data[5]
    if 6 + length + 2 > len(data):
        return None
    body = data[:6 + length]
    crc_rx = int.from_bytes(data[6 + length:6 + length + 2], "little")
    if _crc16_modbus(body) != crc_rx:
        return None  # not a valid ROC Plus frame (or not ROC at all) — fail closed

    roc_unit, roc_group = data[0], data[1]
    extra = {"protocol": "roc_plus", "roc_opcode": opcode,
             "roc_address": f"{roc_unit}/{roc_group}"}
    model = "Emerson ROC / ROC Plus RTU"
    firmware = None
    if opcode == _OPCODE_SYSTEM_CONFIG and length >= 17:
        payload = data[6:6 + length]
        system_mode = payload[0]
        security_mode = payload[1]
        revision = payload[3]
        roc_subtype = payload[4]
        roc_type = payload[16]
        series = "Series 1" if roc_subtype == 1 else ("Series 2" if roc_subtype == 0 else f"subtype {roc_subtype}")
        type_name = _ROC_TYPE_NAMES.get(roc_type)
        model = f"Emerson {type_name} RTU" if type_name else f"Emerson ROC RTU (type {roc_type})"
        firmware = f"opcode6 rev {revision}"
        extra.update({
            "roc_type": roc_type,
            "roc_subtype": series,
            "opcode6_revision": revision,
            "system_mode": {0: "firmware-update", 1: "run"}.get(system_mode, system_mode),
            "security_mode": security_mode,
            "model": model,
        })
    return FingerprintResult(vendor="Emerson", model=model, firmware=firmware or "unknown",
                             confidence="high", method="roc_plus_system_config",
                             extra=extra)


def probe_roc_plus_identity(host: str, port: int = ROC_PLUS_PORT, timeout: float = 3.0,
                            roc_unit: int = 1, roc_group: int = 2):
    """Active ROC Plus identity probe: TCP-connect, send one benign opcode-6 (System Configuration)
    request, and parse the reply into a FingerprintResult. Sends no write/control opcode. The ROC's
    configured unit/group default to 1/2 (the common/ICSNPP default); override for a known device."""
    from core.fingerprint import FingerprintResult
    req = build_roc_plus_request(_OPCODE_SYSTEM_CONFIG, roc_unit=roc_unit, roc_group=roc_group)
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(req)
            buf = b""
            while len(buf) < 256:
                chunk = s.recv(256)
                if not chunk:
                    break
                buf += chunk
                if len(buf) >= 8 and 6 + buf[5] + 2 <= len(buf):
                    break
    except (OSError, socket.timeout):
        return FingerprintResult(vendor="unknown", confidence="none", method="roc_plus_system_config")
    res = parse_roc_plus_response(buf)
    if res is None:
        return FingerprintResult(vendor="unknown", confidence="none", method="roc_plus_system_config")
    return res
