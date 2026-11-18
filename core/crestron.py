"""Crestron CIP (Crestron-over-IP) — passive frame parser + benign active identity probe.

Crestron CIP is the control protocol spoken by Crestron processors, touch panels, and AV devices on
TCP 41794 (the TLS variant, SCIP, is 41796). Every frame is ``[type:1][length:2 big-endian][payload]``;
payloads begin with a 2-byte handle (00 00 on TCP). On connect, a Crestron control processor sends an
unsolicited PROGRAM_STATUS (0x0F) frame announcing its program state -- so a client can confirm a
Crestron device just by connecting and reading the greeting, without registering a panel IP ID or
sending any join/button value. That is exactly what this probe does: connect, read the greeting, close.

Frame types and framing follow the pycrestron-cip reference implementation (the protocol is not publicly
specified by Crestron).
"""
import re
import socket

CRESTRON_CIP_PORT = 41794

# Crestron UDP device-info response (the amplification vector documented by Phenomite/AMP-Research): a
# single control-byte query to UDP 41794 elicits a ~394-byte reply, mostly null padding around two ASCII
# identity strings -- a device name ("DIN-AP-7F74F65F") and a full identity line
# ("DIN-AP3 [v1.503.3318.26859 (Feb 01 2018), #00D93D96] @E-00107f74f65f"). Only the strings are parsed.
_CRESTRON_ASCII_RUN = re.compile(rb"[\x20-\x7e]{6,}")
_CRESTRON_VER = re.compile(r"v([0-9][0-9.]+)")
_CRESTRON_MAC = re.compile(r"@E-([0-9A-Fa-f]{12})")

# From pycrestron-cip FrameType: CONNECT/RESPONSE, DISCONNECT/RESPONSE, DATA, CONNECT_ALT, AUTH/RESPONSE,
# HEARTBEAT/RESPONSE, PROGRAM_STATUS, EXTENDED_DATA.
_CIP_FRAME_TYPES = {0x01, 0x02, 0x03, 0x04, 0x05, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x12}
_CIP_FRAME_NAMES = {0x02: "connect_response", 0x05: "data", 0x0D: "heartbeat",
                    0x0F: "program_status", 0x12: "extended_data"}
_CIP_PROGRAM_STATUS = {0: "loading", 1: "not-running", 2: "ready"}


def parse_crestron_cip_frame(data: bytes):
    """Validate a Crestron CIP frame ([type][len:2 BE][payload]) and return a FingerprintResult, or None.
    Recognises any valid frame type on the wire; extracts the program state from a PROGRAM_STATUS frame."""
    from core.fingerprint import FingerprintResult
    if len(data) < 3:
        return None
    ftype = data[0]
    if ftype not in _CIP_FRAME_TYPES:
        return None
    length = int.from_bytes(data[1:3], "big")
    if 3 + length > len(data):                     # declared payload must be present (reject partial/FP)
        return None
    extra = {"protocol": "crestron_cip", "frame_type": _CIP_FRAME_NAMES.get(ftype, f"0x{ftype:02x}")}
    if ftype == 0x0F and length >= 3:              # PROGRAM_STATUS: handle(2) + status(1)
        extra["program_status"] = _CIP_PROGRAM_STATUS.get(data[5], data[5])
    return FingerprintResult(vendor="Crestron", model="Crestron control system or touch panel (CIP)",
                             confidence="low", method="crestron_cip", extra=extra)


def parse_crestron_cip_udp(data: bytes):
    """Parse a Crestron UDP device-info response (UDP 41794) into a FingerprintResult, or None. The reply
    is dominated by null padding; the identity is in its ASCII runs -- the richest carries model, firmware
    version and the device MAC (``@E-<12 hex>``). To stay low-FP on a port that also carries TLS/other
    UDP, it requires a Crestron-shaped identity (a version token or an ``@E-`` MAC). The short 1-byte query
    has no identity and is ignored. Reference: Phenomite/AMP-Research "Port 41794 - Crestron CIP"."""
    from core.fingerprint import FingerprintResult
    if len(data) < 20:                                    # the query is 1 byte; real responses are long
        return None
    runs = [m.group(0).decode("latin-1") for m in _CRESTRON_ASCII_RUN.finditer(data)]
    if not runs:
        return None
    full = max(runs, key=len)                             # the richest run holds model/version/MAC
    ver = _CRESTRON_VER.search(full)
    mac = _CRESTRON_MAC.search(full)
    if not (ver or mac):                                  # FP guard: demand a Crestron-shaped identity
        return None
    model = full.split(" ", 1)[0].split("[", 1)[0].strip() or "Crestron device"
    extra = {"protocol": "crestron_cip", "transport": "udp", "frame_type": "device_info_response",
             "crestron_identity": full}
    if mac:
        extra["mac"] = mac.group(1).lower()
    name = next((r for r in runs if r is not full and r.split("-")[0] == model.split("-")[0]), None)
    if name:
        extra["device_name"] = name
    return FingerprintResult(vendor="Crestron", model=model,
                             firmware=ver.group(1) if ver else "unknown",
                             confidence="medium", method="crestron_cip_udp", extra=extra)


def probe_crestron_cip_identity(host: str, port: int = CRESTRON_CIP_PORT, timeout: float = 4.0):
    """Benign active probe: connect to a Crestron processor and read its unsolicited greeting (the
    PROGRAM_STATUS frame it sends on connect). Sends nothing -- no panel registration, no join values."""
    from core.fingerprint import FingerprintResult
    none = FingerprintResult(vendor="unknown", confidence="none", method="crestron_cip")
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            buf = b""
            while len(buf) < 512:
                chunk = s.recv(512)
                if not chunk:
                    break
                buf += chunk
                if len(buf) >= 3 and 3 + int.from_bytes(buf[1:3], "big") <= len(buf):
                    break
    except (OSError, socket.timeout):
        return none
    res = parse_crestron_cip_frame(buf)
    return res if res is not None else none
