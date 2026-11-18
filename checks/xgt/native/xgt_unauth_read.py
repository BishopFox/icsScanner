"""Native check — LS Electric XGT dedicated-protocol UNAUTHENTICATED read probe.

Confirms the vulnerability CLASS behind CVE-2023-22803 / CVE-2023-22804 (CISA ICSA-23-040-02): the
LS Electric XGT "dedicated" Ethernet protocol (TCP 2004) enforces NO authentication (CWE-306). This
check sends a single, benign, READ-ONLY XGT read-request for one word at %MW0 and treats a well-
formed XGT read RESPONSE as proof that the device processed an unauthenticated request. It does NOT
send the consequential create-user (CVE-2023-22804) or change-operation-mode (CVE-2023-22803)
operations — only a read — so it is safe to fire unsupervised, same discipline as the project's
Modbus-read / ENIP-identity probes.

WIRE FORMAT — cross-verified across independent sources (same multi-source rigor as the Schneider
UMAS check), no live device needed for a read:
  - VENDOR SPEC: LS Electric "XGT FEnet I/F Module User's Manual" V2.30 (dedicated protocol, TCP 2004).
  - golanglsplc (github song9063/golanglsplc) — Go frame builder, header "LSIS-XGT".
  - ciaoly/PLC-XGT-protocol-for-Wireshark (xgb.lua) — Lua dissector / parser side.
  (XGT is also dissected by mainline Wireshark.)

Frame (header multi-byte numeric fields are LITTLE-ENDIAN; confirmed by both impls):
  Header (20B): "LSIS-XGT"+0x0000 (10B company id) | PLC-info(2)=0 | CPU(1)=0 | source(1)=0x33 req /
                0x11 resp | invokeID(2) | app-length(2) | FEnet-position(1)=0 | BCC(1)=0
  App (read):   command(2)=0x0054 (resp 0x0055) | data-type(2)=0x0002 word | reserved(2)=0 |
                var-count(2)=1 | name-length(2) | ASCII variable name (e.g. "%MW0")
  Read response (0x0055) app layout: command | data-type | reserved | error-status(2) | ...
                error-status 0x0000 == success.

params schema:
  default_port:  fallback port (XGT dedicated default 2004)
  variable:      device variable to read (default "%MW0" — a Word in the always-present M area)
  timeout:       seconds (default 5.0)
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_COMPANY_ID = b"LSIS-XGT\x00\x00"  # 10-byte company-ID field
_CMD_READ_REQ = 0x0054
_CMD_READ_RESP = 0x0055
_DTYPE_WORD = 0x0002
_SRC_CLIENT = 0x33
_SRC_SERVER = 0x11


def _le16(n: int) -> bytes:
    return struct.pack("<H", n & 0xFFFF)


def build_read_request(variable: str = "%MW0", invoke: int = 1, data_type: int = _DTYPE_WORD) -> bytes:
    """Build an XGT dedicated-protocol read-single-variable request (little-endian numeric fields)."""
    name = variable.encode("ascii", "replace")
    app = (_le16(_CMD_READ_REQ) + _le16(data_type) + _le16(0x0000)
           + _le16(1) + _le16(len(name)) + name)
    header = (_COMPANY_ID + _le16(0x0000) + bytes([0x00]) + bytes([_SRC_CLIENT])
              + _le16(invoke) + _le16(len(app)) + bytes([0x00, 0x00]))
    return header + app


def parse_read_response(data: bytes) -> Optional[dict]:
    """Return {src, command, error_status} for a well-formed XGT response, else None."""
    if len(data) < 28 or not data.startswith(b"LSIS-XGT"):
        return None
    src = data[13]
    command = struct.unpack_from("<H", data, 20)[0]       # app offset 0
    error_status = struct.unpack_from("<H", data, 26)[0]  # app offset 6 (read-response error word)
    return {"src": src, "command": command, "error_status": error_status}


class XgtUnauthReadCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        port = target.port or params.get("default_port", 2004)
        variable = params.get("variable", "%MW0")
        timeout = params.get("timeout", 5.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target.host, port))
            sock.sendall(build_read_request(variable))
            resp = sock.recv(512)
        except OSError:
            return self._result(target, CheckStatus.NOT_APPLICABLE,
                                description=f"no XGT response on {port} — not applicable")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

        parsed = parse_read_response(resp)
        if parsed is None:
            return self._result(target, CheckStatus.NOT_APPLICABLE,
                                description="response was not a well-formed XGT dedicated-protocol frame — not applicable")
        if parsed["src"] == _SRC_SERVER and parsed["command"] == _CMD_READ_RESP:
            if parsed["error_status"] == 0x0000:
                detail = f"unauthenticated XGT read of {variable} SUCCEEDED (error_status=0x0000)"
            else:
                detail = f"device processed the unauthenticated XGT read (error_status=0x{parsed['error_status']:04x})"
            return self._result(target, CheckStatus.CONFIRMED,
                                description=f"LS Electric XGT dedicated protocol answered an UNAUTHENTICATED request on {port}: {detail} — missing authentication (CWE-306, CVE-2023-22803/22804 root cause)")
        return self._result(target, CheckStatus.NOT_APPLICABLE,
                            description=f"XGT header present but no valid read response (src=0x{parsed['src']:02x}, cmd=0x{parsed['command']:04x}) — not applicable")

    def _result(self, target: Target, status: CheckStatus, description: str = "") -> CheckResult:
        return CheckResult(
            check_id=self.metadata.check_id,
            protocol=self.metadata.protocol,
            target=str(target),
            status=status,
            confidence=self.metadata.confidence,
            cve_id=self.metadata.cve_id,
            can_id=self.metadata.can_id,
            severity=self.metadata.severity,
            description=description,
        )


CHECK_CLASS = XgtUnauthReadCheck
