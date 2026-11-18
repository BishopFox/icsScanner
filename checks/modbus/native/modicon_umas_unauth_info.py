"""Native check — Schneider Electric Modicon UMAS UNAUTHENTICATED PLC-info disclosure.

UMAS (Unified Messaging Application Services) is Schneider's proprietary protocol carried over
Modbus/TCP (port 502) under Modbus function code 0x5A. UMAS function 0x02 ("Get PLC info" / READ_ID)
returns the PLC model, firmware version, hardware id, and device/project name — and it requires NO
authentication: engineering tools (and modicon_exploit.py / modicon-info.nse) call it BEFORE any
reservation or the signed-reservation handshake. On newer PLCs (M340/M580/Quantum) the RESERVATION
is gated by a signed SHA256 hash (so the M221 no-auth-reservation check does NOT apply to them), but
READ_ID stays unauthenticated across the whole Modicon UMAS line — an information-disclosure /
missing-authentication exposure (CWE-306/CWE-200) usable to fingerprint + target the device.

This check sends ONE benign UMAS READ_ID request and treats a UMAS success response (Modbus 0x5A
echoed + UMAS response code 0xFE) as proof the PLC disclosed its identity unauthenticated. It is
READ-ONLY (no reservation, no write, no mode change), safe to fire unsupervised.

WIRE FORMAT — cross-verified (no live PLC needed; XGT/SLMP playbook): Kaspersky ICS-CERT "The secrets
of Schneider Electric's UMAS protocol" (2022) + the OSS dissectors (kushfj/se-umas se_umas_dissector.lua
function table: 0x01 init-comm, 0x02 get-PLC-info, 0x10 take-reservation) + 0xedh/schneider_plc_exploit
(modicon_exploit.py: mbtcp_fnc=b"\\x5a", read_id=b"\\x00\\x02", get_idinfo() parses model/FW/HW from the
response, called pre-auth) + Orange-Cyberdefense awesome-industrial-protocols umas.md / Redpoint
modicon-info.nse. All agree: UMAS rides Modbus fn 0x5A; request = [0x5A][pairing 0x00][UMAS fn]; a
response echoes 0x5A with status 0xFE (success) / 0xFD (error).

Frame (UMAS READ_ID over Modbus/TCP): MBAP(tid, proto=0, len, unit) + 0x5A + 0x00 (pairing/pre-
reservation) + 0x02 (UMAS Get-PLC-info). Response: MBAP + 0x5A + 0xFE + <PLC id/FW/hw/device text>.

params schema:
  default_port:  fallback port (Modbus/TCP 502)
  unit_id:       Modbus unit id (default 0x00; UMAS is a CPU passthrough, unit-agnostic on most PLCs)
  timeout:       seconds (default 5.0)
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_MODBUS_FN_UMAS = 0x5A
_UMAS_READ_ID = 0x02        # "Get PLC info"
_UMAS_PAIRING_UNPAIRED = 0x00
_UMAS_STATUS_OK = 0xFE
_UMAS_STATUS_ERR = 0xFD


def build_umas_read_id_request(unit_id: int = 0x00, tid: int = 0x0001) -> bytes:
    """UMAS READ_ID (Get PLC info) over Modbus/TCP: MBAP + 0x5A + pairing 0x00 + UMAS fn 0x02."""
    pdu = bytes([_MODBUS_FN_UMAS, _UMAS_PAIRING_UNPAIRED, _UMAS_READ_ID])
    mbap = struct.pack(">HHHB", tid, 0x0000, 1 + len(pdu), unit_id & 0xFF)
    return mbap + pdu


def parse_umas_response(data: bytes) -> Optional[dict]:
    """Return {status, info} for a well-formed UMAS Modbus/TCP response (Modbus fn 0x5A @offset 7)."""
    if len(data) < 9 or data[7] != _MODBUS_FN_UMAS:
        return None
    return {"status": data[8], "info": data[9:]}


class ModiconUmasUnauthInfoCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        port = target.port or params.get("default_port", 502)
        unit_id = params.get("unit_id", 0x00)
        timeout = params.get("timeout", 5.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target.host, port))
            sock.sendall(build_umas_read_id_request(unit_id))
            resp = sock.recv(512)
        except OSError:
            return self._result(target, CheckStatus.NOT_APPLICABLE,
                                description=f"no UMAS/Modbus response on {port} — not applicable")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

        parsed = parse_umas_response(resp)
        if parsed is None:
            return self._result(target, CheckStatus.NOT_APPLICABLE,
                                description="response was not a well-formed UMAS (Modbus fn 0x5A) frame — not applicable")
        if parsed["status"] == _UMAS_STATUS_OK:
            n = len(parsed["info"])
            return self._result(target, CheckStatus.CONFIRMED,
                                description=f"Schneider Modicon disclosed PLC identity (UMAS READ_ID / fn 0x02) over an UNAUTHENTICATED request on {port}: {n} bytes of model/firmware/device info returned (status 0xFE) — missing authentication on UMAS info read (CWE-306/CWE-200)")
        # a UMAS error status still proves an unauthenticated UMAS stack answered
        return self._result(target, CheckStatus.NOT_APPLICABLE,
                            description=f"UMAS stack present but READ_ID returned status 0x{parsed['status']:02x} (not 0xFE) — not confirmed")

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


CHECK_CLASS = ModiconUmasUnauthInfoCheck
