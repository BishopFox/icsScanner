"""Native check — Mitsubishi MELSEC SLMP / MC-protocol (3E binary) UNAUTHENTICATED read probe.

MELSEC Q/L/iQ-R (and iQ-F/FX5) CPUs expose the SLMP / MC-protocol binary "3E frame" service on an
Ethernet port (commonly TCP 5000, configurable in the CPU's Open Settings). The protocol has NO
authentication of its own; the ONLY gate MELSEC offers is an OPTIONAL "remote password" on the
Ethernet port, which is OFF by default. When unset, any client can batch-read/write PLC device
memory and change CPU state with no credential (CWE-306, Missing Authentication). This check sends a
single BENIGN, READ-ONLY SLMP batch-read of one word at D0 and treats a well-formed 3E response as
proof the device answered an unauthenticated request. It does NOT write, change mode, or touch the
remote-password mechanism — read only, safe to fire unsupervised (same discipline as the project's
Modbus-read / ENIP-identity / LS-XGT probes).

WIRE FORMAT — cross-verified without a live PLC (same multi-source rigor as the LS XGT + Schneider
UMAS checks):
  - VENDOR SPEC: Mitsubishi "MELSEC Communication Protocol Reference Manual" (SH-080008) + the
    MELSEC iQ-F FX5 "SLMP" manual (JY997D60801) — SLMP/MC 3E binary frame.
  - OSS: senrust/pymcprotocol (type3e.py / mcprotocolconst.py) — the exact 3E binary frame
    construction + device codes, used here as the ground-truth cross-check.

3E binary request frame (all multi-byte numeric fields LITTLE-ENDIAN; the subheader is the one
BIG-ENDIAN field):
  subheader 0x5000 (BE -> 50 00) | network 0x00 | PC 0xFF | request-dest-module-I/O 0x03FF (LE) |
  request-dest-station 0x00 | request-data-length (LE = 2 + len(command-block)) | monitoring-timer
  (LE, 4 = 1s) || command 0x0401 (LE, batch read) | subcommand 0x0000 (LE, word units) |
  head-device-number (3 bytes LE) | device-code (1 byte; D = 0xA8) | number-of-points (LE).
Response: subheader 0xD000 (-> D0 00); completion/end code is a 2-byte LE word at offset 9
  (0x0000 = success); read data begins at offset 11.

params schema:
  default_port:  fallback port (MELSEC SLMP binary default 5000; configurable per CPU Open Settings)
  device_code:   MELSEC device code to read (default 0xA8 = D register)
  head_device:   head device number (default 0 -> D0)
  count:         number of word points to read (default 1)
  timeout:       seconds (default 5.0)
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_SUBHEADER_REQ = b"\x50\x00"   # 0x5000, big-endian on the wire
_SUBHEADER_RESP = b"\xd0\x00"  # 0xD000 response
_CMD_BATCH_READ = 0x0401
_SUBCMD_WORD = 0x0000
_DEV_D = 0xA8                  # D register device code
_END_SUCCESS = 0x0000


def build_slmp_read_request(head_device: int = 0, device_code: int = _DEV_D, count: int = 1,
                            network: int = 0x00, pc: int = 0xFF, timer: int = 4) -> bytes:
    """Build a MELSEC SLMP/MC 3E-binary batch-read-in-word-units request (pymcprotocol-verified)."""
    command_block = (
        struct.pack("<H", _CMD_BATCH_READ) + struct.pack("<H", _SUBCMD_WORD)
        + head_device.to_bytes(3, "little") + bytes([device_code & 0xFF])
        + struct.pack("<H", count)
    )
    header = (
        _SUBHEADER_REQ + bytes([network & 0xFF, pc & 0xFF])
        + struct.pack("<H", 0x03FF) + bytes([0x00])
        + struct.pack("<H", 2 + len(command_block))   # request data length = timer(2) + command block
        + struct.pack("<H", timer)
    )
    return header + command_block


def parse_slmp_response(data: bytes) -> Optional[dict]:
    """Return {end_code, data} for a well-formed 3E response (subheader 0xD000), else None."""
    if len(data) < 11 or data[0:2] != _SUBHEADER_RESP:
        return None
    end_code = struct.unpack_from("<H", data, 9)[0]  # completion code, 2 bytes LE at offset 9
    return {"end_code": end_code, "data": data[11:]}


class MelsecSlmpUnauthReadCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        port = target.port or params.get("default_port", 5000)
        device_code = params.get("device_code", _DEV_D)
        head_device = params.get("head_device", 0)
        count = params.get("count", 1)
        timeout = params.get("timeout", 5.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target.host, port))
            sock.sendall(build_slmp_read_request(head_device, device_code, count))
            resp = sock.recv(512)
        except OSError:
            return self._result(target, CheckStatus.NOT_APPLICABLE,
                                description=f"no SLMP/MC response on {port} — not applicable")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

        parsed = parse_slmp_response(resp)
        if parsed is None:
            return self._result(target, CheckStatus.NOT_APPLICABLE,
                                description="response was not a well-formed MELSEC 3E (SLMP) frame — not applicable")
        if parsed["end_code"] == _END_SUCCESS:
            detail = "unauthenticated SLMP batch-read of D0 SUCCEEDED (end code 0x0000)"
        else:
            detail = f"device processed the unauthenticated SLMP request (MELSEC end code 0x{parsed['end_code']:04x})"
        return self._result(target, CheckStatus.CONFIRMED,
                            description=f"Mitsubishi MELSEC answered an UNAUTHENTICATED SLMP/MC-protocol request on {port}: {detail} — no Ethernet remote password set (CWE-306 missing authentication; SLMP also permits unauthenticated write/mode-change)")

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


CHECK_CLASS = MelsecSlmpUnauthReadCheck
