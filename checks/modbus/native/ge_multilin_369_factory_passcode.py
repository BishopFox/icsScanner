"""Native check — GE Multilin 369 Motor Management Relay factory-default Communications Access
Level ("Read & Write," i.e. unrestricted, no credential enforced), verified via Modbus. Sourced
directly from GE Power Management's own "369 Motor Management Relay Instruction Manual"
(GE Publication Code GEK-106288, Manual P/N 1601-0077-BC) — see
checks/candidates/ge-multilin-369-factory-passcode.yaml for the full research trail (Section
5.2.2 "Setpoint Access," Section 4.1.5 "Setpoint Entry," and the Modbus Memory Map, Section
10.4.5, all read directly).

MISSING-AUTHENTICATION-BY-DEFAULT, not a guessed credential — the SIMPLEST and SAFEST design of
any GE Multilin check in this project, a pure read with no write at all:

The manual documents holding register 0051h ("Comm Access Level," format F162, range 0-1,
factory default 0) as the device's own reported access-control state for its communications
ports — 0 means "Read & Write" (unrestricted): "If the access level is Read/Write, write access
to setpoints is automatic and a 0 password need not be entered." This is a plain, ordinary
Modbus holding register (FC03-readable, matching the same class every other GE Multilin memory-
mapped register uses), so a single read is DEFINITIVE per the manual's own stated logic — unlike
469/489/850/869/750/760, this check never needs to write, guess, or interpret a password field at
all; the access-level enum itself is the complete answer. Still classified destructive/adverse
(risk_reason: ["login"]) per this project's standing convention that ANY live probe against a
real device confirming a missing-authentication or default-credential condition is gated the
same way as an actual login attempt (see checks/crimson/redlion-crimson-cve-2020-27285-unauth-
read.yaml for the same reasoning applied to a pure identity read) — not because this read itself
mutates anything, it doesn't.

WIRE FRAMING — an explicit, user-confirmed decision, not a silent assumption: GEK-106288 states
"The 369 has one RS232 front panel port and three RS485 rear ports. The Modbus RTU protocol is
standard to all ports" — serial-only, no confirmed native Ethernet (a full-manual search found
exactly one isolated "Ethernet Connection OK" status bit, likely describing an accessory module,
not a base-unit port). The candidate file explicitly flagged this as needing either a native-
Ethernet confirmation or "an explicit decision to build against the RTU-over-TCP-gateway
assumption the way the 469/489 checks already do" before promotion — the user made that decision
directly (2026-08-30). This module therefore builds/parses raw Modbus RTU frames (slave address,
function code, data, CRC-16) over a transparent serial-to-Ethernet gateway, same reasoning and
same "fails safe (ERROR, not a dangerous outcome) if wrong" posture as 469/489/750/760.

No documented Access Lockout mechanism for this register in the excerpt reviewed — single-
attempt (in this case single-READ) design regardless, matching the conservative posture used for
every GE Multilin check in this project. CRC-16 uses the standard, universal Modbus algorithm
(poly 0xA001, reflected) already cross-validated against real worked examples in the 469/489/
850/869/750/760 manuals without discrepancy — no NEW worked example was available in the 369
excerpt reviewed to re-verify against specifically, noted honestly rather than fabricated.

fingerprint_precondition requires BOTH vendor AND product ("369") — same deliberate safety gate
as every other GE Multilin check: there is no live way to distinguish this model from its
siblings over Modbus, so this only ever fires when an operator explicitly asserts
`product_hint: "369"` for a target.
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_COMM_ACCESS_LEVEL_REG = 0x0051
_FACTORY_DEFAULT_VALUE = 0  # GEK-106288, Section 10.4.5 Modbus Memory Map, format F162: 0 = "Read & Write" (unrestricted)

_FC_READ_HOLDING = 0x03


def _crc16(data: bytes) -> bytes:
    """Standard Modbus RTU CRC-16 (poly 0xA001, reflected) — the same public, universal
    algorithm every other GE Multilin check module in this project uses."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return struct.pack("<H", crc)


def _rtu_frame(slave_address: int, function_code: int, data: bytes) -> bytes:
    body = bytes([slave_address, function_code]) + data
    return body + _crc16(body)


def _read_comm_access_level_pdu(slave_address: int) -> bytes:
    data = struct.pack(">HH", _COMM_ACCESS_LEVEL_REG, 1)
    return _rtu_frame(slave_address, _FC_READ_HOLDING, data)


def _valid_rtu_response(data: bytes, slave_address: int, expected_fc: int) -> bool:
    if len(data) < 5:
        return False
    if data[-2:] != _crc16(data[:-2]):
        return False
    if data[0] != slave_address:
        return False
    return data[1] == expected_fc


def _send_recv(target: Target, pdu: bytes, timeout: float) -> bytes:
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target.host, target.port))
        sock.sendall(pdu)
        return sock.recv(256)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


class GeMultilin369FactoryPasscodeCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        if target.port is None:
            return self._result(target, CheckStatus.ERROR, description="target has no port configured")

        params = self.metadata.params or {}
        slave_address = params.get("slave_address", 1)
        timeout = params.get("timeout", 5.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        read_pdu = _read_comm_access_level_pdu(slave_address)
        try:
            read_resp = _send_recv(target, read_pdu, timeout)
        except socket.timeout:
            return self._result(target, CheckStatus.ERROR, description="no response to the Comm Access Level read within timeout")
        except OSError as e:
            return self._result(target, CheckStatus.ERROR, description=f"connection error on read attempt: {e}")

        if not _valid_rtu_response(read_resp, slave_address, _FC_READ_HOLDING):
            return self._result(
                target,
                CheckStatus.ERROR,
                description=(
                    "Comm Access Level read got a malformed/unexpected response (bad CRC, or a "
                    "slave-address/function-code mismatch) — the device may use a different "
                    "slave address than params.slave_address, or this target may not actually "
                    "be reachable via raw RTU-over-TCP framing (see module docstring)."
                ),
                evidence=read_resp,
            )

        byte_count = read_resp[2]
        value = int.from_bytes(read_resp[3 : 3 + byte_count], "big") if byte_count >= 2 else None

        if value == _FACTORY_DEFAULT_VALUE:
            return self._result(
                target,
                CheckStatus.CONFIRMED,
                description=(
                    "Comm Access Level register (0051h) read directly and reports 0 ('Read & "
                    "Write', unrestricted) — the device's own factory-default state, per its "
                    "manual: 'write access to setpoints is automatic and a 0 password need not "
                    "be entered.' A direct, device-reported observation, no login attempt or "
                    "write of any kind was needed."
                ),
                evidence=read_resp,
            )
        return self._result(
            target,
            CheckStatus.NOT_APPLICABLE,
            description=(
                f"Comm Access Level register (0051h) read successfully but does not report the "
                f"unrestricted factory-default state (value={value}) — communications access has "
                f"been restricted from the factory default."
            ),
            evidence=read_resp,
        )

    def _result(
        self, target: Target, status: CheckStatus, description: str = "", evidence: Optional[bytes] = None
    ) -> CheckResult:
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
            evidence=evidence,
        )


CHECK_CLASS = GeMultilin369FactoryPasscodeCheck
