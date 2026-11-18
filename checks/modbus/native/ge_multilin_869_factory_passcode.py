"""Native check — GE Multilin 869 Motor Protection System factory-default Administrator/Operator
passcode ("0"), verified via Modbus. Sourced directly from GE's own dedicated "869 Motor
Protection System Communications Guide" — the manual's own "Administrator Login and Commands via
Modbus for 8 Series Relays" section and Modbus Memory Map table, read directly, not
search-summarized. This is the SAME "8 Series" GE Grid Solutions platform mechanism the 850
check already documents — the 869 model is explicitly named as covered by that check's own
primary source (GE's shared "8 Series Instruction Manual — Communications System",
8S-1601-0702-C430), and this dedicated 869-specific manual independently confirms the identical
registers and worked example — double corroboration across two separate GE documents, not
assumed from the 850 alone.

DESTRUCTIVE, EXTRA CAUTION: real motor protection relay, same review bar the 850/489/469 checks
got. Two-path design, read preferred — IDENTICAL mechanism and register addresses to the 850
check, because this manual documents the exact same "Password Characters 1-22" field at holding
register 0xF32D and the exact same 44-byte Role+Password login write at 0xF322:

1. READ (FC03, Read Holding Registers) the Administrator password field directly (holding
   registers 0xF32D-0xF337, 11 registers / 22 bytes — "Password Characters 1-22" per this
   manual's own memory map, same field name and address the 850's manual uses). A match against
   the documented factory pattern (ASCII "0" + 21 null bytes — this manual's own worked example
   explicitly states "the relay password in this example is 0") is CONFIRMED; anything else
   readable is a confident NOT_APPLICABLE.
2. If the read is blocked, FALL BACK to the documented Administrator login write (FC10, Store
   Multiple Setpoints, Role="Administrator"+Password="0" at holding register 0xF322 — this
   manual's own Table 10-16 "Data Written to Relay to Login as Administrator" gives this exact
   byte layout). Same explicit design decision as 850: a write attempt NEVER reports CONFIRMED
   on its own (Function 10H only echoes what was stored, not whether the content was correct) —
   capped at FINGERPRINT_ONLY, ambiguity stated plainly in the description.

WIRE FRAMING — CONFIRMED, not an open assumption like 469's: this manual's own "Ethernet Ports"
chapter explicitly states "The communications CPU also supports Modbus TCP, IEC 104, DNP TCP,
TFTP, SFTP..." over a native 10/100 Mbps Ethernet port — true Modbus TCP/MBAP framing, same as
the 850 check, not the raw-RTU-over-TCP fallback assumption the 469/489 checks needed.

ACCESS LOCKOUT — a real, explicitly documented number for this model (not found for 469/489):
this manual's own memory map gives holding register 0x32DF ("Access Lockout") a factory default
of 3 — i.e. 3 failed attempts before lockout. Reinforces the single-attempt, no-retry design
already used project-wide, now with a concrete documented threshold for this specific model.

fingerprint_precondition requires BOTH vendor AND product ("869") — same deliberate safety gate
as every other GE Multilin relay check in this project: there is no live way to distinguish the
869 from its GE Multilin siblings over Modbus, so this only ever fires when an operator
explicitly asserts `product_hint: "869"` for a target.
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_PASSWORD_START_REG = 0xF32D
_PASSWORD_REG_COUNT = 11  # 22 bytes, "Password Characters 1-22"
_EXPECTED_DEFAULT_PASSWORD = b"0".ljust(22, b"\x00")

_LOGIN_START_REG = 0xF322
_LOGIN_REG_COUNT = 22  # 44 bytes: 22-byte Role + 22-byte Password
_ROLE_ADMINISTRATOR = b"Administrator".ljust(22, b"\x00")
_LOGIN_WRITE_DATA = _ROLE_ADMINISTRATOR + _EXPECTED_DEFAULT_PASSWORD

_FC_READ_HOLDING = 0x03
_FC_WRITE_MULTIPLE = 0x10


def _mbap(pdu: bytes, unit_id: int = 0xFE, tid: int = 0x1601) -> bytes:
    # unit_id default FE (254) matches the 850 check's own worked examples — same GE 8-Series
    # convention, not independently re-derived from an 869-specific worked example (this
    # manual's own Table 10-16 example doesn't include a full MBAP-framed worked packet, only
    # the raw PDU bytes shown in the "===" match below).
    return struct.pack(">HHHB", tid, 0x0000, 1 + len(pdu), unit_id) + pdu


def _send_recv(target: Target, pdu: bytes, timeout: float = 5.0) -> bytes:
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target.host, target.port))
        sock.sendall(_mbap(pdu))
        return sock.recv(256)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


class GeMultilin869FactoryPasscodeCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        if target.port is None:
            return self._result(target, CheckStatus.ERROR, description="target has no port configured")

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        read_pdu = struct.pack(">BHH", _FC_READ_HOLDING, _PASSWORD_START_REG, _PASSWORD_REG_COUNT)
        try:
            read_resp = _send_recv(target, read_pdu)
        except socket.timeout:
            return self._result(target, CheckStatus.ERROR, description="no response to password-register read within timeout")
        except OSError as e:
            return self._result(target, CheckStatus.ERROR, description=f"connection error on read attempt: {e}")

        if len(read_resp) >= 9 and read_resp[7] == _FC_READ_HOLDING:
            byte_count = read_resp[8]
            data = read_resp[9 : 9 + byte_count]
            if data == _EXPECTED_DEFAULT_PASSWORD:
                return self._result(
                    target,
                    CheckStatus.CONFIRMED,
                    description=(
                        "Administrator password register (holding 0xF32D-0xF337) read directly "
                        "and matches the documented factory default ('0', null-padded) — a "
                        "direct observation of the stored value, not an inferred login result."
                    ),
                    evidence=read_resp,
                )
            return self._result(
                target,
                CheckStatus.NOT_APPLICABLE,
                description=(
                    "Administrator password register read successfully but does NOT match the "
                    "factory default pattern — relay is confirmed reachable, password has been "
                    "changed from default."
                ),
                evidence=read_resp,
            )

        # Read blocked (Modbus exception) or an unrecognized response — fall back to the
        # documented login write. Never self-reports CONFIRMED (same reasoning as the 850 check):
        # Function 10H's echo only proves the write was accepted, not that the password content
        # was correct.
        if rate_limiter is not None:
            rate_limiter.acquire(target.host)
        write_pdu = struct.pack(">BHHB", _FC_WRITE_MULTIPLE, _LOGIN_START_REG, _LOGIN_REG_COUNT, len(_LOGIN_WRITE_DATA)) + _LOGIN_WRITE_DATA
        try:
            write_resp = _send_recv(target, write_pdu)
        except socket.timeout:
            return self._result(
                target,
                CheckStatus.ERROR,
                description="password read was blocked, and the login-write fallback got no response within timeout",
                evidence=read_resp,
            )
        except OSError as e:
            return self._result(
                target,
                CheckStatus.ERROR,
                description=f"password read was blocked, and the login-write fallback hit a connection error: {e}",
                evidence=read_resp,
            )

        write_ok = len(write_resp) >= 8 and write_resp[7] == _FC_WRITE_MULTIPLE
        note = "write appears to have been accepted (clean echo)" if write_ok else "write also failed/returned an exception"
        return self._result(
            target,
            CheckStatus.FINGERPRINT_ONLY,
            description=(
                "Could not verify via direct password read (blocked or unrecognized response). "
                f"Attempted the documented Administrator login write (Role='Administrator', "
                f"Password='0') as a fallback — {note}. A write's Modbus response cannot confirm "
                "whether the password was actually correct (Function 10H only echoes what was "
                "stored), so this is deliberately NOT reported as confirmed — human follow-up "
                "(e.g. local front-panel verification) is needed to determine the actual outcome. "
                "Access Lockout on this model defaults to 3 failed attempts (register 0x32DF) — "
                "this check performs exactly one attempt, never retries."
            ),
            evidence=read_resp + write_resp,
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


CHECK_CLASS = GeMultilin869FactoryPasscodeCheck
