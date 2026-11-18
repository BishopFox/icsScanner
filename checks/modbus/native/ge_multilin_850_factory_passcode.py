"""Native check — GE Multilin 850 Feeder Protection System factory-default Administrator/Operator
passcode ("0"), verified via Modbus. See checks/candidates/ge-multilin-relay-factory-passcode.yaml
for the full research trail (two independent official GE manuals, read directly).

DESTRUCTIVE, EXTRA CAUTION: real grid protection equipment. Two-path design, read preferred:

1. READ (FC03, Read Holding Registers) the Administrator password field directly (holding
   registers 0xF32D-0xF337, 11 registers / 22 bytes — "Password Characters 1-22" per the
   documented memory map). If readable, this is a DIRECT observation of the currently-stored
   value — no ambiguity, unlike a login attempt. A match against the documented factory pattern
   (ASCII "0" + 21 null bytes) is CONFIRMED; anything else readable is a confident NOT_APPLICABLE
   (the relay is real and reachable, the password is provably not the default).
2. If the read is blocked (a Modbus exception response — plausible, many devices deliberately
   block reads of credential fields), FALL BACK to the documented Administrator login write
   (FC10, Store Multiple Setpoints, Role="Administrator"+Password="0" at holding register
   0xF322 — the exact bytes GE's own "8 Series Communications System" manual and the dedicated
   850 instruction manual both give). Per an explicit user decision (2026-08-16, asked directly
   given the stakes): a write attempt NEVER reports CONFIRMED on its own — Modbus's Function 10H
   semantics only echo what was stored, they don't reflect whether the password content was
   actually correct, so a clean echo doesn't prove the login worked. Capped at FINGERPRINT_ONLY
   regardless of the write's own response, with the ambiguity stated plainly in the description.

fingerprint_precondition requires BOTH vendor AND product ("850") — there is no live way to
distinguish the 850 from its GE Multilin siblings (845/859/869/889, or the older/unrelated
489/469/750 family) over Modbus, so this only ever fires when an operator explicitly asserts
`product_hint: "850"` for a target (see core/scan_engine.py:_apply_vendor_hint_fallback, fixed
2026-08-16 specifically to make this kind of product-level opt-in possible). This is a
deliberate safety gate, not a limitation to work around — it means the tool never attempts
anything against a GE Multilin device it hasn't been explicitly told is this exact model.
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
_EXCEPTION_BIT = 0x80


def _mbap(pdu: bytes, unit_id: int = 0xFE, tid: int = 0x1601) -> bytes:
    # unit_id default FE (254) matches every worked example in both source manuals.
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


class GeMultilin850FactoryPasscodeCheck(Check):
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
        # documented login write. Per explicit user decision, this path never self-reports
        # CONFIRMED: Function 10H's echo only proves the write was accepted, not that the
        # password content was correct.
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
                "(e.g. local front-panel verification) is needed to determine the actual outcome."
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


CHECK_CLASS = GeMultilin850FactoryPasscodeCheck
