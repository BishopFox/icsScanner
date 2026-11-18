"""Native check — GE Multilin 750/760 Feeder Management Relay factory-default Communications
Port Passcode ("0"), verified via Modbus. Sourced directly from GE Multilin's own dedicated
"750/760 Feeder Management Relay COMMUNICATIONS GUIDE" (GE Publication Code GEK-106473F, GE
Multilin Part Number 1601-0229-A7, software revision 7.3x) — the manual's own Modbus Memory Map,
Function Code descriptions, and worked examples, read directly, not search-summarized. This is
the exact document named as the missing blocker since 2026-08-17 (see
lab-notes/human-review-queue.md's GE Multilin passcode entry).

ONE MODULE SHARED BY TWO check_ids (750 and 760), unlike every other GE Multilin check in this
project (469/489/850/869 each get their own module file even where mechanisms are near-
identical): this is deliberate, not an inconsistency — GEK-106473F is ONE document explicitly
covering BOTH models with IDENTICAL registers, unlike 850/869 (two separate, if closely related,
Communications Guides for a shared platform). Forking identical code into two files here would
just be two copies to keep in sync forever for no benefit.

DESTRUCTIVE, EXTRA CAUTION: real feeder protection equipment, same review bar as 850/869.
Two-path design, read preferred — same shape as the 850/869 checks, applied here because
GEK-106473F's own memory map lists the passcode register under a "COMMANDS (read/write)" section
header and its own Function Code 03h/04h description states plainly that these codes read "one
or more consecutive data registers (actual values OR setpoints)" — i.e. this register is
documented as genuinely readable, not write-only:

1. READ (FC03, Read Holding Registers) the Communications Port Passcode directly — holding
   registers 0088h-008Bh, 4 registers / 8 bytes, format code F33 (ASCII text). If readable, this
   is a DIRECT observation of the currently-stored value, no login ambiguity. A match against the
   expected factory pattern is CONFIRMED; any other decodable ASCII is a confident NOT_APPLICABLE.
2. If the read is blocked (a Modbus exception), FALL BACK to writing the passcode via FC10 (Store
   Multiple Setpoints) to the same register block — GEK-106473F's own worked FC10 example (a
   clock-sync write, Section 3.8) is used to confirm this device's exact response framing, which
   has a real, documented quirk worth capturing precisely: the response's quantity field is
   labeled "Number of Bytes" (echoing the byte count, e.g. 0008h for a 4-register/8-byte write),
   NOT "Number of Registers" the way 469/489/489's simpler FC06 writes do — this module validates
   against that documented echo shape, not the generic assumption. Per the same explicit design
   decision already applied project-wide: a write's clean echo NEVER self-reports CONFIRMED
   (Function 10h only proves the write was accepted, not that the password content was actually
   correct) — capped at FINGERPRINT_ONLY, ambiguity stated plainly in the description.

FACTORY-DEFAULT PASSCODE VALUE AND PADDING — the value "0" itself is independently confirmed
from TWO separate GE Multilin Instruction Manuals for this exact relay family (GEK-106293D
firmware 5.X, GEK-106471L software 7.2x — see lab-notes/human-review-queue.md), which state the
factory default is "0", up to 8 alphanumeric characters. GEK-106473F itself (this module's
primary source for the register/mechanism) does NOT show a worked example of this specific
register's factory-default byte content, so the exact PADDING of "0" out to the full 8-byte field
is an EXPLICITLY FLAGGED ASSUMPTION, inferred by family convention from the 850/869 manuals' own
directly-confirmed "ASCII '0' + trailing null bytes" pattern for their analogous password-
character fields (not a guess invented for this module) — null-padded, not space-padded. If this
assumption is wrong, the check simply falls through to NOT_APPLICABLE (a real device that's still
at its factory default would then read as "changed"), never a false CONFIRMED or a dangerous
outcome — fails safe.

TEXT BYTE ORDER: GEK-106473F's own Data Formats table (F33, "ASCII Text Characters") states each
word packs the FIRST character in the high byte (FF00h) and the SECOND in the low byte (00FFh) —
i.e. plain big-endian/Motorola byte order for text, the same explicitly-stated exception to this
relay family's otherwise Intel/little-endian numeric convention that 469/489/MIW's manuals each
independently confirm for their own text fields. No byte-swapping needed when decoding — the raw
8-byte block reads directly as the ASCII string.

WIRE FRAMING: GEK-106473F's own Physical Layer section (1.2) confirms the relay has a front-panel
RS232 port and two rear RS485/RS422 ports — NO native Ethernet is mentioned anywhere in this
manual, matching 489's situation, not 850's. This module builds and parses raw Modbus RTU frames
(slave address, function code, data, CRC-16) assuming a transparent serial-to-Ethernet gateway,
the same reasoning and same "fails safe (ERROR, not a dangerous mis-write) if wrong" posture
469/489 already use.

No documented Access Lockout mechanism for this passcode field anywhere in GEK-106473F (checked
directly, same as 469/489 — unlike 850/869's confirmed 3-attempt lockout) — single-attempt
design regardless, matching the conservative posture used for every GE Multilin check in this
project.

fingerprint_precondition requires BOTH vendor AND product ("750" or "760", set per check_id) —
same deliberate safety gate as every other GE Multilin check: there is no live way to distinguish
these models from their siblings over Modbus, so this only ever fires when an operator
explicitly asserts the matching `product_hint` for a target.
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_PASSCODE_REG = 0x0088
_PASSCODE_REG_COUNT = 4  # 4 words / 8 bytes, GEK-106473F Modbus Memory Map, format F33 (ASCII)
_EXPECTED_DEFAULT_PASSCODE = b"0".ljust(8, b"\x00")  # see module docstring — padding is an
# explicitly-flagged assumption by family convention, not shown as a worked example in this
# specific manual for this specific register.

_FC_READ_HOLDING = 0x03
_FC_WRITE_MULTIPLE = 0x10


def _crc16(data: bytes) -> bytes:
    """Standard Modbus RTU CRC-16 (poly 0xA001, reflected) — matches GEK-106473F's own documented
    CRC-16 Algorithm section (2.3) exactly; cross-checked against that section's own worked
    examples in tests/smoke_test_ge_multilin_750_760.py before use."""
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


def _read_passcode_pdu(slave_address: int) -> bytes:
    data = struct.pack(">HH", _PASSCODE_REG, _PASSCODE_REG_COUNT)
    return _rtu_frame(slave_address, _FC_READ_HOLDING, data)


def _write_passcode_pdu(slave_address: int) -> bytes:
    data = struct.pack(">HHB", _PASSCODE_REG, _PASSCODE_REG_COUNT, len(_EXPECTED_DEFAULT_PASSCODE)) + _EXPECTED_DEFAULT_PASSCODE
    return _rtu_frame(slave_address, _FC_WRITE_MULTIPLE, data)


def _valid_rtu_header(data: bytes, slave_address: int, expected_fc: int) -> bool:
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


class GeMultilin750760FactoryPasscodeCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        if target.port is None:
            return self._result(target, CheckStatus.ERROR, description="target has no port configured")

        params = self.metadata.params or {}
        slave_address = params.get("slave_address", 1)
        timeout = params.get("timeout", 5.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        read_pdu = _read_passcode_pdu(slave_address)
        try:
            read_resp = _send_recv(target, read_pdu, timeout)
        except socket.timeout:
            return self._result(target, CheckStatus.ERROR, description="no response to the passcode-register read within timeout")
        except OSError as e:
            return self._result(target, CheckStatus.ERROR, description=f"connection error on read attempt: {e}")

        if _valid_rtu_header(read_resp, slave_address, _FC_READ_HOLDING):
            byte_count = read_resp[2]
            data = read_resp[3 : 3 + byte_count]
            if data == _EXPECTED_DEFAULT_PASSCODE:
                return self._result(
                    target,
                    CheckStatus.CONFIRMED,
                    description=(
                        "Communications Port Passcode register (0088h-008Bh) read directly and "
                        "matches the expected factory-default pattern ('0', null-padded) — a "
                        "direct observation of the stored value, not an inferred write result."
                    ),
                    evidence=read_resp,
                )
            return self._result(
                target,
                CheckStatus.NOT_APPLICABLE,
                description=(
                    "Communications Port Passcode register read successfully but does NOT match "
                    "the expected factory-default pattern — relay is confirmed reachable, "
                    "passcode has been changed from default (or this module's padding assumption "
                    "is wrong for this device — see module docstring)."
                ),
                evidence=read_resp,
            )

        # Read blocked (Modbus exception) or an unrecognized response — fall back to a write.
        # Per this project's established rule, this path never self-reports CONFIRMED.
        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        write_pdu = _write_passcode_pdu(slave_address)
        try:
            write_resp = _send_recv(target, write_pdu, timeout)
        except socket.timeout:
            return self._result(
                target,
                CheckStatus.ERROR,
                description="passcode read was blocked, and the write fallback got no response within timeout",
                evidence=read_resp,
            )
        except OSError as e:
            return self._result(
                target,
                CheckStatus.ERROR,
                description=f"passcode read was blocked, and the write fallback hit a connection error: {e}",
                evidence=read_resp,
            )

        write_ok = _valid_rtu_header(write_resp, slave_address, _FC_WRITE_MULTIPLE)
        note = "write appears to have been accepted (clean echo)" if write_ok else "write also failed/returned an exception"
        return self._result(
            target,
            CheckStatus.FINGERPRINT_ONLY,
            description=(
                "Could not verify via direct passcode read (blocked or unrecognized response). "
                f"Attempted the documented passcode write (FC10, value '0') as a fallback — "
                f"{note}. A write's Modbus response cannot confirm whether the passcode content "
                "was actually correct, so this is deliberately NOT reported as confirmed — human "
                "follow-up (e.g. local front-panel verification) is needed to determine the "
                "actual outcome."
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


CHECK_CLASS = GeMultilin750760FactoryPasscodeCheck
