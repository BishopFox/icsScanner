"""Native check — GE Multilin 489 Generator Management Relay factory-default Communications Port
Passcode ("0"), verified via Modbus. Sourced directly from GE's own dedicated "489 Generator
Management Relay COMMUNICATIONS GUIDE" (GE Publication Code GEK-106495A, GE Multilin Part Number
1601-0149-A2) — the manual's own "Passcode Operation" section and Modbus Memory Map table, read
directly, not search-summarized.

DESTRUCTIVE, EXTRA CAUTION: real power-grid generator protection relay, same review bar the 850
check got. Single-attempt design (no retries — see Access Lockout note below):

1. WRITE the passcode value 0 (the documented factory default) to holding register 0088h
   ("Communications Port Passcode"), via Function Code 06 (Store Single Setpoint). Per the
   manual's own "Passcode Operation" text: "the front port, rear port and auxiliary port have
   individual access to the setpoints" — this is a per-port write, and writing the CORRECT
   passcode is how a port gets access; writing a WRONG passcode does not damage anything, it
   simply fails to grant access (and per the sibling 469/750 manuals' identical mechanism,
   writing an invalid passcode into this register can also PROACTIVELY DISABLE any currently-
   granted access on that same port — a real but minor side effect, documented here rather than
   hidden, not a destructive action against the relay's actual protection configuration).
2. READ holding register 0203h ("Communications Setpoint Access") via Function Code 03. The
   manual states plainly: "A value of 1 read from this register indicates that the user has full
   access rights to changing setpoints from the given port." This is a GENUINE, DEVICE-REPORTED
   confirmation — unlike the 850 check's write-fallback path (Modbus Function 10H only echoes
   what was stored, never proving the password content was correct), this check CAN and DOES
   self-report CONFIRMED unambiguously, because 0203h is an independent status register the
   device itself computes, not an inference from an echoed write.

WIRE FRAMING — a real, explicitly-flagged assumption, NOT confirmed the way the 850's native
Ethernet port was: GEK-106495A's own "Electrical Interface" section documents ONLY RS485
(2-wire) and front-panel RS232 — no native Ethernet/Modbus-TCP port is mentioned anywhere in the
Communications Guide, unlike the 850's own manual which explicitly confirms one. Network
reachability for this relay therefore most plausibly means a transparent serial-to-Ethernet
gateway (the wire protocol on the network side is classic Modbus RTU — slave address, function
code, data, CRC-16 — tunneled raw through a TCP socket), NOT true Modbus TCP/MBAP framing like
the 850 check uses. This module builds and parses raw RTU frames accordingly. If this assumption
turns out wrong for a given deployment, the check simply gets no valid response (ERROR), not a
dangerous outcome — but it is a real, undocumented gap worth surfacing, not silently assumed.

SLAVE ADDRESS is a deployment-specific Modbus configuration value, not a documented factory
default in GEK-106495A (the manual's own worked examples use slave address 11 purely as an
illustrative example, not a stated default) — configurable via `params.slave_address`, defaulting
to 1 (the common cross-vendor Modbus convention) but very likely needs adjusting per real target.

fingerprint_precondition requires BOTH vendor AND product ("489") — same deliberate safety gate
as the 850 check: there is no live way to distinguish GE Multilin models over Modbus, so this
only ever fires when an operator explicitly asserts `product_hint: "489"` for a target.
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_PASSCODE_REG = 0x0088
_ACCESS_STATUS_REG = 0x0203
_FACTORY_PASSCODE = 0  # GEK-106495A Modbus Memory Map, "Communications Port Passcode", DEFAULT 0

_FC_WRITE_SINGLE = 0x06
_FC_READ_HOLDING = 0x03
_EXCEPTION_BIT = 0x80


def _crc16(data: bytes) -> bytes:
    """Standard Modbus RTU CRC-16 (poly 0xA001, reflected) — a public, universal algorithm, not
    vendor-specific, matching GEK-106495A's own documented CRC-16 Algorithm section exactly."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return struct.pack("<H", crc)  # low byte first, per the manual's own CRC framing


def _rtu_frame(slave_address: int, function_code: int, data: bytes) -> bytes:
    body = bytes([slave_address, function_code]) + data
    return body + _crc16(body)


def _write_passcode_pdu(slave_address: int) -> bytes:
    data = struct.pack(">HH", _PASSCODE_REG, _FACTORY_PASSCODE)
    return _rtu_frame(slave_address, _FC_WRITE_SINGLE, data)


def _read_access_status_pdu(slave_address: int) -> bytes:
    data = struct.pack(">HH", _ACCESS_STATUS_REG, 1)
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


class GeMultilin489FactoryPasscodeCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        if target.port is None:
            return self._result(target, CheckStatus.ERROR, description="target has no port configured")

        params = self.metadata.params or {}
        slave_address = params.get("slave_address", 1)
        timeout = params.get("timeout", 5.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        write_pdu = _write_passcode_pdu(slave_address)
        try:
            write_resp = _send_recv(target, write_pdu, timeout)
        except socket.timeout:
            return self._result(target, CheckStatus.ERROR, description="no response to the passcode write within timeout")
        except OSError as e:
            return self._result(target, CheckStatus.ERROR, description=f"connection error on the passcode write: {e}")

        if not _valid_rtu_response(write_resp, slave_address, _FC_WRITE_SINGLE):
            return self._result(
                target,
                CheckStatus.ERROR,
                description=(
                    "passcode write got a malformed/unexpected response (bad CRC, or a "
                    "slave-address/function-code mismatch) — the device may use a different "
                    "slave address than params.slave_address, or this target may not actually "
                    "be reachable via raw RTU-over-TCP framing (see module docstring)."
                ),
                evidence=write_resp,
            )

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        read_pdu = _read_access_status_pdu(slave_address)
        try:
            read_resp = _send_recv(target, read_pdu, timeout)
        except socket.timeout:
            return self._result(
                target,
                CheckStatus.ERROR,
                description="the passcode write got a valid response, but the access-status read got no response within timeout",
                evidence=write_resp,
            )
        except OSError as e:
            return self._result(
                target,
                CheckStatus.ERROR,
                description=f"the passcode write got a valid response, but the access-status read hit a connection error: {e}",
                evidence=write_resp,
            )

        if not _valid_rtu_response(read_resp, slave_address, _FC_READ_HOLDING):
            return self._result(
                target,
                CheckStatus.ERROR,
                description="access-status read (register 0203h) got a malformed/unexpected response after the passcode write",
                evidence=write_resp + read_resp,
            )

        byte_count = read_resp[2]
        value = int.from_bytes(read_resp[3 : 3 + byte_count], "big") if byte_count >= 2 else None

        if value == 1:
            return self._result(
                target,
                CheckStatus.CONFIRMED,
                description=(
                    "factory-default passcode '0' written to the Communications Port Passcode "
                    "register (0088h), and the device's own Communications Setpoint Access "
                    "status register (0203h) reads back 1 (full access granted) — a genuine, "
                    "device-reported confirmation, not an inferred write-echo result."
                ),
                evidence=write_resp + read_resp,
            )
        return self._result(
            target,
            CheckStatus.NOT_APPLICABLE,
            description=(
                f"factory-default passcode '0' was written, but the device's Communications "
                f"Setpoint Access status register (0203h) does not report full access "
                f"(read value={value}) — the passcode has been changed from the factory default."
            ),
            evidence=write_resp + read_resp,
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


CHECK_CLASS = GeMultilin489FactoryPasscodeCheck
