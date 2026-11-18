"""Native check — GE Multilin 469 Motor Management Relay factory-default Communications Port
Passcode ("0"), verified via Modbus. Sourced directly from GE Grid Solutions' own "469 Motor
Management Relay COMMUNICATIONS GUIDE" (GE Publication Code GEK-106491M, GE part number
1601-0152-AD, software revision 5.2x) — the manual's own Modbus Memory Map table and Data
Formats (format-code) table, read directly, not search-summarized.

DESTRUCTIVE, EXTRA CAUTION: real power-grid motor protection relay, same review bar the 850/489
checks got. Single-attempt design (no retries — same conservative posture as every other GE
Multilin relay check in this project, since Access Lockout behavior isn't independently
documented for this model any more than it was for the 489):

1. WRITE the passcode value 0 (the documented factory default) to holding register 0088h
   ("Communications port passcode"), via Function Code 06 (Store Single Setpoint) — this is the
   SAME register address, value, and resulting wire bytes as the 489 check's own write (both
   manuals independently name register 0088h "Communications [Port] passcode" with factory
   default 0 — the two relays evidently share this part of their Modbus command-register layout,
   confirmed by reading both manuals directly, not assumed from one to the other).
2. READ holding register 0205h ("Communication setpoint access") via Function Code 03. The
   manual's own Data Formats table defines this register's format code (F126) as a plain
   DISABLED(0)/ENABLED(1) selection — a genuine, device-reported confirmation that the write
   actually granted access, the same self-confirming design the 489 check uses (its own
   equivalent register is 0203h, a different address — NOT assumed to be shared with the 489,
   independently confirmed from this manual's own memory map).

WIRE FRAMING — an explicitly flagged, NOT independently confirmed assumption, same honesty
standard the 489 check's own docstring uses: this manual's own memory map lists an "ETHERNET"
register group (1020h "Ethernet IP address", 1022h "Ethernet subnet mask", 1024h "Ethernet
gateway address") AND a dedicated "Ethernet status" register (064Ch, with a documented "Ethernet
Link Status" bit) plus a comms-port-selection format code (F166) that lists "Ethernet-T" as one
of four possible active ports alongside COMP_RS485/AUX_RS485/DeviceNet — genuinely stronger
evidence of a real native networking option than the 489's manual ever showed (which documented
ONLY RS485/RS232, no Ethernet fields anywhere). However, this specific PDF copy's table-of-
contents lists a dedicated "ETHERNET" prose section (page 36) whose actual content did not
extract from this copy (likely a scan/OCR gap in the source PDF, not a real absence in GE's
original document) — so whether the wire framing on that Ethernet interface is true Modbus
TCP/MBAP (like the 850's confirmed native Ethernet) or a raw RTU frame tunneled over TCP (like
the 489's assumed serial-to-Ethernet-gateway path) is NOT confirmed either way. This module
follows the 489 check's own precedent and builds/parses raw RTU frames (slave address, function
code, data, CRC-16) rather than true MBAP framing — the safer default already proven out by that
check, and one that fails safe (an ERROR result, not a dangerous mis-write) if the assumption
turns out wrong for a real deployment's Ethernet interface, same reasoning the 489 docstring
gives for its own analogous gap.

SLAVE ADDRESS is a deployment-specific Modbus configuration value, not a documented factory
default in this manual (same situation as 489) — configurable via `params.slave_address`,
defaulting to 1 (the common cross-vendor Modbus convention).

fingerprint_precondition requires BOTH vendor AND product ("469") — same deliberate safety gate
as the 850/489 checks: there is no live way to distinguish GE Multilin models over Modbus, so
this only ever fires when an operator explicitly asserts `product_hint: "469"` for a target.
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_PASSCODE_REG = 0x0088
_ACCESS_STATUS_REG = 0x0205
_FACTORY_PASSCODE = 0  # GEK-106491M Modbus Memory Map, "Communications port passcode", DEFAULT 0

_FC_WRITE_SINGLE = 0x06
_FC_READ_HOLDING = 0x03


def _crc16(data: bytes) -> bytes:
    """Standard Modbus RTU CRC-16 (poly 0xA001, reflected) — same public, universal algorithm
    the 489 check's own module uses, not vendor-specific."""
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


class GeMultilin469FactoryPasscodeCheck(Check):
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
                    "be reachable via raw RTU-over-TCP framing (see module docstring — this "
                    "relay's Ethernet transport framing is not independently confirmed)."
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
                description="access-status read (register 0205h) got a malformed/unexpected response after the passcode write",
                evidence=write_resp + read_resp,
            )

        byte_count = read_resp[2]
        value = int.from_bytes(read_resp[3 : 3 + byte_count], "big") if byte_count >= 2 else None

        if value == 1:
            return self._result(
                target,
                CheckStatus.CONFIRMED,
                description=(
                    "factory-default passcode '0' written to the Communications port passcode "
                    "register (0088h), and the device's own Communication setpoint access "
                    "status register (0205h) reads back 1 (Enabled) — a genuine, device-reported "
                    "confirmation, not an inferred write-echo result."
                ),
                evidence=write_resp + read_resp,
            )
        return self._result(
            target,
            CheckStatus.NOT_APPLICABLE,
            description=(
                f"factory-default passcode '0' was written, but the device's Communication "
                f"setpoint access status register (0205h) does not report Enabled "
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


CHECK_CLASS = GeMultilin469FactoryPasscodeCheck
