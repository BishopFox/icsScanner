"""Native check — Schneider Electric Modicon M221: does the UMAS device-reservation mechanism
(the operation that gates PLC program upload/download and configuration changes) grant a
reservation with NO password/authentication data sent at all?

Built 2026-09-14 for CVE-2018-7791 (Schneider Electric Modicon M221, all references, firmware
prior to V1.6.2.0, SEVD-2018-235-01) — "allows unauthorized users to overwrite the original
password with their password... the attacker can upload the original program from the PLC." The
same root cause this check confirms — the reservation operation isn't actually gated by a real
password check — is also what CVE-2018-7790 ("replay authentication sequences") describes; see
checks/candidates/candidate-cve-2018-7790.yaml for that CVE's own disposition (still not
independently built: a literal replay attack needs a previously-captured legitimate session,
which this stateless single-target scanner architecturally doesn't have — this check instead
demonstrates the more fundamental condition both CVEs stem from).

SOURCING, deliberately cross-verified across multiple primary/named sources before writing any
wire logic — never a single-source guess:
  1. Kaspersky ICS CERT's own byte-exact UMAS protocol paper ("The secrets of Schneider Electric's
     UMAS protocol", 2022) — documents the general UMAS transport precisely: Modbus function code
     0x5A wraps every UMAS message; a 1-byte "session" key follows immediately; UMAS function
     0x10 = umas_QueryTakePLCReservation, 0x11 = umas_QueryReleasePLCReservation; the response's
     status byte sits immediately after the echoed session byte, where 0xFE = success and 0xFD =
     error; on a 0xFE, the device additionally returns a NEW one-byte session key used to
     authorize subsequent requests. This paper documents Modicon M340/M580 devices specifically
     (a related but different product line/security-mechanism generation than M221's own
     "Application Password" concept never existed on) — the transport-layer mechanics above are
     the SAME UMAS wrapper the whole product family shares, but the M221-specific password-field
     encoding this paper's own "Application Password" section describes was NOT assumed to carry
     over, and is NOT used by this check at all — see the design note below.
  2. Cisco Talos TALOS-2018-0741 (Modicon M580, CVE-2018-7842) independently corroborates the
     0x5A wrapper and the 0xFE/0xFD status-byte convention from a completely separate research
     team, on yet another product in the same family.
  3. Schneider's own EcoStruxure Machine Expert - Basic V1.3 engineering-tool DLL (MbComms.dll,
     disassembled directly via radare2, see the candidate files' own notes) confirms M221's client
     independently implements the SAME 0x10/0x11 reservation functions, and that the client's own
     response-validation code never references the client-supplied "random number" field at all.

DESIGN, deliberately conservative given the cross-family verification gap: this check sends the
UMAS TakeReservation request in the EXACT byte-for-byte form all three sources above agree on —
function 0x10, session 0x00, a length-prefixed reservation name, and NOTHING ELSE (no password
field of any kind, encoded or otherwise). No password-field bytes are constructed or guessed for
M221 specifically, because that encoding was only confirmed for M340's later, different security
mechanism — inventing M221-specific password bytes without verification is exactly the kind of
wire-format guess this project's sourcing discipline exists to prevent, and sending malformed data
at a live PLC carries real risk. If the device grants the reservation anyway (status 0xFE) with
zero password material ever supplied, that is an unambiguous, conservative demonstration that the
reservation mechanism enforces no real authentication on this device — a strict superset of what
both CVE-2018-7790 and CVE-2018-7791 describe (if no password is required at all, both "replay a
captured password" and "overwrite the password without knowing the old one" are trivially true).
A device that correctly rejects this (status 0xFD, or any non-0xFE response) is NOT confirmed
vulnerable BY THIS CHECK — it may still carry the more specific replay/overwrite primitive the
CVEs describe when a real password IS configured, which this check cannot exercise without the
M221-specific password-field format (not verified this pass).

DESTRUCTIVE, tier `device_write` (not `login`): taking a PLC reservation is a real state change —
it exclusively locks out any other client (including a legitimate engineer's own session) for as
long as it's held. This check ALWAYS immediately releases the reservation it took
(umas_QueryReleasePLCReservation, function 0x11) as its very next action after confirming, whether
CONFIRMED or not, restoring the device to its prior state — the same "verify then immediately
restore" pattern already used elsewhere in this project for destructive-but-reversible checks.

params schema: none — this check is fully self-contained (no vendor-specific values to
configure), matching the fingerprint_precondition's own vendor+product gate.
"""

from __future__ import annotations

import socket
import struct
from typing import Optional, Tuple

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_UMAS_FUNCTION_CODE = 0x5A
_SERVICE_SESSION = 0x00
_UMAS_TAKE_RESERVATION = 0x10
_UMAS_RELEASE_RESERVATION = 0x11
_STATUS_SUCCESS = 0xFE
_STATUS_ERROR = 0xFD
_RESERVATION_NAME = b"ICSSCANNER"
_DEFAULT_PORT = 502


def _mbap(pdu: bytes, unit_id: int = 0xFF, tid: int = 0x0001) -> bytes:
    return struct.pack(">HHHB", tid, 0x0000, 1 + len(pdu), unit_id) + pdu


def _take_reservation_request() -> bytes:
    data = bytes([len(_RESERVATION_NAME)]) + _RESERVATION_NAME
    pdu = bytes([_UMAS_FUNCTION_CODE, _SERVICE_SESSION, _UMAS_TAKE_RESERVATION]) + data
    return _mbap(pdu)


def _release_reservation_request(session: int) -> bytes:
    pdu = bytes([_UMAS_FUNCTION_CODE, session, _UMAS_RELEASE_RESERVATION])
    return _mbap(pdu)


def _send(sock: socket.socket, payload: bytes) -> Optional[bytes]:
    try:
        sock.sendall(payload)
        return sock.recv(256)
    except (OSError, socket.timeout):
        return None


class SchneiderM221UmasReservationNoAuthCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        if target.port is None and _DEFAULT_PORT is None:
            return self._result(target, CheckStatus.ERROR, description="target has no port configured")
        port = target.port or _DEFAULT_PORT

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        sock: Optional[socket.socket] = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((target.host, port))

            resp = _send(sock, _take_reservation_request())
            if resp is None:
                return self._result(target, CheckStatus.ERROR, description="no response to UMAS TakePLCReservation request within timeout")

            outcome, new_session = self._parse_take_response(resp)

            if outcome == "confirmed" and new_session is not None:
                # Always release immediately — restore the device to its prior state before
                # reporting anything.
                _send(sock, _release_reservation_request(new_session))
                return self._result(
                    target,
                    CheckStatus.CONFIRMED,
                    description=(
                        "UMAS TakePLCReservation (function 0x10) succeeded with NO password/"
                        "authentication data sent at all — the device granted an exclusive PLC "
                        "reservation to an unauthenticated request. Released immediately "
                        "(function 0x11) to restore the device to its prior state."
                    ),
                    evidence=resp,
                )

            if outcome == "rejected":
                return self._result(
                    target,
                    CheckStatus.NOT_APPLICABLE,
                    description="UMAS TakePLCReservation was rejected (status 0xFD) — the device did not grant a reservation without authentication data.",
                    evidence=resp,
                )

            return self._result(
                target,
                CheckStatus.ERROR,
                description="unrecognized response to UMAS TakePLCReservation request",
                evidence=resp,
            )
        except (OSError, socket.timeout) as e:
            return self._result(target, CheckStatus.ERROR, description=f"connection error: {e}")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def _parse_take_response(self, resp: bytes) -> Tuple[str, Optional[int]]:
        # MBAP header is 7 bytes; PDU: [0]=function code echo, [1]=session echo, [2]=status,
        # [3]=new session key (present only on success) — see module docstring for sourcing.
        if len(resp) < 10:
            return "unrecognized", None
        if resp[7] != _UMAS_FUNCTION_CODE:
            return "unrecognized", None
        status = resp[9]
        if status == _STATUS_SUCCESS:
            new_session = resp[10] if len(resp) > 10 else None
            if new_session is None:
                return "unrecognized", None
            return "confirmed", new_session
        if status == _STATUS_ERROR:
            return "rejected", None
        return "unrecognized", None

    def _result(self, target: Target, status: CheckStatus, description: str = "", evidence: Optional[bytes] = None) -> CheckResult:
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


CHECK_CLASS = SchneiderM221UmasReservationNoAuthCheck
