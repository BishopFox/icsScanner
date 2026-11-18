"""Native check — Galil Motion Control DMC/RIO controllers: is the program-space lock (^L^K)
left disengaged, meaning the ED/UL/LS/TR commands (create, read, list, and modify the
controller's stored motion-control program) are reachable with no authentication at all over the
Telnet-style TCP:23 interface?

Built 2026-09-14 (default-credentials sweep, user: "create the new-protocol for galil"). See
checks/candidates/galil-dmc-rio-program-space-unlocked-by-default.yaml for the full sourcing —
Galil's own official "DMC-40x0 Firmware Command Reference" (01/25/2017 edition) confirms:
  - The `PW` command's own documented default is an empty string — a fresh/never-configured
    controller has no password set.
  - `^L^K` (literal Ctrl-L Ctrl-K bytes, 0x0C 0x0B) is the SEPARATE command that actually engages
    the lock using whatever password PW last set; with no password ever set, it is never
    meaningfully engaged either.
  - `^L^K` also provides a genuinely safe, documented, READ-ONLY query form: "^L^K ? will return
    a 0 if the controller is not locked, and a 1 if it is locked." This check sends ONLY that
    query form — it never sends ED/UL/LS/TR itself, and never attempts to set or change PW.

DESIGN: this check deliberately queries lock STATE rather than exercising the program-space
commands the lock actually gates — the same "demonstrate the condition, don't exercise the
write-capable primitive it enables" discipline used elsewhere in this project (e.g. the ICS
Electronics GPIB/Modbus relay check, which reads status rather than sending a control command).
A "0" response means the controller currently has no lock engaged, i.e. ED/UL/LS/TR are reachable
unauthenticated; that is the full extent of what this check confirms.

DESTRUCTIVE tier `login` (not `device_write`): this sends a single documented read-only status
query and writes nothing to the controller — matches the ADVERSE-tier reasoning the candidate
file's own disposition already laid out.

params schema: none — self-contained, matching the fingerprint_precondition's own protocol_probe
gate (galil_identity, core/fingerprint.py).
"""

from __future__ import annotations

import socket
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_DEFAULT_PORT = 23
_LOCK_QUERY = b"\x0c\x0b ?\r"  # ^L^K ?\r — byte-exact per the vendor's own ASCII Values table


class GalilProgramSpaceUnlockedCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        port = target.port or _DEFAULT_PORT

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        sock: Optional[socket.socket] = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((target.host, port))
            sock.sendall(_LOCK_QUERY)
            resp = sock.recv(256)
        except (OSError, socket.timeout) as e:
            return self._result(target, CheckStatus.ERROR, description=f"connection error: {e}")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

        outcome = self._parse_lock_response(resp)

        if outcome == "unlocked":
            return self._result(
                target,
                CheckStatus.CONFIRMED,
                description=(
                    "Galil ^L^K lock-status query ('^L^K ?') returned 0 (not locked) — the "
                    "program-space commands (ED/UL/LS/TR, which create/read/list/modify the "
                    "controller's stored motion-control program) are reachable with no "
                    "authentication of any kind over Telnet."
                ),
                evidence=resp,
            )
        if outcome == "locked":
            return self._result(
                target,
                CheckStatus.NOT_APPLICABLE,
                description="Galil ^L^K lock-status query returned 1 (locked) — a password has been configured and engaged.",
                evidence=resp,
            )
        return self._result(
            target,
            CheckStatus.ERROR,
            description="unrecognized response to Galil ^L^K lock-status query",
            evidence=resp,
        )

    def _parse_lock_response(self, resp: bytes) -> str:
        if resp is None:
            return "unrecognized"
        stripped = resp.strip(b"\r\n :")
        if stripped == b"0":
            return "unlocked"
        if stripped == b"1":
            return "locked"
        return "unrecognized"

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


CHECK_CLASS = GalilProgramSpaceUnlockedCheck
