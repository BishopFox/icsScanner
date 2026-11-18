"""Generic native check — FTP default-credential test for devices whose login mechanism expects
a genuinely BLANK username (not "anonymous"), with authentication happening purely via the
password. First need identified 2026-08-17 reviewing a Schneider Electric PowerLogic EGX400
manual (Instruction Bulletin 63230-314-202/A1): its own documented FTP session shows the operator
pressing Enter at the "User (IP:(none)):" prompt with nothing typed, and the device's own FTP
server replying "331 User (none) OK, send password" — a real, vendor-documented server behavior,
not a guess.

Deliberately NOT reusable via checks/ftp/native/ftp_default_creds.py: this project already
established (see checks/ftp/ge-pacsystems-rx3i-ftp-default.yaml's own research trail) that
stdlib ftplib's high-level login() method unconditionally substitutes "anonymous" for ANY falsy
username (`if not user: user = 'anonymous'`, read directly from ftplib's own source, confirmed
again here) — there is no way to make login() send a truly empty USER argument. This module
instead calls ftplib's lower-level sendcmd() primitive directly (the same primitive login()
itself is built on), bypassing that substitution entirely, so the wire-level command sent is
genuinely `USER ` with nothing after it — matching the documented device behavior exactly rather
than silently testing "anonymous" instead.

Reusable across vendors: password list comes from CheckMetadata.params, not per-vendor Python —
same convention as ftp_default_creds.py, just for this distinct blank-username mechanism shape.

DESTRUCTIVE: same reasoning as every other credential-testing check here — real authentication
traffic, lockout risk on devices that implement one.

params schema:
  passwords:     list of password strings, tried in order (blank username each time) — stops at
                 first success
  timeout:       connection/command timeout in seconds (default 5.0)
  default_port:  fallback port if the target doesn't specify one (default 21)
"""

from __future__ import annotations

import ftplib
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target


class FtpBlankUsernameDefaultCredsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        passwords = params.get("passwords", [])
        timeout = params.get("timeout", 5.0)
        port = target.port or params.get("default_port", 21)

        if not passwords:
            return self._result(target, CheckStatus.ERROR, description="check has no passwords configured in params")

        for password in passwords:
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            outcome = self._try_one(target.host, port, password, timeout)
            if outcome == "auth_ok":
                return self._result(
                    target,
                    CheckStatus.CONFIRMED,
                    description=(
                        f"blank username + password '{password}' accepted via FTP "
                        f"(USER sent with no argument, matching the documented device behavior)"
                    ),
                )

        return self._result(
            target,
            CheckStatus.NOT_APPLICABLE,
            description=f"none of {len(passwords)} tested password(s) were accepted for a blank FTP username",
        )

    def _try_one(self, host: str, port: int, password: str, timeout: float) -> str:
        ftp: Optional[ftplib.FTP] = None
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=timeout)
            # Deliberately NOT ftp.login() — see module docstring for why: login() unconditionally
            # substitutes "anonymous" for a falsy username, which is not what this mechanism is.
            resp = ftp.sendcmd("USER ")
            if resp[0] != "3":
                return "auth_failed"
            resp = ftp.sendcmd("PASS " + password)
            if resp[0] == "2":
                return "auth_ok"
            return "auth_failed"
        except ftplib.error_perm:
            return "auth_failed"
        except ftplib.all_errors:
            return "conn_error"
        finally:
            if ftp is not None:
                try:
                    ftp.close()
                except OSError:
                    pass

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


CHECK_CLASS = FtpBlankUsernameDefaultCredsCheck
