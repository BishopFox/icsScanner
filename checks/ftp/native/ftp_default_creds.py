"""Generic native check — FTP default-credential test. Uses stdlib ftplib (FTP is a genuinely
standard protocol, unlike the hand-rolled telnet/PCOM-TCP clients elsewhere in this project —
no reason not to use the stdlib client here).

Reusable across vendors: credential list comes from CheckMetadata.params, not per-vendor Python.

DESTRUCTIVE: same reasoning as the HTTP/SSH/Telnet variants — real authentication-attempt
traffic, lockout risk on devices that implement one.

A successful login is unambiguous (ftplib raises error_perm on rejection, returns cleanly on
acceptance) — this class of check gets confidence=high the same way SSH does, unlike telnet's
banner-text guessing.

params schema:
  credentials:    list of [username, password] pairs, tried in order — stops at first success
  timeout:        connection/command timeout in seconds (default 5.0)
  default_port:   fallback port if the target doesn't specify one (default 21)
"""

from __future__ import annotations

import ftplib
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target


class FtpDefaultCredsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        credentials = params.get("credentials", [])
        timeout = params.get("timeout", 5.0)
        port = target.port or params.get("default_port", 21)

        if not credentials:
            return self._result(target, CheckStatus.ERROR, description="check has no credentials configured in params")

        for username, password in credentials:
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            outcome = self._try_one(target.host, port, username, password, timeout)
            if outcome == "auth_ok":
                return self._result(
                    target,
                    CheckStatus.CONFIRMED,
                    description=f"default credential '{username}:{password}' accepted via FTP",
                )

        return self._result(
            target,
            CheckStatus.NOT_APPLICABLE,
            description=f"none of {len(credentials)} tested default credential(s) were accepted via FTP",
        )

    def _try_one(self, host: str, port: int, username: str, password: str, timeout: float) -> str:
        ftp: Optional[ftplib.FTP] = None
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=timeout)
            ftp.login(username, password)
            return "auth_ok"
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


CHECK_CLASS = FtpDefaultCredsCheck
