"""Native check -- Opto 22 SNAP PAC / SNAP I/O FTP management service exposed. SAFE + READ-ONLY.

Opto 22 SNAP PAC and SNAP I/O controllers run a built-in FTP management service. CISA advisory
ICSA-23-236-02 flags this FTP service as open by default on affected firmware (CVE-2023-40708), and the
same advisory covers a web management server that, on affected firmware (<= R10.3b), had no
login-attempt limit and permitted weak/default passwords (CVE-2023-40706; remediated in later firmware,
which now forces credential setup and rejects default values).

This check reuses core.fingerprint.probe_opto22_ftp_identity, which reads ONLY the FTP 220 greeting
("220 Opto 22 FTP server ready.") and sends NO USER/PASS and attempts NO authentication. A matching
banner confirms the Opto 22 FTP management service is network-reachable -> CONFIRMED (the
CVE-2023-40708 exposure condition). No Opto 22 FTP banner -> NOT_APPLICABLE. The check never logs in or
tests credentials; it is an exposure/identity detection, not a credential check.

params schema (all optional):
  default_port: FTP port (default 21)
  timeout:      seconds (default 5.0)
"""

from __future__ import annotations

from core.check import Check, CheckResult, CheckStatus
from core.target import Target
from core.fingerprint import probe_opto22_ftp_identity


class Opto22FtpManagementExposedCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        port = target.port or params.get("default_port", 21)
        timeout = params.get("timeout", 5.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        fp = probe_opto22_ftp_identity(target.host, port, timeout=timeout)
        if fp.confidence != "none":
            banner = (fp.extra or {}).get("ftp_banner", "Opto 22 FTP server")
            return self._result(
                target, CheckStatus.CONFIRMED,
                description=(
                    f"Opto 22 FTP management service reachable (banner: {banner!r}) -- the SNAP PAC / "
                    f"SNAP I/O built-in FTP service is network-exposed (CVE-2023-40708, ICSA-23-236-02; "
                    f"Opto 22 advises disabling it via Network Security). On firmware <= R10.3b the web "
                    f"admin also permitted weak/default credentials (CVE-2023-40706). This check only read "
                    f"the FTP greeting; it sent no credentials and did not authenticate."
                ),
            )
        return self._result(
            target, CheckStatus.NOT_APPLICABLE,
            description=f"no Opto 22 FTP server greeting on the port ({fp.method})",
        )

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


CHECK_CLASS = Opto22FtpManagementExposedCheck
