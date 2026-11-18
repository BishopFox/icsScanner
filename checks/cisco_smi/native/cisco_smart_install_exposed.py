"""Native check — Cisco Smart Install (SMI) unauthenticated exposure, TCP/4786.

SMI has no authentication anywhere in the protocol (Cisco's own advisories
cisco-sa-20170214-smi and cisco-sa-20180409-smi, and the 2019 NSA/CISA joint advisory on SMI
protocol misuse, all describe this as the root issue, not a bug in one implementation) — a
switch running as an SMI "client" answers a director-role query from anyone who can reach port
4786, no credential involved. That means "the client role responds to this query" and "the
exposure exists" are the same fact, so this check reuses
core.fingerprint.probe_cisco_smi_identity() directly (see that function's own docstring for the
full sourcing note: wire format taken verbatim from SIET, github.com/frostbits-security/SIET,
the reference public tool for this exact issue class, not reverse-engineered here) rather than
duplicating the probe logic.

NON-DESTRUCTIVE BY DESIGN: the reused probe sends only SIET's own read-only "test device" query
and never SIET's separate, genuinely state-changing functionality (change_tftp/update_ios/
get_config), which push a new TFTP server address, IOS image, or config to the target. Nothing
here writes to, reloads, or reconfigures the device.

No CVE — Smart Install's lack of authentication is architectural, documented directly by Cisco
across multiple advisories over several years, not a single patchable defect. disclosure_status:
public (this is Cisco's own long-published guidance, not a new finding).
"""

from __future__ import annotations

from core.check import Check, CheckResult, CheckStatus
from core.fingerprint import probe_cisco_smi_identity
from core.target import Target

_DEFAULT_PORT = 4786
_TIMEOUT_S = 5.0


class CiscoSmartInstallExposedCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        port = target.port or _DEFAULT_PORT

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        result = probe_cisco_smi_identity(target.host, port=port, timeout=_TIMEOUT_S)

        if result.confidence != "high":
            return self._result(
                target, CheckStatus.NOT_APPLICABLE,
                description=f"no Smart Install Client-active response from {target.host}:{port} ({result.method})",
            )

        return self._result(
            target, CheckStatus.CONFIRMED,
            description=(
                f"{target.host}:{port} answered the unauthenticated Smart Install director-role "
                f"query as an active SMI client (Cisco advisories cisco-sa-20170214-smi / "
                f"cisco-sa-20180409-smi) — the SMI protocol accepts director-level commands "
                f"(config/image replacement via TFTP, CLI execution) from any reachable client "
                f"with no authentication"
            ),
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


CHECK_CLASS = CiscoSmartInstallExposedCheck
