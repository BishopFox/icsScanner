"""Native check -- Veeder-Root TLS / ATG Serial Command Port exposed (unauthenticated). SAFE + READ-ONLY.

Veeder-Root TLS-300/350/450/4 Automatic Tank Gauge consoles expose a "Serial Command Port" over TCP
(default 10001). The TLS-350 command protocol has no authentication of its own -- access is gated only
by an optional, operator-enabled security code. When that security is off (a common default/misconfig),
any network-reachable client can issue TLS-350 commands: read inventory/config (I-series) AND change
console configuration (S-series), including tank geometry and alarm thresholds, which Bitsight/CISA's
2024 ATG advisories tie to fuel-leak safety impact (CWE-306). Veeder-Root's own TLS4 security
notification (576047-407) documents enabling the security code / disabling the port as the mitigation,
which confirms this is a documented exposure class, not a novel defect (same shape as the Omron FINS /
MELSEC SLMP / SECS-GEM-HSMS / Opto 22 OptoMMP exposure checks here) -> disclosure_status: public.

This check reuses core.fingerprint.probe_atg_tls350_identity, which sends ONE benign TLS-350 I90200
(system software version) read -- the least-sensitive command, returning console software/type with no
tank or fuel data -- and never issues an S-series set command or reads inventory. A matching response
== the Serial Command Port answered an unauthenticated command -> CONFIRMED. No TLS-350 response ->
NOT_APPLICABLE. Because the protocol has no auth of its own, "answers the read" is itself the finding.

params schema (all optional):
  default_port: Serial Command Port (default 10001)
  timeout:      seconds (default 5.0)
"""

from __future__ import annotations

from core.check import Check, CheckResult, CheckStatus
from core.target import Target
from core.fingerprint import probe_atg_tls350_identity


class AtgSerialCommandPortExposedCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        port = target.port or params.get("default_port", 10001)
        timeout = params.get("timeout", 5.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        fp = probe_atg_tls350_identity(target.host, port, timeout=timeout)
        if fp.confidence != "none":
            return self._result(
                target, CheckStatus.CONFIRMED,
                description=(
                    f"Veeder-Root TLS / ATG Serial Command Port answered an unauthenticated TLS-350 "
                    f"command (method {fp.method}) -- the console accepts commands over TCP with no "
                    f"security code (CWE-306); TLS-350 S-series SET commands (tank/alarm configuration) "
                    f"are reachable the same way, the Bitsight/CISA ATG exposure class. This check only "
                    f"READ the I90200 software-version report; it issued no set command and read no inventory."
                ),
            )
        return self._result(
            target, CheckStatus.NOT_APPLICABLE,
            description=f"no TLS-350 response to an unauthenticated I90200 version read ({fp.method})",
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


CHECK_CLASS = AtgSerialCommandPortExposedCheck
