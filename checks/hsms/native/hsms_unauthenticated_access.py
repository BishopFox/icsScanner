"""Native check — SECS/GEM-over-HSMS unauthenticated access detection. SAFE + READ-ONLY.

HSMS (SEMI E37) is the TCP transport for SECS-II/GEM on semiconductor / SMT / ATE equipment
(TCP 5000). The protocol has NO authentication layer anywhere: a peer that completes the HSMS
Select handshake is in a SECS-II session with no credential ever offered or checked (CWE-306).
Once selected, SECS-II/GEM carries equipment data collection (status/alarms/process data) and --
where the equipment's GEM remote-control state permits -- remote commands, equipment-constant
writes, and recipe / process-program download.

This check reuses core.fingerprint.probe_hsms_identity, which sends ONE standard HSMS Select.req
control message (no SECS-II data, no equipment command) and confirms a Select.rsp echoing our
system bytes, or a Reject.req -- either proves an HSMS peer answered an unauthenticated handshake.
It NEVER sends a SECS-II message, remote command, or recipe. A confirmed HSMS peer == the SECS/GEM
interface accepts a session with no credential -> CONFIRMED. No HSMS response -> NOT_APPLICABLE.
Because HSMS has no auth step, "completes the Select handshake" is itself the finding; there is
nothing to brute-force.

Port 5000 is shared with Mitsubishi MELSEC SLMP; probe_hsms_identity disambiguates by frame (an
HSMS peer returns a Select.rsp with sType 0x02 echoing our system bytes, which SLMP never does),
so this check does not fire on an SLMP CPU.

params schema (all optional):
  default_port: HSMS port (default 5000)
  timeout:      seconds (default 5.0)
"""

from __future__ import annotations

from core.check import Check, CheckResult, CheckStatus
from core.target import Target
from core.fingerprint import probe_hsms_identity


class HsmsUnauthenticatedAccessCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        port = target.port or params.get("default_port", 5000)
        timeout = params.get("timeout", 5.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        fp = probe_hsms_identity(target.host, port, timeout=timeout)
        if fp.confidence != "none":
            return self._result(
                target, CheckStatus.CONFIRMED,
                description=(
                    f"unauthenticated HSMS (SEMI E37) Select handshake completed (method {fp.method}) "
                    f"-- the SECS/GEM equipment interface accepts a session with no credential (CWE-306). "
                    f"SECS-II data collection is reachable this way, and remote commands / equipment-constant "
                    f"writes / recipe download are reachable where the equipment's GEM remote-control state "
                    f"permits. This check only completed the HSMS handshake; it sent no SECS-II message."
                ),
            )
        return self._result(
            target, CheckStatus.NOT_APPLICABLE,
            description=f"no HSMS Select response to an unauthenticated handshake ({fp.method})",
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


CHECK_CLASS = HsmsUnauthenticatedAccessCheck
