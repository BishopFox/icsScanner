"""Native check -- IEC 60870-5-104 controlled station unauthenticated access. SAFE + READ-ONLY.

IEC 60870-5-104 (IEC-104, TCP 2404) is a core telecontrol protocol in water/wastewater and electric
SCADA, and a first-class Geo SCADA Expert driver. The base protocol has no authentication: a master
connects, issues a STARTDT (Start Data Transfer) handshake, and can then both READ (General
Interrogation, C_IC_NA_1) and CONTROL -- C_SC (single command), C_DC (double command), C_RC (regulating
step), C_SE (set point). Without an external control (VPN/firewall/IEC 62351), any reachable peer can do
this (CWE-306), the same missing-authentication exposure class as the DNP3 / FINS / SLMP checks here.

This check reuses core.fingerprint.probe_iec104_identity, which sends ONLY the standard U-format STARTDT
activation -- the benign session-start handshake every 104 master issues, NOT a process command -- and
looks for the station's STARTDT confirmation. A station that confirms STARTDT with no authentication
accepts an unauthenticated master -> CONFIRMED. The check NEVER sends a C_SC/C_DC/C_RC/C_SE command; an
actuation proof-of-impact belongs in scripts/safety_critical/, never an armed check.

params schema (all optional):
  default_port: IEC-104 port (default 2404)
  timeout:      seconds (default 5.0)
"""

from __future__ import annotations

from core.check import Check, CheckResult, CheckStatus
from core.target import Target
from core.fingerprint import probe_iec104_identity


class Iec104UnauthenticatedAccessCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        port = target.port or params.get("default_port", 2404)
        timeout = params.get("timeout", 5.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        fp = probe_iec104_identity(target.host, port, timeout=timeout)
        if fp.confidence != "none":
            return self._result(
                target, CheckStatus.CONFIRMED,
                description=(
                    f"IEC 60870-5-104 controlled station on TCP {port} confirmed an unauthenticated STARTDT "
                    f"(Start Data Transfer) handshake ({fp.method}) -- the station accepts a master with no "
                    f"authentication (CWE-306). The same unauthenticated session reaches IEC-104 control "
                    f"ASDUs -- C_SC/C_DC single/double command, C_RC regulating step, C_SE set point (e.g. "
                    f"pump/valve operation and setpoints). This check sent only the benign STARTDT handshake; "
                    f"it issued no control command."
                ),
            )
        return self._result(
            target, CheckStatus.NOT_APPLICABLE,
            description=f"no IEC-104 STARTDT confirmation ({fp.method}); not a 104 station or unreachable",
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


CHECK_CLASS = Iec104UnauthenticatedAccessCheck
