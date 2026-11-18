"""Native check -- DNP3 outstation unauthenticated access (no DNP3 Secure Authentication). SAFE + READ-ONLY.

DNP3 (IEEE 1815) is the dominant SCADA protocol for water/wastewater, electric, and other utility RTU
telemetry, on TCP 20000. The base protocol has no authentication; DNP3 Secure Authentication (SAv5,
IEEE 1815-2012) is an optional add-on that most field deployments do not enable. When it is absent, any
network-reachable master can both READ all points (tank levels, pump/valve status, flows) and issue
CONTROL commands -- Operate / CROB (binary output control, e.g. start/stop a pump, open/close a valve)
and Analog Output Block (setpoints). This is the missing-authentication exposure class (CWE-306), the
same shape as the FINS / MELSEC-SLMP / OptoMMP unauthenticated-access checks here.

This check reuses core.fingerprint.probe_dnp3_identity, which sends ONLY a benign Group 0 Device
Attributes READ (Var 243 manufacturer name, Var 245 model) using function code READ -- never an
Operate/CROB or Analog Output. An outstation that answers that read with its device attributes, with no
Secure Authentication challenge, proves the outstation accepts an unauthenticated master -> CONFIRMED.
Because the demonstrated read required no authentication, the CROB/Operate control path is reachable the
same way; this check NEVER sends a control command (a CROB proof-of-impact is the isolated
scripts/safety_critical/dnp3_crob_select_* plan-confirm tool, never an armed check).

A device that does not implement Group 0 device attributes (older outstations) fails closed as
NOT_APPLICABLE rather than being reported -- the check does not overclaim. The result is conservative:
a CONFIRMED is always a true unauthenticated-read.

params schema (all optional):
  default_port: DNP3/TCP port (default 20000)
  timeout:      seconds (default 4.0)
"""

from __future__ import annotations

from core.check import Check, CheckResult, CheckStatus
from core.target import Target
from core.fingerprint import probe_dnp3_identity


class Dnp3UnauthenticatedAccessCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        port = target.port or params.get("default_port", 20000)
        timeout = params.get("timeout", 4.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        fp = probe_dnp3_identity(target.host, port, timeout=timeout)
        if fp.confidence != "none":
            model = fp.model if fp.model and fp.model != "unknown" else "unknown model"
            return self._result(
                target, CheckStatus.CONFIRMED,
                description=(
                    f"DNP3 outstation on TCP {port} answered an unauthenticated Group 0 Device Attributes "
                    f"READ (manufacturer '{fp.vendor}', {model}) with no DNP3 Secure Authentication "
                    f"challenge (CWE-306). The same unauthenticated session reaches DNP3 control -- Operate "
                    f"/ CROB (binary output control, e.g. pump/valve) and Analog Output setpoints. This "
                    f"check only READ device attributes; it issued no control command."
                ),
            )
        return self._result(
            target, CheckStatus.NOT_APPLICABLE,
            description=(
                f"no unauthenticated DNP3 Group 0 device-attributes response ({fp.method}); "
                f"not a DNP3 outstation, or Group 0 attributes not implemented"
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


CHECK_CLASS = Dnp3UnauthenticatedAccessCheck
