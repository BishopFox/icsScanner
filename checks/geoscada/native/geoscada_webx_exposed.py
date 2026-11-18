"""Native check -- Schneider Geo SCADA Expert / ClearSCADA WebX web interface exposed. SAFE + READ-ONLY.

Geo SCADA Expert (formerly ClearSCADA) is a dominant water/wastewater + utility SCADA host. Its WebX web
interface (and the DBServer on TCP 5481) is the remote management/operations surface -- the login surface
for default credentials, the built-in Guest account, and the remote-access vector behind the 2021 Oldsmar
water intrusion. CISA/NSA WWS guidance is explicit that SCADA web/HMI interfaces must not be reachable
from untrusted networks. This check confirms a Geo SCADA WebX interface is network-reachable; it does not
assert a credential bypass (that is a deeper Guest/default-cred check).

This reuses core.fingerprint.probe_geoscada_webx_identity, which sends ONE unauthenticated HTTP(S) GET "/"
and matches the distinctive Geo SCADA WebX response (an XML "<Page>" referencing /file/xsl/ AND naming the
Geo SCADA Expert web server) -- confirmed live against a Geo SCADA Expert 2025 R2 server. A match ==
CONFIRMED (the WebX management interface answered on the network). No match -> NOT_APPLICABLE. The check
sends no credentials and no writes.

params schema (all optional):
  default_port: WebX port (default 8080; commonly 80/443 too)
  timeout:      seconds (default 5.0)
"""

from __future__ import annotations

from core.check import Check, CheckResult, CheckStatus
from core.target import Target
from core.fingerprint import probe_geoscada_webx_identity


class GeoScadaWebxExposedCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        port = target.port or params.get("default_port", 8080)
        timeout = params.get("timeout", 5.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        fp = probe_geoscada_webx_identity(target.host, port, timeout=timeout)
        if fp.confidence != "none":
            return self._result(
                target, CheckStatus.CONFIRMED,
                description=(
                    f"Schneider Geo SCADA Expert / ClearSCADA WebX web interface answered an "
                    f"unauthenticated GET on TCP {port} ({fp.method}) -- the SCADA remote management/"
                    f"operations surface is network-reachable. This is the login surface for default "
                    f"credentials and the built-in Guest account, and the remote-access vector CISA/NSA "
                    f"WWS guidance says to keep off untrusted networks (the companion DBServer is "
                    f"typically on TCP 5481). This check only identified the interface; it sent no "
                    f"credentials and made no writes."
                ),
            )
        return self._result(
            target, CheckStatus.NOT_APPLICABLE,
            description=f"no Geo SCADA WebX response ({fp.method}); not a Geo SCADA/ClearSCADA WebX server",
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


CHECK_CLASS = GeoScadaWebxExposedCheck
