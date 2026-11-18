"""Native check -- Schneider Geo SCADA Expert / ClearSCADA unauthenticated SOAP database read. READ-ONLY.

Geo SCADA's WebX web server exposes a SOAP web service at /webservices/scx (SCXService). Per Schneider's
own Knowledge Base ("Using SOAP interface to connect to Geo SCADA", KB 279083), the service can be used as
the built-in Guest user WITHOUT logging in, and ExecuteQuery runs SQL SELECTs against the LIVE SCADA
database (points, values, configuration). When a server permits non-secure / Guest SOAP access, any
network-reachable client can therefore READ the SCADA database over HTTP with no authentication (CWE-306)
-- materially worse than the WebX landing page alone, and the same SOAP service exposes ExecuteMethod
(the write/control path, e.g. setting a point's CurrentValue).

This check reuses core.fingerprint.probe_geoscada_soap_unauth_query, which POSTs ONE benign, READ-ONLY
Guest ExecuteQuery ("SELECT FullName FROM CDBPoint") to /webservices/scx and confirms the server returned
query results (ExecuteQueryResponse / ResultSet). A results response == the SCADA DB was read with no auth
-> CONFIRMED. A gated response (self-signed-cert warning, /logon redirect, SOAP fault) or a non-Geo-SCADA
host -> NOT_APPLICABLE, so hardened/default servers correctly do not trip. The check NEVER calls
ExecuteMethod or issues a write; an actuation proof-of-impact belongs in scripts/safety_critical/.

params schema (all optional):
  default_port: WebX/SOAP port (default 8080; commonly 80/443 too)
  timeout:      seconds (default 6.0)
"""

from __future__ import annotations

from core.check import Check, CheckResult, CheckStatus
from core.target import Target
from core.fingerprint import probe_geoscada_soap_unauth_query


class GeoScadaSoapUnauthQueryCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        port = target.port or params.get("default_port", 8080)
        timeout = params.get("timeout", 6.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        fp = probe_geoscada_soap_unauth_query(target.host, port, timeout=timeout)
        if fp.confidence != "none":
            return self._result(
                target, CheckStatus.CONFIRMED,
                description=(
                    f"Schneider Geo SCADA Expert / ClearSCADA returned SCADA-database query results to an "
                    f"UNAUTHENTICATED Guest SOAP ExecuteQuery on TCP {port} (/webservices/scx) -- the live "
                    f"database (points, values, configuration) is readable over HTTP with no login "
                    f"(CWE-306). The same SOAP service exposes ExecuteMethod (write/control, e.g. setting a "
                    f"point CurrentValue). This check sent only a read-only SELECT; it made no write and "
                    f"issued no control."
                ),
            )
        return self._result(
            target, CheckStatus.NOT_APPLICABLE,
            description=(
                f"no unauthenticated SOAP query result ({fp.method}); the SOAP endpoint is gated "
                f"(cert warning / logon required), or this is not a Geo SCADA server"
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


CHECK_CLASS = GeoScadaSoapUnauthQueryCheck
