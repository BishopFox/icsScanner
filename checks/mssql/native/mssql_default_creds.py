"""Generic native check — Microsoft SQL Server default-credential test, via pymssql. Decided
2026-08-14 over pyodbc for the same reason as every other library choice in this project:
pymssql bundles its own FreeTDS-based connector and needs no separate system ODBC driver
install, less deployment friction for a check that just needs "does this login work" — mirrors
the asyncua-vs-python-opcua and paramiko choices' reasoning.

Reusable across vendors the same way basic_auth_default_creds.py/ssh_default_creds.py are: the
credential list comes from CheckMetadata.params, not per-vendor Python. First user: Wonderware
Historian (CVE-2017-5155) — several ICS products vendor a SQL Server backend with default
logins (Siemens WinCC's CVE-2010-2772 is architecturally the same shape, still a candidate
pending its own exact-credential confirmation).

DESTRUCTIVE: real authentication-attempt traffic; SQL Server can be configured to lock out
logins after repeated failures same as any other credential-testing surface in this project.

CONFIRMED on the first credential pair that authenticates successfully — a clean signal (a
successful pymssql connection vs. a login-failure exception).

params schema:
  credentials:   list of [username, password] pairs, tried in order
  timeout:       connection timeout in seconds (default 5.0)
  default_port:  fallback port if the target doesn't specify one (default 1433)
"""

from __future__ import annotations


from core.check import Check, CheckResult, CheckStatus
from core.target import Target

try:
    import pymssql
except ImportError:
    pymssql = None


class MssqlDefaultCredsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        if pymssql is None:
            return self._result(target, CheckStatus.ERROR, description="pymssql not installed — pip install pymssql")

        params = self.metadata.params or {}
        credentials = params.get("credentials", [])
        timeout = params.get("timeout", 5.0)
        port = target.port or params.get("default_port", 1433)

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
                    description=f"default credential '{username}:{password}' authenticated via SQL Server login",
                )
            if outcome == "conn_error":
                # A connection-level failure (not real TDS, or unreachable) applies identically
                # to every remaining credential — fail fast rather than repeat it 7 more times
                # against a target that was never going to answer differently.
                return self._result(
                    target, CheckStatus.ERROR,
                    description="target did not respond as a real SQL Server — unreachable or not this protocol",
                )

        return self._result(
            target,
            CheckStatus.NOT_APPLICABLE,
            description=f"none of {len(credentials)} tested default credential(s) authenticated via SQL Server login",
        )

    def _try_one(self, host: str, port: int, username: str, password: str, timeout: float) -> str:
        from core.fingerprint import _mssql_is_connection_level_error

        conn = None
        try:
            conn = pymssql.connect(
                server=host, port=str(port), user=username, password=password,
                timeout=timeout, login_timeout=timeout,
            )
            return "auth_ok"
        except pymssql.OperationalError as e:
            # Same classification as core/fingerprint.py:probe_mssql_identity() — a DB-Lib
            # connection-level failure (nothing listening, not real TDS) is NOT the same as a
            # genuine SQL-Server-level auth rejection. Shared, not duplicated, so the two can't
            # silently diverge (see that function's docstring for the real-server-unverified
            # caveat this classification carries).
            return "conn_error" if _mssql_is_connection_level_error(e) else "auth_failed"
        except Exception:
            return "conn_error"
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
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


CHECK_CLASS = MssqlDefaultCredsCheck
