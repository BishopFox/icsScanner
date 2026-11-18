"""Generic native check — SSH password-authentication default-credential test, via paramiko
(the de facto standard library for this exact use case — no serious competing alternative for
scripted password-auth testing, unlike the asyncua-vs-python-opcua choice which had a real
tradeoff to weigh).

Reusable across vendors the same way basic_auth_default_creds.py is: the credential list comes
from CheckMetadata.params, not per-vendor Python.

DESTRUCTIVE: real authentication-attempt traffic; some devices lock an account (or the whole
management interface) out after a handful of failed attempts.

CONFIRMED on the first credential pair that authenticates successfully — a clean signal (a
successful paramiko connect vs. AuthenticationException), unlike telnet's banner-text heuristics.
look_for_keys=False and allow_agent=False are set explicitly so this only ever tests the exact
supplied password, never accidentally "succeeds" via an unrelated local SSH key or agent.

params schema:
  credentials:   list of [username, password] pairs, tried in order
  timeout:       connection timeout in seconds (default 5.0)
  default_port:  fallback port if the target doesn't specify one (default 22)
"""

from __future__ import annotations


from core.check import Check, CheckResult, CheckStatus
from core.target import Target

try:
    import paramiko
except ImportError:
    paramiko = None


class SshDefaultCredsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        if paramiko is None:
            return self._result(target, CheckStatus.ERROR, description="paramiko not installed — pip install paramiko")

        params = self.metadata.params or {}
        credentials = params.get("credentials", [])
        timeout = params.get("timeout", 5.0)
        port = target.port or params.get("default_port", 22)

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
                    description=f"default credential '{username}:{password}' authenticated via SSH",
                )
            # "auth_failed" -> try next credential; "conn_error" -> also try next (transient),
            # but if EVERY attempt is a conn_error we still end up at not-applicable below,
            # which is the honest result (couldn't confirm either way).

        return self._result(
            target,
            CheckStatus.NOT_APPLICABLE,
            description=f"none of {len(credentials)} tested default credential(s) authenticated via SSH",
        )

    def _try_one(self, host: str, port: int, username: str, password: str, timeout: float) -> str:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host,
                port=port,
                username=username,
                password=password,
                timeout=timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            return "auth_ok"
        except paramiko.AuthenticationException:
            return "auth_failed"
        except Exception:
            return "conn_error"
        finally:
            client.close()

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


CHECK_CLASS = SshDefaultCredsCheck
