"""Generic native check — HTTP Basic Auth default-credential test. Reusable across vendors: the
credential list, path, and success condition all come from CheckMetadata.params, so a new
vendor/product needing this exact mechanism (an embedded web UI gated by HTTP Basic Auth — the
common case for older/embedded ICS web interfaces) is a new YAML file, not new Python. Vendors
whose web UI uses form-based login or a vendor-specific auth API need their own native check
class instead — this only covers the Basic Auth case.

DESTRUCTIVE (default-credentials sweep decision, 2026-08-14): trying even a handful of known
defaults is real authentication-attempt traffic, and some ICS devices lock an account (or the
whole web UI) after a small number of failed attempts — a real availability risk (CWE-307-
adjacent), not a benign read. Gated the same as every other destructive check in this project.

params schema (all required except where noted):
  path:            URL path to request, e.g. "/" or "/login"
  credentials:      list of [username, password] pairs to try, in order — stops at first success
  success_status:  HTTP status code that means "authenticated" (default: 200)
  https:           bool, use HTTPS instead of HTTP (default: false)
  default_port:    fallback port if the target inventory entry doesn't specify one
"""

from __future__ import annotations

import base64
import http.client
import ssl
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

# Embedded ICS web UIs overwhelmingly use self-signed or expired certificates for local HTTPS
# management interfaces, not certs chained to a CA this scanning host trusts. http.client.
# HTTPSConnection verifies by default (confirmed 2026-08-14, Phase 8: it silently turned every
# https:true probe into a false "not applicable" against a self-signed-cert mock server, the
# SSLCertVerificationError swallowed by the same except clause as a real connection failure) —
# same failure mode every vulnerability scanner (nmap, nuclei) deliberately avoids by not
# verifying certs when the whole point is probing a specific target's own service, not trusting
# it as a relying party. Verification is deliberately skipped for this destructive-recon use
# case, not an oversight.
_UNVERIFIED_TLS_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_UNVERIFIED_TLS_CONTEXT.check_hostname = False
_UNVERIFIED_TLS_CONTEXT.verify_mode = ssl.CERT_NONE


class HttpBasicAuthDefaultCredsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        credentials = params.get("credentials", [])
        path = params.get("path", "/")
        success_status = params.get("success_status", 200)
        use_https = params.get("https", False)
        port = target.port or params.get("default_port", 443 if use_https else 80)

        if not credentials:
            return self._result(target, CheckStatus.ERROR, description="check has no credentials configured in params")

        for username, password in credentials:
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            status = self._try_one(target.host, port, path, username, password, use_https)
            if status is None:
                continue  # connection error on this attempt — try the next credential anyway
            if status == success_status:
                return self._result(
                    target,
                    CheckStatus.CONFIRMED,
                    description=f"default credential '{username}:{password}' accepted at {path} (HTTP {status})",
                )

        return self._result(
            target,
            CheckStatus.NOT_APPLICABLE,
            description=f"none of {len(credentials)} tested default credential(s) were accepted at {path}",
        )

    def _try_one(self, host: str, port: int, path: str, username: str, password: str, use_https: bool) -> Optional[int]:
        conn = None
        try:
            if use_https:
                conn = http.client.HTTPSConnection(host, port, timeout=5.0, context=_UNVERIFIED_TLS_CONTEXT)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=5.0)
            creds = base64.b64encode(f"{username}:{password}".encode()).decode()
            conn.request("GET", path, headers={"Authorization": f"Basic {creds}"})
            resp = conn.getresponse()
            resp.read()
            return resp.status
        except (OSError, http.client.HTTPException):
            return None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
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


CHECK_CLASS = HttpBasicAuthDefaultCredsCheck
