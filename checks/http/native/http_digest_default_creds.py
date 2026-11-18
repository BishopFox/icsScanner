"""Generic native check — HTTP Digest Auth default-credential test (RFC 2617 / RFC 7616).

Built 2026-10-06 for Intel AMT (the AMT web management interface on ports 16992/16993 uses HTTP
Digest by default), but written generically: the credential list, path, success condition, and an
optional realm filter all come from CheckMetadata.params, so any embedded web UI gated by HTTP
Digest is a new YAML, not new Python. (Basic-Auth UIs use basic_auth_default_creds.py;
form/JSON/vendor logins use their own executors.)

Flow (so it cannot false-positive on an unauthenticated endpoint):
  1. GET `path` with no auth. If it does NOT return 401 + a `WWW-Authenticate: Digest` challenge,
     the endpoint is not Digest-gated -> NOT_APPLICABLE ("no_challenge").
  2. Compute the Digest response for each credential (MD5 / MD5-sess, qop="auth" or legacy no-qop).
  3. Re-GET with the `Authorization: Digest ...` header. `success_status` (default 200) => the
     credential was accepted (CONFIRMED). A second 401 => rejected.

DESTRUCTIVE: real authentication-attempt traffic (same lockout reasoning as every credential check).

params schema:
  path:            URL path to request (default "/")
  credentials:     list of [username, password] pairs, tried in order
  success_status:  HTTP status meaning authenticated (default 200)
  realm_contains:  optional case-insensitive substring the challenge realm must contain for the
                   check to apply (e.g. "Digest:" for Intel AMT) — guards against mis-firing on an
                   unrelated Digest-gated service. If set and the realm doesn't match -> NOT_APPLICABLE.
  https:           bool (default false); default_port / timeout optional
"""

from __future__ import annotations

import hashlib
import http.client
import os
import re
import ssl
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_UNVERIFIED_TLS_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_UNVERIFIED_TLS_CONTEXT.check_hostname = False
_UNVERIFIED_TLS_CONTEXT.verify_mode = ssl.CERT_NONE

# key=value or key="value" tokens in a WWW-Authenticate: Digest header
_TOKEN_RE = re.compile(r'(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))')


def _md5(s: str) -> str:
    return hashlib.md5(s.encode("latin-1", "replace")).hexdigest()


def parse_digest_challenge(header: str) -> Optional[dict]:
    """Parse a `WWW-Authenticate: Digest ...` header value into a dict. Returns None if not Digest."""
    if not header:
        return None
    # tolerate multiple comma-joined schemes; isolate the Digest one
    idx = header.lower().find("digest")
    if idx < 0:
        return None
    params = {}
    for m in _TOKEN_RE.finditer(header[idx + len("digest"):]):
        params[m.group(1).lower()] = m.group(2) if m.group(2) is not None else m.group(3)
    return params


def build_digest_authorization(username: str, password: str, method: str, uri: str,
                               challenge: dict, cnonce: Optional[str] = None,
                               nc: str = "00000001") -> str:
    """Compute an `Authorization: Digest` header value (RFC 2617/7616; MD5 + MD5-sess, qop auth)."""
    realm = challenge.get("realm", "")
    nonce = challenge.get("nonce", "")
    algorithm = (challenge.get("algorithm") or "MD5")
    qop_raw = challenge.get("qop")
    opaque = challenge.get("opaque")
    if cnonce is None:
        cnonce = os.urandom(8).hex()

    ha1 = _md5(f"{username}:{realm}:{password}")
    if algorithm.lower() == "md5-sess":
        ha1 = _md5(f"{ha1}:{nonce}:{cnonce}")
    ha2 = _md5(f"{method}:{uri}")

    # pick qop=auth if offered (it may be a comma list like "auth,auth-int")
    qop = None
    if qop_raw:
        for q in (x.strip() for x in qop_raw.split(",")):
            if q == "auth":
                qop = "auth"
                break

    if qop == "auth":
        response = _md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    else:
        response = _md5(f"{ha1}:{nonce}:{ha2}")  # legacy RFC 2069

    parts = [
        f'username="{username}"', f'realm="{realm}"', f'nonce="{nonce}"',
        f'uri="{uri}"', f'response="{response}"',
    ]
    if algorithm:
        parts.append(f"algorithm={algorithm}")
    if qop == "auth":
        parts.append("qop=auth")
        parts.append(f"nc={nc}")
        parts.append(f'cnonce="{cnonce}"')
    if opaque is not None:
        parts.append(f'opaque="{opaque}"')
    return "Digest " + ", ".join(parts)


class HttpDigestDefaultCredsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        credentials = params.get("credentials", [])
        path = params.get("path", "/")
        success_status = params.get("success_status", 200)
        realm_contains = params.get("realm_contains")
        use_https = params.get("https", False)
        port = target.port or params.get("default_port", 443 if use_https else 80)
        timeout = params.get("timeout", 5.0)

        if not credentials:
            return self._result(target, CheckStatus.ERROR, description="check has no credentials configured in params")

        for username, password in credentials:
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            outcome = self._try_one(target.host, port, path, username, password,
                                    success_status, realm_contains, use_https, timeout)
            if outcome == "auth_ok":
                return self._result(target, CheckStatus.CONFIRMED,
                                    description=f"default credential '{username}:{password}' accepted at {path} via HTTP Digest")
            if outcome == "no_challenge":
                return self._result(target, CheckStatus.NOT_APPLICABLE,
                                    description=f"{path} did not issue an HTTP Digest challenge — not applicable")
            if outcome == "realm_mismatch":
                return self._result(target, CheckStatus.NOT_APPLICABLE,
                                    description=f"Digest realm did not match required '{realm_contains}' — not applicable")
        return self._result(target, CheckStatus.NOT_APPLICABLE,
                            description=f"none of {len(credentials)} tested default credential(s) were accepted at {path}")

    def _try_one(self, host, port, path, username, password, success_status,
                 realm_contains, use_https, timeout) -> str:
        conn = None
        try:
            if use_https:
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=_UNVERIFIED_TLS_CONTEXT)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)

            # Step 1: unauthenticated GET -> expect a 401 Digest challenge.
            conn.request("GET", path)
            resp = conn.getresponse()
            resp.read()
            if resp.status != 401:
                return "no_challenge"
            challenge = parse_digest_challenge(resp.getheader("WWW-Authenticate"))
            if not challenge or "nonce" not in challenge:
                return "no_challenge"
            if realm_contains and realm_contains.lower() not in (challenge.get("realm", "").lower()):
                return "realm_mismatch"

            # Step 2+3: compute the Digest response and re-request.
            auth = build_digest_authorization(username, password, "GET", path, challenge)
            conn.request("GET", path, headers={"Authorization": auth})
            resp2 = conn.getresponse()
            resp2.read()
            if resp2.status == success_status:
                return "auth_ok"
            return "auth_failed"
        except (OSError, http.client.HTTPException):
            return "conn_error"
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


CHECK_CLASS = HttpDigestDefaultCredsCheck
