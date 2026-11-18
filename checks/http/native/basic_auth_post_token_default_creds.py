"""Generic native check — HTTP Basic Auth on a POST whose JSON response carries a session token,
default-credential test.

Distinct from the three existing default-creds executors here:
  - basic_auth_default_creds.py sends a GET and judges success purely by HTTP status.
  - json_rest_login_default_creds.py / json_post_default_creds.py carry the credentials IN the
    JSON request body (username/password fields), not in an Authorization header.
This module is the missing combination: the credentials go in an HTTP **Basic Auth header** on a
**POST** (optionally with a small JSON body), and success is confirmed by a **JSON key present
with a truthy value in the response body** (e.g. a session token), optionally also/instead by an
HTTP status. That is exactly the shape a token-minting endpoint uses when it authenticates with
Basic client credentials and returns a bearer token (OAuth2-client-credentials-like) rather than
echoing a login form. Built as a reusable CAPABILITY, not a one-off — the same convention every
other *_default_creds.py here follows (success criteria, path, body, credentials and the token
key path all come from CheckMetadata.params, not from per-vendor Python).

First consumer: SICK's device REST API (checks/http/sick-rest-api-service-default-creds.yaml).
Characterized directly from SICK AG's own MIT-licensed firmware_update_example.py (shipped in the
SICK firmware ingest, 2026-10-12), whose session step is literally:

    requests.post(f"{base}/api/CreateSessionToken", auth=("Service", password), json={})
                 .json()["data"]["token"]

i.e. HTTP Basic Auth ("Service", password), an empty JSON body, and a token nested at data.token
on success. This executor reproduces exactly that: Basic Auth + a configurable JSON body +
success when the configured dotted token key path resolves to a truthy value (and/or on a
configured success_status).

REQUIRED EXPLICIT SUCCESS CRITERIA — same deliberate design choice as the other POST-based
executors here (the SEL-relay Telnet near-miss lesson): at least one of `success_status` or
`token_key_path` MUST be configured, or the check returns ERROR rather than guessing.

DESTRUCTIVE: same reasoning as every other credential-testing check here — real
authentication-attempt traffic, lockout risk on devices that implement one.

params schema (all required except where noted):
  path:            URL path to POST to, e.g. "/api/CreateSessionToken"
  credentials:     list of [username, password] pairs to try, in order — stops at first success
  body:            optional JSON-serializable request body (default: {} — an empty JSON object,
                   which is what the SICK endpoint expects); set to null to send no body at all
  token_key_path:  optional dotted path into the parsed JSON response whose presence-with-truthy-
                   value means "authenticated", e.g. "data.token". Checked before success_status.
  success_status:  optional HTTP status code that also/instead means "authenticated"
  https:           bool, use HTTPS instead of HTTP (default: false)
  default_port:    fallback port if the target inventory entry doesn't specify one
"""

from __future__ import annotations

import base64
import http.client
import json
import ssl
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

# Embedded ICS web UIs overwhelmingly use self-signed/expired certs for local HTTPS management, not
# certs chained to a CA this host trusts — verify-by-default silently turns every https probe into
# a false NOT_APPLICABLE (see basic_auth_default_creds.py's note). Verification is deliberately
# skipped for this destructive-recon use case, same as every other HTTPS probe here.
_UNVERIFIED_TLS_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_UNVERIFIED_TLS_CONTEXT.check_hostname = False
_UNVERIFIED_TLS_CONTEXT.verify_mode = ssl.CERT_NONE

_MISSING = object()


class BasicAuthPostTokenDefaultCredsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        credentials = params.get("credentials", [])
        path = params.get("path")
        body = params.get("body", {})
        token_key_path = params.get("token_key_path")
        success_status = params.get("success_status")
        use_https = params.get("https", False)
        port = target.port or params.get("default_port", 443 if use_https else 80)

        if not credentials:
            return self._result(target, CheckStatus.ERROR, description="check has no credentials configured in params")
        if not path:
            return self._result(target, CheckStatus.ERROR, description="check has no 'path' configured in params")
        if token_key_path is None and success_status is None:
            return self._result(
                target, CheckStatus.ERROR,
                description="check must configure at least one of 'token_key_path' or 'success_status'",
            )

        for username, password in credentials:
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            outcome = self._try_one(target.host, port, path, username, password, body, use_https)
            if outcome is None:
                continue  # connection/HTTP error on this attempt — try the next credential anyway
            status, parsed = outcome
            if token_key_path is not None and self._token_present(parsed, token_key_path):
                return self._result(
                    target, CheckStatus.CONFIRMED,
                    description=(f"default credential '{username}:{password}' accepted at {path} "
                                f"(HTTP {status}, '{token_key_path}' returned in response body)"),
                )
            if success_status is not None and status == success_status:
                return self._result(
                    target, CheckStatus.CONFIRMED,
                    description=f"default credential '{username}:{password}' accepted at {path} (HTTP {status})",
                )

        return self._result(
            target, CheckStatus.NOT_APPLICABLE,
            description=f"none of {len(credentials)} tested default credential(s) were accepted at {path}",
        )

    def _try_one(self, host: str, port: int, path: str, username: str, password: str,
                 body, use_https: bool) -> Optional[tuple]:
        conn = None
        try:
            if use_https:
                conn = http.client.HTTPSConnection(host, port, timeout=5.0, context=_UNVERIFIED_TLS_CONTEXT)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=5.0)
            creds = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers = {"Authorization": f"Basic {creds}"}
            payload = b""
            if body is not None:
                payload = json.dumps(body).encode()
                headers["Content-Type"] = "application/json"
            conn.request("POST", path, body=payload, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            parsed = None
            try:
                parsed = json.loads(raw.decode("utf-8", errors="replace"))
            except ValueError:
                parsed = None
            return resp.status, parsed
        except (OSError, http.client.HTTPException):
            return None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass

    @staticmethod
    def _token_present(parsed, dotted_path: str) -> bool:
        """True iff `dotted_path` (e.g. "data.token") resolves to a truthy value in the parsed
        JSON. Any missing segment, non-dict traversal, or falsy/empty leaf -> False."""
        if not isinstance(parsed, (dict, list)):
            return False
        node = parsed
        for seg in dotted_path.split("."):
            if isinstance(node, dict):
                node = node.get(seg, _MISSING)
            else:
                return False
            if node is _MISSING:
                return False
        return bool(node)

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


CHECK_CLASS = BasicAuthPostTokenDefaultCredsCheck
