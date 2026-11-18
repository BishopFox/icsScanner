"""Generic native check — JSON REST API login default-credential test. Distinct from
checks/http/native/basic_auth_default_creds.py (an Authorization header challenge, no page
content) and checks/http/native/form_post_default_creds.py (a classic
application/x-www-form-urlencoded HTML form POST): this module POSTs a JSON request body to a
REST login endpoint and expects a JSON response — the shape a modern device REST API (typically
returning a bearer token on success) uses instead of either older pattern.

Built 2026-09-22 for Bosch Rexroth ctrlX CORE (checks/candidates/
bosch-rexroth-ctrlx-core-default-creds.yaml), the first candidate this session to have its exact
login wire format fully characterized (from Bosch's own official OpenAPI spec: POST /auth/token,
{"name": ..., "password": ...}, HTTP 201 on success with a Token-schema body, HTTP 401 on
failure) but with no existing executor able to drive it — neither basic_auth_default_creds.py
nor form_post_default_creds.py speaks JSON request/response bodies. Built as a new, genuinely
reusable capability (this exact JSON-login shape is common across modern device REST APIs, not
unique to ctrlX CORE), matching this project's established convention of building the missing
CAPABILITY rather than a one-off for a single vendor — same reasoning already applied when
form_post_default_creds.py itself was built.

Reusable across vendors: field names, path, credentials, and success criteria all come from
CheckMetadata.params, not per-vendor Python — same convention as every other *_default_creds.py
executor in this project.

DESTRUCTIVE: same reasoning as every other credential-testing check here — real
authentication-attempt traffic, lockout risk on devices that implement one.

REQUIRED EXPLICIT SUCCESS CRITERIA — same deliberate design choice as form_post_default_creds.py,
for the same reason (this project's SEL-relay Telnet near-miss with a weak "no failure keyword"
fallback). At least one of `success_status` or `success_json_keys` must be configured, or the
check returns ERROR immediately rather than guessing.

EXTENDED 2026-09-22 (same day, Moxa ThingsPro Gateway re-analysis) with `extra_fields`: the
ThingsPro Gateway web UI's real client code (found by extracting its shipped Angular bundle, not
guessed) POSTs a THIRD field, `isKeepEmail` (a "remember me" UI preference), alongside
email/password to its own /auth/local endpoint — the first real candidate needing more than
exactly two fields. Rather than assume the backend safely ignores an unexpected field, `params`
can now carry an optional flat dict of additional static fields merged into every request body.

KNOWN LIMITATION, deliberately not built: only flat JSON values are supported (strings, and now
via `extra_fields` also bools/numbers) — no nested objects. No cookie-jar or multi-step session
handling (e.g. fetching a CSRF/nonce token via GET first). No candidate this project has found so
far needs either; add if one does, not preemptively.

params schema:
  path:                 URL path to POST to, e.g. "/auth/token"
  password_only:        bool, default false. Set true for password-only endpoints (no username
                         field at all) — same convention as telnet_default_creds.py's flag of the
                         same name.
  username_field:       JSON field name for the username, e.g. "name" — required unless
                         password_only is true. NOTE: many REST APIs use a field literally named
                         "name" or "user" rather than "username" — read the actual API spec, do
                         not assume.
  password_field:       JSON field name for the password, e.g. "password" — always required.
  credentials:           list of [username, password] pairs, tried in order — stops at first
                         success. For password_only endpoints, username is ignored
                         (conventionally "" in the YAML).
  extra_fields:          optional flat dict of additional static field-name -> value pairs
                         merged into every request body (e.g. {"isKeepEmail": false}) — for an
                         endpoint whose real client sends more than just username/password.
                         Values are serialized as-is (str/bool/int/float/None all valid JSON
                         scalar types); no nested objects.
  success_status:        optional HTTP status code that means "authenticated" (e.g. 201 for
                         ctrlX CORE's POST /auth/token).
  success_json_keys:     optional list of top-level JSON key names — a successfully-parsed JSON
                         response body containing ANY of these keys (e.g. ["token",
                         "access_token"]) confirms success. Useful when the exact success status
                         code alone isn't a confident enough signal, or as a second check
                         alongside success_status.
  failure_status:        optional HTTP status code that means "rejected" (e.g. 401), checked
                         before success_status/success_json_keys — same ordering convention as
                         form_post_default_creds.py's failure_indicators.
  https:                 bool, use HTTPS instead of HTTP (default: false — most embedded device
                         REST APIs of this shape use HTTPS with a self-signed cert; set
                         explicitly per check, not assumed).
  default_port:          fallback port if the target doesn't specify one (default 80, or 443 if
                         https).
  timeout:               per-request timeout in seconds (default 5.0).

  At least one of success_status / success_json_keys MUST be set, or the check returns ERROR
  immediately (a configuration error, not a probe result) rather than guessing.
"""

from __future__ import annotations

import http.client
import json
import ssl

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_UNVERIFIED_TLS_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_UNVERIFIED_TLS_CONTEXT.check_hostname = False
_UNVERIFIED_TLS_CONTEXT.verify_mode = ssl.CERT_NONE


class JsonRestLoginDefaultCredsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        credentials = params.get("credentials", [])
        path = params.get("path")
        password_only = params.get("password_only", False)
        username_field = params.get("username_field")
        password_field = params.get("password_field")
        success_status = params.get("success_status")
        success_json_keys = params.get("success_json_keys")
        failure_status = params.get("failure_status")
        extra_fields = params.get("extra_fields") or {}
        use_https = params.get("https", False)
        port = target.port or params.get("default_port", 443 if use_https else 80)
        timeout = params.get("timeout", 5.0)

        if not credentials:
            return self._result(target, CheckStatus.ERROR, description="check has no credentials configured in params")
        if not path:
            return self._result(target, CheckStatus.ERROR, description="check has no path configured in params")
        if not password_field:
            return self._result(target, CheckStatus.ERROR, description="check has no password_field configured in params")
        if not password_only and not username_field:
            return self._result(target, CheckStatus.ERROR, description="check has no username_field configured in params (set password_only:true if this endpoint has no username field)")
        if success_status is None and not success_json_keys:
            return self._result(target, CheckStatus.ERROR, description="check has neither success_status nor success_json_keys configured — explicit success criteria are required, not guessed")

        for username, password in credentials:
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            outcome = self._try_one(
                target.host, port, path, username, password, password_only,
                username_field, password_field, success_status, success_json_keys,
                failure_status, extra_fields, use_https, timeout,
            )
            if outcome == "auth_ok":
                return self._result(
                    target,
                    CheckStatus.CONFIRMED,
                    description=f"default credential '{username}:{password}' accepted at {path}",
                )

        return self._result(
            target,
            CheckStatus.NOT_APPLICABLE,
            description=f"none of {len(credentials)} tested default credential(s) were accepted at {path}",
        )

    def _try_one(
        self, host, port, path, username, password, password_only,
        username_field, password_field, success_status, success_json_keys,
        failure_status, extra_fields, use_https, timeout,
    ) -> str:
        conn = None
        try:
            fields = dict(extra_fields)
            fields[password_field] = password
            if not password_only:
                fields[username_field] = username
            body = json.dumps(fields).encode("utf-8")

            if use_https:
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=_UNVERIFIED_TLS_CONTEXT)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request(
                "POST", path, body=body,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
            resp = conn.getresponse()
            resp_body = resp.read()

            if failure_status is not None and resp.status == failure_status:
                return "auth_failed"
            if success_status is not None and resp.status == success_status:
                return "auth_ok"
            if success_json_keys:
                try:
                    parsed = json.loads(resp_body)
                except (ValueError, UnicodeDecodeError):
                    parsed = None
                if isinstance(parsed, dict) and any(k in parsed for k in success_json_keys):
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


CHECK_CLASS = JsonRestLoginDefaultCredsCheck
