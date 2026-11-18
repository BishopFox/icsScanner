"""Generic native check — JSON-body HTTP POST login (optionally with one static extra header),
default-credential test.

Distinct from both checks/http/native/basic_auth_default_creds.py (an Authorization header, no
body at all) and checks/http/native/form_post_default_creds.py (application/x-www-form-urlencoded
body, no extra headers): this module POSTs an application/json body and can attach ONE static
extra header the target's login route expects (e.g. a CSRF-style header) — increasingly the
mechanism modern JS-framework (Angular/React) embedded web UIs use, since they're built as an SPA
calling a REST API rather than serving a classic server-rendered HTML form.

Built 2026-09-14 for the Siemens SCALANCE LPE9403 candidate
(checks/http/siemens-scalance-lpe9403-edgebox-web-app-default-creds.yaml), the first candidate in
this project confirmed to need this exact mechanism.

STATIC HEADER VALUE, NOT A FETCHED TOKEN — a deliberate design choice, verified directly against
the real client source, not a guess or a workaround. The LPE9403's own Angular frontend bundle
(main-*.js, extracted from its firmware) was read directly: its login() method attaches
`"X-CSRF-TOKEN": `${this.sessionService.getCsrfToken()}`` to the request, where getCsrfToken()
reads `sessionStorage.getItem("csrfToken")`. Grepping the WHOLE bundle confirms sessionStorage is
only ever POPULATED with a csrfToken value INSIDE the login response handler itself (i.e. AFTER a
successful login) — there is no earlier bootstrap call, cookie, or app-initializer that seeds a
real value beforehand, and the app never reads a CSRF value from a cookie either (this is the
app's own custom header, not Angular's built-in HttpClientXsrfModule, which uses a differently-
named header and a cookie it would read automatically). This means a genuine fresh browser
session's very FIRST login POST carries the literal string "null" (JavaScript's default toString
of a null sessionStorage read, interpolated into the template literal) as this header's value —
this executor reproduces that exact real behavior via a configurable static `extra_header_value`,
rather than implementing a token pre-fetch step no real candidate has actually demonstrated
needing (same "don't build speculative complexity ahead of a real requirement" principle
form_post_default_creds.py's own docstring already states for its own CSRF-prefetch gap). If a
FUTURE candidate is found that genuinely requires a freshly-fetched, per-session token value,
that is real new work for this module to grow into — not assumed solved by this design.

DESTRUCTIVE: same reasoning as every other credential-testing check here — real
authentication-attempt traffic, lockout risk on devices that implement one.

REQUIRED EXPLICIT SUCCESS CRITERIA, same non-negotiable rule as form_post_default_creds.py: the
check YAML must configure success_status and/or success_body_field, or the check returns ERROR
rather than guessing — HTML/JSON login responses have too many different "did it work" shapes to
trust a keyword-free fallback.

params schema:
  path:                 URL path to POST to, e.g. "/auth/login"
  username_field:       JSON body field name for the username, e.g. "username"
  password_field:       JSON body field name for the password, e.g. "password"
  credentials:          list of [username, password] pairs, tried in order — stops at first
                        success
  extra_header_name:    optional extra header name to send on every attempt (e.g. "X-CSRF-TOKEN")
  extra_header_value:   the literal value to send for extra_header_name — required if
                        extra_header_name is set. See the design note above for why a literal
                        static value (not a fetched token) is correct here.
  success_status:       optional HTTP status code that means "authenticated" (e.g. 200)
  success_body_field:   optional JSON key expected to be present with a truthy value in the
                        response BODY on success (e.g. "sessionToken") — the response is parsed
                        as JSON; a non-JSON or non-dict body is treated as this criterion failing
  https:                bool, use HTTPS instead of HTTP (default: false)
  default_port:         fallback port if the target doesn't specify one (default 80, or 443 if
                        https)
  timeout:              per-request timeout in seconds (default 5.0)

  At least one of success_status / success_body_field MUST be set, or the check returns ERROR
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


class JsonPostDefaultCredsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        credentials = params.get("credentials", [])
        path = params.get("path")
        username_field = params.get("username_field")
        password_field = params.get("password_field")
        extra_header_name = params.get("extra_header_name")
        extra_header_value = params.get("extra_header_value")
        success_status = params.get("success_status")
        success_body_field = params.get("success_body_field")
        use_https = params.get("https", False)
        port = target.port or params.get("default_port", 443 if use_https else 80)
        timeout = params.get("timeout", 5.0)

        if not credentials:
            return self._result(target, CheckStatus.ERROR, description="check has no credentials configured in params")
        if not path:
            return self._result(target, CheckStatus.ERROR, description="check has no path configured in params")
        if not password_field:
            return self._result(target, CheckStatus.ERROR, description="check has no password_field configured in params")
        if not username_field:
            return self._result(target, CheckStatus.ERROR, description="check has no username_field configured in params")
        if extra_header_name and extra_header_value is None:
            return self._result(target, CheckStatus.ERROR, description="check sets extra_header_name but no extra_header_value")
        if success_status is None and not success_body_field:
            return self._result(target, CheckStatus.ERROR, description="check has neither success_status nor success_body_field configured — explicit success criteria are required, not guessed")

        for username, password in credentials:
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            outcome = self._try_one(
                target.host, port, path, username, password,
                username_field, password_field, extra_header_name, extra_header_value,
                success_status, success_body_field, use_https, timeout,
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
        self, host, port, path, username, password,
        username_field, password_field, extra_header_name, extra_header_value,
        success_status, success_body_field, use_https, timeout,
    ) -> str:
        conn = None
        try:
            body = json.dumps({username_field: username, password_field: password}).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            if extra_header_name:
                headers[extra_header_name] = extra_header_value

            if use_https:
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=_UNVERIFIED_TLS_CONTEXT)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read()

            if success_status is not None and resp.status != success_status:
                return "auth_failed"

            if success_body_field:
                try:
                    parsed = json.loads(resp_body.decode("utf-8", errors="replace"))
                except json.JSONDecodeError:
                    return "auth_failed"
                if not isinstance(parsed, dict) or not parsed.get(success_body_field):
                    return "auth_failed"

            return "auth_ok"
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


CHECK_CLASS = JsonPostDefaultCredsCheck
