"""Generic native check — JSON-envelope-in-a-form-field login default-credential test. Distinct
from every other HTTP login executor in this project: json_post_default_creds.py and
json_rest_login_default_creds.py both POST a raw application/json BODY (no enclosing form field);
form_post_default_creds.py POSTs two independent application/x-www-form-urlencoded fields
(username_field, password_field). This module POSTs a SINGLE application/x-www-form-urlencoded
field whose VALUE is itself a JSON-encoded envelope carrying the username/password as nested keys
— a distinct shape some embedded web UIs use when their JS front end funnels every backend RPC
call (not just login) through one generic "command" endpoint, serializing a `{obj, data}`-style
envelope into a single POST field rather than hitting a dedicated REST route.

Built 2026-10-02 for Phoenix Contact TC EXTENDER
(checks/candidates/phoenix-contact-tc-extender-default-admin-password.yaml), the first candidate
this project found needing this exact shape — confirmed from BOTH sides of the real firmware
(FW_EXTENDER_v512_20260324.zip, firmware 512/2026-03-24): the server (home/web/html/pxc_json.php)
and the actual client JS that builds the real request (home/web/html/js/helpfunctions.js's
`sendJsonDataObjectReturn`, called from headline.js's `login_data()`). The real request:
    POST /pxc_json.php
    Content-Type: application/x-www-form-urlencoded (jQuery $.ajax default)
    Body: cmd=<urlencoded JSON>  where the JSON (before encoding) is exactly
          [{"obj":"usrLogin","data":{"uname":"<username>","pw":"<password>"}}]
and the response is a JSON object whose `loginState` field is 1 on success, 0 on failure — the
KEY is present in both cases, so a key-presence check (like json_rest_login_default_creds.py's
success_json_keys) can't distinguish them; this needs an explicit field=value match instead.

Reusable across vendors: envelope field name, obj name, nested field names, path, credentials,
and success criteria all come from CheckMetadata.params, not per-vendor Python — same convention
as every other *_default_creds.py executor in this project. The one-object-per-array-envelope
shape (`[{"obj": ..., "data": {...}}]`) is itself taken as a params-level constant per check
rather than hardcoded, in case a future candidate's envelope nests the username/password one
level differently — though no such candidate exists yet, so this stays the only envelope shape
supported (see KNOWN LIMITATION below).

DESTRUCTIVE: same reasoning as every other credential-testing check here — real
authentication-attempt traffic, lockout risk on devices that implement one.

REQUIRED EXPLICIT SUCCESS CRITERIA — same deliberate design choice as every other HTTP login
executor in this project (the SEL-relay Telnet near-miss is the reason this convention exists at
all, see form_post_default_creds.py's own docstring). At least one of `success_status` or
(`success_json_field` + `success_json_value`) MUST be configured, or the check returns ERROR
immediately rather than guessing.

KNOWN LIMITATION, deliberately not built: only the exact `[{"obj": ..., "data": {...}}]`
single-element-array envelope shape is supported (TC EXTENDER's own confirmed shape) — no support
for a differently-nested envelope, multiple commands batched in one array, or a non-array
top-level envelope. No real candidate has demonstrated needing any of those; add support if one
does, not preemptively. No cookie-jar or multi-step session handling either, matching every
sibling executor's own stated limitation.

params schema:
  path:                  URL path to POST to, e.g. "/pxc_json.php".
  envelope_field:        the single form field name carrying the JSON envelope, e.g. "cmd".
  obj_name:              the literal value for the envelope's "obj" key, e.g. "usrLogin".
  password_only:         bool, default false. Set true if the envelope's "data" object has no
                         username key at all — same convention as every other *_default_creds.py
                         executor's flag of the same name.
  username_field:        nested JSON key (inside "data") for the username, e.g. "uname" —
                         required unless password_only is true.
  password_field:        nested JSON key (inside "data") for the password, e.g. "pw" — always
                         required.
  credentials:           list of [username, password] pairs, tried in order — stops at first
                         success. For password_only endpoints, username is ignored
                         (conventionally "" in the YAML).
  success_status:        optional HTTP status code that means "authenticated".
  success_json_field:    optional top-level JSON key in the response body to inspect for a
                         specific value (e.g. "loginState") — paired with success_json_value.
  success_json_value:    the value success_json_field must equal (compared after JSON parsing, so
                         1 matches a JSON integer 1, not the string "1") — required if
                         success_json_field is set.
  https:                 bool, use HTTPS instead of HTTP (default: false).
  default_port:          fallback port if the target doesn't specify one (default 80, or 443 if
                         https).
  timeout:               per-request timeout in seconds (default 5.0).

  At least one of success_status / (success_json_field + success_json_value) MUST be set, or the
  check returns ERROR immediately (a configuration error, not a probe result) rather than
  guessing.
"""

from __future__ import annotations

import http.client
import json
import ssl
import urllib.parse

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_UNVERIFIED_TLS_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_UNVERIFIED_TLS_CONTEXT.check_hostname = False
_UNVERIFIED_TLS_CONTEXT.verify_mode = ssl.CERT_NONE

_SENTINEL = object()


class JsonEnvelopePostDefaultCredsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        credentials = params.get("credentials", [])
        path = params.get("path")
        envelope_field = params.get("envelope_field")
        obj_name = params.get("obj_name")
        password_only = params.get("password_only", False)
        username_field = params.get("username_field")
        password_field = params.get("password_field")
        success_status = params.get("success_status")
        success_json_field = params.get("success_json_field")
        success_json_value = params.get("success_json_value", _SENTINEL)
        use_https = params.get("https", False)
        port = target.port or params.get("default_port", 443 if use_https else 80)
        timeout = params.get("timeout", 5.0)

        if not credentials:
            return self._result(target, CheckStatus.ERROR, description="check has no credentials configured in params")
        if not path:
            return self._result(target, CheckStatus.ERROR, description="check has no path configured in params")
        if not envelope_field:
            return self._result(target, CheckStatus.ERROR, description="check has no envelope_field configured in params")
        if not obj_name:
            return self._result(target, CheckStatus.ERROR, description="check has no obj_name configured in params")
        if not password_field:
            return self._result(target, CheckStatus.ERROR, description="check has no password_field configured in params")
        if not password_only and not username_field:
            return self._result(target, CheckStatus.ERROR, description="check has no username_field configured in params (set password_only:true if this envelope has no username key)")
        if success_status is None and (not success_json_field or success_json_value is _SENTINEL):
            return self._result(target, CheckStatus.ERROR, description="check has neither success_status nor a complete success_json_field/success_json_value pair configured — explicit success criteria are required, not guessed")

        for username, password in credentials:
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            outcome = self._try_one(
                target.host, port, path, envelope_field, obj_name, username, password,
                password_only, username_field, password_field, success_status,
                success_json_field, success_json_value, use_https, timeout,
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
        self, host, port, path, envelope_field, obj_name, username, password,
        password_only, username_field, password_field, success_status,
        success_json_field, success_json_value, use_https, timeout,
    ) -> str:
        conn = None
        try:
            data = {password_field: password}
            if not password_only:
                data[username_field] = username
            envelope = json.dumps([{"obj": obj_name, "data": data}])
            body = urllib.parse.urlencode({envelope_field: envelope})

            if use_https:
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=_UNVERIFIED_TLS_CONTEXT)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request(
                "POST", path, body=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp = conn.getresponse()
            resp_body = resp.read()

            if success_status is not None and resp.status == success_status:
                return "auth_ok"
            if success_json_field:
                try:
                    parsed = json.loads(resp_body)
                except (ValueError, UnicodeDecodeError):
                    parsed = None
                if isinstance(parsed, dict) and parsed.get(success_json_field) == success_json_value:
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


CHECK_CLASS = JsonEnvelopePostDefaultCredsCheck
