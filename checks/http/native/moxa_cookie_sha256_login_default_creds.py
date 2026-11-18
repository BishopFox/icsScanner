"""Native check — Moxa EDR secure-router web default-login (cookie-based sha256). A FIFTH Moxa login
variant (distinct from moxa_web_login_default_creds' A/B/C): confirmed from EDR-G902 v5.7 firmware
(Login.asp, via the moxa_rom sidecar handler). The EDR login form `InputPassword` carries a plaintext
`Username` field and sets the password as a COOKIE, not a form field:

    document.cookie = "PASSWORD=" + sha256(Password.value);   // theName="PASSWORD"
    form.action = "/init.asp"; form.submit();                 // posts Username, PASSWORD cookie rides along

So the credential test is: compute sha256_hex(password), send it as the `PASSWORD` cookie, and submit
`Username=<user>` to the action (default /init.asp). (When RADIUS is enabled the device sends the raw
password instead; this check targets the default local-auth path.) Success/failure are judged by the
device's own confirmed response strings ("Login Success" / "Authentication fail", read from firmware).

DOCUMENTED-DEFAULT class (Moxa declines these; and the EDR hardcoded-cred issue is itself already
disclosed+fixed per MPSA-220202) -> disclosure_status: public, a DETECTION check. DESTRUCTIVE: a real
login attempt. REQUIRED EXPLICIT SUCCESS CRITERIA: at least one of success_indicators / success_status
must be set (same discipline as the other default-creds executors).

params schema:
  action_path:        login POST/GET path (default "/init.asp")
  credentials:        list of [username, password] pairs, in order -- stops at first success
  username_field:     form field for the username (default "Username")
  cookie_name:        cookie that carries the hashed password (default "PASSWORD")
  method:             "POST" (default) or "GET"
  success_indicators: list of substrings that mean authenticated (e.g. ["Login Success"])
  failure_indicators: list of substrings that mean rejected (e.g. ["Authentication fail"])
  success_status:     optional HTTP status that means authenticated
  https / default_port / timeout
"""

from __future__ import annotations

import hashlib
import http.client
import ssl
import urllib.parse
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_UNVERIFIED_TLS_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_UNVERIFIED_TLS_CONTEXT.check_hostname = False
_UNVERIFIED_TLS_CONTEXT.verify_mode = ssl.CERT_NONE


class MoxaCookieSha256LoginDefaultCredsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        credentials = params.get("credentials", [])
        action_path = params.get("action_path", "/init.asp")
        username_field = params.get("username_field", "Username")
        cookie_name = params.get("cookie_name", "PASSWORD")
        method = (params.get("method", "POST") or "POST").upper()
        success_indicators = params.get("success_indicators")
        failure_indicators = params.get("failure_indicators")
        success_status = params.get("success_status")
        use_https = params.get("https", False)
        port = target.port or params.get("default_port", 443 if use_https else 80)
        timeout = params.get("timeout", 5.0)

        if not credentials:
            return self._result(target, CheckStatus.ERROR, description="check has no credentials configured in params")
        if not success_indicators and success_status is None:
            return self._result(target, CheckStatus.ERROR,
                                description="check must set success_indicators or success_status (no guessing)")

        for username, password in credentials:
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            outcome = self._try_one(target.host, port, action_path, username, password, username_field,
                                    cookie_name, method, success_indicators, failure_indicators,
                                    success_status, use_https, timeout)
            if outcome == "auth_ok":
                return self._result(target, CheckStatus.CONFIRMED,
                                    description=f"default credential '{username}:{password}' accepted via Moxa cookie-sha256 login at {action_path}")

        return self._result(target, CheckStatus.NOT_APPLICABLE,
                            description=f"none of {len(credentials)} tested default credential(s) were accepted at {action_path}")

    def _try_one(self, host, port, action_path, username, password, username_field, cookie_name,
                 method, success_indicators, failure_indicators, success_status, use_https, timeout) -> Optional[str]:
        conn = None
        try:
            pw_hash = hashlib.sha256(password.encode("latin-1", "replace")).hexdigest()
            headers = {"Cookie": f"{cookie_name}={pw_hash}"}
            body = urllib.parse.urlencode({username_field: username})
            if use_https:
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=_UNVERIFIED_TLS_CONTEXT)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            if method == "GET":
                conn.request("GET", action_path + ("?" + body if body else ""), headers=headers)
            else:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                conn.request("POST", action_path, body=body, headers=headers)
            resp = conn.getresponse()
            text = resp.read().decode("latin-1", errors="replace")
            if failure_indicators and any(fi in text for fi in failure_indicators):
                return "auth_failed"
            if success_indicators and any(si in text for si in success_indicators):
                return "auth_ok"
            if success_status is not None and resp.status == success_status:
                return "auth_ok"
            return "no_match"
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


CHECK_CLASS = MoxaCookieSha256LoginDefaultCredsCheck
