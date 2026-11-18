"""Native check — Hesai LiDAR web-control (`pandar.cgi`) default-credential test.

Vendor-specific, like moxa_web_login_default_creds.py / iologik_challenge_response_default_creds.py:
the Hesai LiDAR web control does not use HTTP Basic Auth or a plain form POST. Its login wire
format was characterized directly from Hesai's own sample code
(github.com/HesaiTechnology/Cyber_Security, Point_Cloud_Signature/ptc_cgi_sample/cgi/py/http.py --
the vendor's own `HttpsApi.login()`):

    url  = 'http://<ip>/pandar.cgi?action=get&object=login'
    data = {'key': <username>, 'value': base64(<password>)}     # password is base64-encoded
    res  = requests.post(url, json=data)
    # success -> response JSON carries a session cookie at Body.cookie.name / Body.cookie.value

So the credential test is: POST that JSON body (password base64-encoded in `value`) and treat a
response whose JSON contains a non-empty cookie value (default path `Body.cookie.value`) as
"authenticated". The default password is `123456`, documented verbatim in Hesai's own user manuals
(Pandar128E3X, QT128C2X, et al.: "Default password: 123456 ... please change the default
password") -- the Moxa/WAGO documented-default class (disclosure_status: public), legitimate
detection, not a novel vuln.

CONFIRMED (vendor sample code): endpoint, method, JSON `{key,value}` body, base64-of-password in
`value`, and the Body.cookie.value success shape. CONFIRMED (vendor manuals): the default login is
`admin` / `123456` -- QT128C2X_User_Manual §4.9 Login tabulates "Username admin" + "Default
password: 123456" -- and web auth is OFF by default (gated behind the "Cyber Security Master
Switch"). (The sample code masked the username as `default_admin='*****'`; the manual resolves it
to `admin`.) confidence:low is kept only because this was not tested against live hardware, not
because of any credential uncertainty.

DESTRUCTIVE: a real login attempt -- same gating as every other credential-testing check here.

params schema:
  path:            login URL path (default: "/pandar.cgi?action=get&object=login")
  credentials:     list of [username, password] pairs to try, in order -- stops at first success
  value_b64:       bool, base64-encode the password into the `value` field (default: true -- the
                   confirmed Hesai behavior). false sends the raw password.
  key_field:       JSON field name for the username (default: "key")
  value_field:     JSON field name for the (base64) password (default: "value")
  cookie_key_path: dotted path into the response JSON whose non-empty value means "authenticated"
                   (default: "Body.cookie.value")
  https:           bool, use HTTPS (default: false -- the device default is plain HTTP)
  default_port:    fallback port if the target has none
"""

from __future__ import annotations

import base64
import http.client
import json
import ssl
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_UNVERIFIED_TLS_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_UNVERIFIED_TLS_CONTEXT.check_hostname = False
_UNVERIFIED_TLS_CONTEXT.verify_mode = ssl.CERT_NONE

_MISSING = object()


class HesaiPandarCgiLoginDefaultCredsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        credentials = params.get("credentials", [])
        path = params.get("path", "/pandar.cgi?action=get&object=login")
        value_b64 = params.get("value_b64", True)
        key_field = params.get("key_field", "key")
        value_field = params.get("value_field", "value")
        cookie_key_path = params.get("cookie_key_path", "Body.cookie.value")
        use_https = params.get("https", False)
        port = target.port or params.get("default_port", 443 if use_https else 80)

        if not credentials:
            return self._result(target, CheckStatus.ERROR, description="check has no credentials configured in params")

        for username, password in credentials:
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            value = base64.b64encode(password.encode()).decode() if value_b64 else password
            body = json.dumps({key_field: username, value_field: value}).encode()
            parsed = self._try_one(target.host, port, path, body, use_https)
            if parsed is None:
                continue  # connection/HTTP/JSON error on this attempt -- try the next credential
            if self._cookie_present(parsed, cookie_key_path):
                shown = f"{username}:{password}" if username else password
                return self._result(
                    target, CheckStatus.CONFIRMED,
                    description=(f"default credential '{shown}' accepted at {path} "
                                f"(session cookie returned at '{cookie_key_path}')"),
                )

        return self._result(
            target, CheckStatus.NOT_APPLICABLE,
            description=f"none of {len(credentials)} tested default credential(s) were accepted at {path}",
        )

    def _try_one(self, host: str, port: int, path: str, body: bytes, use_https: bool) -> Optional[dict]:
        conn = None
        try:
            if use_https:
                conn = http.client.HTTPSConnection(host, port, timeout=5.0, context=_UNVERIFIED_TLS_CONTEXT)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=5.0)
            conn.request("POST", path, body=body, headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            raw = resp.read()
            if resp.status != 200:
                return None
            try:
                return json.loads(raw.decode("utf-8", errors="replace"))
            except ValueError:
                return None
        except (OSError, http.client.HTTPException):
            return None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass

    @staticmethod
    def _cookie_present(parsed, dotted_path: str) -> bool:
        """True iff `dotted_path` (e.g. "Body.cookie.value") resolves to a non-empty value."""
        if not isinstance(parsed, dict):
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


CHECK_CLASS = HesaiPandarCgiLoginDefaultCredsCheck
