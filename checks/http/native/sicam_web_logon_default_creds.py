"""Native check — Siemens "SICAM WEB" Cmd_LogOn default-credential test.

Distinct from checks/http/native/form_post_default_creds.py and basic_auth_default_creds.py:
SICAM WEB (the embedded web management interface on SICAM A8000 Series / SICAM RTUs devices)
uses neither a standard HTML form POST nor an HTTP Basic Auth challenge — it's a custom XML
command API. Reverse-engineered directly from a genuine, UNENCRYPTED SICAM WEB frontend package
(SWEB00-SWEB00_V26.20_all.ipk, an ordinary opkg/ar archive -> data.tar.gz -> a real webpack-built
JS single-page app, all extracted and read in the clear — no firmware decryption or disassembly
needed, unlike most of this project's other SICAM/SIPROTEC RE work). The exact request the app's
own login dialog issues, found directly in its bundled JS (module `requestLogOn`):

    POST /sicweb-ajax/auth
    Content-Type: application/xml

    <?xml version="1.0" encoding="UTF-8"?>
    <Cmd_LogOn><authentication user="USERNAME" pwd="PASSWORD"/><language id="en"/></Cmd_LogOn>

And the response parser the same app uses (`responseLogOnLogOff`): a successful login is
indicated by a `<status value="1">` or `<status value="3">` element together with a `<Rsp_LogOn>`
element both present in the response body — any other status value, or a `<Rsp_LogOn>` absent
from an otherwise-successful-looking status, is a rejection. A `<Rsp_LogOn>` element may carry a
`<role id="...">` child (the authenticated user's role) and a `<pwd_change force="true|false">`
child (whether the device is forcing a password change on this login) — surfaced in the
CONFIRMED description when present, same "the credential still authenticated, note the nuance,
don't downgrade the verdict" philosophy already used by this project's other credential checks
(e.g. snmpv3_default_creds.py's authorizationError-still-CONFIRMED handling).

PARSING CHOICE, deliberate: uses targeted regexes over the response text rather than a full XML
parse (xml.etree.ElementTree or similar). The response shape needed is narrow and known (a
handful of specific elements/attributes), and avoiding a general-purpose XML parser on
network-supplied data sidesteps entity-expansion/XXE-class parser risk entirely for a case that
doesn't need general XML robustness — the same "no premature complexity" reasoning already
documented in form_post_default_creds.py for its own encoding-support choice.

No session-ID header is sent — reading the same app's own error-handling code (a Cmd_LogOff sent
on unexpected termination) shows the custom `SICWEB-SID` header is only used for an ALREADY-
established session; the initial Cmd_LogOn this check performs is exactly what a browser sends on
a fresh page load, with no prior session, matching the request shape found in the frontend's own
code (no SID header attached at the point requestLogOn is called from the login dialog).

REACHABILITY/SCHEME NOTE: the SICAM A8000 Series manual documents SICAM WEB as reachable via both
HTTP (port 80) and HTTPS (port 443) as separate, both-optional-per-footnote entries under "Web
server" in its own port table. Which one is the actual default for a specific CPC80/CP-8000 unit
is not stated explicitly in the source read for this check (unlike a newer sibling module, CPCI85,
whose own manual passage says HTTPS is merely "possible," implying HTTP as the base case) — this
executor defaults to plain HTTP (`https: false`) on that same "older platform, unencrypted base
case" reasoning, with `https: true` a one-line params override if a specific target needs it.

DESTRUCTIVE: a real authentication attempt against the device's live user-management/session
system, same reasoning as every other credential-testing check in this project.

params schema:
  credentials:    list of [username, password] pairs, tried in order — stops at first accepted.
  path:           URL path to POST to (default "/sicweb-ajax/auth" — the literal path found in
                  the vendor's own frontend code; overridable in case a sibling product uses a
                  different path).
  language_id:    the <language id="..."/> value sent (default "en" — cosmetic, does not affect
                  authentication outcome as far as the reverse-engineered client code shows).
  https:          bool, use HTTPS instead of HTTP (default: false — see REACHABILITY note above).
  default_port:   fallback port if the target doesn't specify one (default 80, or 443 if https).
  timeout:        per-request timeout in seconds (default 5.0).
"""

from __future__ import annotations

import http.client
import re
import ssl
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_UNVERIFIED_TLS_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_UNVERIFIED_TLS_CONTEXT.check_hostname = False
_UNVERIFIED_TLS_CONTEXT.verify_mode = ssl.CERT_NONE

_STATUS_RE = re.compile(r'<status\s+value="([^"]*)"')
_ROLE_RE = re.compile(r'<role\s+id="([^"]*)"')
_PWD_CHANGE_RE = re.compile(r'<pwd_change\s+force="([^"]*)"')
_ERROR_TEXT_RE = re.compile(r"<text>([^<]*)</text>")
_SUCCESS_STATUSES = {"1", "3"}


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _build_logon_body(username: str, password: str, language_id: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<Cmd_LogOn><authentication user="{_xml_escape(username)}" pwd="{_xml_escape(password)}"/>'
        f'<language id="{_xml_escape(language_id)}"/></Cmd_LogOn>'
    )


def _parse_logon_response(body_text: str) -> dict:
    result = {"status": None, "logon_ok": False, "role": None, "force_pwd_change": None, "error_text": None}
    status_match = _STATUS_RE.search(body_text)
    if status_match:
        result["status"] = status_match.group(1)
    has_rsp_logon = "<Rsp_LogOn" in body_text
    if result["status"] in _SUCCESS_STATUSES and has_rsp_logon:
        result["logon_ok"] = True
        role_match = _ROLE_RE.search(body_text)
        if role_match:
            result["role"] = role_match.group(1)
        pwd_change_match = _PWD_CHANGE_RE.search(body_text)
        if pwd_change_match:
            result["force_pwd_change"] = pwd_change_match.group(1) == "true"
    else:
        error_match = _ERROR_TEXT_RE.search(body_text)
        if error_match:
            result["error_text"] = error_match.group(1)
    return result


class SicamWebLogonDefaultCredsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        credentials = params.get("credentials", [])
        path = params.get("path", "/sicweb-ajax/auth")
        language_id = params.get("language_id", "en")
        use_https = params.get("https", False)
        port = target.port or params.get("default_port", 443 if use_https else 80)
        timeout = params.get("timeout", 5.0)

        if not credentials:
            return self._result(target, CheckStatus.ERROR, description="check has no credentials configured in params")

        for username, password in credentials:
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            outcome = self._try_one(target.host, port, path, username, password, language_id, use_https, timeout)
            if outcome is not None and outcome["logon_ok"]:
                extra = []
                if outcome["role"]:
                    extra.append(f"role={outcome['role']}")
                if outcome["force_pwd_change"] is not None:
                    extra.append(f"forced password change={'yes' if outcome['force_pwd_change'] else 'no'}")
                detail = f" ({', '.join(extra)})" if extra else ""
                return self._result(
                    target,
                    CheckStatus.CONFIRMED,
                    description=f"SICAM WEB credential '{username}:{password}' accepted at {path}{detail}",
                )

        return self._result(
            target,
            CheckStatus.NOT_APPLICABLE,
            description=f"none of {len(credentials)} tested SICAM WEB credential(s) were accepted at {path}",
        )

    def _try_one(self, host, port, path, username, password, language_id, use_https, timeout) -> Optional[dict]:
        conn = None
        try:
            body = _build_logon_body(username, password, language_id)
            if use_https:
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=_UNVERIFIED_TLS_CONTEXT)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request("POST", path, body=body, headers={"Content-Type": "application/xml"})
            resp = conn.getresponse()
            resp_text = resp.read().decode("utf-8", errors="replace")
            return _parse_logon_response(resp_text)
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


CHECK_CLASS = SicamWebLogonDefaultCredsCheck
