"""Native check — Moxa ioLogik E1200 series "Input Password" challenge-response default-
credential test.

Distinct from checks/http/native/form_post_default_creds.py and basic_auth_default_creds.py: the
ioLogik E1200 series web console accepts neither a plaintext credential POST nor an HTTP Basic
Auth challenge. Reverse-engineered directly from real firmware
(moxa-iologik-e1200-series-iologik-e1210-e1210-t-firmware-v4.0.1kp and the e1260 sibling, both
v4.0 -- see checks/candidates/moxa-iologik-e1200-e1500-railway-remote-io.yaml for the full
extraction trail). The login is PASSWORD-ONLY (no username field anywhere in the page). An
unauthenticated GET renders an "Input Password" page containing:

    <FORM name=InputPassword method="post" action=home.htm onSubmit="return SetPass(this);">
    <INPUT type="hidden" name="Token" value="<LOGIN_TOKEN>">
    ... <INPUT type=text name="Password" id="pd" style="display:none" ...> ...

and the page's own JS computes, on submit:

    var a = sha256(password + Token.value);
    Password.value = a;

i.e. the actual credential sent over the wire is SHA256(password + token), never the plaintext
password, and the token is a fresh value read out of the same page's own hidden field on every
load (not a fixed constant). On success the device responds with `Set-Cookie: MoxaPass=...`; on
failure it re-renders the same page with the literal string `<P>Invalid password !</P>` --
confirmed byte-for-byte in the firmware's own string table (not inferred from the template
`<FAIL_MSG>` placeholder).

The E1200H/E1200W hardware-variant firmware uses the IDENTICAL page shape and flow but MD5
instead of SHA256 (their own `SetPass()` calls `MD5(...)`, still sets `Set-Cookie: MoxaPass=...`
on success) -- the `hash_algo` param supports both so a future candidate for those variants can
reuse this module with zero new code. This check's own shipped params use sha256, matching the
confirmed core E1200/E1210/E1260 finding; the H/W variants were checked directly and do NOT
contain the literal "moxa" default (see the candidate file) -- do not assume they share it.

INFERRED, not independently confirmed against live hardware: that the login page is served at
the same path the form posts back to (`home.htm`) when unauthenticated, rather than at a separate
path like "/". This mirrors the same self-referencing-login-page pattern seen on the E1200H/E4200
siblings and is the most literal reading of the firmware's own template, but is an inference, not
a live-traffic capture -- overridable via the `path` param if a real target turns out to differ.

PARSING CHOICE, deliberate: a single targeted regex pulls the `Token` value out of the login page
rather than a full HTML parser -- the same "no premature complexity" reasoning already used by
sicam_web_logon_default_creds.py for its own XML response.

DESTRUCTIVE: a real authentication attempt against the device's live session system, same
reasoning as every other credential-testing check in this project. No documented lockout
mechanism was found for this login form.

params schema:
  credentials:   list of [_, password] pairs, tried in order -- stops at first accepted. The
                 login is password-only; each pair's first element is accepted but ignored, kept
                 as a 2-tuple only for consistency with every other credentials list in this
                 project.
  path:          URL path to GET the login page from and POST the response to (default
                 "/home.htm" -- the literal form `action` target found in the firmware).
  hash_algo:     "sha256" (default, confirmed for the core E1200 line) or "md5" (the
                 E1200H/E1200W shape -- not shipped as a credential this project has confirmed,
                 but supported for a future candidate).
  https:         bool, use HTTPS instead of HTTP (default: false).
  default_port:  fallback port if the target doesn't specify one (default 80, or 443 if https).
  timeout:       per-request timeout in seconds (default 5.0).
"""

from __future__ import annotations

import hashlib
import http.client
import re
import ssl
from typing import Optional
from urllib.parse import urlencode

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_UNVERIFIED_TLS_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_UNVERIFIED_TLS_CONTEXT.check_hostname = False
_UNVERIFIED_TLS_CONTEXT.verify_mode = ssl.CERT_NONE

_TOKEN_RE = re.compile(r'name="Token"\s+value="([^"]*)"')
_INVALID_PASSWORD_TEXT = b"Invalid password"

_HASH_FUNCS = {
    "sha256": hashlib.sha256,
    "md5": hashlib.md5,
}


class IologikChallengeResponseDefaultCredsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        credentials = params.get("credentials", [])
        path = params.get("path", "/home.htm")
        hash_algo = params.get("hash_algo", "sha256")
        use_https = params.get("https", False)
        port = target.port or params.get("default_port", 443 if use_https else 80)
        timeout = params.get("timeout", 5.0)

        if not credentials:
            return self._result(target, CheckStatus.ERROR, description="check has no credentials configured in params")
        hash_func = _HASH_FUNCS.get(hash_algo)
        if hash_func is None:
            return self._result(target, CheckStatus.ERROR, description=f"unknown hash_algo {hash_algo!r} in params")

        for _, password in credentials:
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            outcome = self._try_one(target.host, port, path, password, hash_func, use_https, timeout)
            if outcome is True:
                return self._result(
                    target,
                    CheckStatus.CONFIRMED,
                    description=f"ioLogik web-console password '{password}' accepted at {path}",
                )

        return self._result(
            target,
            CheckStatus.NOT_APPLICABLE,
            description=f"none of {len(credentials)} tested ioLogik web-console password(s) were accepted at {path}",
        )

    def _get_token(self, host, port, path, use_https, timeout) -> Optional[str]:
        conn = None
        try:
            if use_https:
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=_UNVERIFIED_TLS_CONTEXT)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request("GET", path)
            resp = conn.getresponse()
            body_text = resp.read().decode("iso-8859-1", errors="replace")
            match = _TOKEN_RE.search(body_text)
            return match.group(1) if match else None
        except (OSError, http.client.HTTPException):
            return None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass

    def _try_one(self, host, port, path, password, hash_func, use_https, timeout) -> Optional[bool]:
        token = self._get_token(host, port, path, use_https, timeout)
        if token is None:
            return None

        digest = hash_func((password + token).encode("utf-8")).hexdigest()
        body = urlencode({"Token": token, "PdHdn": "", "Password": digest, "Submit": "Submit"})

        conn = None
        try:
            if use_https:
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=_UNVERIFIED_TLS_CONTEXT)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request(
                "POST",
                path,
                body=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp = conn.getresponse()
            resp_body = resp.read()

            if _INVALID_PASSWORD_TEXT in resp_body:
                return False
            set_cookie = resp.getheader("Set-Cookie", "") or ""
            if "MoxaPass" in set_cookie:
                return True
            # No explicit failure text and no session cookie -- an unexpected response shape
            # (e.g. a firmware variant with a different success/failure signal). Inconclusive,
            # not a false positive.
            return None
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


CHECK_CLASS = IologikChallengeResponseDefaultCredsCheck
