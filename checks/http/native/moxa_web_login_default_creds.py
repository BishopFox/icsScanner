"""Native check — Moxa web-login default-credential test for the shared challenge-obfuscated login
used across Moxa's embedded web UIs (MGate, MiiNePort, NPort 6000, CSM, and siblings).

Moxa's login is a MULTI-STEP, challenge-obfuscated POST, not a plain form POST. Reverse-engineering
multiple firmware images (see lab-notes/moxa-web-login-wire-format.md) showed there are TWO closely
related variants of the SAME obfuscation, differing only in the challenge hash and which fields are
transformed:

  VARIANT A — "SetSHA256" (newer; MGate MB3180 v2.7 `account_password_form` login):
     md = sha256_hex(FakeChallenge); BOTH account and password are obfuscated and POSTed as
     `account` / `password`. Failure re-serves the login form (account_password_form / ${NOTIFY_MSG}).
  VARIANT B — "SetPass / MD5" (older "NP6000" lib; NPort 6000 v1.21, MiiNePort E3 v1.2, CSM-400 v1.2):
     md = md5_hex(FakeChallenge); ONLY the password is obfuscated, into a hidden `MD5Password` field,
     while the account/username is sent in PLAINTEXT (field name varies by product: `Username` on
     MiiNePort, `account`/`Account` on NPort 6000 / CSM-400). The cleared `Password` field is dropped.
  VARIANT C — "SetPass + MD5 wrap" (NPort 5000 / IA5000 / NPort Express, firmware v1.8):
     PASSWORD-ONLY (no username field at all). md = md5_hex(FakeChallenge); the xor'd hex `p` is then
     wrapped in a final MD5 -> `EncPasswd = MD5(p)`, and the form is submitted via GET (the login
     `<form action=home.htm>` has no method= attribute). Set wrap_md5:true, send_account:false,
     password_field:"EncPasswd", method:"GET".

Shared obfuscation core (both variants), firmware-verified:
  1. GET the login page -> the server substitutes a per-load `FakeChallenge` hidden value and
     (variant A) a `${CSRF_TOKEN}` hidden input.
  2. The device's own JS (`SetSHA256` / `SetPass`, from its `loginframe.html` / `md5.js` helper)
     transforms each value client-side before submit:
        md       = HASH_hex(FakeChallenge)          # HASH = sha256 (A) or md5 (B), lowercase hex
        p        = raw_value.encode().hex()         # Moxa's `ascii` table maps printable char c to
                                                    #   index ord(c), so per-char index-hex == raw.hex()
        out[i]   = hex_nibble( nibble(p[i]) XOR nibble(md[i % len(md)]) )  for each hex nibble of p
     (md is cycled only if p is longer than md -- never happens for real credentials).
  3. POST the (variant-specific) fields + FakeChallenge + any CSRF hidden input to the form action.

Algorithm RE'd DIRECTLY from firmware: variant A from moxa-mgate-mb3180-firmware-v2.7.rom (Login.html
+ loginframe.html: `function SetSHA256`, Paul-Johnston `function SHA256(s){var chrsz=8;hexcase=0;}`);
variant B from moxa-nport-6000 v1.21 / moxa-miineport-e3 v1.2 / moxa-csm-400 v1.2 (`function SetPass`,
`md = MD5(theform.FakeChallenge.value)`, `theform.MD5Password.value = md5_pass`). See
tools/ghidra-re/weblogin_scan.py and lab-notes/moxa-web-login-wire-format.md for the recovery.

CSRF handling: the executor re-submits EVERY hidden <input> found on the login page (that carries
whatever the server named its CSRF token), so it does not need the token's field name hardcoded.

DESTRUCTIVE: real authentication-attempt traffic; same lockout-risk reasoning as every other
credential-testing executor here.

REQUIRED EXPLICIT SUCCESS CRITERIA: like form_post_default_creds.py, the check YAML MUST set at
least one of `success_status` / `success_indicators` / `success_is_absence_of_failure`; a
`failure_indicators` (the login page's re-served form marker) is strongly recommended and checked first.

params schema:
  login_path:        GET path of the login page (default "/")
  action_path:       POST path for the form action (default "/")
  credentials:       list of [account, password] pairs, tried in order (e.g. [["admin","moxa"]])
  challenge_field:   hidden field holding the challenge (default "FakeChallenge")
  password_hash:     "sha256" (variant A, default) | "md5" (variant B) — the challenge-hash algorithm
  account_field:     POST field name for the account/username (default "account"; "Username" MiiNePort)
  password_field:    POST field name for the (obfuscated) password (default "password";
                     "MD5Password" for variant B)
  transform_account: bool (default true). Variant A obfuscates the account; variant B sends it
                     PLAINTEXT, so set false for MD5/SetPass products.
  extra_fields:      optional dict of literal extra POST fields (e.g. a submit button name/value a
                     given server dispatches on)
  wrap_md5:          bool (default false). Variant C: wrap the obfuscated hex in a final MD5 before
                     submitting (EncPasswd = MD5(xor_hex)).
  send_account:      bool (default true). Set false for password-only logins (variant C) so no
                     account/username field is sent at all.
  method:            "POST" (default) or "GET" (variant C submits the login via GET query string).
  success_status:    HTTP status meaning authenticated (e.g. 302)
  success_indicators / failure_indicators: case-insensitive body substrings
  success_is_absence_of_failure: bool (default false). When true (requires failure_indicators),
                     treat "login challenge was present on GET, and NO failure_indicator matched the
                     POST response" as success. Sound ONLY for a known BINARY POST outcome with a
                     reliable failure signal — e.g. Moxa, which ALWAYS re-serves the login form on
                     failure (so the login-page-only markers FakeChallenge / account_password_form /
                     MD5Password / NOTIFY_MSG work as failure_indicators). The executor only reaches
                     the POST after confirming a Moxa login page via the challenge, so the outcomes
                     are login-form(fail) vs main-page(success). CAVEAT: an unexpected intermediate
                     page lacking the failure marker would read as success; prefer a positive
                     success_indicator confirmed from a live unit where available.
  https:             bool (default false); default_port / timeout optional
"""
from __future__ import annotations

import hashlib
import http.client
import re
import ssl
import urllib.parse

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_UNVERIFIED_TLS_CONTEXT = ssl._create_unverified_context()
_HEX = "0123456789abcdef"
_HASHES = {"sha256": hashlib.sha256, "md5": hashlib.md5}
_HIDDEN_INPUT_RE = re.compile(
    r"""<input\b[^>]*\btype\s*=\s*['"]?hidden['"]?[^>]*>""", re.IGNORECASE)
# Real Moxa firmware emits UNQUOTED HTML attributes (name=FakeChallenge value="x"), so these must
# accept quoted ("x"), single-quoted ('x'), AND bare (x) attribute values — matching on the
# quoted-only form silently returned {} against real devices (found via the IA5000 variant-C work).
_NAME_RE = re.compile(r"""\bname\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""", re.IGNORECASE)
_VALUE_RE = re.compile(r"""\bvalue\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""", re.IGNORECASE)


def _attr(match):
    """Return the populated capture group from _NAME_RE/_VALUE_RE (quoted/single/bare), or None."""
    if not match:
        return None
    return next((g for g in match.groups() if g is not None), None)


def moxa_obfuscate(raw: str, challenge: str, algo: str = "sha256") -> str:
    """Reproduce Moxa's client-side SetSHA256()/SetPass() obfuscation (firmware-sourced; see module
    docstring). `algo` selects the challenge hash: "sha256" (variant A) or "md5" (variant B)."""
    hfn = _HASHES.get(algo, hashlib.sha256)
    md = hfn(challenge.encode("latin-1", "replace")).hexdigest()  # lowercase hex (chrsz=8, hexcase=0)
    p = raw.encode("latin-1", "replace").hex()  # ascii.lastIndexOf(c)==ord(c) for printable c
    out = []
    for i, ch in enumerate(p):
        m = _HEX.find(ch)
        n = _HEX.find(md[i % len(md)])
        out.append(_HEX[(m ^ n) & 0xF])
    return "".join(out)


def moxa_set_sha256(raw: str, challenge: str) -> str:
    """Back-compat alias for variant A (SHA-256). Prefer moxa_obfuscate(raw, challenge, algo)."""
    return moxa_obfuscate(raw, challenge, "sha256")


def moxa_sha256_xor(raw: str, challenge: str) -> str:
    """VARIANT D — MGate 5000 "/goform/webLogin" SetCookie() scheme (firmware-sourced from
    moxa-mgate-5118/w5108 v2.0 bin/webs). The device JS does, in order:
        result = XOR(ChallengeText, password)   # byte-wise XOR of ascii.lastIndexOf() indices;
                                                 # ascii.lastIndexOf(c)==ord(c) for printable c, so
                                                 # result[i] = ord(chall[i]) ^ ord(pw[i]) over the
                                                 # overlap, then the un-XOR'd challenge tail passes
                                                 # through (output length == len(challenge)).
        Passwd = SHA256(result)                  # webtoolkit SHA256, lowercase hex, UTF-8 pre-image
    This is a DIFFERENT composition than variant A (which is SHA256(challenge) then nibble-XOR of the
    password hex) -- XOR-THEN-HASH, not hash-then-XOR. Account (UserName) is sent in PLAINTEXT; the
    obfuscated value is also mirrored into cookies AccountName508/Password508."""
    c = challenge.encode("latin-1", "replace")
    p = raw.encode("latin-1", "replace")
    ov = min(len(c), len(p))
    buf = bytes(c[i] ^ p[i] for i in range(ov)) + c[ov:]
    return hashlib.sha256(buf).hexdigest()


class MoxaWebLoginDefaultCredsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        credentials = params.get("credentials", [])
        login_path = params.get("login_path", "/")
        action_path = params.get("action_path", "/")
        challenge_field = params.get("challenge_field", "FakeChallenge")
        password_hash = params.get("password_hash", "sha256")
        account_field = params.get("account_field", "account")
        password_field = params.get("password_field", "password")
        transform_account = params.get("transform_account", True)
        extra_fields = params.get("extra_fields") or {}
        wrap_md5 = params.get("wrap_md5", False)
        send_account = params.get("send_account", True)
        account_cookie = params.get("account_cookie")    # variant D: mirror account into this cookie
        password_cookie = params.get("password_cookie")  # variant D: mirror obf password into this cookie
        method = (params.get("method", "POST") or "POST").upper()
        success_status = params.get("success_status")
        success_indicators = params.get("success_indicators")
        failure_indicators = params.get("failure_indicators")
        success_is_absence_of_failure = params.get("success_is_absence_of_failure", False)
        use_https = params.get("https", False)
        port = target.port or params.get("default_port", 443 if use_https else 80)
        timeout = params.get("timeout", 5.0)

        if not credentials:
            return self._result(target, CheckStatus.ERROR, description="check has no credentials configured in params")
        if success_status is None and not success_indicators and not success_is_absence_of_failure:
            return self._result(target, CheckStatus.ERROR, description="check has no success criteria — set success_status, success_indicators, or success_is_absence_of_failure (with failure_indicators)")
        if success_is_absence_of_failure and not failure_indicators:
            return self._result(target, CheckStatus.ERROR, description="success_is_absence_of_failure requires failure_indicators to be configured")

        for account, password in credentials:
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            outcome = self._try_one(
                target.host, port, login_path, action_path, account, password,
                challenge_field, success_status, success_indicators, failure_indicators,
                success_is_absence_of_failure, use_https, timeout,
                password_hash, account_field, password_field, transform_account, extra_fields,
                wrap_md5, send_account, method, account_cookie, password_cookie,
            )
            if outcome == "auth_ok":
                return self._result(target, CheckStatus.CONFIRMED,
                                    description=f"default credential '{account}:{password}' accepted via Moxa challenge-obfuscated login ({password_hash}) at {action_path}")
            if outcome == "no_challenge":
                return self._result(target, CheckStatus.NOT_APPLICABLE,
                                    description=f"no '{challenge_field}' challenge found at {login_path} — not a Moxa SetSHA256 login page")
        return self._result(target, CheckStatus.NOT_APPLICABLE,
                            description=f"none of {len(credentials)} tested default credential(s) were accepted")

    def _get_login_page(self, conn, login_path):
        conn.request("GET", login_path, headers={"Accept": "text/html"})
        resp = conn.getresponse()
        body = resp.read().decode("latin-1", errors="replace")
        return resp, body

    def _parse_hidden(self, html: str):
        """Return dict of all hidden <input> name->value (carries FakeChallenge + CSRF token)."""
        fields = {}
        for tag in _HIDDEN_INPUT_RE.findall(html):
            name = _attr(_NAME_RE.search(tag))
            if not name:
                continue
            value = _attr(_VALUE_RE.search(tag))
            fields[name] = value if value is not None else ""
        return fields

    def _try_one(self, host, port, login_path, action_path, account, password,
                 challenge_field, success_status, success_indicators, failure_indicators,
                 success_is_absence_of_failure, use_https, timeout,
                 password_hash="sha256", account_field="account", password_field="password",
                 transform_account=True, extra_fields=None, wrap_md5=False, send_account=True,
                 method="POST", account_cookie=None, password_cookie=None) -> str:
        conn = None
        try:
            if use_https:
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=_UNVERIFIED_TLS_CONTEXT)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)

            # Step 1: GET login page, carry any session cookie, read challenge + hidden fields.
            resp, html = self._get_login_page(conn, login_path)
            set_cookie = resp.getheader("Set-Cookie")
            hidden = self._parse_hidden(html)
            challenge = hidden.get(challenge_field)
            if challenge is None:
                # tolerate a differently-cased challenge field name
                for k, v in hidden.items():
                    if k.lower() == challenge_field.lower():
                        challenge = v
                        break
            if challenge is None:
                return "no_challenge"

            # Step 2: obfuscate credentials exactly as the device's own JS does. Variant A
            # (SetSHA256) obfuscates both account+password; variant B (SetPass/MD5) obfuscates only
            # the password into MD5Password and sends the account/username in plaintext; variant C
            # (NPort 5000/IA5000) is password-only and wraps the obfuscated hex in a final MD5
            # (EncPasswd = MD5(xor_hex)) and submits via GET.
            fields = dict(hidden)  # re-submit FakeChallenge + CSRF token + any other hidden inputs
            if password_hash == "md5_concat":
                # VARIANT C (Moxa ICS-G7526/G7528 eCos login, firmware-confirmed 2026-10-13): NOT the
                # stream-obfuscation of A/B -- the device JS computes `theValue = MD5(op+chall)` where
                # op=password and `chall` is a client-chosen "fake" challenge echoed in a hidden field
                # (name="chall"), POSTed as `logpwd`. So the submitted secret is a plain
                # md5_hex(password + challenge), with the account sent in plaintext. The challenge the
                # server verifies against is whatever we echo back (the hidden field value), so reusing
                # the GET page's `chall` value and resubmitting it (via `fields = dict(hidden)`) is
                # exactly what the browser does.
                pw = hashlib.md5((password + (challenge or "")).encode("latin-1", "replace")).hexdigest()
            elif password_hash == "sha256_xor":
                # VARIANT D (MGate 5000 /goform/webLogin): Passwd = SHA256(XOR(challenge, password)).
                pw = moxa_sha256_xor(password, challenge)
            else:
                pw = moxa_obfuscate(password, challenge, password_hash)
            if wrap_md5:
                pw = hashlib.md5(pw.encode("latin-1", "replace")).hexdigest()
            if send_account:
                fields[account_field] = moxa_obfuscate(account, challenge, password_hash) if transform_account else account
            fields[password_field] = pw
            if extra_fields:
                fields.update(extra_fields)
            body = urllib.parse.urlencode(fields)

            headers = {}
            cookie_parts = []
            if set_cookie:
                cookie_parts.append(set_cookie.split(";", 1)[0])
            # variant D mirrors the account + obfuscated password into cookies (device JS SetCookie()).
            if account_cookie:
                cookie_parts.append(f"{account_cookie}={urllib.parse.quote(account)}")
            if password_cookie:
                cookie_parts.append(f"{password_cookie}={pw}")
            if cookie_parts:
                headers["Cookie"] = "; ".join(cookie_parts)

            # Step 3: submit the login (POST body, or GET query string for method=GET devices).
            if method == "GET":
                sep = "&" if "?" in action_path else "?"
                conn.request("GET", action_path + sep + body, headers=headers)
            else:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                conn.request("POST", action_path, body=body, headers=headers)
            presp = conn.getresponse()
            ptext = presp.read().decode("latin-1", errors="replace").lower()

            if failure_indicators and any(f.lower() in ptext for f in failure_indicators):
                return "auth_failed"
            if success_status is not None and presp.status == success_status:
                return "auth_ok"
            if success_indicators and any(s.lower() in ptext for s in success_indicators):
                return "auth_ok"
            # Only reached if no failure_indicator matched. With success_is_absence_of_failure the
            # challenge was confirmed on GET (we're past that), so a POST response lacking the
            # login-form failure marker means the credential was accepted.
            if success_is_absence_of_failure:
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


CHECK_CLASS = MoxaWebLoginDefaultCredsCheck
