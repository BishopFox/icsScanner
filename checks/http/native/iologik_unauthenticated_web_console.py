"""Native check — Moxa ioLogik E1200H/E1200W web console reachable with NO authentication at all
on a factory-default unit (CWE-306, missing authentication), NOT a default-credential guess.

Distinct in kind from checks/http/native/iologik_challenge_response_default_creds.py (the core
E1200 line's finding): that check tests a specific hardcoded PASSWORD ("moxa"). This check tests
whether a password is required AT ALL. Sourced directly from Moxa's own official manuals
(ioLogik E1200H Series User Manual v2.2, ioLogik E1200W Series User Manual v2.2, user-supplied),
both stating identically, in their own "Factory Default Settings" reference table:

    Password    N/A

and in their "Change Password" section: "For all changes to the...password protection
settings, you will first need to enter the old password. Leave this blank if you are setting up
password protection for the first time." -- i.e. password protection on these two models is
OPT-IN, off by default, not a hardcoded default value to guess.

WIRE BEHAVIOR, confirmed directly from real firmware (moxa-iologik-e1200h-series-e1261h-t-
firmware-v1.1.1kp, moxa-iologik-e1200w-series-e1261w-t-firmware-v1.1.1kp): the same URL
(`home.htm`) that serves the "Input Password" challenge form on a password-protected unit (see
the sibling module's own docstring for that flow) ALSO serves the device's real "I/O Server
general information" page directly -- found verbatim in both firmware images:

    <TITLE>I/O Server general information</TITLE> ... <H2>Welcome to ioLogik <MODEL_NAME> Series</H2>
    ... Model Name ... Serial Number ... Firmware Version ...

-- when no password is configured, i.e. on a factory-default unit. This check's fingerprint gate
is exactly this response-shape distinction (same "strict shape gate, not a bare 200" design as
checks/http/native/nodered_unauthenticated_flows.py): CONFIRMED requires the "Welcome to
ioLogik"/"I/O Server general information" markers to be present AND the "Input Password"/hidden
Token-field markers to be ABSENT -- a device that shows the login prompt is NOT vulnerable to
this specific finding (it has password protection enabled, working as intended), so that shape is
explicitly NOT_APPLICABLE rather than an error.

DOES NOT apply to the core E1200 line (E1210/E1260/etc.) -- those ship WITH a default password
("moxa") on firmware 3.3+, a different (and already-covered) finding; see
checks/candidates/moxa-iologik-e1200-e1500-railway-remote-io.yaml for why the two lines were kept
as separate findings after this project's own hardware-variant firmware review found they did not
share the same default.

NON-DESTRUCTIVE: a single read-only GET, no credential guessing, no state change.

params schema:
  path:          URL path to GET (default "/home.htm" -- the literal URL this firmware's own
                 login form and info page share).
  https:         bool, use HTTPS instead of HTTP (default: false).
  default_port:  fallback port if the target doesn't specify one (default 80, or 443 if https).
  timeout:       per-request timeout in seconds (default 5.0).
"""

from __future__ import annotations

import http.client
import ssl
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_UNVERIFIED_TLS_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_UNVERIFIED_TLS_CONTEXT.check_hostname = False
_UNVERIFIED_TLS_CONTEXT.verify_mode = ssl.CERT_NONE

_INFO_PAGE_MARKERS = (b"I/O Server general information", b"Welcome to ioLogik")
_LOGIN_MARKERS = (b"Input Password", b'name="Token"', b"name=Token")


class IologikUnauthenticatedWebConsoleCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        path = params.get("path", "/home.htm")
        use_https = params.get("https", False)
        port = target.port or params.get("default_port", 443 if use_https else 80)
        timeout = params.get("timeout", 5.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        conn = None
        try:
            if use_https:
                conn = http.client.HTTPSConnection(target.host, port, timeout=timeout, context=_UNVERIFIED_TLS_CONTEXT)
            else:
                conn = http.client.HTTPConnection(target.host, port, timeout=timeout)
            conn.request("GET", path)
            resp = conn.getresponse()
            body = resp.read()
        except (OSError, http.client.HTTPException) as e:
            return self._result(
                target, CheckStatus.NOT_APPLICABLE,
                description=f"could not reach {target.host}:{port}{path} ({type(e).__name__}: {e})",
            )
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass

        if resp.status != 200:
            return self._result(
                target, CheckStatus.NOT_APPLICABLE,
                description=f"GET {path} returned HTTP {resp.status}, not the expected 200",
            )

        has_login = any(marker in body for marker in _LOGIN_MARKERS)
        has_info = any(marker in body for marker in _INFO_PAGE_MARKERS)

        if has_login:
            return self._result(
                target, CheckStatus.NOT_APPLICABLE,
                description=f"GET {path} served the Input Password login prompt -- password protection is enabled on this unit",
            )
        if not has_info:
            return self._result(
                target, CheckStatus.NOT_APPLICABLE,
                description=f"GET {path} returned HTTP 200 but the body matches neither the ioLogik info page "
                            f"nor the login prompt shape -- likely not this device",
            )

        return self._result(
            target, CheckStatus.CONFIRMED,
            description=f"GET {path} served the device's I/O Server info page directly, with no login "
                        f"challenge -- web console is reachable with no authentication at all",
            evidence=body[:2048],
        )

    def _result(self, target: Target, status: CheckStatus, description: str = "", evidence: Optional[bytes] = None) -> CheckResult:
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
            evidence=evidence,
        )


CHECK_CLASS = IologikUnauthenticatedWebConsoleCheck
