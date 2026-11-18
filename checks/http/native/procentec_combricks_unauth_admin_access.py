"""Native check — Procentec (HMS Networks) ComBricks Head Station: unauthenticated admin web-UI
access. Sourced directly from Procentec's own official "ComBricks User Manual" (bundled on the
device's own SD card image, both firmware releases reviewed): "Passwords are NOT activated when
the product is purchased or reset and all menu items are accessible and adjustable" (Section 4.9,
Table 1). CWE-1188 (Insecure Default Initialization of Resource with Insecure Settings) /
CWE-306 (Missing Authentication for a Critical Function) — there is no credential to guess here
(CWE-798 doesn't apply), authentication is simply not configured out of the box, so none of this
project's login-attempt executors (basic_auth/form_post/json_rest/socketio) apply. Same shape as
checks/http/native/nodered_unauthenticated_flows.py and
checks/cisco_smi/native/cisco_smart_install_exposed.py: confirms the underlying condition via a
single read-only GET, not a credential attempt.

WIRE-LEVEL EVIDENCE, read directly from the device's own firmware (CB-HS-T1.pkg, a genuine
embedded-httpd content image — binwalk-confirmed HTML document regions, carved directly, not
guessed): the firmware bundles a distinct admin settings page (`/cfg_gen.htm`, "General
configuration") whose raw served HTML template contains no conditional server-side auth check
before its title renders, and a SEPARATE, distinctly-titled "Please log in" page
(internally the "403" page — includes `403.css`/`403.js`) that presumably replaces normal page
content when a password IS configured and the client isn't authenticated (per the manual's own
description of the protected-mode behavior). Confirming `/cfg_gen.htm` returns its OWN real
title, not the login page's title, is therefore the safe, minimal proxy for "no authentication is
configured" — reading a settings page's title, never submitting or changing any configuration.

NON-DESTRUCTIVE BY DESIGN: a single GET, no state change, no credential submitted — same posture
as the two sibling checks named above.

Default port 80 (HTTP, not HTTPS) and default management IP 192.168.1.254, both confirmed
directly from the vendor's own manual.
"""

from __future__ import annotations

import http.client
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_DEFAULT_PORT = 80
_ADMIN_PAGE_PATH = "/cfg_gen.htm"
_TIMEOUT_S = 5.0

# Read directly from the carved firmware HTML template — exact byte sequence, not paraphrased.
_ADMIN_PAGE_MARKER = b"General configuration</tt></title>"
_LOGIN_PAGE_MARKER = b"Please log in</tt></title>"


class ProcentecCombricksUnauthAdminAccessCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        port = target.port or _DEFAULT_PORT

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        conn: Optional[http.client.HTTPConnection] = None
        try:
            conn = http.client.HTTPConnection(target.host, port, timeout=_TIMEOUT_S)
            conn.request("GET", _ADMIN_PAGE_PATH)
            resp = conn.getresponse()
            body = resp.read()
        except (OSError, http.client.HTTPException) as e:
            return self._result(
                target, CheckStatus.NOT_APPLICABLE,
                description=f"could not reach {target.host}:{port}{_ADMIN_PAGE_PATH} ({type(e).__name__}: {e})",
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
                description=f"GET {_ADMIN_PAGE_PATH} returned HTTP {resp.status}, not the expected 200",
            )

        if _LOGIN_PAGE_MARKER in body:
            return self._result(
                target, CheckStatus.NOT_APPLICABLE,
                description=f"GET {_ADMIN_PAGE_PATH} returned the login-required page — authentication appears configured",
            )

        if _ADMIN_PAGE_MARKER not in body:
            return self._result(
                target, CheckStatus.NOT_APPLICABLE,
                description=f"GET {_ADMIN_PAGE_PATH} returned HTTP 200 but the body matches neither the known admin-page nor login-page marker — likely not a ComBricks Head Station",
            )

        return self._result(
            target, CheckStatus.CONFIRMED,
            description=f"GET {_ADMIN_PAGE_PATH} returned the real General Configuration admin page with no authentication challenge — ComBricks ships with no password configured by default",
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


CHECK_CLASS = ProcentecCombricksUnauthAdminAccessCheck
