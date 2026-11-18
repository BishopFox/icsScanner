"""Generic native check — unauthenticated HTTP endpoint access confirmed by RESPONSE-BODY content
(missing-authentication / information-disclosure detection). The text-body sibling of
unauthenticated_http_json_get: a single read-only, unauthenticated GET to a path that SHOULD require
auth, CONFIRMED when it returns the configured success status AND the body matches the configured
evidence. Use this for devices whose unauthenticated endpoint returns a non-JSON body — an HTML page,
a CGI script's JavaScript blob, a plain-text config dump — where the proof is a distinctive string or
pattern, not a JSON key.

This covers two closely-related CWE classes depending on what the body contains:
  - CWE-306 (missing authentication): the endpoint answers at all without a credential.
  - CWE-200 (information disclosure): the body itself leaks sensitive data (e.g. a credential),
    which is strictly stronger — the disclosure IS the finding, no follow-up login needed.
The YAML's description/comment carries which one a given check is claiming; this executor just proves
"unauthenticated GET returned the expected evidence".

SAFE BY CONSTRUCTION: GET only, one request, never a state-changing endpoint. Point `path` at a
read-only endpoint; this executor will not POST/PUT/DELETE.

REQUIRED EXPLICIT SUCCESS CRITERIA (same discipline as unauthenticated_http_json_get): the check must
configure EITHER `body_regex` (a regex that must match the body, searched with DOTALL) OR a non-empty
`body_markers` list (substrings that must ALL be present). A bare 200 is never enough — a captive
portal or proxy can 200 anything. If neither is configured the check returns ERROR rather than
guessing.

params schema:
  path:            URL path (incl. query string) to GET, e.g. "/cgi-bin/readfile.cgi?query=ADMINID"
  body_regex:      regex the response body must match (re.search, DOTALL). Takes precedence over
                   body_markers when both are set.
  body_markers:    list of substrings; CONFIRMED only if the body contains ALL of them. Required if
                   body_regex is absent.
  success_status:  HTTP status that counts as "answered" (default: 200)
  https:           bool, use HTTPS (default: false)
  default_port:    fallback port if the target has none
  timeout:         seconds (default 5.0)
  max_body:        cap bytes read from the response (default 65536) — a disclosure blob is small.
"""

from __future__ import annotations

import http.client
import re
import ssl

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_UNVERIFIED_TLS_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_UNVERIFIED_TLS_CONTEXT.check_hostname = False
_UNVERIFIED_TLS_CONTEXT.verify_mode = ssl.CERT_NONE


class UnauthenticatedHttpBodyGetCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        path = params.get("path")
        body_regex = params.get("body_regex")
        body_markers = params.get("body_markers") or []
        success_status = params.get("success_status", 200)
        use_https = params.get("https", False)
        port = target.port or params.get("default_port", 443 if use_https else 80)
        timeout = params.get("timeout", 5.0)
        max_body = params.get("max_body", 65536)

        if not path:
            return self._result(target, CheckStatus.ERROR, description="check has no 'path' configured in params")
        if not body_regex and not body_markers:
            return self._result(target, CheckStatus.ERROR,
                                description="check must configure 'body_regex' or non-empty 'body_markers' (a bare 200 is not proof)")

        compiled = None
        if body_regex:
            try:
                compiled = re.compile(body_regex, re.DOTALL)
            except re.error as e:
                return self._result(target, CheckStatus.ERROR, description=f"invalid body_regex: {e}")

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
            raw = resp.read(max_body)
        except (OSError, http.client.HTTPException) as e:
            return self._result(target, CheckStatus.NOT_APPLICABLE,
                                description=f"could not reach {target.host}:{port}{path} ({type(e).__name__}: {e})")
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass

        if resp.status != success_status:
            return self._result(target, CheckStatus.NOT_APPLICABLE,
                                description=f"GET {path} returned HTTP {resp.status}, not the expected {success_status}")

        body = raw.decode("utf-8", errors="replace")
        if compiled is not None:
            if compiled.search(body):
                return self._result(target, CheckStatus.CONFIRMED,
                                    description=(f"unauthenticated GET {path} returned HTTP {resp.status} with a body "
                                                f"matching the expected evidence pattern -- endpoint reachable with no "
                                                f"credential"))
            return self._result(target, CheckStatus.NOT_APPLICABLE,
                                description=f"GET {path} returned HTTP {resp.status} but body did not match body_regex")

        missing = [m for m in body_markers if m not in body]
        if not missing:
            return self._result(target, CheckStatus.CONFIRMED,
                                description=(f"unauthenticated GET {path} returned HTTP {resp.status} with all expected "
                                            f"body markers {body_markers} -- endpoint reachable with no credential"))
        return self._result(target, CheckStatus.NOT_APPLICABLE,
                            description=f"GET {path} returned HTTP {resp.status} but body missing markers {missing}")

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


CHECK_CLASS = UnauthenticatedHttpBodyGetCheck
