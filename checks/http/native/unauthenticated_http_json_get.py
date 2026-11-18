"""Generic native check — unauthenticated HTTP JSON endpoint access (missing-authentication
detection). Reusable across vendors: a single read-only, unauthenticated GET to a path that SHOULD
require auth; CONFIRMED when it returns the configured success status (default 200) AND the parsed
JSON body contains any of the configured marker keys. This is the project's "unauthenticated-access"
class (cf. iologik_unauthenticated_web_console / nodered_unauthenticated_flows), generalized to the
common modern shape of a device REST API that answers protected GETs with no credential at all
(CWE-306). First consumer: the Ouster LiDAR device HTTP API
(checks/http/ouster-lidar-unauthenticated-http-api.yaml).

SAFE BY CONSTRUCTION: GET only, one request, never a state-changing endpoint. The YAML must point
`path` at a read-only endpoint; this executor will not POST/PUT/DELETE.

REQUIRED EXPLICIT SUCCESS CRITERIA (same discipline as the *_default_creds executors): `json_markers`
must be configured (a non-empty list of top-level JSON keys whose presence proves a real device
response, not a generic 200 from an unrelated server), or the check returns ERROR rather than
guessing. A bare 200 is not enough -- a captive portal or proxy can 200 anything.

params schema:
  path:            URL path to GET (e.g. "/api/v1/sensor/metadata")
  json_markers:    list of top-level JSON key names; CONFIRMED if the parsed JSON (object) contains
                   ANY of them. REQUIRED.
  success_status:  HTTP status that counts as "answered" (default: 200)
  https:           bool, use HTTPS (default: false)
  default_port:    fallback port if the target has none
  timeout:         seconds (default 5.0)
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


class UnauthenticatedHttpJsonGetCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        path = params.get("path")
        json_markers = params.get("json_markers") or []
        success_status = params.get("success_status", 200)
        use_https = params.get("https", False)
        port = target.port or params.get("default_port", 443 if use_https else 80)
        timeout = params.get("timeout", 5.0)

        if not path:
            return self._result(target, CheckStatus.ERROR, description="check has no 'path' configured in params")
        if not json_markers:
            return self._result(target, CheckStatus.ERROR,
                                description="check must configure non-empty 'json_markers' (a bare 200 is not proof)")

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
            raw = resp.read()
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
        try:
            parsed = json.loads(raw.decode("utf-8", errors="replace"))
        except ValueError:
            return self._result(target, CheckStatus.NOT_APPLICABLE,
                                description=f"GET {path} returned HTTP {resp.status} but a non-JSON body")
        # A marker is satisfied if it is a top-level key of a JSON object, OR a key of any object in
        # a top-level JSON array (some device APIs return an array of config/param objects, e.g. the
        # MicroHAWK WebLink /api/v1/file/device/parameters.json param-schema list).
        hit = None
        if isinstance(parsed, dict):
            hit = next((k for k in json_markers if k in parsed), None)
        elif isinstance(parsed, list):
            for item in parsed:
                if isinstance(item, dict):
                    hit = next((k for k in json_markers if k in item), None)
                    if hit:
                        break
        if hit is not None:
            return self._result(target, CheckStatus.CONFIRMED,
                                description=(f"unauthenticated GET {path} returned HTTP {resp.status} with device JSON "
                                            f"(key '{hit}') -- endpoint is reachable with no credential (CWE-306)"))
        return self._result(target, CheckStatus.NOT_APPLICABLE,
                            description=f"GET {path} returned JSON without any expected marker key {json_markers}")

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


CHECK_CLASS = UnauthenticatedHttpJsonGetCheck
