"""Native check — Siemens SIMATIC IoT2050 Advanced (CVE-2026-58115): unauthenticated access to
Node-RED's admin HTTP API. Sourced from Siemens's own ProductCERT advisory (SSA-834709, fetched
and read directly): affected devices "do not enforce authentication on the Node-RED HTTP
interface, allowing unauthenticated access to programming nodes... to execute arbitrary code on
the underlying server with maximum privileges" (CWE-306, CVSS 10.0 CRITICAL both v3.1 and v4.0).

NON-DESTRUCTIVE BY DESIGN: this check never creates, modifies, or deploys a flow, and never
exercises the actual code-execution capability the finding describes. It confirms the
UNDERLYING CONDITION (the admin API answers with no auth challenge) via a single read-only
GET /flows — a real, documented Node-RED admin endpoint (nodered.org/docs/api/admin/methods/
get/flows/), confirmed directly from Node-RED's own official docs, not guessed. Node-RED's own
docs describe this endpoint's Authorization/Bearer-token requirement as CONDITIONAL ("if
authentication is enabled") — an instance with auth left off (the CVE's own described state)
answers with no challenge at all.

Response-shape validation doubles as the fingerprint gate: this check is scoped to
`fingerprint_precondition: {vendor: Siemens, product: SIMATIC IoT2050 Advanced}` (an OUI-level
gate, not a Node-RED-specific protocol_probe — see the candidate file's own note flagging this
as a known simplification, not yet resolved with a dedicated protocol-level probe), so a false
CONFIRMED against an unrelated Siemens device that happens to answer on port 1880 is guarded
against by checking the RESPONSE BODY matches Node-RED's own documented /flows shape exactly
(a bare HTTP 200 alone is not trusted) — either a JSON array of node/tab objects (API v1) or a
JSON object carrying a "flows" list (API v2), per Node-RED's own docs.

Default port: 1880, Node-RED's own well-known default (nodered.org/docs/user-guide/runtime/
configuration) — used only when the target inventory doesn't specify one, same convention as
this project's other protocol-default-port checks (e.g. Modbus's 502, S7comm's 102).
"""

from __future__ import annotations

import http.client
import json
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_DEFAULT_PORT = 1880
_FLOWS_PATH = "/flows"
_TIMEOUT_S = 5.0


def _is_node_red_flows_shape(body: bytes) -> Optional[int]:
    """Returns the flow/tab entry count if `body` matches Node-RED's own documented /flows
    response shape (either API version), or None if it doesn't — the actual confirmation gate,
    not just an HTTP-200 check. Deliberately strict: requires at least one entry carrying a
    recognizable Node-RED node "type" key, not just "any JSON list/dict," so an unrelated JSON
    API returning 200 on this same path can't produce a false CONFIRMED."""
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None

    if isinstance(data, dict) and isinstance(data.get("flows"), list):
        entries = data["flows"]
    elif isinstance(data, list):
        entries = data
    else:
        return None

    if not entries or not all(isinstance(e, dict) and "type" in e for e in entries):
        return None
    return len(entries)


class NodeRedUnauthenticatedFlowsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        port = target.port or _DEFAULT_PORT

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        conn: Optional[http.client.HTTPConnection] = None
        try:
            conn = http.client.HTTPConnection(target.host, port, timeout=_TIMEOUT_S)
            conn.request("GET", _FLOWS_PATH)
            resp = conn.getresponse()
            body = resp.read()
        except (OSError, http.client.HTTPException) as e:
            return self._result(
                target, CheckStatus.NOT_APPLICABLE,
                description=f"could not reach {target.host}:{port}{_FLOWS_PATH} ({type(e).__name__}: {e})",
            )
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass

        if resp.status in (401, 403):
            return self._result(
                target, CheckStatus.NOT_APPLICABLE,
                description=f"GET {_FLOWS_PATH} returned HTTP {resp.status} — authentication appears enforced",
            )
        if resp.status != 200:
            return self._result(
                target, CheckStatus.NOT_APPLICABLE,
                description=f"GET {_FLOWS_PATH} returned HTTP {resp.status}, not the expected 200",
            )

        entry_count = _is_node_red_flows_shape(body)
        if entry_count is None:
            return self._result(
                target, CheckStatus.NOT_APPLICABLE,
                description=f"GET {_FLOWS_PATH} returned HTTP 200 but the body does not match Node-RED's "
                            f"documented /flows response shape — likely not a Node-RED instance",
            )

        return self._result(
            target, CheckStatus.CONFIRMED,
            description=f"GET {_FLOWS_PATH} returned {entry_count} flow/tab entry(ies) with no authentication "
                        f"challenge — Node-RED admin API is reachable unauthenticated (CVE-2026-58115)",
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


CHECK_CLASS = NodeRedUnauthenticatedFlowsCheck
