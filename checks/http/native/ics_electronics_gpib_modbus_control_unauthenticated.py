"""Native check — ICS Electronics 9065 (Ethernet-to-GPIB Gateway) and 9099 (Ethernet-to-Modbus
RTU Interface): is the device's control.html page — the same page whose "cmd" field relays
arbitrary commands to whatever instrument/field device is attached downstream — reachable over
HTTP with no authentication challenge at all?

Sourced directly from ICS Electronics' own official firmware update packages (icselect.com/
pc_files/ICS_9065R8_AUpdate.zip, ICS_9099R14_AUpdate.zip), which ship the device's actual
embedded web-server HTML source unpacked — read directly, not inferred. See
checks/candidates/ics-electronics-9065-9099-unauthenticated-gpib-modbus-command-relay.yaml for
the full research trail: control.html's own <form> elements show zero password/token/session
field anywhere, confirmed by grepping every .html file across all 5 of the vendor's official 90xx
firmware packages (not just these two) for "password"/"passwd"/"login" — zero matches anywhere in
the whole product line's shipped source.

NON-DESTRUCTIVE BY DESIGN, same "confirm the underlying condition, not the full exploit" choice
already made for the Siemens IoT2050 Node-RED check (checks/http/native/
nodered_unauthenticated_flows.py) — this check NEVER sends the "cmd" field or presses the page's
"Send" button (submitsend), which is the actual command-injection primitive the candidate file
describes and the reason that finding was deliberately left unbuilt pending exactly this kind of
explicit go-ahead. Instead it presses only the page's separate, argument-less "Read" button
(submitread) — confirmed from the shipped HTML to be its own distinct <form> containing nothing
but a hidden `chain=control.html` field and the submit button itself, no "cmd" parameter at all:

    <form method="get" action="/cgi">
      <input type="hidden" name="chain" value="control.html" />
      <input type="submit" name="submitread" value="Read" />
    </form>

This reads back whatever is already in the device's own response buffer — it cannot inject, alter,
or trigger a NEW command to the attached GPIB instrument or Modbus RTU field device. A CONFIRMED
result proves the necessary PRECONDITION for the command-relay finding (the control page answers
with no auth challenge) without ever exercising the write/relay capability itself.

Response-shape validation, not a bare HTTP-200 check: fingerprint_precondition only gates on
`vendor: "ICS Electronics"` (not a specific product), since the 90xx family shares a common web
stack and only the 9065/9099 models ship control.html at all — the other three models (9006,
9009, 9055) simply won't match the strict body-shape check below, so this check naturally
excludes them without needing a separate protocol-level product probe. The response must contain
BOTH the literal "Device Response" heading and the `name="resp"` response textarea — confirmed
present, byte-for-byte identical, in both the 9065 and 9099 packages' own control.html source —
before this is trusted as a real match, guarding against a false CONFIRMED on an unrelated device
that happens to return 200 for a GET to /cgi.

Default port: 80 (plain HTTP — every 90xx config/control page examined serves over HTTP, no TLS).
"""

from __future__ import annotations

import http.client
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_DEFAULT_PORT = 80
_READ_PATH = "/cgi?chain=control.html&submitread=Read"
_TIMEOUT_S = 5.0
_REQUIRED_MARKERS = (b"Device Response", b'name="resp"')


class IcsElectronicsGpibModbusControlUnauthenticatedCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        port = target.port or _DEFAULT_PORT

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        conn: Optional[http.client.HTTPConnection] = None
        try:
            conn = http.client.HTTPConnection(target.host, port, timeout=_TIMEOUT_S)
            conn.request("GET", _READ_PATH)
            resp = conn.getresponse()
            body = resp.read()
        except (OSError, http.client.HTTPException) as e:
            return self._result(
                target, CheckStatus.NOT_APPLICABLE,
                description=f"could not reach {target.host}:{port}{_READ_PATH} ({type(e).__name__}: {e})",
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
                description=f"GET {_READ_PATH} returned HTTP {resp.status} — authentication appears enforced",
            )
        if resp.status != 200:
            return self._result(
                target, CheckStatus.NOT_APPLICABLE,
                description=f"GET {_READ_PATH} returned HTTP {resp.status}, not the expected 200",
            )

        if not all(marker in body for marker in _REQUIRED_MARKERS):
            return self._result(
                target, CheckStatus.NOT_APPLICABLE,
                description="GET returned HTTP 200 but the body does not match the ICS Electronics "
                            "control.html response shape (missing 'Device Response' heading and/or the "
                            "'resp' textarea) — likely not a 9065/9099 control page",
            )

        return self._result(
            target, CheckStatus.CONFIRMED,
            description=(
                f"GET {_READ_PATH} returned the device's control.html page (Device Response / "
                "resp textarea present) with no authentication challenge. This confirms the "
                "control page — whose 'cmd' field, NOT exercised by this check, relays arbitrary "
                "commands to the attached GPIB instrument or Modbus RTU field device — is "
                "reachable unauthenticated. No command was sent to any downstream device."
            ),
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


CHECK_CLASS = IcsElectronicsGpibModbusControlUnauthenticatedCheck
