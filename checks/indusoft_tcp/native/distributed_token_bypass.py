"""Native check — AVEVA InduSoft Web Studio / InTouch Edge HMI "TCP/IP Server Task" agent
(port 1234), the "DistributedToken|<hash>" blank-Main-Password authentication bypass
(CVE-2018-17914/CVE-2018-17916, Tenable TRA-2018-34). Uses core/indusoft_tcp.py's wire protocol
(byte-exact decoded from Tenable's own raw advisory PoC hex — see that module's docstring for
full provenance and the WebFetch-summary-truncation catch that made a direct curl re-fetch
necessary).

**CAPPED AT FINGERPRINT_ONLY, NEVER CONFIRMED** — unlike this project's other credential checks,
neither Tenable source documents or verifies a command-69 success/failure response signature (both
of Tenable's own PoCs fire the login frame and blindly chain into a separate buffer-overflow
attack without checking it first). This check therefore CANNOT determine from the wire alone
whether the bypass actually succeeded. Per this project's established honesty rule (a write/attempt
whose correctness can't be self-verified never self-reports CONFIRMED, e.g. the GE Multilin
750/760 write-fallback path), this check sends the real, byte-verified bypass frame and ALSO a
differential control frame (same shape, meaningless identity value) so a human reviewer has both
raw responses to compare — but the check itself only ever reports FINGERPRINT_ONLY or ERROR.

Explicitly does NOT implement the separate Guest-account variant ('username=Guest,
credentials=<hash>') — Tenable's advisory only describes that in prose, never in verified hex,
and its field layout (two separate named values vs. this variant's single combined field) is not
independently confirmed. Building it would mean guessing a field layout for a security-sensitive
authentication attempt, which this project does not do (see checks/candidates/
indusoft-aveva-tcpip-server-task-guest-login.yaml for the full research trail and the open
Guest-variant thread).

Gated by fingerprint_precondition: protocol_probe: indusoft_tcp_identity (core/fingerprint.py),
which uses a completely separate, read-only, well-documented command (Pi(), command 55) to
confirm genuine IWS presence — deliberately never touches the login/credential path as a side
effect of fingerprinting, same split as pcom_tcp_identity/PCOM-TCP.

DESTRUCTIVE (an authentication-bypass attempt), risk_reason=["login"] — a plain credential/
identity attempt, no confirmed lockout mechanism documented anywhere in either source, and no
persistent device write (this is a session-level TCP auth attempt, not a register/config write).
"""

from __future__ import annotations

from core.check import Check, CheckResult, CheckStatus
from core.indusoft_tcp import attempt_control_probe, attempt_distributed_token_bypass
from core.target import Target

_DEFAULT_PORT = 1234


class IndusoftDistributedTokenBypassCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        port = target.port or _DEFAULT_PORT
        params = self.metadata.params or {}
        timeout = params.get("timeout", 5.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)
        real_response = attempt_distributed_token_bypass(target.host, port, timeout=timeout)

        if real_response is None:
            return self._result(
                target, CheckStatus.ERROR,
                description=(
                    "no response to the DistributedToken bypass frame within timeout, or a "
                    "connection error — target may not speak this protocol on this port, or is "
                    "unreachable (the fingerprint_precondition gate should normally prevent this "
                    "check from firing at all in that case)"
                ),
            )

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)
        control_response = attempt_control_probe(target.host, port, timeout=timeout)

        evidence = b"REAL:" + real_response + b"|CONTROL:" + (control_response or b"<no response>")
        if control_response is None:
            differential_note = (
                "the differential control probe (same frame shape, a meaningless identity value) "
                "got no response at all, where the real bypass attempt did — a real, if weak, "
                "differential signal worth a human's attention"
            )
        elif control_response == real_response:
            differential_note = (
                "the differential control probe's response was BYTE-IDENTICAL to the real "
                "bypass attempt's — either the server doesn't validate this field at all "
                "(also consistent with the underlying vulnerability, just not proof this "
                "SPECIFIC value was what mattered), or this protocol's response doesn't "
                "reflect login outcome the way this check hoped it might"
            )
        else:
            differential_note = (
                "the differential control probe's response DIFFERED from the real bypass "
                "attempt's — see attached evidence for both; this is suggestive but not proof, "
                "since no source documents what a success/failure response actually looks like"
            )

        return self._result(
            target,
            CheckStatus.FINGERPRINT_ONLY,
            description=(
                "Sent the byte-verified 'DistributedToken|<hash>' blank-Main-Password bypass "
                "frame (CVE-2018-17914/CVE-2018-17916) and got a response, confirming the "
                "target accepted and processed a well-formed command-69 login frame. Neither "
                "Tenable source documents a success/failure response signature for this "
                "command, so this CANNOT be reported as confirmed — human follow-up is needed "
                "to determine the actual outcome. " + differential_note
            ),
            evidence=evidence,
        )

    def _result(
        self, target: Target, status: CheckStatus, description: str = "", evidence=None
    ) -> CheckResult:
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


CHECK_CLASS = IndusoftDistributedTokenBypassCheck
