"""Native check — Unitronics Vision/Samba PLC & HMI default password (CVE-2023-6448). Uses
core/pcom_tcp.py's wire protocol (ported byte-for-byte from Claroty Team82's PCOM-Tools, see
that module's docstring for full provenance).

**HIGH REAL-WORLD STAKES**: this is the actual vulnerability behind the November 2023 attacks
on U.S. water utility infrastructure (Municipal Water Authority of Aliquippa, PA and others) —
KEV-listed, actively exploited. Surfaced via CISA KEV catalog research during the
default-credentials sweep (2026-08-14), not the originally-planned vendor list.

DESTRUCTIVE: sends a real authentication attempt with the actual default password ("1111") —
same reasoning as every other credential-testing check in this project. Gated behind
protocol_probe: pcom_tcp_identity (core/fingerprint.py), which itself uses a dummy WRONG
credential specifically so the fingerprint step doesn't test the real default as a side effect
of gating.
"""

from __future__ import annotations

from core.check import Check, CheckResult, CheckStatus
from core.pcom_tcp import check_password
from core.target import Target

_DEFAULT_PASSWORD = "1111"


class UnitronicsDefaultPasswordCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        port = target.port or 20256

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)
        result = check_password(target.host, port, _DEFAULT_PASSWORD, timeout=5.0)

        if result is None:
            return self._result(
                target, CheckStatus.ERROR,
                description="target did not return a well-formed PCOM/TCP response — unreachable or not this protocol",
            )
        if result:
            return self._result(
                target, CheckStatus.CONFIRMED,
                description='default password "1111" accepted via PCOM/TCP Check Password (opcode 0x02) — CVE-2023-6448',
            )
        return self._result(
            target, CheckStatus.NOT_APPLICABLE,
            description='default password "1111" rejected — device speaks PCOM/TCP but is not using the factory-default password',
        )

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


CHECK_CLASS = UnitronicsDefaultPasswordCheck
