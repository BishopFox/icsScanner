"""Native check — CVE-2021-22681 Rockwell Automation Logix Controllers, AFFECTED-PRODUCT-FAMILY
detection only. NOT an exploit, NOT a confirmed-unpatched determination.

Deliberate scope decision (default-credentials sweep, Phase 2, 2026-08-14): CVE-2021-22681
(CVSS 10, KEV-listed) is a cryptographic key-discovery vulnerability — Studio 5000 Logix
Designer embeds a private key used to verify controller communications, and that key can be
extracted/replicated to forge authenticated traffic. Actually exploiting this would mean
embedding the discovered/leaked key material into this tool — a materially different, more
sensitive class of check content than testing a documented factory-default credential (the rest
of this sweep). Not built without that being an explicit, discussed decision, not a default.

What IS built instead: a safe, read-only, non-destructive check using EtherNet/IP List Identity
(a standard, unauthenticated CIP discovery service every EtherNet/IP device answers — no
proprietary reverse-engineering needed, unlike PCOM/TCP) to flag whether the target's reported
product name matches Rockwell's documented affected-product list for this CVE.

LOW confidence, deliberately: the CISA/GitHub advisory does not specify a fixed/patched version
(mitigation may require enabling CIP Security rather than a firmware update — the affected
products list covers essentially the entire current Logix controller line), and the exact
product-name string format a real device's List Identity response uses has not been
cross-validated against real hardware. This is a "worth investigating" flag, not a demonstrated
finding — the pattern the project's own Milestone 4 charter anticipated for curated public CVEs
with vague advisories.
"""

from __future__ import annotations

from core.check import Check, CheckResult, CheckStatus
from core.fingerprint import probe_enip_identity
from core.target import Target

# Product-name substrings from the affected list in ICSA-21-056-03 / GHSA-pvh9-p4pw-h78q.
# Broad on purpose — the advisory covers essentially the whole current Logix controller line
# (CompactLogix, ControlLogix, GuardLogix, DriveLogix, SoftLogix), so this is closer to "is this
# any Logix-family controller" than fine-grained model discrimination. See module docstring.
_AFFECTED_PRODUCT_SUBSTRINGS = [
    "compactlogix",
    "controllogix",
    "guardlogix",
    "drivelogix",
    "softlogix",
    "1768",
    "1769",
    "1794-l34",
]


class RockwellLogixKeyBypassFamilyCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        port = target.port or 44818

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)
        fp = probe_enip_identity(target.host, port)

        if fp.confidence == "none":
            return self._result(
                target, CheckStatus.ERROR,
                description="target did not respond to EtherNet/IP List Identity — unreachable or not this protocol",
            )

        model_lower = (fp.model or "").lower()
        matched = [s for s in _AFFECTED_PRODUCT_SUBSTRINGS if s in model_lower]

        if matched:
            return self._result(
                target, CheckStatus.CONFIRMED,
                description=(
                    f"reported product name '{fp.model}' matches the Logix controller family "
                    f"affected by CVE-2021-22681 (matched: {matched}) — worth investigating, "
                    f"NOT a confirmed-unpatched or demonstrated-exploitable determination "
                    f"(no fixed-version cutoff is published; mitigation may require CIP "
                    f"Security rather than a firmware update)"
                ),
            )
        return self._result(
            target, CheckStatus.NOT_APPLICABLE,
            description=f"reported product name '{fp.model}' does not match the known affected Logix product families",
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


CHECK_CLASS = RockwellLogixKeyBypassFamilyCheck
