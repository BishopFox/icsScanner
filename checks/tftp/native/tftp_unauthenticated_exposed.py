"""Native check — generic TFTP (RFC 1350) unauthenticated exposure, UDP/69.

TFTP has no authentication field anywhere in the protocol -- there is no vendor-specific
"default credential" to guess here, unlike this project's other default-creds checks. The
exposure is the protocol itself answering at all: any client that can reach the port can
request any file it can name, no login. Reuses core.fingerprint.probe_tftp_identity() directly
(see that function's own docstring) rather than duplicating the RRQ-building/response-parsing
logic -- the fingerprint probe and the check confirmation are the same operation, same reasoning
already established for the Smart Install check built alongside this one.

NON-DESTRUCTIVE BY DESIGN, AND DELIBERATELY NOT A DATA-EXFIL CHECK: the reused probe requests a
scanner-tagged, deliberately nonexistent filename and never follows up a DATA reply with further
block reads, so no real file transfer is ever completed even in the unlikely case the probed
name happens to exist on the target.

Framed as an informational CWE-306 (Missing Authentication for Critical Function) exposure
signal, not a CVSS-scored vulnerability -- unlike Smart Install, actual impact here depends
entirely on what a given device happens to serve over TFTP (a config backup service, a firmware
upgrade helper, or nothing sensitive at all), which this generic, vendor-agnostic check has no
way to know. No CVE -- TFTP's lack of authentication is the documented protocol design (RFC
1350), not a vulnerability in any one implementation.
"""

from __future__ import annotations

from core.check import Check, CheckResult, CheckStatus
from core.fingerprint import probe_tftp_identity
from core.target import Target

_DEFAULT_PORT = 69
_TIMEOUT_S = 5.0


class TftpUnauthenticatedExposedCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        port = target.port or _DEFAULT_PORT

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        result = probe_tftp_identity(target.host, port=port, timeout=_TIMEOUT_S)

        if result.confidence != "high":
            return self._result(
                target, CheckStatus.NOT_APPLICABLE,
                description=f"no TFTP response from {target.host}:{port} ({result.method})",
            )

        opcode = result.extra.get("opcode")
        if opcode == 5:
            detail = f"ERROR reply (code {result.extra.get('error_code')}: {result.extra.get('error_message', '')!r})"
        else:
            detail = f"DATA reply (block {result.extra.get('block_number')})"

        return self._result(
            target, CheckStatus.CONFIRMED,
            description=(
                f"{target.host}:{port} answered an unauthenticated TFTP read request with a "
                f"well-formed {detail} -- TFTP has no authentication mechanism (RFC 1350), so "
                f"any file this server serves is reachable by anyone who can reach this port "
                f"(CWE-306)"
            ),
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


CHECK_CLASS = TftpUnauthenticatedExposedCheck
