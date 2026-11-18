"""Native check -- Opto 22 OptoMMP unauthenticated access detection. SAFE + READ-ONLY.

OptoMMP is Opto 22's IEEE-1394-based memory-mapped protocol (TCP 2001) spoken by SNAP PAC, groov
EPIC, groov RIO, and SNAP I/O brains. It has NO authentication layer: any client that can reach
TCP/2001 can read AND write the device memory map -- I/O points (digital/analog), control, and config
-- with no credential (CWE-306). Opto 22's own guidance is to restrict the OptoMMP/web interfaces via
network security, which confirms the exposure is architectural, not a patchable defect (directly
analogous to the Omron FINS, MELSEC SLMP, SECS/GEM-HSMS and Cisco Smart Install exposure checks in
this repo) -> disclosure_status: public, a detection of an already-public by-design exposure.

This check reuses core.fingerprint.probe_optommp_identity, which sends ONE benign READ-BLOCK request
for the firmware-version memory-map address (0xF030001C) and confirms a read-block response. It carries
NO write/control and never touches an I/O point. A confirmed OptoMMP read == the device answers
unauthenticated memory-map requests -> CONFIRMED (MEMORY WRITE / I/O control reachable the same way).
No OptoMMP response -> NOT_APPLICABLE. Because OptoMMP has no auth step, "answers the read" is itself
the finding; there is nothing to brute-force.

params schema (all optional):
  default_port: OptoMMP port (default 2001)
  timeout:      seconds (default 5.0)
"""

from __future__ import annotations

from core.check import Check, CheckResult, CheckStatus
from core.target import Target
from core.fingerprint import probe_optommp_identity


class OptoMmpUnauthenticatedAccessCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        port = target.port or params.get("default_port", 2001)
        timeout = params.get("timeout", 5.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        fp = probe_optommp_identity(target.host, port, timeout=timeout)
        if fp.confidence != "none":
            fw = fp.firmware if fp.firmware and fp.firmware != "unknown" else "unknown"
            return self._result(
                target, CheckStatus.CONFIRMED,
                description=(
                    f"unauthenticated OptoMMP read-block answered by an Opto 22 device (firmware {fw}, "
                    f"method {fp.method}) -- the OptoMMP memory map (TCP/2001) accepts requests with no "
                    f"credential (CWE-306); memory/I/O WRITE and control are reachable the same way. This "
                    f"check only READ the firmware-version address; it issued no write/control."
                ),
            )
        return self._result(
            target, CheckStatus.NOT_APPLICABLE,
            description=f"no OptoMMP read-block response to an unauthenticated firmware-version read ({fp.method})",
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


CHECK_CLASS = OptoMmpUnauthenticatedAccessCheck
