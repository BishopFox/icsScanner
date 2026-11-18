"""Native check — Omron FINS unauthenticated access detection. SAFE + READ-ONLY.

FINS (Factory Interface Network Service, Omron) has NO authentication layer -- any node that can
reach the CPU over FINS/UDP or FINS/TCP (port 9600) can issue MEMORY AREA READ/WRITE and RUN/STOP.
Omron's own Sysmac NJ FINS Technical Guide (W518-E1-01) documents that NJ-series CPUs support these
commands over the built-in EtherNet/IP port with "Network write protection: Not supported" (see
checks/candidates/omron-nj-fins-unauthenticated-memory-control.yaml). So a FINS device answering an
UNAUTHENTICATED read confirms the unauthenticated-control exposure (CWE-306).

This check reuses core.fingerprint.probe_fins_identity, which sends ONE benign CONTROLLER DATA READ
(FINS command 0x0501 -- returns the controller model/version, a pure read) over FINS/UDP first, then
FINS/TCP with the node-address handshake. It NEVER issues MEMORY AREA WRITE, RUN, or STOP. A
well-formed FINS response to that unauthenticated read == the device accepts FINS with no credential
-> CONFIRMED. No response / not FINS -> NOT_APPLICABLE. Because FINS has no auth step, "responds to
the read" is itself the finding; there is nothing to brute-force.

params schema (all optional):
  default_port: FINS port (default 9600)
  timeout:      seconds (default 5.0)
"""

from __future__ import annotations

from core.check import Check, CheckResult, CheckStatus
from core.target import Target
from core.fingerprint import probe_fins_identity


class FinsUnauthenticatedAccessCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        port = target.port or params.get("default_port", 9600)
        timeout = params.get("timeout", 5.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        fp = probe_fins_identity(target.host, port, timeout=timeout)
        if fp.confidence != "none":
            model = fp.model if fp.model and fp.model != "unknown" else "a FINS CPU"
            return self._result(
                target, CheckStatus.CONFIRMED,
                description=(f"unauthenticated FINS Controller Data Read answered by {model} "
                            f"(method {fp.method}) -- the FINS interface accepts commands with no "
                            f"credential; MEMORY AREA WRITE and RUN/STOP are reachable the same way (CWE-306). "
                            f"This check only READ the controller data; it issued no write/run/stop."),
            )
        return self._result(
            target, CheckStatus.NOT_APPLICABLE,
            description=f"no well-formed FINS response to an unauthenticated Controller Data Read ({fp.method})",
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


CHECK_CLASS = FinsUnauthenticatedAccessCheck
