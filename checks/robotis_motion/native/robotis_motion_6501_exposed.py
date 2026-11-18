"""Native check -- ROBOTIS RoboPlus Motion control server exposed (unauthenticated). SAFE + READ-ONLY.

The ROBOTIS RoboPlus Motion server (roboplus_vm) listens on TCP 6501 on networked ROBOTIS controllers
(the DARwIn-OP / ROBOTIS-OP2 humanoid is the documented host) and accepts a text command protocol with
NO authentication: a client connects and immediately issues commands. The protocol mixes read commands
(v = version, E = enumerate, Get, List, info) with actuation commands (go/set = move to goal position,
play/rplay = play a stored motion page, on/off = torque). An unauthenticated network client can
therefore command robot motion (CWE-306). Publicly reported by IOActive (2017, "Hacking Robots Before
Skynet"); confirmed from ROBOTIS's own open-source server (darwinop SourceForge,
robotisop2/Linux/project/roboplus/main.cpp + protocol.txt) -> disclosure_status: public.

This check reuses core.fingerprint.probe_robotis_motion_identity, which sends ONLY the benign "v"
version query -- in the open-source server the "v" handler returns "{[DARwIn:VERSION]}" and does nothing
else (no torque-enable, no motion) -- and parses the braced model:version reply. Because the protocol
has no auth of its own, "answers the unauthenticated version query" IS the finding. The check NEVER
sends go/set/play/on -- any actuation proof-of-impact belongs in scripts/safety_critical/, not here.

params schema (all optional):
  default_port: RoboPlus Motion control port (default 6501)
  timeout:      seconds (default 5.0)
"""

from __future__ import annotations

from core.check import Check, CheckResult, CheckStatus
from core.target import Target
from core.fingerprint import probe_robotis_motion_identity


class RobotisMotion6501ExposedCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        port = target.port or params.get("default_port", 6501)
        timeout = params.get("timeout", 5.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        fp = probe_robotis_motion_identity(target.host, port, timeout=timeout)
        if fp.confidence != "none":
            return self._result(
                target, CheckStatus.CONFIRMED,
                description=(
                    f"ROBOTIS RoboPlus Motion control server answered an unauthenticated version query "
                    f"on TCP {port} (model {fp.model}, roboplus_vm {fp.firmware}) -- the server accepts "
                    f"its command protocol with no authentication (CWE-306), and the same unauthenticated "
                    f"session reaches the go/set/play/torque motion commands. This check only sent the "
                    f"benign 'v' version query (the open-source server's 'v' handler just returns the "
                    f"version string); it issued no motion command."
                ),
            )
        return self._result(
            target, CheckStatus.NOT_APPLICABLE,
            description=f"no RoboPlus Motion version reply to an unauthenticated 'v' query ({fp.method})",
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


CHECK_CLASS = RobotisMotion6501ExposedCheck
