"""Native check -- Franklin Fueling Systems web console exposed (bb-web-server platform). SAFE + READ-ONLY.

Franklin Fueling Systems fuel-site controllers run a common Debian-based Linux platform whose web UI is
served by mc-web-server (platform "mc") or tg-web-server (platform "tg"), both on libbb-web-server.
Grounded in firmware triaged 2026-11-13: RCS 1.6.3 (platform "mc", motor/pump control -- E-stop / module
switching) and EVO 600/6000 3.31.4 + EVO ONE LLD 200/400 3.32.2 (platform "tg", automatic tank gauge +
line-leak detection). A network-reachable console web interface is the exposed-ICS-web-management surface
CISA fuel/WWS guidance says to keep off untrusted networks: the login surface and the remote-operations
vector for a device that controls fuel dispensing / leak detection (tg) or motors (mc).

This reuses core.fingerprint.probe_franklin_fueling_web_identity, which sends ONE unauthenticated HTTP(S)
GET "/" and matches the served Franklin brand marker (required -> fail-closed) plus a bb-web-server
platform signal. A brand match == a Franklin Fueling console answered -> CONFIRMED; no brand -> NOT_APPLICABLE.

IMPORTANT -- what this does NOT claim: these consoles are hardened (WebAuthn/FIDO2 web login, all OS
accounts locked, SSH host + TLS keys generated at boot, GPG-signed updates). This check identifies an
exposed management interface; it is NOT a credential bypass and asserts no default/weak credential. It
sends no credentials and makes no writes.

params schema (all optional):
  default_port: console web port (default 443; also 80)
  timeout:      seconds (default 5.0)
"""

from __future__ import annotations

from core.check import Check, CheckResult, CheckStatus
from core.target import Target
from core.fingerprint import probe_franklin_fueling_web_identity


class FranklinFuelingWebConsoleExposedCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        port = target.port or params.get("default_port", 443)
        timeout = params.get("timeout", 5.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        fp = probe_franklin_fueling_web_identity(target.host, port, timeout=timeout)
        if fp.confidence != "none":
            return self._result(
                target, CheckStatus.CONFIRMED,
                description=(
                    f"A Franklin Fueling Systems web console answered an unauthenticated GET on TCP "
                    f"{port} ({fp.method}, {fp.confidence} confidence) -- the fuel-site controller's "
                    f"management/operations web interface is network-reachable. On tank-gauge (tg) "
                    f"builds this fronts fuel inventory, line-leak detection and dispenser functions "
                    f"(the ATG serial command port TCP/10001 is often also exposed); on motor-control "
                    f"(mc) builds it fronts E-stop and module control. This is the exposed-ICS-web-"
                    f"management surface CISA fuel/WWS guidance says to remove from untrusted networks. "
                    f"The check only identified the interface: it sent no credentials and made no "
                    f"writes, and asserts no credential weakness (device login is WebAuthn/FIDO2)."
                ),
            )
        return self._result(
            target, CheckStatus.NOT_APPLICABLE,
            description=f"no Franklin Fueling web console response ({fp.method}); not a Franklin Fueling bb-web-server console",
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


CHECK_CLASS = FranklinFuelingWebConsoleExposedCheck
