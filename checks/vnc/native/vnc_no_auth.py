"""Native check — VNC/RFB security-type-1 ("None") reachability. Built 2026-09-14 specifically to
unblock checks/candidates/abb-cp600-hmi-vnc-no-authentication-default.yaml (ABB CP600 HMI panels
ship their optional VNC remote-control server, TCP 5900, with no authentication by default once
enabled — confirmed directly in two official ABB application notes). See
checks/vnc/native/_rfb_common.py's own module docstring for the full RFB protocol sourcing.

Confirms the server OFFERS AND ACCEPTS security-type 1 ("None") — i.e. any client can connect
with no credential at all. Stops immediately once the security handshake resolves: never sends a
ClientInit, never reads the framebuffer, never transmits an input event (this project's
read-only-first discipline — the security handshake alone is sufficient proof).

RISK TIER: sends no credential at all — security-type None means the connection either is or
isn't allowed with zero authentication material, so there is nothing to "guess" or lock out.
Tagged risk_reason ["login"] (adverse tier) in the promoted check's own YAML, matching this
project's other no-guessing connection-only checks.

params schema:
  timeout:       connection timeout in seconds (default 5.0)
  default_port:  fallback port if the target doesn't specify one (default 5900)
"""

from __future__ import annotations

import socket

from core.check import Check, CheckResult, CheckStatus
from core.target import Target
from checks.vnc.native._rfb_common import (
    RfbProtocolError,
    SECURITY_TYPE_NONE,
    read_protocol_version,
    read_security_result,
    read_security_types,
    select_security_type,
)


class VncNoAuthenticationCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        timeout = params.get("timeout", 5.0)
        port = target.port or params.get("default_port", 5900)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        try:
            with socket.create_connection((target.host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                major, minor, raw_version = read_protocol_version(sock)
                sock.sendall(raw_version)
                version = (major, minor)
                offered = read_security_types(sock, version)

                if SECURITY_TYPE_NONE not in offered:
                    return self._result(
                        target,
                        CheckStatus.NOT_APPLICABLE,
                        description=f"server did not offer security-type None (offered: {offered})",
                    )

                select_security_type(sock, version, SECURITY_TYPE_NONE)

                if version >= (3, 8):
                    result = read_security_result(sock)
                    if result != 0:
                        return self._result(
                            target,
                            CheckStatus.NOT_APPLICABLE,
                            description=f"server offered security-type None but rejected it (SecurityResult={result})",
                        )

                return self._result(
                    target,
                    CheckStatus.CONFIRMED,
                    description="server offered and accepted VNC security-type 1 (None) — unauthenticated access confirmed",
                )
        except RfbProtocolError as exc:
            return self._result(target, CheckStatus.NOT_APPLICABLE, description=f"not a usable RFB handshake: {exc}")
        except (OSError, socket.timeout) as exc:
            return self._result(target, CheckStatus.ERROR, description=f"connection error: {exc}")

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


CHECK_CLASS = VncNoAuthenticationCheck
