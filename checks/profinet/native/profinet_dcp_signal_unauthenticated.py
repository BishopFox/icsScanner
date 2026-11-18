"""Native check — PROFINET DCP Set(Control/Signal) accepted with no authentication at all.

Confirms PISA-001 (PI/PROFIBUS & PROFINET International's own security advisory, "Improper
Access Control for DCP Services," CWE-862 Missing Authorization + CWE-1314 Missing Write
Protection for Parametric Data Values): DCP-Set has no authentication mechanism in the base
protocol, so any device on the local Ethernet segment can issue one. Not a vendor-specific
0-day — a protocol-wide characteristic affecting every PROFINET product/protocol version prior
to 2.4 MU4 that doesn't implement Security Class 1 (per PISA-001 itself; devices that DO
implement Security Class 1 "must have DCP Set disabled" entirely).

Uses Signal (the "flash LED" identify command) rather than PISA-001's own cited examples
(DCP-Set(NameOfStation), DCP-Set(Reset-to-Factory)) — those carry real communication-disruption
risk the advisory itself describes ("temporary interruption of the communication, until the
device name is set to the correct value"); Signal is a safe proxy that exercises the identical
unauthenticated-Set code path with zero operational impact (the device just blinks an LED for
~3 seconds per the official spec, PN-AL-protocol_2722_V24MU4_May23.pdf section 4.3.1.4.15 —
routine, harmless, everyday engineering-tool behavior). A CONFIRMED result here demonstrates the
same root cause PISA-001 describes; it does not itself replay the advisory's own riskier
examples.

DESTRUCTIVE for the same reason every other check here is: real protocol traffic against the
device, even though this specific operation has no lasting effect.

Wire-level orchestration lives in core/fingerprint.py:signal_profinet_device() — that module
owns the raw-socket/interface-detection plumbing and the Set request/response wire format
(cross-verified against scapy's and Wireshark's own PROFINET DCP implementations); this check
module owns only the CheckStatus mapping, matching this project's usual split.

IMPORTANT ambiguity, documented rather than hidden: signal_profinet_device() returns None for
several different underlying reasons it deliberately doesn't distinguish (device not locatable
by IP, no CAP_NET_RAW, no response in time) — this check treats every None as ERROR, since the
overwhelmingly likely cause in this project's default unprivileged posture is the scanner itself
lacking the raw-socket privilege PROFINET DCP requires, not a real negative result about the
device. A genuine NOT_APPLICABLE (the device responded but rejected the Set) is possible but
likely rare in practice — DCP's own BLOCK_ERRORS enum has no authentication-specific code at
all, which is itself part of PISA-001's own point.

params schema:
  timeout:   per-attempt response timeout in seconds (default 3.0)
  interface: network interface to use (default: auto-detected via routing, Linux only)
"""

from __future__ import annotations

from core.check import Check, CheckResult, CheckStatus
from core.fingerprint import signal_profinet_device
from core.target import Target


class ProfinetDcpSignalUnauthenticatedCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        timeout = params.get("timeout", 3.0)
        interface = params.get("interface")

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        block_error = signal_profinet_device(target.host, timeout=timeout, interface=interface)

        if block_error is None:
            return self._result(
                target,
                CheckStatus.ERROR,
                description=(
                    "could not complete the DCP Set(Signal) exchange. Most likely cause: this "
                    "scanner process lacks CAP_NET_RAW/root, which PROFINET DCP's raw AF_PACKET "
                    "socket requires (a real exception to this project's otherwise-unprivileged "
                    "probe posture). Could also mean the device wasn't locatable by IP or didn't "
                    "respond in time — see core/fingerprint.py:signal_profinet_device()'s "
                    "docstring for the full list of fail-closed reasons this doesn't distinguish."
                ),
            )

        if block_error == 0x00:
            return self._result(
                target,
                CheckStatus.CONFIRMED,
                description=(
                    "DCP Set(Control/Signal) accepted with no authentication challenge at all "
                    "(block_error=Ok). Confirms PISA-001 (PI/PROFINET International's own "
                    "advisory, CWE-862 Missing Authorization + CWE-1314 Missing Write Protection "
                    "for Parametric Data Values): DCP-Set has no authentication mechanism in the "
                    "base protocol. Signal (flash-LED) was used as a safe proxy for PISA-001's "
                    "own cited examples (NameOfStation, Reset-to-Factory), which carry real "
                    "communication-disruption risk this check deliberately avoids."
                ),
            )

        return self._result(
            target,
            CheckStatus.NOT_APPLICABLE,
            description=(
                f"device responded to the DCP Set(Signal) request but did not accept it "
                f"(block_error=0x{block_error:02X}). Note: DCP's own error-code set has no "
                f"authentication-specific value at all, so this does not necessarily mean the "
                f"device enforces authentication — it may simply be busy, not support the "
                f"Control option, or reject it for an unrelated local reason."
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


CHECK_CLASS = ProfinetDcpSignalUnauthenticatedCheck
