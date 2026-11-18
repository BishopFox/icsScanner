"""Native check — TCP connection pool exhaustion. Ported from
a companion fuzzing toolkit:_check_pool_exhaust. Fundamentally a
multi-connection loop (opens several connections rapidly, watches for the point pooling breaks
down) — doesn't fit core/declarative.py's single-connection send/expect step model, hence
native rather than declarative, per the format decision
(../../../01-METHODOLOGY-AND-CHECKLISTS.md).

DESTRUCTIVE: opens up to 7 rapid connections and can cause brief service disruption — the
original PoC's own disclaimer calls this out explicitly (`--safe-only` skips it there). Never
runs unless the scan explicitly opts in (ScanEngine safe-mode default, Milestone 1).
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_VALID_PDU = struct.pack(">BHH", 0x03, 0x0000, 0x0001)


def _mbap(pdu: bytes, uid: int = 0x01, tid: int = 0x0001) -> bytes:
    return struct.pack(">HHHB", tid, 0x0000, 1 + len(pdu), uid) + pdu


class EspmodbusPoolExhaustCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        if target.port is None:
            return self._result(target, CheckStatus.ERROR, description="target has no port configured")

        first_reset: Optional[int] = None
        for i in range(7):
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3.0)
                sock.connect((target.host, target.port))
                sock.sendall(_mbap(_VALID_PDU, tid=i + 1))
                sock.recv(256)
            except ConnectionResetError:
                if first_reset is None:
                    first_reset = i + 1
            except OSError:
                pass
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

        if first_reset is not None:
            return self._result(
                target,
                CheckStatus.CONFIRMED,
                description=f"connection pool exhaustion — reset observed on connection #{first_reset} of 7",
            )
        return self._result(
            target, CheckStatus.NOT_APPLICABLE, description="no connection resets observed across 7 rapid connections"
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


CHECK_CLASS = EspmodbusPoolExhaustCheck
