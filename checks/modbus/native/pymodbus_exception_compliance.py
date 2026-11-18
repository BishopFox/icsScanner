"""Native check — Modbus exception-response protocol compliance (transaction ID echo + correct
exception function code). Ported from
a companion fuzzing toolkit's finding. Native because it needs to
compare the RESPONSE's transaction ID against the exact TID this probe sent — dynamic
request/response correlation core/declarative.py's static prefix-match model can't express (see
../../../01-METHODOLOGY-AND-CHECKLISTS.md's format decision).

SAFE / non-destructive: sends one unassigned function code, expects a compliant exception
response. disclosure_status=disclosed-fixed — the bug this checks for (hardcoded exception FC
0x28 + transaction_id never set for undecodable FCs) was fixed upstream in pymodbus (PR #2992,
[[project-cve-submissions]]); this check can report either CONFIRMED (an unpatched/pre-fix
pymodbus version) or NOT_APPLICABLE (fixed, compliant behavior) — it is eligible for
CheckRegistry.shippable() once posture allows.
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_UNASSIGNED_FC = 0x2C  # unassigned per Modbus Application Protocol v1.1b3 §6


class PymodbusExceptionComplianceCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        if target.port is None:
            return self._result(target, CheckStatus.ERROR, description="target has no port configured")

        tid = 0x4242  # a distinctive TID, unlikely to collide with anything else in flight
        pdu = bytes([_UNASSIGNED_FC])
        payload = struct.pack(">HHHB", tid, 0x0000, 1 + len(pdu), 0x01) + pdu

        sock: Optional[socket.socket] = None
        try:
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((target.host, target.port))
            sock.sendall(payload)
            response = sock.recv(256)
        except socket.timeout:
            return self._result(
                target, CheckStatus.ERROR, description="no response to unassigned-FC probe within timeout"
            )
        except OSError as e:
            return self._result(target, CheckStatus.ERROR, description=f"connection error: {e}")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

        if len(response) < 9:
            return self._result(
                target,
                CheckStatus.ERROR,
                description=f"response too short to evaluate ({len(response)} bytes)",
                evidence=response,
            )

        resp_tid = struct.unpack_from(">H", response, 0)[0]
        resp_fc = response[7]
        expected_exception_fc = _UNASSIGNED_FC | 0x80

        tid_correct = resp_tid == tid
        fc_correct = resp_fc == expected_exception_fc

        if tid_correct and fc_correct:
            return self._result(
                target,
                CheckStatus.NOT_APPLICABLE,
                description="compliant exception response (correct TID echo, correct exception FC) — not the pre-fix pymodbus bug",
                evidence=response,
            )
        return self._result(
            target,
            CheckStatus.CONFIRMED,
            description=(
                f"non-compliant exception response (tid_correct={tid_correct}, "
                f"fc_correct={fc_correct}) — matches the pre-fix pymodbus#2990 bug pattern"
            ),
            evidence=response,
        )

    def _result(self, target: Target, status: CheckStatus, description: str = "", evidence: Optional[bytes] = None) -> CheckResult:
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
            evidence=evidence,
        )


CHECK_CLASS = PymodbusExceptionComplianceCheck
