"""Native check — Beckwith Electric M-3425A Comprehensive Generator Relay: is the Modbus
communication channel currently unlocked (i.e. is communication security effectively bypassed
right now, regardless of whether that's because the factory-default comm access code 9999 was
never changed, or some other reason)?

Sourced directly from Beckwith's own official "M-3425A MODBUS/BECO2200 COMMUNICATION DATABASE"
(Rev. 1.15a), read via pdftotext, not search-summarized. Two facts from that document combine to
make this check both real and genuinely safe:

1. The relay ships with its Communication Access Code set to 9999 — the documented sentinel
   value that DISABLES communication security entirely (confirmed twice in the companion M-3425A
   Instruction Book: "if the communication access code is set to 9999 (default), communication
   security is disabled"). A factory-fresh unit therefore never locks its comm channel at all.
2. TYPE 0, POINT 30 ("Communication channel lock status") is a genuine, DEVICE-COMPUTED,
   READ-ONLY register: "0 = comm channel unlocked, 1 = comm channel locked". This is a direct
   observation, the same design principle as the GE Multilin 850 check's password-register read
   (checks/modbus/native/ge_multilin_850_factory_passcode.py) — not an inference from an echoed
   write.

NON-DESTRUCTIVE BY DESIGN (destructive: false), a deliberate choice, not an oversight: this
check performs ONLY a single Modbus read (FC03), no write of any kind. The same protocol document
explicitly warns that writing to the access-code register (TYPE 0, POINT 35) — even an attempt to
proactively confirm the 9999-disabled state by writing 9999 — "will unconditionally lock the
communication channel" if security happens to be enabled. A write-based check could therefore
ACTIVELY LOCK OUT a legitimate operator's live session on a relay where security is properly
configured — a real availability risk this check avoids entirely by never writing anything.

REGISTER ADDRESSING — a real, easy-to-get-wrong conversion, verified against the document's own
worked example before use, not assumed: the document's own worked example states "TYPE 3, POINT
NUMBER 43 -> address = 3*256+43 = 811 (0-based)... this would be register 812" i.e. the
document's own "REGISTER" column = (0-based PDU address) + 1. TYPE 0 POINT 30 is documented as
"REGISTER 31" in the same table, so the actual 0-based Modbus PDU address to request is 31 - 1 =
30 (= 0*256 + 30, matching the type*256+point formula directly, a useful cross-check that the -1
conversion was applied correctly).

INTERPRETATION CAVEAT, stated plainly: a CONFIRMED result here means the comm channel is
observed unlocked RIGHT NOW — it does not, and cannot, prove this is specifically because the
factory-default 9999 code was never changed, versus a legitimate operator having just
successfully unlocked it with a real, non-default code (the document states the channel also
re-locks automatically after ~2.5 minutes of inactivity, so a transient legitimate unlock is
possible). The underlying exposure — TYPE non-0 setpoints and control points are freely
readable/writable over Modbus with no credential ever having been supplied by this check, for as
long as the channel reads unlocked — is real and worth reporting regardless of root cause, the
same way this project's other checks report what is observably true rather than asserting
unprovable causation.

fingerprint_precondition requires BOTH vendor AND product ("M-3425A") — there is no live way to
distinguish this specific Beckwith relay model from other Beckwith protection relays over Modbus,
same deliberate safety gate as every other model-specific relay check in this project.
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_LOCK_STATUS_ADDR = 30  # 0-based PDU address; document's own "REGISTER 31" minus 1 -- see module docstring
_FC_READ_HOLDING = 0x03


def _mbap(pdu: bytes, unit_id: int = 0xFF, tid: int = 0x0001) -> bytes:
    return struct.pack(">HHHB", tid, 0x0000, 1 + len(pdu), unit_id) + pdu


class BeckwithM3425aCommChannelUnlockedCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        if target.port is None:
            return self._result(target, CheckStatus.ERROR, description="target has no port configured")

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        pdu = struct.pack(">BHH", _FC_READ_HOLDING, _LOCK_STATUS_ADDR, 1)
        sock: Optional[socket.socket] = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((target.host, target.port))
            sock.sendall(_mbap(pdu))
            resp = sock.recv(256)
        except socket.timeout:
            return self._result(target, CheckStatus.ERROR, description="no response to comm-channel-lock-status read within timeout")
        except OSError as e:
            return self._result(target, CheckStatus.ERROR, description=f"connection error: {e}")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

        if len(resp) >= 11 and resp[7] == _FC_READ_HOLDING and resp[8] == 2:
            value = struct.unpack_from(">H", resp, 9)[0]
            if value == 0:
                return self._result(
                    target,
                    CheckStatus.CONFIRMED,
                    description=(
                        "Communication channel lock status register (0-based address 30, "
                        "documented 'REGISTER 31') reads 0 (unlocked) — the Modbus channel is "
                        "currently open with no credential ever having been supplied by this "
                        "check. Consistent with the documented factory-default state (comm "
                        "access code 9999, communication security disabled) but this read alone "
                        "cannot distinguish that from a legitimate operator's active session — "
                        "see the check module's docstring."
                    ),
                    evidence=resp,
                )
            return self._result(
                target,
                CheckStatus.NOT_APPLICABLE,
                description="Communication channel lock status register reads 1 (locked) — relay is confirmed reachable, communication security is currently active.",
                evidence=resp,
            )

        return self._result(
            target,
            CheckStatus.ERROR,
            description="unrecognized or exception response reading the comm-channel-lock-status register",
            evidence=resp,
        )

    def _result(
        self, target: Target, status: CheckStatus, description: str = "", evidence: Optional[bytes] = None
    ) -> CheckResult:
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


CHECK_CLASS = BeckwithM3425aCommChannelUnlockedCheck
