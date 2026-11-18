"""Native check — Siemens S7comm UNAUTHENTICATED SZL CPU-identification read (info disclosure).

Classic S7comm (S7-300/400, ET200, WinAC, and s7comm-compatible stacks like snap7/OpenPLC) has NO
authentication on the System Status List (SZL) read: any client that completes the standard
ISO-on-TCP handshake can read SZL-ID 0x001C (CPU component identification: module order number /
"6ES7..." MLFB, firmware/version, serial, plant designation, OEM copyright) with no credential.
This is the Siemens analog of the Schneider UMAS READ_ID, LS XGT read, and Mitsubishi SLMP read —
an information-disclosure / missing-authentication exposure (CWE-306 / CWE-200). (S7-1200/1500 use
s7comm-PLUS with integrated auth/encryption, which gates this -> those are out of scope here.)

This check performs the benign, READ-ONLY sequence on ONE connection: COTP CR -> CC, S7 Setup
Communication -> ack, S7 Userdata Read-SZL (0x001C, fallback 0x0011) -> response. It never writes,
stops the CPU, or changes mode. A successful SZL data response (S7 userdata, return code 0xFF)
confirms the unauthenticated disclosure.

WIRE FORMAT cross-verified (XGT/SLMP/UMAS playbook; no SIOS firmware needed): the COTP CR + S7 Setup
frames are the project's own proven probe_s7comm_identity frames; the Read-SZL userdata request +
SZL-ID 0x001C/0x0011 are from snap7 / python-snap7 (read_szl / get_cpu_info), klsecservices/s7scan,
plcscan (s7-enumerate.nse), and nmap s7-info.nse -- all of which issue the identical unauthenticated
SZL read.

params schema:
  default_port:  fallback port (ISO-on-TCP 102)
  szl_ids:       list of SZL-IDs to try, in order (default [0x001C, 0x0011])
  timeout:       seconds (default 5.0)
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

# COTP Connection Request (TPKT + COTP CR, dst/src TSAP 0x0001) — same frame probe_s7comm_identity
# uses and that is proven to elicit a CC + Setup-Comm ack (a CPU-level function).
_S7_COTP_CR = struct.pack("!BBH", 0x03, 0x00, 22) + bytes([
    0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
    0xC0, 0x01, 0x0A,
    0xC1, 0x02, 0x00, 0x01,
    0xC2, 0x02, 0x00, 0x01,
])
_COTP_DT = bytes([0x02, 0xF0, 0x80])  # COTP Data (DT), EOT


def _tpkt(payload: bytes) -> bytes:
    return struct.pack("!BBH", 0x03, 0x00, 4 + len(payload)) + payload


_S7_SETUP_COMM = _tpkt(_COTP_DT + bytes([
    0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
    0xF0, 0x00, 0x00, 0x08, 0x00, 0x08, 0x03, 0xC0,
]))


def build_szl_read(szl_id: int, szl_index: int = 0x0000, pdu_ref: int = 0x0001) -> bytes:
    """S7 Userdata Read-SZL request (CPU functions, subfunction Read SZL)."""
    s7_header = bytes([0x32, 0x07, 0x00, 0x00]) + struct.pack(">H", pdu_ref) + bytes([0x00, 0x08, 0x00, 0x08])
    param = bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00])
    data = bytes([0xFF, 0x09, 0x00, 0x04]) + struct.pack(">H", szl_id) + struct.pack(">H", szl_index)
    return _tpkt(_COTP_DT + s7_header + param + data)


def _recv_tpkt(sock: socket.socket, timeout: float) -> Optional[bytes]:
    sock.settimeout(timeout)
    try:
        hdr = b""
        while len(hdr) < 4:
            chunk = sock.recv(4 - len(hdr))
            if not chunk:
                return b""
            hdr += chunk
        if hdr[0] != 0x03:
            return hdr
        total = struct.unpack("!H", hdr[2:4])[0]
        rest = total - 4
        body = b""
        while len(body) < rest > 0:
            chunk = sock.recv(min(rest - len(body), 65536))
            if not chunk:
                break
            body += chunk
        return hdr + body
    except socket.timeout:
        return None
    except (ConnectionResetError, OSError):
        return b""


def _extract_order_number(resp: bytes) -> Optional[str]:
    """Pull a recognizable Siemens MLFB order number (6ES7.../6GK.../6AG...) from an SZL response."""
    for prefix in (b"6ES7", b"6ES", b"6GK", b"6AG", b"6DL"):
        i = resp.find(prefix)
        if i >= 0:
            raw = resp[i:i + 24]
            printable = bytes(c for c in raw if 0x20 <= c < 0x7F).decode("latin-1", "replace").strip()
            if len(printable) >= 6:
                return printable
    return None


def _szl_response_ok(resp: Optional[bytes]) -> bool:
    """True if resp is an S7comm USERDATA response (0x32/0x07) carrying a success SZL data block."""
    if not resp or len(resp) < 19:
        return False
    if resp[7] != 0x32 or resp[8] != 0x07:   # S7 protocol id + ROSCTR userdata
        return False
    # the userdata DATA section carries return code 0xFF (success) + transport size 0x09 before SZL
    return b"\xff\x09" in resp[17:]


class S7commSzlUnauthInfoCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        port = target.port or params.get("default_port", 102)
        szl_ids = params.get("szl_ids", [0x001C, 0x0011])
        timeout = params.get("timeout", 5.0)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target.host, port))
            sock.sendall(_S7_COTP_CR)
            cc = _recv_tpkt(sock, timeout)
            if not cc or len(cc) < 6 or cc[5] != 0xD0:   # COTP Connection Confirm
                return self._result(target, CheckStatus.NOT_APPLICABLE,
                                    description=f"no COTP Connection Confirm on {port} — not S7comm/ISO-on-TCP")
            sock.sendall(_S7_SETUP_COMM)
            setup = _recv_tpkt(sock, timeout)
            if not setup or len(setup) < 9 or setup[7] != 0x32:
                return self._result(target, CheckStatus.NOT_APPLICABLE,
                                    description="S7 Setup Communication was not acknowledged — not applicable")
            for szl_id in szl_ids:
                sock.sendall(build_szl_read(szl_id))
                resp = _recv_tpkt(sock, timeout)
                if _szl_response_ok(resp):
                    mlfb = _extract_order_number(resp)
                    idtxt = f" (order number {mlfb})" if mlfb else ""
                    return self._result(target, CheckStatus.CONFIRMED,
                                        description=f"Siemens S7comm disclosed CPU identification via an UNAUTHENTICATED SZL read (SZL-ID 0x{szl_id:04x}) on {port}{idtxt} — missing authentication on classic S7comm SZL (CWE-306/CWE-200)")
            return self._result(target, CheckStatus.NOT_APPLICABLE,
                                description="S7comm present but SZL read returned no success data (may be s7comm-plus / access-protected) — not confirmed")
        except OSError:
            return self._result(target, CheckStatus.NOT_APPLICABLE,
                                description=f"no S7comm response on {port} — not applicable")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

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


CHECK_CLASS = S7commSzlUnauthInfoCheck
