"""PCOM/TCP wire protocol — Unitronics Vision/Samba PLC & HMI proprietary protocol, port 20256.
Ported byte-for-byte from Claroty Team82's `claroty/PCOM-Tools` (github.com/claroty/PCOM-Tools,
`pcom_client.py`), reverse-engineered by them from real Wireshark captures during their
Unitronics attack forensics research — read directly via source fetch on 2026-08-14, not
reconstructed from memory or a search summary, given the stakes (this is the wire format behind
CVE-2023-6448, the actively-exploited CVE behind the real November 2023 U.S. water-utility
attacks).

Shared between core/fingerprint.py's probe_pcom_tcp_identity() and
checks/pcom-tcp/native/unitronics_default_password.py's actual check — kept in one place rather
than duplicated (unlike S7comm/Modbus's small static-frame builders, this protocol's checksum
algorithm is intricate enough that two independently-maintained copies would be a real
correctness risk if they ever drifted apart).

No official public spec exists (Unitronics doesn't publish PCOM's format) — this is entirely
derived from Claroty's reverse-engineering work. Only the "Check Password" operation (opcode
0x02/0x82) is implemented; PCOM has many other function codes (memory read/write, project
upload, etc.) not needed here and deliberately not built.
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

_TCP_HEADER_SIZE = 6
_BINARY_HEADER_SIZE = 24
_BINARY_MAGIC = b"/_OPLC"
_BINARY_SUFFIX = b"\\"

_OP_CHECK_PASSWORD_REQUEST = 0x02
_OP_CHECK_PASSWORD_RESPONSE = 0x82
_CHECK_PASSWORD_SUCCESS_BYTE = 0x64  # 100 decimal — response byte 13 on success


def _calc_header_crc(header_22_bytes: bytes) -> bytes:
    """Two's-complement checksum over the first 22 header bytes — NOT a real CRC despite the
    source's function name (calc_binary_hedear_crc), verified from source: sum mod 0x10000,
    bitwise NOT, +1, mod 0xffff, +1, packed little-endian u16."""
    total = sum(header_22_bytes) % 0x10000
    return struct.pack("<H", ((~total + 1) % 0xFFFF + 1))


def _calc_footer_crc(payload_after_header: bytes) -> bytes:
    """Same checksum algorithm, computed over the command_data bytes (everything after the
    24-byte header, before the footer itself is appended)."""
    total = sum(payload_after_header) % 0x10000
    return struct.pack("<H", ((~total + 1) % 0xFFFF + 1))


def build_check_password_request(password: str, tcp_transaction_id: int = 1) -> bytes:
    """Builds a complete PCOM/TCP-wrapped 'Check Password' request. password is truncated to 8
    chars, left-justified with spaces, ASCII-encoded — matches Unitronics' own 8-character
    password field width."""
    command_data = password[:8].ljust(8, " ").encode("ascii", errors="replace")

    header = bytearray()
    header += _BINARY_MAGIC  # offset 0-5: magic
    header += b"\x00"  # offset 6: ID
    header += b"\xfe"  # offset 7: res1
    header += b"\x01"  # offset 8: res2
    header += b"\x00\x00\x00"  # offset 9-11: res3 (Check-Password-specific override, not the
    # general create_binary_request default of \x01\x00\x00)
    header += struct.pack("b", _OP_CHECK_PASSWORD_REQUEST)  # offset 12: opcode
    header += b"\x00"  # offset 13: res4
    header += b"\x00\x00\x00\x00\x00\x00"  # offset 14-19: command_details (unused here)
    header += struct.pack("<H", len(command_data))  # offset 20-21: data length
    header += _calc_header_crc(bytes(header))  # offset 22-23: header checksum, over header[0:22]

    packet = bytearray(header)
    packet += command_data
    packet += _calc_footer_crc(command_data)  # footer checksum over command_data only
    packet += _BINARY_SUFFIX

    pcom_payload = bytes(packet)
    tcp_header = struct.pack("<H", tcp_transaction_id) + struct.pack("B", 102) + b"\x00" + struct.pack("<H", len(pcom_payload))
    return tcp_header + pcom_payload


def parse_check_password_response(raw: bytes) -> Optional[bool]:
    """Strips the 6-byte TCP header, then checks the binary payload's opcode (offset 12) and
    status byte (offset 13). Returns True (password accepted), False (rejected but a valid PCOM
    response), or None (not a well-formed PCOM response at all — wrong protocol / garbage)."""
    if len(raw) < _TCP_HEADER_SIZE + 14:
        return None
    payload = raw[_TCP_HEADER_SIZE:]
    if payload[0:6] != _BINARY_MAGIC:
        return None
    opcode = payload[12]
    status = payload[13]
    if opcode != _OP_CHECK_PASSWORD_RESPONSE:
        return None
    return status == _CHECK_PASSWORD_SUCCESS_BYTE


def check_password(host: str, port: int, password: str, timeout: float = 5.0) -> Optional[bool]:
    """Convenience wrapper: connect, send a Check Password request, return the parsed result.
    None means the target didn't return a well-formed PCOM response (not this protocol, or
    unreachable) — distinct from False (well-formed PCOM response, password rejected)."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(build_check_password_request(password))
        response = sock.recv(4096)
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return parse_check_password_response(response)
