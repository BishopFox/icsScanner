"""Shared RFB (VNC) protocol handshake logic for checks/vnc/native/*.py — this project's first
VNC executor, built 2026-09-14 to unblock
checks/candidates/abb-cp600-hmi-vnc-no-authentication-default.yaml. Same shared-helper convention
as checks/opcua/native/_common.py.

PROTOCOL, sourced directly from the community-maintained RFB protocol spec
(https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst — the actively-maintained
de facto successor to RFC 6143, fetched and read directly), not guessed or hand-derived:

  1. ProtocolVersion handshake: server sends "RFB xxx.yyy\\n" (12 ASCII bytes); client replies
     with a ProtocolVersion of its own. This module always echoes back exactly what the server
     sent (never tries to negotiate a different/newer version) — the simplest correct behavior
     for a probe that only needs the Security handshake, not a real remote-control session.
  2. Security handshake:
     - RFB <= 3.3: server sends a single 4-byte big-endian U32 security-type directly (0=invalid/
       connection-failed, 1=None, 2=VNC Authentication) — no negotiation, no client response.
     - RFB >= 3.7: server sends a 1-byte count followed by that many 1-byte security-type values;
       the client responds with a single byte selecting one of the offered types.
  3. security-type 1 ("None"): spec's own words — "No authentication is needed and protocol data
     is to be sent unencrypted." RFB 3.8+ still sends a SecurityResult message after the client
     selects it; RFB 3.3/3.7 do not (the connection is simply usable from that point on).
  4. security-type 2 ("VNC Authentication"): server sends a random 16-byte challenge; client
     encrypts it — "each 8 bytes... independently" (i.e. ECB mode, two consecutive blocks) —
     using DES, keyed by the password with an unusual bit-reversal, spec's own words: "The lowest
     bit of each byte is considered the first bit and the highest discarded as parity. This is
     the reverse order of most implementations of DES." I.e.: null-pad or truncate the password
     to exactly 8 bytes, then reverse the BIT ORDER WITHIN each byte (not byte order) to get the
     actual 8-byte DES key. VNC Authentication always yields a SecurityResult, regardless of RFB
     version (unlike security-type None, where 3.3/3.7 skip it) — without it there would be no
     way to signal a wrong password on the pre-3.8 protocol at all.
  5. SecurityResult: 4-byte big-endian U32, 0=OK, 1=failed, 2=failed-too-many-attempts (RFB 3.8
     additionally carries a reason string on failure — not read here, a failure is a failure
     regardless of the human-readable why, and skipping it keeps this a fixed-length read).

DES NOTE: Python's stdlib has no DES, and the `cryptography` package (already a dependency of
this project) dropped standalone single-DES support — only TripleDES remains. TripleDES keyed
with the SAME 8-byte key repeated 3 times (K,K,K) is mathematically identical to single DES: the
EDE (Encrypt-Decrypt-Encrypt) formula collapses to a single Encrypt when all three sub-keys match,
since E_k(D_k(E_k(x))) = E_k(x) (D_k undoes the preceding E_k). VERIFIED here, not just derived on
paper: this exact construction (`TripleDES(key=b'\\x00'*24)` over ECB, one all-zero 8-byte block)
reproduces the well-known standard all-zero-key/all-zero-plaintext single-DES test vector
`8ca64de9c1b123a7` byte-for-byte. The bit-reversal step (reverse_bits_byte / vnc_des_key below)
was separately verified against two independent published worked examples (password "COW", and
password "12345678" whose reversed-key value is independently published as `8c4ccc2cac6cec1c` —
reproduced exactly by this module).
"""

from __future__ import annotations

import socket
import struct

SECURITY_TYPE_INVALID = 0
SECURITY_TYPE_NONE = 1
SECURITY_TYPE_VNC_AUTH = 2


class RfbProtocolError(Exception):
    """Raised for any handshake-level failure (short read, unexpected version string, no
    matching security type offered, etc.) — always caught by the Check classes that use this
    module and turned into a CheckResult, never allowed to propagate out of probe()."""


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RfbProtocolError(f"connection closed after {len(buf)} of {n} expected bytes")
        buf += chunk
    return buf


def read_protocol_version(sock: socket.socket) -> tuple[int, int, bytes]:
    raw = recv_exact(sock, 12)
    if not raw.startswith(b"RFB ") or raw[-1:] != b"\n":
        raise RfbProtocolError(f"not an RFB ProtocolVersion message: {raw!r}")
    try:
        major = int(raw[4:7])
        minor = int(raw[8:11])
    except ValueError as exc:
        raise RfbProtocolError(f"malformed ProtocolVersion message: {raw!r}") from exc
    return major, minor, raw


def read_security_types(sock: socket.socket, version: tuple[int, int]) -> list[int]:
    """Returns the list of security types on offer — a single-element list for RFB <= 3.3 (the
    server decided unilaterally), or the server's real offered list for RFB >= 3.7."""
    if version <= (3, 3):
        (value,) = struct.unpack(">I", recv_exact(sock, 4))
        if value == SECURITY_TYPE_INVALID:
            raise RfbProtocolError("server sent security-type 0 (invalid / connection failed)")
        return [value]
    count = recv_exact(sock, 1)[0]
    if count == 0:
        # RFB >= 3.7 signals failure the same way as 3.3's type-0: a reason string follows.
        (reason_len,) = struct.unpack(">I", recv_exact(sock, 4))
        reason = recv_exact(sock, reason_len).decode("utf-8", errors="replace") if reason_len else ""
        raise RfbProtocolError(f"server offered zero security types: {reason!r}")
    return list(recv_exact(sock, count))


def select_security_type(sock: socket.socket, version: tuple[int, int], chosen: int) -> None:
    """RFB <= 3.3 has nothing to send back (the server already decided); RFB >= 3.7 requires the
    client to pick one of the offered types."""
    if version >= (3, 7):
        sock.sendall(bytes([chosen]))


def read_security_result(sock: socket.socket) -> int:
    (value,) = struct.unpack(">I", recv_exact(sock, 4))
    return value


def reverse_bits_byte(b: int) -> int:
    """Reverses the bit order within a single byte — the VNC/RFB-specific DES key transform
    (spec's own words: "the lowest bit of each byte is considered the first bit"). See this
    module's own docstring for the two independent published worked examples this was verified
    against."""
    b = ((b & 0xF0) >> 4) | ((b & 0x0F) << 4)
    b = ((b & 0xCC) >> 2) | ((b & 0x33) << 2)
    b = ((b & 0xAA) >> 1) | ((b & 0x55) << 1)
    return b


def vnc_des_key(password: str) -> bytes:
    """Password (ASCII, any length) -> the 8-byte DES key VNC Authentication actually uses:
    truncate/null-pad to 8 bytes, then bit-reverse each byte."""
    pw_bytes = password.encode("ascii", errors="replace")[:8]
    pw_bytes = pw_bytes + b"\x00" * (8 - len(pw_bytes))
    return bytes(reverse_bits_byte(byte) for byte in pw_bytes)


def des_encrypt_16(key8: bytes, data16: bytes) -> bytes:
    """Encrypts a 16-byte VNC-Authentication challenge as two independent 8-byte ECB blocks,
    using single DES keyed by key8 — implemented via `cryptography`'s TripleDES with the same
    8-byte key repeated 3 times, which collapses to single DES (see module docstring for the
    verified derivation)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:  # older `cryptography` versions without the decrepit split
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

    cipher = Cipher(TripleDES(key8 * 3), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(data16) + encryptor.finalize()
