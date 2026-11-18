"""Generic native check — SNMPv3 USM (User-based Security Model) default-credential test.

Fills the gap flagged by checks/candidates/schneider-modicon-tm172si-snmpv3-default-creds.yaml:
the existing checks/snmp/native/snmp_community_default_creds.py only implements SNMPv1/v2c's
single shared community string — a fundamentally simpler mechanism than SNMPv3 USM, which is a
real per-user auth (and optionally privacy) protocol requiring engine-ID discovery and RFC 3414
key derivation before a single credential can even be tested.

SCOPE, DELIBERATE: this check only exercises "authNoPriv" security level (authentication, no
encryption) for real passphrase-based credentials — it never implements DES/AES privacy. Two
reasons:
  1. Python's stdlib has no DES/AES primitive (hashlib/hmac cover the auth side entirely: MD5/SHA1
     digests and HMAC truncation are all RFC 3414 needs for authentication). Adding a real crypto
     dependency (cryptography/pycryptodome) for a scanner check this project has otherwise kept
     stdlib-only would be a real new dependency, not a params-only extension.
  2. It isn't actually needed for what this check proves. USM authentication and VACM authorization
     are separate RFC 3414/3415 layers: authenticating at authNoPriv either gets a real
     GetResponse-PDU back (full success) or a GetResponse-PDU carrying an authorizationError
     (VACM denied the *read* because the configured user/group requires "priv" for this OID/view —
     see net-snmp's `rwuser NAME priv` syntax) — but BOTH outcomes prove the auth key itself was
     accepted by the device's USM layer. Only a Report-PDU carrying usmStatsWrongDigests or
     usmStatsUnknownUserNames is an unambiguous "this credential is wrong." This check treats any
     GetResponse-PDU as CONFIRMED regardless of its error-status, and only a wrong-credential
     Report (or no response) as NOT_APPLICABLE.

SECOND, SEPARATE CAPABILITY (added 2026-09-16, for the SIPROTEC 5 candidate's own documented
`initial`/noAuthNoPriv/read+write USM user — a genuinely different and more severe finding than a
weak-but-real passphrase): `noauth_usernames` tests whether the DEVICE ITSELF accepts a real
(non-empty) username with NO authentication and NO privacy at all — i.e. this specific username
requires no credential whatsoever, per its own USM security-level configuration. This reuses the
exact same noAuthNoPriv message shape `_build_message` already builds for engine discovery
(auth_key=None), just with a real username instead of the empty one discovery uses. A genuine
GetResponse-PDU proves the device's USM layer accepted the username with zero authentication; a
Report-PDU (typically usmStatsUnsupportedSecLevels, if the user is actually configured to require
auth, or usmStatsUnknownUserNames if the username doesn't exist) or no response proves it doesn't.
DELIBERATELY READ-ONLY even when the vendor documents write access for this user (as SIPROTEC 5
does for `initial`): this check only ever sends a GetRequest, never a SetRequest — proving
unauthenticated READ access is sufficient evidence for a default-credential finding, and actually
writing to a live device (a protection relay, in the SIPROTEC 5 case) to "prove" the documented
write capability would be a materially more destructive test than this project's other
credential checks perform, for no additional evidentiary value.

PROTOCOL FLOW (RFC 3414):
  1. Discovery: send one unauthenticated (noAuthNoPriv) GetRequest with an empty engineID. Any
     SNMPv3 agent replies with a Report-PDU whose msgAuthoritativeEngineID/EngineBoots/EngineTime
     (in the cleartext security parameters, NOT the Report's own payload) are the device's real
     values — this is required before an authenticated request is even possible, since the
     localized auth key is itself derived from the engineID.
  2. Password-to-key (RFC 3414 Appendix A.2): the passphrase is cyclically expanded to a virtual
     1,048,576-byte string and hashed (MD5 or SHA1) in 64-byte chunks -> Ku.
  3. Key localization (RFC 3414 §2.6): Kul = HASH(Ku + engineID + Ku) — the actual auth key used
     for HMAC, unique per (passphrase, engine).
  4. Build an authNoPriv GetRequest with a 12-byte zero placeholder in
     msgAuthenticationParameters, HMAC the WHOLE message with Kul, truncate to 12 bytes (RFC 3414
     §6.3.1/§7.3.1 — "HMAC-*-96"), splice the real digest back into the same byte range.
  5. usmStatsNotInTimeWindows is resynced once (the device's own Report echoes back the correct
     current engineBoots/engineTime specifically so the manager can retry) — everything else
     (usmStatsWrongDigests, usmStatsUnknownUserNames, or no response at all) is treated as this
     credential failing, matching the honest "SNMP silently drops"-style ambiguity this project's
     v1/v2c check already documents for its own no-response case.

DESTRUCTIVE: real authentication-attempt traffic (a real credential check), same as this
project's other default-creds checks.

BER encode/decode kept self-contained here (same "reusable native check owns its own wire logic"
convention as checks/snmp/native/snmp_community_default_creds.py) — a generic recursive
tag/length/value reader is used instead of that file's ad hoc positional parsing, since SNMPv3's
nested envelope (message -> securityParameters -> scopedPDU -> PDU -> varbind) is materially more
structured.

params schema:
  credentials:      list of {username, auth_protocol: "MD5"|"SHA", auth_key: <passphrase>} dicts,
                    tried in order — stops at first accepted. Deliberately no priv_protocol/
                    priv_key fields — see SCOPE above.
  noauth_usernames: list of plain username strings, tried BEFORE credentials (a noAuthNoPriv
                    accept is the more severe finding) — no passphrase, no hash algorithm, see
                    SECOND, SEPARATE CAPABILITY above. Optional; at least one of `credentials` /
                    `noauth_usernames` must be non-empty.
  timeout:          per-attempt UDP response timeout in seconds (default 3.0)
  default_port:     fallback port if the target inventory entry doesn't specify one (default 161)
"""

from __future__ import annotations

import hashlib
import hmac
import socket
from typing import Optional, Tuple

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_SYSDESCR_OID = (1, 3, 6, 1, 2, 1, 1, 1, 0)

_HASH_ALGOS = {"MD5": hashlib.md5, "SHA": hashlib.sha1}

_USM_STATS = {
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0): "usmStatsUnsupportedSecLevels",
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0): "usmStatsNotInTimeWindows",
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0): "usmStatsUnknownUserNames",
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0): "usmStatsUnknownEngineIDs",
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0): "usmStatsWrongDigests",
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0): "usmStatsDecryptionErrors",
}


# ---------------------------------------------------------------------------
# BER encode/decode helpers
# ---------------------------------------------------------------------------

def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    encoded = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _encode_int(n: int) -> bytes:
    """Full BER INTEGER TLV (tag 0x02), minimal two's-complement body."""
    if n == 0:
        body = b"\x00"
    else:
        length = 1
        while True:
            try:
                body = n.to_bytes(length, "big", signed=True)
                break
            except OverflowError:
                length += 1
    return _tlv(0x02, body)


def _encode_oid(oid: tuple) -> bytes:
    body = bytes([oid[0] * 40 + oid[1]])
    for n in oid[2:]:
        if n < 0x80:
            body += bytes([n])
        else:
            chunks = []
            while n:
                chunks.insert(0, n & 0x7F)
                n >>= 7
            body += bytes([c | 0x80 for c in chunks[:-1]] + [chunks[-1]])
    return _tlv(0x06, body)


def _decode_oid(body: bytes) -> tuple:
    if not body:
        return ()
    first = body[0]
    oid = [first // 40, first % 40]
    n = 0
    for b in body[1:]:
        n = (n << 7) | (b & 0x7F)
        if not (b & 0x80):
            oid.append(n)
            n = 0
    return tuple(oid)


def _read_tlv(data: bytes, pos: int) -> Tuple[int, bytes, int]:
    """Generic tag/length/value reader. Returns (tag, raw value bytes, offset past this TLV).
    Works for both primitive types (OCTET STRING, INTEGER) and constructed ones (SEQUENCE) —
    the caller re-parses the returned value bytes as its own buffer for constructed types."""
    tag = data[pos]
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        n_bytes = length & 0x7F
        length = int.from_bytes(data[pos : pos + n_bytes], "big")
        pos += n_bytes
    value = data[pos : pos + length]
    return tag, value, pos + length


# ---------------------------------------------------------------------------
# RFC 3414 key derivation
# ---------------------------------------------------------------------------

def _password_to_key(password: bytes, algo) -> bytes:
    """RFC 3414 Appendix A.2 password-to-key: the password is cycled to fill a virtual
    1,048,576-byte string, hashed incrementally in 64-byte chunks."""
    hasher = algo()
    password_len = len(password)
    if password_len == 0:
        return hasher.digest()
    count = 0
    idx = 0
    while count < 1_048_576:
        chunk = bytearray(64)
        for i in range(64):
            chunk[i] = password[idx % password_len]
            idx += 1
        hasher.update(bytes(chunk))
        count += 64
    return hasher.digest()


def _localize_key(ku: bytes, engine_id: bytes, algo) -> bytes:
    """RFC 3414 §2.6 key localization: Kul = HASH(Ku || engineID || Ku)."""
    hasher = algo()
    hasher.update(ku + engine_id + ku)
    return hasher.digest()


def _auth_key(passphrase: str, engine_id: bytes, protocol: str) -> bytes:
    algo = _HASH_ALGOS[protocol.upper()]
    ku = _password_to_key(passphrase.encode("utf-8"), algo)
    return _localize_key(ku, engine_id, algo)


def _compute_auth_digest(message: bytes, auth_key: bytes, algo) -> bytes:
    """RFC 3414 §6.3.1/§7.3.1 — HMAC-MD5-96 / HMAC-SHA-96: full HMAC digest truncated to the
    leftmost (most-significant) 12 bytes."""
    return hmac.new(auth_key, message, algo).digest()[:12]


# ---------------------------------------------------------------------------
# Message construction
# ---------------------------------------------------------------------------

def _build_message(
    msg_id: int,
    engine_id: bytes,
    engine_boots: int,
    engine_time: int,
    username: str,
    auth_key: Optional[bytes],
    algo,
    oid: tuple,
    pdu_request_id: int,
) -> bytes:
    """Builds a full SNMPv3 message. auth_key=None builds an unauthenticated (noAuthNoPriv)
    discovery GetRequest; otherwise builds an authNoPriv GetRequest with a real computed HMAC."""
    auth_flag = auth_key is not None
    flags = 0x04 | (0x01 if auth_flag else 0x00)  # reportableFlag always set

    header_seq = _tlv(
        0x30,
        _encode_int(msg_id) + _encode_int(65507) + _tlv(0x04, bytes([flags])) + _encode_int(3),
    )

    auth_placeholder = b"\x00" * 12 if auth_flag else b""
    sec_part1 = (
        _tlv(0x04, engine_id)
        + _encode_int(engine_boots)
        + _encode_int(engine_time)
        + _tlv(0x04, username.encode("utf-8"))
    )
    auth_tlv_header = bytes([0x04]) + _ber_len(len(auth_placeholder))
    offset_in_sec_inner = len(sec_part1) + len(auth_tlv_header)
    sec_params_inner = sec_part1 + auth_tlv_header + auth_placeholder + _tlv(0x04, b"")

    sec_params_seq = _tlv(0x30, sec_params_inner)
    offset_in_sec_seq = (len(sec_params_seq) - len(sec_params_inner)) + offset_in_sec_inner

    sec_params_octetstring = _tlv(0x04, sec_params_seq)
    offset_in_sec_os = (len(sec_params_octetstring) - len(sec_params_seq)) + offset_in_sec_seq

    null_val = _tlv(0x05, b"")
    varbind = _tlv(0x30, _encode_oid(oid) + null_val)
    varbind_list = _tlv(0x30, varbind)
    get_pdu = _tlv(0xA0, _encode_int(pdu_request_id) + _encode_int(0) + _encode_int(0) + varbind_list)
    scoped_pdu = _tlv(0x30, _tlv(0x04, engine_id) + _tlv(0x04, b"") + get_pdu)

    message_body = _encode_int(3) + header_seq + sec_params_octetstring + scoped_pdu
    offset_in_body = len(_encode_int(3)) + len(header_seq) + offset_in_sec_os

    message = _tlv(0x30, message_body)
    outer_header_len = len(message) - len(message_body)
    auth_offset = outer_header_len + offset_in_body

    if auth_flag:
        assert message[auth_offset : auth_offset + 12] == auth_placeholder
        digest = _compute_auth_digest(message, auth_key, algo)
        message = message[:auth_offset] + digest + message[auth_offset + 12 :]

    return message


def _parse_message(data: bytes) -> Optional[dict]:
    """Parses engineID/boots/time (always cleartext, even in a Report) and, when the scopedPDU
    isn't encrypted (always true here — we never request privacy), the PDU type/error-status/
    first varbind OID. Returns None on any malformed input."""
    try:
        _, msg_val, _ = _read_tlv(data, 0)
        pos = 0
        _, _, pos = _read_tlv(msg_val, pos)  # msgVersion
        _, _, pos = _read_tlv(msg_val, pos)  # headerData (unused further)
        _, sec_os_val, pos = _read_tlv(msg_val, pos)  # msgSecurityParameters OCTET STRING
        data_tag, data_val, pos = _read_tlv(msg_val, pos)  # msgData

        _, sec_seq_val, _ = _read_tlv(sec_os_val, 0)
        spos = 0
        _, engine_id, spos = _read_tlv(sec_seq_val, spos)
        _, eboots_val, spos = _read_tlv(sec_seq_val, spos)
        _, etime_val, spos = _read_tlv(sec_seq_val, spos)
        engine_boots = int.from_bytes(eboots_val, "big", signed=True) if eboots_val else 0
        engine_time = int.from_bytes(etime_val, "big", signed=True) if etime_val else 0

        result = {
            "engine_id": engine_id,
            "engine_boots": engine_boots,
            "engine_time": engine_time,
            "pdu_tag": None,
            "first_oid": None,
        }

        if data_tag == 0x30:  # scopedPDU in the clear (no privacy) — always true for us
            dpos = 0
            _, _, dpos = _read_tlv(data_val, dpos)  # contextEngineID
            _, _, dpos = _read_tlv(data_val, dpos)  # contextName
            pdu_tag, pdu_val, _ = _read_tlv(data_val, dpos)
            result["pdu_tag"] = pdu_tag

            ppos = 0
            _, _, ppos = _read_tlv(pdu_val, ppos)  # request-id
            _, errstat_val, ppos = _read_tlv(pdu_val, ppos)
            _, _, ppos = _read_tlv(pdu_val, ppos)  # error-index
            _, vbl_val, _ = _read_tlv(pdu_val, ppos)
            result["error_status"] = int.from_bytes(errstat_val, "big", signed=True) if errstat_val else 0

            if vbl_val:
                _, vb_val, _ = _read_tlv(vbl_val, 0)
                _, oid_val, vpos = _read_tlv(vb_val, 0)
                result["first_oid"] = _decode_oid(oid_val)
                value_tag, value_val, _ = _read_tlv(vb_val, vpos)
                if value_tag == 0x04:
                    result["value_str"] = value_val.decode("ascii", errors="replace").strip()

        return result
    except (IndexError, ValueError):
        return None


def _send(host: str, port: int, payload: bytes, timeout: float) -> Optional[bytes]:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(payload, (host, port))
        try:
            data, _ = sock.recvfrom(4096)
        except OSError:
            return None
        return data
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _discover(host: str, port: int, timeout: float) -> Optional[Tuple[bytes, int, int]]:
    payload = _build_message(0x1001, b"", 0, 0, "", None, None, _SYSDESCR_OID, 0x2001)
    resp = _send(host, port, payload, timeout)
    if resp is None:
        return None
    parsed = _parse_message(resp)
    if parsed is None:
        return None
    return parsed["engine_id"], parsed["engine_boots"], parsed["engine_time"]


def _try_credential(
    host: str,
    port: int,
    timeout: float,
    engine_id: bytes,
    engine_boots: int,
    engine_time: int,
    username: str,
    passphrase: str,
    protocol: str,
) -> Tuple[bool, Optional[str]]:
    algo = _HASH_ALGOS[protocol.upper()]
    auth_key = _auth_key(passphrase, engine_id, protocol)

    for attempt in range(2):  # one resync retry on a stale time window
        payload = _build_message(0x1002, engine_id, engine_boots, engine_time, username, auth_key, algo, _SYSDESCR_OID, 0x2002)
        resp = _send(host, port, payload, timeout)
        if resp is None:
            return False, None
        parsed = _parse_message(resp)
        if parsed is None:
            return False, None

        if parsed["pdu_tag"] == 0xA2:
            # A real GetResponse-PDU — proves the auth key was accepted by USM, regardless of
            # error-status (an authorizationError here means VACM denied the read, not that the
            # credential was wrong).
            return True, parsed.get("value_str")

        if parsed["pdu_tag"] == 0xA8:
            stat_name = _USM_STATS.get(parsed.get("first_oid"))
            if stat_name == "usmStatsNotInTimeWindows" and attempt == 0:
                engine_boots = parsed["engine_boots"]
                engine_time = parsed["engine_time"]
                continue
            return False, None  # usmStatsWrongDigests / usmStatsUnknownUserNames / anything else

        return False, None

    return False, None


def _try_noauth_username(
    host: str,
    port: int,
    timeout: float,
    engine_id: bytes,
    engine_boots: int,
    engine_time: int,
    username: str,
) -> Tuple[bool, Optional[str]]:
    """Tests whether `username` is accepted with NO authentication and NO privacy at all — the
    same noAuthNoPriv message shape _discover() uses (auth_key=None), but with a real username
    instead of the empty one discovery sends. A genuine GetResponse-PDU (0xA2) proves the device's
    USM layer accepted this username with zero credential presented — a real, more severe finding
    than a weak-but-real passphrase, since it means no credential exists to guess in the first
    place. A Report-PDU (usmStatsUnsupportedSecLevels if the user requires auth,
    usmStatsUnknownUserNames if it doesn't exist) or no response means this username isn't a
    usable noAuthNoPriv account."""
    payload = _build_message(0x1003, engine_id, engine_boots, engine_time, username, None, None, _SYSDESCR_OID, 0x2003)
    resp = _send(host, port, payload, timeout)
    if resp is None:
        return False, None
    parsed = _parse_message(resp)
    if parsed is None:
        return False, None
    if parsed["pdu_tag"] == 0xA2:
        return True, parsed.get("value_str")
    return False, None


class Snmpv3DefaultCredsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        credentials = params.get("credentials", [])
        noauth_usernames = params.get("noauth_usernames", [])
        timeout = params.get("timeout", 3.0)
        port = target.port or params.get("default_port", 161)

        if not credentials and not noauth_usernames:
            return self._result(target, CheckStatus.ERROR, description="check has no credentials or noauth_usernames configured in params")

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)
        discovered = _discover(target.host, port, timeout)
        if discovered is None:
            return self._result(
                target,
                CheckStatus.NOT_APPLICABLE,
                description="no SNMPv3 engine discovery response (device unreachable, SNMP disabled/firewalled, or not running SNMPv3)",
            )
        engine_id, engine_boots, engine_time = discovered

        for username in noauth_usernames:
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            ok, sysdescr = _try_noauth_username(target.host, port, timeout, engine_id, engine_boots, engine_time, username)
            if ok:
                detail = f", sysDescr: {sysdescr!r}" if sysdescr else " (VACM denied the read itself, but the username required no credential at all)"
                return self._result(
                    target,
                    CheckStatus.CONFIRMED,
                    description=f"SNMPv3 USM username={username!r} accepted with NO authentication and NO privacy at all{detail}",
                )

        for cred in credentials:
            username = cred["username"]
            protocol = cred.get("auth_protocol", "MD5").upper()
            passphrase = cred["auth_key"]
            if protocol not in _HASH_ALGOS:
                continue
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            ok, sysdescr = _try_credential(target.host, port, timeout, engine_id, engine_boots, engine_time, username, passphrase, protocol)
            if ok:
                detail = f", sysDescr: {sysdescr!r}" if sysdescr else " (VACM denied the read itself, but the credential authenticated)"
                return self._result(
                    target,
                    CheckStatus.CONFIRMED,
                    description=f"SNMPv3 USM credential username={username!r} auth={protocol} accepted{detail}",
                )

        return self._result(
            target,
            CheckStatus.NOT_APPLICABLE,
            description=(
                f"none of {len(noauth_usernames)} tested noauth username(s) and {len(credentials)} "
                "tested SNMPv3 credential(s) were accepted. Each attempt got either an explicit "
                "usmStats*/Report-PDU rejection or no response — this does not distinguish 'all "
                "tested credentials rejected' from 'device unreachable mid-sweep', matching this "
                "project's v1/v2c SNMP check's own documented ambiguity."
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


CHECK_CLASS = Snmpv3DefaultCredsCheck
