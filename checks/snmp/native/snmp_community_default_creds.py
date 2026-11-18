"""Generic native check — SNMP v1/v2c default community-string test.

SNMP has no username:password pair — v1/v2c authentication is a single "community string"
(classic defaults: "public", read-only, and "private", read-write and more severe since it
allows SET as well as GET). params below therefore takes a flat list of strings, not the
[username, password] pairs the FTP/HTTP/Telnet default-creds checks use.

Reusable across vendors: SNMP has no single hardware-vendor tie (used by hundreds of ICS/OT
vendors' gear), which is why this check's fingerprint_precondition narrows on the protocol
itself (protocol_probe: snmp_identity) rather than a vendor/product pair — same reasoning as
s7comm's snap7-count-max-crash check (see checks/s7comm/snap7-count-max-crash.yaml).

DESTRUCTIVE: real authentication-attempt traffic against the device, same as the other
default-creds checks.

IMPORTANT ambiguity, documented rather than hidden: SNMP silently DROPS a GetRequest carrying a
wrong community string instead of returning an explicit rejection (unlike FTP/SSH/Telnet, which
all reply with an unambiguous auth-failure). That means a timeout here is indistinguishable from
"wrong community," "device unreachable," or "SNMP disabled/firewalled" — this check can prove a
default community string IS accepted (an unambiguous positive: a well-formed GetResponse-PDU
came back), but it can never prove one is NOT accepted with the same confidence an FTP/SSH
rejection gives. NOT_APPLICABLE here means "no response to any tested community," not "all
tested communities were confirmed rejected."

BER encode/decode kept self-contained here (not imported from core/fingerprint.py's private
`_snmp_*` helpers) — same "reusable native check owns its own wire logic" convention as
checks/ftp/native/ftp_default_creds.py using stdlib ftplib rather than reaching into core/.

params schema:
  communities:   list of community strings, tried in order — stops at first accepted (default
                 ["public", "private"] if not supplied)
  timeout:       per-attempt UDP response timeout in seconds (default 3.0)
  default_port:  fallback port if the target doesn't specify one (default 161)
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_SYSDESCR_OID = (1, 3, 6, 1, 2, 1, 1, 1, 0)


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    encoded = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


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


def _get_request(oid: tuple, community: bytes, request_id: int) -> bytes:
    null_val = _tlv(0x05, b"")
    varbind = _tlv(0x30, _encode_oid(oid) + null_val)
    varbind_list = _tlv(0x30, varbind)
    pdu_body = (
        _tlv(0x02, struct.pack(">i", request_id))
        + _tlv(0x02, b"\x00")
        + _tlv(0x02, b"\x00")
        + varbind_list
    )
    pdu = _tlv(0xA0, pdu_body)
    message = _tlv(0x02, b"\x00") + _tlv(0x04, community) + pdu
    return _tlv(0x30, message)


def _parse_ber_len(data: bytes, pos: int):
    length = data[pos]
    pos += 1
    if length & 0x80:
        n_bytes = length & 0x7F
        length = int.from_bytes(data[pos : pos + n_bytes], "big")
        pos += n_bytes
    return length, pos


def _parse_response(data: bytes, expected_request_id: int) -> Optional[str]:
    """Returns the sysDescr string on a well-formed, request-id-matching GetResponse-PDU, else
    None. A non-None return is the unambiguous "this community string was accepted" signal."""
    try:
        pos = 0
        if data[pos] != 0x30:
            return None
        _, pos = _parse_ber_len(data, pos + 1)
        if data[pos] != 0x02:
            return None
        _, pos = _parse_ber_len(data, pos + 1)
        pos += 1
        if data[pos] != 0x04:
            return None
        clen, pos = _parse_ber_len(data, pos + 1)
        pos += clen
        if data[pos] not in (0xA2, 0xA0):
            return None
        _, pos = _parse_ber_len(data, pos + 1)
        if data[pos] != 0x02:
            return None
        idlen, pos = _parse_ber_len(data, pos + 1)
        resp_id = int.from_bytes(data[pos : pos + idlen], "big", signed=True)
        pos += idlen
        if resp_id != expected_request_id:
            return None
        for _ in range(2):
            if data[pos] != 0x02:
                return None
            elen, pos = _parse_ber_len(data, pos + 1)
            pos += elen
        if data[pos] != 0x30:
            return None
        _, pos = _parse_ber_len(data, pos + 1)
        if data[pos] != 0x30:
            return None
        _, pos = _parse_ber_len(data, pos + 1)
        if data[pos] != 0x06:
            return None
        oidlen, pos = _parse_ber_len(data, pos + 1)
        pos += oidlen
        value_tag = data[pos]
        vlen, pos = _parse_ber_len(data, pos + 1)
        if value_tag != 0x04:
            return None
        return data[pos : pos + vlen].decode("ascii", errors="replace").strip()
    except (IndexError, ValueError):
        return None


class SnmpCommunityDefaultCredsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        communities = params.get("communities", ["public", "private"])
        timeout = params.get("timeout", 3.0)
        port = target.port or params.get("default_port", 161)

        if not communities:
            return self._result(target, CheckStatus.ERROR, description="check has no community strings configured in params")

        for community in communities:
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            sysdescr = self._try_one(target.host, port, community, timeout)
            if sysdescr is not None:
                return self._result(
                    target,
                    CheckStatus.CONFIRMED,
                    description=(
                        f"default SNMP community string '{community}' accepted "
                        f"(sysDescr: {sysdescr!r})"
                    ),
                )

        return self._result(
            target,
            CheckStatus.NOT_APPLICABLE,
            description=(
                f"none of {len(communities)} tested default community string(s) got a response. "
                "Note: SNMP silently drops requests with a wrong community string rather than "
                "rejecting them, so this does not distinguish 'all tested communities rejected' "
                "from 'device unreachable' or 'SNMP disabled/firewalled' — a weaker negative "
                "than this project's other default-creds checks."
            ),
        )

    def _try_one(self, host: str, port: int, community: str, timeout: float) -> Optional[str]:
        request_id = 0x1C15
        payload = _get_request(_SYSDESCR_OID, community.encode("ascii", errors="ignore"), request_id)
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(payload, (host, port))
            try:
                data, _ = sock.recvfrom(2048)
            except OSError:
                return None
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        return _parse_response(data, request_id)

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


CHECK_CLASS = SnmpCommunityDefaultCredsCheck
