"""Generic native check — SNMP v1/v2c readable-password OID exposure test. Distinct from
checks/snmp/native/snmp_community_default_creds.py: that module tests whether a device accepts
a GUESSED community string at all (via the universal sysDescr OID, present on every SNMP agent).
This module assumes the community string is already known (or itself default/guessable — pass
the same community list) and GETs a SPECIFIC, VENDOR-DOCUMENTED OID that a device's own MIB
declares as a read-write DisplayString password field — i.e. the vendor's own MIB says this OID
can be read back, not just set, over plain SNMP GET with no further authentication.

Built 2026-09-23 for Phoenix Contact mGuard's own MGUARDB-MIB.txt, which defines
mGuardRootPassword (ROOT_PASSWORD, OID 1.3.6.1.4.1.15450.2.4.1.1) and mGuardAdminPassword
(WWW_PASSWORD, OID 1.3.6.1.4.1.15450.2.4.1.2) as `SYNTAX DisplayString ACCESS read-write` — the
same shape already seen in this project's checks/candidates/
avocent-pm-pdu-snmp-readable-admin-password-default-community.yaml finding (a read-write
DisplayString password OID in a vendor's own official MIB), which explicitly anticipated this
exact reusable executor being built later ("This project has an SNMP community-string executor
already... that could be extended to probe this exact OID"). Built as a genuinely reusable
capability, not a one-off: any vendor whose MIB declares a password field the same way needs the
identical shape.

Reusable across vendors: OIDs, labels, and community strings all come from CheckMetadata.params,
not per-vendor Python — same convention as every other *_default_creds.py executor in this
project. BER encode/decode logic is a direct reuse of the exact functions already validated in
snmp_community_default_creds.py's own docstring ("verified by executing the module's own
_get_request() BER encoder directly") — not reimplemented from scratch, to avoid re-introducing
a subtle ASN.1/BER encoding bug in a second place.

DESTRUCTIVE: real SNMP traffic naming a specific device password OID, same reasoning as every
other default-creds check here — a lower bar than an authentication ATTEMPT (no credential is
submitted, GET is a read operation only, no SET is ever sent), but real, identifiable traffic
against a security-relevant object, gated the same way.

IMPORTANT AMBIGUITY, same shape already documented in snmp_community_default_creds.py: SNMP
silently drops a GetRequest carrying a wrong community string, so NOT_APPLICABLE here means "no
readable value came back for any tested OID/community combination" — it does not distinguish a
genuinely non-exposing device from an unreachable one, a firewalled one, or one where the SNMP
AGENT enforces additional view-based access control beyond what the MIB's own ACCESS clause
declares (a real, common possibility this project doesn't assume away: `ACCESS read-write` in a
MIB is necessary but not sufficient proof a live agent actually returns a real value on GET).
CONFIRMED here means a well-formed GetResponse-PDU carrying SOME value (including an empty
string) came back for a targeted OID — that alone proves the OID is remotely GET-able with only
a community string, which is the exposure itself; the actual returned value (possibly empty, if
no password is currently configured on that specific device) is included in the description for
a human to judge real-world severity, not silently suppressed.

params schema:
  oids:          list of [dotted-decimal OID string, label] pairs, tried in order per community
                 — e.g. [["1.3.6.1.4.1.15450.2.4.1.1", "ROOT_PASSWORD"]]. Stops at the first
                 OID+community combination that returns a well-formed value.
  communities:   list of community strings, tried in order per OID (default ["public"] — a
                 read-community guess; include "private" too if a vendor's own tooling defaults
                 to it, as several already-confirmed findings in this project do).
  timeout:       per-attempt UDP response timeout in seconds (default 3.0)
  default_port:  fallback port if the target doesn't specify one (default 161)
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target


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


def _parse_oid_string(dotted: str) -> tuple:
    return tuple(int(p) for p in dotted.strip(".").split("."))


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
    """Returns the returned varbind's OCTET STRING value on a well-formed, request-id-matching
    GetResponse-PDU (including an empty string), else None. A non-None return is the
    unambiguous "this OID answered under this community" signal — see this module's own
    docstring on why an empty string still counts."""
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
        return data[pos : pos + vlen].decode("ascii", errors="replace")
    except (IndexError, ValueError):
        return None


class SnmpOidPasswordExposureCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        oids = params.get("oids", [])
        communities = params.get("communities", ["public"])
        timeout = params.get("timeout", 3.0)
        port = target.port or params.get("default_port", 161)

        if not oids:
            return self._result(target, CheckStatus.ERROR, description="check has no oids configured in params")
        if not communities:
            return self._result(target, CheckStatus.ERROR, description="check has no community strings configured in params")

        for oid_str, label in oids:
            for community in communities:
                if rate_limiter is not None:
                    rate_limiter.acquire(target.host)
                value = self._try_one(target.host, port, oid_str, community, timeout)
                if value is not None:
                    shown = value if value else "<empty>"
                    return self._result(
                        target,
                        CheckStatus.CONFIRMED,
                        description=(
                            f"OID {oid_str} ({label}) answered a GET under community "
                            f"'{community}' with value {shown!r} — remotely readable with no "
                            f"authentication beyond the community string"
                        ),
                    )

        return self._result(
            target,
            CheckStatus.NOT_APPLICABLE,
            description=(
                f"none of {len(oids)} OID(s) across {len(communities)} community string(s) "
                "returned a value. Note: SNMP silently drops requests with a wrong community "
                "string rather than rejecting them, so this does not distinguish 'genuinely not "
                "exposed' from 'device unreachable', 'SNMP disabled/firewalled', or an agent-side "
                "access-control restriction beyond the MIB's own declared ACCESS clause — a "
                "weaker negative than this project's other default-creds checks."
            ),
        )

    def _try_one(self, host: str, port: int, oid_str: str, community: str, timeout: float) -> Optional[str]:
        request_id = 0x1C16
        oid = _parse_oid_string(oid_str)
        payload = _get_request(oid, community.encode("ascii", errors="ignore"), request_id)
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


CHECK_CLASS = SnmpOidPasswordExposureCheck
