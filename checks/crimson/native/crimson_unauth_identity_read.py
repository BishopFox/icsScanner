"""Native check — CVE-2020-27285 Red Lion Controls Crimson (build < 3119.001): the device's
configuration database can be read AND modified with no authentication of any kind (CWE-306,
Missing Authentication for Critical Function). This check demonstrates the same missing-
authentication root cause via the SAFEST available operation — an unauthenticated manufacturer/
model identity query — rather than attempting a full database content read, the same safe-proxy
design already used by checks/profinet/native/profinet_dcp_signal_unauthenticated.py (exercise
the vulnerable code path with a read-only, informational request instead of the advisory's own
cited stronger example of reading/writing the live tag/configuration database).

Wire format confirmed directly from TWO independent, named, source-available community tools
(top of this project's sourcing hierarchy for a proprietary protocol with no vendor-published
spec): the Crimson v3 Wireshark dissector (github.com/internetofallthethings/cr3-wireshark/
cr3.lua) and a working nmap NSE fingerprint script for the same protocol
(github.com/weaponize/redlion/cr3-nmap/cr3-fingerprint.nse) — both agree on the same 6-byte
request format and register numbers, and the NSE script is a functioning nmap probe, not merely
a passive dissector guess.

Request format (both sources agree, no payload beyond the header): [length:u16 BE]
[register:u16 BE][packet_type:u16 BE], length=4 (covers only the register+packet_type fields,
per the dissector's own `pktlen == cr3len + 2` framing check). Two registers demonstrate the
same no-auth-required behavior:
  - register 0x012B, packet_type 0x1B00 -> manufacturer identity query
  - register 0x012A, packet_type 0x1A00 -> model identity query
A device that answers with packet_type 0x0300 and a non-empty string payload has processed a
Crimson protocol request without any authentication step ever occurring in the exchange —
demonstrating CVE-2020-27285's core finding via the least invasive read available.

NOT implemented: the database-length query (register 0x022A/0x022B) and the chunked-read path
(packet_type 0x1500, via a 0x1B00 READ_LENGTH request carrying an offset/length payload) that
would retrieve actual tag/configuration data. The community dissector's own comments flag real
ambiguity in that path ("sometimes the device will only report 4 bytes", several unlabeled
packet types) that this project's no-guessed-protocol-detail discipline isn't comfortable
shipping without validation against real hardware. The identity-query path alone is sufficient
to demonstrate the vulnerability class.

DESTRUCTIVE for the same reason profinet_dcp_signal_unauthenticated.py is: real protocol traffic
against the device, even though this specific operation is read-only and has no lasting effect.

CVSS discrepancy, documented rather than silently picking one: CISA's own published vector for
this advisory is CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N = 6.5 (cited as `severity` in this
check's YAML, per this project's "never re-scored, copied from upstream" convention). NVD's own
independent recalculation of the SAME CVE instead scores C:H/I:H = 9.1, arguing the "database"
in question is the device's full control-logic/tag store, not a narrow field. Both numbers are
real and both are cited in lab-notes/default-credentials-sweep.md's Phase 41 entry.

params schema:
  timeout:       per-connection response timeout in seconds (default 3.0)
  default_port:  fallback port if the target doesn't specify one (default 789)
"""

from __future__ import annotations

import socket
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_MANUFACTURER_QUERY = bytes([0x00, 0x04, 0x01, 0x2B, 0x1B, 0x00])
_MODEL_QUERY = bytes([0x00, 0x04, 0x01, 0x2A, 0x1A, 0x00])


def _query(host: str, port: int, request: bytes, timeout: float) -> Optional[bytes]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(request)
            sock.settimeout(timeout)
            return sock.recv(1024)
    except OSError:
        return None


def _decode_identity(resp: Optional[bytes]) -> Optional[str]:
    # Response shape (both source tools agree): [len:2][reg:2][packet_type=0x0300:2][string...]
    if not resp or len(resp) <= 6:
        return None
    if resp[4:6] != b"\x03\x00":
        return None
    text = resp[6:].split(b"\x00", 1)[0].decode("latin-1", errors="replace").strip()
    return text or None


class CrimsonUnauthIdentityReadCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        timeout = params.get("timeout", 3.0)
        port = target.port or params.get("default_port", 789)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)
        manufacturer = _decode_identity(_query(target.host, port, _MANUFACTURER_QUERY, timeout))

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)
        model = _decode_identity(_query(target.host, port, _MODEL_QUERY, timeout))

        if manufacturer or model:
            return self._result(
                target,
                CheckStatus.CONFIRMED,
                description=(
                    f"Crimson protocol (TCP:{port}) answered an identity query with no "
                    f"authentication challenge at any point in the exchange "
                    f"(manufacturer={manufacturer!r}, model={model!r}) — demonstrates "
                    f"CVE-2020-27285's missing-authentication root cause; build <3119.001 "
                    f"reads/writes the full configuration database the same way"
                ),
            )
        return self._result(
            target,
            CheckStatus.NOT_APPLICABLE,
            description=f"no valid Crimson protocol identity response received on TCP:{port}",
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


CHECK_CLASS = CrimsonUnauthIdentityReadCheck
