"""Generic native check — Telnet default-credential test. Hand-rolled raw-socket telnet client
(minimal IAC option negotiation: politely declines every negotiated option to reach plain-text
mode) rather than depending on the stdlib `telnetlib` module — confirmed 2026-08-14 that
`telnetlib` is deprecated as of Python 3.11 and REMOVED in 3.13; still importable on this
project's Python 3.12 today, but building new code on a module already scheduled for removal is
a bad bet for a tool meant to keep working.

Reusable across vendors: credential list and prompt/success/failure text all come from
CheckMetadata.params, not per-vendor Python.

DESTRUCTIVE: same reasoning as the HTTP/SSH variants — real authentication-attempt traffic,
lockout risk on devices that implement one.

Classification is inherently less precise than HTTP (status code) or SSH (clean auth exception)
— telnet has no universal machine-readable success/failure signal, only banner text that varies
per device. A check built on this executor should default to confidence=low unless a specific
device's exact post-login banner has been verified against real hardware.

KNOWN LIMITATION: the IAC negotiation parser processes one recv() chunk at a time and does not
handle an IAC command sequence split across two TCP segments — acceptable for the common case
(embedded devices typically send their option negotiation in one burst at connect time, small
enough to fit in one segment) but a real edge case a more careful state-machine parser would
close. Not built now — flag if a real device ever hits it.

params schema:
  credentials:         list of [username, password] pairs, tried in order. For password_only
                        devices, username is ignored (conventionally "" in the YAML) — only
                        password is sent.
  password_only:       bool, default false. Set true for classic Cisco-IOS-lineage devices (and
                        similar) configured with a line-password login (no username prompt at
                        all, straight to "Password:") — added 2026-08-14 for Stratix switches
                        (Rockwell-branded, Cisco IOS under license), a real gap found while
                        building that check: the original two-prompt-only design would have
                        timed out waiting for a username prompt that never arrives.
  pre_command:          optional string, sent verbatim (+ "\r\n") immediately after connecting,
                        BEFORE waiting for any prompt — added 2026-08-18 for SEL protection
                        relays, a real gap found building that check: SEL's ASCII terminal
                        protocol requires typing an access-level command (e.g. "ACC") before the
                        device even shows a password prompt at all, unlike password_only devices
                        which prompt immediately on connect. Implies password_only (there is no
                        separate username exchange in this mode either — only pre_command, then
                        password).
  chains:               optional list of multi-step login chains — added 2026-08-29 for SEL
                        relays' Access Level 2, a real gap this executor couldn't express before:
                        reaching Level 2 requires TWO command+password exchanges in the same
                        session ("ACC"+"OTTER" to reach Level 1, THEN "2AC"+"TAIL" to reach Level
                        2 FROM Level 1), not a single pre_command+password pair. Each chain is a
                        list of [command, password] steps: for each step, `command` is sent
                        verbatim (+ "\r\n"), the executor waits for password_prompt, then
                        `password` is sent verbatim (+ "\r\n") — repeated for every step in the
                        chain, in the same connection, before the final response is drained and
                        checked against failure_indicators/success_indicators exactly like a
                        single-step attempt. `chains` is a list of chains (like `credentials` is
                        a list of pairs) so more than one full chain can be tried per target if a
                        device's escalation sequence is ever ambiguous — for SEL's case there is
                        exactly one confirmed chain, sourced byte-for-byte from SEL-351's own
                        manual and cross-confirmed across 8 independently-sourced SEL models.
                        Mutually exclusive with `credentials`/`pre_command` in practice — a check
                        should configure one shape or the other, not mix them; at least one of
                        `credentials` or `chains` must be present.
  username_prompt:     substring, case-insensitive (default "login:"), ignored if password_only
  password_prompt:     substring, case-insensitive (default "password:")
  failure_indicators:  list of substrings, case-insensitive (default: incorrect/failed/denied/invalid)
  success_indicators:  optional list of substrings that confirm success beyond "no failure
                        indicator seen" — if omitted, absence of any failure_indicator after a
                        password attempt is treated as success (a weaker signal, still useful)
  timeout:              per-read timeout in seconds (default 5.0)
  default_port:         fallback port if the target doesn't specify one (default 23)
"""

from __future__ import annotations

import socket
import time
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_IAC, _DONT, _DO, _WONT, _WILL, _SB, _SE = 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF0

_DEFAULT_FAILURE_INDICATORS = ["incorrect", "failed", "denied", "invalid"]


def _read_until(sock: socket.socket, until_substr: str, timeout: float, max_bytes: int = 8192) -> str:
    """Reads from sock, transparently answering IAC option-negotiation requests (decline
    everything -> plain text), until until_substr (case-insensitive) appears or time/size runs
    out. Returns the plain-text (negotiation bytes stripped) accumulated so far either way —
    INCLUDING on a connection reset/abrupt close mid-read (found via testing, not theoretical: a
    device that resets the connection shortly after showing its post-login banner must not lose
    whatever text it already sent — the alternative is a false negative on a real hit)."""
    sock.settimeout(timeout)
    buf = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and len(buf) < max_bytes:
        try:
            chunk = sock.recv(1024)
        except socket.timeout:
            break
        except OSError:
            break  # connection reset/abrupt close — keep whatever was already read, don't discard it
        if not chunk:
            break
        i = 0
        while i < len(chunk):
            b = chunk[i]
            if b == _IAC and i + 1 < len(chunk):
                cmd = chunk[i + 1]
                if cmd in (_WILL, _WONT, _DO, _DONT) and i + 2 < len(chunk):
                    opt = chunk[i + 2]
                    if cmd == _DO:
                        sock.sendall(bytes([_IAC, _WONT, opt]))
                    elif cmd == _WILL:
                        sock.sendall(bytes([_IAC, _DONT, opt]))
                    i += 3
                    continue
                if cmd == _SB:
                    j = i + 2
                    while j < len(chunk) - 1 and not (chunk[j] == _IAC and chunk[j + 1] == _SE):
                        j += 1
                    i = j + 2
                    continue
                i += 2
                continue
            buf.append(b)
            i += 1
        text = buf.decode("latin-1", errors="replace")
        if until_substr.lower() in text.lower():
            return text
    return buf.decode("latin-1", errors="replace")


class TelnetDefaultCredsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        params = self.metadata.params or {}
        credentials = params.get("credentials", [])
        chains = params.get("chains", [])
        password_only = params.get("password_only", False)
        username_prompt = params.get("username_prompt", "login:")
        password_prompt = params.get("password_prompt", "password:")
        failure_indicators = params.get("failure_indicators", _DEFAULT_FAILURE_INDICATORS)
        success_indicators = params.get("success_indicators")
        timeout = params.get("timeout", 5.0)
        port = target.port or params.get("default_port", 23)
        pre_command = params.get("pre_command")

        if not credentials and not chains:
            return self._result(target, CheckStatus.ERROR, description="check has no credentials or chains configured in params")

        for username, password in credentials:
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            outcome = self._try_one(
                target.host, port, username, password, username_prompt, password_prompt,
                failure_indicators, success_indicators, timeout, password_only, pre_command,
            )
            if outcome == "auth_ok":
                return self._result(
                    target,
                    CheckStatus.CONFIRMED,
                    description=f"default credential '{username}:{password}' accepted via Telnet",
                )

        for chain in chains:
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            outcome = self._try_chain(
                target.host, port, chain, password_prompt, failure_indicators,
                success_indicators, timeout,
            )
            if outcome == "auth_ok":
                steps = " -> ".join(f"{cmd}:{pw}" for cmd, pw in chain)
                return self._result(
                    target,
                    CheckStatus.CONFIRMED,
                    description=f"default credential chain '{steps}' accepted via Telnet",
                )

        attempted = len(credentials) + len(chains)
        return self._result(
            target,
            CheckStatus.NOT_APPLICABLE,
            description=f"none of {attempted} tested default credential(s)/chain(s) were accepted via Telnet",
        )

    def _try_one(
        self, host, port, username, password, username_prompt, password_prompt,
        failure_indicators, success_indicators, timeout, password_only=False, pre_command=None,
    ) -> str:
        sock: Optional[socket.socket] = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            if pre_command is not None:
                sock.sendall((pre_command + "\r\n").encode("latin-1"))
            elif not password_only:
                _read_until(sock, username_prompt, timeout)
                sock.sendall((username + "\r\n").encode("latin-1"))

            _read_until(sock, password_prompt, timeout)
            sock.sendall((password + "\r\n").encode("latin-1"))

            response = _read_until(sock, "\x00", timeout)  # no real sentinel — just drain what comes back
            response_lower = response.lower()

            if any(f.lower() in response_lower for f in failure_indicators):
                return "auth_failed"
            if success_indicators:
                return "auth_ok" if any(s.lower() in response_lower for s in success_indicators) else "auth_failed"
            return "auth_ok"  # no failure indicator seen, no success_indicators configured — weaker signal, still a real one
        except OSError:
            return "conn_error"
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def _try_chain(
        self, host, port, chain, password_prompt, failure_indicators, success_indicators, timeout,
    ) -> str:
        """One multi-step [command, password] chain in a single connection — e.g. SEL's
        ACC/OTTER (Level 1) then 2AC/TAIL (Level 2). Every step is command-then-password
        (password_only semantics throughout, no username exchange at any step); only the FINAL
        response (after the last step's password) is checked against failure_indicators/
        success_indicators — an intermediate step failing quietly still lets the chain run to
        completion rather than trying to detect per-step success, since this project's devices
        have no universal machine-readable per-step signal (same reasoning _try_one already
        documents for the single-step case)."""
        sock: Optional[socket.socket] = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            for command, password in chain:
                sock.sendall((command + "\r\n").encode("latin-1"))
                _read_until(sock, password_prompt, timeout)
                sock.sendall((password + "\r\n").encode("latin-1"))

            response = _read_until(sock, "\x00", timeout)  # no real sentinel — just drain what comes back
            response_lower = response.lower()

            if any(f.lower() in response_lower for f in failure_indicators):
                return "auth_failed"
            if success_indicators:
                return "auth_ok" if any(s.lower() in response_lower for s in success_indicators) else "auth_failed"
            return "auth_ok"  # no failure indicator seen, no success_indicators configured — weaker signal, still a real one
        except OSError:
            return "conn_error"
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


CHECK_CLASS = TelnetDefaultCredsCheck
