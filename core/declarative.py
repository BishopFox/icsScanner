"""Declarative check executor — Milestone 2. Runs the send/expect step sequence a
`kind: declarative` check YAML defines (see checks/modbus/*.yaml for real examples ported from
a companion fuzzing toolkit). Static wire bytes only for v1 — no protocol
templating engine. A step's send_hex is the exact final bytes to put on the wire, computed once
by whoever authored the check; this matches how the ported checks actually work (emelianov's
bare-FC-family probes are fixed malformed frames, not runtime-computed ones — MBAP length/TID
are hardcoded per the existing PoC's own approach). Multi-step ICS handshakes (S7comm ACSE,
OPC-UA sessions) stay `kind: native` per the format decision — this executor is intentionally
not trying to cover that case.

Step schema:
  send_hex:   exact wire bytes, hex string
  timeout_s:  socket timeout for this step's recv (default 5.0)
  on_timeout: {continue: true}                              — inconclusive, try the next step
              {status: "confirmed", description: "..."}      — terminal classification
  match:      [{prefix_hex: "83", status: "not-applicable", note: "..."}, ...] — checked in
              order against a real response; first hit wins
  default:    {status: "not-applicable", description: "..."} — used when a response is received
              but no match rule fires

A response (of any kind) is always terminal — only a timeout can move to the next step, via
on_timeout.continue. This matches every check in the actual inventory: a step either times out
(maybe-inconclusive, maybe-terminal) or gets an answer (always terminal — even an unexpected
answer means "this step's malformed input didn't hang the connection").
"""

from __future__ import annotations

import socket
from typing import Optional

from core.check import Check, CheckResult, CheckStatus
from core.target import Target


class DeclarativeCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        steps = self.metadata.steps or []
        if target.port is None:
            return self._result(target, CheckStatus.ERROR, description="target has no port configured")

        sock: Optional[socket.socket] = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((target.host, target.port))

            for step in steps:
                if rate_limiter is not None:
                    rate_limiter.acquire(target.host)

                payload = bytes.fromhex(step["send_hex"])
                timeout_s = step.get("timeout_s", 5.0)
                sock.settimeout(timeout_s)
                sock.sendall(payload)

                try:
                    response = sock.recv(4096)
                except socket.timeout:
                    outcome = step.get("on_timeout", {"status": CheckStatus.NOT_APPLICABLE.value})
                    if outcome.get("continue"):
                        continue  # inconclusive on this step — e.g. confirm-recovery pattern:
                        # try a known-good frame next before deciding
                    return self._result(
                        target,
                        CheckStatus(outcome.get("status", CheckStatus.NOT_APPLICABLE.value)),
                        description=outcome.get("description", self.metadata.description),
                    )
                else:
                    # A response — of any kind — is always terminal. Even an unexpected answer
                    # means this step's malformed input did NOT hang the connection.
                    matched = self._match_response(step, response)
                    chosen = matched if matched is not None else step.get(
                        "default", {"status": CheckStatus.NOT_APPLICABLE.value}
                    )
                    return self._result(
                        target,
                        CheckStatus(chosen.get("status", CheckStatus.NOT_APPLICABLE.value)),
                        description=chosen.get("note", chosen.get("description", self.metadata.description)),
                        evidence=response,
                    )

            # Every step said "continue" — no terminal classification was ever reached. A
            # check-authoring bug (the last step's on_timeout must not set continue), not a
            # runtime condition — surfaced as an error rather than guessed at.
            return self._result(
                target, CheckStatus.ERROR, description="steps exhausted without a terminal classification"
            )
        except (ConnectionRefusedError, OSError) as e:
            return self._result(target, CheckStatus.ERROR, description=f"connection error: {e}")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def _match_response(self, step: dict, response: bytes) -> Optional[dict]:
        response_hex = response.hex()
        for rule in step.get("match", []):
            prefix = rule.get("prefix_hex")
            if prefix is not None and response_hex.startswith(prefix.lower()):
                return rule
        return None

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
