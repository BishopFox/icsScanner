"""Native check — MQTT broker reachable with no authentication at all (CWE-306, missing
authentication), NOT a default-credential guess.

Generic, protocol-level check, not vendor-specific — same design philosophy as
checks/snmp/native/snmp_community_default_creds.py ("SNMP is used by hundreds of ICS/OT vendors'
gear with no single hardware tie"). Mosquitto's own documented behavior (and most other MQTT
broker implementations) is that when no password_file/ACL is configured, `allow_anonymous`
effectively permits any client to connect with no credential at all — a deployment
misconfiguration this project has now found on real firmware (see
checks/candidates/moxa-mar-2000-mosquitto-unauthenticated-mqtt.yaml), but not something unique to
one vendor's hardware, so this check narrows on the protocol itself (a real MQTT CONNECT/CONNACK
handshake) rather than a vendor/product fingerprint pair.

Built on `paho-mqtt`, already a real project dependency — see core/discovery.py's own Sparkplug B
passive listener (`_listen_sparkplug`) for the existing `CallbackAPIVersion.VERSION2` usage
pattern this module follows, rather than hand-rolling the MQTT wire protocol a second time in
this codebase.

MECHANISM: opens a real MQTT connection with Clean Session=1, a randomly generated Client ID
(`icsscanner-<8 hex chars>` by default — random specifically so a broker enforcing per-client-ID
ACLs isn't accidentally matched against a guessable/fixed ID), and NO username/password fields
set at all — exactly what a client with no configured credentials sends. A CONNACK with reason
code 0 (Success) confirms the broker accepted the connection without requiring any
authentication. Any failure reason code (5 = Not Authorized, 4 = Bad username or password, etc.)
or no CONNACK at all within the timeout is NOT_APPLICABLE.

NON-DESTRUCTIVE BY DESIGN, same posture as core/discovery.py's Sparkplug B listener: this check
never publishes or subscribes to anything. It confirms the underlying condition (anonymous
CONNECT is accepted) via the connection handshake alone, then immediately disconnects — it never
exercises the actual read/write access an accepted anonymous connection would grant to the
broker's topic tree.

params schema:
  client_id_prefix:  prefix for the randomly generated MQTT client ID (default "icsscanner-")
  default_port:      fallback port if the target doesn't specify one (default 1883, MQTT's own
                      well-known unencrypted port)
  timeout:            seconds to wait for a CONNACK before giving up (default 5.0)
"""

from __future__ import annotations

import secrets
import threading

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

_DEFAULT_PORT = 1883


class MqttUnauthenticatedBrokerCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        if mqtt is None:
            return self._result(target, CheckStatus.ERROR, description="paho-mqtt is not installed")

        params = self.metadata.params or {}
        port = target.port or params.get("default_port", _DEFAULT_PORT)
        timeout = params.get("timeout", 5.0)
        client_id = params.get("client_id_prefix", "icsscanner-") + secrets.token_hex(4)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        connack_event = threading.Event()
        outcome: dict = {"reason_code": None}

        def on_connect(_client, _userdata, _connect_flags, reason_code, _properties=None) -> None:
            outcome["reason_code"] = reason_code
            connack_event.set()

        client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=client_id,
            clean_session=True,
        )
        client.on_connect = on_connect

        try:
            client.connect(target.host, port, keepalive=max(int(timeout), 1))
        except (OSError, ValueError) as e:
            return self._result(
                target, CheckStatus.NOT_APPLICABLE,
                description=f"could not reach {target.host}:{port} ({type(e).__name__}: {e})",
            )

        client.loop_start()
        try:
            got_connack = connack_event.wait(timeout)
        finally:
            client.loop_stop()
            try:
                client.disconnect()
            except OSError:
                pass

        if not got_connack:
            return self._result(
                target, CheckStatus.NOT_APPLICABLE,
                description=f"no CONNACK received from {target.host}:{port} within {timeout}s",
            )

        reason_code = outcome["reason_code"]
        if reason_code is not None and not reason_code.is_failure:
            return self._result(
                target, CheckStatus.CONFIRMED,
                description=f"MQTT broker at {target.host}:{port} accepted an unauthenticated "
                            f"CONNECT (reason: {reason_code}) — no credentials required",
            )
        return self._result(
            target, CheckStatus.NOT_APPLICABLE,
            description=f"MQTT broker at {target.host}:{port} rejected the unauthenticated "
                        f"CONNECT (reason: {reason_code})",
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


CHECK_CLASS = MqttUnauthenticatedBrokerCheck
