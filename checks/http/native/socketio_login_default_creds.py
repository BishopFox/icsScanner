"""Generic native check — Socket.IO login default-credential test. Distinct from
checks/http/native/basic_auth_default_creds.py, form_post_default_creds.py, and
json_rest_login_default_creds.py: none of those three can drive a Socket.IO exchange, which is
a genuinely different shape from a single HTTP request/response — Socket.IO layers its own
event-based framing on top of Engine.IO's own transport-negotiation handshake (HTTP long-polling,
optionally upgrading to a WebSocket), not a plain POST/response.

Built 2026-09-23 for HMS Industrial Networks' Anybus Atlas2 Plus / Osiris (checks/candidates/
hms-anybus-atlas2plus-osiris-default-credentials-socketio-login.yaml), whose login was confirmed
directly from the shipped Angular bundle to work by emitting a "login" Socket.IO event
({username, password, client}) and waiting for the SERVER to reply via its own "login" event
({loggedIn, sessionId}) — not a request/ack-callback exchange, the response arrives as a
separate, server-initiated event on the same event name. Built as a new, genuinely reusable
capability (any device using a Socket.IO-based management UI needs the same shape), matching this
project's established convention (see json_rest_login_default_creds.py's own docstring for the
same reasoning when it was built).

Uses the `python-socketio` client library (the de facto reference implementation — hand-rolling
Engine.IO's own transport/packet framing would be exactly the kind of protocol-detail risk this
project avoids, same reasoning already applied to every other library choice in requirements.txt).
Verified end-to-end against a real `socketio.Server`-based mock (not just the client library in
isolation) before this module was considered done.

Reusable across vendors: path, namespace, event names, field names, and success criteria all come
from CheckMetadata.params, not per-vendor Python — same convention as every other
*_default_creds.py executor in this project. The response event defaults to the SAME name as the
emitted event (Atlas2Plus/Osiris's own shape), but is independently configurable
(`response_event`) for a device that replies via a different event name.

DESTRUCTIVE: same reasoning as every other credential-testing check here — real
authentication-attempt traffic, lockout risk on devices that implement one.

REQUIRED EXPLICIT SUCCESS CRITERIA — same deliberate design choice as the other three
*_default_creds.py executors. `success_key` must name a boolean-valued field in the response
event's payload (e.g. "loggedIn") — checked for truthiness, not just presence (unlike
json_rest_login_default_creds.py's `success_json_keys`, presence alone is the WRONG contract
here: Atlas2Plus/Osiris's response always carries the `loggedIn` key on both success AND
failure, only its boolean value differs).

KNOWN LIMITATION, deliberately not built: only a single, flat, non-namespaced Socket.IO
connection is supported (one event round-trip per credential attempt, fresh connection each
time — no session reuse across attempts). No candidate found so far needs anything more elaborate
(e.g. a multi-step challenge-response, or a namespace-scoped login); add it if one does, not
preemptively.

params schema:
  path:                 the Engine.IO/Socket.IO HTTP path (NOT a login-specific path — this is
                         the transport-negotiation endpoint, e.g. "socket.io", Socket.IO's own
                         default). Passed as socketio_path to the client library.
  namespace:             Socket.IO namespace (default "/", the root namespace — almost every
                         device uses this; only override if a candidate's own research confirms
                         a non-root namespace).
  event_name:            the Socket.IO event the client emits to submit credentials (e.g.
                         "login").
  response_event:        the Socket.IO event the SERVER replies via — defaults to the same value
                         as event_name (Atlas2Plus/Osiris's confirmed shape: server pushes back
                         on the identical event name, not a distinct one).
  password_only:         bool, default false. Set true for password-only endpoints (no username
                         field at all) — same convention as every other *_default_creds.py
                         executor's flag of the same name.
  username_field:        payload field name for the username, e.g. "username" — required unless
                         password_only is true.
  password_field:        payload field name for the password, e.g. "password" — always required.
  extra_fields:           optional flat dict of additional static field-name -> value pairs
                         merged into every emitted payload (e.g. {"client": "angular js"}, the
                         real value Atlas2Plus/Osiris's own Angular client sends) — same
                         convention as json_rest_login_default_creds.py's extra_fields.
  credentials:            list of [username, password] pairs, tried in order — stops at first
                         success. For password_only endpoints, username is ignored
                         (conventionally "" in the YAML).
  success_key:            REQUIRED — the boolean-valued key in the response event's payload that
                         means "authenticated" (e.g. "loggedIn"). Checked for truthiness, not
                         just key presence.
  https:                  bool, use HTTPS/WSS instead of HTTP/WS (default: false — most embedded
                         device management UIs of this shape use HTTPS with a self-signed cert;
                         set explicitly per check, not assumed). Certificate verification is
                         disabled either way (ssl_verify=False), matching this project's other
                         HTTPS-speaking executors' handling of the self-signed-cert-by-default
                         reality of this device class.
  default_port:           fallback port if the target doesn't specify one (default 80, or 443 if
                         https).
  timeout:                seconds to wait for BOTH the initial Engine.IO connection handshake and
                         the server's response event, checked independently (default 8.0 —
                         longer than the other executors' default 5.0, since a Socket.IO
                         handshake genuinely involves more round trips than a single HTTP
                         request).

  `success_key` and `credentials` (plus `password_field`, and `username_field` unless
  password_only) MUST all be set, or the check returns ERROR immediately (a configuration error,
  not a probe result) rather than guessing.
"""

from __future__ import annotations

import threading

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

try:
    import socketio
except ImportError:
    socketio = None


class SocketIoLoginDefaultCredsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        if socketio is None:
            return self._result(target, CheckStatus.ERROR, description="python-socketio not installed — pip install python-socketio")

        params = self.metadata.params or {}
        credentials = params.get("credentials", [])
        password_only = params.get("password_only", False)
        username_field = params.get("username_field")
        password_field = params.get("password_field")
        extra_fields = params.get("extra_fields") or {}
        event_name = params.get("event_name", "login")
        response_event = params.get("response_event", event_name)
        success_key = params.get("success_key")
        socketio_path = params.get("path", "socket.io")
        namespace = params.get("namespace", "/")
        use_https = params.get("https", False)
        port = target.port or params.get("default_port", 443 if use_https else 80)
        timeout = params.get("timeout", 8.0)

        if not credentials:
            return self._result(target, CheckStatus.ERROR, description="check has no credentials configured in params")
        if not password_field:
            return self._result(target, CheckStatus.ERROR, description="check has no password_field configured in params")
        if not password_only and not username_field:
            return self._result(target, CheckStatus.ERROR, description="check has no username_field configured in params (set password_only:true if this endpoint has no username field)")
        if not success_key:
            return self._result(target, CheckStatus.ERROR, description="check has no success_key configured in params — explicit success criteria are required, not guessed")

        scheme = "https" if use_https else "http"
        url = f"{scheme}://{target.host}:{port}"

        for username, password in credentials:
            if rate_limiter is not None:
                rate_limiter.acquire(target.host)
            outcome = self._try_one(
                url, socketio_path, namespace, event_name, response_event,
                username, password, password_only, username_field, password_field,
                extra_fields, success_key, timeout,
            )
            if outcome == "auth_ok":
                return self._result(
                    target,
                    CheckStatus.CONFIRMED,
                    description=f"default credential '{username}:{password}' accepted via Socket.IO event '{event_name}'",
                )

        return self._result(
            target,
            CheckStatus.NOT_APPLICABLE,
            description=f"none of {len(credentials)} tested default credential(s) were accepted via Socket.IO event '{event_name}'",
        )

    def _try_one(
        self, url, socketio_path, namespace, event_name, response_event,
        username, password, password_only, username_field, password_field,
        extra_fields, success_key, timeout,
    ) -> str:
        payload = dict(extra_fields)
        payload[password_field] = password
        if not password_only:
            payload[username_field] = username

        response: dict = {}
        response_received = threading.Event()

        sio = socketio.Client(logger=False, engineio_logger=False, ssl_verify=False, request_timeout=timeout)

        @sio.on(response_event, namespace=namespace)
        def _on_response(data):
            if isinstance(data, dict):
                response.update(data)
            response_received.set()

        try:
            sio.connect(url, socketio_path=socketio_path, namespaces=[namespace], wait_timeout=timeout)
        except Exception:
            return "conn_error"

        try:
            sio.emit(event_name, payload, namespace=namespace)
            response_received.wait(timeout=timeout)
        finally:
            try:
                sio.disconnect()
            except Exception:
                pass

        if not response_received.is_set():
            return "conn_error"
        return "auth_ok" if bool(response.get(success_key)) else "auth_failed"

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


CHECK_CLASS = SocketIoLoginDefaultCredsCheck
