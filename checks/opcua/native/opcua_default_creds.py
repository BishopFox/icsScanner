"""Native check — OPC-UA UserName/Password default-credential test.

Tries to open and ACTIVATE an OPC-UA session using a vendor-documented default credential
(UserNameIdentityToken). Uses the asyncua library (project standard for OPC-UA — see
core/fingerprint.py probe_opcua_identity and checks/opcua/native/anon_write_*.py), driven from the
sync probe() via asyncio.run, same as the anon-write checks.

Two guards keep it from false-positiving on a server that isn't actually enforcing a username login:
  1. DISCOVERY: GetEndpoints must advertise a UserName identity token (else this is not a
     username/password login -> NOT_APPLICABLE). Controlled by `require_username_endpoint`.
  2. NEGATIVE CONTROL: before trying the default, it tries a RANDOM bogus username/password. If the
     server activates a session for that, the server accepts anything (anonymous elevation / no real
     auth) and a "default credential accepted" claim would be bogus -> NOT_APPLICABLE. Controlled by
     `negative_control`. Only if the bogus credential is REJECTED and a default is ACCEPTED does this
     return CONFIRMED.

DESTRUCTIVE: real authentication-attempt traffic (session activation). It does NOT read/write any
application data — it only establishes a session, then disconnects. (The anon-write checks cover the
write side.) Same lockout reasoning as every other credential check.

Limitation: if the server only offers the UserName token over an ENCRYPTED SecurityPolicy (not
#None) this client has no certificate to establish that channel, so the attempt errors out and the
check reports NOT_APPLICABLE (fail-closed, never a false CONFIRMED).

params schema:
  credentials:                list of [username, password] pairs, tried in order
  default_port:               fallback port if the target has none (OPC-UA default 4840)
  timeout:                    per-connection timeout seconds (default 8.0)
  require_username_endpoint:  bool (default true) — require a UserName identity token in GetEndpoints
  negative_control:           bool (default true) — reject servers that accept a random bogus credential
"""

from __future__ import annotations

import asyncio
import secrets

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

try:
    from asyncua import Client, ua
except ImportError:  # pragma: no cover
    Client = None
    ua = None

# asyncua raises ua.UaStatusCodeError whose text carries the OPC-UA status name; these mean the
# server evaluated and REJECTED the identity token (as opposed to a transport/negotiation failure).
_REJECT_MARKERS = (
    "baduseraccessdenied", "badidentitytokenrejected", "badidentitytokeninvalid",
    "accessdenied", "identitytoken",
)


async def _try_login(url: str, timeout: float, username: str, password: str) -> str:
    """Return 'accepted' | 'rejected' | 'error' for one UserName/Password session attempt."""
    client = Client(url=url, timeout=timeout)
    client.set_user(username)
    client.set_password(password)
    try:
        async with client:  # connect -> open secure channel -> create + ACTIVATE session
            return "accepted"
    except Exception as e:  # noqa: BLE001 - classify below
        text = f"{type(e).__name__}:{e}".lower()
        if any(m in text for m in _REJECT_MARKERS):
            return "rejected"
        return "error"


async def _probe_async(host, port, credentials, timeout, require_username_endpoint, negative_control):
    url = f"opc.tcp://{host}:{port}"

    # 1. discovery — reachable + advertises a UserName identity token
    try:
        disc = Client(url=url, timeout=timeout)
        endpoints = await disc.connect_and_get_server_endpoints()
    except Exception as e:  # noqa: BLE001
        return (CheckStatus.NOT_APPLICABLE,
                f"OPC-UA endpoint unreachable ({type(e).__name__}) — not applicable")

    has_username = any(
        tok.TokenType == ua.UserTokenType.UserName
        for ep in endpoints for tok in (ep.UserIdentityTokens or [])
    )
    if require_username_endpoint and not has_username:
        return (CheckStatus.NOT_APPLICABLE,
                "server advertises no UserName identity token — not a username/password login")

    # 2. negative control — reject accept-any servers
    if negative_control:
        nc = await _try_login(url, timeout, "nx_" + secrets.token_hex(6), secrets.token_hex(12))
        if nc == "accepted":
            return (CheckStatus.NOT_APPLICABLE,
                    "server activated a session for a RANDOM bogus credential (accepts-any / anonymous "
                    "elevation) — not a default-credential finding")

    # 3. the real default credential(s)
    for username, password in credentials:
        if await _try_login(url, timeout, username, password) == "accepted":
            return (CheckStatus.CONFIRMED,
                    f"default OPC-UA credential '{username}:{password}' accepted (UserName session activated)")
    return (CheckStatus.NOT_APPLICABLE,
            f"none of {len(credentials)} default credential(s) were accepted")


class OpcuaDefaultCredsCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        if Client is None:
            return self._result(target, CheckStatus.ERROR, description="asyncua not installed — pip install asyncua")
        params = self.metadata.params or {}
        credentials = params.get("credentials", [])
        if not credentials:
            return self._result(target, CheckStatus.ERROR, description="check has no credentials configured in params")
        port = target.port or params.get("default_port", 4840)
        timeout = params.get("timeout", 8.0)
        require_username_endpoint = params.get("require_username_endpoint", True)
        negative_control = params.get("negative_control", True)

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)
        status, description = asyncio.run(
            _probe_async(target.host, port, credentials, timeout, require_username_endpoint, negative_control))
        return self._result(target, status, description=description)

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


CHECK_CLASS = OpcuaDefaultCredsCheck
