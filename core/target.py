"""Target model — the scanner's inventory unit. New in icsScanner; no direct icsFuzzer
equivalent (the closest antecedent is base_module.py's Device, which folds into this plus a
credential-reference layer — see core/check.py for what replaces the rest of Device/base_module).

Credential handling policy (00-PROJECT-CHARTER.md § Scope, decided 2026-08-12):
  - User-provided target auth is NEVER stored as plaintext in the target inventory YAML. The
    inventory stores a keyring reference (service + username); the actual secret is resolved
    from the OS/backend keyring at run time. Enforced here, not just documented: a plaintext
    password/secret/token/api_key field in the inventory is a hard load-time error.
  - Known/default credentials used as CHECK CONTENT (e.g. testing a published factory-default
    admin/admin) are public information and stay in the check itself as plain strings — a
    different thing from a target's own auth, and not handled by this module.

Environment note (verified 2026-08-12 on this project's WSL2 dev environment): headless Linux
has no D-Bus Secret Service session, so the `keyring` package's default backend resolves to a
no-op `fail` backend rather than silently falling back to plaintext storage — confirmed by
testing, not assumed. `configure_keyring_backend()` detects this and switches to
`keyrings.cryptfile` (AES-encrypted file, password from the ICSSCANNER_KEYRING_PASSWORD env
var) instead of proceeding with no usable backend. On native Windows/macOS the OS keychain
works out of the box and this function is a no-op. See ../requirements.txt for the two new
dependencies this required (keyring, keyrings.cryptfile) beyond what icsFuzzer already used.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

import yaml


class CredentialResolutionError(RuntimeError):
    """Raised when a target's credential reference can't be resolved to an actual secret."""


class InsecureKeyringBackendError(RuntimeError):
    """Raised when the only available keyring backend would store secrets insecurely (e.g.
    keyrings.alt's PlaintextKeyring) — refuse rather than proceed quietly."""


# Backend class names known to store secrets in plaintext or otherwise insecurely. Checked by
# class name so this doesn't require importing keyrings.alt just to check for it.
_INSECURE_BACKEND_NAMES = {"PlaintextKeyring", "UnencryptedFileKeyring"}


def configure_keyring_backend() -> None:
    """Ensure a usable, non-insecure keyring backend is active. Idempotent; safe to call before
    every credential resolution, not just once at startup."""
    import keyring
    from keyring.backends.fail import Keyring as FailKeyring

    current = keyring.get_keyring()

    if type(current).__name__ in _INSECURE_BACKEND_NAMES:
        raise InsecureKeyringBackendError(
            f"Active keyring backend {type(current).__name__} stores secrets insecurely "
            "(plaintext/unencrypted). Refusing to use it. Configure a real backend (OS "
            "keychain, or keyrings.cryptfile on headless Linux)."
        )

    if isinstance(current, FailKeyring):
        # No usable OS backend — expected on headless Linux/WSL2 (verified 2026-08-12: no
        # D-Bus Secret Service session available). Use an encrypted file backend instead of
        # failing outright, but require an explicit password — never auto-generate one.
        password = os.environ.get("ICSSCANNER_KEYRING_PASSWORD")
        if not password:
            raise CredentialResolutionError(
                "No usable keyring backend on this system (headless Linux without a D-Bus "
                "Secret Service session — expected on WSL2). Set ICSSCANNER_KEYRING_PASSWORD "
                "and this will use an AES-encrypted file backend (keyrings.cryptfile) instead. "
                "Only needed if a target in the inventory has a `credential:` reference."
            )
        try:
            from keyrings.cryptfile.cryptfile import CryptFileKeyring
        except ImportError as e:
            raise CredentialResolutionError(
                "keyrings.cryptfile not installed. Install with: pip install --user "
                "--break-system-packages keyrings.cryptfile"
            ) from e
        backend = CryptFileKeyring()
        backend.keyring_key = password
        keyring.set_keyring(backend)


@dataclass
class CredentialRef:
    """A reference to a secret held in the keyring backend — never the secret itself."""

    keyring_service: str
    keyring_username: str

    def resolve(self) -> str:
        import keyring

        configure_keyring_backend()
        secret = keyring.get_password(self.keyring_service, self.keyring_username)
        if secret is None:
            raise CredentialResolutionError(
                f"No credential stored for service={self.keyring_service!r} "
                f"username={self.keyring_username!r}. Set it first, e.g.:\n"
                f"  python3 -c \"import keyring; keyring.set_password("
                f"{self.keyring_service!r}, {self.keyring_username!r}, 'the-secret')\""
            )
        return secret


@dataclass
class Target:
    host: str
    port: Optional[int] = None
    protocol_hint: Optional[str] = None
    vendor_hint: Optional[str] = None
    product_hint: Optional[str] = None
    version_hint: Optional[str] = None
    credential: Optional[CredentialRef] = None
    metadata: dict = field(default_factory=dict)

    def resolve_credential(self) -> Optional[str]:
        """Returns the resolved secret, or None if this target has no credential reference."""
        if self.credential is None:
            return None
        return self.credential.resolve()

    def __str__(self) -> str:
        port_part = f":{self.port}" if self.port else ""
        proto_part = f" [{self.protocol_hint}]" if self.protocol_hint else ""
        return f"{self.host}{port_part}{proto_part}"


# Field names that must never appear directly on a target entry — catches an author pasting a
# real secret into the inventory instead of using a credential: {service, username} reference.
_FORBIDDEN_PLAINTEXT_FIELDS = {"password", "secret", "token", "api_key", "apikey"}


def load_target_inventory(path: Union[str, Path]) -> list[Target]:
    """Parse a YAML target inventory. See 00-PROJECT-CHARTER.md § Scope for the format decision
    and templates/target-inventory.example.yaml for the shape."""
    path = Path(path)
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not data or "targets" not in data:
        raise ValueError(f"{path}: expected a top-level 'targets:' list")

    if not isinstance(data["targets"], list):
        raise ValueError(f"{path}: 'targets:' must be a list")

    targets = []
    for i, entry in enumerate(data["targets"]):
        if not isinstance(entry, dict):
            raise ValueError(
                f"{path}: target #{i} is a {type(entry).__name__}, not a mapping — each entry "
                f"must be `host: ...` with optional port/vendor/product/credential keys, "
                f"not a bare value."
            )
        if "host" not in entry:
            raise ValueError(f"{path}: target #{i} has no 'host:' key")
        bad = _FORBIDDEN_PLAINTEXT_FIELDS & entry.keys()
        if bad:
            raise ValueError(
                f"{path}: target #{i} ({entry.get('host', '?')}) has plaintext field(s) "
                f"{sorted(bad)} — credentials must be a keyring reference "
                f"(`credential: {{service: ..., username: ...}}`), never a plaintext secret. "
                f"See 00-PROJECT-CHARTER.md § Scope."
            )

        cred = None
        if "credential" in entry:
            c = entry["credential"]
            if not isinstance(c, dict) or "service" not in c or "username" not in c:
                raise ValueError(
                    f"{path}: target #{i} ({entry.get('host', '?')}) has a malformed "
                    f"`credential:` — expected {{service: ..., username: ...}}"
                )
            cred = CredentialRef(keyring_service=c["service"], keyring_username=c["username"])

        targets.append(
            Target(
                host=entry["host"],
                port=entry.get("port"),
                protocol_hint=entry.get("protocol"),
                vendor_hint=entry.get("vendor"),
                product_hint=entry.get("product"),
                version_hint=entry.get("version"),
                credential=cred,
                metadata=entry.get("metadata", {}),
            )
        )
    return targets
