"""Native check — SSH PUBLIC-KEY-authentication test against a hardcoded/shared private key that
ships inside a vendor's own firmware image, via paramiko.

Built 2026-09-14 for CVE-2023-48251 (Bosch Rexroth Nexo cordless nutrunner, BOSCH-SA-711465) —
see checks/ssh/bosch-rexroth-nexo-hardcoded-dropbear-ssh-private-key.yaml for the full finding
and sourcing. Distinct from ssh_default_creds.py: that executor tests PASSWORD credentials
supplied directly in params (safe to commit — a short string). This one authenticates with a
PRIVATE KEY, a fundamentally more sensitive artifact this project will not embed in a committed
YAML params: block or anywhere in git history (matches the same "don't distribute the actual key"
reasoning already applied to CVE-2022-38465's hardcoded S7-1200/1500 global key).

KEY MATERIAL HANDLING — the actual design decision this executor exists to implement: the key
lives ONLY as a local file path, resolved relative to the repository root (params:
`private_key_path`, e.g. "secrets/bosch-rexroth-nexo-id_rsa.pem"), under `secrets/` — a directory
this project's own .gitignore excludes unconditionally. An operator running this check supplies
their own extracted copy of the key at that path; nothing in checks/, git history, or any export
this project produces (see export-demo-repos.py) ever carries the key content itself. If the file
is missing, this check reports CheckStatus.ERROR with a clear message, never a silent skip or a
guessed result — the same "fail loud, not quiet" discipline as ssh_default_creds.py's own
"check has no credentials configured" error path.

DESTRUCTIVE: real authentication-attempt traffic against a live device's SSH daemon, same risk
tier as ssh_default_creds.py.

CONFIRMED on a successful paramiko connect using the key (AuthenticationException -> not
confirmed) — look_for_keys=False and allow_agent=False are set explicitly, matching
ssh_default_creds.py's own discipline, so this only ever tests the exact supplied key file, never
an unrelated local key or agent.

params schema:
  username:           SSH username to authenticate as
  private_key_path:    path to a PEM-format private key file. Resolved relative to the
                       repository root if not already absolute — NEVER defaults to a path this
                       project ships content at.
  key_type:            one of "rsa" (default), "ecdsa", "ed25519", and "dss" where paramiko still
                       provides DSSKey (removed in some recent paramiko releases; DSA is
                       deprecated/insecure) — which paramiko key class to load the file as.
                       Vendor firmware in the wild has been observed shipping classic RSA keys
                       (Bosch Rexroth Nexo's own dropbear/OpenSSH key pair is RSA 2048); other
                       key types are supported for future reuse.
  timeout:             connection timeout in seconds (default 5.0)
  default_port:        fallback port if the target doesn't specify one (default 22)
"""

from __future__ import annotations

from pathlib import Path

from core.check import Check, CheckResult, CheckStatus
from core.target import Target

try:
    import paramiko
except ImportError:
    paramiko = None

_REPO_ROOT = Path(__file__).resolve().parents[3]

_KEY_LOADERS = {}
if paramiko is not None:
    # DSSKey was removed from recent paramiko releases (DSA is deprecated/insecure) — build the
    # loader table defensively so this module still imports cleanly on those versions; "dss" is
    # then simply not an accepted key_type, reported the normal "unsupported key_type" way if
    # ever requested rather than an ImportError.
    _KEY_LOADERS = {
        "rsa": paramiko.RSAKey.from_private_key_file,
        "ecdsa": paramiko.ECDSAKey.from_private_key_file,
        "ed25519": paramiko.Ed25519Key.from_private_key_file,
    }
    if hasattr(paramiko, "DSSKey"):
        _KEY_LOADERS["dss"] = paramiko.DSSKey.from_private_key_file


class SshHardcodedPrivateKeyCheck(Check):
    def probe(self, target: Target, rate_limiter=None) -> CheckResult:
        if paramiko is None:
            return self._result(target, CheckStatus.ERROR, description="paramiko not installed — pip install paramiko")

        params = self.metadata.params or {}
        username = params.get("username")
        key_path_param = params.get("private_key_path")
        key_type = params.get("key_type", "rsa")
        timeout = params.get("timeout", 5.0)
        port = target.port or params.get("default_port", 22)

        if not username or not key_path_param:
            return self._result(target, CheckStatus.ERROR, description="check is missing 'username' or 'private_key_path' in params")

        key_path = Path(key_path_param)
        if not key_path.is_absolute():
            key_path = _REPO_ROOT / key_path

        if not key_path.exists():
            return self._result(
                target,
                CheckStatus.ERROR,
                description=(
                    f"private key file not found at {key_path} — this check needs your own local "
                    f"copy of the key placed there (never committed to this repository; see the "
                    f"check's own module docstring). Nothing was sent to the target."
                ),
            )

        loader = _KEY_LOADERS.get(key_type)
        if loader is None:
            return self._result(target, CheckStatus.ERROR, description=f"unsupported key_type '{key_type}' — expected one of {sorted(_KEY_LOADERS)}")

        try:
            private_key = loader(str(key_path))
        except Exception as e:
            return self._result(target, CheckStatus.ERROR, description=f"failed to load private key from {key_path}: {e}")

        if rate_limiter is not None:
            rate_limiter.acquire(target.host)

        outcome = self._try_key(target.host, port, username, private_key, timeout)
        if outcome == "auth_ok":
            return self._result(
                target,
                CheckStatus.CONFIRMED,
                description=f"authenticated via SSH as '{username}' using the hardcoded private key",
            )
        if outcome == "auth_failed":
            return self._result(
                target,
                CheckStatus.NOT_APPLICABLE,
                description=f"the supplied private key was rejected for user '{username}' via SSH",
            )
        return self._result(target, CheckStatus.ERROR, description=f"connection error while attempting SSH key authentication as '{username}'")

    def _try_key(self, host: str, port: int, username: str, private_key, timeout: float) -> str:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host,
                port=port,
                username=username,
                pkey=private_key,
                timeout=timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            return "auth_ok"
        except paramiko.AuthenticationException:
            return "auth_failed"
        except Exception:
            return "conn_error"
        finally:
            client.close()

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


CHECK_CLASS = SshHardcodedPrivateKeyCheck
