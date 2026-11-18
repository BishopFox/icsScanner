"""Builds a searchable default-credential reference table straight from the check registry's own
metadata — added 2026-08-30, user-requested ("as an interface output, is it possible to generate
a searchable default password list"). Every value surfaced here is already public in
checks/**/*.yaml and their module docstrings; this only re-presents structured data that already
exists, it doesn't disclose anything new (the same posture as SCADAPASS's own public CSV, which
this project's own history names as a direct ancestor — see lab-notes/default-credentials-sweep.md).

Same read-only, no-probing-capability posture as web/server.py's existing
`/api/physical-access-checks` route (the Field Reference tab): this module only ever reads
already-loaded CheckMetadata, never opens a socket.

EXTRACTION, not guessing: most checks (140/167 as of this writing) express their default
credential(s) directly in `params` using one of a small number of shapes already used by this
project's reusable native check classes (`credentials`, `chains`, `passwords`, `communities`).
For those, the value shown here is read verbatim from the same params dict the check itself runs
with. A handful of checks (6, as of this writing) hardcode their default value in Python rather
than expose it via params (e.g. the GE Multilin factory-passcode checks) — for those, rather than
regex-parse a value out of free-text prose (fragile, and risks silently drifting from the actual
check if the description is ever edited), this module falls back to showing the check's own
description text verbatim, flagged as `via_description: true` so the UI can render it
differently. That fallback list is an explicit, manually-verified allowlist
(`_DESCRIPTION_ONLY_CHECK_IDS` below), not a heuristic — every other check without a recognized
params shape is a genuinely different finding class (DoS/fuzzing, protocol-compliance, anonymous
write access, key-bypass) and is correctly excluded rather than mis-included via a guessed
filename pattern.
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.check import Check

# Manually verified 2026-08-30 by reading each check's own description — see this module's
# docstring for why this is an explicit allowlist rather than a filename/keyword heuristic.
_DESCRIPTION_ONLY_CHECK_IDS = {
    "ge-multilin-469-factory-passcode",
    "ge-multilin-489-factory-passcode",
    "ge-multilin-850-factory-passcode",
    "ge-multilin-869-factory-passcode",
    "beckwith-m3425a-comm-channel-unlocked",
    "pcom-tcp-unitronics-default-password",
}


def _credentials_from_params(params: dict) -> List[Dict[str, str]]:
    """Returns a list of {"username", "password"} pairs for any recognized params shape, or []
    if none is present. Never guesses at a shape not already in active use by a real check."""
    if "credentials" in params:
        # Rows are normally [username, password]; tolerate a stray 1- or 3+-element row rather
        # than raising a ValueError that would 500 the whole /api/credential-list route.
        out = []
        for row in params["credentials"]:
            if isinstance(row, (list, tuple)) and len(row) >= 2:
                out.append({"username": row[0], "password": row[1]})
            else:
                out.append({"username": "(malformed entry)", "password": str(row)})
        return out
    if "chains" in params:
        entries = []
        for chain in params["chains"]:
            steps = " -> ".join(
                f"{step[0]}:{step[1]}" if isinstance(step, (list, tuple)) and len(step) >= 2
                else str(step)
                for step in chain
            )
            entries.append({"username": "(multi-step)", "password": steps})
        return entries
    if "passwords" in params:
        return [{"username": "(none)", "password": p} for p in params["passwords"]]
    if "communities" in params:
        return [{"username": "(SNMP community)", "password": c} for c in params["communities"]]
    return []


def build_credential_entries(checks: List[Check]) -> List[Dict[str, Any]]:
    """One entry per check that has a known default credential — either structured (from params)
    or the explicit description-only allowlist above. Every other check (fuzzing/DoS/protocol-
    compliance/key-bypass/anonymous-access findings with no actual credential) is omitted, not
    padded in with a guessed value."""
    entries = []
    for check in checks:
        m = check.metadata
        params = m.params or {}
        credentials = _credentials_from_params(params)
        via_description = False
        if not credentials:
            if m.check_id not in _DESCRIPTION_ONLY_CHECK_IDS:
                continue
            via_description = True

        fp = m.fingerprint_precondition or {}
        entries.append({
            "check_id": m.check_id,
            "protocol": m.protocol,
            "vendor": fp.get("vendor", ""),
            "product": fp.get("product", ""),
            "credentials": credentials,
            "via_description": via_description,
            "description": (m.description or "").strip(),
            "risk_tier": m.risk_tier(),
            "risk_reason": m.risk_reason,
            "references": m.references or [],
        })
    return entries
