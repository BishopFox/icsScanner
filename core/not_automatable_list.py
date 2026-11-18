"""Builds the "verified but not automatable" reference list straight from the check registry's own
candidate metadata — added 2026-11-05 (side-quest #2, lab-notes/side-quests.md). These are real
default credentials that were confirmed against a primary/strong source but CANNOT be turned into an
automated icsScanner check — because the login is an HTML form whose field names are unknown, the
credential is derived per-device (MAC/serial), the auth rides a proprietary protocol with no executor,
or it is a wireless/out-of-scope surface. Each such candidate carries a structured
`not_automatable_reference: {credential, source, category, reason}` block; this module collects them.

Same read-only, no-probing posture as core/credential_list.py and web/server.py's
/api/physical-access-checks route: it only reads already-loaded CheckMetadata, never opens a socket.
It also EXTRACTS rather than guesses — every field shown is read verbatim from the candidate's own
`not_automatable_reference` block (hand-curated from each candidate's primary-source research trail),
not regex-parsed out of prose. Candidates without that block are simply not included.

Nothing here is new disclosure: every credential is already public in checks/candidates/**.yaml and in
the vendor manuals / sources those files cite. This re-presents structured data that already exists —
the same posture SCADAPASS's own public CSV established, which this project names as a direct ancestor.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# human-readable labels for the not-automatable categories (the `category` key in each block)
CATEGORY_LABELS: Dict[str, str] = {
    "form-login-fields-unconfirmed": "HTML form login — field names unconfirmed",
    "auth-flow-ambiguous": "Auth-challenge flow ambiguous (GET vs POST / disabled by default)",
    "derived-credential-architectural": "Per-device derived credential (architectural mismatch)",
    "wireless-out-of-scope": "Wireless / non-TCP-IP surface (out of scope)",
    "proprietary-protocol-no-executor": "Proprietary protocol — no wire spec / no executor",
}


def _vendor_of(meta) -> str:
    fp = meta.fingerprint_precondition or {}
    v = fp.get("vendor")
    if v:
        return v
    # fall back to the first word of the check id after the "candidate-" prefix
    cid = (meta.check_id or "").removeprefix("candidate-")
    return cid.split("-")[0].upper() if cid else "unknown"


def build_not_automatable_entries(registry) -> List[Dict[str, Any]]:
    """Walk the registry's candidates, return one dict per candidate carrying a
    not_automatable_reference block. Sorted by category then vendor for stable, grouped output."""
    cands = registry.candidates() if callable(getattr(registry, "candidates", None)) else registry.candidates
    entries: List[Dict[str, Any]] = []
    for meta in cands:
        ref: Optional[dict] = getattr(meta, "not_automatable_reference", None)
        if not ref:
            continue
        category = ref.get("category", "")
        entries.append({
            "check_id": meta.check_id,
            "vendor": _vendor_of(meta),
            "protocol": meta.protocol,
            "credential": ref.get("credential", ""),
            "source": ref.get("source", ""),
            "category": category,
            "category_label": CATEGORY_LABELS.get(category, category or "uncategorized"),
            "reason": ref.get("reason", ""),
            "disclosure_status": meta.disclosure_status,
            "references": meta.references or [],
        })
    entries.sort(key=lambda e: (e["category_label"], e["vendor"].lower(), e["check_id"]))
    return entries
