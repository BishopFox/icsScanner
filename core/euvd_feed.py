"""ENISA EUVD (EU Vulnerability Database) ingestion -> human-reviewed candidate queue. Same
candidate-stub discipline as core/cve_feed.py / core/jvn_feed.py / core/csaf_feed.py: every entry
that passes the vendor + noise filters becomes a CheckMetadata STUB (kind=None, is_candidate()
True) written to checks/candidates/, never an executable check.

EUVD is a real, live, unauthenticated JSON REST API at euvdservices.enisa.europa.eu/api/search —
found via the frontend's own CORS response header (no public API docs exist anywhere; not a
documented/versioned contract, treat as liable to change without notice, same caveat the plan
file already carries for this source). Confirmed live 2026-08-17 (re-verified, not assumed from
the earlier investigation): `vendor=`, `size=` (100/page max, `total` given up front), `fromDate=`
all work as query params against the live API.

NOT CSAF-shaped — a custom flat JSON response `{"items": [...], "total": N}`, one item per
CVE/advisory (closer to JVN's shape than CSAF's advisory-bundles-many-CVEs shape). No
`baseSeverity` field (unlike CSAF/JVN) — only `baseScore`/`baseScoreVersion`/`baseScoreVector`,
so the severity band word is derived locally from the score using the same public CVSS
score->band thresholds core/reporter.py:_severity_band() already applies. `references`/`aliases`
are newline-delimited STRINGS, not JSON arrays — split before use.

THE REAL SCOPING PROBLEM (confirmed both in the original investigation and re-confirmed live
here): EUVD has no OT/ICS category to filter on server-side. `vendor=Siemens` alone returns 1,798
results (re-confirmed) including entirely unrelated open-source software that merely lists
Siemens as its GitHub-org vendor (e.g. "kas", a bitbake setup tool). Two-layer filtering here:

1. VENDOR ALLOWLIST (query-time): only ever queries a curated list of known ICS/OT vendor names
   (`_ICS_VENDOR_NAMES` — same 4 vendors already curated in core/jvn_feed.py's _ICS_VENDOR_IDS,
   deliberately kept identical rather than diverging, extend as more get verified).
2. ASSIGNER FILTER (local, post-query): a real STRUCTURAL signal, not keyword guessing — found by
   inspecting live data directly. The `assigner` field records WHO filed the CVE. Checked across
   100-item samples for all 4 curated vendors: the noise (e.g. "kas") is consistently assigned by
   `GitHub_M` (GitHub's own CNA covering arbitrary open-source projects), while genuine
   vendor-relevant advisories are assigned either by the vendor itself (case varies: "siemens",
   "Mitsubishi", "OMRON" all observed — matched case-insensitively) or by a small set of
   ICS/OT-focused CNAs that showed up repeatedly across EVERY vendor's sample: `icscert` (CISA's
   own ICS-CERT), `jpcert` (Japan's CERT), `dragos` (a named ICS/OT security research firm).
   Empirically: Siemens 95/100 self-assigned in one sample; Schneider Electric 100/100
   self+icscert; Mitsubishi Electric 100/100 self+icscert; Omron 64/64
   self+icscert+jpcert+dragos. This is a precise, evidence-based filter, not guessed.

   KNOWN LIMITATION, flagged not hidden: matching on "the vendor self-assigned this CVE" does NOT
   guarantee the affected PRODUCT is actually OT/industrial — a large diversified vendor (Siemens
   spans healthcare, mobility/rail, building tech, and digital industries, not just ICS) could in
   principle self-assign a CVE for a non-OT product line, and this filter would still let it
   through. Accepted as a real gap for this first pass, same "good progress, not perfect" posture
   already applied to CSAF's/JVN's own filters — a human still reviews every candidate before
   promotion, this filter only reduces the review queue's noise, it doesn't replace the review.

Checked for the bare-integer-CVSS-score bug (hit twice already this session, JVN and CSAF) before
writing this: NOT present here — sampled 140+ real items across all 4 curated vendors, every
baseScore value in the raw JSON carries an explicit decimal (`10.0`, `7.0`, never a bare `10`).
Defensive `.1f` normalization applied anyway, cheap insurance given this API's own
liable-to-change-without-notice status, matching the same fix pattern (normalize at the source)
already established for the other two sources' real occurrences of this bug.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from core.check import CheckMetadata, Confidence, DisclosureStatus
from core.registry import metadata_to_yaml_dict

import yaml

_EUVD_SEARCH_URL = "https://euvdservices.enisa.europa.eu/api/search"

# Same curated set as core/jvn_feed.py's _ICS_VENDOR_IDS keys, deliberately kept identical rather
# than diverging — extend as more vendors get verified against EUVD's own `vendor=` param
# (a name string here, not a numeric id like JVN's vid).
_ICS_VENDOR_NAMES = ["Siemens", "Schneider Electric", "Mitsubishi Electric", "Omron"]

# Real ICS/OT-focused CNA names confirmed appearing across every curated vendor's live sample
# (see module docstring for the evidence) — case-insensitive match against `assigner`.
_KNOWN_OT_ASSIGNERS = {"icscert", "jpcert", "dragos", "cisa"}

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")


def _split_lines(value: Optional[str]) -> list[str]:
    if not value:
        return []
    return [line.strip() for line in value.split("\n") if line.strip()]


def _extract_cve(aliases: Optional[str]) -> Optional[str]:
    for alias in _split_lines(aliases):
        if _CVE_RE.match(alias):
            return alias
    return None


def _severity_band_word(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return ""


def _format_severity(item: dict) -> Optional[str]:
    vector = item.get("baseScoreVector")
    raw_score = item.get("baseScore")
    if not vector or raw_score is None:
        return None
    try:
        score_float = float(raw_score)
    except (TypeError, ValueError):
        return None
    score = f"{score_float:.1f}"  # defensive normalization — see module docstring
    band = _severity_band_word(score_float)
    sev_text = f" {band}" if band else ""
    return f"{vector} ({score}{sev_text})"


_EUVD_VER_RE = re.compile(r"(<=|>=|<|>)?\s*[vV]?([0-9][0-9.]*)")


def _parse_euvd_version(pv) -> dict:
    """Parse an EUVD `product_version` range string into an affected-version spec {exact|min|max|fixed}
    for the version gate (core/version_match.py). EUVD uses free-text forms: '< 5.3' -> {fixed:5.3};
    '<= 5.3' -> {max}; '>= 4.8' -> {min}; '0 <V2606' -> {fixed:2606}; '4.8, < 5.3' -> {min:4.8, fixed:5.3};
    a bare '1.2.3' -> {exact}. The upper bound drives suppression, so it is captured first and a bare
    lower number only becomes {min} when an upper bound is present. {} when nothing parseable."""
    if not pv:
        return {}
    spec: dict = {}
    bare = None
    for clause in re.split(r"[,;/]", str(pv)):
        for m in _EUVD_VER_RE.finditer(clause):
            op, ver = m.group(1), m.group(2)
            if ver in ("0", ""):                 # a bare 0 lower bound carries no information
                continue
            if op == "<":
                spec["fixed"] = ver
            elif op == "<=":
                spec["max"] = ver
            elif op in (">=", ">"):
                spec["min"] = ver
            elif bare is None:
                bare = ver
    if bare:
        if "fixed" in spec or "max" in spec:
            spec.setdefault("min", bare)
        elif not spec:
            spec["exact"] = bare
    return spec


def _resolve_vendor_product(item: dict) -> tuple:
    vendors = item.get("enisaIdVendor") or []
    vendor = "unknown"
    if vendors and isinstance(vendors[0], dict):
        vendor = (vendors[0].get("vendor") or {}).get("name", "unknown")

    products = item.get("enisaIdProduct") or []
    product = "unknown"
    version_spec: dict = {}
    if products and isinstance(products[0], dict):
        product = (products[0].get("product") or {}).get("name", "unknown")
        version_spec = _parse_euvd_version(products[0].get("product_version"))

    return vendor or "unknown", product or "unknown", version_spec


def _passes_noise_filter(item: dict, vendor: str) -> bool:
    """The assigner-based structural filter — see module docstring for the evidence behind it."""
    assigner = (item.get("assigner") or "").strip().lower()
    if not assigner:
        return False
    if assigner in _KNOWN_OT_ASSIGNERS:
        return True
    vendor_lower = (vendor or "").lower()
    return bool(vendor_lower) and (assigner in vendor_lower or vendor_lower in assigner)


def _references(item: dict, euvd_id: str) -> Optional[list]:
    urls = _split_lines(item.get("references"))
    urls.append(f"https://euvd.enisa.europa.eu/vulnerability/{euvd_id}")
    return urls or None


def parse_euvd_items(items: list[dict], apply_noise_filter: bool = True) -> list[CheckMetadata]:
    """Parse a raw EUVD API `items` list into candidate CheckMetadata stubs. apply_noise_filter=False
    disables the assigner-based filter entirely (includes every item with a real CVE alias,
    regardless of who assigned it) — the widening lever, same shape as the CWE-allowlist levers
    in the other two feed modules, for whenever "as much coverage as possible" is wanted instead."""
    candidates = []
    for item in items:
        euvd_id = item.get("id")
        if not euvd_id:
            continue
        cve = _extract_cve(item.get("aliases"))
        if not cve:
            continue  # nothing to key a candidate on — skip rather than guess one

        vendor, product, version_spec = _resolve_vendor_product(item)
        if apply_noise_filter and not _passes_noise_filter(item, vendor):
            continue

        description = f"EUVD candidate — {euvd_id} {cve} ({vendor} {product}). {(item.get('description') or '').strip()}".strip()

        candidates.append(
            CheckMetadata(
                check_id=f"candidate-{cve.lower()}",
                protocol="unknown",
                kind=None,  # candidate stub — is_candidate() True, never executable
                cve_id=cve,
                severity=_format_severity(item),
                disclosure_status=DisclosureStatus.PUBLIC,  # EUVD entries are public by definition
                confidence=Confidence.LOW,
                fingerprint_precondition=(
                    {"vendor": vendor, "product": product, "version": version_spec}
                    if version_spec else {"vendor": vendor, "product": product}),
                description=description,
                references=_references(item, euvd_id),
            )
        )
    return candidates


def fetch_vendor_items(
    vendor: str, size: int = 50, from_date: Optional[str] = None, timeout: float = 30.0
) -> list[dict]:
    """The only network-touching function in this module — GET a page of results for one vendor.
    Deliberately kept OUT of automated test coverage (see tests/smoke_test_euvd_feed.py's own
    docstring) — manual verification only, same "don't make the regression suite depend on a
    live external resource" rule already applied to core/jvn_feed.py/core/csaf_feed.py."""
    params = f"vendor={urllib.parse.quote(vendor)}&size={min(size, 100)}"
    if from_date:
        params += f"&fromDate={urllib.parse.quote(from_date)}"
    url = f"{_EUVD_SEARCH_URL}?{params}"
    req = urllib.request.Request(url, headers={"User-Agent": "icsScanner-euvd-feed/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read())
    return data.get("items", []) or []


def write_candidates(candidates: list[CheckMetadata], out_dir: Union[str, Path]) -> list[Path]:
    """Same shape as the other three feed modules' write_candidates — one YAML file per
    candidate."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for meta in candidates:
        file_path = out_dir / f"{meta.check_id}.yaml"
        with open(file_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(metadata_to_yaml_dict(meta), f, sort_keys=False, allow_unicode=True)
        written.append(file_path)
    return written


def load_state(state_path: Union[str, Path]) -> dict:
    state_path = Path(state_path)
    if not state_path.exists():
        return {"processed": {}}
    with open(state_path, encoding="utf-8") as f:
        return json.load(f)


def save_state(state: dict, state_path: Union[str, Path]) -> None:
    state_path = Path(state_path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)


def ingest(
    vendor_names: Optional[list] = None,
    size: int = 50,
    from_date: Optional[str] = None,
    apply_noise_filter: bool = True,
    force: bool = False,
    state_path: Union[str, Path] = "lab-notes/euvd-sync-state.json",
    out_dir: Union[str, Path] = "checks/candidates",
) -> list[Path]:
    """Top-level entry point, mirrors core/cve_feed.py's / core/jvn_feed.py's / core/csaf_feed.py's
    ingest() shape. vendor_names defaults to the curated _ICS_VENDOR_NAMES allowlist; pass a
    subset for a smaller batch (matches the sweep's own phased pacing) or a wider list once more
    vendor names get verified against EUVD's own data.

    State-file dedup: an EUVD id already marked processed is skipped on a later call unless
    force=True, regardless of whether its candidate file still exists on disk — same load-bearing
    "tracks ever-surfaced, not file-still-exists" safety property as the other two state files.
    Tracked per EUVD id (item-level, like JVN) — EUVD's response shape is one item per CVE, not
    CSAF's one-advisory-bundles-many-CVEs shape.
    """
    vendor_names = vendor_names if vendor_names is not None else _ICS_VENDOR_NAMES
    state = load_state(state_path)
    processed = state.setdefault("processed", {})

    all_candidates = []
    for vendor in vendor_names:
        items = fetch_vendor_items(vendor, size=size, from_date=from_date)
        candidates = parse_euvd_items(items, apply_noise_filter=apply_noise_filter)
        for meta in candidates:
            euvd_id = meta.references[-1].rsplit("/", 1)[-1] if meta.references else meta.check_id
            # references[-1] is always the constructed EUVD detail-page URL we appended in
            # _references() — extract the EUVD id back out of it rather than re-deriving from
            # the CVE (a candidate's check_id is CVE-keyed, but state tracking is EUVD-id-keyed).
            if not force and euvd_id in processed:
                continue
            all_candidates.append(meta)
            processed[euvd_id] = datetime.now(timezone.utc).isoformat()

    written = write_candidates(all_candidates, out_dir)
    save_state(state, state_path)
    return written
