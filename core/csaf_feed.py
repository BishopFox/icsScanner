"""CSAF 2.0 advisory ingestion -> human-reviewed candidate queue. Same candidate-stub discipline
as core/cve_feed.py and core/jvn_feed.py: every CVE that passes the CWE allowlist becomes a
CheckMetadata STUB (kind=None, is_candidate() True) written to checks/candidates/, never an
executable check.

CSAF 2.0 (Common Security Advisory Framework) is a real OASIS standard, not CISA-specific —
verified directly against `github.com/cisagov/CSAF` (a real, live repo, not assumed): 3,877
individual CISA OT advisories under csaf_files/OT/white, each a full CSAF 2.0 document, with a
single ROLIE feed manifest (cisa-csaf-ot-feed-tlp-white.json) enumerating all of them. The
parsing core below (parse_csaf_advisory) works on any valid CSAF 2.0 document, not just CISA's —
the CISA-specific feed URL is one CsafFeedSource entry, not baked into the parser, so a second
government's feed (if also CSAF-shaped, which the standard makes likely) is one more entry, not
new parsing code.

Schema notes (from a real fixture, tests/fixtures/csaf-sample-icsa-25-007-01.json — ICSA-25-007-01,
ABB ASPECT, 26 CVEs, not hand-built):
- One advisory's `vulnerabilities[]` can hold many CVEs (26 in the sample) — unlike JVN, where
  one entry is usually at most one CVE.
- `cwe.id`/`cwe.name` is a clean, structured field — no free-text guessing needed.
- `scores[].cvss_v3` gives a pre-parsed `vectorString`/`baseScore`/`baseSeverity` — formatted
  into the same "<vector> (<score> <SEVERITY>)" convention hand-written checks already use, which
  core/reporter.py:_severity_band() already parses correctly, no changes needed there.
- `product_tree` is a nested branches[] tree: vendor -> product_family -> product_name ->
  product_version/product_version_range, with the leaf product.product_id CVEs reference via
  product_status.known_affected/.fixed. Walked once per advisory into a flat
  product_id -> (vendor, product_name) lookup — "product_name" is the category-level name (e.g.
  "ASP-ENT-x"), not the full version-range-suffixed leaf name (e.g. "ASP-ENT-x <=3.08.01"), since
  fingerprint_precondition needs a stable identity to match against, not a version string.
- `notes[category=="description"].text` gives the per-CVE description; `references[].url` gives
  the per-CVE reference list.
"""

from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from core.check import CheckMetadata, Confidence, DisclosureStatus
from core.registry import metadata_to_yaml_dict

import yaml

# The CWE classes this project's existing check patterns (basic_auth_default_creds.py,
# telnet_default_creds.py, the OPC-UA anon-write checks, etc.) actually know how to probe.
# `parse_csaf_advisory()` takes cwe_allowlist as a parameter — None or an empty set disables
# filtering entirely. This is the one lever to move for "as much coverage as possible" later
# (user's explicit instruction) — no redesign required, just widen or drop the set. Mirrors
# core/jvn_feed.py's _DEFAULT_CWE_ALLOWLIST value-for-value (separate literal, not shared code —
# independent sibling modules, same as cve_feed.py/jvn_feed.py already are).
_DEFAULT_CWE_ALLOWLIST = {
    "CWE-798",  # hardcoded credentials
    "CWE-259",  # hardcoded password
    "CWE-306",  # missing authentication for critical function
    "CWE-287",  # improper authentication
    "CWE-521",  # weak password requirements
    "CWE-522",  # insufficiently protected credentials
}


@dataclass
class CsafFeedSource:
    name: str
    manifest_url: str


# CISA is the first pluggable source, not the only one — see the module docstring. Verified live
# this session (gh api + raw fetches): 3,877 advisories under this manifest.
_CISA_OT_WHITE = CsafFeedSource(
    "CISA OT (TLP:WHITE)",
    "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json",
)


_CSAF_VER_RE = re.compile(r"(<=|>=|<|>)?\s*v?([0-9][0-9.]*)")


def _parse_csaf_version(category: Optional[str], name: Optional[str]) -> dict:
    """Turn a CSAF version branch into an affected-version spec {exact|min|max|fixed} (see
    core/version_match.py). product_version '3.08.03' -> {exact}; product_version_range '<=3.08.01'
    -> {max}; '<3.1' -> {fixed}; '>=3.08.02' -> {min}; 'A to B' -> {min,max}. {} when unparseable."""
    if not name:
        return {}
    text = str(name).strip()
    if category == "product_version":
        return {"exact": text}
    parts = re.split(r"\s+to\s+|\s+-\s+", text)
    if len(parts) == 2:
        lo, hi = _CSAF_VER_RE.match(parts[0].strip()), _CSAF_VER_RE.match(parts[1].strip())
        if lo and hi:
            return {"min": lo.group(2), "max": hi.group(2)}
    m = _CSAF_VER_RE.match(text)
    if not m:
        return {}
    op, ver = m.group(1), m.group(2)
    if op == "<=":
        return {"max": ver}
    if op == "<":
        return {"fixed": ver}
    if op in (">=", ">"):
        return {"min": ver}
    return {"exact": ver}


def _walk_product_tree(node: dict, vendor: Optional[str], product: Optional[str], out: dict) -> None:
    """Recursively walk a CSAF product_tree branches[] node, tracking the nearest ancestor
    vendor (category=="vendor") and product_name (category=="product_name") as we descend, and
    recording product_id -> (vendor, product, version_spec) whenever a leaf's own `product` dict
    appears — the leaf sits under a product_version / product_version_range branch whose name is the
    version/range string, parsed into the affected-version spec."""
    category = node.get("category")
    if category == "vendor":
        vendor = node.get("name", vendor)
    elif category == "product_name":
        product = node.get("name", product)

    leaf_product = node.get("product")
    if isinstance(leaf_product, dict) and leaf_product.get("product_id"):
        vspec = (_parse_csaf_version(category, node.get("name"))
                 if category in ("product_version", "product_version_range") else {})
        out[leaf_product["product_id"]] = (vendor or "unknown", product or "unknown", vspec)

    for child in node.get("branches", []) or []:
        _walk_product_tree(child, vendor, product, out)


def _build_product_id_lookup(doc: dict) -> dict:
    lookup: dict = {}
    product_tree = doc.get("product_tree") or {}
    for branch in product_tree.get("branches", []) or []:
        _walk_product_tree(branch, None, None, lookup)
    return lookup


def _resolve_vendor_product(vuln: dict, product_lookup: dict) -> tuple:
    """Resolve a single (vendor, product) pair for a vulnerability's fingerprint_precondition
    from its affected product IDs. Multiple affected products can name different vendors in
    principle (a multi-vendor advisory) — this project's fingerprint_precondition is exact-match
    single-vendor/product, so the FIRST resolved pair is used, same "don't over-engineer beyond
    what's needed" call cve_feed.py already makes with its own single vendor/product fields."""
    status = vuln.get("product_status", {}) or {}
    # Prefer a known_affected product — ITS version range is the affected range we gate on.
    for pid in status.get("known_affected", []) or []:
        if pid in product_lookup:
            return product_lookup[pid]  # (vendor, product, version_spec)
    # Fall back to a fixed product for identity only (a fix range is not the affected range).
    for pid in status.get("fixed", []) or []:
        if pid in product_lookup:
            vendor, product, _ = product_lookup[pid]
            return vendor, product, {}
    return "unknown", "unknown", {}


def _format_severity(vuln: dict) -> Optional[str]:
    scores = vuln.get("scores") or []
    if not scores:
        return None
    cvss = scores[0].get("cvss_v3") or scores[0].get("cvss_v2")
    if not cvss:
        return None
    vector = cvss.get("vectorString")
    raw_score = cvss.get("baseScore")
    severity = cvss.get("baseSeverity")
    if not vector or raw_score is None:
        return None
    # CSAF's baseScore is sometimes a bare JSON integer (10, not 10.0 — confirmed in the real
    # fixture, CVE-2024-51545) — core/reporter.py:_severity_band()'s number regex requires a
    # decimal point (see its own docstring for why a looser regex was tried and reverted: it
    # false-matched incidental integers in hedged placeholder text). Normalize here, at the
    # actual source of the inconsistent format, same fix pattern already applied for JVN's
    # identical issue in core/jvn_feed.py:_severity().
    try:
        score = f"{float(raw_score):.1f}"
    except (TypeError, ValueError):
        score = str(raw_score)
    sev_text = f" {severity}" if severity else ""
    return f"{vector} ({score}{sev_text})"


def _description_text(vuln: dict) -> str:
    for note in vuln.get("notes", []) or []:
        if note.get("category") == "description":
            return (note.get("text") or "").strip()
    return ""


def _references(vuln: dict, advisory_id: str, source_url: str) -> list:
    urls = [r["url"] for r in vuln.get("references", []) or [] if r.get("url")]
    if source_url:
        urls.append(source_url)
    return urls or None


def parse_csaf_advisory(
    doc: dict, source_url: str = "", cwe_allowlist: Optional[set] = _DEFAULT_CWE_ALLOWLIST
) -> list[CheckMetadata]:
    """Parse one CSAF 2.0 document into candidate CheckMetadata stubs. Works on any valid CSAF
    2.0 document, not just CISA's. cwe_allowlist=None or an empty set disables CWE filtering
    entirely (includes every CVE regardless of CWE, or lack of one)."""
    tracking = (doc.get("document") or {}).get("tracking") or {}
    advisory_id = tracking.get("id", "unknown")
    product_lookup = _build_product_id_lookup(doc)

    candidates = []
    for vuln in doc.get("vulnerabilities", []) or []:
        cve = vuln.get("cve")
        if not cve:
            continue  # nothing to key a candidate on — skip rather than guess one

        cwe = vuln.get("cwe") or {}
        cwe_id = cwe.get("id")
        if cwe_allowlist and cwe_id not in cwe_allowlist:
            continue

        vendor, product, version_spec = _resolve_vendor_product(vuln, product_lookup)
        cwe_note = f" [{cwe_id}: {cwe.get('name')}]" if cwe_id else ""
        description = (
            f"CSAF candidate — {advisory_id} {cve}{cwe_note} ({vendor} {product}). "
            f"{_description_text(vuln)}"
        ).strip()

        candidates.append(
            CheckMetadata(
                check_id=f"candidate-{cve.lower()}",
                protocol="unknown",
                kind=None,  # candidate stub — is_candidate() True, never executable
                cve_id=cve,
                severity=_format_severity(vuln),
                disclosure_status=DisclosureStatus.PUBLIC,  # CISA/CSAF advisories are public by definition
                confidence=Confidence.LOW,
                fingerprint_precondition=(
                    {"vendor": vendor, "product": product, "version": version_spec}
                    if version_spec else {"vendor": vendor, "product": product}),
                description=description,
                references=_references(vuln, advisory_id, source_url),
            )
        )
    return candidates


def fetch_feed_entries(source: CsafFeedSource = _CISA_OT_WHITE) -> list[dict]:
    """The first of two network-touching functions in this module — GET the ROLIE feed manifest,
    return its feed.entry[] list. Deliberately kept OUT of automated test coverage (see
    tests/smoke_test_csaf_feed.py's own docstring) — manual verification only, same
    "don't make the regression suite depend on a live external resource" rule already applied
    to core/jvn_feed.py's fetch_vuln_overview_xml()."""
    req = urllib.request.Request(source.manifest_url, headers={"User-Agent": "icsScanner-csaf-feed/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        manifest = json.loads(resp.read())
    return manifest.get("feed", {}).get("entry", []) or []


def fetch_advisory(entry: dict) -> dict:
    """The second network-touching function — GET the advisory JSON an entry's content.src
    points at. Same manual-verification-only status as fetch_feed_entries()."""
    src = (entry.get("content") or {}).get("src")
    req = urllib.request.Request(src, headers={"User-Agent": "icsScanner-csaf-feed/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def select_entries(
    entries: list, since: Optional[str] = None, year: Optional[int] = None, limit: Optional[int] = None
) -> list:
    """Filter/sort manifest entries BEFORE any advisory is fetched, so a batch run only pulls
    what it needs — matches the default-creds sweep's own phased pacing, not a bulk dump.
    Composable: year=2025 + limit=50 = the 50 newest 2025 advisories. Sorted newest-first by
    `updated` (falling back to `published`)."""
    def _sort_key(e: dict) -> str:
        return e.get("updated") or e.get("published") or ""

    filtered = list(entries)
    if since:
        filtered = [e for e in filtered if _sort_key(e) >= since]
    if year:
        year_str = str(year)
        filtered = [e for e in filtered if _sort_key(e)[:4] == year_str]
    filtered.sort(key=_sort_key, reverse=True)
    if limit:
        filtered = filtered[:limit]
    return filtered


def write_candidates(candidates: list[CheckMetadata], out_dir: Union[str, Path]) -> list[Path]:
    """Same shape as core/cve_feed.py's / core/jvn_feed.py's write_candidates — one YAML file
    per candidate."""
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
    source: CsafFeedSource = _CISA_OT_WHITE,
    cwe_allowlist: Optional[set] = _DEFAULT_CWE_ALLOWLIST,
    since: Optional[str] = None,
    year: Optional[int] = None,
    limit: Optional[int] = None,
    force: bool = False,
    state_path: Union[str, Path] = "lab-notes/csaf-sync-state.json",
    out_dir: Union[str, Path] = "checks/candidates",
) -> list[Path]:
    """Top-level entry point, mirrors core/cve_feed.py's ingest_csv() / core/jvn_feed.py's
    ingest() shape. Fetches the feed manifest, batches via select_entries(), fetches+parses each
    selected advisory, and writes any not-already-processed candidates.

    State-file dedup: an advisory ID already marked processed is skipped on a later call unless
    force=True, regardless of whether its candidate files still exist on disk — a human may have
    already reviewed and deleted a rejected candidate; re-running must never resurrect it just
    because the file's gone. Same load-bearing safety property as core/jvn_feed.py's ingest().
    Tracks by ADVISORY id (one CISA advisory can hold many CVEs) — an advisory is only skipped
    once every CVE in it has already been surfaced in a prior run.
    """
    state = load_state(state_path)
    processed = state.setdefault("processed", {})

    entries = fetch_feed_entries(source)
    selected = select_entries(entries, since=since, year=year, limit=limit)

    all_candidates = []
    for entry in selected:
        advisory_id = entry.get("id", "")
        if not force and advisory_id in processed:
            continue
        doc = fetch_advisory(entry)
        source_url = (entry.get("content") or {}).get("src", "")
        candidates = parse_csaf_advisory(doc, source_url=source_url, cwe_allowlist=cwe_allowlist)
        all_candidates.extend(candidates)
        processed[advisory_id] = datetime.now(timezone.utc).isoformat()

    written = write_candidates(all_candidates, out_dir)
    save_state(state, state_path)
    return written
