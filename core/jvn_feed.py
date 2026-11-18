"""JVN / MyJVN API ingestion -> human-reviewed candidate queue. Same candidate-stub discipline
as core/cve_feed.py: every entry becomes a CheckMetadata STUB (kind=None, is_candidate() True)
written to checks/candidates/, never an executable check. A human reviews each one before it's
promoted, same as any other candidate — see ../01-METHODOLOGY-AND-CHECKLISTS.md.

MyJVN is IPA/JPCERT's official, publicly documented API for JVN iPedia (jvndb.jvn.jp/apis/ —
verified directly 2026-08-16, not assumed): explicitly designed for third-party automated
consumption (no auth, no token, the docs invite building apps on it), unlike CNVD's ICS
sub-database which gates the same class of data behind a registered-account token wall (see
core/csaf_feed.py's sibling module for that source's status — CNVD is not implemented here or
anywhere in this project). Real-world precedent: the open-source scanner Vuls
(github.com/future-architect/vuls) uses this same API as one of its data sources.

Schema notes (from real fixtures in tests/fixtures/jvn-sample-*.xml, not assumed):
- One JVNDB-*.html entry usually maps to at most one CVE (unlike CSAF, where one advisory can
  bundle many) — some entries have no CVE at all (JVN-native "JVNVU#" advisories), so check_id
  is keyed on the JVNDB id, not the CVE, to always have a stable key.
- CWE id(s) appear as <sec:references> elements with an id="CWE-NNN" attribute and NO source
  attribute (CVE/NVD/CISA-KEV references DO have a source attribute) — this is how CWE-allowlist
  filtering below identifies them.
- <sec:cvss> may be entirely absent (a real observed case: a Siemens JVNVU-only advisory with no
  CVE and no CVSS at all) — severity is Optional, never invented.
- <sec:cpe> vendor/product names are frequently in Japanese even for international vendors (e.g.
  "シーメンス" for Siemens) — fingerprint_precondition carries whatever the feed gives, a human
  reviewing the candidate needs to resolve/translate this, same as the free-text description.
- Free-text title/description are Japanese-only through this API (feed="en" was tried live and
  returns nothing for getVulnOverviewList) — structured fields (CVE/CWE/CVSS/CPE/reference URLs)
  are language-neutral and don't need translation; the prose does. Flagged, not hidden.
"""

from __future__ import annotations

import json
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union
from urllib.parse import urlencode

from core.check import CheckMetadata, Confidence, DisclosureStatus
from core.registry import metadata_to_yaml_dict

import yaml

_NS = {
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "rss": "http://purl.org/rss/1.0/",
    "dc": "http://purl.org/dc/elements/1.1/",
    "sec": "http://jvn.jp/rss/mod_sec/3.0/",
}

# Mirrors core/csaf_feed.py's _DEFAULT_CWE_ALLOWLIST value-for-value (kept as a separate literal
# here, not imported — the two source modules are independent siblings, same as cve_feed.py, not
# a shared abstraction) — the CWE classes this project's existing check patterns
# (basic_auth_default_creds.py, telnet_default_creds.py, etc.) actually know how to probe.
# None or an empty set disables filtering entirely — the one lever to move for "as much coverage
# as possible" later (user's explicit instruction, 2026-08-16).
_DEFAULT_CWE_ALLOWLIST = {
    "CWE-798",  # hardcoded credentials
    "CWE-259",  # hardcoded password
    "CWE-306",  # missing authentication for critical function
    "CWE-287",  # improper authentication
    "CWE-521",  # weak password requirements
    "CWE-522",  # insufficiently protected credentials
}

# Curated ICS-vendor -> JVN vid lookup, seeded from vendors confirmed live via getVendorList
# 2026-08-16 (not guessed — see the plan file for the discovery process). Omron has a second,
# older vid (8880, cpe="omron_2") deliberately excluded here — not verified which is authoritative,
# flagged rather than silently picking one. Extend this dict as more vendors get verified; there's
# no live getVendorList call in ingest() itself (that endpoint returns ~35k rows across several
# paginated calls — too expensive to run per-ingest, this is a maintained allowlist instead, same
# shape as core/fingerprint.py's OUI table).
_ICS_VENDOR_IDS = {
    "Siemens": 584,
    "Schneider Electric": 766,
    "Mitsubishi Electric": 4499,
    "Omron": 11958,
}

_MYJVN_BASE = "https://jvndb.jvn.jp/myjvn"


def _cwe_ids(item: ET.Element) -> list[str]:
    ids = []
    for ref in item.findall("sec:references", _NS):
        cwe_id = ref.attrib.get("id")
        if cwe_id and cwe_id.startswith("CWE-") and "source" not in ref.attrib:
            ids.append(cwe_id)
    return ids


def _cve_id(item: ET.Element) -> Optional[str]:
    for ref in item.findall("sec:references", _NS):
        if ref.attrib.get("source") == "CVE":
            return ref.attrib.get("id")
    return None


def _severity(item: ET.Element) -> Optional[str]:
    cvss = item.find("sec:cvss", _NS)
    if cvss is None:
        return None
    vector = cvss.attrib.get("vector", "")
    raw_score = cvss.attrib.get("score", "")
    sev = cvss.attrib.get("severity", "").upper()
    if not vector or not raw_score:
        return None
    # JVN's raw score is sometimes a bare integer ("7", not "7.0") — every hand-written check's
    # severity string in this checkout carries a decimal, and core/reporter.py:_severity_band()
    # relies on that (a looser number regex was tried and reverted there — see its docstring —
    # because it started false-matching incidental integers in hedged placeholder text). Normalize
    # here, at the actual source of the inconsistent format, instead of loosening a shared regex.
    try:
        score = f"{float(raw_score):.1f}"
    except ValueError:
        score = raw_score
    return f"{vector} ({score} {sev})".strip()


def _vendor_product(item: ET.Element) -> tuple[str, str]:
    cpe = item.find("sec:cpe", _NS)
    if cpe is None:
        return "unknown", "unknown"
    return cpe.attrib.get("vendor", "unknown"), cpe.attrib.get("product", "unknown")


def _cpe_version(item: ET.Element) -> Optional[str]:
    """A specific affected version from the sec:cpe URI text (e.g. cpe:/a:vendor:product:1.2.3), for
    the version gate. The `version` attribute here is the CPE SPEC version (2.2/2.3), not the product
    version — the product version is in the element text. None when absent/wildcard."""
    cpe = item.find("sec:cpe", _NS)
    if cpe is None or not (cpe.text or "").strip():
        return None
    from core.version_match import version_from_cpe
    return version_from_cpe(cpe.text.strip())


def _references(item: ET.Element) -> list[str]:
    urls = [ref.text.strip() for ref in item.findall("sec:references", _NS) if ref.text and ref.text.strip()]
    link = item.find("rss:link", _NS)
    if link is not None and link.text:
        urls.append(link.text.strip())
    return urls


def parse_jvn_overview_xml(
    xml_bytes: Union[str, bytes], cwe_allowlist: Optional[set] = _DEFAULT_CWE_ALLOWLIST
) -> list[CheckMetadata]:
    """Parse one getVulnOverviewList response (a page of <item>s) into candidate CheckMetadata
    stubs. cwe_allowlist=None or an empty set disables CWE filtering entirely (includes every
    item regardless of CWE, or lack of one)."""
    root = ET.fromstring(xml_bytes)
    candidates = []
    for item in root.findall("rss:item", _NS):
        identifier_el = item.find("sec:identifier", _NS)
        identifier = identifier_el.text.strip() if identifier_el is not None and identifier_el.text else None
        if not identifier:
            continue  # no stable id to key a candidate on — skip rather than guess one

        cwe_ids = _cwe_ids(item)
        if cwe_allowlist:
            if not any(c in cwe_allowlist for c in cwe_ids):
                continue

        title_el = item.find("rss:title", _NS)
        title = title_el.text.strip() if title_el is not None and title_el.text else ""
        vendor, product = _vendor_product(item)
        cve = _cve_id(item)
        cwe_note = f" [{', '.join(cwe_ids)}]" if cwe_ids else ""
        precond = {"vendor": vendor, "product": product}
        ver = _cpe_version(item)  # version gate enrichment from the CPE URI, when specific
        if ver:
            precond["version"] = {"exact": ver}

        candidates.append(
            CheckMetadata(
                check_id=f"candidate-{identifier.lower()}",
                protocol="unknown",
                kind=None,  # candidate stub — is_candidate() True, never executable
                cve_id=cve,
                severity=_severity(item),
                disclosure_status=DisclosureStatus.PUBLIC,
                confidence=Confidence.LOW,
                fingerprint_precondition=dict(precond),
                description=(
                    f"JVN candidate — {identifier}{cwe_note} ({vendor} {product}). "
                    f"Title (Japanese, not translated): {title}"
                ),
                references=_references(item) or None,
            )
        )
    return candidates


def fetch_vuln_overview_xml(
    vendor_id: Optional[int] = None, start_item: int = 1, max_count_item: int = 50, feed: str = "hnd"
) -> bytes:
    """The only network-touching function in this module — GETs one page of
    getVulnOverviewList. Kept out of automated test coverage deliberately (see
    tests/smoke_test_jvn_feed.py's own docstring) — the standard "don't make the regression
    suite depend on a live external resource" rule already applied to core/csaf_feed.py."""
    params = {"method": "getVulnOverviewList", "feed": feed, "startItem": start_item, "maxCountItem": max_count_item}
    if vendor_id is not None:
        params["vendorId"] = vendor_id
    url = f"{_MYJVN_BASE}?{urlencode(params)}"
    req = urllib.request.Request(url, headers={"User-Agent": "icsScanner-jvn-feed/1.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read()


def write_candidates(candidates: list[CheckMetadata], out_dir: Union[str, Path]) -> list[Path]:
    """Same shape as core/cve_feed.py's write_candidates — one YAML file per candidate."""
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
    vendor_ids: Optional[dict] = None,
    cwe_allowlist: Optional[set] = _DEFAULT_CWE_ALLOWLIST,
    max_count_item: int = 50,
    force: bool = False,
    state_path: Union[str, Path] = "lab-notes/jvn-sync-state.json",
    out_dir: Union[str, Path] = "checks/candidates",
) -> list[Path]:
    """Top-level entry point, mirrors core/cve_feed.py's ingest_csv() / core/csaf_feed.py's
    planned ingest() shape. vendor_ids defaults to the curated _ICS_VENDOR_IDS allowlist; pass a
    subset for a smaller batch (matches the default-creds sweep's own phased pacing — e.g. 2
    vendors this session, more later), or a wider dict once more vendor vids get verified.

    State-file dedup: an advisory id already marked processed is skipped on a later call unless
    force=True, regardless of whether its candidate file still exists on disk — a human may have
    already reviewed and deleted a rejected candidate; re-running must never resurrect it just
    because the file's gone. Same load-bearing safety property as core/csaf_feed.py's plan.
    """
    vendor_ids = vendor_ids if vendor_ids is not None else _ICS_VENDOR_IDS
    state = load_state(state_path)
    processed = state.setdefault("processed", {})

    all_candidates = []
    for vendor_name, vid in vendor_ids.items():
        xml_bytes = fetch_vuln_overview_xml(vendor_id=vid, max_count_item=max_count_item)
        candidates = parse_jvn_overview_xml(xml_bytes, cwe_allowlist=cwe_allowlist)
        for meta in candidates:
            identifier = meta.check_id[len("candidate-"):]
            if not force and identifier in processed:
                continue
            all_candidates.append(meta)
            processed[identifier] = datetime.now(timezone.utc).isoformat()

    written = write_candidates(all_candidates, out_dir)
    save_state(state, state_path)
    return written
