"""Report link enrichment.

Turns a check's structured metadata into the set of clickable report links the HTML/CSV reports show
for each finding, from four sources (user request, 2026-11-11):
  1. an auto-generated NVD link from `cve_id`,
  2. the `advisory_url` (the canonical vendor advisory / disclosure page),
  3. any http(s) URL in the free-text `references` list,
  4. a structured `links` list of {label, url}.

The reporter resolves a finding's links by check_id via LinkResolver (a lazily-built check_id ->
metadata map over the whole registry — armed checks AND candidates, since passive-CVE findings carry a
candidate id). No network access: NVD links are constructed, not fetched.
"""
from __future__ import annotations

from typing import Optional

_NVD = "https://nvd.nist.gov/vuln/detail/"


def build_links(cve_id: Optional[str] = None, references: Optional[list] = None,
                advisory_url: Optional[str] = None, links: Optional[list] = None) -> list:
    """Return an ordered, de-duplicated list of {"label", "url"} dicts for a finding."""
    out: list = []
    seen: set = set()

    def add(label: str, url: Optional[str]) -> None:
        if not url or not isinstance(url, str):
            return
        url = url.strip()
        if not url or url in seen:
            return
        seen.add(url)
        out.append({"label": label, "url": url})

    if cve_id:
        add(cve_id, _NVD + cve_id.strip())
    add("Advisory", advisory_url)
    for ref in (references or []):
        # a `references` entry is often "https://... — human description"; take just the URL token.
        if isinstance(ref, str):
            s = ref.strip()
            if s.lower().startswith(("http://", "https://")):
                add("Reference", s.split(None, 1)[0])
    for ln in (links or []):
        if isinstance(ln, dict) and ln.get("url"):
            add(str(ln.get("label") or "Link"), ln.get("url"))
    return out


class LinkResolver:
    """Maps a finding's check_id (or candidate id) to its report links, lazily loading the registry
    once. Fail-safe: any load problem yields an empty map, so reports still render (just without the
    extra links)."""

    def __init__(self, checks_dir: str = "checks"):
        self._checks_dir = checks_dir
        self._by_id: Optional[dict] = None

    def _load(self) -> dict:
        if self._by_id is None:
            self._by_id = {}
            try:
                from pathlib import Path
                from core.registry import load_check_metadata
                for yaml_file in Path(self._checks_dir).glob("**/*.yaml"):
                    try:
                        meta = load_check_metadata(yaml_file)  # CheckMetadata (armed AND candidates)
                    except Exception:
                        continue
                    if getattr(meta, "check_id", None):
                        self._by_id[meta.check_id] = meta
            except Exception:
                self._by_id = {}
        return self._by_id

    def for_finding(self, check_id: Optional[str], cve_id: Optional[str] = None) -> list:
        """Links for a finding: the check's metadata (references/advisory_url/links) plus an NVD link
        from cve_id (the finding's own cve_id wins; else the check's)."""
        meta = self._load().get(check_id) if check_id else None
        return build_links(
            cve_id=cve_id or (getattr(meta, "cve_id", None) if meta else None),
            references=getattr(meta, "references", None) if meta else None,
            advisory_url=getattr(meta, "advisory_url", None) if meta else None,
            links=getattr(meta, "links", None) if meta else None,
        )
