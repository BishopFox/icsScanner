"""Offline reporter: reads JSONL check-result output and renders text/HTML/CSV summaries.
Adapted from icsFuzzer's core/reporter.py (FuzzReporter). HTML and CSV report generation are
Milestone 5 work (00-PROJECT-CHARTER.md § Milestones), built 2026-08-16 alongside a diagnostic-
logging pass (core/logger.py:ScanLogger.log_event() — run_start/run_end/aliveness_failure/
credential_error sentinel records) so a report can show not just findings but what a run
actually covered and what went wrong, not just per-check outcomes.

Single aggregation implementation (build_summary()) backs the CLI text summary, the HTML/CSV
renderers, AND web/server.py's job-status JSON — previously web/server.py had its own parallel
in-memory aggregation that duplicated this logic; unified onto "read the JSONL after it's
written" since re-reading a few-hundred-KB log costs low-single-digit milliseconds next to the
scan itself, and every future field would otherwise need to be added twice.
"""

from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Optional

# CVSS spec-version prefixes ("CVSS 3.1", "CVSS:3.1", "CVSS 4.0") must be stripped before
# searching for the actual score — see _severity_band()'s docstring for why this matters.
_CVSS_VERSION_RE = re.compile(r"CVSS:?\s*\d+\.\d+")
_NUMBER_RE = re.compile(r"\d+\.\d+")
_BAND_WORDS = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}


_LINK_RESOLVER = None


def _link_resolver():
    """Lazily-built, process-cached registry-backed link resolver (core/links.py)."""
    global _LINK_RESOLVER
    if _LINK_RESOLVER is None:
        from core.links import LinkResolver
        _LINK_RESOLVER = LinkResolver()
    return _LINK_RESOLVER


def _links_from_refs(references):
    """Fallback when a finding's check is no longer in the registry: build links from the log's own
    references (same trimming/filtering as the resolver)."""
    from core.links import build_links
    return build_links(references=references)


class ScanReporter:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)

    def _latest_log(self) -> Optional[Path]:
        logs = sorted(self.output_dir.glob("icsscanner-*.jsonl"), reverse=True)
        return logs[0] if logs else None

    @staticmethod
    def _read_records(path: Path) -> list[dict]:
        records = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return records

    @staticmethod
    def _severity_band(raw: Optional[str]) -> tuple[str, Optional[float]]:
        """Buckets an EXISTING severity value into the public CVSS score->band table — never
        invents a score (02-DISCLOSURE-PLAYBOOK.md: "CVSS — copied, not re-derived"). `severity`
        is free text in this project (only 15/98 real checks set it at all, in wildly
        inconsistent formats: bare words like "critical", "10.0 CRITICAL (score only...)", full
        CVSS vector strings, or hedged placeholders like "score not confirmed..."), so this is
        deliberately conservative:

        1. A bare band word ("critical"/"high"/"medium"/"low") matches directly.
        2. Strip any CVSS SPEC-VERSION prefix ("CVSS 3.1", "CVSS:3.1") before searching for a
           score. Without this, a naive first-number search grabs the version number instead of
           the score on most real vector-string-shaped severity values in this checkout (e.g.
           "CVSS:3.1/AV:N/.../A:H (7.5 HIGH...)" would match "3.1", not "7.5") — a real
           correctness bug, not cosmetic, since it silently misclassifies High/Critical findings
           as Low (3.1 falls in the 0.1-3.9 band).
        3. No confident number found (e.g. "score not confirmed in this pass...") -> "Unscored",
           never guessed, never dropped. Given most checks here are default-creds findings with
           no CVE at all, "Unscored" is legitimately the majority bucket — accurate, not a bug.

        Known, documented limitation: one check embeds two scores from two different CVSS
        versions (e.g. "CVSS 3.1: 8.6 / CVSS 4.0: 9.3") — this picks the first-listed one
        deterministically. The raw string is always shown in full in the report regardless of
        which one drives the rollup bucket, so nothing is hidden, just bucketed by one of the two.

        Near-miss caught 2026-08-16 via a live JVN/MyJVN fixture (core/jvn_feed.py): JVN's raw
        API returns whole-number CVSS scores like `score="7"` with no decimal point, which this
        regex doesn't match — first "fix" attempted was loosening `_NUMBER_RE` to accept bare
        integers too, which immediately regressed: hedged placeholder text containing incidental
        integers (e.g. "...see CISA ICSA-17-024-01") started false-matching "17" as a score.
        Reverted. Fixed at the actual source instead — core/jvn_feed.py normalizes every score to
        always carry a decimal (`7` -> `7.0`) before building the severity string, matching the
        format every hand-written check in this checkout already uses — not touched here.

        Same issue recurred 2026-08-16 with a THIRD source, CISA's CSAF feed (core/csaf_feed.py)
        — its baseScore field is sometimes a bare JSON integer too (confirmed: CVE-2024-51545's
        baseScore is the int `10`, not `10.0`). Same fix, same place: normalized at the source in
        csaf_feed.py:_format_severity(), not here — two independent external sources hitting the
        identical gap is a good sign this regex-tightening-here approach really was the wrong
        fix, and normalize-at-the-source really is the right general pattern for this class of
        issue.
        """
        if not raw:
            return "Unscored", None
        stripped = raw.strip().lower()
        if stripped in _BAND_WORDS:
            return _BAND_WORDS[stripped], None
        remainder = _CVSS_VERSION_RE.sub("", raw)
        m = _NUMBER_RE.search(remainder)
        if m:
            score = float(m.group())
            if score >= 9.0:
                return "Critical", score
            if score >= 7.0:
                return "High", score
            if score >= 4.0:
                return "Medium", score
            if score >= 0.1:
                return "Low", score
        return "Unscored", None

    def build_summary(self, log_path: Optional[Path] = None) -> Optional[dict]:
        """Single aggregation implementation — summarize(), to_html(), to_csv(), and
        web/server.py's job.summary all call this. Returns None if no log file / no check
        records exist (callers decide how to surface that — a print for summarize(), a
        ValueError for the file-writing renderers)."""
        path = log_path or self._latest_log()
        if not path or not path.exists():
            return None

        records = self._read_records(path)
        check_records = [r for r in records if r.get("check_id") and not r.get("type")]
        if not check_records:
            return None
        run_events = [r for r in records if r.get("type")]

        confirmed = [r for r in check_records if r.get("status") == "confirmed"]
        fp_only = [r for r in check_records if r.get("status") == "likely-affected-fingerprint-only"]
        errors = [r for r in check_records if r.get("status") == "error"]

        by_protocol: dict[str, int] = defaultdict(int)
        by_confidence: dict[str, int] = defaultdict(int)
        by_severity: dict[str, int] = defaultdict(int)

        for r in check_records:
            by_protocol[r.get("protocol", "unknown")] += 1
            if r.get("status") == "confirmed":
                by_confidence[r.get("confidence", "unknown")] += 1
                band, _ = self._severity_band(r.get("severity"))
                by_severity[band] += 1

        # confirmed + fingerprint-only — not-applicable/clean-error stay as rollup counts only,
        # matching what the CLI/web summary have always shown; itemizing all ~98 not-applicable
        # rows per target would be noise, not signal.
        from core.exploit_intel import enrich as _exploit_enrich
        findings = []
        for r in confirmed + fp_only:
            band, score = self._severity_band(r.get("severity"))
            intel = _exploit_enrich(r.get("cve_id"), band)
            findings.append({
                "kev": intel["kev"],
                "kev_ransomware": intel["kev_ransomware"],
                "epss": intel["epss"],
                "epss_pct": intel["epss_pct"],
                "priority_label": intel["priority_label"],
                "_priority_key": intel["priority_key"],
                "check_id": r.get("check_id"),
                "target": r.get("target"),
                "protocol": r.get("protocol"),
                "status": r.get("status"),
                "confidence": r.get("confidence"),
                "cve_id": r.get("cve_id"),
                "can_id": r.get("can_id"),
                "severity_raw": r.get("severity"),
                "severity_band": band,
                "severity_score": score,
                "references": r.get("references") or [],
                # Report links: advisory_url + http(s) references + structured links (the NVD link
                # from cve_id is rendered separately in the CVE column). Resolved from the check's
                # metadata; see core/links.py. Falls back to the log's own references if a check is
                # no longer in the registry.
                "links": (_link_resolver().for_finding(r.get("check_id"), cve_id=None)
                          or _links_from_refs(r.get("references"))),
                "destructive": bool(r.get("destructive")),
                "description": r.get("description"),
                "duration_ms": r.get("duration_ms"),
                "evidence_hex": r.get("evidence_hex"),
            })

        # Rank by real-world exploitability: confirmed over fingerprint-only, then KEV/EPSS priority,
        # then CVSS score — so known-exploited CVEs surface first (see core/exploit_intel.py).
        findings.sort(key=lambda f: (f["status"] == "confirmed", f.get("_priority_key", 0),
                                     f.get("severity_score") or 0), reverse=True)

        return {
            "log_path": path,
            "total": len(check_records),
            "confirmed": len(confirmed),
            "fingerprint_only": len(fp_only),
            "errors": len(errors),
            "by_protocol": dict(sorted(by_protocol.items())),
            "by_confidence": dict(sorted(by_confidence.items(), key=lambda kv: -kv[1])),
            "by_severity": dict(sorted(by_severity.items(), key=lambda kv: -kv[1])),
            "findings": findings,
            "run_events": run_events,
        }

    def summarize(self, log_path: Optional[Path] = None) -> None:
        summary = self.build_summary(log_path)
        if summary is None:
            path = log_path or self._latest_log()
            if not path or not path.exists():
                print("[report] No log file found.")
            else:
                print("[report] No check records found in log.")
            return

        confirmed_findings = [f for f in summary["findings"] if f["status"] == "confirmed"]

        print("\n" + "=" * 60)
        print(" icsScanner — Scan Report")
        print("=" * 60)
        print(f"  Log file:              {summary['log_path'].name}")
        print(f"  Total checks run:      {summary['total']}")
        print(f"  Confirmed:             {summary['confirmed']}")
        print(f"  Fingerprint-only:      {summary['fingerprint_only']}  (destructive, not actively probed)")
        print(f"  Errors:                {summary['errors']}")

        if summary["by_protocol"]:
            print("\n  By Protocol:")
            for proto, count in summary["by_protocol"].items():
                print(f"    {proto:<14} {count}")

        if confirmed_findings:
            print("\n  Confirmed findings (triage):")
            print(
                f"  {'Check ID':<28} {'CVE/CAN':<24} {'Confidence':<10} "
                f"{'Protocol':<10} Description"
            )
            print("  " + "-" * 100)
            for f in confirmed_findings:
                cve = f["cve_id"] or f["can_id"] or "n/a"
                print(
                    f"  {f['check_id']:<28} {cve:<24} {f['confidence'] or '?':<10} "
                    f"{f['protocol'] or '?':<10} {(f['description'] or '?')[:50]}"
                )

        if summary["by_confidence"]:
            print("\n  Confirmed-finding Confidence Breakdown:")
            for level, count in summary["by_confidence"].items():
                print(f"    {level:<10} {count}")

        print("=" * 60 + "\n")

    def to_html(
        self,
        log_path: Optional[Path] = None,
        output_path: Optional[Path] = None,
        include_evidence: bool = False,
    ) -> Path:
        """Self-contained HTML (inline <style>, no CDN) — dark-theme tokens/status classes
        match web/page.py for visual consistency with the web UI. Raises ValueError if no
        log/records found (a file-writing method can't silently no-op the way summarize()'s
        print can)."""
        summary = self.build_summary(log_path)
        if summary is None:
            raise ValueError(f"no check records found for {log_path or self._latest_log()}")

        path = summary["log_path"]
        out = output_path or path.with_suffix(".html")
        html = _render_html(summary, include_evidence=include_evidence)
        out.write_text(html, encoding="utf-8")
        return out

    def to_csv(
        self,
        log_path: Optional[Path] = None,
        output_path: Optional[Path] = None,
        include_evidence: bool = False,
    ) -> Path:
        """One row per finding (confirmed + fingerprint-only, same set to_html uses) — no
        rollup/summary block mixed in, CSV stays one-shape-per-row for spreadsheet tools.
        `references` semicolon-joined (a CSV cell can't hold a list). Raises ValueError if no
        log/records found."""
        summary = self.build_summary(log_path)
        if summary is None:
            raise ValueError(f"no check records found for {log_path or self._latest_log()}")

        path = summary["log_path"]
        out = output_path or path.with_suffix(".csv")

        fields = [
            "check_id", "target", "protocol", "status", "confidence",
            "cve_id", "nvd_url", "kev", "kev_ransomware", "epss", "priority_label",
            "can_id", "severity_raw", "severity_band",
            "references", "links", "destructive", "description", "duration_ms",
        ]
        if include_evidence:
            fields.append("evidence_hex")

        with open(out, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for finding in summary["findings"]:
                row = dict(finding)
                row["references"] = "; ".join(row.get("references") or [])
                # nvd_url from cve_id + the resolved advisory/reference/custom links, for SIEM ingestion.
                row["nvd_url"] = (f"https://nvd.nist.gov/vuln/detail/{finding['cve_id']}"
                                  if finding.get("cve_id") else "")
                row["links"] = "; ".join(l["url"] for l in finding.get("links", []))
                if not include_evidence:
                    row.pop("evidence_hex", None)
                writer.writerow(row)

        return out

    # ── Discovery (core/discovery.py) — a separate aggregation path, not merged into
    # build_summary(). Discovery logs have no check_id at all (only device_discovered/
    # discovery_run_summary events), so they don't fit build_summary()'s check_records filter
    # (`r.get("check_id") and not r.get("type")`) — a device record is exactly the opposite
    # shape. Written 2026-08-25 alongside core/discovery.py.

    def build_discovery_summary(self, log_path: Optional[Path] = None) -> Optional[dict]:
        path = log_path or self._latest_log()
        if not path or not path.exists():
            return None
        records = self._read_records(path)
        devices = [r for r in records if r.get("type") == "device_discovered"]
        run_summary = next((r for r in records if r.get("type") == "discovery_run_summary"), None)
        if not devices and run_summary is None:
            return None

        by_method: dict[str, int] = defaultdict(int)
        for d in devices:
            by_method[d.get("method", "unknown")] += 1

        # Observed-activity section: categorized passive detections logged from a Zeek notice.log,
        # correlated back to the discovered inventory. Deliberately outside the original posture-only
        # design — see core/detections.py. Omitted (None) when the run logged no detections.
        from core.detections import summarize_detections
        detection_records = [r for r in records if r.get("type") == "detection"]
        detections = summarize_detections(detection_records, devices)

        return {
            "log_path": path,
            "devices": devices,
            "total": len(devices),
            "by_method": dict(sorted(by_method.items(), key=lambda kv: -kv[1])),
            "run_summary": run_summary,
            "detections": detections,
        }

    def to_discovery_csv(self, log_path: Optional[Path] = None, output_path: Optional[Path] = None) -> Path:
        """One row per discovered device. Raises ValueError if no discovery records found."""
        summary = self.build_discovery_summary(log_path)
        if summary is None:
            raise ValueError(f"no discovery records found for {log_path or self._latest_log()}")

        path = summary["log_path"]
        out = output_path or path.with_suffix(".csv")
        fields = ["ip", "mac", "vendor", "method", "model", "firmware", "matched_cves",
                  "matched_cve_urls", "first_seen", "last_seen"]

        with open(out, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for d in summary["devices"]:
                extra = d.get("extra") or {}
                row = {k: d.get(k) for k in fields}
                row["model"] = extra.get("model")
                row["firmware"] = extra.get("firmware")
                cves = extra.get("matched_cves") or []
                row["matched_cves"] = ";".join(cves) if cves else ""
                row["matched_cve_urls"] = ";".join(
                    f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves) if cves else ""
                writer.writerow(row)

        return out

    def to_discovery_html(self, log_path: Optional[Path] = None, output_path: Optional[Path] = None) -> Path:
        """Same calm, cool-toned dark palette as to_html()'s scan report (both are documents a
        user reads after the fact) — the live web UI's amber/relay-panel identity is intentional
        only for the operator's real-time control instrument, not for downloaded reports. See
        web/page.py's own docstring for the full reasoning."""
        summary = self.build_discovery_summary(log_path)
        if summary is None:
            raise ValueError(f"no discovery records found for {log_path or self._latest_log()}")

        path = summary["log_path"]
        out = output_path or path.with_suffix(".html")
        out.write_text(_render_discovery_html(summary), encoding="utf-8")
        return out

    def to_discovery_svg(self, log_path: Optional[Path] = None, output_path: Optional[Path] = None) -> Path:
        """Hand-rolled, dependency-free SVG device map — NOT an inferred network topology (ARP/
        Sparkplug don't reveal who-talks-to-whom), the caption says so explicitly rather than
        overclaiming. Devices on a circle for legibility up to ~30; a grid beyond that."""
        summary = self.build_discovery_summary(log_path)
        if summary is None:
            raise ValueError(f"no discovery records found for {log_path or self._latest_log()}")

        path = summary["log_path"]
        out = output_path or path.with_suffix(".svg")
        out.write_text(_render_discovery_svg(summary), encoding="utf-8")
        return out

    def to_discovery_json(self, log_path: Optional[Path] = None, output_path: Optional[Path] = None) -> Path:
        """Machine-ingestible asset inventory (SIEM/CMDB). One flat object per discovered device with
        the fingerprint-rich fields pulled out of `extra` into named keys (model, firmware, serial,
        product_code, device_type, matched CVEs), plus the full `extra` for anything else. Mirrors
        to_discovery_csv()'s flattening. Raises ValueError if no discovery records found."""
        summary = self.build_discovery_summary(log_path)
        if summary is None:
            raise ValueError(f"no discovery records found for {log_path or self._latest_log()}")

        path = summary["log_path"]
        out = output_path or path.with_suffix(".json")

        devices = []
        for d in summary["devices"]:
            extra = d.get("extra") or {}
            cves = extra.get("matched_cves") or []
            devices.append({
                "ip": d.get("ip"),
                "mac": d.get("mac"),
                "vendor": d.get("vendor"),
                "method": d.get("method"),
                "protocol": extra.get("protocol"),
                "port": extra.get("port"),
                "model": extra.get("model"),
                "firmware": extra.get("firmware"),
                "serial": extra.get("serial"),
                "product_code": extra.get("product_code"),
                "device_type": extra.get("device_type"),
                "vendor_id": extra.get("vendor_id"),
                "matched_cves": cves,
                "matched_cve_urls": [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves],
                "first_seen": d.get("first_seen"),
                "last_seen": d.get("last_seen"),
                "extra": extra,
            })

        doc = {
            "schema": "icsscanner-discovery-inventory/1",
            "total": summary["total"],
            "by_method": summary["by_method"],
            "detections": summary.get("detections"),
            "devices": devices,
        }
        out.write_text(json.dumps(doc, indent=2, default=str) + "\n", encoding="utf-8")
        return out


def _render_html(summary: dict, include_evidence: bool) -> str:
    def esc(s) -> str:
        if s is None:
            return ""
        return (
            str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    run_start = next((e for e in summary["run_events"] if e.get("type") == "run_start"), None)
    run_end = next((e for e in summary["run_events"] if e.get("type") == "run_end"), None)
    aliveness_failures = [e for e in summary["run_events"] if e.get("type") == "aliveness_failure"]
    credential_errors = [e for e in summary["run_events"] if e.get("type") == "credential_error"]

    meta_rows = ""
    if run_start:
        meta_rows += (
            f"<tr><th>Targets</th><td>{esc(run_start.get('target_count'))} "
            f"({esc(', '.join(run_start.get('targets', [])))})</td></tr>"
            f"<tr><th>Checks</th><td>{esc(run_start.get('check_count'))} across protocols: "
            f"{esc(', '.join(run_start.get('protocols', [])))}</td></tr>"
            f"<tr><th>Destructive mode</th><td>{esc(run_start.get('include_destructive'))}</td></tr>"
        )
    if run_end:
        meta_rows += f"<tr><th>Duration</th><td>{esc(round(run_end.get('duration_s', 0), 2))}s</td></tr>"
        aborted = [t for t in run_end.get("targets", []) if t.get("outcome") == "aborted_early"]
        if aborted:
            meta_rows += (
                f"<tr><th>Aborted targets</th><td>{esc(', '.join(t['target'] for t in aborted))} "
                f"— see Diagnostics below</td></tr>"
            )

    diagnostics_html = ""
    if aliveness_failures or credential_errors:
        rows = ""
        for e in aliveness_failures:
            rows += (
                f"<tr><td>aliveness_failure</td><td>{esc(e.get('target'))}</td>"
                f"<td>target stopped responding after check "
                f"<code>{esc(e.get('triggering_check_id'))}</code> (index {esc(e.get('check_index'))}), "
                f"waited {esc(e.get('waited_s'))}s — {esc(e.get('aborted_check_count'))} "
                f"remaining check(s) skipped</td></tr>"
            )
        for e in credential_errors:
            rows += f"<tr><td>credential_error</td><td>—</td><td>{esc(e.get('error'))}</td></tr>"
        diagnostics_html = f"""
        <div class="panel">
          <h3>Diagnostics</h3>
          <table><tr><th>Event</th><th>Target</th><th>Detail</th></tr>{rows}</table>
        </div>"""

    def rollup_table(title: str, data: dict) -> str:
        if not data:
            return ""
        rows = "".join(f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in data.items())
        return f'<div class="panel"><h3>{esc(title)}</h3><table>{rows}</table></div>'

    findings_rows = ""
    for f in summary["findings"]:
        cve = f["cve_id"] or f["can_id"] or "n/a"
        # Both links are constructed (not fetched/guessed) from the CVE id: NVD detail + the
        # authoritative MITRE CVE record. Per-vendor advisory URLs stay a per-check research backfill.
        cve_cell = (
            f'<a href="https://nvd.nist.gov/vuln/detail/{esc(f["cve_id"])}" target="_blank">{esc(f["cve_id"])}</a>'
            f' <a href="https://www.cve.org/CVERecord?id={esc(f["cve_id"])}" target="_blank" '
            f'class="src-mini" title="MITRE CVE record">MITRE</a>'
            if f["cve_id"] else esc(cve)
        )
        # Exploitability signal (CISA KEV / FIRST EPSS) — known-exploited and high-EPSS CVEs are the
        # ones to act on first; findings are already sorted by this.
        if f.get("kev"):
            cve_cell += (' <span class="kev-badge" title="On the CISA Known Exploited Vulnerabilities '
                         'catalog">KEV' + (' — ransomware' if f.get("kev_ransomware") else '') + '</span>')
        if f.get("epss") is not None and f["epss"] >= 0.01:  # suppress negligible-probability noise
            cve_cell += f' <span class="epss-badge" title="FIRST EPSS exploit probability">EPSS {f["epss"]:.0%}</span>'
        refs_cell = "<br>".join(
            f'<a href="{esc(l["url"])}" target="_blank" rel="noopener">{esc(l["label"])}</a>'
            for l in f.get("links", [])
        ) or "—"
        destructive_badge = '<span class="destructive-tag">destructive</span>' if f["destructive"] else ""
        status_class = "status-confirmed" if f["status"] == "confirmed" else "status-pending"
        evidence_cell = f"<td><code>{esc((f.get('evidence_hex') or '')[:80])}</code></td>" if include_evidence else ""
        score = f["severity_score"]
        score_suffix = f" ({esc(score)})" if score is not None else ""
        findings_rows += (
            f'<tr><td class="{status_class}">{esc(f["status"])}</td>'
            f"<td>{esc(f['check_id'])} {destructive_badge}</td>"
            f"<td>{cve_cell}</td><td>{esc(f['severity_band'])}{score_suffix}</td>"
            f"<td>{esc(f['confidence'])}</td><td>{esc(f['protocol'])}</td><td>{esc(f['target'])}</td>"
            f"<td>{esc(f['description'])}</td><td>{refs_cell}</td>{evidence_cell}</tr>"
        )
    evidence_header = "<th>Evidence (hex, truncated)</th>" if include_evidence else ""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>icsScanner Report — {esc(summary['log_path'].name)}</title>
<style>
  :root {{
    --bg: #0f1115; --panel: #171a21; --border: #2a2f3a; --text: #e6e8eb; --muted: #9aa4b2;
    --accent: #4f8cff; --danger: #e5484d; --ok: #3dd68c;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    background: var(--bg); color: var(--text); font-family: -apple-system, Segoe UI, Roboto, sans-serif;
    max-width: 1100px; margin: 0 auto; padding: 24px 16px 64px;
  }}
  h1 {{ font-size: 1.4rem; margin-bottom: 4px; }}
  h3 {{ font-size: 1rem; margin: 0 0 10px; }}
  .panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 16px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; }}
  th, td {{ text-align: left; border-bottom: 1px solid var(--border); padding: 6px 8px; vertical-align: top; }}
  th {{ color: var(--muted); font-weight: 600; }}
  .status-confirmed {{ color: var(--danger); font-weight: 600; }}
  .status-pending {{ color: var(--muted); }}
  .destructive-tag {{ color: var(--danger); font-size: 0.72rem; border: 1px solid var(--danger); border-radius: 4px; padding: 0 4px; }}
  .kev-badge {{ color: #111; background: var(--danger); font-size: 0.68rem; font-weight: 700; border-radius: 4px; padding: 0 5px; white-space: nowrap; }}
  .epss-badge {{ color: var(--muted); font-size: 0.68rem; border: 1px solid var(--border); border-radius: 4px; padding: 0 5px; white-space: nowrap; }}
  .src-mini {{ font-size: 0.66rem; color: var(--muted); }}
  a {{ color: var(--accent); }}
  code {{ font-family: ui-monospace, SFMono-Regular, monospace; }}
</style>
</head>
<body>
  <h1>icsScanner Report</h1>
  <p style="color: var(--muted);">{esc(summary['log_path'].name)}</p>

  <div class="panel">
    <h3>Run Summary</h3>
    <table>
      <tr><th>Total checks</th><td>{summary['total']}</td></tr>
      <tr><th>Confirmed</th><td class="status-confirmed">{summary['confirmed']}</td></tr>
      <tr><th>Fingerprint-only</th><td>{summary['fingerprint_only']}</td></tr>
      <tr><th>Errors</th><td>{summary['errors']}</td></tr>
      {meta_rows}
    </table>
  </div>

  {diagnostics_html}
  {rollup_table("By Protocol", summary["by_protocol"])}
  {rollup_table("Confirmed-Finding Confidence Breakdown", summary["by_confidence"])}
  {rollup_table("Confirmed-Finding Severity Breakdown", summary["by_severity"])}

  <div class="panel">
    <h3>Findings (confirmed + fingerprint-only)</h3>
    <table>
      <tr><th>Status</th><th>Check</th><th>CVE/CAN</th><th>Severity</th><th>Confidence</th>
        <th>Protocol</th><th>Target</th><th>Description</th><th>References</th>{evidence_header}</tr>
      {findings_rows}
    </table>
  </div>
</body>
</html>
"""


def _esc(s) -> str:
    if s is None:
        return ""
    return (
        str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _render_discovery_html(summary: dict) -> str:
    """Same cool-toned dark palette as _render_html() above — deliberately, not by omission. See
    ScanReporter.to_discovery_html()'s docstring for why."""
    rows = "".join(
        f"<tr><td>{_esc(d.get('ip'))}</td><td>{_esc(d.get('mac')) or '&mdash;'}</td>"
        f"<td>{_esc(d.get('vendor'))}</td><td>{_esc(d.get('method'))}</td>"
        f"<td>{_esc(d.get('first_seen'))}</td><td>{_esc(d.get('last_seen'))}</td></tr>"
        for d in summary["devices"]
    ) or '<tr><td colspan="6"><i>No devices discovered in this window.</i></td></tr>'

    method_rows = "".join(
        f"<tr><td>{_esc(k)}</td><td>{v}</td></tr>" for k, v in summary["by_method"].items()
    )

    detections_html = ""
    if summary.get("detections"):
        from core.detections import render_detections_html
        detections_html = render_detections_html(summary["detections"])

    from core.cpg import cpg_alignment, render_cpg_html
    cpg_html = render_cpg_html(cpg_alignment(devices=summary.get("devices"),
                                             detections=summary.get("detections")))

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>icsScanner Discovery Report — {_esc(summary['log_path'].name)}</title>
<style>
  :root {{
    --bg: #0f1115; --panel: #171a21; --border: #2a2f3a; --text: #e6e8eb; --muted: #9aa4b2;
    --accent: #4f8cff; --danger: #e5484d; --ok: #3dd68c;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    background: var(--bg); color: var(--text); font-family: -apple-system, Segoe UI, Roboto, sans-serif;
    max-width: 1000px; margin: 0 auto; padding: 24px 16px 64px;
  }}
  h1 {{ font-size: 1.4rem; margin-bottom: 4px; }}
  h3 {{ font-size: 1rem; margin: 0 0 10px; }}
  .panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 16px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; }}
  th, td {{ text-align: left; border-bottom: 1px solid var(--border); padding: 6px 8px; vertical-align: top; }}
  th {{ color: var(--muted); font-weight: 600; }}
  .note {{ color: var(--muted); font-size: 0.82rem; }}
  .cpg-yes {{ color: var(--ok); font-size: 0.72rem; font-weight: 600; border: 1px solid var(--ok); border-radius: 4px; padding: 0 5px; }}
</style>
</head>
<body>
  <h1>icsScanner Discovery Report</h1>
  <p style="color: var(--muted);">{_esc(summary['log_path'].name)}</p>

  <div class="panel">
    <h3>Summary</h3>
    <table><tr><th>Devices found</th><td>{summary['total']}</td></tr></table>
  </div>

  <div class="panel"><h3>By Discovery Method</h3><table>{method_rows}</table></div>

  <div class="panel">
    <h3>Discovered Devices</h3>
    <p class="note">A device map, not an inferred network topology — ARP/Sparkplug traffic
    reveals which hosts are present, not who talks to whom.</p>
    <table>
      <tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Method</th><th>First seen</th><th>Last seen</th></tr>
      {rows}
    </table>
  </div>
  {detections_html}
  {cpg_html}
</body>
</html>
"""


def _render_discovery_svg(summary: dict) -> str:
    """Hand-rolled, dependency-free device map. Circle layout up to ~30 devices for legibility;
    a grid beyond that. Colored by discovery method, matching web/page.py's method-dot palette
    (amber=active ARP, muted steel=passive ARP, teal=Sparkplug B) so the live UI and this
    downloaded artifact read as the same visual language."""
    import math

    devices = summary["devices"]
    method_colors = {
        "arp_active": "#ffb020",
        "arp_passive": "#8d8a76",
        "sparkplug_b": "#3ecfb8",
        "micom_courier_active": "#c77dff",
        "factorytalk_rna_active": "#ff7a7a",
    }
    width = 800
    n = len(devices)
    nodes = []

    if n == 0:
        height = 200
        nodes.append(
            f'<text x="{width/2}" y="{height/2}" fill="#8d8a76" font-family="monospace" '
            f'font-size="14" text-anchor="middle">No devices discovered in this window.</text>'
        )
    elif n <= 30:
        height = 800
        cx, cy = width / 2, height / 2
        radius = min(width, height) / 2 - 90
        for i, d in enumerate(devices):
            angle = 2 * math.pi * i / n
            x = cx + radius * math.cos(angle)
            y = cy + radius * math.sin(angle)
            color = method_colors.get(d.get("method"), "#e8e4d6")
            label = f"{d.get('ip', '?')} ({d.get('vendor', 'unknown')})"
            nodes.append(
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="9" fill="{color}" stroke="#0b0c09" stroke-width="1.5"/>'
                f'<text x="{x:.1f}" y="{y + 22:.1f}" fill="#e8e4d6" font-family="monospace" '
                f'font-size="11" text-anchor="middle">{_esc(label)}</text>'
            )
        nodes.append(f'<circle cx="{cx}" cy="{cy}" r="6" fill="#ffb020"/>')
        nodes.append(
            f'<text x="{cx}" y="{cy - 14}" fill="#ffb020" font-family="monospace" '
            f'font-size="12" text-anchor="middle">THIS HOST</text>'
        )
    else:
        cols = math.ceil(math.sqrt(n))
        spacing_x = (width - 80) / cols
        spacing_y = 60
        height = 100 + math.ceil(n / cols) * spacing_y
        for i, d in enumerate(devices):
            col, row = i % cols, i // cols
            x = 40 + col * spacing_x + spacing_x / 2
            y = 70 + row * spacing_y
            color = method_colors.get(d.get("method"), "#e8e4d6")
            nodes.append(
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="7" fill="{color}"/>'
                f'<text x="{x:.1f}" y="{y + 16:.1f}" fill="#e8e4d6" font-family="monospace" '
                f'font-size="9" text-anchor="middle">{_esc(d.get("ip", "?"))}</text>'
            )

    legend = (
        '<g font-family="monospace" font-size="11">'
        '<circle cx="20" cy="20" r="6" fill="#ffb020"/><text x="34" y="24" fill="#e8e4d6">active ARP</text>'
        '<circle cx="150" cy="20" r="6" fill="#8d8a76"/><text x="164" y="24" fill="#e8e4d6">passive ARP</text>'
        '<circle cx="290" cy="20" r="6" fill="#3ecfb8"/><text x="304" y="24" fill="#e8e4d6">Sparkplug B</text>'
        "</g>"
    )
    caption = (
        f'<text x="{width/2}" y="{height - 12}" fill="#8d8a76" font-family="monospace" '
        f'font-size="10" text-anchor="middle">Device map from observed ARP/Sparkplug traffic '
        f"&#8212; not an inferred network topology (who talks to whom is not derivable from this data).</text>"
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">'
        f'<rect width="{width}" height="{height}" fill="#0b0c09"/>'
        f"{legend}{''.join(nodes)}{caption}"
        f"</svg>"
    )
