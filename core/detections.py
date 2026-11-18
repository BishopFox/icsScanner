"""Passive-detection (observed-activity) report section.

This is the activity half of passive mode, and deliberately OUTSIDE the original passive-mode design
(which produced only static posture: an asset inventory + identity-only CVE findings). A Zeek sensor
running the detection-gen rules (core/renderers/zeek.py signatures + zeek_policy.py ATT&CK-for-ICS
NOTICEs) emits a notice.log of temporal detections — src -> dst, time, technique — a different data
class from the inventory. This module turns that notice.log into a report SECTION, correlated back to
the discovered inventory so a line reads "device X was the target of technique Y" rather than a bare IP.

Honest framing is load-bearing here (an activity report invites over-reading):
  * A NOTICE is a pattern match on the wire, NOT a confirmed compromise. Language stays "observed
    activity matching check Y", never "attack confirmed".
  * narrow vs broad is always labelled: narrow = the scanner's own probe bytes (a reconnaissance
    signature); broad = the exploitation class, which can match benign OT traffic (false-positive
    prone). The report must not present a broad hit as fact.
  * This is a passive-detection SUMMARY, not real-time alerting, and is kept visibly separate from the
    vulnerability findings.

The detections are only as trustworthy as the generating Zeek rules (see the signature-anchoring fix,
2026-11-11 — before it every rule was inert).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from core.passive import read_zeek_tsv

# The categorized NOTICEs the zeek_policy renderer raises all live under this module namespace; the
# base Signatures::Sensitive_Signature notice Zeek also emits per match is intentionally ignored.
_ICS_NOTE_PREFIX = "ICS_Scanner::"
# $msg the policy emits: "ICS-SCANNER NARROW - <check_id>" / "ICS-SCANNER BROAD - <check_id>".
_MSG_RE = re.compile(r"ICS-SCANNER (NARROW|BROAD) - (.+)")


@dataclass
class Detection:
    """One categorized passive detection (one ICS_Scanner NOTICE row)."""
    ts: float = 0.0
    src: str = ""
    dst: str = ""
    src_port: str = ""
    dst_port: str = ""
    note: str = ""          # ICS_Scanner::ICS_<mode>_<base>
    check_id: str = ""      # exact check id, recovered from $msg
    mode: str = ""          # "narrow" | "broad" | ""
    app_protocol: str = ""  # from $sub "<app>/<mitre>"
    mitre: str = ""
    msg: str = ""
    finding_type: str = ""  # config_exposure | attack_activity | reconnaissance | "" (unspecified)

    def as_dict(self) -> dict:
        return {
            "type": "detection",
            "ts": self.ts,
            "ts_iso": _iso(self.ts),
            "src": self.src, "dst": self.dst,
            "src_port": self.src_port, "dst_port": self.dst_port,
            "note": self.note, "check_id": self.check_id, "mode": self.mode,
            "app_protocol": self.app_protocol, "mitre": self.mitre, "msg": self.msg,
            "finding_type": self.finding_type,
        }


def _iso(ts: float) -> str:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except (ValueError, OSError, OverflowError):
        return ""


def parse_notice_log(path: str) -> list:
    """Parse a Zeek notice.log into Detection records, keeping only the categorized ICS_Scanner
    NOTICEs the zeek_policy renderer raises. Never raises — returns [] on any read/format problem
    (read_zeek_tsv is itself fail-closed)."""
    out = []
    for r in read_zeek_tsv(path):
        note = r.get("note", "")
        if not note.startswith(_ICS_NOTE_PREFIX):
            continue
        msg = r.get("msg", "")
        m = _MSG_RE.search(msg)
        mode = m.group(1).lower() if m else ""
        check_id = m.group(2).strip() if m else ""
        sub = r.get("sub", "") or ""
        app, _, mitre = sub.partition("/")
        try:
            ts = float(r.get("ts") or 0.0)
        except (TypeError, ValueError):
            ts = 0.0
        out.append(Detection(
            ts=ts,
            src=r.get("id.orig_h", "") or r.get("src", ""),
            dst=r.get("id.resp_h", "") or r.get("dst", ""),
            src_port=r.get("id.orig_p", ""),
            dst_port=r.get("id.resp_p", ""),
            note=note, check_id=check_id, mode=mode,
            app_protocol=app, mitre=mitre, msg=msg,
        ))
    return out


def _device_index(devices: Optional[list]) -> dict:
    """Map ip -> (vendor, model) from the discovered inventory (device records as dicts)."""
    idx = {}
    for d in devices or []:
        ip = d.get("ip")
        if not ip:
            continue
        extra = d.get("extra") or {}
        idx[ip] = (d.get("vendor") or "unknown", extra.get("model") or "unknown")
    return idx


def summarize_detections(detections: list, devices: Optional[list] = None) -> Optional[dict]:
    """Roll up detection dicts (Detection.as_dict shape) and correlate each target (dst) back to the
    inventory. Returns None when there are no detections (callers omit the section)."""
    dets = [d for d in detections if d]
    if not dets:
        return None
    dev_idx = _device_index(devices)

    by_mode: dict = {"narrow": 0, "broad": 0}
    by_finding_type: dict = {}
    by_mitre: dict = {}
    by_check: dict = {}
    by_source: dict = {}
    targets: dict = {}  # dst -> {count, techniques:set, checks:set}
    ts_vals = []

    for d in dets:
        mode = d.get("mode") or "unknown"
        by_mode[mode] = by_mode.get(mode, 0) + 1
        mitre = d.get("mitre") or "—"
        by_mitre[mitre] = by_mitre.get(mitre, 0) + 1
        cid = d.get("check_id") or d.get("note") or "—"
        by_check[cid] = by_check.get(cid, 0) + 1
        src = d.get("src") or "—"
        by_source[src] = by_source.get(src, 0) + 1
        ft = d.get("finding_type") or ""
        if ft:
            by_finding_type[ft] = by_finding_type.get(ft, 0) + 1
        dst = d.get("dst") or "—"
        t = targets.setdefault(dst, {"count": 0, "techniques": set(), "checks": set(),
                                     "modes": set(), "finding_types": set()})
        t["count"] += 1
        if d.get("mitre"):
            t["techniques"].add(d["mitre"])
        t["checks"].add(cid)
        t["modes"].add(mode)
        if ft:
            t["finding_types"].add(ft)
        if d.get("ts"):
            ts_vals.append(d["ts"])

    target_rows = []
    for dst, t in sorted(targets.items(), key=lambda kv: -kv[1]["count"]):
        vendor, model = dev_idx.get(dst, ("", ""))
        ident = ""
        if vendor and vendor != "unknown":
            ident = vendor + (f" {model}" if model and model != "unknown" else "")
        target_rows.append({
            "dst": dst,
            "identity": ident,              # "" when the target isn't in the passive inventory
            "count": t["count"],
            "techniques": sorted(t["techniques"]),
            "checks": sorted(t["checks"]),
            "modes": sorted(t["modes"]),
            "finding_types": sorted(t["finding_types"]),
        })

    return {
        "total": len(dets),
        "by_mode": by_mode,
        "by_finding_type": dict(sorted(by_finding_type.items(), key=lambda kv: -kv[1])),
        "by_mitre": dict(sorted(by_mitre.items(), key=lambda kv: -kv[1])),
        "by_check": dict(sorted(by_check.items(), key=lambda kv: -kv[1])),
        "by_source": dict(sorted(by_source.items(), key=lambda kv: -kv[1])),
        "targets": target_rows,
        "first_ts": _iso(min(ts_vals)) if ts_vals else "",
        "last_ts": _iso(max(ts_vals)) if ts_vals else "",
        "detections": dets,
    }


# ─────────────────────────────── rendering (a report section) ───────────────────────────────

# Finding-type labels. config_exposure matters most: it fires on benign traffic *because the device
# really is misconfigured* (e.g. a default SNMP community in use) — a true finding, not a false positive,
# but a config state, not an attack. attack_activity = someone acting (a DoS/exhaustion); reconnaissance
# = probing/scanning shape.
_FT_LABEL = {
    "config_exposure": "config exposure (device misconfigured; fires on benign traffic too)",
    "attack_activity": "attack activity",
    "reconnaissance": "reconnaissance",
}

_CAVEAT = ("Observed activity — traffic matching a check's signature, NOT a confirmed compromise. "
           "narrow = this scanner's own probe bytes (reconnaissance signature); broad = the "
           "exploitation class and can match benign traffic. Correlate before acting.")


def render_detections_text(summary: dict) -> str:
    if not summary:
        return ""
    lines = []
    lines.append("Observed activity (passive detections)")
    lines.append("-" * 90)
    bm = summary["by_mode"]
    modeline = (f"  {summary['total']} detection(s): "
                f"{bm.get('broad', 0)} broad (exploitation-class), "
                f"{bm.get('narrow', 0)} narrow (recon)")
    if bm.get("behavioral"):
        modeline += f", {bm['behavioral']} behavioral (volumetric)"
    lines.append(modeline)
    if summary["first_ts"]:
        lines.append(f"  window: {summary['first_ts']} .. {summary['last_ts']}")
    if summary["by_mitre"]:
        tech = ", ".join(f"{k} ({v})" for k, v in summary["by_mitre"].items())
        lines.append(f"  techniques (ATT&CK for ICS): {tech}")
    if summary.get("by_finding_type"):
        ft = ", ".join(f"{_FT_LABEL.get(k, k)} ({v})" for k, v in summary["by_finding_type"].items())
        lines.append(f"  finding types: {ft}")
    lines.append("  targets:")
    for t in summary["targets"]:
        who = f" [{t['identity']}]" if t["identity"] else ""
        tech = f"  {','.join(t['techniques'])}" if t["techniques"] else ""
        lines.append(f"    {t['dst']:<16}{who}  x{t['count']}  "
                     f"({'/'.join(t['modes'])}){tech}")
    lines.append(f"  note: {_CAVEAT}")
    return "\n".join(lines)


def _esc(s) -> str:
    if s is None:
        return ""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


_DET_LINK_RESOLVER = None


def _det_link_resolver():
    global _DET_LINK_RESOLVER
    if _DET_LINK_RESOLVER is None:
        from core.links import LinkResolver
        _DET_LINK_RESOLVER = LinkResolver()
    return _DET_LINK_RESOLVER


def _finding_type_html(summary: dict) -> str:
    bft = summary.get("by_finding_type") or {}
    if not bft:
        return ""
    rows = "".join(f"<tr><td>{_esc(_FT_LABEL.get(k, k))}</td><td>{v}</td></tr>" for k, v in bft.items())
    return ('<h3 style="margin-top:14px">By finding type</h3>'
            f'<table><tr><th>Finding type</th><th>Detections</th></tr>{rows}</table>')


def render_detections_html(summary: dict) -> str:
    """Return an HTML .panel fragment to slot into the discovery report (reuses that report's CSS)."""
    if not summary:
        return ""
    bm = summary["by_mode"]
    mitre_rows = "".join(
        f"<tr><td>{_esc(k)}</td><td>{v}</td></tr>" for k, v in summary["by_mitre"].items()
    ) or '<tr><td colspan="2"><i>none</i></td></tr>'
    target_rows = ""
    for t in summary["targets"]:
        ident = f" <span class='note'>[{_esc(t['identity'])}]</span>" if t["identity"] else ""
        target_rows += (
            f"<tr><td>{_esc(t['dst'])}{ident}</td>"
            f"<td>{_esc('/'.join(t['modes']))}</td>"
            f"<td>{_esc(', '.join(t['techniques']) or '—')}</td>"
            f"<td>{t['count']}</td>"
            f"<td>{_esc(', '.join(t['checks']))}</td></tr>"
        )
    # Per-check report links (NVD from cve_id + advisory_url + references + custom links) for the
    # checks that fired — so a reader can click through from a detection to its source.
    check_link_rows = ""
    try:
        for cid in summary.get("by_check", {}):
            links = _det_link_resolver().for_finding(cid)
            if links:
                anchors = " &middot; ".join(
                    f'<a href="{_esc(l["url"])}" target="_blank" rel="noopener">{_esc(l["label"])}</a>'
                    for l in links)
                check_link_rows += f"<tr><td>{_esc(cid)}</td><td>{anchors}</td></tr>"
    except Exception:
        check_link_rows = ""
    check_links_html = (f'<h3 style="margin-top:14px">Check references</h3>'
                        f'<table><tr><th>Check</th><th>Links</th></tr>{check_link_rows}</table>'
                        if check_link_rows else "")

    window = f"{_esc(summary['first_ts'])} .. {_esc(summary['last_ts'])}" if summary["first_ts"] else "—"
    return f"""
  <div class="panel">
    <h3>Observed Activity (passive detections)</h3>
    <p class="note">{_esc(_CAVEAT)}</p>
    <table>
      <tr><th>Detections</th><td>{summary['total']} &mdash;
        {bm.get('broad', 0)} broad (exploitation-class), {bm.get('narrow', 0)} narrow (recon){f", {bm['behavioral']} behavioral (volumetric)" if bm.get('behavioral') else ""}</td></tr>
      <tr><th>Window</th><td>{window}</td></tr>
    </table>
    {_finding_type_html(summary)}
    <h3 style="margin-top:14px">By ATT&amp;CK-for-ICS technique</h3>
    <table><tr><th>Technique</th><th>Detections</th></tr>{mitre_rows}</table>
    <h3 style="margin-top:14px">By target</h3>
    <table>
      <tr><th>Target (correlated identity)</th><th>Mode</th><th>Technique(s)</th><th>Count</th><th>Check(s)</th></tr>
      {target_rows}
    </table>
    {check_links_html}
  </div>"""
