"""CPG 2.0 / NIST CSF 2.0 alignment for icsScanner output.

CISA's Cross-Sector Cybersecurity Performance Goals (v2.0, Dec 2025) are organized by the NIST CSF 2.0
functions (GOVERN / IDENTIFY / PROTECT / DETECT / RESPOND / RECOVER) and call out OT practices like
asset inventory, no exploitable default credentials, network segmentation, and OT monitoring. The
2025 NSA/CISA "OT Asset Inventory Guidance" pushes the same direction.

icsScanner provides EVIDENCE for a subset of these — it is NOT a self-assessment tool (that is CSET's
job), and it deliberately states what it CANNOT assess. This module maps a passive/active run's output
to the framework areas it speaks to, with live counts, so a report can show federal-framework alignment
honestly. No fabricated practice IDs — areas are named by CSF function + the well-known CPG theme.
"""
from __future__ import annotations

from typing import Optional


def cpg_alignment(devices: Optional[list] = None, detections: Optional[dict] = None,
                  findings: Optional[list] = None) -> list:
    """Return a list of alignment areas, each {csf, theme, evidence, gap, status, detail}. `status` is
    "evidence" when the run produced data for it, "n/a" when this run didn't exercise it."""
    devices = devices or []
    findings = findings or []
    det = detections or {}

    n_assets = len(devices)
    n_vendor = sum(1 for d in devices if (d.get("vendor") or "unknown") not in ("unknown", ""))
    # default-credential / config-exposure signal
    n_default = sum(1 for f in findings if "default" in (f.get("check_id") or "").lower()
                    or "credential" in (f.get("check_id") or "").lower())
    bft = (det.get("by_finding_type") or {})
    n_config = bft.get("config_exposure", 0)
    n_det = det.get("total", 0)
    # segments observed (distinct /24s among discovered IPs — a coarse segment proxy)
    segs = set()
    for d in devices:
        ip = d.get("ip") or ""
        if ip.count(".") == 3:
            segs.add(ip.rsplit(".", 1)[0])
    n_kev = sum(1 for f in findings if f.get("kev"))

    def area(csf, theme, evidence, gap, status, detail):
        return {"csf": csf, "theme": theme, "evidence": evidence, "gap": gap,
                "status": status, "detail": detail}

    return [
        area("IDENTIFY", "Asset inventory",
             "zero-transmit passive device inventory (vendor/OUI/protocol) + active fingerprinting",
             "silent devices and encrypted traffic are invisible; pair with an authorized active scan where policy allows",
             "evidence" if n_assets else "n/a",
             f"{n_assets} asset(s) inventoried, {n_vendor} vendor-resolved, across {len(segs)} observed segment(s)"),
        area("PROTECT", "No exploitable default/weak credentials",
             "default-credential checks + config-exposure detections (e.g. default SNMP community in use)",
             "tests only the documented default-credential set; not a full credential audit",
             "evidence" if (n_default or n_config) else "n/a",
             f"{n_default} default-credential finding(s); {n_config} config-exposure detection(s)"),
        area("PROTECT", "Network segmentation",
             "passive observation of which segment each asset sits on (per-flow who-talks-to-whom is a follow-up)",
             "flow-level conversation mapping not yet aggregated — segments are inferred from asset addressing",
             "evidence" if len(segs) > 1 else "n/a",
             f"{len(segs)} distinct segment(s) observed among discovered assets"),
        area("DETECT", "OT network monitoring / detection",
             "detection-gen rules (Sigma/ESCU/Suricata/Zeek signature+policy+field-level) + native Observed-Activity matcher, Malcolm/Hedgehog-deployable",
             "detections are signature/field/volumetric, not behavioral-anomaly baselining",
             "evidence" if n_det else "n/a",
             f"{n_det} passive detection(s) in this run; the check corpus also renders to deployable sensor rules"),
        area("RESPOND", "Vulnerability prioritization",
             "CVE correlation + version gating + CISA-KEV / FIRST-EPSS exploitability ranking",
             "identity/version-based and feed-driven; not asset-criticality weighted and not threat-intel",
             "evidence" if findings else "n/a",
             f"{len(findings)} finding(s); {n_kev} on the CISA KEV catalog (actively exploited)"),
    ]


def _esc(s) -> str:
    return ("" if s is None else str(s)).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_cpg_html(areas: list) -> str:
    """An HTML .panel fragment mapping the run to CPG 2.0 / NIST CSF 2.0 areas."""
    if not areas:
        return ""
    rows = ""
    for a in areas:
        badge = ("<span class='cpg-yes'>evidence</span>" if a["status"] == "evidence"
                 else "<span class='note'>not exercised</span>")
        rows += (f"<tr><td>{_esc(a['csf'])}</td><td>{_esc(a['theme'])}</td><td>{badge}</td>"
                 f"<td>{_esc(a['detail'])}</td><td class='note'>{_esc(a['gap'])}</td></tr>")
    return (
        '<div class="panel">'
        '<h3>CPG 2.0 / NIST CSF 2.0 alignment</h3>'
        '<p class="note">What this run evidences toward CISA\'s Cross-Sector Cybersecurity Performance '
        'Goals (v2.0) and the NSA/CISA OT asset-inventory guidance. icsScanner provides evidence for a '
        'subset of practices; it is not a full self-assessment (use CSET for that). The gap column states '
        'what it cannot assess.</p>'
        '<table><tr><th>CSF function</th><th>Practice theme</th><th>This run</th><th>Evidence</th>'
        '<th>Limits</th></tr>' + rows + '</table></div>'
    )
