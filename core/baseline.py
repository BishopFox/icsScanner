"""Light passive baselining — flag what's NEW vs a saved snapshot.

Not an anomaly-detection platform: a bounded, deterministic diff of a passive run against a baseline
captured on a prior run. It answers the questions the CPG/DETECT practices actually ask of a quiet OT
segment: did a new device appear, did a known IP's MAC change (possible ARP spoofing or a device swap),
did a known asset start speaking a protocol it never did, did a new network segment show up. Zero
transmit — it only compares already-captured passive inventory.

Baseline file = JSON: {"generated", "assets": {ip: {"mac", "vendor", "protocols": [...]}}}.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional


def _asdict(d) -> dict:
    """Accept a DiscoveredDevice or an already-serialized dict."""
    if hasattr(d, "as_dict"):
        d = d.as_dict()
    extra = d.get("extra") or {}
    return {"ip": d.get("ip") or "", "mac": d.get("mac"), "vendor": d.get("vendor") or "unknown",
            "protocols": sorted(extra.get("protocols") or [])}


def save_baseline(devices: list, path: str) -> int:
    """Write the current inventory as a baseline. Returns the asset count."""
    assets = {}
    for d in devices:
        a = _asdict(d)
        if a["ip"]:
            assets[a["ip"]] = {"mac": a["mac"], "vendor": a["vendor"], "protocols": a["protocols"]}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"generated": datetime.now(timezone.utc).isoformat(), "assets": assets}, fh, indent=2)
    return len(assets)


def load_baseline(path: str) -> Optional[dict]:
    """Load a baseline, or None (never raises) if absent/unreadable."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) and "assets" in data else None
    except (OSError, ValueError):
        return None


def diff_baseline(baseline: dict, devices: list) -> dict:
    """Compare a current run against a baseline. Returns deviation lists:
    new_assets [{ip,vendor,mac}], mac_changes [{ip,old,new}], new_protocols [{ip,protocol}],
    new_segments [seg]. mac_changes is the security-relevant one (ARP spoofing / device swap)."""
    base = (baseline or {}).get("assets") or {}
    base_segs = {ip.rsplit(".", 1)[0] for ip in base if ip.count(".") == 3}

    new_assets, mac_changes, new_protocols, new_segs = [], [], [], set()
    seen_segs = set()
    for d in devices:
        a = _asdict(d)
        ip = a["ip"]
        if not ip:
            continue
        if ip.count(".") == 3:
            seg = ip.rsplit(".", 1)[0]
            seen_segs.add(seg)
            if seg not in base_segs:
                new_segs.add(seg)
        if ip not in base:
            new_assets.append({"ip": ip, "vendor": a["vendor"], "mac": a["mac"]})
            continue
        b = base[ip]
        if a["mac"] and b.get("mac") and a["mac"] != b["mac"]:
            mac_changes.append({"ip": ip, "old": b["mac"], "new": a["mac"]})
        base_protos = set(b.get("protocols") or [])
        for p in a["protocols"]:
            if p not in base_protos:
                new_protocols.append({"ip": ip, "protocol": p})
    return {
        "new_assets": new_assets,
        "mac_changes": mac_changes,
        "new_protocols": new_protocols,
        "new_segments": sorted(new_segs),
        "total_deviations": len(new_assets) + len(mac_changes) + len(new_protocols) + len(new_segs),
    }


def render_text(dev: dict) -> str:
    """A terse CLI summary of the baseline diff."""
    if not dev or not dev.get("total_deviations"):
        return "Baseline: no deviations (all assets/protocols/MACs match the baseline)."
    lines = [f"Baseline deviations ({dev['total_deviations']}):"]
    for m in dev.get("mac_changes", []):
        lines.append(f"  [!] MAC CHANGED for {m['ip']}: {m['old']} -> {m['new']} (possible ARP spoofing / device swap)")
    for a in dev.get("new_assets", []):
        lines.append(f"  [+] new asset {a['ip']} ({a.get('vendor') or 'unknown'}, {a.get('mac') or '-'})")
    for p in dev.get("new_protocols", []):
        lines.append(f"  [+] {p['ip']} now speaks {p['protocol']} (not in baseline)")
    for s in dev.get("new_segments", []):
        lines.append(f"  [+] new segment {s}.0/24")
    return "\n".join(lines)
