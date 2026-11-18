"""Scan policy — the invocation model decided in 00-PROJECT-CHARTER.md § Scope ("proceeding as
default, not separately contested"): a YAML scan-policy file (target inventory + check selection
+ rate profile + output) with CLI flags as overrides, closer to a Nessus scan-policy model than
icsFuzzer's flag-heavy CLI. Mirrors core/target.py:load_target_inventory()'s rigor — fail loudly
on a malformed file rather than silently defaulting.

`inventory:` is a path, resolved by reference — the credential-parsing/plaintext-secret-rejection
logic lives entirely in core/target.py and isn't duplicated here.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

import yaml


@dataclass
class ScanPolicy:
    inventory: str
    protocols: Optional[list[str]] = None
    check_ids: Optional[list[str]] = None
    include_destructive: bool = False
    include_adverse: bool = False  # added 2026-08-29 alongside CheckMetadata.risk_reason — a
    # SEPARATE opt-in from include_destructive, not a superset/subset of it. A check's own
    # risk_tier() decides which of the two flags actually gates it (see core/check.py); this
    # lets an operator include plain-login "adverse" checks without also opting into the smaller,
    # higher-consequence "destructive" set (lockout risk, device writes), or vice versa.
    max_concurrent_targets: int = 4
    global_pps: Optional[float] = None
    global_delay_s: float = 0.1
    per_target_pps: Optional[float] = None
    per_target_delay_s: float = 0.2
    output_dir: str = "./output"
    report_html: bool = False
    report_csv: bool = False
    include_evidence: bool = False


def load_scan_policy(path: Union[str, Path]) -> ScanPolicy:
    """Parse a YAML scan-policy file. See templates/scan-policy.example.yaml for the shape."""
    path = Path(path)
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not data or "inventory" not in data:
        raise ValueError(f"{path}: expected a top-level 'inventory:' path")

    for key in ("protocols", "check_ids"):
        if key in data and data[key] is not None and not isinstance(data[key], list):
            raise ValueError(f"{path}: '{key}:' must be a list if present")

    rate = data.get("rate", {}) or {}
    if not isinstance(rate, dict):
        raise ValueError(f"{path}: 'rate:' must be a mapping if present")

    return ScanPolicy(
        inventory=data["inventory"],
        protocols=data.get("protocols"),
        check_ids=data.get("check_ids"),
        include_destructive=bool(data.get("include_destructive", False)),
        include_adverse=bool(data.get("include_adverse", False)),
        max_concurrent_targets=int(data.get("max_concurrent_targets", 4)),
        global_pps=rate.get("global_pps"),
        global_delay_s=float(rate.get("global_delay_s", 0.1)),
        per_target_pps=rate.get("per_target_pps"),
        per_target_delay_s=float(rate.get("per_target_delay_s", 0.2)),
        output_dir=data.get("output_dir", "./output"),
        report_html=bool(data.get("report_html", False)),
        report_csv=bool(data.get("report_csv", False)),
        include_evidence=bool(data.get("include_evidence", False)),
    )
