"""Zeek behavioral renderer — connection-concurrency NOTICE for pool/connection-exhaustion checks.

The Suricata behavioral rule counts connection INITIATIONS over a time window (a rate). Real OT
masters reconnect in bursts as large as the attack, so rate cannot reliably separate the two
(measured on the PNNL set: legitimate bursts of 8-9 conn/2s vs a ~7-conn attack). The faithful signal
for small-pool exhaustion is CONCURRENCY — how many connections are held open to the target device at
once — which only a stateful engine can measure. This renderer emits a Zeek policy that tracks the
number of simultaneously-open connections per responder host on the service port and raises a NOTICE
when it reaches a tunable pool threshold.

Renders only for a `behavioral` block whose signal is connection_rate / connection_count and whose
app_protocol maps to a known service port. The threshold defaults to the check's behavioral
`threshold` and is exposed as a Zeek `option` so a deployment redefs it to the device's real
connection-pool / max-clients size. Passive detection only; never inline.
"""
from __future__ import annotations

import re
import textwrap
from typing import Optional

from core.check_loader import CheckRecord
from core.renderers.suricata import _APP_PORT, _CONNECTION_SIGNALS


def _ident(check_id: str) -> str:
    return re.sub(r"[^0-9a-zA-Z]+", "_", check_id).strip("_")


def _tuning_lines(tuning) -> str:
    """The check's behavioral `tuning` text as wrapped `# TUNING:` comment lines, so the
    threat-hunter guidance (expected FPs + how to set the concurrency threshold) ships in the policy."""
    if not tuning or not str(tuning).strip():
        return ""
    lines = textwrap.wrap(" ".join(str(tuning).split()), width=95)
    out = f"# TUNING: {lines[0]}\n" if lines else ""
    for ln in lines[1:]:
        out += f"#   {ln}\n"
    return out


def output_filename(record: CheckRecord, mode: str) -> Optional[str]:
    # One policy per check; fixed .zeek ext so a mixed zeek/zeek-* run is unambiguous.
    return f"{record.check_id}.{mode}.zeek"


def render(record: CheckRecord, mode: str) -> Optional[str]:
    if mode != "behavioral" or not record.has_hints:
        return None
    hints = record.detection_hints
    beh = hints.get("behavioral")
    if not isinstance(beh, dict) or beh.get("signal") not in _CONNECTION_SIGNALS or not beh.get("threshold"):
        return None
    port = _APP_PORT.get(hints.get("app_protocol"))
    if port is None:
        return None  # need a concrete service port to scope the concurrency count

    ident = _ident(record.check_id)
    thr = int(beh["threshold"])
    app_protocol = hints.get("app_protocol") or "ics"
    mitre = hints.get("mitre_attack_id")
    notice = f"ICS_behavioral_{ident}"
    sub = f"{app_protocol}/{mitre}" if mitre else app_protocol
    active = f"ics_{ident}_active"
    thr_opt = f"ics_{ident}_concurrency_threshold"
    port_opt = f"ics_{ident}_port"

    meta = [f"# detection_gen_mode: behavioral ({beh['signal']} -> connection concurrency)",
            f"# check_id: {record.check_id}", f"# app_protocol: {app_protocol}"]
    if mitre:
        meta.append(f"# mitre_attack_id: {mitre}")
    if record.cve_id:
        meta.append(f"# cve: {record.cve_id}")

    return (
        f"# Auto-generated connection-concurrency policy by detection-gen from icsScanner check "
        f"'{record.check_id}'.\n"
        f"# Pool/connection-exhaustion detector: counts connections held OPEN at once to the service\n"
        f"# host on tcp/{port} and raises a NOTICE when that reaches {thr_opt}. Concurrency is the\n"
        f"# faithful signal -- connection RATE cannot separate this attack from reconnect-heavy masters\n"
        f"# (see lab-notes/detection-gen-pnnl-full-set-validation-2026-11.md). TUNE {thr_opt} to the\n"
        f"# target device's real connection-pool / max-clients size at deploy time.\n"
        + "\n".join(meta) + "\n"
        + _tuning_lines(beh.get("tuning"))
        + "@load base/frameworks/notice\n\n"
        "module ICS_Scanner;\n\n"
        "export {\n"
        f"\tredef enum Notice::Type += {{ {notice} }};\n"
        f"\t## Concurrency at/above which to alert -- redef to the target device's pool size.\n"
        f"\toption {thr_opt}: count = {thr};\n"
        f"\toption {port_opt}: port = {port}/tcp;\n"
        "}\n\n"
        f"global {active}: table[addr] of count &default=0;\n\n"
        "event connection_established(c: connection)\n"
        "\t{\n"
        f"\tif ( c$id$resp_p != {port_opt} ) return;\n"
        "\tlocal srv = c$id$resp_h;\n"
        f"\t{active}[srv] += 1;\n"
        f"\tif ( {active}[srv] >= {thr_opt} )\n"
        f"\t\tNOTICE([$note=ICS_Scanner::{notice},\n"
        f"\t\t        $msg=fmt(\"ICS-SCANNER BEHAVIORAL - {record.check_id} (%d concurrent connections to %s)\", {active}[srv], cat(srv)),\n"
        f"\t\t        $sub=\"{sub}\",\n"
        "\t\t        $conn=c,\n"
        f"\t\t        $identifier=cat(cat(srv), \"{record.check_id}\")]);\n"
        "\t}\n\n"
        "event connection_state_remove(c: connection)\n"
        "\t{\n"
        f"\tif ( c$id$resp_p != {port_opt} ) return;\n"
        "\tlocal srv = c$id$resp_h;\n"
        f"\tif ( srv in {active} && {active}[srv] > 0 )\n"
        f"\t\t{active}[srv] -= 1;\n"
        "\t}\n"
    )
