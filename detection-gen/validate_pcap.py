#!/usr/bin/env python3
"""Validate detection-gen's generated Suricata rules against labeled ICS pcaps — built for the PNNL
ICS network-capture dataset (DOI 10.25584/PNNLDH/1838670), whose ~14 scenarios are labeled (normal
baseline vs. unauthorized-IP, malformed, identity-spoofing, ARP-MITM, recon, data-injection, ...).

It answers the two questions that matter for a generated ruleset: do the rules FIRE on the attack
scenarios (true positives), and do they stay SILENT on the normal baseline (no false positives)?

Usage (from detection-gen/, after generating rules and downloading the dataset):
    python3 generate.py --checks-dir ../checks --out output/ --formats suricata
    python3 validate_pcap.py --pcaps <pnnl-dir> --rules output/

- --pcaps: a file or directory of .pcap/.pcapng (recursed). Each file's scenario label comes from its
  filename; any label containing a baseline keyword (default: normal, baseline, benign) is expected
  to stay silent, everything else is expected to fire. Override with --baseline-keyword (repeatable).
- --rules: a .rules file or a directory of them (all are combined).

Suricata must be installed to actually run the captures. If it is not, the tool prints the exact
commands it WOULD run (per pcap) and exits 2 — so it is still useful as a runbook on a box without
Suricata. SAFE/offline: it only replays pcaps through Suricata locally; it sends nothing on a network.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_BASELINE_KEYWORDS = ("normal", "baseline", "benign")
_FASTLOG_SID = re.compile(r"\[\d+:(\d+):\d+\]")


def scenario_of(pcap: Path) -> str:
    return pcap.stem.lower()


def expectation_for(scenario: str, baseline_keywords=DEFAULT_BASELINE_KEYWORDS) -> str:
    """'should_not_fire' for a baseline capture, else 'should_fire'. Pure + unit-testable."""
    s = scenario.lower()
    return "should_not_fire" if any(k in s for k in baseline_keywords) else "should_fire"


def verdict_for(expectation: str, fired: bool) -> str:
    """Map (expectation, fired?) to a result. Pure + unit-testable.
    - baseline that stayed silent  -> ok
    - baseline that fired          -> false_positive
    - attack that fired            -> ok (true positive)
    - attack that stayed silent    -> missed (no coverage — not necessarily a bug: the ruleset may
                                       simply not target this scenario's protocol/behavior)"""
    if expectation == "should_not_fire":
        return "ok" if not fired else "false_positive"
    return "ok" if fired else "missed"


def evaluate(results: dict) -> dict:
    """results: {pcap_name: {"scenario": str, "expectation": str, "sids": [int,...]}}.
    Returns {"rows":[...], "summary":{ok, false_positive, missed, total}}. Pure + unit-testable."""
    rows, counts = [], {"ok": 0, "false_positive": 0, "missed": 0}
    for name, r in sorted(results.items()):
        fired = bool(r.get("sids"))
        v = verdict_for(r["expectation"], fired)
        counts[v] += 1
        rows.append({"pcap": name, "scenario": r["scenario"], "expectation": r["expectation"],
                     "fired": fired, "sids": sorted(set(r.get("sids", []))), "verdict": v})
    return {"rows": rows, "summary": {**counts, "total": len(rows)}}


def parse_fast_log(text: str) -> list:
    """Extract alerted SIDs from a Suricata fast.log body. Pure + unit-testable."""
    return [int(m) for m in _FASTLOG_SID.findall(text)]


# ── content-only matching (no Suricata; tests the rule's content/pcre against payloads directly) ──
# Suricata suppresses a rule before testing its content when the capture doesn't satisfy the rule's
# flow:established / direction guards (e.g. a one-sided attacker-VM capture). Those guards are correct
# for detecting icsScanner's own probe but hide whether the SIGNATURE discriminates attack from
# baseline. This mode answers that question directly: extract each packet's app-layer payload via
# tshark and test the rule's content:/pcre: matchers against it, ignoring flow state entirely.
_CONTENT_RE = re.compile(r'content:"((?:[^"\\]|\\.)*)"')
_PCRE_RE = re.compile(r'pcre:"/(.*?)/([ismxADSEnan] *)*"')
_SID_RE = re.compile(r"\bsid:(\d+)\b")


def parse_content_value(s: str) -> bytes:
    """A Suricata content string -> bytes. |..| sections are space-separated hex; text outside pipes
    is literal ASCII (with \\\" and \\\\ unescaped)."""
    out = bytearray()
    in_hex = False
    i = 0
    s = s.replace('\\"', '"').replace("\\\\", "\\")
    for part in s.split("|"):
        if in_hex:
            for tok in part.split():
                out.append(int(tok, 16))
        else:
            out.extend(part.encode("latin-1", errors="replace"))
        in_hex = not in_hex
    return bytes(out)


def extract_matchers(rule_line: str):
    """Return (sid, [ (kind, value) ]) for a rule: kind 'content' -> bytes, 'pcre' -> compiled bytes
    regex. A payload 'fires' the rule only if it satisfies ALL matchers (Suricata ANDs them)."""
    sid_m = _SID_RE.search(rule_line)
    sid = int(sid_m.group(1)) if sid_m else -1
    matchers = []
    for m in _CONTENT_RE.finditer(rule_line):
        matchers.append(("content", parse_content_value(m.group(1))))
    for m in _PCRE_RE.finditer(rule_line):
        body = m.group(1)
        flags = re.DOTALL if (m.group(2) and "s" in m.group(2)) else 0
        try:
            matchers.append(("pcre", re.compile(body.encode("latin-1"), flags)))
        except re.error:
            pass
    return sid, matchers


def rule_fires_on(matchers, payload: bytes) -> bool:
    if not matchers:
        return False
    for kind, val in matchers:
        if kind == "content":
            if val not in payload:
                return False
        else:  # pcre
            if not val.search(payload):
                return False
    return True


def _payloads_via_tshark(pcap: Path):
    """Yield each packet's non-empty TCP/UDP app-layer payload bytes from a capture (streamed)."""
    cmd = ["tshark", "-r", str(pcap), "-Y", "tcp.len>0 || udp.length>8", "-T", "fields",
           "-e", "tcp.payload", "-e", "udp.payload", "-E", "separator=|"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    try:
        for line in proc.stdout:
            tcp_pl, _, udp_pl = line.rstrip("\n").partition("|")
            hexes = tcp_pl or udp_pl
            if not hexes:
                continue
            try:
                yield bytes.fromhex(hexes)
            except ValueError:
                continue
    finally:
        proc.stdout.close()
        proc.wait()


def content_only_run(pcap: Path, rules: list) -> list:
    """Return the sids whose matchers fire on any payload in the capture. `rules` is a list of
    (sid, matchers). Streams payloads; a rule is recorded on its first matching payload."""
    pending = {sid: m for sid, m in rules if m}
    fired = []
    for payload in _payloads_via_tshark(pcap):
        if not pending:
            break
        for sid in list(pending):
            if rule_fires_on(pending[sid], payload):
                fired.append(sid)
                del pending[sid]
    return fired


def load_rules_for_content(rules_path: Path) -> list:
    """Parse all alert rules under a file/dir into [(sid, matchers)]."""
    files = [rules_path] if rules_path.is_file() else sorted(rules_path.rglob("*.rules"))
    out = []
    for f in files:
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip().startswith("alert "):
                out.append(extract_matchers(line))
    return out


def iter_pcaps(path: Path):
    if path.is_dir():
        yield from sorted(f for f in path.rglob("*") if f.suffix.lower() in (".pcap", ".pcapng"))
    elif path.suffix.lower() in (".pcap", ".pcapng"):
        yield path


def combine_rules(rules_path: Path, dest: Path) -> int:
    """Concatenate one .rules file or every .rules in a dir into `dest`. Returns the rule-line count."""
    files = ([rules_path] if rules_path.is_file()
             else sorted(rules_path.rglob("*.rules")))
    n = 0
    with dest.open("w", encoding="utf-8") as out:
        for f in files:
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                out.write(line + "\n")
                if line.strip().startswith("alert "):
                    n += 1
    return n


def suricata_command(pcap: Path, rules: Path, workdir: Path) -> list:
    """The exact argv this tool runs per pcap (also printed when Suricata is absent)."""
    return ["suricata", "-r", str(pcap), "-S", str(rules), "-l", str(workdir), "-k", "none"]


def run_one(pcap: Path, rules: Path) -> list:
    """Run Suricata on one pcap, return the alerted SIDs. Requires suricata on PATH."""
    with tempfile.TemporaryDirectory() as td:
        wd = Path(td)
        subprocess.run(suricata_command(pcap, rules, wd), capture_output=True, text=True, timeout=600)
        fast = wd / "fast.log"
        return parse_fast_log(fast.read_text(encoding="utf-8", errors="replace")) if fast.exists() else []


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcaps", required=True, type=Path, help="pcap file or directory (recursed)")
    ap.add_argument("--rules", required=True, type=Path, help=".rules file or directory of them")
    ap.add_argument("--baseline-keyword", action="append", default=[],
                    help="filename substring marking a baseline (silent-expected) capture; repeatable")
    ap.add_argument("--content-only", action="store_true",
                    help="test each rule's content/pcre against capture payloads directly (via tshark), "
                         "ignoring Suricata flow/direction guards — runs without Suricata")
    args = ap.parse_args()

    baseline_kw = tuple(args.baseline_keyword) or DEFAULT_BASELINE_KEYWORDS
    pcaps = list(iter_pcaps(args.pcaps))
    if not pcaps:
        ap.error(f"no .pcap/.pcapng under {args.pcaps}")

    if args.content_only:
        rules = load_rules_for_content(args.rules)
        rules = [(sid, m) for sid, m in rules if m]   # only rules with usable matchers
        print(f"[validate] content-only: {len(pcaps)} capture(s); {len(rules)} rule(s) with matchers from {args.rules}")
        if shutil.which("tshark") is None:
            print("[validate] tshark is required for --content-only.", file=sys.stderr)
            sys.exit(2)
        results = {}
        for pcap in pcaps:
            scenario = scenario_of(pcap)
            results[pcap.name] = {"scenario": scenario, "expectation": expectation_for(scenario, baseline_kw),
                                  "sids": content_only_run(pcap, rules)}
        report = evaluate(results)
        for row in report["rows"]:
            mark = {"ok": "ok ", "false_positive": "FP ", "missed": "-- "}[row["verdict"]]
            sids = f" sids={row['sids']}" if row["sids"] else ""
            print(f"  [{mark}] {row['pcap']:46} {row['expectation']:16} fired={row['fired']}{sids}")
        s = report["summary"]
        print(f"\n{s['ok']} ok, {s['false_positive']} false-positive, {s['missed']} missed (no content match), of {s['total']}")
        sys.exit(1 if s["false_positive"] else 0)

    combined = Path(tempfile.gettempdir()) / "detgen_combined.rules"
    rule_count = combine_rules(args.rules, combined)
    print(f"[validate] {len(pcaps)} capture(s); {rule_count} rule(s) from {args.rules}")

    if shutil.which("suricata") is None:
        print("[validate] Suricata is not installed — cannot replay. Commands to run where it is:\n", file=sys.stderr)
        for pcap in pcaps:
            print("  " + " ".join(suricata_command(pcap, combined, Path("/tmp/suri-<scenario>"))))
        print("\nThen read each run's fast.log; a non-empty fast.log means the ruleset fired.", file=sys.stderr)
        sys.exit(2)

    results = {}
    for pcap in pcaps:
        scenario = scenario_of(pcap)
        results[pcap.name] = {"scenario": scenario, "expectation": expectation_for(scenario, baseline_kw),
                              "sids": run_one(pcap, combined)}
    report = evaluate(results)

    for row in report["rows"]:
        mark = {"ok": "ok ", "false_positive": "FP ", "missed": "-- "}[row["verdict"]]
        sids = f" sids={row['sids']}" if row["sids"] else ""
        print(f"  [{mark}] {row['pcap']:40} {row['expectation']:16} fired={row['fired']}{sids}")
    s = report["summary"]
    print(f"\n{s['ok']} ok, {s['false_positive']} false-positive, {s['missed']} missed (no fire), of {s['total']}")
    # A false positive on a baseline is the only hard failure; a 'missed' attack is a coverage note.
    sys.exit(1 if s["false_positive"] else 0)


if __name__ == "__main__":
    main()
