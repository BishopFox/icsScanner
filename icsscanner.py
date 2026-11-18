#!/usr/bin/env python3
"""icsscanner.py — icsScanner CLI driver.

The "last mile" this project was missing: everything else (core/registry.py, core/target.py,
core/scan_engine.py, core/logger.py, core/reporter.py, 98 checks under checks/) already worked,
but the only way to run a scan was a one-off Python script, same as the tests/smoke_test_*.py
files use. This wires those pieces into the invocation model 00-PROJECT-CHARTER.md § Scope
already decided: a YAML scan-policy file (target inventory + check selection + rate profile +
output) with CLI flags as overrides — closer to a Nessus scan-policy model than
a companion fuzzing toolkit's flag-heavy CLI. The authorized-use banner and --yes consent gate mirror
a companion fuzzing toolkit's confirm_targets() and a companion fuzzing toolkit's live-action
gate — same dual-use discipline, not new invention.

Usage:
    python3 icsscanner.py --policy templates/scan-policy.example.yaml --yes
    python3 icsscanner.py --inventory templates/target-inventory.example.yaml --protocol http
    python3 icsscanner.py --inventory my-inventory.yaml --include-destructive \
        --check-id http-schneider-powerlogic-egx100-default-creds --yes

AUTHORIZED USE ONLY — only scan devices you own or have explicit written permission to test.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from core.check import Check
from core.logger import ScanLogger
from core.registry import CheckRegistry
from core.reporter import ScanReporter
from core.scan_engine import ScanEngine, ScanEngineConfig, TwoTierRateLimiter
from core.scan_policy import ScanPolicy, load_scan_policy
from core.target import (
    CredentialResolutionError,
    InsecureKeyringBackendError,
    Target,
    load_target_inventory,
)

VERSION = "0.3.0"

WARNING_BANNER = """
╔══════════════════════════════════════════════════════════════════════╗
║                      *** AUTHORIZED USE ONLY ***                     ║
║                                                                      ║
║  icsScanner sends live protocol traffic to ICS/OT devices, including ║
║  real login attempts against published factory-default credentials  ║
║  when destructive checks are enabled. This can cause:                ║
║                                                                      ║
║    •  Account lockouts on devices with login-attempt thresholds      ║
║    •  Unexpected device reboots, hangs, or degraded availability     ║
║    •  Disruption to physical processes or equipment                  ║
║                                                                      ║
║  ONLY use against systems you have EXPLICIT WRITTEN AUTHORIZATION    ║
║  to test. ALWAYS coordinate with plant/facility operators before     ║
║  running. NEVER target production systems without approval.          ║
║                                                                      ║
║  By proceeding you confirm you have authorization to test the        ║
║  specified targets and accept full responsibility for any impact.    ║
╚══════════════════════════════════════════════════════════════════════╝
"""


PASSIVE_NOTICE = """
┌──────────────────────────────────────────────────────────────────────┐
│  PASSIVE MODE — receive-only. This mode TRANSMITS NOTHING: it reads    │
│  mirrored traffic (SPAN/TAP) or a capture file and dissects it.        │
│  Still, only monitor networks you are authorized to observe.           │
└──────────────────────────────────────────────────────────────────────┘
"""


def print_warning(passive: bool = False) -> None:
    print(PASSIVE_NOTICE if passive else WARNING_BANNER)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="icsscanner",
        description="Safety-first active ICS/OT vulnerability scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  icsscanner.py --policy templates/scan-policy.example.yaml --yes
  icsscanner.py --inventory templates/target-inventory.example.yaml --protocol http
  icsscanner.py --inventory my-inventory.yaml --include-destructive --yes
        """,
    )
    parser.add_argument(
        "--policy", default=None, metavar="PATH",
        help="Scan-policy YAML (see templates/scan-policy.example.yaml). CLI flags below "
             "override any value it sets.",
    )
    parser.add_argument(
        "--inventory", default=None, metavar="PATH",
        help="Target inventory YAML (see templates/target-inventory.example.yaml). Required "
             "if --policy is not given; overrides the policy's inventory: if both are given.",
    )
    parser.add_argument(
        "--protocol", action="append", default=None, metavar="PROTO",
        help="Restrict to this protocol. Repeatable. Overrides the policy's protocols: list.",
    )
    parser.add_argument(
        "--check-id", action="append", default=None, metavar="CHECK_ID",
        help="Restrict to this check_id. Repeatable. Overrides the policy's check_ids: list.",
    )
    parser.add_argument(
        "--include-destructive", action="store_true", default=False,
        help="Allow DESTRUCTIVE-tier checks to actually fire — confirmed lockout risk or a "
             "device write as part of the check's own verification (default: safe mode — these "
             "report fingerprint-only and never probe). Independent of --include-adverse, not a "
             "superset of it. Overrides the policy's include_destructive: if passed.",
    )
    parser.add_argument(
        "--include-adverse", action="store_true", default=False,
        help="Allow ADVERSE-tier checks to actually fire — a plain login attempt with no "
             "confirmed lockout risk and no device write (default: safe mode). Independent of "
             "--include-destructive, not a subset of it. Overrides the policy's "
             "include_adverse: if passed.",
    )
    parser.add_argument(
        "--max-concurrent-targets", type=int, default=None, metavar="N",
        help="Bounded concurrency across targets. Overrides the policy's value if passed.",
    )
    parser.add_argument(
        "--output", default=None, metavar="DIR",
        help="Output directory for the JSONL log and text summary. Overrides the policy's "
             "output_dir: if passed.",
    )
    parser.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip the interactive confirmation prompt before running destructive checks.",
    )
    parser.add_argument(
        "--report-html", action="store_true", default=False,
        help="Write a self-contained HTML report alongside the JSONL log in the output "
             "directory. Overrides the policy's report_html: if passed.",
    )
    parser.add_argument(
        "--report-csv", action="store_true", default=False,
        help="Write a CSV report (one row per finding) alongside the JSONL log in the output "
             "directory. Overrides the policy's report_csv: if passed.",
    )
    parser.add_argument(
        "--include-evidence", action="store_true", default=False,
        help="Include raw evidence bytes (hex) in generated HTML/CSV reports. No effect "
             "without --report-html/--report-csv. Excluded by default — reports are shared "
             "more casually than the raw JSONL log. Overrides the policy's include_evidence: "
             "if passed.",
    )

    # `discover` is a subcommand, not a top-level flag set, so the existing flat invocation
    # above (no subcommand = scan, exactly today's behavior) stays fully backward compatible —
    # dest="command" is None when no subcommand is given. See core/discovery.py (2026-08-25) for
    # the network-discovery feature this drives.
    subparsers = parser.add_subparsers(dest="command")
    discover_parser = subparsers.add_parser(
        "discover",
        help="Network discovery — active ARP scan or passive multi-protocol listener. "
             "AUTHORIZED USE ONLY, same as every other capability in this tool.",
    )
    discover_sub = discover_parser.add_subparsers(dest="discover_mode", required=True)

    active_parser = discover_sub.add_parser(
        "active", help="Broadcast one ARP request (or MiCOM Courier RPC query) per host in a subnet, collect replies.",
    )
    active_parser.add_argument("--cidr", required=True, metavar="CIDR", help="e.g. 192.168.1.0/24")
    active_parser.add_argument(
        "--method", default="arp", choices=["arp", "micom_courier", "factorytalk_rna", "enip", "knx"], metavar="METHOD",
        help="'arp' (default): broadcast ARP sweep. 'micom_courier': ONC-RPC portmapper query "
             "for MiCOM Courier-over-Ethernet/IEC 103 devices (core/discovery.py:micom_courier_scan). "
             "'factorytalk_rna': benign OpenNamespace handshake per host for FactoryTalk Linx RNA "
             "servers on TCP 4241 (core/discovery.py:factorytalk_rna_scan). 'enip': one UDP/44818 "
             "EtherNet/IP List Identity broadcast -> every CIP device on the segment replies with "
             "vendor/model/firmware/serial (core/discovery.py:enip_list_identity_scan). 'knx': one "
             "KNXnet/IP SEARCH_REQUEST to the KNX multicast group 224.0.23.12:3671 -> every KNX/IP "
             "gateway replies with its device info (core/discovery.py:knxnet_search_scan; --cidr ignored).",
    )
    active_parser.add_argument("--iface", default=None, metavar="IFACE", help="Default: auto-detect (arp method only)")
    active_parser.add_argument("--timeout", type=float, default=2.0, metavar="SECONDS", help="Reply collection window")
    active_parser.add_argument(
        "--force", action="store_true",
        help="Allow a range larger than /20 (4096 hosts) — refused by default (core/discovery.py:MAX_HOSTS_WITHOUT_FORCE).",
    )

    passive_parser = discover_sub.add_parser(
        "passive", help="Listen only — zero packets sent for ARP; a read-only MQTT subscribe for Sparkplug B.",
    )
    passive_parser.add_argument("--listen", type=float, required=True, dest="duration", metavar="SECONDS")
    passive_parser.add_argument("--iface", default=None, metavar="IFACE", help="Default: auto-detect")
    passive_parser.add_argument(
        "--protocols", default=None, metavar="LIST",
        help="Comma-separated (e.g. arp,sparkplug_b). Default: every registered listener.",
    )
    passive_parser.add_argument(
        "--broker", default=None, metavar="HOST:PORT",
        help="Sparkplug B MQTT broker — required if 'sparkplug_b' is among --protocols. No "
             "auto-discovery exists for this; it must be supplied.",
    )

    sniff_parser = discover_sub.add_parser(
        "sniff",
        help="Passive SPAN/TAP or pcap capture -> ICS asset inventory + CVE correlation. Zero packets sent.",
    )
    sniff_src = sniff_parser.add_mutually_exclusive_group(required=True)
    sniff_src.add_argument("--pcap", metavar="FILE", help="Offline capture file to dissect (no network).")
    sniff_src.add_argument("--span", metavar="IFACE",
                           help="Live SPAN/mirror/TAP interface — opened RX-only + promiscuous, never transmits.")
    sniff_src.add_argument("--zeek-logs", metavar="DIR", dest="zeek_logs",
                           help="Hybrid path: ingest an existing Zeek/ICSNPP sensor's identity logs instead of dissecting frames.")
    sniff_parser.add_argument("--window", type=float, default=60.0, metavar="SECONDS",
                              help="Live capture window with --span (default 60).")
    sniff_parser.add_argument("--detections", action="store_true",
                              help="Match the check corpus' detection_hints against the captured "
                                   "payloads natively (no Zeek) and render an 'Observed activity' "
                                   "section. Works with --pcap/--span. Zero transmit.")
    sniff_parser.add_argument("--notice-log", metavar="FILE", dest="notice_log",
                              help="A Zeek notice.log produced by the detection-gen rules; renders an "
                                   "'Observed activity' detections section correlated to the inventory. "
                                   "Pattern-on-wire, not confirmed compromise.")
    sniff_parser.add_argument("--save-baseline", metavar="FILE", dest="save_baseline",
                              help="Write the discovered inventory as a baseline snapshot (JSON) for "
                                   "future --baseline comparison. Zero transmit.")
    sniff_parser.add_argument("--baseline", metavar="FILE", dest="baseline",
                              help="Compare this run against a saved baseline and flag deviations: new "
                                   "assets, MAC changes (possible ARP spoofing), new protocols, new segments.")
    sniff_parser.add_argument("--emit-targets", metavar="FILE", dest="emit_targets",
                              help="Write the discovered endpoints as a YAML target-inventory file "
                                   "(host/port + vendor/product/version hints) that `scan --targets` "
                                   "consumes — passive identity pre-seeds the active fingerprint/version "
                                   "gate. Zero transmit.")
    sniff_parser.add_argument("--cve", action="store_true",
                              help="Correlate discovered assets against the CVE candidate corpus (identity-only, no packets).")
    sniff_parser.add_argument("--push-malcolm", metavar="URL", dest="push_malcolm",
                              help="After CVE correlation, push findings into an EXISTING Malcolm (mapi) "
                                   "via /mapi/event so the vuln layer shows in Malcolm's dashboards.")
    sniff_parser.add_argument("--malcolm-token", dest="malcolm_token", default=None,
                              help="Bearer token for --push-malcolm, if required.")
    sniff_parser.add_argument("--malcolm-insecure", dest="malcolm_insecure", action="store_true",
                              help="Skip TLS verification for --push-malcolm (lab host only).")

    malcolm_parser = discover_sub.add_parser(
        "malcolm",
        help="Read the asset inventory from an EXISTING Malcolm deployment (mapi) + correlate CVEs; "
             "optionally push findings back. Targets a running Malcolm — never builds or bundles one.")
    malcolm_parser.add_argument("--url", required=True, metavar="URL",
                                help="Base URL of the operator's Malcolm (e.g. https://malcolm.example).")
    malcolm_parser.add_argument("--token", default=None, help="Bearer token for the Malcolm mapi, if required.")
    malcolm_parser.add_argument("--insecure", action="store_true", help="Skip TLS verification (lab host only).")
    malcolm_parser.add_argument("--ip-field", dest="ip_field", default="source.ip", metavar="FIELD",
                                help="IP field to aggregate on (default source.ip).")
    malcolm_parser.add_argument("--detail-field", dest="detail_field", default="event.dataset", metavar="FIELD",
                                help="Field nested under the IP. Default lists protocols (Zeek datasets); point "
                                     "it at a vendor field + --vendor-from-detail to enable CVE correlation.")
    malcolm_parser.add_argument("--vendor-from-detail", dest="vendor_from_detail", action="store_true",
                                help="Treat the detail field's values as vendor identities (enables --cve).")
    malcolm_parser.add_argument("--since", default="7 days ago", metavar="WHEN",
                                help="Start of the aggregation time window (default '7 days ago').")
    malcolm_parser.add_argument("--cve", action="store_true",
                                help="Correlate the pulled inventory against the CVE candidate corpus.")
    malcolm_parser.add_argument("--push", action="store_true",
                                help="Push the correlated CVE findings back into Malcolm via /mapi/event.")

    for p in (active_parser, passive_parser, sniff_parser, malcolm_parser):
        p.add_argument("--output", default="./output", metavar="DIR")
        p.add_argument("--html", action="store_true", help="Write a discovery HTML report.")
        p.add_argument("--csv", action="store_true", help="Write a discovery CSV (one row per device).")
        p.add_argument("--svg", action="store_true", help="Write a device-map SVG (not an inferred topology).")
        p.add_argument("--json", action="store_true", help="Write a machine-ingestible inventory JSON (SIEM/CMDB).")

    return parser


def _push_findings_to_malcolm(url: str, findings: list, token, insecure: bool) -> int:
    """Push CVE findings into an EXISTING Malcolm via its /mapi/event webhook. Returns the count pushed."""
    from core.malcolm import MalcolmClient
    client = MalcolmClient(url, token=token, verify_tls=not insecure)
    pushed = client.push_findings([
        {"device_ip": f["ip"], "cve_id": f["cve_id"], "vendor": f.get("vendor"), "model": f.get("model"),
         "title": f"{f['cve_id']} — {f.get('vendor', '')} {f.get('model') or ''}".strip(" —")}
        for f in findings if f.get("cve_id") and f.get("ip")])
    print(f"[malcolm] pushed {pushed} finding(s) into {url} via /mapi/event.")
    return pushed


def run_discover(args: argparse.Namespace) -> int:
    """Dispatches to core/discovery.py, logs results via the same JSONL-log convention every
    other run in this project uses (core/logger.py:ScanLogger — a distinct "icsscanner-
    discovery" filename prefix keeps these logs/reports from colliding in name with a scan
    run's), and writes whichever of --html/--csv/--svg was requested via core/reporter.py."""
    from core.discovery import (arp_scan, micom_courier_scan, factorytalk_rna_scan, enip_list_identity_scan,
                                 knxnet_search_scan, passive_listen)
    from core.logger import ScanLogger

    findings: list = []
    if args.discover_mode == "active":
        if args.method == "micom_courier":
            print(f"[discovery] Active MiCOM Courier/IEC 103 RPC scan of {args.cidr}...")
            devices = micom_courier_scan(cidr=args.cidr, timeout=args.timeout, force=args.force)
        elif args.method == "factorytalk_rna":
            print(f"[discovery] Active FactoryTalk Linx RNA sweep of {args.cidr} (TCP 4241)...")
            devices = factorytalk_rna_scan(cidr=args.cidr, timeout=args.timeout, force=args.force)
        elif args.method == "enip":
            print(f"[discovery] Active EtherNet/IP List Identity broadcast sweep of {args.cidr} (UDP 44818)...")
            devices = enip_list_identity_scan(cidr=args.cidr, timeout=args.timeout, force=args.force)
        elif args.method == "knx":
            print("[discovery] Active KNXnet/IP multicast SEARCH sweep (UDP 3671, 224.0.23.12; --cidr ignored)...")
            devices = knxnet_search_scan(timeout=args.timeout)
        else:
            print(f"[discovery] Active ARP scan of {args.cidr} (interface: {args.iface or 'auto-detect'})...")
            devices = arp_scan(cidr=args.cidr, iface=args.iface, timeout=args.timeout, force=args.force)
    elif args.discover_mode == "sniff":
        from core.passive import run_passive, correlate_cves
        native_dets: list = []
        matchers = None
        if getattr(args, "detections", False):
            if args.zeek_logs:
                print("[detections] --detections needs packets; ignored with --zeek-logs "
                      "(use --notice-log for a Zeek sensor's own detections).")
            else:
                from core.detect_match import build_matchers
                matchers = build_matchers("checks")
                print(f"[detections] native matcher armed: {matchers['count']} pattern(s)")
        if args.pcap:
            print(f"[discovery] Passive dissection of {args.pcap} — zero packets sent...")
            devices = run_passive(pcap=args.pcap, matchers=matchers, detections_out=native_dets)
        elif args.zeek_logs:
            from core.passive import ingest_zeek_logs
            print(f"[discovery] Ingesting Zeek/ICSNPP identity logs from {args.zeek_logs}...")
            devices = ingest_zeek_logs(args.zeek_logs)
        else:
            print(f"[discovery] Passive SPAN/TAP capture on {args.span} for {args.window}s "
                  f"(RX-only, promiscuous, zero packets sent)...")
            devices = run_passive(iface=args.span, window=args.window,
                                  matchers=matchers, detections_out=native_dets)
        findings = correlate_cves(devices) if args.cve else []
        if getattr(args, "push_malcolm", None) and findings:
            _push_findings_to_malcolm(args.push_malcolm, findings,
                                      getattr(args, "malcolm_token", None), getattr(args, "malcolm_insecure", False))
    elif args.discover_mode == "malcolm":
        from core.malcolm import MalcolmClient
        from core.passive import correlate_cves
        from core.discovery import DiscoveredDevice
        client = MalcolmClient(args.url, token=args.token, verify_tls=not args.insecure)
        print(f"[malcolm] reading asset inventory from {args.url} (mapi)...")
        devices = []
        try:
            # Prefer NetBox-enriched vendor/model identity (enables real CVE correlation); the custom
            # --vendor-from-detail path bypasses it for operators whose schema exposes vendor elsewhere.
            idents = [] if args.vendor_from_detail else client.read_identities(time_from=args.since)
            if idents:
                for r in idents:
                    dev = DiscoveredDevice(ip=r["ip"], vendor=r.get("vendor") or "unknown", method="malcolm_mapi")
                    if r.get("model"):
                        dev.extra["model"] = r["model"]
                    devices.append(dev)
                print(f"[malcolm] pulled {len(devices)} NetBox-enriched asset(s) (vendor/model).")
            else:
                for a in client.read_assets(ip_field=args.ip_field, detail_field=args.detail_field, time_from=args.since):
                    dev = DiscoveredDevice(ip=a["ip"], method="malcolm_mapi")
                    if args.vendor_from_detail and a["protocols"]:
                        dev.vendor = a["protocols"][0]
                        dev.extra["malcolm_values"] = a["protocols"]
                    else:
                        dev.extra["protocols"] = a["protocols"]
                    devices.append(dev)
                print(f"[malcolm] pulled {len(devices)} asset(s) (presence; no NetBox device identity found).")
        except OSError as exc:
            print(f"[malcolm] could not reach Malcolm: {exc}")
            return 1
        findings = correlate_cves(devices) if args.cve else []
        if args.push and findings:
            _push_findings_to_malcolm(args.url, findings, args.token, args.insecure)
    else:
        protocols = args.protocols.split(",") if args.protocols else None
        broker = None
        if args.broker:
            host, _, port = args.broker.partition(":")
            broker = (host, int(port) if port else 1883)
        elif protocols is None or "sparkplug_b" in protocols:
            print("[discovery] Note: no --broker given — the sparkplug_b listener will fail "
                  "closed (no auto-discovery exists for a Sparkplug B broker address).")
        print(f"[discovery] Listening for {args.duration}s (interface: {args.iface or 'auto-detect'})...")
        devices = passive_listen(duration=args.duration, iface=args.iface, protocols=protocols, sparkplug_broker=broker)

    print(f"\n[discovery] {len(devices)} device(s) found.")
    if devices:
        print(f"  {'IP':<16} {'MAC':<18} {'Vendor':<28} Method")
        print("  " + "-" * 90)
        for d in devices:
            print(f"  {d.ip:<16} {d.mac or '—':<18} {d.vendor:<28} {d.method}")
            model = d.extra.get("model")
            if model and model != "unknown":
                line = f"      model: {model}"
                cves = d.extra.get("matched_cves")
                if cves:
                    line += f"  |  likely CVEs: {', '.join(cves)}"
                print(line)
    if findings:
        model_hits = sum(1 for f in findings if f.get("scope") == "model")
        print(f"\n[cve] {model_hits} model-confirmed advisory match(es); "
              f"{len(findings) - model_hits} vendor-wide (model not confirmed).")

    if getattr(args, "save_baseline", None):
        from core.baseline import save_baseline
        n = save_baseline(devices, args.save_baseline)
        print(f"\n[baseline] Saved {n} asset(s) to {args.save_baseline}")
    if getattr(args, "baseline", None):
        from core.baseline import load_baseline, diff_baseline, render_text
        base = load_baseline(args.baseline)
        if base is None:
            print(f"\n[baseline] Could not read a baseline from {args.baseline}.")
        else:
            print("\n[baseline] " + render_text(diff_baseline(base, devices)))

    if getattr(args, "emit_targets", None):
        from core.passive import write_target_inventory
        n_entries = write_target_inventory(devices, args.emit_targets)
        print(f"\n[targets] Wrote {n_entries} pre-hinted target entry(ies) to {args.emit_targets} "
              f"— review, then: scan --targets {args.emit_targets}")

    # Detections come from the native matcher (--detections) and/or an external Zeek notice.log
    # (--notice-log); both produce the same Detection records and render one Observed-Activity section.
    detections = list(locals().get("native_dets") or [])
    if getattr(args, "notice_log", None):
        from core.detections import parse_notice_log
        detections.extend(parse_notice_log(args.notice_log))
    if detections:
        from core.detections import summarize_detections, render_detections_text
        det_summary = summarize_detections([d.as_dict() for d in detections],
                                           [d.as_dict() for d in devices])
        if det_summary:
            print("\n" + render_detections_text(det_summary))
    elif getattr(args, "notice_log", None):
        print(f"\n[detections] No ICS_Scanner NOTICEs found in {args.notice_log}.")
    elif getattr(args, "detections", False):
        print("\n[detections] No detection_hints patterns matched the capture.")

    with ScanLogger(args.output, filename_prefix="icsscanner-discovery") as logger:
        for d in devices:
            logger.log_event("device_discovered", **d.as_dict())
        if findings:
            from core.passive import findings_to_results
            for result in findings_to_results(findings, devices):
                logger.log(result)  # FINGERPRINT_ONLY -> renders in the main findings report
        for det in detections:
            fields = {k: v for k, v in det.as_dict().items() if k != "type"}
            logger.log_event("detection", **fields)  # -> Observed Activity section in the report
        logger.log_event(
            "discovery_run_summary",
            mode=args.discover_mode,
            total=len(devices),
            findings=len(findings),
            duration_s=getattr(args, "duration", None) if args.discover_mode == "passive" else None,
        )
        log_path = logger.log_path

    if args.html or args.csv or args.svg or args.json:
        from core.reporter import ScanReporter

        reporter = ScanReporter(args.output)
        if args.html:
            print(f"[report] Inventory HTML: {reporter.to_discovery_html(log_path=log_path)}")
        if args.csv:
            print(f"[report] Inventory CSV: {reporter.to_discovery_csv(log_path=log_path)}")
        if args.svg:
            print(f"[report] Device-map SVG: {reporter.to_discovery_svg(log_path=log_path)}")
        if args.json:
            print(f"[report] Inventory JSON: {reporter.to_discovery_json(log_path=log_path)}")
        # Passive CVE findings render through the SAME findings report as an active scan.
        if findings and args.html:
            print(f"[report] Findings HTML: {reporter.to_html(log_path=log_path)}")
        if findings and args.csv:
            print(f"[report] Findings CSV: {reporter.to_csv(log_path=log_path)}")

    return 0


def confirm_destructive_run(targets: list[Target], checks: list[Check], yes: bool, tier: str = "destructive") -> bool:
    """Mirrors a companion fuzzing toolkit:confirm_targets() — lists what's about to happen,
    short-circuits on --yes, otherwise requires an explicit interactive 'y'. Returns True to
    proceed, False to abort. Only called when include_destructive (or, for the adverse tier,
    include_adverse) is actually true — safe-mode runs need no prompt, matching the engine's own
    safe-by-default posture. `tier` only changes the printed wording (default "destructive"
    preserves this function's original text exactly, for the adverse tier main() passes
    tier="adverse") — both tiers still perform a real, live login attempt against the target and
    get the same confirmation discipline, not a lighter one for "adverse."""
    label = tier.upper()
    print(f"\n[targets] The following hosts will be scanned with {label} checks enabled:")
    for t in targets:
        print(f"    {t}")
    print(f"\n[checks] {len(checks)} {tier} check(s) may fire, fingerprint permitting.")

    if yes:
        print("\n[--yes] Skipping confirmation prompt.\n")
        return True

    print()
    try:
        answer = input(f"Proceed with LIVE {tier} checks? [y/N] ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print("\n[abort] Cancelled by user.")
        return False

    if answer != "y":
        print("Aborted.")
        return False
    return True


def resolve_policy(args: argparse.Namespace) -> ScanPolicy:
    """Load the policy (or start from all-defaults if --policy wasn't given), then apply any
    CLI flag the user actually passed as an override on top of it."""
    policy = load_scan_policy(args.policy) if args.policy else ScanPolicy(inventory=args.inventory or "")

    if args.inventory:
        policy.inventory = args.inventory
    if args.protocol:
        policy.protocols = args.protocol
    if args.check_id:
        policy.check_ids = args.check_id
    if args.include_destructive:
        policy.include_destructive = True
    if args.include_adverse:
        policy.include_adverse = True
    if args.max_concurrent_targets is not None:
        policy.max_concurrent_targets = args.max_concurrent_targets
    if args.output:
        policy.output_dir = args.output
    if args.report_html:
        policy.report_html = True
    if args.report_csv:
        policy.report_csv = True
    if args.include_evidence:
        policy.include_evidence = True

    return policy


def select_checks(registry: CheckRegistry, policy: ScanPolicy) -> list[Check]:
    selected = registry.checks()
    if policy.protocols:
        selected = [c for c in selected if c.metadata.protocol in policy.protocols]
    if policy.check_ids:
        wanted = set(policy.check_ids)
        selected = [c for c in selected if c.metadata.check_id in wanted]
    return selected


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # Passive discovery (listen / sniff) transmits NOTHING — don't show the active-scan warning.
    passive_mode = (getattr(args, "command", None) == "discover"
                    and getattr(args, "discover_mode", None) in ("passive", "sniff"))
    print_warning(passive=passive_mode)

    if getattr(args, "command", None) == "discover":
        return run_discover(args)

    if not args.policy and not args.inventory:
        parser.error("--inventory is required when --policy is not given")

    try:
        policy = resolve_policy(args)
    except (ValueError, yaml.YAMLError) as e:
        print(f"[error] {e}", file=sys.stderr)
        return 1

    checks_dir = Path(__file__).resolve().parent / "checks"
    registry = CheckRegistry(checks_dir).load()
    selected = select_checks(registry, policy)

    try:
        targets = load_target_inventory(policy.inventory)
    except (ValueError, FileNotFoundError, KeyError, yaml.YAMLError) as e:
        print(f"[error] failed to load target inventory: {e}", file=sys.stderr)
        return 1

    if not targets:
        print("[error] No targets in the inventory. Exiting.")
        return 1
    if not selected:
        print("[error] No checks matched --protocol/--check-id (or the check registry is "
              "empty). Exiting.")
        return 1

    if policy.include_destructive:
        destructive = [c for c in selected if c.metadata.risk_tier() == "destructive"]
        if destructive and not confirm_destructive_run(targets, destructive, args.yes, tier="destructive"):
            return 0
    if policy.include_adverse:
        adverse = [c for c in selected if c.metadata.risk_tier() == "adverse"]
        if adverse and not confirm_destructive_run(targets, adverse, args.yes, tier="adverse"):
            return 0

    rate_limiter = TwoTierRateLimiter(
        global_pps=policy.global_pps,
        global_delay_s=policy.global_delay_s,
        per_target_pps=policy.per_target_pps,
        per_target_delay_s=policy.per_target_delay_s,
    )
    config = ScanEngineConfig(
        include_destructive=policy.include_destructive,
        include_adverse=policy.include_adverse,
        max_concurrent_targets=policy.max_concurrent_targets,
        rate_limiter=rate_limiter,
    )

    # Reachability note: as of 2026-08-16, no check actually calls Target.resolve_credential()
    # yet — this is defensive-in-depth for when one does. Any credential failure raised INSIDE
    # a check's own probe() already gets caught by ScanEngine._run_one()'s broad exception
    # handler and turned into a normal per-check ERROR result (with the exception type+message
    # in `error`, already diagnostic) — this outer except only fires for a failure outside that
    # path (e.g. during setup), which nothing triggers today. Logged here too, cheaply, so the
    # JSONL stays self-contained evidence even in that edge case.
    try:
        with ScanLogger(policy.output_dir) as logger:
            try:
                engine = ScanEngine(selected, config=config, logger=logger)
                engine.run(targets)
            except (CredentialResolutionError, InsecureKeyringBackendError) as e:
                logger.log_event("credential_error", error=f"{type(e).__name__}: {e}")
                raise
    except (CredentialResolutionError, InsecureKeyringBackendError) as e:
        print(f"[error] {e}", file=sys.stderr)
        return 1

    reporter = ScanReporter(policy.output_dir)
    reporter.summarize(log_path=logger.log_path)
    if policy.report_html:
        html_path = reporter.to_html(log_path=logger.log_path, include_evidence=policy.include_evidence)
        print(f"[report] HTML report: {html_path}")
    if policy.report_csv:
        csv_path = reporter.to_csv(log_path=logger.log_path, include_evidence=policy.include_evidence)
        print(f"[report] CSV report: {csv_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
