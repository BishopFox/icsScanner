#!/usr/bin/env python3
"""Derive Suricata rules for the SOURCE-based OT attacks that content signatures can't catch —
unauthorized-IP access and identity spoofing — by learning the authorized master->device flows from a
known-good BASELINE capture and emitting an allowlist rule per protocol. Built 2026-11-06 (c1 of the
PNNL detection work; see lab-notes/pnnl-validation.md).

detection-gen's normal rules come from icsScanner checks (a known vulnerable behavior -> a content
signature). That cannot express "a DNP3/Modbus request to a device from a source that is not an
authorized master", because the authorized set is environment-specific. This tool learns that set
from the baseline the operator captures in THEIR environment, then emits:

    alert tcp ![<authorized masters>] any -> [<devices>] <port> ( msg:"..."; flow:to_server; ... )

one per protocol. A non-master talking the protocol to a device (the unauthorized-IP / spoofing
attacks) fires it; the authorized masters stay silent.

Usage (from detection-gen/; requires tshark):
    python3 derive_from_captures.py --baseline <baseline.pcap> [more...] \
        --out output/derived.rules [--protocols dnp3,modbus]

SAFE/offline: reads pcaps via tshark, writes a rules file; sends nothing on the network. The emitted
rules embed the learned IPs, so they are specific to the environment the baseline came from — review
before deploying, and re-derive when the authorized master set changes.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

PROTOCOL_PORTS = {"dnp3": 20000, "modbus": 502}
_SID_BASE = 9100000   # derived rules get their own block above the check-generated 9000000-9099999 range


def flows_via_tshark(pcap: Path, ports):
    """Yield (proto, src_ip, dst_ip) for every packet sent TO a device port (to_server)."""
    port_to_proto = {p: proto for proto, p in ports.items()}
    filt = " || ".join(f"tcp.dstport=={p} || udp.dstport=={p}" for p in ports.values())
    cmd = ["tshark", "-r", str(pcap), "-Y", filt, "-T", "fields",
           "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.dstport", "-e", "udp.dstport", "-E", "separator=|"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    try:
        for line in proc.stdout:
            parts = line.rstrip("\n").split("|")
            if len(parts) != 4:
                continue
            src, dst, tdp, udp = parts
            port = tdp or udp
            try:
                proto = port_to_proto.get(int(port))
            except (TypeError, ValueError):
                proto = None
            if proto and src and dst:
                yield proto, src, dst
    finally:
        proc.stdout.close()
        proc.wait()


def learn_authorized(flow_tuples, protocols):
    """flow_tuples: iterable of (proto, src, dst) to-device packets. Returns
    {proto: {"masters": sorted[ip], "devices": sorted[ip]}} — masters = sources seen talking to a
    device port in the baseline; devices = the destinations. Pure + unit-testable."""
    masters = {p: set() for p in protocols}
    devices = {p: set() for p in protocols}
    for proto, src, dst in flow_tuples:
        if proto not in masters:
            continue
        masters[proto].add(src)
        devices[proto].add(dst)
    return {p: {"masters": sorted(masters[p]), "devices": sorted(devices[p])} for p in protocols
            if masters[p] and devices[p]}


def emit_rules(learned, ports, sid_base=_SID_BASE):
    """Emit one unauthorized-source allowlist rule per protocol. Pure + unit-testable."""
    rules = []
    sid = sid_base
    for proto in sorted(learned):
        port = ports[proto]
        masters = ",".join(learned[proto]["masters"])
        devices = ",".join(learned[proto]["devices"])
        rules.append(
            f'alert tcp ![{masters}] any -> [{devices}] {port} '
            f'( msg:"ICS-DERIVED unauthorized {proto.upper()} source (not a baseline master)"; '
            f'flow:to_server; classtype:attempted-recon; '
            f'metadata:detection_gen_mode derived, detection_gen_source baseline_allowlist, '
            f'mitre_attack_id T0846; sid:{sid}; rev:1; )'
        )
        sid += 1
    return rules


def build(baseline_paths, protocols):
    ports = {p: PROTOCOL_PORTS[p] for p in protocols}

    def all_flows():
        for bp in baseline_paths:
            bp = Path(bp)
            caps = ([bp] if bp.is_file()
                    else sorted(f for f in bp.rglob("*") if f.suffix.lower() in (".pcap", ".pcapng")))
            for cap in caps:
                yield from flows_via_tshark(cap, ports)

    learned = learn_authorized(all_flows(), protocols)
    return learned, emit_rules(learned, ports)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baseline", required=True, nargs="+", help="known-good baseline pcap(s)/dir(s)")
    ap.add_argument("--out", required=True, type=Path, help="output .rules file")
    ap.add_argument("--protocols", default="dnp3,modbus", help="comma-separated (default dnp3,modbus)")
    args = ap.parse_args()

    if shutil.which("tshark") is None:
        ap.error("tshark is required")
    protocols = [p.strip() for p in args.protocols.split(",") if p.strip()]
    unknown = [p for p in protocols if p not in PROTOCOL_PORTS]
    if unknown:
        ap.error(f"unknown protocol(s) {unknown}")

    learned, rules = build(args.baseline, protocols)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    header = ["# Derived from baseline captures by derive_from_captures.py — environment-specific, review before use."]
    for proto in sorted(learned):
        header.append(f"#   {proto}: masters={learned[proto]['masters']} devices={learned[proto]['devices']}")
    args.out.write_text("\n".join(header + rules) + "\n", encoding="utf-8")

    print("[derive] learned from baseline:")
    for proto in sorted(learned):
        print(f"  {proto}: {len(learned[proto]['masters'])} master(s), {len(learned[proto]['devices'])} device(s)")
    print(f"[derive] wrote {len(rules)} rule(s) -> {args.out}")


if __name__ == "__main__":
    main()
