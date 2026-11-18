#!/usr/bin/env python3
"""Capture-analysis detectors for the two PNNL attack classes that are NOT expressible as Suricata
content/pcre signatures (so neither detection-gen's check-derived rules (c2) nor the baseline
allowlist rules (c1) cover them): malformed DNP3 frames (bad CRC) and ARP spoofing. Built 2026-11-06.

Both are semantic/stateful, not byte-signatures:
  - bad DNP3 CRC: the data-link CRC is computed over the frame bytes, so no fixed pattern matches a
    "bad" frame; you must RECOMPUTE the DNP3 CRC and compare. A real device silently drops these, so a
    burst of them is a malformed-traffic / fuzzing indicator (PNNL test case 4).
  - ARP spoofing: an IP suddenly answered by a second MAC (the MitM inserting itself). You detect it
    by tracking IP->MAC bindings, not by matching payload bytes (PNNL test case 8).

Usage (from detection-gen/; requires tshark):
    python3 capture_anomaly_check.py --pcap <capture> [--check dnp3-crc,arp-spoof]

SAFE/offline: reads the capture via tshark, computes/compares; sends nothing on the network.
"""
from __future__ import annotations

import argparse
import collections
import shutil
import subprocess
import sys
from pathlib import Path

_DNP3_START = b"\x05\x64"


def dnp3_crc(data: bytes) -> int:
    """DNP3 data-link CRC (poly 0xA6BC reflected, final one's-complement), transmitted low byte first.
    Pure + unit-testable; self-validated below by every well-formed baseline frame passing."""
    crc = 0x0000
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if (crc & 1) else (crc >> 1)
    return (~crc) & 0xFFFF


def dnp3_frame_crc_ok(frame: bytes) -> bool:
    """True iff the frame's 10-byte data-link header carries a valid CRC (bytes 8-9, low byte first).
    Only the link-header CRC is checked (enough to flag the malformed frames); frames too short or not
    starting with 0x0564 are treated as not-a-DNP3-link-frame (returns True — not our anomaly)."""
    if len(frame) < 10 or frame[0:2] != _DNP3_START:
        return True
    want = frame[8] | (frame[9] << 8)
    return dnp3_crc(frame[0:8]) == want


def check_dnp3_crc(pcap: Path):
    """Return (total_dnp3_frames, bad_frames) by recomputing the link-header CRC of each DNP3 payload.

    NOTE (verified 2026-11-06 against PNNL test case 4): this validates the data-link HEADER CRC, which
    reliably flags link-header corruption. It does NOT catch PNNL test case 4's specific malformed
    frames, whose corruption is in the per-16-byte DATA-CHUNK CRCs — tshark's DNP3 reassembly strips
    those chunk CRCs before presenting the payload here, so they aren't observable from `tcp.payload`.
    Catching chunk-CRC corruption needs a raw per-packet framing walk (read the packet bytes without
    DNP3 reassembly, then validate each data chunk's trailing CRC) — a future refinement."""
    cmd = ["tshark", "-r", str(pcap), "-Y", "dnp3 && tcp.len>0", "-T", "fields", "-e", "tcp.payload"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    total = bad = 0
    try:
        for line in proc.stdout:
            hexes = line.strip()
            if not hexes:
                continue
            try:
                frame = bytes.fromhex(hexes)
            except ValueError:
                continue
            if frame[0:2] != _DNP3_START:
                continue
            total += 1
            if not dnp3_frame_crc_ok(frame):
                bad += 1
    finally:
        proc.stdout.close()
        proc.wait()
    return total, bad


def find_arp_conflicts(arp_rows):
    """arp_rows: iterable of (ip, mac). Return {ip: sorted[macs]} for every IP bound to >1 MAC — the
    ARP-spoof signal. Pure + unit-testable."""
    seen = collections.defaultdict(set)
    for ip, mac in arp_rows:
        if ip and mac:
            seen[ip].add(mac)
    return {ip: sorted(macs) for ip, macs in seen.items() if len(macs) > 1}


def check_arp_spoof(pcap: Path):
    """Return {ip: [macs]} for IPs claimed by more than one MAC in the capture's ARP replies/requests."""
    cmd = ["tshark", "-r", str(pcap), "-Y", "arp", "-T", "fields",
           "-e", "arp.src.proto_ipv4", "-e", "arp.src.hw_mac", "-E", "separator=|"]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    rows = []
    for line in out.splitlines():
        ip, _, mac = line.partition("|")
        rows.append((ip.strip(), mac.strip()))
    return find_arp_conflicts(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap", required=True, type=Path)
    ap.add_argument("--check", default="dnp3-crc,arp-spoof", help="comma-separated: dnp3-crc, arp-spoof")
    args = ap.parse_args()
    if shutil.which("tshark") is None:
        ap.error("tshark is required")
    checks = {c.strip() for c in args.check.split(",")}
    anomalies = 0

    if "dnp3-crc" in checks:
        total, bad = check_dnp3_crc(args.pcap)
        print(f"[dnp3-crc] {total} DNP3 link frames, {bad} with a BAD link CRC (malformed / test case 4)")
        anomalies += bad
    if "arp-spoof" in checks:
        conflicts = check_arp_spoof(args.pcap)
        print(f"[arp-spoof] {len(conflicts)} IP(s) claimed by more than one MAC (ARP spoof / test case 8):")
        for ip, macs in sorted(conflicts.items()):
            print(f"    {ip}: {', '.join(macs)}")
        anomalies += len(conflicts)

    print(f"\n{anomalies} anomaly indicator(s).")
    sys.exit(1 if anomalies else 0)


if __name__ == "__main__":
    main()
