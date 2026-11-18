"""Zeek signature renderer.

Zeek is the dissection engine behind the CISA/INL Malcolm + Hedgehog OT sensor stack (and Corelight),
so emitting Zeek detections from the same icsScanner `detection_hints` lets the check corpus drop
straight onto the passive sensors regulated operators already run — the same sensors whose ICSNPP logs
the scanner's passive mode (core/passive.py:ingest_zeek_logs) consumes.

This renderer emits Zeek SIGNATURE-FRAMEWORK entries (.sig) — byte/regex payload matching, the mode
that maps 1:1 from our `detection_hints` patterns (the same literal byte/regex content the Suricata
renderer emits). Each `broad` block becomes an exploitation-attempt signature; `narrow` is this
scanner's own probe bytes.

A second, richer mode — protocol-aware `.zeek` policy scripts that hook ICSNPP events
(event enip_*, modbus_message, dnp3_application_request, synchrophasor events, …) and raise a NOTICE,
ATT&CK-for-ICS / ACID style keyed on `app_protocol` + `mitre_attack_id` — is a deliberate FUTURE
addition: it needs an app_protocol -> (Zeek event, field) mapping table and only covers the subset of
checks whose protocol ICSNPP dissects. The signature mode here is the recommended first step (broad
coverage, no new metadata). See lab-notes and the passive-mode plan.

Like the Suricata renderer these are passive DETECTION signatures (they raise a signature_match /
NOTICE), never inline blocking — deployment decides what to do with a hit.
"""
from __future__ import annotations

import hashlib
import re
from typing import Optional

from core.check_loader import CheckRecord


def _stable_sid(check_id: str, mode: str) -> int:
    # Deterministic, hash-derived (no persisted counter) — same as the Suricata renderer.
    h = hashlib.sha256(f"zeek:{check_id}:{mode}".encode()).hexdigest()
    return int(h[:8], 16) % 99999


def _bytes_to_zeek_regex(byte_pattern: str) -> str:
    """Python-escape-style byte string (e.g. '\\x41\\x42' or literal 'ABC') -> a Zeek signature regex
    body of \\xNN hex escapes, the encoding that round-trips arbitrary binary bytes regardless of
    printability (same rationale as the Suricata renderer's pipe-hex)."""
    raw = byte_pattern.encode().decode("unicode_escape").encode("latin-1")
    return "".join(f"\\x{b:02x}" for b in raw)


def _sig_id(check_id: str, mode: str, sid: int) -> str:
    base = re.sub(r"[^0-9a-zA-Z]+", "_", check_id).strip("_")
    return f"ics_scanner_{mode}_{base}_{sid}"


def render(record: CheckRecord, mode: str) -> Optional[str]:
    if not record.has_hints:
        return None
    block = record.detection_hints.get(mode)
    if not block or not block.get("patterns"):
        return None

    hints = record.detection_hints
    transport = hints.get("transport", "tcp")
    proto = "udp" if transport == "udp" else "tcp"

    # Zeek signatures match the REASSEMBLED stream, so drop trivially-generic patterns (noise, e.g.
    # a bare `\r\n$`) and stream-unsafe patterns (segment-boundary semantics a reassembly engine
    # can't honor). Nothing usable left -> honest absence, no signature. See core/pattern_quality.py.
    from core.pattern_quality import usable_patterns
    stream_patterns = usable_patterns(block["patterns"], stream=True)
    if not stream_patterns:
        return None

    # Zeek anchors a signature `payload` regex at the START of the (reassembled) payload buffer —
    # verified against Zeek 9.0.1: `payload /\x65\x03/` does NOT match a stream containing those
    # bytes mid-payload, but `payload /.*\x65\x03/` does. ICS probe/exploit bytes almost never sit
    # at offset 0 (a Modbus PDU follows the 6-byte MBAP header, responses carry their own headers),
    # so every pattern must be made unanchored with a leading `.*` or the signature is inert — the
    # Zeek-idiom equivalent of Suricata's unanchored `content:`. (Zeek's own docs write `payload /.*root/`.)
    payload_conditions = []
    for p in stream_patterns:
        if "bytes" in p:
            payload_conditions.append(f"    payload /.*{_bytes_to_zeek_regex(p['bytes'])}/")
        elif "regex" in p:
            # `/` is the Zeek regex delimiter, same as PCRE — escape a literal one (URLs etc.).
            escaped = p["regex"].replace("/", "\\/")
            # Prefix `.*` unless the author already made it unanchored, to avoid a double `.*`.
            prefix = "" if escaped.startswith(".*") else ".*"
            payload_conditions.append(f"    payload /{prefix}{escaped}/")
    if not payload_conditions:
        return None

    sid = _stable_sid(record.check_id, mode)
    sig_id = _sig_id(record.check_id, mode, sid)
    msg = f"ICS-SCANNER {mode.upper()} - {record.check_id}".replace('"', "'")

    conditions = [f"    ip-proto == {proto}"]
    if proto == "tcp":
        # originator = client->server, matching the Suricata renderer's flow:established,to_server.
        conditions.append("    tcp-state established, originator")
    conditions += payload_conditions
    conditions.append(f'    event "{msg}"')

    # Metadata as comment lines (Zeek's signature framework has no structured metadata field).
    meta = [f"# detection_gen_mode: {mode}", f"# check_id: {record.check_id}"]
    if record.cve_id:
        meta.append(f"# cve: {record.cve_id}")
    if getattr(record, "can_id", None):
        meta.append(f"# can_id: {record.can_id}")
    mitre = hints.get("mitre_attack_id")
    if mitre:
        meta.append(f"# mitre_attack_id: {mitre}")

    description_lines = block.get("description", record.description).split("\n")
    desc_comment = "\n".join(
        f"# {mode.upper()}: {line}" if i == 0 else f"# {line}"
        for i, line in enumerate(description_lines)
    )

    return (
        f"# Auto-generated by detection-gen from icsScanner check '{record.check_id}'\n"
        f"{desc_comment}\n"
        + "\n".join(meta) + "\n"
        f"signature {sig_id} {{\n"
        + "\n".join(conditions) + "\n"
        "}\n"
    )
