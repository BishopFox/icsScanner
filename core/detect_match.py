"""Native passive detection matcher (the in-process / self-contained detection path).

Runs the checks' own `detection_hints` byte/regex patterns directly against captured packet payloads,
in-process, with no Zeek. The SAME `detection_hints` that detection-gen renders to Zeek/Suricata rules
are the single source of truth; this is a second execution surface for the pcap/live path, so a
workstation with just icsScanner gets the Observed-Activity detections without standing up a sensor.

Matching is gated by transport (tcp/udp) and a pattern runs against the packet payload regardless of
port — the same semantics as the validated Zeek signatures (which constrain `ip-proto` but not port),
so the native path and a Zeek sensor agree on what fires. Per-packet, not stream reassembly: a pattern
split across two TCP segments can be missed (that is the external-Zeek / `--notice-log` path's job).

Two pattern classes are skipped, matching the renderers' gates (see detection-gen core/pattern_quality):
trivially-generic patterns (noise), and `stream_safe: false` patterns — the latter were kept here at
first on the theory that per-packet matching honors their segment-boundary semantics, but real-traffic
validation showed they still over-fire per-packet (normal DNP3 coalesces multiple link frames into one
TCP segment), so they are skipped by default too. These are OBSERVATIONS matching a check's signature,
never a confirmed compromise (see core/detections.py for the honest-framing contract this feeds).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from core.detections import Detection

# app_protocol -> canonical service port, carried on each detection for context only (NOT a match gate;
# gating on port would miss a protocol on a non-standard port and diverge from the Zeek signatures).
_APP_PORT = {
    "modbus": 502, "dnp3": 20000, "s7comm": 102, "iec104": 2404, "enip": 44818, "bacnet": 47808,
    "fins": 9600, "mms": 102, "fox": 1911, "codesys_v3": 1740, "c37118": 4712, "ge_srtp": 18245,
    "telnet": 23, "http": 80, "https": 443, "ftp": 21, "snmp": 161, "ssh": 22, "vnc": 5900,
    "tftp": 69, "bsap": 1234, "profinet": 34964,
}

# ── pattern-quality gate (kept in lockstep with detection-gen core/pattern_quality is_trivially_generic) ──
# Strip the tokens that carry no content: anchors, line terminators, the alternation bar, and any
# "match-anything" char class (., \s, \S, \w, \W, \d, \D) with an optional quantifier (* + ? {m,n}).
# What's left is the literal/structural content; if that's empty the pattern matches ~any line.
_GENERIC_TOKEN = re.compile(
    r"\\[rnt]|[\^$|]|(?:\.|\\[sSwWdD])(?:[*+?]|\{\d+(?:,\d*)?\})?")


def _regex_is_generic(rx: str) -> bool:
    s = (rx or "").strip()
    if not s:
        return True
    return _GENERIC_TOKEN.sub("", s).strip() in ("", "()")


def _is_generic(p: dict) -> bool:
    """Skip a pattern with no real content (matches ~all traffic of its transport)."""
    if "regex" in p:
        return _regex_is_generic(p["regex"])
    if "bytes" in p:
        try:
            raw = (p["bytes"] or "").encode().decode("unicode_escape").encode("latin-1")
        except (UnicodeDecodeError, UnicodeEncodeError):
            return False
        return len(raw) <= 1 or set(raw) <= {0x0d, 0x0a, 0x20, 0x09}
    return True


def _compile(p: dict):
    try:
        if "regex" in p:
            return re.compile(p["regex"].encode("latin-1"), re.DOTALL)
        if "bytes" in p:
            raw = p["bytes"].encode().decode("unicode_escape").encode("latin-1")
            return re.compile(re.escape(raw), re.DOTALL)
    except (re.error, UnicodeDecodeError, UnicodeEncodeError):
        return None
    return None


def _sanitize(check_id: str) -> str:
    return re.sub(r"[^0-9a-zA-Z]+", "_", check_id).strip("_")


def _prescreen_literal(p: dict):
    """A byte literal that MUST appear in any match of this pattern, or None. Used as a cheap
    substring prefilter before the full regex on large captures. Correctness-safe: returned only when
    the literal is guaranteed present in every match (a bytes pattern, or a pure-literal regex with no
    metachar/alternation), so skipping on its absence can never miss a real match."""
    if "bytes" in p:
        try:
            raw = p["bytes"].encode().decode("unicode_escape").encode("latin-1")
        except (UnicodeDecodeError, UnicodeEncodeError):
            return None
        return raw if len(raw) >= 2 else None
    rx = p.get("regex") or ""
    i = 1 if rx.startswith("^") else 0
    end = len(rx) - 1 if rx.endswith("$") else len(rx)
    out = bytearray()
    while i < end:
        c = rx[i]
        if c in "|[](){}*+?.":
            return None  # a real metachar -> the pattern is not a pure literal
        if c == "\\":
            if i + 1 >= end:
                return None
            d = rx[i + 1]
            if d == "r": out.append(0x0d); i += 2
            elif d == "n": out.append(0x0a); i += 2
            elif d == "t": out.append(0x09); i += 2
            elif d == "\\": out.append(0x5c); i += 2
            elif d == "x" and i + 4 <= end:
                try:
                    out.append(int(rx[i + 2:i + 4], 16)); i += 4
                except ValueError:
                    return None
            else:
                return None  # \S \d \w etc. -> not a literal
        else:
            out.append(ord(c) & 0xFF); i += 1
    return bytes(out) if len(out) >= 3 else None


def build_matchers(checks_dir, include_stream_unsafe: bool = False) -> dict:
    """Compile every usable detection_hints pattern (armed checks AND candidates) into a
    transport-indexed matcher set: {"tcp": [matcher], "udp": [matcher], "count": int}. Trivially-generic
    patterns are always skipped; stream-unsafe patterns are skipped unless include_stream_unsafe=True."""
    from core.registry import load_check_metadata
    by_transport: dict = {"tcp": [], "udp": [], "behavioral": []}
    count = 0
    for yaml_file in sorted(Path(checks_dir).glob("**/*.yaml")):
        try:
            meta = load_check_metadata(yaml_file)
        except Exception:
            continue
        hints = getattr(meta, "detection_hints", None)
        if not hints:
            continue
        app = hints.get("app_protocol")
        mitre = hints.get("mitre_attack_id") or ""
        ft = hints.get("finding_type") or ""
        transport = "udp" if hints.get("transport") == "udp" else "tcp"
        beh = hints.get("behavioral")
        if isinstance(beh, dict) and beh.get("signal") and beh.get("threshold"):
            spec = {"check_id": meta.check_id, "app": app or transport, "mitre": mitre,
                    "transport": transport, "signal": beh["signal"],
                    "threshold": int(beh["threshold"]),
                    "window": float(beh.get("window_seconds") or 0),
                    "port": _APP_PORT.get(app), "target": beh.get("target", "resp"),
                    "ft": ft or "attack_activity",  # a threshold breach is activity, not a config state
                    "match_rx": _compile(beh["match"]) if isinstance(beh.get("match"), dict) else None}
            by_transport["behavioral"].append(spec)
            count += 1
        for mode in ("narrow", "broad"):
            block = hints.get(mode) or {}
            for p in (block.get("patterns") or []):
                if _is_generic(p):
                    continue
                if not include_stream_unsafe and not p.get("stream_safe", True):
                    continue
                rx = _compile(p)
                if rx is None:
                    continue
                by_transport[transport].append(
                    {"check_id": meta.check_id, "mode": mode, "app": app or transport,
                     "mitre": mitre, "transport": transport, "rx": rx,
                     "lit": _prescreen_literal(p), "ft": ft})
                count += 1
    by_transport["count"] = count
    return by_transport


def match_frame(pkt: dict, ts: Optional[float], matchers: dict) -> list:
    """Return Detection records for one decapped packet: run every matcher of the packet's transport
    against the payload (port-agnostic, like the Zeek signatures)."""
    payload = pkt.get("payload") or b""
    if not payload:
        return []
    transport = pkt.get("l4")
    if transport not in ("tcp", "udp"):
        return []
    dport = pkt.get("dport")
    sport = pkt.get("sport")
    out = []
    for m in matchers.get(transport, ()):
        lit = m.get("lit")
        if lit is not None and lit not in payload:
            continue  # safe prefilter: a required literal absent -> the regex cannot match
        if m["rx"].search(payload):
            out.append(Detection(
                ts=ts or 0.0,
                src=pkt.get("src_ip") or "", dst=pkt.get("dst_ip") or "",
                src_port=str(sport or ""), dst_port=str(dport or ""),
                note=f"ICS_Scanner::ICS_{m['mode']}_{_sanitize(m['check_id'])}",
                check_id=m["check_id"], mode=m["mode"],
                app_protocol=m["app"], mitre=m["mitre"], finding_type=m.get("ft", ""),
                msg=f"ICS-SCANNER {m['mode'].upper()} - {m['check_id']}",
            ))
    return out


class BehavioralTracker:
    """Stateful detector for volumetric/behavioral signals a byte pattern can't express — the real
    signal of the DoS/exhaustion/flood checks (connection count, packet rate). Fed every packet during
    the capture; emit() at the end returns one Detection per (check, target) over threshold. This is
    why the s7comm-exhaustion / espmodbus-pool-exhaust checks can have a detection at all: their attack
    is "~N connections held open", a count, not a byte sequence.

    Signals (detection_hints.behavioral.signal):
      connection_count  — distinct originators (src:sport) seen going to the service port on a target;
                          flags when >= threshold (optionally within a sliding window_seconds).
      packet_rate       — packets (optionally matching `match`) to a target per window_seconds; flags
                          when any window's count >= threshold.
    `target: resp` (default) counts per responder IP; `orig` counts per originator IP.
    """

    def __init__(self, specs: list):
        self.specs = specs or []
        # state[i] : for connection_count -> {target_ip: set((src,sport)|ts-bucketed)}, for
        # packet_rate -> {target_ip: {bucket: count}}
        self.state = [{} for _ in self.specs]
        self.last_ts = [0.0 for _ in self.specs]

    def feed(self, pkt: dict, ts: Optional[float]) -> None:
        transport = pkt.get("l4")
        if transport not in ("tcp", "udp"):
            return
        dport, sport = pkt.get("dport"), pkt.get("sport")
        src, dst = pkt.get("src_ip") or "", pkt.get("dst_ip") or ""
        t = float(ts) if ts else 0.0
        for i, s in enumerate(self.specs):
            if s["transport"] != transport:
                continue
            port = s.get("port")
            # only the client->server direction (to the service port), when the port is known
            if port is not None and dport != port:
                continue
            target = dst if s["target"] == "resp" else src
            if not target:
                continue
            self.last_ts[i] = max(self.last_ts[i], t)
            st = self.state[i]
            if s["signal"] == "connection_count":
                st.setdefault(target, set()).add((src, sport))
            elif s["signal"] == "connection_rate":
                win = s["window"] or 1.0
                st.setdefault(target, {}).setdefault(int(t // win), set()).add((src, sport))
            elif s["signal"] == "packet_rate":
                rx = s.get("match_rx")
                if rx is not None and not rx.search(pkt.get("payload") or b""):
                    continue
                win = s["window"] or 1.0
                bucket = int(t // win)
                st.setdefault(target, {})
                st[target][bucket] = st[target].get(bucket, 0) + 1

    def emit(self) -> list:
        out = []
        for i, s in enumerate(self.specs):
            thr = s["threshold"]
            for target, data in self.state[i].items():
                if s["signal"] == "connection_count":
                    n = len(data)
                elif s["signal"] == "connection_rate":
                    n = max((len(v) for v in data.values()), default=0)
                elif s["signal"] == "packet_rate":
                    n = max(data.values()) if data else 0
                else:
                    n = 0
                if n < thr:
                    continue
                if s["signal"] == "connection_count":
                    unit = "connections"
                elif s["signal"] == "connection_rate":
                    unit = f"connections/{s['window'] or 1:g}s"
                else:
                    unit = f"packets/{s['window'] or 1:g}s"
                out.append(Detection(
                    ts=self.last_ts[i], src="(multiple)", dst=target,
                    note=f"ICS_Scanner::ICS_behavioral_{_sanitize(s['check_id'])}",
                    check_id=s["check_id"], mode="behavioral",
                    app_protocol=s["app"], mitre=s["mitre"], finding_type=s.get("ft", "attack_activity"),
                    msg=f"ICS-SCANNER BEHAVIORAL - {s['check_id']} ({n} {unit} >= {thr})",
                ))
        return out
