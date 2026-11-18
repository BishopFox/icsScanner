"""Detection-pattern quality gates for the renderers.

Two independent defects, both surfaced by validating generated detections against real PNNL OT traffic
(2026-11-11), each with its own gate here:

1. TRIVIALLY-GENERIC pattern — a `detection_hints` pattern with no real content: a bare line
   terminator (`\\r\\n$`), `.*`, whitespace only, a single byte. It matches essentially all traffic
   of its transport, so it is noise in every output format. `is_trivially_generic` flags it; all
   renderers skip such patterns (honest absence, like an empty `broad`). Example caught: the perle /
   yaskawa telnet checks' `broad: \\r\\n$`, which fired on every Telnet line.

2. STREAM-UNSAFE pattern — a pattern whose detection semantics depend on TCP SEGMENT boundaries
   (e.g. "two DNP3 start markers 0x0564 packed into ONE TCP segment" = an evasion shape). A
   stream-reassembly engine (Zeek signatures, Suricata stream mode) matches against the REASSEMBLED
   byte stream, where segment boundaries are gone, so over a long-lived connection the condition is
   always satisfied and the signature over-matches. Such a pattern is marked `stream_safe: false` in
   the check YAML; `is_stream_safe` reads it, and the STREAM renderers (zeek, suricata) skip it while
   the log-field renderers (sigma, escu) are unaffected. Example caught: dnp3-batched-application-
   fragments, which fired ~15k times on normal RTU->relay polling.

The gate is conservative: when in doubt it keeps the pattern (returns not-generic / stream-safe), so a
real pattern is never silently dropped.
"""
from __future__ import annotations

import re
from typing import Optional

# Tokens that carry no content: anchors, line terminators, the alternation bar, and any
# "match-anything" char class (., \s, \S, \w, \W, \d, \D) with an optional quantifier (* + ? {m,n}).
# Strip them; if nothing literal/structural is left the pattern matches ~any line of its transport
# (e.g. `\r\n$`, `.*`, or `^\S{1,64}\r\n` — "any Telnet line"). Real-traffic validation caught the
# char-class-quantifier forms firing on all Telnet traffic, which the plain token list missed.
_GENERIC_TOKEN = re.compile(
    r"\\[rnt]|[\^$|]|(?:\.|\\[sSwWdD])(?:[*+?]|\{\d+(?:,\d*)?\})?")


def _regex_is_generic(rx: Optional[str]) -> bool:
    s = (rx or "").strip()
    if not s:
        return True
    return _GENERIC_TOKEN.sub("", s).strip() in ("", "()")


def _bytes_is_generic(b: Optional[str]) -> bool:
    try:
        raw = (b or "").encode().decode("unicode_escape").encode("latin-1")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return False
    if len(raw) <= 1:
        return True
    return set(raw) <= {0x0d, 0x0a, 0x20, 0x09}  # CR / LF / space / tab only


def is_trivially_generic(pattern: dict) -> bool:
    """True if the pattern has no real content (matches ~all traffic of its transport)."""
    if not isinstance(pattern, dict):
        return False
    if "regex" in pattern:
        return _regex_is_generic(pattern["regex"])
    if "bytes" in pattern:
        return _bytes_is_generic(pattern["bytes"])
    return False


def is_stream_safe(pattern: dict) -> bool:
    """False only when the check YAML explicitly marks the pattern `stream_safe: false` (its meaning
    depends on TCP segment boundaries, so a reassembly-based signature would over-match)."""
    if not isinstance(pattern, dict):
        return True
    return bool(pattern.get("stream_safe", True))


def usable_patterns(patterns, *, stream: bool = False) -> list:
    """Filter a pattern list: always drop trivially-generic patterns; additionally drop stream-unsafe
    ones when rendering for a stream-reassembly engine (stream=True)."""
    out = []
    for p in patterns or []:
        if is_trivially_generic(p):
            continue
        if stream and not is_stream_safe(p):
            continue
        out.append(p)
    return out


def pattern_quality_warnings(record) -> list:
    """Lint a CheckRecord: return [(check_id, mode, reason, pattern_value)] for any detection_hints
    pattern that a renderer will skip, so generate.py can report them instead of silently dropping."""
    warnings = []
    hints = getattr(record, "detection_hints", None) or {}
    for mode in ("narrow", "broad"):
        block = hints.get(mode) or {}
        for p in block.get("patterns") or []:
            val = p.get("regex") if "regex" in p else p.get("bytes", "")
            if is_trivially_generic(p):
                warnings.append((record.check_id, mode, "trivially-generic (skipped in all formats)", val))
            elif not is_stream_safe(p):
                warnings.append((record.check_id, mode, "stream-unsafe (skipped for zeek/suricata)", val))
    return warnings
