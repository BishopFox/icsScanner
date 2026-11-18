"""Suricata rule renderer. Verified against docs.suricata.io's current official documentation
(rules/intro.html) — see ../../lab-notes/format-research.md.

Unlike Sigma/ESCU, Suricata rules operate directly on network bytes — this is the format where
icsScanner's `detection_hints` (which are themselves byte/regex patterns) map most directly and
literally, with the least "best-effort" translation needed of the three formats.

`alert` (not `drop`/`reject`) is used for every generated rule — these are passive detection
signatures for monitoring a network for exploitation attempts, not inline-blocking rules; this
project has no basis for asserting a rule is safe to auto-block on, and blocking is a
user/deployment decision, not something to bake into a generated template.

SID ALLOCATION: this generator claims the range 9000000-9099999 (Suricata/Emerging Threats
convention reserves ranges below 1000000 for official rulesets and recommends local/custom rules
use a distinct high range to avoid collisions — no single central registry exists for this, so
this range is a project-local convention, documented here and in each generated rule's own
comment, not verified against any authoritative allocation list since none exists to check
against).

TWO BUGS FIXED (2026-08-25), same root cause as the escu.py rewrite — hand-formatted text standing
in for a real emitter, safe only by coincidence for the 7 pilot checks:

1. **Multi-line `description` broke the one-rule-per-line file contract.** The old code embedded
   `block.get('description', record.description)` directly into a single `# {mode}: {description}`
   comment line. A check whose own `description:` is itself multi-line (valid icsScanner YAML,
   just not exercised by any of the 7 pilot checks) put every line after the first newline into
   the file with NO `#` prefix — a bare, non-comment, non-rule line sitting in what real Suricata
   requires to be strictly one-rule-per-line. Confirmed live: a synthetic two-line description
   produced exactly that stray unprefixed line. Fixed by prefixing every line of the description
   with `#` individually instead of assuming it's single-line.
2. **`pcre:"/{regex}/";` never escaped a literal `/` inside the regex** — `/` is the PCRE
   delimiter in Suricata's own `pcre` keyword syntax, and the old escaping only handled backslash
   and double-quote. Any regex containing a literal `/` (extremely plausible for the HTTP checks
   this project explicitly targets, e.g. a URL path like `GET /admin/login`) silently produced a
   rule where Suricata's own parser would treat the pattern as ending at the FIRST embedded `/`
   and the remainder as garbage modifier characters — a malformed rule Suricata rejects at load
   time. Confirmed this was a real, previously-unresearched gap: `lab-notes/format-research.md`
   never mentions PCRE delimiter escaping at all, and the project's own `idstools`-based tests
   didn't catch it either, since `idstools` treats the `pcre` value as an opaque quoted string and
   never validates delimiter semantics the way real Suricata does — worth keeping in mind for any
   future format research pass: a parser succeeding is not the same as the target tool accepting
   the rule. Fixed by backslash-escaping `/` the same way `\\` and `"` already are, which is
   Suricata's own documented convention for embedding a literal delimiter character inside a
   `pcre` pattern.
"""

from __future__ import annotations

import hashlib
import re
import textwrap
from typing import Optional

from core.check_loader import CheckRecord

_SID_BASE = 9000000
_SID_SPAN = 100000  # the project-local range 9000000..9099999

# Deterministic collision overrides, populated by plan_sids() over the WHOLE corpus. The bare
# hash below maps into only _SID_SPAN slots, so with a few hundred rules a collision is
# statistically expected (two checks -> one SID); on a sensor that loads every rule at once,
# Suricata then drops one as a duplicate signature. plan_sids() resolves that globally; when it
# is empty (e.g. the smoke tests rendering a single check) the bare hash is used unchanged.
_SID_OVERRIDES: dict[tuple[str, str], int] = {}


def _hash_sid(check_id: str, mode: str) -> int:
    # Deterministic (hash-derived), not sequential/stateful — regenerating a template for the
    # same check+mode always produces the same base SID, without a persisted counter file.
    h = hashlib.sha256(f"{check_id}:{mode}".encode()).hexdigest()
    return _SID_BASE + (int(h[:8], 16) % (_SID_SPAN - 1))


def _stable_sid(check_id: str, mode: str) -> int:
    return _SID_OVERRIDES.get((check_id, mode)) or _hash_sid(check_id, mode)


def plan_sids(records) -> dict[tuple[str, str], int]:
    """Assign a unique SID to every (check_id, mode) that renders a Suricata rule, over the FULL
    corpus, resolving hash collisions by linear probe. Deterministic: keys are taken in sorted
    order and each keeps its bare-hash SID unless an earlier-sorted key already holds it, so only
    the colliding key moves. Callers (generate.py) must pass the whole check set — not a single
    --check-id subset — or a per-check regen could assign a SID different from a full run. Set the
    result on _SID_OVERRIDES before rendering."""
    keys = []
    for r in records:
        for mode in ("narrow", "broad", "behavioral"):
            if render(r, mode) is not None:          # only keys that actually emit a rule
                keys.append((r.check_id, mode))
    keys.sort()
    used: set[int] = set()
    mapping: dict[tuple[str, str], int] = {}
    for key in keys:
        sid = _hash_sid(*key)
        start = sid
        while sid in used:                           # linear probe within the local range
            sid = _SID_BASE + ((sid - _SID_BASE + 1) % _SID_SPAN)
            if sid == start:
                raise RuntimeError("SID space exhausted (corpus exceeds the 9000000-9099999 range)")
        used.add(sid)
        mapping[key] = sid
    return mapping


_APP_PROTO_MAP = {
    "http": "http",
    "ftp": "ftp",
    "telnet": None,  # Suricata has no dedicated telnet app-layer parser; fall back to raw tcp
    "modbus": None,  # Suricata's Modbus app-layer parser exists but is disabled by default in
    # most builds and has a narrower keyword set than this project's byte-pattern hints need —
    # using raw tcp content matching is the safer default until confirmed otherwise.
    "ssh": "ssh",
    "s7comm": None,
}

# app_protocol -> service port, for the behavioral/threshold rules (which track a rate/count to the
# target's service port rather than matching content).
_APP_PORT = {
    "modbus": 502, "dnp3": 20000, "s7comm": 102, "iec104": 2404, "enip": 44818, "bacnet": 47808,
    "fins": 9600, "mms": 102, "telnet": 23, "http": 80, "https": 443, "ftp": 21, "snmp": 161,
    "ssh": 22, "vnc": 5900, "tftp": 69,
}


def _classtype(record: CheckRecord) -> str:
    if record.severity and "denial" in (record.description or "").lower():
        return "attempted-dos"
    if record.destructive:
        return "attempted-admin"
    return "misc-attack"


_CONNECTION_SIGNALS = {"connection_rate", "connection_count"}


def _render_behavioral(record: CheckRecord) -> Optional[str]:
    """A volumetric/threshold rule from detection_hints.behavioral (connection/packet rate or count).

    For a CONNECTION signal (connection_rate / connection_count) the rule counts connection
    INITIATIONS — `flags:S,12` (a client SYN), not every request packet. Counting packets was wrong:
    a normal master polling on one long-lived connection sends far more than N requests per window,
    so the old `flow:to_server` form fired on routine polling (420k alerts over the PNNL set). Even
    counting connections correctly, this is HUNTING-GRADE: real reconnect-heavy masters can open as
    many connections as the attack (measured: legitimate OT bursts of 8-9 conn/2s, above a 7-conn
    attack), so NO rate threshold cleanly separates attack from baseline. The threshold is a starting
    point to be TUNED PER ENVIRONMENT (and correlated with the device's connection-pool size); the
    faithful detector is connection CONCURRENCY, emitted by the zeek-behavioral renderer. classtype
    is misc-activity (low priority) to reflect the hunting posture. A packet/byte-rate signal keeps
    the per-destination packet threshold."""
    hints = record.detection_hints
    beh = hints.get("behavioral")
    if not isinstance(beh, dict) or not beh.get("signal") or not beh.get("threshold"):
        return None
    port = _APP_PORT.get(hints.get("app_protocol"))
    if port is None:
        return None  # a threshold rule needs a concrete service port to track against
    wire = "udp" if hints.get("transport") == "udp" else "tcp"
    signal = beh["signal"]
    is_conn = signal in _CONNECTION_SIGNALS
    thr = int(beh["threshold"])
    secs = int(beh.get("window_seconds") or 60)  # connection_count has no window -> a 60s default
    sid = _stable_sid(record.check_id, "behavioral")
    msg = f"ICS-SCANNER BEHAVIORAL - {record.check_id} ({signal})".replace('"', "'")
    meta = ["detection_gen_mode behavioral", f"detection_gen_check_id {record.check_id}"]
    mitre = hints.get("mitre_attack_id")
    if mitre:
        meta.append(f"mitre_attack_id {mitre}")
    # connection signals: count client SYNs (connection inits). packet/byte signals: count requests.
    rate_match = "flags:S,12;" if is_conn else "flow:to_server;"
    classtype = "misc-activity" if is_conn else _classtype(record)
    opts = [
        f'msg:"{msg}";', rate_match,
        f"threshold:type both, track by_dst, count {thr}, seconds {secs};",
        f"classtype:{classtype};", f'metadata:{", ".join(meta)};',
        f"sid:{sid};", "rev:1;",
    ]
    if is_conn:
        header = ("# behavioral/volumetric rule — counts connection INITIATIONS (client SYN) toward the\n"
                  "# service, not request packets. HUNTING-GRADE: legitimate reconnect-heavy masters can\n"
                  "# open as many connections as this attack, so count/seconds below is a STARTING POINT\n"
                  "# that MUST BE TUNED PER ENVIRONMENT (correlate with the device's connection-pool size).\n"
                  "# The faithful signal is connection concurrency — see the generated zeek-behavioral policy.\n")
    else:
        header = ("# behavioral/volumetric rule (threshold) — the attack's signal is a rate/count, not a\n"
                  "# byte pattern; Suricata tracks it per destination. See the check's behavioral block.\n")
    header += _tuning_comment(beh.get("tuning"))
    return header + f"alert {wire} any any -> any {port} ({' '.join(opts)})\n"


def _tuning_comment(tuning) -> str:
    """Render a check's behavioral `tuning` text (threat-hunter deployment guidance: expected false
    positives + how to tune the threshold) as wrapped `# TUNING:` comment lines in the rule header,
    so the guidance travels with the deployed rule rather than living only in the check YAML."""
    if not tuning or not str(tuning).strip():
        return ""
    body = " ".join(str(tuning).split())
    lines = textwrap.wrap(body, width=95)
    out = f"# TUNING: {lines[0]}\n" if lines else ""
    for ln in lines[1:]:
        out += f"#   {ln}\n"
    return out


def render(record: CheckRecord, mode: str) -> Optional[str]:
    if not record.has_hints:
        return None
    if mode == "behavioral":
        return _render_behavioral(record)
    block = record.detection_hints.get(mode)
    if not block or not block.get("patterns"):
        return None

    hints = record.detection_hints
    app_protocol = hints.get("app_protocol")
    proto = _APP_PROTO_MAP.get(app_protocol) if app_protocol else None
    transport = hints.get("transport", "tcp")
    wire_proto = proto or transport

    # Suricata pcre/content match the reassembled stream too -> same gate as Zeek: drop generic +
    # stream-unsafe patterns (see core/pattern_quality.py).
    from core.pattern_quality import usable_patterns
    content_clauses = []
    for p in usable_patterns(block["patterns"], stream=True):
        if "bytes" in p:
            hex_content = _to_suricata_hex(p["bytes"])
            content_clauses.append(f'content:"{hex_content}";')
        elif "regex" in p:
            # The regex is a PCRE pattern meant to go VERBATIM into Suricata's pcre keyword, so its
            # backslashes are PCRE metacharacters (e.g. `\x05` = byte 0x05, `\\` = a literal
            # backslash) and must pass through UNCHANGED. Blindly doubling them was a real bug,
            # caught 2026-11-06 validating against the PNNL dataset: `\x05` became `\\x05` (which
            # matches the literal text "\x05", not byte 0x05), so NO pcre rule ever fired while
            # idstools still parsed it fine. The ONLY characters that need escaping inside
            # `pcre:"/.../"` are the `/` delimiter and the `"` that would close the option string:
            # escape an UNescaped `/` (negative lookbehind so an already-escaped `\/` isn't doubled)
            # and any `"`. Do NOT touch backslashes. (smoke_test_suricata.py guards this.)
            escaped = re.sub(r'(?<!\\)/', r'\\/', p["regex"]).replace('"', '\\"')
            content_clauses.append(f'pcre:"/{escaped}/";')

    if not content_clauses:
        return None

    sid = _stable_sid(record.check_id, mode)
    msg = f"ICS-SCANNER {mode.upper()} - {record.check_id}"
    msg = msg.replace('"', "'")

    classtype = _classtype(record)
    metadata_parts = [f"detection_gen_mode {mode}", f"detection_gen_check_id {record.check_id}"]
    if record.cve_id:
        metadata_parts.append(f"cve {record.cve_id}")
    if record.can_id:
        metadata_parts.append(f"can_id {record.can_id}")
    mitre = hints.get("mitre_attack_id")
    if mitre:
        metadata_parts.append(f"mitre_attack_id {mitre}")

    options = (
        [f'msg:"{msg}";', "flow:established,to_server;"]
        + content_clauses
        + [
            f"classtype:{classtype};",
            f'metadata:{", ".join(metadata_parts)};',
            f"sid:{sid};",
            "rev:1;",
        ]
    )

    # Real Suricata .rules files (Emerging Threats' own ruleset included) are ONE RULE PER LINE
    # — caught by testing generated output against the real `idstools` rule parser, which
    # (matching Suricata's own line-based file loading) silently found zero rules in an earlier
    # multi-line pretty-printed version of this same rule, with no error raised. Comments stay on
    # their own `#`-prefixed lines above the rule (both Suricata and idstools skip full comment
    # lines), but the actual `alert ... ( ... )` block must never itself contain a newline.
    rule_line = f"alert {wire_proto} $HOME_NET any -> $EXTERNAL_NET any ( " + " ".join(options) + " )"

    # Every line of the description must get its OWN `#` prefix — icsScanner's own description
    # field is not this project's content to constrain, and a multi-line value here must not be
    # allowed to produce a bare, unprefixed line in a file that real Suricata requires to be
    # strictly one-rule-per-line.
    description_lines = block.get("description", record.description).split("\n")
    description_comment = "\n".join(
        f"# {mode.upper()}: {line}" if i == 0 else f"# {line}"
        for i, line in enumerate(description_lines)
    )

    rule = (
        f"# Auto-generated by detection-gen from icsScanner check '{record.check_id}'\n"
        f"{description_comment}\n"
        f"# SID range 9000000-9099999 is a project-local convention (see renderer docstring) —\n"
        f"# verify it does not collide with your own local/custom rule allocation before loading.\n"
        f"{rule_line}\n"
    )
    return rule


def _to_suricata_hex(byte_pattern: str) -> str:
    """Converts a Python-escape-style byte string (e.g. '\\x41\\x42' or a literal 'ABC') into
    Suricata's pipe-delimited hex content syntax (|41 42|), the only encoding that reliably
    round-trips arbitrary binary bytes in a Suricata rule regardless of whether the original
    byte string mixes printable ASCII and non-printable bytes."""
    raw = byte_pattern.encode().decode("unicode_escape").encode("latin-1")
    return "|" + " ".join(f"{b:02x}" for b in raw) + "|"
