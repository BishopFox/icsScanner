"""core/version_match.py — tolerant version comparison + range matching for ICS firmware strings.

ICS firmware versions are messy and vendor-specific: "4.3", "V3.1.27", "1.73", "02.00.06", "v1.75",
"FW 01.01.03", "R0401". This module extracts the dotted numeric core, compares as integer tuples, and
decides whether a version falls in an advisory's affected range. The guiding rule for a vulnerability
assessment is CONSERVATIVE honesty: if either side can't be parsed, matching returns None ("unknown"),
never a false hard match or a false miss — the caller then treats it as version-unconfirmed.

Version-range spec (what a fingerprint_precondition's `version` dict holds — all optional):
  {"exact": "4.3"}          affected iff the version equals 4.3
  {"max": "3.08.01"}        affected up to and including 3.08.01 (the common "versions <= X")
  {"min": "1.70"}           affected from 1.70 onward
  {"fixed": "1.75"}         affected strictly below the fix (the common "fixed in v1.75")
  {"min": "...", "max": "..."}   inclusive band
Combined keys AND together. An empty/absent spec means "no version info to gate on" -> None.
"""
from __future__ import annotations

import re
from typing import Optional

_NUM_RE = re.compile(r"\d[\d.]*")
# A *cleanly comparable* version: an optional short cosmetic prefix (V, v, FW, Ver, R) + whitespace,
# then a pure dotted-numeric core, and NOTHING else. Strings with a service-pack/build/update suffix
# ("V1.500 SP3", "V1500-SP2", "V13.00 SP1") deliberately do NOT match — parse_version would silently
# drop the suffix and compare the remainder, which can invert the result and SUPPRESS a real finding.
_CLEAN_VER_RE = re.compile(r"^\s*[A-Za-z]{0,3}\s*(\d+(?:\.\d+)*)\s*$")


def parse_version(s) -> Optional[tuple]:
    """Extract the dotted numeric core of a version string into a tuple of ints, or None if there is
    no numeric content. 'V3.1.27' -> (3,1,27); '02.00.06' -> (2,0,6); '4.3' -> (4,3); 'R0401' -> (401,).
    Trailing/leading dots and empty components are dropped."""
    if s is None:
        return None
    m = _NUM_RE.search(str(s))
    if not m:
        return None
    parts = [p for p in m.group(0).split(".") if p != ""]
    try:
        out = tuple(int(p) for p in parts)
    except ValueError:
        return None
    return out or None


def _clean_core(s) -> Optional[tuple]:
    """Return the dotted-numeric tuple ONLY if `s` is a cleanly-comparable version (optional cosmetic
    prefix + pure dotted numeric, nothing trailing); None otherwise. Guards the false-suppression hazard:
    a string like 'V1.500 SP3' or 'V1500-SP2' is NOT cleanly comparable and must not be compared, because
    its significant suffix would be dropped and the numeric remainder could compare backwards."""
    if s is None:
        return None
    m = _CLEAN_VER_RE.match(str(s))
    if not m:
        return None
    try:
        nums = tuple(int(p) for p in m.group(1).split(".") if p != "")
    except ValueError:
        return None
    return nums or None


def cmp_versions(a, b) -> Optional[int]:
    """Return -1/0/1 comparing two version strings, or None if EITHER is not cleanly comparable (carries
    a service-pack/build suffix, non-numeric tail, or no numeric core). Shorter tuples are zero-padded
    ('4.3' == '4.3.0'). Returning None on a messy version is the conservative-honesty contract: the gate
    then treats it as version-unconfirmed and does NOT suppress, rather than suppressing on a wrong parse."""
    pa, pb = _clean_core(a), _clean_core(b)
    if pa is None or pb is None:
        return None
    n = max(len(pa), len(pb))
    pa += (0,) * (n - len(pa))
    pb += (0,) * (n - len(pb))
    return (pa > pb) - (pa < pb)


def version_in_range(version, spec: Optional[dict]) -> Optional[bool]:
    """Is `version` within the affected range `spec`? Returns True (affected), False (not affected), or
    None (can't tell — version or a bound is unparseable, or the spec carries no version constraint)."""
    if not spec:
        return None
    if parse_version(version) is None:
        return None

    checks = []  # each: the required comparison result, or None if a bound is unparseable
    if "exact" in spec:
        c = cmp_versions(version, spec["exact"])
        checks.append(None if c is None else (c == 0))
    if "min" in spec:
        c = cmp_versions(version, spec["min"])
        checks.append(None if c is None else (c >= 0))
    if "max" in spec:
        c = cmp_versions(version, spec["max"])
        checks.append(None if c is None else (c <= 0))
    if "fixed" in spec:
        c = cmp_versions(version, spec["fixed"])
        checks.append(None if c is None else (c < 0))

    if not checks:
        return None               # spec had no recognized version key
    if any(c is None for c in checks):
        return None               # a bound we needed was unparseable -> unknown
    return all(checks)            # every present constraint must hold (AND)


def version_from_cpe(cpe) -> Optional[str]:
    """Extract a SPECIFIC affected version from a CPE string, or None. Handles CPE 2.3
    (`cpe:2.3:a:vendor:product:version:...`, version at field 5) and the 2.2 URI form
    (`cpe:/a:vendor:product:version:...`, version at field 3 after the prefix). Wildcard/any/empty
    versions (`*`, `-`, `ANY`, `NA`, blank) return None (no constraint). A single CPE carries only an
    exact version, not a range — the advisory's range (if any) still comes from the CSAF feed; this
    just lets the identity-only feeds (cve/jvn) contribute an `{exact: version}` where a specific CPE
    version is present. Used by core/cve_feed.py and core/jvn_feed.py to populate the version gate."""
    if not cpe or not isinstance(cpe, str):
        return None
    s = cpe.strip()
    if s.lower().startswith("cpe:2.3:"):
        parts = s.split(":")
        ver = parts[5] if len(parts) > 5 else None
    elif s.lower().startswith("cpe:/"):
        parts = s[len("cpe:/"):].split(":")  # part, vendor, product, version, ...
        ver = parts[3] if len(parts) > 3 else None
    else:
        return None
    if not ver:
        return None
    ver = ver.strip()
    if ver in ("*", "-", "") or ver.upper() in ("ANY", "NA"):
        return None
    # must contain a digit to be a usable version (reject stray labels)
    return ver if _NUM_RE.search(ver) else None


def precondition_version_status(precond: Optional[dict], firmware) -> Optional[bool]:
    """Given a fingerprint_precondition (which may carry a `version` range spec) and an observed
    firmware string, is the device in the advisory's affected version range? Returns True (affected),
    False (not affected — safe to suppress the finding), or None (can't tell: no version spec on the
    candidate, or the firmware is unknown/unparseable -> fall back to identity-only, version-unconfirmed).
    This is the single gate the matchers (core/check.py, core/passive.py) call for version narrowing."""
    if not precond:
        return None
    spec = precond.get("version")
    if not spec:
        return None
    if not firmware or firmware in ("unknown", "", None):
        return None
    return version_in_range(firmware, spec)
