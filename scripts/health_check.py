#!/usr/bin/env python3
"""Corpus + detections health check (read-only).

Audits the checks/candidates corpus and the detection-gen outputs for the integrity drift that has
historically been caught only by ad-hoc discovery (stale disclosure_status, promoted-but-retained
candidate stubs, armed checks missing a fingerprint gate / executor / detection_hints, orphan
detection outputs). Fixes NOTHING — emits a ranked Markdown report; all remediation is user-gated.

Reuses core/registry.py (load/checks/candidates/shippable) and core/check.py enums. Part B shells out
to detection-gen/generate.py and the real-tool validator smoke tests when available.

Usage:
  python3 scripts/health_check.py [--out lab-notes/health-check-YYYY-MM-DD.md] [--no-detections]
"""
from __future__ import annotations
import argparse, datetime, os, re, subprocess, sys, tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent          # ics-scanner/
RESEARCH = REPO.parent                                 # research/
# Prefer the in-repo detection-gen subtree (self-contained: travels with the repo, so a fresh
# clone works without the research/ sibling). Fall back to the sibling for legacy layouts.
DETGEN = REPO / "detection-gen" if (REPO / "detection-gen" / "generate.py").exists() else RESEARCH / "detection-gen"
sys.path.insert(0, str(REPO))

from core.registry import CheckRegistry, load_check_metadata          # noqa: E402
from core.check import DisclosureStatus, Confidence                   # noqa: E402

SHIPPABLE = {DisclosureStatus.PUBLIC, DisclosureStatus.DISCLOSED_FIXED}

# finding buckets
BLOCK, WARN, INFO = "blocker", "warning", "info"
findings: list[tuple[str, str, str]] = []   # (severity, code, message)
def add(sev, code, msg): findings.append((sev, code, msg))


def rel(p: Path) -> str:
    try: return str(p.relative_to(REPO))
    except ValueError: return str(p)


# ---------------------------------------------------------------- Part A
def part_a():
    checks_dir = REPO / "checks"
    yamls = sorted(checks_dir.glob("**/*.yaml"))
    loaded = {}        # path -> metadata
    by_id: dict[str, list[Path]] = {}

    # A1 load integrity
    for y in yamls:
        try:
            m = load_check_metadata(y)
        except Exception as e:
            add(BLOCK, "A1-load", f"{rel(y)}: load failed -> {type(e).__name__}: {str(e)[:120]}")
            continue
        loaded[y] = m
        by_id.setdefault(m.check_id, []).append(y)

    armed = {y: m for y, m in loaded.items() if "candidates" not in y.parts and not m.is_candidate()}
    cands = {y: m for y, m in loaded.items() if "candidates" in y.parts or m.is_candidate()}
    add(INFO, "A1-count", f"loaded {len(loaded)} yaml ({len(armed)} armed, {len(cands)} candidate); "
        f"{len([1 for f in findings if f[1]=='A1-load'])} load failures")

    # A2 duplicate check_id + armed/candidate overlap
    for cid, paths in by_id.items():
        if len(paths) > 1:
            add(WARN, "A2-dupe-id", f"check_id '{cid}' defined in {len(paths)} files: {', '.join(rel(p) for p in paths)}")
    armed_slugs = {m.check_id.replace('candidate-', ''): y for y, m in armed.items()}
    for y, m in cands.items():
        base = m.check_id.replace('candidate-', '')
        promoted = any("promoted" in part.lower() for part in y.parts) or \
            _has(y, r'PROMOTED\b.*(->|→)|kept as the research record')
        twin = armed_slugs.get(base)
        if twin and not promoted:
            add(WARN, "A2-overlap", f"candidate {rel(y)} overlaps armed {rel(twin)} but is NOT marked PROMOTED (verify it's not a stale dupe)")

    # A3 arming-gate compliance
    #   disclosure_status gates shippable()/export, NOT local execution. An armed check at
    #   `disclosed-pending-fix` is the legitimate coordinated-disclosure state (runs locally with
    #   --include-destructive; shippable() correctly excludes it; flips to public on CVE publish --
    #   see the snap7 AGENT-NOTES contract). Only `undisclosed`+armed is a real concern (should it be
    #   a candidate, or is it mis-statused?) -> warning, not blocker.
    for y, m in armed.items():
        ds = m.disclosure_status
        if ds == DisclosureStatus.UNDISCLOSED:
            add(WARN, "A3-armed-undisclosed", f"ARMED {rel(y)} is disclosure_status=undisclosed (review: should it be a candidate, or re-statused? never ships via shippable())")
        if m.destructive and not m.fingerprint_precondition:
            add(BLOCK, "A3-gate-fingerprint", f"ARMED destructive {rel(y)} has NO fingerprint_precondition (could fire at arbitrary hosts)")
        if m.kind and getattr(m.kind, "value", str(m.kind)) == "native" and m.module:
            modfile = REPO / (m.module.replace(".", "/") + ".py")
            if not modfile.exists():
                add(BLOCK, "A3-executor-missing", f"ARMED {rel(y)} module '{m.module}' -> {rel(modfile)} does not exist")
        if not m.detection_hints and not _has(y, r'no .*(byte-?pattern|signature)|omit.*detection_hints|detection_hints.*(intentionally|deliberately|omitted)|deliberately omitted|OMITTED'):
            add(WARN, "A3-detection-hints", f"ARMED {rel(y)} has no detection_hints and no honest-absence note")
        if m.confidence not in (Confidence.HIGH, Confidence.LOW):
            add(BLOCK, "A3-confidence", f"ARMED {rel(y)} confidence invalid: {m.confidence}")

    # A4 disclosure_status table (assisted reconcile) + heuristics
    status_counts: dict[str, int] = {}
    for y, m in loaded.items():
        v = getattr(m.disclosure_status, "value", str(m.disclosure_status))
        status_counts[v] = status_counts.get(v, 0) + 1
    add(INFO, "A4-status", "disclosure_status spread: " + ", ".join(f"{k}={v}" for k, v in sorted(status_counts.items())))

    # A5 candidate hygiene
    for y, m in cands.items():
        if m.kind is not None and "candidates" in y.parts:
            add(WARN, "A5-candidate-kind", f"candidate {rel(y)} carries kind={getattr(m.kind,'value',m.kind)} (candidate stubs should have no kind)")
        if m.kind and getattr(m.kind, "value", str(m.kind)) == "native" and m.module:
            modfile = REPO / (m.module.replace(".", "/") + ".py")
            if not modfile.exists() and not _has(y, r'NOT YET BUILDABLE|code-gap|firmware-gap|live-hardware-gap'):
                add(WARN, "A5-candidate-executor", f"candidate {rel(y)} names missing module '{m.module}' without a NOT-YET-BUILDABLE note")
    return {"armed": armed, "cands": cands, "ids": set(by_id)}


def _has(path: Path, pattern: str) -> bool:
    try: return re.search(pattern, path.read_text(errors="ignore"), re.I) is not None
    except Exception: return False


def _has_patterns(dh: dict) -> bool:
    """True if detection_hints declares at least one non-empty pattern list. All-empty patterns are
    the methodology's honest-absence case (e.g. SSH-encrypted logins) -> no output is expected."""
    for key in ("narrow", "broad"):
        sect = (dh or {}).get(key) or {}
        if sect.get("patterns"):
            return True
    return False


# ---------------------------------------------------------------- Part B
def part_b(ctx):
    if not DETGEN.exists():
        add(WARN, "B0-detgen-missing", f"detection-gen not found at {DETGEN}; skipped Part B")
        return
    gen = DETGEN / "generate.py"
    with tempfile.TemporaryDirectory() as tmp:
        # B1 render clean
        try:
            r = subprocess.run([sys.executable, str(gen), "--checks-dir", str(REPO / "checks"),
                                "--out", tmp], capture_output=True, text=True, timeout=600, cwd=str(DETGEN))
            out = r.stdout + r.stderr
            ntmpl = len(list(Path(tmp).glob("**/*")))
            # match genuine error diagnostics, not per-check progress lines whose NAME contains
            # "exception"/"error" (e.g. "modbus-pymodbus-exception-compliance: 3 template(s)")
            errlines = [l for l in out.splitlines()
                        if re.search(r'traceback|^\s*(error|exception)\b|: error|error:|exception:|failed', l, re.I)
                        and not re.search(r'\d+\s+template', l, re.I)]
            if r.returncode != 0 or errlines:
                add(BLOCK, "B1-render", f"generate.py rc={r.returncode}; {len(errlines)} error line(s); e.g. {errlines[:2]}")
            else:
                add(INFO, "B1-render", f"generate.py OK, {ntmpl} output files rendered to tmp")
        except Exception as e:
            add(WARN, "B1-render", f"could not run generate.py: {type(e).__name__}: {str(e)[:100]}")

    # B2 coverage: armed checks with detection_hints should have output in detection-gen/output
    out_dir = DETGEN / "output"
    if out_dir.exists():
        out_blob = " ".join(p.name for p in out_dir.glob("**/*"))
        for y, m in ctx["armed"].items():
            if m.detection_hints and _has_patterns(m.detection_hints):
                slug = m.check_id.replace("_", "-")
                if slug not in out_blob and m.check_id not in out_blob:
                    add(WARN, "B2-coverage", f"ARMED {m.check_id} has non-empty detection patterns but no output under detection-gen/output")
        # B4 orphan outputs: output stems with no current check_id
        current = {c.replace("-", "").replace("_", "") for c in ctx["ids"]}
        orphans = 0
        for p in out_dir.glob("**/*"):
            if not p.is_file():
                continue
            stem = re.sub(r'\.(broad|narrow)$', '', p.stem)
            stem = re.sub(r'^ics_(broad|narrow)___', '', stem)
            norm = stem.replace("-", "").replace("_", "")
            if norm and not any(norm in c or c in norm for c in current):
                orphans += 1
        if orphans:
            add(WARN, "B4-orphan", f"{orphans} detection output file(s) have no matching current check_id (stale; candidates for cleanup)")

        # B5 duplicate Suricata SIDs: every generated rule must carry a corpus-unique sid, or a
        # sensor that loads them all drops one as a Duplicate signature. plan_sids() resolves hash
        # collisions at generate time; this guards that the on-disk output actually is collision-free.
        sur_dir = out_dir / "suricata"
        if sur_dir.exists():
            sid_sources: dict[str, list[str]] = {}
            for p in sur_dir.glob("*.rules"):
                for sid in re.findall(r'\bsid:(\d+)\b', p.read_text(encoding="utf-8", errors="replace")):
                    sid_sources.setdefault(sid, []).append(p.name)
            dupes = {s: v for s, v in sid_sources.items() if len(v) > 1}
            if dupes:
                for s, files in sorted(dupes.items()):
                    add(BLOCK, "B5-sid-collision", f"Suricata sid {s} emitted by {len(files)} rules ({', '.join(sorted(set(files)))}); a sensor drops all but one")
    else:
        add(INFO, "B2-coverage", "detection-gen/output not present; skipped coverage/orphan checks")

    # B3 real-tool validators
    for t in ("smoke_test_sigma.py", "smoke_test_suricata.py", "smoke_test_escu.py"):
        tp = DETGEN / "tests" / t
        if not tp.exists():
            continue
        try:
            r = subprocess.run([sys.executable, str(tp)], capture_output=True, text=True, timeout=300, cwd=str(DETGEN))
            if r.returncode != 0:
                add(BLOCK, "B3-validate", f"{t} FAILED (rc={r.returncode}); real-tool rejected output: {(r.stdout+r.stderr).splitlines()[-3:]}")
            else:
                add(INFO, "B3-validate", f"{t} passed (real-tool validation)")
        except Exception as e:
            add(WARN, "B3-validate", f"{t} could not run: {type(e).__name__}: {str(e)[:100]}")


# ---------------------------------------------------------------- report
def report(path: Path):
    order = {BLOCK: 0, WARN: 1, INFO: 2}
    findings.sort(key=lambda f: (order[f[0]], f[1]))
    nb = sum(1 for f in findings if f[0] == BLOCK)
    nw = sum(1 for f in findings if f[0] == WARN)
    today = datetime.date.today().isoformat()
    lines = [f"# icsScanner corpus + detections health check — {today}", "",
             f"**{nb} blocker(s), {nw} warning(s).** Read-only audit; all remediation is user-gated.", ""]
    for sev in (BLOCK, WARN, INFO):
        rows = [f for f in findings if f[0] == sev]
        if not rows:
            continue
        lines.append(f"## {sev.upper()} ({len(rows)})")
        for _, code, msg in rows:
            lines.append(f"- `{code}` — {msg}")
        lines.append("")
    path.write_text("\n".join(lines))
    print(f"\n{nb} blocker(s), {nw} warning(s). Report: {rel(path)}")
    return nb


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    ap.add_argument("--no-detections", action="store_true")
    a = ap.parse_args()
    # sanity: registry loads
    try:
        CheckRegistry(REPO / "checks").load()
    except Exception as e:
        add(BLOCK, "A0-registry", f"CheckRegistry.load() failed: {type(e).__name__}: {str(e)[:120]}")
    ctx = part_a()
    if not a.no_detections:
        part_b(ctx)
    out = Path(a.out) if a.out else (REPO / "lab-notes" / f"health-check-{datetime.date.today().isoformat()}.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    nb = report(out)
    sys.exit(1 if nb else 0)


if __name__ == "__main__":
    main()
