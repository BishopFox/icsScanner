#!/usr/bin/env python3
"""detection-gen — generates Sigma/Splunk ESCU/Suricata detection templates from icsScanner's
own check YAML files. Pilot scope (2026-08-21): the 7 checks that have hand-authored
`detection_hints:` metadata. See lab-notes/format-research.md for how each format was verified,
and README.md for the project's own scope/design decisions.

Usage (run from detection-gen/, now a subdirectory of the ics-scanner repo itself):
    python3 generate.py --checks-dir ../checks --out output/
    python3 generate.py --checks-dir ../checks --check-id telnet-sel-relay-access-level-1-default-password --out output/
"""

from __future__ import annotations

import argparse
from pathlib import Path

from core.check_loader import load_all_checks
from core.renderers import escu, sigma, suricata, zeek, zeek_policy, zeek_protocol, zeek_behavioral

_RENDERERS = {
    "sigma": (sigma, "yml"),
    "escu": (escu, "yml"),
    "suricata": (suricata, "rules"),
    "zeek": (zeek, "sig"),
    "zeek-policy": (zeek_policy, "zeek"),
    "zeek-protocol": (zeek_protocol, "zeek"),  # field-level protocol-analyzer-event policies
    "zeek-behavioral": (zeek_behavioral, "zeek"),  # connection-concurrency policy (pool exhaustion)
}


def generate_for_check(record, out_dir: Path, formats: list[str]) -> list[Path]:
    written = []
    for fmt in formats:
        module, ext = _RENDERERS[fmt]
        for mode in ("narrow", "broad", "behavioral"):
            content = module.render(record, mode)
            if content is None:
                continue
            fmt_dir = out_dir / fmt
            fmt_dir.mkdir(parents=True, exist_ok=True)
            # Some formats (ESCU) require the on-disk filename to be mechanically derived from
            # the content's own `name` field (contentctl's validate_file_name_matches_content_name()) —
            # a renderer exposing `output_filename()` opts into that instead of the default,
            # human-readable `{check_id}.{mode}.{ext}` scheme every other format uses.
            derive_name = getattr(module, "output_filename", None)
            derived = derive_name(record, mode) if derive_name else None
            out_path = fmt_dir / (derived if derived else f"{record.check_id}.{mode}.{ext}")
            out_path.write_text(content, encoding="utf-8")
            written.append(out_path)
    return written


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--checks-dir", required=True, type=Path, help="Path to icsScanner's checks/ directory")
    parser.add_argument("--out", required=True, type=Path, help="Output directory for generated templates")
    parser.add_argument("--check-id", action="append", help="Generate for only this check_id (repeatable). Default: all checks with detection_hints.")
    parser.add_argument("--formats", default="sigma,escu,suricata,zeek,zeek-protocol,zeek-behavioral", help="Comma-separated formats (default: sigma,escu,suricata,zeek,zeek-protocol,zeek-behavioral)")
    args = parser.parse_args()

    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    for f in formats:
        if f not in _RENDERERS:
            parser.error(f"unknown format {f!r} — choose from {list(_RENDERERS)}")

    records = load_all_checks(args.checks_dir, only_check_ids=args.check_id)
    hinted = [r for r in records if r.has_hints]
    skipped = [r for r in records if not r.has_hints]

    # Suricata SIDs are deduplicated across the WHOLE corpus (the bare hash can collide), so the map
    # must be built from every check, not just a --check-id subset — otherwise a per-check regen
    # (e.g. the pre-commit hook) could assign a SID a full run wouldn't. Load the full set once here
    # purely to plan the SIDs; only the requested checks are written below.
    if "suricata" in formats:
        full_hinted = [r for r in load_all_checks(args.checks_dir) if r.has_hints] if args.check_id else hinted
        suricata._SID_OVERRIDES = suricata.plan_sids(full_hinted)

    print(f"Loaded {len(records)} real check(s) from {args.checks_dir}")
    print(f"  {len(hinted)} have detection_hints — generating templates")
    if skipped and not args.check_id:
        print(f"  {len(skipped)} have no detection_hints yet — skipped (no code-inspection fallback built yet, see lab-notes/format-research.md)")

    # Lint: report any detection_hints pattern the renderers will skip (trivially-generic in every
    # format, or stream-unsafe for zeek/suricata) so a low-quality pattern is visible, not silently
    # dropped. See core/pattern_quality.py (both gates added after real-traffic validation).
    from core.pattern_quality import pattern_quality_warnings
    lint = [w for r in hinted for w in pattern_quality_warnings(r)]
    if lint:
        print(f"\n  pattern-quality lint — {len(lint)} pattern(s) skipped:")
        for check_id, mode, reason, val in lint:
            print(f"    [{reason}] {check_id} ({mode}): {val!r}")

    total_written = 0
    for record in hinted:
        written = generate_for_check(record, args.out, formats)
        total_written += len(written)
        print(f"  {record.check_id}: {len(written)} template(s)")

    print(f"\n{total_written} template file(s) written to {args.out}")


if __name__ == "__main__":
    main()
