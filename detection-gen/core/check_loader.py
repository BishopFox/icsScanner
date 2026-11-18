"""Reads icsScanner's own check YAML files directly (not via icsScanner's CheckRegistry, which
this project deliberately does not depend on as a library — detection-gen is a standalone
consumer of icsScanner's check YAML as data, not a plugin loaded by icsScanner itself).

A CheckRecord's `detection_hints` field carries this project's own real input: `narrow`/`broad`
pattern lists, `transport`, `app_protocol`, `mitre_attack_id`. When a check has no
`detection_hints` at all (every check authored before 2026-08-21, or any future one where a
human simply didn't fill it in), `has_hints` is False and the pilot's code-inspection fallback
(not yet built — see lab-notes/generator-design.md's open items) is the only other source of
truth. This loader does NOT invent hints when they're absent; it reports the absence honestly so
the generator can decide what to do (skip, warn, or fall back), rather than silently returning an
empty-but-present hints dict that would look identical to "no vulnerability class exists here."

CANDIDATES WITH HINTS, 2026-08-25: candidates (`kind: absent`) used to be excluded unconditionally
— the original reasoning was "there is no probe to detect for a stub with no implementation."
That reasoning doesn't hold for every candidate anymore: icsScanner's own "Scanner check vs.
standalone script" convention (`01-METHODOLOGY-AND-CHECKLISTS.md`) deliberately keeps some
fully-researched, wire-format-confirmed findings OUT of the active `checks/` registry (destructive-
uncertain, privileged-tier-unlocking, derived/computed, or still-undisclosed cases) — these are
real `kind: absent` candidates, but the underlying attack traffic is just as well-understood as
any active check's. A DETECTION for such a finding is safe to generate and ship even when the
ACTIVE probing tool is deliberately kept standalone or unbuilt — generating a Sigma/ESCU/Suricata
template never touches a live target, unlike running the check/script itself. So: a candidate is
now loaded for detection generation purposes if and only if it carries `detection_hints:` — a
candidate with no hints yet (the ordinary "still researching" case) is still excluded, since there
genuinely is nothing to generate from.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class CheckRecord:
    check_id: str
    protocol: str
    kind: Optional[str]
    destructive: bool
    confidence: str
    severity: Optional[str]
    cve_id: Optional[str]
    can_id: Optional[str]
    description: str
    fingerprint_precondition: Optional[dict]
    detection_hints: Optional[dict]
    source_path: Path

    @property
    def has_hints(self) -> bool:
        return bool(self.detection_hints)

    @property
    def is_candidate(self) -> bool:
        return self.kind is None


def load_check(path: Path) -> CheckRecord:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not data or "check_id" not in data:
        raise ValueError(f"{path}: not a valid icsScanner check file (missing check_id)")
    return CheckRecord(
        check_id=data["check_id"],
        protocol=data.get("protocol", "unknown"),
        kind=data.get("kind"),
        destructive=bool(data.get("destructive", False)),
        confidence=data.get("confidence", "low"),
        severity=data.get("severity"),
        cve_id=data.get("cve_id"),
        can_id=data.get("can_id"),
        description=data.get("description", ""),
        fingerprint_precondition=data.get("fingerprint_precondition"),
        detection_hints=data.get("detection_hints"),
        source_path=path,
    )


def load_all_checks(checks_dir: Path, only_check_ids: Optional[list[str]] = None) -> list[CheckRecord]:
    """Loads every real check YAML under checks_dir, PLUS any candidate (kind: absent) that
    already carries detection_hints — see the module docstring's "CANDIDATES WITH HINTS" note.
    A candidate with no hints yet is still excluded; there's genuinely nothing to generate."""
    records = []
    for yaml_file in sorted(checks_dir.glob("**/*.yaml")):
        record = load_check(yaml_file)
        if record.is_candidate and not record.has_hints:
            continue
        if only_check_ids and record.check_id not in only_check_ids:
            continue
        records.append(record)
    return records
