"""Check registry — Milestone 2 (00-PROJECT-CHARTER.md). Loads check definitions from YAML,
instantiates Check objects (declarative via core/declarative.py's step executor, native via
dynamic import), and separates executable checks from CVE-feed candidate stubs (never
executable — see core/cve_feed.py). Implements the check module format decided 2026-08-12
(see ../01-METHODOLOGY-AND-CHECKLISTS.md).

Directory convention:
  checks/<protocol>/<check_id>.yaml   — real, executable checks (kind: declarative or native)
  checks/candidates/<anything>.yaml   — CVE-feed candidate stubs (kind absent/null), never
                                         instantiated, always kept in a separate bucket so a
                                         human reviewing them can't mistake one for a real check
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Optional, Union

import yaml

from core.check import Check, CheckKind, CheckMetadata, Confidence, DisclosureStatus


def _norm_protocol(name: str) -> str:
    """Normalize a protocol name for filtering so '-' and '_' are interchangeable and case is
    ignored. Most protocols are single tokens (http, modbus, s7comm), but the multi-word ones are
    spelled inconsistently across the tree: directories/probes/core modules use underscores
    (pcom_tcp, indusoft_tcp, cisco_smi) while two checks declare the hyphen form in their
    `protocol:` field (pcom-tcp, indusoft-tcp). Without this, `--protocol pcom_tcp` silently matched
    zero checks even though the directory, probe, and core module all use that exact spelling."""
    return name.strip().lower().replace("-", "_") if name else name


class CheckDefinitionError(ValueError):
    """Raised for a malformed or unsafe check YAML file — see the "is this a safe check?" gate
    in ../01-METHODOLOGY-AND-CHECKLISTS.md, specifically the mandatory fingerprint_precondition
    rule this enforces at load time rather than leaving it as a convention to remember."""


def load_check_metadata(path: Union[str, Path]) -> CheckMetadata:
    """Parse one check YAML file into a CheckMetadata. Field names match CheckMetadata's
    dataclass fields directly — no separate translation layer, so the YAML stays diffable
    against the Python model it becomes."""
    path = Path(path)
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not data or "check_id" not in data or "protocol" not in data:
        raise CheckDefinitionError(f"{path}: missing required 'check_id'/'protocol'")

    kind = CheckKind(data["kind"]) if data.get("kind") else None
    disclosure_status = DisclosureStatus(data.get("disclosure_status", DisclosureStatus.UNDISCLOSED.value))
    confidence = Confidence(data.get("confidence", Confidence.LOW.value))

    meta = CheckMetadata(
        check_id=data["check_id"],
        protocol=data["protocol"],
        kind=kind,
        cve_id=data.get("cve_id"),
        can_id=data.get("can_id"),
        severity=data.get("severity"),
        destructive=bool(data.get("destructive", False)),
        risk_reason=data.get("risk_reason"),
        disclosure_status=disclosure_status,
        confidence=confidence,
        fingerprint_precondition=data.get("fingerprint_precondition"),
        module=data.get("module"),
        steps=data.get("steps"),
        description=data.get("description", ""),
        params=data.get("params"),
        references=data.get("references"),
        advisory_url=data.get("advisory_url"),
        links=data.get("links"),
        detection_hints=data.get("detection_hints"),
        physical_access_reference=data.get("physical_access_reference"),
        not_automatable_reference=data.get("not_automatable_reference"),
    )

    if meta.is_candidate():
        return meta  # candidate stubs are exempt from every rule below — see cve_feed.py

    if kind == CheckKind.NATIVE and not meta.module:
        raise CheckDefinitionError(f"{path}: kind=native requires 'module'")
    if kind == CheckKind.DECLARATIVE and not meta.steps:
        raise CheckDefinitionError(f"{path}: kind=declarative requires 'steps'")
    if not meta.fingerprint_precondition:
        raise CheckDefinitionError(
            f"{path}: executable check has no fingerprint_precondition — a missing "
            f"precondition is a defect (01-METHODOLOGY 'is this a safe check?' gate), not "
            f"permission to fire unconditionally. Candidate stubs (kind: absent) are exempt."
        )
    if meta.fingerprint_precondition.get("protocol_only") and meta.destructive:
        raise CheckDefinitionError(
            f"{path}: protocol_only fingerprint_precondition is not allowed on a destructive "
            f"check — real vendor/model narrowing is required exactly where a check can degrade "
            f"a target. protocol_only is only for non-destructive checks with no meaningful "
            f"hardware-vendor identity to narrow on (e.g. a software library check)."
        )
    probe_name = meta.fingerprint_precondition.get("protocol_probe")
    if probe_name:
        from core.fingerprint import PROTOCOL_PROBES

        if probe_name not in PROTOCOL_PROBES:
            raise CheckDefinitionError(
                f"{path}: unknown protocol_probe {probe_name!r} — known probes: "
                f"{sorted(PROTOCOL_PROBES)}. Fail fast at load time, not at scan time."
            )

    return meta


def metadata_to_yaml_dict(meta: CheckMetadata) -> dict:
    """Inverse of load_check_metadata — used by cve_feed.py to write candidate stubs to disk."""
    d = {
        "check_id": meta.check_id,
        "protocol": meta.protocol,
        "kind": meta.kind.value if meta.kind else None,
        "cve_id": meta.cve_id,
        "can_id": meta.can_id,
        "severity": meta.severity,
        "destructive": meta.destructive,
        "disclosure_status": meta.disclosure_status.value,
        "confidence": meta.confidence.value,
        "fingerprint_precondition": meta.fingerprint_precondition,
        "description": meta.description,
    }
    if meta.module:
        d["module"] = meta.module
    if meta.steps:
        d["steps"] = meta.steps
    if meta.params:
        d["params"] = meta.params
    if meta.references:
        d["references"] = meta.references
    if meta.advisory_url:
        d["advisory_url"] = meta.advisory_url
    if meta.links:
        d["links"] = meta.links
    if meta.detection_hints:
        d["detection_hints"] = meta.detection_hints
    if meta.physical_access_reference:
        d["physical_access_reference"] = meta.physical_access_reference
    if meta.not_automatable_reference:
        d["not_automatable_reference"] = meta.not_automatable_reference
    if meta.risk_reason:
        d["risk_reason"] = meta.risk_reason
    return {k: v for k, v in d.items() if v is not None}


class CheckRegistry:
    def __init__(self, checks_dir: Union[str, Path] = "checks"):
        self.checks_dir = Path(checks_dir)
        self._checks: dict[str, Check] = {}
        self._candidates: dict[str, CheckMetadata] = {}

    def load(self) -> "CheckRegistry":
        if not self.checks_dir.exists():
            return self
        for yaml_file in sorted(self.checks_dir.glob("**/*.yaml")):
            rel_parts = yaml_file.relative_to(self.checks_dir).parts
            in_candidates_dir = "candidates" in rel_parts
            meta = load_check_metadata(yaml_file)
            if in_candidates_dir or meta.is_candidate():
                self._candidates[meta.check_id] = meta
                continue
            self._checks[meta.check_id] = self._instantiate(meta, yaml_file)
        return self

    def _instantiate(self, meta: CheckMetadata, path: Path) -> Check:
        if meta.kind == CheckKind.DECLARATIVE:
            from core.declarative import DeclarativeCheck

            return DeclarativeCheck(meta)
        if meta.kind == CheckKind.NATIVE:
            module = importlib.import_module(meta.module)
            cls = getattr(module, "CHECK_CLASS", None)
            if cls is None:
                raise CheckDefinitionError(
                    f"{path}: native module {meta.module!r} has no CHECK_CLASS attribute "
                    f"pointing at its Check subclass"
                )
            return cls(meta)
        raise CheckDefinitionError(f"{path}: unknown kind {meta.kind!r}")

    def checks(self, protocol: Optional[str] = None) -> list[Check]:
        result = list(self._checks.values())
        if protocol:
            want = _norm_protocol(protocol)
            result = [c for c in result if _norm_protocol(c.metadata.protocol) == want]
        return result

    def candidates(self, protocol: Optional[str] = None) -> list[CheckMetadata]:
        result = list(self._candidates.values())
        if protocol:
            want = _norm_protocol(protocol)
            result = [c for c in result if _norm_protocol(c.protocol) == want]
        return result

    def shippable(self) -> list[Check]:
        """Checks whose disclosure_status would permit inclusion outside this private working
        copy. Not wired to any export tooling yet (posture is private-only per
        03-STYLE-AND-DECISIONS.md) — exists now so a future export step doesn't have to invent
        this filter, mirroring icsFuzzer's PUBLIC_ALLOWLIST discipline."""
        shippable_statuses = {DisclosureStatus.DISCLOSED_FIXED, DisclosureStatus.PUBLIC}
        return [c for c in self._checks.values() if c.metadata.disclosure_status in shippable_statuses]
