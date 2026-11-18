"""ICS Advisory Project CSV ingestion -> human-reviewed candidate queue. Milestone 2
(00-PROJECT-CHARTER.md § Scope: "CVE-feed adapter shape ... candidate-queue pattern, not
auto-generated checks"). Every row becomes a CheckMetadata STUB (kind unset — is_candidate() is
True) written to checks/candidates/ — never an executable check. A human reviews each one,
decides whether a safe probe is even possible, and only then promotes it into a real
checks/<protocol>/<check_id>.yaml with a real kind/steps-or-module and a validated
fingerprint_precondition, going through the full "is this a safe check?" gate in
../01-METHODOLOGY-AND-CHECKLISTS.md like any other check.

VERIFIED 2026-08-18 against a real downloaded export (icsadvprj/ICS-Advisory-Project on GitHub,
ICS-CERT_ADV/CISA_ICS_ADV_Master.csv, 3986 rows) — the original "documented schema, never
verified" caveat this docstring used to carry was accurate: the real export's headers use
underscores, not the spaced/documented-schema names this module originally assumed (e.g.
`CVE_Number`, not `cve number`), which meant the REQUIRED cve column lookup failed outright
(`ValueError: CSV has no recognizable CVE column`) against every real row. Fixed by adding the
real header names to `_COLUMN_ALIASES`. A second, more consequential real bug found at the same
time: `CVE_Number` frequently holds MULTIPLE comma-separated CVE IDs in one cell (1770 of 3986
rows in the real export, ~44%) — the original code treated the whole cell as one CVE id, which
would have produced a garbled `check_id` (e.g. `candidate-cve-2026-64887, cve-2026-34492`) for
every one of those rows. Fixed by splitting on comma and emitting one candidate per CVE, all
sharing the same vendor/product/severity from that row. Cumulative_CVSS was checked for the
bare-integer-score bug already found in CSAF/JVN (`core/reporter.py`'s docstring) — NOT present
here; the only non-decimal values seen are text placeholders ("Not Applicable"/"Not Assigned"),
which _severity_band() already handles correctly as Unscored, so no fix needed there.
tests/fixtures/ics-advisory-project-sample.csv is now a REAL excerpt of the actual downloaded
export (including a genuine multi-CVE row), not hand-built.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Union

from core.check import CheckMetadata, Confidence, DisclosureStatus
from core.registry import metadata_to_yaml_dict

import yaml

# Accepted header names per logical field, lowercased. Includes the REAL icsadvprj export's
# actual underscore-separated headers (Vendor, Product, CVE_Number, Cumulative_CVSS, CWE_Number)
# confirmed 2026-08-18, plus the originally-assumed spaced variants kept for tolerance in case a
# differently-formatted export shows up later.
_COLUMN_ALIASES = {
    "vendor": {"vendor", "vendor name"},
    "product": {"product", "product name"},
    "cve": {"cve", "cve id", "cve number", "cve_number"},
    "cvss": {"cvss", "cvss score", "cumulative cvss", "cumulative_cvss"},
    "cwe": {"cwe", "cwe id", "cwe number", "cwe_number"},
    "cpe": {"cpe"},
}


def _build_column_map(fieldnames: list) -> dict:
    lower_to_actual = {fn.strip().lower(): fn for fn in fieldnames}
    column_map = {}
    for logical, aliases in _COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in lower_to_actual:
                column_map[logical] = lower_to_actual[alias]
                break
    if "cve" not in column_map:
        raise ValueError(
            f"CSV has no recognizable CVE column (looked for {_COLUMN_ALIASES['cve']}); "
            f"found headers: {fieldnames}. This likely means the real export's schema differs "
            f"from what this module assumes — see the module docstring caveat."
        )
    return column_map


def ingest_csv(path: Union[str, Path]) -> list[CheckMetadata]:
    """Parse an ICS Advisory Project CSV export into candidate CheckMetadata stubs. Every
    candidate: kind=None (never executable), disclosure_status=public (CISA advisories are
    already public by definition), confidence=low (unverified until a human writes and
    validates a real probe — see 01-METHODOLOGY's confidence-ceiling rule), protocol="unknown"
    (the CSV has no wire-protocol column; a human fills this in during review)."""
    path = Path(path)
    candidates = []
    with open(path, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError(f"{path}: empty or unreadable CSV")
        column_map = _build_column_map(reader.fieldnames)

        for row in reader:
            raw_cve = (row.get(column_map["cve"]) or "").strip()
            if not raw_cve:
                continue  # skip rows with no CVE id — nothing to track a candidate against
            # The real export frequently packs multiple CVE IDs into one cell, comma-separated
            # (~44% of rows in the verified 2026-08-18 sample) — one candidate per CVE, all
            # sharing this row's vendor/product/severity, not one garbled candidate per row.
            cve_ids = [c.strip() for c in raw_cve.split(",") if c.strip()]
            vendor = (row.get(column_map.get("vendor", "")) or "").strip() or "unknown"
            product = (row.get(column_map.get("product", "")) or "").strip() or "unknown"
            cvss = (row.get(column_map.get("cvss", "")) or "").strip() or None

            # Version gate enrichment: if the CPE column carries a specific version, feed it to the
            # precondition as {exact: version} so the version gate can narrow this candidate. Only a
            # specific CPE version (not a wildcard) contributes; ranges still come from the CSAF feed.
            precond = {"vendor": vendor, "product": product}
            cpe_cell = (row.get(column_map.get("cpe", "")) or "").strip()
            if cpe_cell:
                import re as _re
                from core.version_match import version_from_cpe
                tok = next((t for t in _re.split(r"[,\s]+", cpe_cell) if t.lower().startswith("cpe:")), "")
                ver = version_from_cpe(tok)
                if ver:
                    precond["version"] = {"exact": ver}

            for cve in cve_ids:
                candidates.append(
                    CheckMetadata(
                        check_id=f"candidate-{cve.lower()}",
                        protocol="unknown",
                        kind=None,  # candidate stub — is_candidate() True, never executable
                        cve_id=cve,
                        severity=cvss,
                        disclosure_status=DisclosureStatus.PUBLIC,
                        confidence=Confidence.LOW,
                        fingerprint_precondition=dict(precond),
                        description=f"CISA ICS advisory candidate — {cve} ({vendor} {product})",
                    )
                )
    return candidates


def write_candidates(candidates: list[CheckMetadata], out_dir: Union[str, Path]) -> list[Path]:
    """Write each candidate to its own YAML file under out_dir (normally checks/candidates/).
    One file per candidate — matches the per-check-file convention real checks use, so promoting
    a candidate to a real check is a small edit, not a reformat."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for meta in candidates:
        file_path = out_dir / f"{meta.check_id}.yaml"
        with open(file_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(metadata_to_yaml_dict(meta), f, sort_keys=False)
        written.append(file_path)
    return written
