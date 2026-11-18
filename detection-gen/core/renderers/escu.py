"""Splunk ESCU detection renderer.

VERSION-DRIFT LESSON, load-bearing (2026-08-21): this renderer was originally built against the
JSON schema on `splunk/security_content`'s GitHub `main` branch
(schemas/EventBasedDetection.schema.json), which specifies FLAT top-level fields
(mitre_attack_id, asset_type, product, security_domain, analytic_story, cve, plus
creation_date/modification_date). Running the actual pip-installable `contentctl==5.6.0` against
generated output (via `contentctl validate` in a real scaffolded project — see
lab-notes/format-research.md's "ESCU version drift" section) revealed that version does NOT
accept that shape at all: it requires those same fields NESTED under a single `tags:` object, a
single `date` field (not the creation/modification pair), and a real max length on `name`. The
GitHub schema is evidently ahead of (or has drifted from) what's actually shipped and
`pip install`-able today. Per an explicit user decision, this renderer targets the CURRENTLY
INSTALLABLE tool's real model (inspected directly from
`contentctl.objects.abstract_security_content_objects.detection_abstract.Detection_Abstract`
and `contentctl.objects.detection_tags.DetectionTags`) — what a real user running
`contentctl validate` today would actually need — not the newer/unreleased schema.

REAL CROSS-REFERENCE CONSTRAINT: `tags.analytic_story` is a list of STORY NAMES that must
resolve to real `stories/*.yml` files in the analyst's own ESCU content pack — this is
inherent to how ESCU's content-pack model works (a Story is real, separate, cross-referenced
content), not something a standalone generator can invent on the analyst's behalf. This
renderer emits a name from a small curated bucket list (see `_KNOWN_STORIES`/`_analytic_story()`
below) and documents the requirement explicitly in `how_to_implement` rather than silently
assuming any name will resolve — until the 2026-09-05 sweep (project_open_tasks.md -52), this
field was unconditionally hardcoded to "ICS Default Credentials" for every check regardless of
actual content, a real bug caught while generating content for the first non-credential checks;
`detection_hints.analytic_story` is now a real per-check field, same posture as
`mitre_attack_id`. The `ics_network_logs`
filter macro referenced in `search` is the same situation (Macro is likewise real, separate,
cross-referenced content). `data_source`, by contrast, defaults to an empty list in the installed
model (`contentctl.objects.data_source.DataSource` usage in detection_abstract.py:
`data_source: list[str] = []`) rather than being required — so this renderer leaves it unset
instead of inventing a placeholder name for it too; an early pilot draft used a placeholder value
here ("Zeek") and it failed the exact same cross-reference validation as an unresolvable Story
name would, confirming the field needs the same restraint, not a stub.

ARCHITECTURAL NOTE (fixed 2026-08-25): earlier versions of this renderer hand-formatted YAML text
via string interpolation + line-list joining rather than building a dict and handing it to a real
YAML emitter, the way sigma.py always has. That was safe for the pilot's own 7 checks only by
coincidence — every `bytes`/`regex` pattern value happened to be routed through Python's `!r`
before landing in free-text search commentary — but every OTHER field was interpolated with zero
escaping, including `description`, which is copied verbatim from icsScanner's own check YAML and
is not this project's content to constrain. A check whose own `description:` field is itself
multi-line (a real, valid way to author that field, just not exercised by any of the 7 pilot
checks) corrupted the hand-formatted `description: |` block: only the first line received the
block's leading indentation, so every line after an embedded newline landed outside the literal
scalar's required indentation, breaking the parse (or, with different content, silently landing
as a different top-level key instead of raising anything) — the exact same "parses different from
intended" bug class as the CR/LF-folding bug described in sigma.py's own docstring, just triggered
by a different input shape. Confirmed live (a synthetic two-line `description` produced a
`yaml.safe_load` `ScannerError`) before fixing.

Fixed by building a real dict and handing it to `yaml.dump()`. A `_LiteralStr` marker forces
literal block (`|`) style for the four prose fields (`description`, `search`,
`how_to_implement`, `known_false_positives`) — matching how real ESCU content authors them,
regardless of whether a given value happens to contain an embedded newline — while every other
field's escaping is left entirely to the real emitter instead of a hand-maintained invariant.
The inline `# format YYYY-MM-DD` comment on the old `date:` line is dropped (PyYAML cannot emit
comments); that instruction now lives in `how_to_implement`, which is the only place any
downstream tool actually reads it.
"""

from __future__ import annotations

import uuid
from typing import Optional

import yaml

from core.check_loader import CheckRecord

_MAX_NAME_LENGTH = 67  # CONTENTCTL_MAX_SEARCH_NAME_LENGTH, confirmed against the installed
# contentctl package directly (contentctl.objects.constants) — not assumed from the error message
# text alone.


class _NoAliasDumper(yaml.SafeDumper):
    """Disables YAML anchor/alias generation — a generated detection rule should never rely on
    a reader resolving `&anchor`/`*alias` references, which some downstream ESCU tooling does
    not support."""

    def ignore_aliases(self, data):
        return True


class _LiteralStr(str):
    """A string that must always render as a literal block scalar (`|`), matching how real ESCU
    content authors multi-line description/search/how_to_implement/known_false_positives fields
    — regardless of whether this particular value happens to contain an embedded newline."""


def _represent_literal_str(dumper: yaml.Dumper, data: str):
    return dumper.represent_scalar("tag:yaml.org,2002:str", str(data), style="|")


_NoAliasDumper.add_representer(_LiteralStr, _represent_literal_str)


def _mitre_ids(record: CheckRecord) -> list[str]:
    hints = record.detection_hints or {}
    mid = hints.get("mitre_attack_id")
    return [mid] if mid else ["T0812"]  # T0812 = Default Credentials, ATT&CK for ICS — this
    # project's own established default per lab-notes/format-research.md's open question; most
    # icsScanner checks are default-credentials findings, T0814 (Denial of Service) is used
    # explicitly instead when a check's own detection_hints override it (e.g. DoS/crash checks).


_DEFAULT_STORY = "ICS Default Credentials"

# Curated bucket list, fixed 2026-09-05 as part of the analytic_story sweep (see
# project_open_tasks.md -52 for the full rationale/sweep writeup), 5th bucket added 2026-09-13
# for the unauthenticated-disclosure check class (see ics-scanner/01-METHODOLOGY-AND-CHECKLISTS.md
# and project_open_tasks.md's -58-adjacent entry — a real, distinct vuln shape this project's
# checks were starting to accumulate with no bucket to put them in: MES3/Yaskawa/GE POWER LEADER/
# Honeywell HICC-1100PT/SICAM RTU, see ics-scanner/lab-notes/side-quests.md). Deliberately NOT one
# story per check — ESCU's own Story concept is meant to group related analytics under one shared
# narrative, and one-story-per-check would just be _MAX_NAME_LENGTH-shaped noise. A check's own
# `detection_hints.analytic_story` (a plain string, added by the original sweep) must be one of
# these five unless a future check genuinely needs a new bucket — this list exists so that
# decision gets made deliberately, not by whatever string a check author happens to type:
#   "ICS Default Credentials"              — static/derived/computed credential-based access
#   "ICS Unauthorized Command Execution"   — auth-bypass, unauthenticated writes/control commands
#   "ICS Denial of Service"                — crash/hang/resource-exhaustion/restart-capable actions
#   "ICS Network Evasion"                  — traffic-shape/monitoring-evasion characteristics
#   "ICS Information Disclosure"           — data/telemetry/credentials exposed with NO auth
#                                             attempt at all (distinct from Default Credentials,
#                                             which always involves testing a specific credential
#                                             value against a real auth gate)
_KNOWN_STORIES = frozenset(
    {
        "ICS Default Credentials",
        "ICS Unauthorized Command Execution",
        "ICS Denial of Service",
        "ICS Network Evasion",
        "ICS Information Disclosure",
    }
)


def _analytic_story(record: CheckRecord) -> str:
    """Real per-check value (`detection_hints.analytic_story`), added by the 2026-09-05 sweep —
    see project_open_tasks.md -52. FIXES a real bug: this field used to be unconditionally
    hardcoded to "ICS Default Credentials" for every check regardless of actual content, silently
    mislabeling every non-credential finding (DoS/crash checks, auth-bypass checks, etc.) —
    caught while generating ESCU content for 3 new non-credential DNP3 candidates for the first
    time. Falls back to the old hardcoded default ONLY for a check that hasn't been swept yet
    (there should be none after the 2026-09-05 sweep, but a silent KeyError on some future
    hint-less-for-this-field check would be worse than a documented, honest fallback — same
    "documented default, not a silent invention" posture as `_mitre_ids()` above). A value outside
    `_KNOWN_STORIES` is used as-is (not rejected) — this project isn't the source of truth for
    what stories exist in a deploying analyst's own content pack, same reasoning as this file's
    own docstring already gives for `analytic_story`/`ics_network_logs` cross-reference in
    general — but it's worth a human's attention if a new value shows up that isn't one of the
    four curated buckets, since that's either a genuinely new category or a typo."""
    hints = record.detection_hints or {}
    return hints.get("analytic_story") or _DEFAULT_STORY


def _derive_name_and_stem(record: CheckRecord, mode: str) -> tuple[str, str]:
    name = f"ICS {mode.upper()} - {record.check_id}"
    if len(name) > _MAX_NAME_LENGTH:
        name = name[: _MAX_NAME_LENGTH - 3] + "..."

    # MUST be derived from the FINAL `name` field value (after truncation), using the exact same
    # transform contentctl's own contentNameToFileName() applies — verified directly against the
    # installed source (contentctl.objects.abstract_security_content_objects.
    # security_content_object_abstract), not guessed from the validator's error-message text
    # alone. contentctl uses this SAME derived stem for two independent, unrelated-looking
    # requirements: (1) the embedded filter-macro name in `search` and (2) the detection file's
    # own filename on disk (`validate_file_name_matches_content_name()` — the file MUST be named
    # `{derived_stem}.yml`, not `{check_id}.{mode}.yml`). Both are exposed here via one shared
    # helper so the two can never drift apart from each other.
    derived_stem = name.replace(" ", "_").replace("-", "_").replace(".", "_").replace("/", "_").lower()
    return name, derived_stem


def output_filename(record: CheckRecord, mode: str) -> Optional[str]:
    if not record.has_hints:
        return None
    block = record.detection_hints.get(mode)
    if not block or not block.get("patterns"):
        return None
    _, derived_stem = _derive_name_and_stem(record, mode)
    return f"{derived_stem}.yml"


def render(record: CheckRecord, mode: str) -> Optional[str]:
    if not record.has_hints:
        return None
    block = record.detection_hints.get(mode)
    if not block or not block.get("patterns"):
        return None

    name, derived_stem = _derive_name_and_stem(record, mode)
    rule_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"detection-gen:escu:{record.check_id}:{mode}"))
    filter_macro = f"{derived_stem}_filter"

    # Drop trivially-generic patterns (noise in any format); ESCU is a SIEM search, not a
    # reassembly engine, so the stream-unsafe gate does not apply. See core/pattern_quality.py.
    from core.pattern_quality import usable_patterns
    pattern_lines = []
    for p in usable_patterns(block["patterns"]):
        if "bytes" in p:
            pattern_lines.append(f'    | (payload matches literal pattern: {p["bytes"]!r})')
        elif "regex" in p:
            pattern_lines.append(f'    | (payload matches regex: {p["regex"]!r})')
    if not pattern_lines:
        return None  # every pattern was filtered out (generic) -> honest absence, no analytic

    search = (
        "`ics_network_logs`\n"
        "    | (* PLACEHOLDER: replace `ics_network_logs` with your environment's actual index/"
        "sourcetype macro for network/packet-capture logs covering this device's traffic *)\n"
        + "\n".join(pattern_lines) + "\n"
        f"    | table _time, src_ip, dest_ip, dest_port\n"
        f"    | `{filter_macro}`"
    )

    description = (
        f"{block.get('description', record.description)}\n"
        f"Auto-generated by detection-gen from icsScanner check '{record.check_id}'."
    )

    known_fp = (
        "Auto-generated placeholder — this search has NOT been validated against a real log "
        "source. Review the byte/regex patterns below for false-positive risk (a 'broad' pattern "
        "intentionally matches the general vulnerability class, not just this scanner's own "
        "probe, and may also match a real operator's legitimate traffic using the same protocol "
        "feature)." if mode == "broad" else
        "Auto-generated placeholder — not yet validated against a real log source."
    )

    # NOTE: `references` is Optional[List[HttpUrl]] in the installed model (confirmed directly
    # against contentctl.objects.abstract_security_content_objects.security_content_object_abstract)
    # — it must be real URLs, never free text (a CAN ID or "no CVE yet" note is not a URL). Two
    # bugs caught here in sequence before this renderer's first successful validation: an earlier
    # draft put a bare '#'-prefixed comment as a list item (invalid — '#' starts a YAML comment,
    # so the item parses as empty/null, not the intended text), and the immediate next draft
    # replaced it with a plain non-URL string (would fail Pydantic's HttpUrl type validation).
    # The correct fix is to only emit `references:` when a real URL exists, and omit the field
    # entirely otherwise — Optional means "may be absent," not "may contain non-URL text."
    references = []
    if record.cve_id:
        references.append(f"https://nvd.nist.gov/vuln/detail/{record.cve_id}")

    can_note = f" CAN tracking ID {record.can_id} (no public CVE assigned yet)." if record.can_id and not record.cve_id else ""
    story = _analytic_story(record)
    how_to_implement = (
        "This is a GENERATED PLACEHOLDER, not a validated detection. Replace the\n"
        "`ics_network_logs` macro with your actual index/sourcetype for network traffic\n"
        "covering this device. tags.asset_type is set to the generic 'Network' value\n"
        "because contentctl's own AssetType enum has no ICS/OT/PLC/RTU-specific value —\n"
        "verify this is acceptable for your environment. tags.analytic_story below names a\n"
        f"PLACEHOLDER story ('{story}') that must resolve to a real\n"
        "stories/*.yml file in your own content pack — either create one or point this at\n"
        "an existing story you already have; contentctl validate will fail otherwise, by\n"
        "design (Analytic Stories are real cross-referenced content, not something this\n"
        "generator can invent on your behalf). data_source is intentionally left unset\n"
        "(contentctl's own model defaults it to an empty list) — set it once you know\n"
        "which real DataSource object(s) in your content pack cover this device's\n"
        f"traffic; guessing a name here would only reproduce the same problem.{can_note}\n"
        "date is left as REPLACE_WITH_TODAYS_DATE — fill in today's date (format YYYY-MM-DD) "
        "before use."
    )

    doc: dict = {
        "name": name,
        "id": rule_id,
        "version": 1,
        "date": "REPLACE_WITH_TODAYS_DATE",
        "author": "detection-gen (auto-generated, review before use)",
        "description": _LiteralStr(description),
        "status": "experimental",
        # type: Hunting, not TTP — deliberate. This scaffold's own default deployment configs
        # (deployments/escu_default_configuration_ttp.yml) enable Risk Based Alerting for every
        # TTP-type detection, which requires a real `rba:` block with a RiskObject (a `field`
        # name that must actually exist in the search output, a `type`, and a `score` 1-100).
        # Fabricating a risk score here would carry the same false authority as the earlier
        # data_source guess this renderer deliberately avoids (and analytic_story used to make,
        # before the 2026-09-05 sweep — see _analytic_story()'s own docstring) — worse, since an
        # invented score could get silently trusted by automated risk-based-alerting scoring
        # rather than just failing a cross-reference check. Hunting requires no RBA in this
        # scaffold and better matches what this content actually is: an unvalidated, generated
        # starting point for a human to review and tune, not a mature automated-scoring TTP.
        "type": "Hunting",
        "search": _LiteralStr(search),
        "how_to_implement": _LiteralStr(how_to_implement),
        "known_false_positives": _LiteralStr(known_fp),
    }
    if references:
        doc["references"] = references

    tags: dict = {
        "analytic_story": [_analytic_story(record)],
        "asset_type": "Network",
        "product": ["Splunk Enterprise", "Splunk Enterprise Security"],
        "security_domain": "network",
        "mitre_attack_id": _mitre_ids(record),
    }
    if record.cve_id:
        tags["cve"] = [record.cve_id]
    doc["tags"] = tags

    return yaml.dump(doc, Dumper=_NoAliasDumper, sort_keys=False, allow_unicode=True, width=100)
