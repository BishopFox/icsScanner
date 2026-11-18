"""Check abstraction — icsScanner's equivalent of icsFuzzer's core/base_module.py.

A Check is metadata (always inspectable without executing code — see
../01-METHODOLOGY-AND-CHECKLISTS.md) plus a probe body that is either declarative (a short
send/expect step sequence, executed by a generic step-runner built in Milestone 2) or native
(a Python class implementing probe() directly, subclassing Check below).

icsFuzzer's Device dataclass is superseded by Target (target.py) — a Check operates against a
Target, not a bare Device, so it can see credential references and vendor/product hints for
fingerprint_matches(). icsFuzzer's FuzzResult/FuzzModule are replaced by CheckResult/Check here;
the anomaly/crash_indicator vocabulary becomes the 4-state CheckStatus (00-PROJECT-CHARTER.md
§ Scope, reporting format), since a scanner's job is classifying against a known CVE, not
detecting a symptom.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.fingerprint import FingerprintResult
    from core.target import Target


class CheckKind(str, Enum):
    DECLARATIVE = "declarative"
    NATIVE = "native"


class DisclosureStatus(str, Enum):
    """See ../02-DISCLOSURE-PLAYBOOK.md for the full contract this field implements — in
    particular the reconciliation requirement (status here is a snapshot, not a live source of
    truth) and the never-ship-undisclosed rule."""

    UNDISCLOSED = "undisclosed"
    DISCLOSED_PENDING_FIX = "disclosed-pending-fix"
    DISCLOSED_FIXED = "disclosed-fixed"
    PUBLIC = "public"


class Confidence(str, Enum):
    """A check's `confidence` in CheckMetadata is a CEILING (decided 2026-08-12) — a run can
    report at or below it, never above. See ../01-METHODOLOGY-AND-CHECKLISTS.md."""

    HIGH = "high"
    LOW = "low"


class CheckStatus(str, Enum):
    """4-state, not boolean (decided 2026-08-12) — see 00-PROJECT-CHARTER.md § Scope."""

    CONFIRMED = "confirmed"
    FINGERPRINT_ONLY = "likely-affected-fingerprint-only"
    NOT_APPLICABLE = "not-applicable"
    ERROR = "error"


@dataclass
class CheckResult:
    check_id: str
    protocol: str
    target: str
    status: CheckStatus
    confidence: Confidence
    cve_id: Optional[str] = None
    can_id: Optional[str] = None
    severity: Optional[str] = None  # CVSS vector string, copied from the upstream finding
    description: str = ""
    evidence: Optional[bytes] = None  # raw response bytes backing the verdict
    evidence_decoded: Optional[dict] = None
    duration_ms: Optional[float] = None
    error: Optional[str] = None


@dataclass
class CheckMetadata:
    """The always-inspectable part of a check, loaded from YAML front-matter regardless of
    whether the probe itself is declarative or native. A CVE-feed candidate stub (Milestone 2)
    is exactly a CheckMetadata with kind/module/steps left unset — see is_candidate()."""

    check_id: str
    protocol: str
    kind: Optional[CheckKind] = None  # None = candidate stub, no probe written yet
    cve_id: Optional[str] = None
    can_id: Optional[str] = None
    severity: Optional[str] = None  # CVSS vector, copied from upstream — never re-scored (02-)
    destructive: bool = False
    disclosure_status: DisclosureStatus = DisclosureStatus.UNDISCLOSED
    confidence: Confidence = Confidence.LOW
    fingerprint_precondition: Optional[dict] = None  # vendor/product/version match rule
    module: Optional[str] = None  # dotted path to a Check subclass, kind=native only
    steps: Optional[list] = None  # declarative send/expect steps, kind=declarative only
    description: str = ""
    params: Optional[dict] = None  # generic per-check config for REUSABLE native check classes
    # (added Milestone 3, default-credentials sweep, 2026-08-14) — e.g. an HTTP Basic Auth
    # default-credential checker takes {"path": ..., "credentials": [[user, pass], ...]} here
    # rather than every vendor/product combination needing its own near-identical Python file.
    # Distinct from `steps` (which is specifically the declarative send/expect DSL); a check
    # class reads its own expected keys out of `params` — there's no shared schema across
    # different reusable check classes.
    references: Optional[list] = None  # list of URL strings — the authoritative/primary sources
    # a finding's specific claims (credential value, CVE detail, protocol wire format) were
    # verified against (added 2026-08-14, per user request: "embed links to exploit or
    # authoritative sources"). Traceable sourcing, not just prose citation in a comment — also
    # sets up Milestone 5's planned "CVE reference links" in generated reports for free, since
    # this is already structured data by the time reporting gets built.
    advisory_url: Optional[str] = None  # the canonical vendor advisory / disclosure "read more" page
    links: Optional[list] = None  # extra report links: [{label, url}, ...] — rendered in the report
    # alongside the auto-generated NVD link (from cve_id), advisory_url, and http(s) `references`.
    # See core/links.py:build_links (added 2026-11-11, per user request for richer report links).
    detection_hints: Optional[dict] = None  # network-detection-format generator input (added
    # 2026-08-21 for the sibling `detection-gen` project's pilot): {transport, app_protocol,
    # mitre_attack_id, narrow: {description, patterns: [{context, bytes|regex}, ...]},
    # broad: {...}} — narrow is THIS check's own literal probe bytes, broad is the underlying
    # vulnerability class in general. Purely descriptive metadata; no icsScanner runtime code
    # reads this field, it exists only to be read by detection-gen's own YAML loader. An absent
    # field (every pre-2026-08-21 check) means "no hints authored yet," not "no detection
    # possible" — detection-gen's own hybrid design falls back to code inspection in that case.
    risk_reason: Optional[list] = None  # list of tags from {"login", "lockout", "device_write",
    # "account_creation"} — added 2026-08-29, refining the single `destructive` boolean into a
    # display/gating TIER without changing what `destructive` itself means (a real, consequential
    # action requiring an opt-in flag before it runs). "login" -> ADVERSE tier (yellow): a plain
    # credential attempt with no confirmed lockout risk and no device write. Any other tag (or
    # `risk_reason` left unset entirely) -> DESTRUCTIVE tier (red): a confirmed lockout mechanism
    # exists on the target ("lockout"), the check itself writes to the device as part of its own
    # verification ("device_write" — a Modbus register write, not just an auth handshake), or
    # successful exploitation creates a new privileged account ("account_creation" — no shipped
    # check uses this yet; that risk class is already routed to scripts/, not checks/, by
    # existing project convention, but the tag exists since a future check could need it).
    # UNSET DEFAULTS TO DESTRUCTIVE TIER, DELIBERATELY — the conservative choice for anything not
    # yet explicitly reclassified, preserving every check's pre-2026-08-29 gating behavior
    # (`include_destructive`) unless a check has been deliberately re-tagged `["login"]`. A check
    # can carry more than one tag (e.g. GE Multilin 850/869 are both `device_write` AND
    # `lockout` — two independently confirmed reasons, not one primary cause). See risk_tier()
    # below and core/scan_engine.py's use of it for the actual gating logic.
    physical_access_reference: Optional[dict] = None  # {summary: str, steps: Optional[list[str]]}
    not_automatable_reference: Optional[dict] = None   # {credential, source, reason, category} — a
    # verified-against-a-primary-source default credential that CANNOT be turned into an automated
    # check (form-login field names unknown, derived/architectural mismatch, proprietary protocol with
    # no executor, wireless/out-of-scope, ...). Surfaced read-only by the "Not Automatable" reference
    # tab + the generated reference doc; never drives a probe. See core/not_automatable_list.py.
    # (added 2026-08-26) — marks a candidate whose credential/unlock mechanism is entered locally
    # (a front-panel keypad, an HMI touchscreen, a hardware reset switch) and therefore can never
    # become a network check by definition, not just "not yet built." Read-only reference data for
    # the web UI's Field Reference tab (an onsite technician's workflow list) — no runtime probing
    # code reads this field, same purely-descriptive contract as detection_hints above. `summary`
    # is a short list-view restatement of the (often much longer, research-history-heavy)
    # `description` field; `steps`, when present, is the sourced procedure verbatim.

    def is_candidate(self) -> bool:
        """True for a metadata-only stub with no probe implemented yet — the shape a CVE-feed
        ingestion adapter (Milestone 2) produces for human review, never an executable check."""
        return self.kind is None

    def risk_tier(self) -> Optional[str]:
        """Returns "adverse", "destructive", or None (this check isn't `destructive` at all, so
        no tier applies). See `risk_reason`'s own docstring above for the full reasoning — the
        short version: `risk_reason == ["login"]` (exactly, nothing else) is "adverse"; any other
        non-empty `risk_reason`, or `risk_reason` left unset, is "destructive" (the conservative
        default for anything not yet explicitly reclassified)."""
        if not self.destructive:
            return None
        if self.risk_reason == ["login"]:
            return "adverse"
        return "destructive"


class Check(ABC):
    """Executable check bound to specific metadata. Native checks subclass this directly;
    declarative checks (kind=declarative) are wrapped by a generic step-executor built in
    Milestone 2 — not implemented yet, this file only establishes the shape it fills."""

    def __init__(self, metadata: CheckMetadata):
        self.metadata = metadata

    @abstractmethod
    def probe(self, target: "Target", rate_limiter=None) -> CheckResult:
        """Run this check's probe against target and return a CheckResult.

        rate_limiter (core.scan_engine.TwoTierRateLimiter, Milestone 1) is provided by the
        engine — a check that sends more than one packet (e.g. a 2-step confirm-recovery
        pattern) must call `rate_limiter.acquire(target.host)` between its own internal sends,
        not just rely on the engine's single per-check pacing call. Optional/None so a check can
        still be unit-tested standalone without a full engine (see
        tests/smoke_test_milestone0.py).

        Must honor metadata.confidence as a ceiling (never report a higher confidence than the
        check itself is rated for) and must not report CheckStatus.CONFIRMED without decoding
        real response evidence — see the "is this a safe check?" gate in
        ../01-METHODOLOGY-AND-CHECKLISTS.md."""

    def fingerprint_matches(self, fp: "FingerprintResult", target: Optional["Target"] = None) -> bool:
        """Evaluate this check's fingerprint_precondition. A check with no precondition set
        never matches anything — a missing precondition is a defect (see the safe-check gate in
        `01-`), not permission to fire unconditionally.

        `protocol_only: true` (Milestone 3, 2026-08-13) is an escape hatch for checks with no
        meaningful hardware-vendor identity to narrow on — software libraries like pymodbus that
        can run on arbitrary hardware, where OUI/vendor matching is structurally inapplicable,
        not just unimplemented. registry.py's load-time validation REJECTS this marker on any
        destructive=True check — the safety rationale for real narrowing is strongest exactly
        where a check can degrade a target, so the escape hatch only exists for checks that
        can't hurt anything by firing on a non-applicable target.

        `protocol_probe: "<name>"` (Milestone 3 continuation, 2026-08-14) is for checks where
        real narrowing exists but isn't a hardware-vendor fact — e.g. the snap7 crash check,
        where the meaningful precondition is "does this genuinely speak S7comm/COTP" (confirmed
        via a live, benign probe), not a vendor lookup. This REQUIRES `target` (the fp argument
        alone, a possibly-stale cached baseline, isn't enough — the probe must run live) and
        looks the name up in core.fingerprint.PROTOCOL_PROBES. Unlike protocol_only, this is
        allowed on destructive checks — it performs real, active narrowing, it just isn't
        vendor/model-shaped.

        Version narrowing (2026-11-11): a precondition may carry a `version` range spec
        ({exact|min|max|fixed} — see core/version_match.py). This method suppresses a match ONLY
        when the observed firmware is KNOWN to be outside the affected range; unknown/unparseable
        firmware stays a match (version-unconfirmed), so a missing firmware never hides a potential
        finding. Vendor/model remain exact-match.
        """
        precond = self.metadata.fingerprint_precondition
        if not precond:
            return False
        if precond.get("protocol_only"):
            return True
        if "protocol_probe" in precond:
            if target is None:
                raise ValueError(
                    f"{self.metadata.check_id}: protocol_probe precondition requires a live "
                    f"target, not just a cached FingerprintResult"
                )
            from core.fingerprint import PROTOCOL_PROBES

            probe_name = precond["protocol_probe"]
            probe_fn = PROTOCOL_PROBES.get(probe_name)
            if probe_fn is None:
                raise ValueError(f"{self.metadata.check_id}: unknown protocol_probe {probe_name!r}")
            # A target with no port specified (a valid, common inventory shape — see
            # templates/target-inventory.example.yaml's minimal entry) must fall through to the
            # probe function's OWN protocol-specific default port (102/502/4840/...), not pass
            # None through explicitly — `probe_fn(host, None)` bypasses that default entirely and
            # crashes deep inside a raw socket.connect() with a real bug, not a fingerprint
            # mismatch: `TypeError: 'NoneType' object cannot be interpreted as an integer`.
            if target.port is not None:
                probe_result = probe_fn(target.host, target.port)
            else:
                probe_result = probe_fn(target.host)
            return probe_result.confidence != "none"
        if "vendor" in precond and precond["vendor"] != fp.vendor:
            return False
        if "product" in precond and precond["product"] != fp.model:
            return False
        from core.version_match import precondition_version_status
        if precondition_version_status(precond, fp.firmware) is False:
            return False  # firmware KNOWN to be outside the affected range -> not applicable
        return True
