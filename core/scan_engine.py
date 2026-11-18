"""Safety/throttling layer — Milestone 1 (00-PROJECT-CHARTER.md). Implements the safety
methodology from ../01-METHODOLOGY-AND-CHECKLISTS.md: two-tier rate limiting (global + per-
target, point 6), per-target aliveness polling with per-target abort scope (point 5), and
safe-mode as the default rather than a flag you remember to pass (point 4).

No check REGISTRY exists yet (Milestone 2, paused) — ScanEngine operates on an explicit list of
Check instances, however they were constructed. No real checks exist yet either (Milestone 3).
This milestone proves the safety MECHANISM works (see tests/smoke_test_milestone1.py); nothing
here should be treated as validated against real protocol content or real hardware yet.
"""

from __future__ import annotations

import concurrent.futures
import socket
import threading
import time
from dataclasses import dataclass, field, replace
from typing import Callable, Optional

from core.check import Check, CheckResult, CheckStatus, Confidence
from core.fingerprint import FingerprintResult, fingerprint_from_oui
from core.target import Target


# Shared verbatim between _aborted_result() and run()'s per-target outcome detection in the
# run_end diagnostic event — one string, not two copies that could drift.
_ALIVENESS_ABORT_ERROR = (
    "skipped — target did not recover after a prior check within the aliveness poll window"
)


class RateLimiter:
    """Thread-safe fixed-interval (or packets-per-second) limiter. One instance = one tier —
    see TwoTierRateLimiter for how the global and per-target tiers combine. Matches the companion fuzzer's
    --delay/--rate-limit convention (default 0.1s delay, PPS overrides delay)."""

    def __init__(self, pps: Optional[float] = None, delay_s: float = 0.1):
        self._interval = (1.0 / pps) if pps else delay_s
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = self._next_allowed - now
            if wait > 0:
                time.sleep(wait)
                now = time.monotonic()
            self._next_allowed = now + self._interval


class TwoTierRateLimiter:
    """Global cap + per-target cap (decided 2026-08-12, 00-PROJECT-CHARTER.md § Scope) — a check
    on one target can never bypass throttling just because other targets in a concurrent run are
    idle, and no single target can exceed the global run-wide cap either. Both tiers must be
    acquired for every send; neither can be skipped by omission (01-METHODOLOGY point 6)."""

    def __init__(
        self,
        global_pps: Optional[float] = None,
        global_delay_s: float = 0.1,
        per_target_pps: Optional[float] = None,
        per_target_delay_s: float = 0.2,
    ):
        self._global = RateLimiter(pps=global_pps, delay_s=global_delay_s)
        self._per_target_pps = per_target_pps
        self._per_target_delay_s = per_target_delay_s
        self._per_target: dict[str, RateLimiter] = {}
        self._per_target_lock = threading.Lock()

    def _target_limiter(self, key: str) -> RateLimiter:
        with self._per_target_lock:
            limiter = self._per_target.get(key)
            if limiter is None:
                limiter = RateLimiter(pps=self._per_target_pps, delay_s=self._per_target_delay_s)
                self._per_target[key] = limiter
            return limiter

    def acquire(self, target_key: str) -> None:
        self._global.acquire()
        self._target_limiter(target_key).acquire()


def default_alive_probe(target: Target, timeout_s: float = 3.0) -> bool:
    """Generic, protocol-agnostic aliveness signal: can a TCP connection to target.host:port be
    opened at all. Weak on purpose — a real per-protocol probe (e.g. a valid Modbus FC03 read,
    matching a companion fuzzing toolkit's _alive()) should be plugged in via
    AlivenessConfig(probe=...) once Milestone 3 checks exist to model one on. Without a port,
    there's nothing to connect to — assume alive rather than block all progress on an
    unanswerable question."""
    if target.port is None:
        return True
    try:
        with socket.create_connection((target.host, target.port), timeout=timeout_s):
            return True
    except OSError:
        return False


@dataclass
class AlivenessConfig:
    """Generalizes the wait/poll loop in
    a companion fuzzing toolkit:_alive()-adjacent code (22s max wait, 2s poll)."""

    poll_interval_s: float = 2.0
    max_wait_s: float = 22.0
    probe: Callable[[Target], bool] = default_alive_probe


def wait_for_recovery(target: Target, config: AlivenessConfig) -> bool:
    """True if target answers the aliveness probe immediately or within max_wait_s of polling.
    False if it never recovers — the caller (ScanEngine.run_target) treats that as grounds to
    abort the REMAINING check queue for this target only (per-target abort scope, required by
    the bounded-concurrency decision — one stuck target must not affect others)."""
    if config.probe(target):
        return True
    waited = 0.0
    while waited < config.max_wait_s:
        time.sleep(config.poll_interval_s)
        waited += config.poll_interval_s
        if config.probe(target):
            return True
    return False


@dataclass
class ScanEngineConfig:
    include_destructive: bool = False  # safe-mode default (01-METHODOLOGY point 4)
    include_adverse: bool = False  # same safe-mode-by-default posture, for the ADVERSE tier
    # (plain login attempts, no confirmed lockout/write risk) — see CheckMetadata.risk_tier();
    # independent from include_destructive, not a superset/subset of it.
    max_concurrent_targets: int = 4  # bounded concurrency across targets (00- § Scope)
    rate_limiter: TwoTierRateLimiter = field(default_factory=TwoTierRateLimiter)
    aliveness: AlivenessConfig = field(default_factory=AlivenessConfig)


class ScanEngine:
    """Orchestrates a list of Check instances against a list of Targets. Bounded concurrency
    across targets (a thread pool capped at max_concurrent_targets); each target's own check
    queue runs sequentially, bracketed by rate limiting and aliveness polling."""

    def __init__(self, checks: list[Check], config: Optional[ScanEngineConfig] = None, logger=None):
        self.checks = checks
        self.config = config or ScanEngineConfig()
        self.logger = logger

    def run(self, targets: list[Target]) -> dict[str, list[CheckResult]]:
        start = time.monotonic()
        if self.logger:
            self.logger.log_event(
                "run_start",
                target_count=len(targets),
                targets=[str(t) for t in targets],
                check_count=len(self.checks),
                protocols=sorted({c.metadata.protocol for c in self.checks}),
                include_destructive=self.config.include_destructive,
                include_adverse=self.config.include_adverse,
                max_concurrent_targets=self.config.max_concurrent_targets,
            )

        results: dict[str, list[CheckResult]] = {}
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.config.max_concurrent_targets
        ) as pool:
            future_to_target = {pool.submit(self.run_target, t): t for t in targets}
            for future in concurrent.futures.as_completed(future_to_target):
                target = future_to_target[future]
                # Two inventory entries can stringify identically (same host/port/protocol_hint);
                # don't let the second silently overwrite the first's results in the returned map.
                key = str(target)
                if key in results:
                    n = 2
                    while f"{key}#{n}" in results:
                        n += 1
                    key = f"{key}#{n}"
                results[key] = future.result()

        if self.logger:
            self.logger.log_event(
                "run_end",
                duration_s=time.monotonic() - start,
                targets=[
                    {
                        "target": key,
                        "outcome": "aborted_early" if any(
                            r.status == CheckStatus.ERROR and r.error == _ALIVENESS_ABORT_ERROR
                            for r in target_results
                        ) else "completed",
                    }
                    for key, target_results in results.items()
                ],
            )
        return results

    def run_target(self, target: Target) -> list[CheckResult]:
        results: list[CheckResult] = []
        checks = list(self.checks)
        # Passive, zero-packet baseline (01-METHODOLOGY point 2: "fingerprint before probe —
        # always"). protocol_probe preconditions do their own live, benign active probing below,
        # cached per (probe name, host:port) so N checks sharing one protocol_probe only pay for
        # it once per target, not once per check.
        baseline_fp = fingerprint_from_oui(target.host)
        protocol_probe_cache: dict[str, bool] = {}
        # Prewarm the protocol-probe cache (one upfront active identity sweep) AND harvest any firmware
        # those identity probes returned for free — feed it to the version gate below. Live firmware
        # wins; _apply_vendor_hint_fallback then fills only a still-unknown firmware from version_hint.
        discovered_fw = self._prewarm_protocol_probe_cache(checks, target, protocol_probe_cache)
        if discovered_fw and baseline_fp.firmware in ("unknown", "", None):
            baseline_fp = replace(baseline_fp, firmware=discovered_fw)
        baseline_fp = self._apply_vendor_hint_fallback(baseline_fp, target)

        for i, check in enumerate(checks):
            # Fingerprint gate runs BEFORE safe-mode gating and BEFORE anything else — the most
            # fundamental question ("does this even apply to this target") is cheapest to answer
            # first, and a protocol_probe evaluation is itself live traffic that must go through
            # the rate limiter like any other send.
            self.config.rate_limiter.acquire(target.host)
            if not self._fingerprint_gate(check, baseline_fp, target, protocol_probe_cache):
                result = self._not_applicable_fingerprint_result(check, target)
                results.append(result)
                self._log(result, check)
                continue

            tier = check.metadata.risk_tier()
            tier_gate_open = (
                tier is None
                or (tier == "destructive" and self.config.include_destructive)
                or (tier == "adverse" and self.config.include_adverse)
            )
            if not tier_gate_open:
                # Safe-mode is the default, not a flag you remember to pass (01-METHODOLOGY
                # point 4) — a destructive-tier check never runs unless include_destructive=True,
                # and (added 2026-08-29) an adverse-tier check never runs unless
                # include_adverse=True — two independent opt-ins, not one superset flag, so an
                # operator can include plain-login checks without also opting into device-write/
                # lockout-risk ones, or vice versa. Still report a fingerprint-only row for
                # visibility without risk, rather than silently omitting it. Only reached once the
                # fingerprint gate above already confirmed the check applies to this target — no
                # point flagging "would need include_destructive/include_adverse" for a check that
                # wouldn't even fire here.
                result = self._fingerprint_only_result(check, target)
                results.append(result)
                self._log(result, check)
                continue

            result = self._run_one(check, target)
            results.append(result)
            self._log(result, check)

            # Post-check recovery gate — brackets every check that actually sent traffic, not
            # just the ones expected to degrade the target (01-METHODOLOGY point 5). Checks
            # skipped above (fingerprint mismatch or safe-mode) never sent anything, so
            # `continue`d past this.
            if not wait_for_recovery(target, self.config.aliveness):
                if self.logger:
                    self.logger.log_event(
                        "aliveness_failure",
                        target=str(target),
                        triggering_check_id=check.metadata.check_id,
                        check_index=i,
                        waited_s=self.config.aliveness.max_wait_s,
                        aborted_check_count=len(checks) - (i + 1),
                    )
                for skipped in checks[i + 1 :]:
                    aborted = self._aborted_result(skipped, target)
                    results.append(aborted)
                    self._log(aborted, skipped)
                break

        return results

    def _apply_vendor_hint_fallback(self, baseline_fp: FingerprintResult, target: Target) -> FingerprintResult:
        """Phase 5 of the CLI last-mile plan (2026-08-16): `Target.vendor_hint`/`product_hint`
        were parsed from the inventory since Milestone 0 but never fed into fingerprint gating —
        every check relied solely on a live OUI probe, even when an operator already knew the
        environment. Design decided with the user: **hint-as-fallback, never hint-as-override**.

        Only substitutes when the live probe found NOTHING (`is_known()` False — no MAC in the
        ARP cache, or a MAC whose OUI isn't in the curated table). If the live probe DID resolve
        a vendor, that's real evidence and wins outright, even if it contradicts the hint — an
        operator's stale/wrong inventory entry can never override what a target actually answered
        with. This is real narrowing either way (a check's own `vendor:`/`product:` precondition
        still has to match exactly), not a bypass — same discipline `protocol_only` already
        enforces for destructive checks, just a different source for the identity claim when live
        evidence doesn't exist. Directly unblocks the several already-shipped checks in this
        program carrying a disclosed "no verifiable OUI in the registry" gap (eWON, Digi,
        Heatmiser, and others — see lab-notes/default-credentials-sweep.md) for any operator
        willing to assert the vendor themselves.

        `version_hint` (2026-11-12) now backfills `firmware` the same hint-as-fallback way, so the
        version gate in `core/check.py:fingerprint_matches` (precondition_version_status) can suppress
        a check whose affected version-range excludes an operator-supplied firmware. Live firmware from
        an identity probe still wins (run_target merges any firmware the prewarm identity sweep found,
        before this fallback only fills a firmware that is still "unknown").

        UPDATE 2026-08-16 (building the GE Multilin 850 check): the vendor and model hints used
        to be substituted as an all-or-nothing pair, gated on `baseline_fp.is_known()` — which
        only checks vendor+confidence, never model. `core/fingerprint.py:fingerprint_from_oui()`
        never sets `model` at all (no live product-level probe exists for any protocol in this
        codebase), so for a check with BOTH `vendor` and `product` in its fingerprint_precondition,
        a live OUI hit (the common, expected case for a vendor this program bothered to verify an
        OUI for) would leave `model` at its "unknown" default forever, AND skip the hint fallback
        entirely (vendor already "known") — the product half of an operator's hint was silently
        discarded even when they explicitly supplied it. Verified this was previously harmless:
        grepped every real check's fingerprint_precondition — zero (of 98) ever set vendor AND
        product together, so no existing check's behavior changes here. But the GE Multilin 850
        check is the first one that NEEDS product-level scoping to be safe (the write mechanism is
        confirmed only for the 850, not the 3 other GE Multilin models this program has checks
        for) — vendor-only matching would let it misfire on unverified sibling models sharing the
        same OUI. Fixed by decoupling: vendor substitution stays exactly as before (only when
        vendor itself is unknown), and model substitution now applies independently, filling in
        `product_hint` whenever `model` is still "unknown" — regardless of whether vendor came
        from live OUI or from the hint above. Never overrides an already-known model (there's
        nothing that sets one today, but this keeps the same "live evidence always wins" principle
        this whole mechanism is built on, for whenever one exists).
        """
        fp = baseline_fp
        if not fp.is_known() and target.vendor_hint:
            fp = replace(fp, vendor=target.vendor_hint, confidence="low", method="operator_hint")
        if fp.model == "unknown" and target.product_hint:
            fp = replace(
                fp,
                model=target.product_hint,
                confidence=fp.confidence if fp.confidence != "none" else "low",
                method=fp.method or "operator_hint",
            )
        if fp.firmware == "unknown" and target.version_hint:
            # Backfill firmware for the version gate (precondition_version_status); orthogonal to the
            # vendor/model confidence above, so it doesn't change those. Live probe firmware wins —
            # run_target merges that before this fallback runs.
            fp = replace(fp, firmware=target.version_hint)
        return fp

    def _prewarm_protocol_probe_cache(self, checks: list[Check], target: Target, cache: dict) -> Optional[str]:
        """Check curation via identify_protocol() (2026-08-18, TODO from the -5h/identify_protocol
        memory entry). Runs every DISTINCT protocol_probe this run's own check list actually
        references — never more than that, so this doesn't probe for protocols nothing in the
        current selection cares about — as ONE upfront batch via identify_protocol(), instead of
        each one being triggered lazily/interleaved whenever _fingerprint_gate() first reaches a
        check that needs it.

        Deliberately NOT a behavior-changing gate: it only pre-populates the SAME cache
        `_fingerprint_gate()` already reads (same cache_key format, same underlying PROTOCOL_PROBES
        functions, same `confidence != "none"` match rule) — every check's own pass/fail outcome
        matches what the lazy per-check path would have produced; this just changes WHEN the
        network probes happen, not what they decide. `identify_protocol(..., timeout=None)` is
        load-bearing for that equivalence: it makes each probe use its own default timeout, the
        same value the lazy `probe_fn(host, port)` call in core/check.py:fingerprint_matches()
        uses — passing a uniform `timeout` here instead would let a borderline-slow device match
        on one path but not the other. vendor/product (OUI)-only checks never touch this cache at
        all — unaffected.

        Real, additive value: (1) a clean upfront batch instead of probes interleaved between
        individual check results, and (2) a genuine new per-target reporting artifact — logs
        which protocols were actually found, independent of whether a check exists for them yet.
        """
        probe_names = {
            check.metadata.fingerprint_precondition.get("protocol_probe")
            for check in checks
            if check.metadata.fingerprint_precondition and "protocol_probe" in check.metadata.fingerprint_precondition
        }
        if not probe_names:
            return

        from core.fingerprint import PROTOCOL_PROBES, identify_protocol

        probes_subset = {name: PROTOCOL_PROBES[name] for name in probe_names if name in PROTOCOL_PROBES}
        if not probes_subset:
            return

        matches = identify_protocol(
            target.host,
            port=target.port,
            timeout=None,  # per-probe defaults — keep this path's verdict aligned with the lazy
            # per-check path in core/check.py:fingerprint_matches() (see this method's docstring)
            probes=probes_subset,
            rate_limiter=self.config.rate_limiter,
        )
        matched_names = set()
        best_firmware = None
        for name, fp in matches:
            matched_names.add(name)
            if best_firmware is None and getattr(fp, "firmware", "unknown") not in ("unknown", "", None):
                best_firmware = fp.firmware  # free firmware for the version gate; first match wins
        for name in probes_subset:
            cache[f"{name}:{target.host}:{target.port}"] = name in matched_names

        if self.logger:
            self.logger.log_event(
                "protocol_identification",
                target=str(target),
                protocols_found=sorted(matched_names),
                protocols_checked=sorted(probes_subset),
            )
        return best_firmware

    def _fingerprint_gate(self, check: Check, baseline_fp, target: Target, cache: dict) -> bool:
        precond = check.metadata.fingerprint_precondition or {}
        probe_name = precond.get("protocol_probe")
        if probe_name:
            cache_key = f"{probe_name}:{target.host}:{target.port}"
            if cache_key not in cache:
                cache[cache_key] = check.fingerprint_matches(baseline_fp, target=target)
            return cache[cache_key]
        return check.fingerprint_matches(baseline_fp, target=target)

    def _run_one(self, check: Check, target: Target) -> CheckResult:
        self.config.rate_limiter.acquire(target.host)
        start = time.monotonic()
        try:
            result = check.probe(target, rate_limiter=self.config.rate_limiter)
        except Exception as e:  # a check's own bug must not take down the whole run
            result = CheckResult(
                check_id=check.metadata.check_id,
                protocol=check.metadata.protocol,
                target=str(target),
                status=CheckStatus.ERROR,
                confidence=check.metadata.confidence,
                cve_id=check.metadata.cve_id,
                can_id=check.metadata.can_id,
                error=f"{type(e).__name__}: {e}",
            )
        if result.duration_ms is None:
            result.duration_ms = (time.monotonic() - start) * 1000
        return result

    def _not_applicable_fingerprint_result(self, check: Check, target: Target) -> CheckResult:
        return CheckResult(
            check_id=check.metadata.check_id,
            protocol=check.metadata.protocol,
            target=str(target),
            status=CheckStatus.NOT_APPLICABLE,
            confidence=check.metadata.confidence,
            cve_id=check.metadata.cve_id,
            can_id=check.metadata.can_id,
            description="fingerprint precondition did not match — check does not apply to this target",
        )

    def _fingerprint_only_result(self, check: Check, target: Target) -> CheckResult:
        tier = check.metadata.risk_tier()
        flag = "include_adverse" if tier == "adverse" else "include_destructive"
        return CheckResult(
            check_id=check.metadata.check_id,
            protocol=check.metadata.protocol,
            target=str(target),
            status=CheckStatus.FINGERPRINT_ONLY,
            confidence=Confidence.LOW,
            cve_id=check.metadata.cve_id,
            can_id=check.metadata.can_id,
            severity=check.metadata.severity,
            description=(
                f"{tier} check — not actively probed in safe mode "
                f"({flag}=True to enable)"
            ),
        )

    def _aborted_result(self, check: Check, target: Target) -> CheckResult:
        return CheckResult(
            check_id=check.metadata.check_id,
            protocol=check.metadata.protocol,
            target=str(target),
            status=CheckStatus.ERROR,
            confidence=check.metadata.confidence,
            cve_id=check.metadata.cve_id,
            can_id=check.metadata.can_id,
            error=_ALIVENESS_ABORT_ERROR,
        )

    def _log(self, result: CheckResult, check: Check) -> None:
        if self.logger:
            self.logger.log(
                result,
                disclosure_status=check.metadata.disclosure_status,
                references=check.metadata.references,
                destructive=check.metadata.destructive,
            )
