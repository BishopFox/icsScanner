"""icsScanner web server — Phase 4 of the CLI "last mile" plan
(~/.claude/plans/this-is-a-feasibility-foamy-hoare.md). A local web front-end over the exact same
pipeline icsscanner.py (the CLI driver) already wires — no duplicated engine/registry logic here,
this module only assembles a ScanPolicy + targets from an HTTP request and calls the same
CheckRegistry -> icsscanner.select_checks -> load_target_inventory -> ScanEngine -> ScanLogger
sequence the CLI uses.

Consent-gate equivalent (the one thing that can't translate directly from the CLI's interactive
`input()` prompt): a two-step POST. Submitting a scan with `include_destructive` true and
`confirmed` false returns the same target/check listing confirm_destructive_run() would print,
WITHOUT running anything. Only a second POST with `confirmed: true` actually starts a job — no
live destructive traffic fires on the first request under any circumstance.

Local-only by default (run_server binds 127.0.0.1 unless told otherwise) — this is a control
surface for a tool that fires real credentialed/destructive network traffic, same dual-use
discipline as the CLI's --yes gate.

Stdlib only (http.server), consistent with this project's general dependency-minimalism —
decided over a framework since the actual UI need (a form + polling) doesn't outgrow it.
"""

from __future__ import annotations

import json
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

import yaml

import icsscanner
from core.credential_list import build_credential_entries
from core.not_automatable_list import build_not_automatable_entries
from core.discovery import (PASSIVE_LISTENERS, _DEFAULT_PROBE_SCAN, arp_scan, micom_courier_scan,
                            mqtt_active_scan, passive_listen, protocol_probe_scan, codesys_v3_broadcast_scan,
                            factorytalk_rna_scan)
from core.registry import CheckRegistry
from core.reporter import ScanReporter
from core.scan_engine import ScanEngine, ScanEngineConfig, TwoTierRateLimiter
from core.scan_policy import ScanPolicy
from core.target import (
    CredentialResolutionError,
    InsecureKeyringBackendError,
    load_target_inventory,
)

CHECKS_DIR = Path(__file__).resolve().parent.parent / "checks"
STATIC_DIR = Path(__file__).resolve().parent / "static"

_STATIC_CONTENT_TYPES = {
    ".woff2": "font/woff2",
    ".woff": "font/woff",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
}


class Job:
    def __init__(self, job_id: str):
        self.id = job_id
        self.status = "pending"  # pending -> running -> done | error
        self.created_at = time.time()
        self.log_path: Optional[str] = None
        self.summary: Optional[dict] = None
        self.error: Optional[str] = None


class JobStore:
    def __init__(self):
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def create(self) -> Job:
        job = Job(uuid.uuid4().hex[:12])
        with self._lock:
            self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)


JOBS = JobStore()


class DiscoveryJob:
    """Separate from Job/JobStore — discovery results are a plain list of DiscoveredDevice
    dicts, not a JSONL log to re-read, so there's no reporter aggregation step here."""

    def __init__(self, job_id: str):
        self.id = job_id
        self.status = "pending"  # pending -> running -> done | error
        self.created_at = time.time()
        self.devices: list = []
        self.findings: list = []
        self.detections: Optional[dict] = None  # summarized Observed-Activity (native --detections)
        self.log_path: Optional[str] = None      # JSONL run log, for downloadable HTML/CSV reports
        self.last_update: float = time.time()    # last time this job made progress (for hung-vs-long-running)
        self.error: Optional[str] = None


class DiscoveryJobStore:
    def __init__(self):
        self._jobs: dict[str, DiscoveryJob] = {}
        self._lock = threading.Lock()

    def create(self) -> DiscoveryJob:
        job = DiscoveryJob(uuid.uuid4().hex[:12])
        with self._lock:
            self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> Optional[DiscoveryJob]:
        with self._lock:
            return self._jobs.get(job_id)


DISCOVERY_JOBS = DiscoveryJobStore()


def _run_discovery_job(job: DiscoveryJob, body: dict) -> None:
    job.status = "running"
    try:
        mode = body.get("mode")
        if mode == "active":
            method = body.get("method") or "arp"
            if method == "micom_courier":
                devices = micom_courier_scan(
                    cidr=body["cidr"],
                    timeout=float(body.get("timeout", 2.0)),
                    rate_limiter=TwoTierRateLimiter(),
                    force=bool(body.get("force", False)),
                )
            elif method == "mqtt":
                devices = mqtt_active_scan(
                    cidr=body["cidr"],
                    port=int(body.get("port", 1883)),
                    timeout=float(body.get("timeout", 2.0)),
                    rate_limiter=TwoTierRateLimiter(),
                    force=bool(body.get("force", False)),
                    auto_sparkplug=bool(body.get("auto_sparkplug", True)),
                )
            elif method == "protocol_probe":
                devices = protocol_probe_scan(
                    cidr=body["cidr"],
                    probes=body.get("probes") or None,
                    timeout=float(body.get("timeout", 3.0)),
                    rate_limiter=TwoTierRateLimiter(),
                    force=bool(body.get("force", False)),
                )
            elif method == "codesys":
                devices = codesys_v3_broadcast_scan(
                    cidr=body["cidr"],
                    timeout=float(body.get("timeout", 3.0)),
                    rate_limiter=TwoTierRateLimiter(),
                    force=bool(body.get("force", False)),
                )
            elif method == "factorytalk_rna":
                devices = factorytalk_rna_scan(
                    cidr=body["cidr"],
                    port=int(body.get("port", 4241)),
                    timeout=float(body.get("timeout", 3.0)),
                    rate_limiter=TwoTierRateLimiter(),
                    force=bool(body.get("force", False)),
                )
            else:
                devices = arp_scan(
                    cidr=body["cidr"],
                    iface=body.get("iface") or None,
                    timeout=float(body.get("timeout", 2.0)),
                    rate_limiter=TwoTierRateLimiter(),
                    force=bool(body.get("force", False)),
                )
        elif mode == "passive":
            broker = body.get("sparkplug_broker") or None
            devices = passive_listen(
                duration=float(body.get("duration", 30.0)),
                iface=body.get("iface") or None,
                protocols=body.get("protocols") or None,
                sparkplug_broker=(broker["host"], int(broker["port"])) if broker else None,
            )
        elif mode == "sniff":
            # Passive SPAN/TAP or pcap capture, or Zeek/ICSNPP log ingest — transmits nothing.
            from core.passive import run_passive, correlate_cves, ingest_zeek_logs
            source = body.get("source")
            native_dets: list = []
            matchers = None
            if body.get("detections") and source != "zeek_logs":
                from core.detect_match import build_matchers
                matchers = build_matchers("checks")  # native in-process detection, still zero-transmit

            def _progress(inv, dets):
                # Stream partial results so a long/live capture updates the UI as it goes. Reassigning
                # the lists/dict is atomic enough for the poll reader (GIL); no lock needed.
                job.devices = [d.as_dict() for d in inv]
                job.last_update = time.time()  # progress heartbeat -> UI distinguishes long-running vs hung
                if dets:
                    from core.detections import summarize_detections
                    job.detections = summarize_detections([d.as_dict() for d in dets], job.devices)

            if source == "pcap":
                devices = run_passive(pcap=body["pcap"], matchers=matchers,
                                      detections_out=native_dets, on_progress=_progress)
            elif source == "zeek_logs":
                devices = ingest_zeek_logs(body["zeek_logs"])
            else:  # live SPAN/TAP interface
                devices = run_passive(iface=body.get("iface") or None,
                                      window=float(body.get("window", 60.0)),
                                      matchers=matchers, detections_out=native_dets,
                                      on_progress=_progress)
            if body.get("cve"):
                job.findings = correlate_cves(devices)  # annotates each device's matched_cves too
            if native_dets:
                from core.detections import summarize_detections
                job.detections = summarize_detections(
                    [d.as_dict() for d in native_dets], [d.as_dict() for d in devices])
        else:
            raise ValueError(f"unknown discovery mode {mode!r} — expected 'active', 'passive', or 'sniff'")
        job.devices = [d.as_dict() for d in devices]
        # Write a run log so the discovery report (HTML/CSV, including the Observed-Activity section)
        # is downloadable from the web UI, mirroring the scanner view. Best-effort: never fail over it.
        try:
            from core.logger import ScanLogger
            nd = locals().get("native_dets") or []
            with ScanLogger("./output", filename_prefix="icsscanner-discovery") as logger:
                for d in devices:
                    logger.log_event("device_discovered", **d.as_dict())
                if job.findings:
                    from core.passive import findings_to_results
                    for res in findings_to_results(job.findings, devices):
                        logger.log(res)
                for det in nd:
                    logger.log_event("detection", **{k: v for k, v in det.as_dict().items() if k != "type"})
                logger.log_event("discovery_run_summary", mode=mode, total=len(devices))
            job.log_path = str(logger.log_path)
        except Exception:
            pass
        job.status = "done"
    except Exception as e:  # a discovery bug must not take the server down
        job.error = f"{type(e).__name__}: {e}"
        job.status = "error"


def _policy_from_dict(d: dict) -> ScanPolicy:
    """Same field set/defaults as ScanPolicy itself — a thin adapter from a JSON request body,
    not a second config schema. inventory is set separately once the posted YAML is written to
    a temp file (see _run_scan_request)."""
    if d is None:  # `"policy": null` in the body — treat as "no policy", not a 500
        d = {}
    if not isinstance(d, dict):
        raise TypeError(f"'policy' must be a JSON object, got {type(d).__name__}")
    return ScanPolicy(
        inventory="",
        protocols=d.get("protocols") or None,
        check_ids=d.get("check_ids") or None,
        include_destructive=bool(d.get("include_destructive", False)),
        include_adverse=bool(d.get("include_adverse", False)),
        max_concurrent_targets=int(d.get("max_concurrent_targets", 4)),
        output_dir=d.get("output_dir", "./output"),
    )


def _run_job(job: Job, checks: list, targets: list, policy: ScanPolicy) -> None:
    from core.logger import ScanLogger  # local import: keep module import order matching icsscanner.py

    job.status = "running"
    try:
        rate_limiter = TwoTierRateLimiter(
            global_pps=policy.global_pps,
            global_delay_s=policy.global_delay_s,
            per_target_pps=policy.per_target_pps,
            per_target_delay_s=policy.per_target_delay_s,
        )
        config = ScanEngineConfig(
            include_destructive=policy.include_destructive,
            include_adverse=policy.include_adverse,
            max_concurrent_targets=policy.max_concurrent_targets,
            rate_limiter=rate_limiter,
        )
        with ScanLogger(policy.output_dir) as logger:
            job.log_path = str(logger.log_path)
            engine = ScanEngine(checks, config=config, logger=logger)
            try:
                engine.run(targets)
            except (CredentialResolutionError, InsecureKeyringBackendError) as e:
                # Reachability note: as of 2026-08-16, no check calls
                # Target.resolve_credential() yet — this is defensive-in-depth. Any credential
                # failure inside a check's own probe() already becomes a normal per-check ERROR
                # result via ScanEngine._run_one()'s broad handler; this only fires for a
                # failure outside that path, which nothing triggers today. Logged anyway so the
                # JSONL stays self-contained evidence even in that edge case.
                logger.log_event("credential_error", error=f"{type(e).__name__}: {e}")
                raise
        # Read the just-written, now-flushed-and-closed JSONL back rather than aggregating the
        # in-memory results dict — single aggregation implementation shared with the CLI text
        # summary and the to_html()/to_csv() renderers (core/reporter.py:ScanReporter), not a
        # second parallel one. Costs low-single-digit ms for a job this size, irrelevant next to
        # the scan itself.
        # build_summary()'s "log_path" value is a Path object (needed internally by
        # to_html()/to_csv()'s own log_path.with_suffix() calls) — not JSON-serializable, and
        # redundant with job.log_path (already a str) anyway. Drop it before this dict gets
        # sent straight to a client as JSON.
        summary = ScanReporter(policy.output_dir).build_summary(log_path=logger.log_path)
        if summary is not None:
            summary.pop("log_path", None)
        job.summary = summary
        job.status = "done"
    except (CredentialResolutionError, InsecureKeyringBackendError) as e:
        job.error = str(e)
        job.status = "error"
    except Exception as e:  # a scan bug must not take the server down
        job.error = f"{type(e).__name__}: {e}"
        job.status = "error"


class Handler(BaseHTTPRequestHandler):
    server_version = "icsscanner-web/0.1"

    def log_message(self, fmt, *args):  # quieter default stdlib access log
        print(f"[web] {self.address_string()} {fmt % args}")

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/":
            from web.page import INDEX_HTML

            body = INDEX_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path.startswith("/static/"):
            # Self-hosted static assets (currently just the Bishop Fox brand fonts) -- no
            # third-party CDN dependency for this tool's UI. Path-traversal-safe: resolve and
            # require the result stay inside STATIC_DIR before ever opening it.
            requested = (STATIC_DIR / path[len("/static/"):]).resolve()
            if STATIC_DIR not in requested.parents or not requested.is_file():
                self.send_response(404)
                self.end_headers()
                return
            content_type = _STATIC_CONTENT_TYPES.get(requested.suffix.lower(), "application/octet-stream")
            body = requested.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/api/health":
            # Lightweight liveness probe for the web UI's HEALTHY lamp heartbeat — no registry
            # load, no side effects, just confirms this server process is up and answering.
            self._send_json(200, {"status": "ok"})
            return

        if path == "/api/checks":
            registry = CheckRegistry(CHECKS_DIR).load()
            payload = [
                {
                    "check_id": c.metadata.check_id,
                    "protocol": c.metadata.protocol,
                    "destructive": c.metadata.destructive,
                    "risk_tier": c.metadata.risk_tier(),
                    "risk_reason": c.metadata.risk_reason,
                    "description": c.metadata.description,
                    "cve_id": c.metadata.cve_id,
                    "confidence": c.metadata.confidence.value,
                    "vendor": (c.metadata.fingerprint_precondition or {}).get("vendor", ""),
                }
                for c in registry.checks()
            ]
            self._send_json(200, payload)
            return

        if path == "/api/physical-access-checks":
            # Read-only reference data for the Field Reference tab — candidates whose credential/
            # unlock mechanism is entered locally (front-panel keypad, HMI touchscreen, hardware
            # reset switch) and can therefore never become a network check. No probing capability
            # is exposed here; this endpoint only ever reads static YAML.
            registry = CheckRegistry(CHECKS_DIR).load()
            payload = [
                {
                    "check_id": c.check_id,
                    "vendor": (c.fingerprint_precondition or {}).get("vendor", "Unknown"),
                    "summary": c.physical_access_reference.get("summary", ""),
                    "steps": c.physical_access_reference.get("steps", []),
                    "description": c.description,
                    "references": c.references or [],
                }
                for c in registry.candidates()
                if getattr(c, "physical_access_reference", None)
            ]
            self._send_json(200, payload)
            return

        if path == "/api/credential-list":
            # Read-only reference data for the Credentials tab — every known default credential
            # across the whole registry, re-presented from data already public in checks/**/*.yaml.
            # No probing capability is exposed here; this endpoint only ever reads static YAML.
            registry = CheckRegistry(CHECKS_DIR).load()
            self._send_json(200, build_credential_entries(registry.checks()))
            return

        if path == "/api/not-automatable":
            # Read-only reference data for the Not Automatable tab — verified-against-a-primary-source
            # default credentials that cannot become an automated check (form-login field names
            # unknown, derived/architectural mismatch, proprietary protocol with no executor, wireless/
            # out of scope). No probing capability; only reads static candidate YAML.
            registry = CheckRegistry(CHECKS_DIR).load()
            self._send_json(200, build_not_automatable_entries(registry))
            return

        if path == "/api/discover-listeners":
            self._send_json(200, {"protocols": sorted(PASSIVE_LISTENERS.keys())})
            return

        if path == "/api/discover-probes":
            # Protocol-identity probes sweepable by the 'protocol_probe' active-discovery method.
            from core.fingerprint import probe_note
            names = [p[:-9] if p.endswith("_identity") else p for p in _DEFAULT_PROBE_SCAN]
            notes = {n: probe_note(n) for n in names if probe_note(n)}
            self._send_json(200, {"probes": names, "notes": notes})
            return

        if path.startswith("/api/discover-jobs/") and (path.endswith("/report.html") or path.endswith("/report.csv")):
            is_html = path.endswith("/report.html")
            suffix = "/report.html" if is_html else "/report.csv"
            job_id = path[len("/api/discover-jobs/"): -len(suffix)]
            job = DISCOVERY_JOBS.get(job_id)
            if job is None or not job.log_path or not Path(job.log_path).exists():
                self._send_json(404, {"error": "no downloadable report for this discovery job"})
                return
            reporter = ScanReporter(str(Path(job.log_path).parent))
            try:
                out_path = (reporter.to_discovery_html if is_html
                            else reporter.to_discovery_csv)(log_path=Path(job.log_path))
            except ValueError as e:
                self._send_json(404, {"error": str(e)})
                return
            out_body = out_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8" if is_html else "text/csv")
            self.send_header("Content-Disposition", f'attachment; filename="{out_path.name}"')
            self.send_header("Content-Length", str(len(out_body)))
            self.end_headers()
            self.wfile.write(out_body)
            return

        if path.startswith("/api/discover-jobs/"):
            job_id = path[len("/api/discover-jobs/"):]
            job = DISCOVERY_JOBS.get(job_id)
            if job is None:
                self._send_json(404, {"error": f"no such discovery job {job_id!r}"})
                return
            self._send_json(200, {
                "id": job.id,
                "status": job.status,
                "devices": job.devices,
                "findings": job.findings,
                "detections": job.detections,
                "idle_s": round(time.time() - job.last_update, 1),  # seconds since last progress
                "error": job.error,
            })
            return

        if path.startswith("/api/jobs/"):
            rest = path[len("/api/jobs/"):]

            if rest.endswith("/log"):
                job = JOBS.get(rest[: -len("/log")])
                if job is None:
                    self._send_json(404, {"error": "no such job"})
                    return
                if not job.log_path:
                    self._send_json(404, {"error": "no log yet for this job"})
                    return
                log_file = Path(job.log_path)
                if not log_file.exists():
                    self._send_json(404, {"error": "log file no longer exists on disk"})
                    return
                body = log_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson")
                self.send_header("Content-Disposition", f'attachment; filename="{log_file.name}"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if rest.endswith("/report.html") or rest.endswith("/report.csv"):
                is_html = rest.endswith("/report.html")
                suffix = "/report.html" if is_html else "/report.csv"
                job = JOBS.get(rest[: -len(suffix)])
                if job is None:
                    self._send_json(404, {"error": "no such job"})
                    return
                if not job.log_path or not Path(job.log_path).exists():
                    self._send_json(404, {"error": "no log yet for this job (or it's gone from disk)"})
                    return
                # include_evidence is a render-time choice, not a scan-time one — evidence is
                # already captured unconditionally at log time (core/logger.py:ScanLogger.log()
                # writes evidence_hex regardless), so one job can produce both an evidence-free
                # report for casual sharing and a full one on request, no re-scan needed.
                include_evidence = query.get("include_evidence", ["0"])[0].lower() in ("1", "true")
                reporter = ScanReporter(str(Path(job.log_path).parent))
                try:
                    if is_html:
                        out_path = reporter.to_html(log_path=Path(job.log_path), include_evidence=include_evidence)
                    else:
                        out_path = reporter.to_csv(log_path=Path(job.log_path), include_evidence=include_evidence)
                except ValueError as e:
                    self._send_json(404, {"error": str(e)})
                    return
                # Regenerated on each request (overwrites the same derived file) — the log
                # itself is the durable artifact, the report is cheap to rebuild, not cached.
                out_body = out_path.read_bytes()
                self.send_response(200)
                self.send_header(
                    "Content-Type",
                    "text/html; charset=utf-8" if is_html else "text/csv",
                )
                self.send_header("Content-Disposition", f'attachment; filename="{out_path.name}"')
                self.send_header("Content-Length", str(len(out_body)))
                self.end_headers()
                self.wfile.write(out_body)
                return

            job = JOBS.get(rest)
            if job is None:
                self._send_json(404, {"error": f"no such job {rest!r}"})
                return
            self._send_json(200, {
                "id": job.id,
                "status": job.status,
                "log_path": job.log_path,
                "summary": job.summary,
                "error": job.error,
            })
            return

        self._send_json(404, {"error": "not found"})

    def _handle_pcap_upload(self):
        """Accept a raw-binary pcap upload (so the web UI doesn't need a server-side path), save it to
        an isolated temp dir, and return the path for a subsequent sniff job. Localhost-only by default;
        size-capped; filename sanitized to a basename."""
        import os
        import tempfile
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            self._send_json(400, {"error": "invalid Content-Length"})
            return
        max_bytes = 500 * 1024 * 1024
        if length <= 0 or length > max_bytes:
            self._send_json(400, {"error": f"pcap size must be 1..{max_bytes} bytes"})
            return
        data = self.rfile.read(length)
        raw_name = self.headers.get("X-Filename", "upload.pcap")
        name = os.path.basename(raw_name).replace("\\", "_").replace("/", "_") or "upload.pcap"
        if not name.lower().endswith((".pcap", ".pcapng", ".cap")):
            name += ".pcap"
        updir = tempfile.mkdtemp(prefix="icsscanner-upload-")
        path = os.path.join(updir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        self._send_json(200, {"path": path})

    def do_POST(self):
        if self.path == "/api/upload-pcap":
            self._handle_pcap_upload()
            return
        if self.path not in ("/api/scan", "/api/discover"):
            self._send_json(404, {"error": "not found"})
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            self._send_json(400, {"error": "invalid Content-Length header"})
            return
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send_json(400, {"error": "malformed JSON body"})
            return
        if not isinstance(body, dict):
            self._send_json(400, {"error": "request body must be a JSON object"})
            return

        if self.path == "/api/discover":
            mode = body.get("mode")
            if mode == "active" and not body.get("cidr"):
                self._send_json(400, {"error": "active discovery requires 'cidr'"})
                return
            if mode not in ("active", "passive", "sniff"):
                self._send_json(400, {"error": "'mode' must be 'active', 'passive', or 'sniff'"})
                return
            job = DISCOVERY_JOBS.create()
            thread = threading.Thread(target=_run_discovery_job, args=(job, body), daemon=True)
            thread.start()
            self._send_json(202, {"job_id": job.id})
            return

        inventory_yaml = body.get("inventory_yaml", "")
        confirmed = bool(body.get("confirmed", False))

        try:
            policy = _policy_from_dict(body.get("policy", {}))
        except (ValueError, TypeError) as e:
            self._send_json(400, {"error": f"bad policy: {e}"})
            return

        with tempfile.NamedTemporaryFile(
            "w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(inventory_yaml)
            tmp_path = tmp.name
        try:
            targets = load_target_inventory(tmp_path)
        except (ValueError, KeyError, yaml.YAMLError) as e:
            self._send_json(400, {"error": f"failed to parse target inventory: {e}"})
            return
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        registry = CheckRegistry(CHECKS_DIR).load()
        checks = icsscanner.select_checks(registry, policy)

        if not targets:
            self._send_json(400, {"error": "no targets in the posted inventory"})
            return
        if not checks:
            self._send_json(400, {"error": "no checks matched the protocol/check_id filters"})
            return

        destructive = [c for c in checks if c.metadata.risk_tier() == "destructive"] if policy.include_destructive else []
        adverse = [c for c in checks if c.metadata.risk_tier() == "adverse"] if policy.include_adverse else []
        if (destructive or adverse) and not confirmed:
            self._send_json(200, {
                "requires_confirmation": True,
                "targets": [str(t) for t in targets],
                "destructive_checks": [c.metadata.check_id for c in destructive],
                "adverse_checks": [c.metadata.check_id for c in adverse],
            })
            return

        job = JOBS.create()
        thread = threading.Thread(target=_run_job, args=(job, checks, targets, policy), daemon=True)
        thread.start()
        self._send_json(202, {"job_id": job.id})


def run_server(host: str = "127.0.0.1", port: int = 8807) -> None:
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"[web] icsScanner web UI listening on http://{host}:{port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[web] shutting down.")
        server.shutdown()
