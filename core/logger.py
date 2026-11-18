"""Structured JSONL logger for check results. Adapted from icsFuzzer's core/logger.py
(FuzzLogger) — same one-record-per-event shape; fields updated for CheckResult instead of
FuzzResult (status/confidence replace anomaly/crash_indicator, cve_id/can_id/disclosure_status
added for audit trail — see check.py)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.check import CheckResult, CheckStatus, DisclosureStatus


class ScanLogger:
    """Writes one JSONL record per check result. Output file: icsscanner-<ts>.jsonl, matching
    the <product-lowercase>-*.jsonl naming convention (03-STYLE-AND-DECISIONS.md)."""

    def __init__(self, output_dir: str, filename_prefix: str = "icsscanner"):
        """`filename_prefix` lets a caller distinguish log families sharing one output directory
        — e.g. core/discovery.py's CLI path uses "icsscanner-discovery" so a discovery run's
        JSONL/derived CSV/HTML/SVG files never collide in name with a scan run's, even if both
        land in the same second. Default unchanged for every existing caller."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.log_path = self.output_dir / f"{filename_prefix}-{ts}.jsonl"
        self._filename_prefix = filename_prefix
        self._file = open(self.log_path, "w", encoding="utf-8")
        self._total = 0
        self._confirmed = 0
        self._errors = 0
        print(f"[log] Writing to {self.log_path}")

    def log(
        self,
        result: CheckResult,
        disclosure_status: Optional[DisclosureStatus] = None,
        references: Optional[list] = None,
        destructive: bool = False,
    ) -> None:
        record = {
            "check_id": result.check_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "protocol": result.protocol,
            "target": result.target,
            "cve_id": result.cve_id,
            "can_id": result.can_id,
            "status": result.status.value,
            "confidence": result.confidence.value,
            "severity": result.severity,
            "description": result.description,
            "evidence_hex": result.evidence.hex() if result.evidence else None,
            "evidence_decoded": result.evidence_decoded,
            "duration_ms": result.duration_ms,
            "error": result.error,
            "disclosure_status": disclosure_status.value if disclosure_status else None,
            "references": references,
            "destructive": destructive,
        }
        self._file.write(json.dumps(record) + "\n")
        self._file.flush()
        self._total += 1
        if result.status == CheckStatus.CONFIRMED:
            self._confirmed += 1
            ref = result.cve_id or result.can_id or "n/a"
            print(f"  [!] CONFIRMED: {result.check_id} ({ref}) — {result.description}")
        if result.status == CheckStatus.ERROR:
            self._errors += 1

    def log_info(self, message: str) -> None:
        """Log a freeform informational message as a sentinel record."""
        record = {
            "type": "info",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": message,
        }
        self._file.write(json.dumps(record) + "\n")
        self._file.flush()

    def log_event(self, event_type: str, **fields) -> None:
        """Structured sentinel record for scan-level diagnostics (run_start/run_end/
        aliveness_failure/credential_error) — same `type`+`timestamp`+no-`check_id` shape as
        log_info() (so core/reporter.py's existing `r.get("check_id") and not r.get("type")`
        check-record filter already excludes these correctly), but carries real fields instead
        of forcing everything into one free-text message. Added 2026-08-16 so a JSONL log is
        self-contained evidence of what a run covered and what went wrong, not just a list of
        per-check outcomes — see lab-notes/default-credentials-sweep.md and the "what caused an
        issue with an endpoint" use case that prompted this."""
        record = {
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **fields,
        }
        self._file.write(json.dumps(record) + "\n")
        self._file.flush()

    def stats(self) -> dict:
        return {
            "total_checks": self._total,
            "confirmed": self._confirmed,
            "errors": self._errors,
        }

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self._file.closed:
            self.close()
        return False

    def close(self) -> None:
        self._file.close()
        # "checks/confirmed/errors" counters are meaningless for a non-scan use of this logger
        # (e.g. core/discovery.py's CLI path only ever calls log_event(), never log()) — print a
        # generic completion line instead of a check-specific one that would misleadingly always
        # read "0 checks, 0 confirmed, 0 errors" for those runs.
        if self._filename_prefix == "icsscanner":
            stats = self.stats()
            print(
                f"[log] Scan complete — {stats['total_checks']} checks, "
                f"{stats['confirmed']} confirmed, {stats['errors']} errors"
            )
        else:
            print(f"[log] {self._filename_prefix} run complete.")
        print(f"[log] Log: {self.log_path}")
