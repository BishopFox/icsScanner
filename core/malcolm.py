"""Interoperate with an EXISTING Malcolm deployment via its `mapi` REST API.

This does NOT build, bundle, or stand up Malcolm — it targets an operator's already-running Malcolm, and
reinforces icsScanner's role as the CVE-correlation + detection layer on top of the Malcolm/Hedgehog/
ICSNPP passive stack. Two directions, both confirmed against the Malcolm `mapi` docs:

  - READ (B): `POST /mapi/agg/<fields>` bucket-aggregates the live OpenSearch index. Filtering on
    `event.provider:zeek` and nesting an IP field under the Zeek dataset gives the passive asset
    inventory, so icsScanner's CVE correlation can run against Malcolm's live data with no file hand-off.
  - WRITE (C): `POST /mapi/event` is Malcolm's documented alert webhook — it indexes a document as a
    session record viewable in Malcolm's own dashboards, with `alert.body` for ECS-style custom fields
    (deep-merged, leaf collisions preserved under `conflicts`). This is the supported write path; we do
    NOT write to OpenSearch directly.

The air-gap-safe on-disk Zeek-log ingest (`core/passive.ingest_zeek_logs`) stays the default (A); this is
the connected-environment enhancement. All calls are to the operator's own Malcolm host.
"""
import json
import ssl
import urllib.request
from typing import Optional


def cvss_to_severity(cvss) -> int:
    """Map a CVSS base score (0–10) to Malcolm/OpenSearch alert severity 1–5 (1 = highest)."""
    try:
        s = float(cvss)
    except (TypeError, ValueError):
        return 3
    if s >= 9.0:
        return 1
    if s >= 7.0:
        return 2
    if s >= 4.0:
        return 3
    if s > 0.0:
        return 4
    return 5


def _parse_agg_assets(resp: dict, ip_field: str, detail_field: str) -> list:
    """Parse a /mapi/agg response (top-level key = first field, nested = subsequent) into
    [{"ip", "protocols"}]. The nested bucket keys are the Zeek datasets the host participates in."""
    out = []
    for b in (resp.get(ip_field) or {}).get("buckets", []):
        ip = b.get("key")
        if not ip:
            continue
        protos = [x.get("key") for x in (b.get(detail_field) or {}).get("buckets", []) if x.get("key")]
        out.append({"ip": ip, "protocols": sorted(set(protos))})
    return out


def _parse_agg_identities(resp: dict, ip_field: str, mfr_field: str, model_field: str) -> dict:
    """Parse a 3-level /mapi/agg response (ip -> manufacturer -> device_type) into
    {ip: {"ip","vendor","model"}}, taking the top bucket at each nested level."""
    out: dict = {}
    for ipb in (resp.get(ip_field) or {}).get("buckets", []):
        ip = ipb.get("key")
        if not ip:
            continue
        vendor = model = None
        mbuckets = (ipb.get(mfr_field) or {}).get("buckets", [])
        if mbuckets:
            vendor = mbuckets[0].get("key")
            dtb = (mbuckets[0].get(model_field) or {}).get("buckets", [])
            if dtb:
                model = dtb[0].get("key")
        out[ip] = {"ip": ip, "vendor": vendor, "model": model}
    return out


class MalcolmClient:
    """Thin client for an existing Malcolm's `mapi`. `base_url` is the operator's Malcolm (e.g.
    https://malcolm.example/mapi or https://malcolm.example). `verify_tls=False` only for a lab host."""

    def __init__(self, base_url: str, token: Optional[str] = None, verify_tls: bool = True,
                 timeout: float = 30.0):
        base = base_url.rstrip("/")
        self.base = base if base.endswith("/mapi") else base + "/mapi"
        self.token = token
        self.verify_tls = verify_tls
        self.timeout = timeout

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        ctx = None if self.verify_tls else ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as r:
            raw = r.read()
        return json.loads(raw) if raw else {}

    # ── B: read the passive asset inventory from the live index ──
    def read_assets(self, ip_field: str = "destination.ip", detail_field: str = "event.dataset",
                    provider: str = "zeek", time_from: str = "7 days ago", limit: int = 500) -> list:
        """Return [{"ip", "protocols"}] from Malcolm's live index via a nested aggregation. `detail_field`
        defaults to the Zeek dataset (so `protocols` lists the Zeek log types each host participates in);
        point it at a vendor/model field to pull richer identity where the operator's schema exposes it."""
        resp = self._request("POST", f"/agg/{ip_field},{detail_field}",
                             {"from": time_from, "to": "now", "limit": limit,
                              "filter": {"event.provider": provider}})
        return _parse_agg_assets(resp, ip_field, detail_field)

    def read_identities(self, time_from: str = "7 days ago", limit: int = 500) -> list:
        """Pull NetBox-enriched device identity (manufacturer -> vendor, device_type -> model) per IP from
        BOTH the source and destination side, merged. Requires Malcolm's NetBox enrichment
        (NETBOX_ENRICHMENT=true); returns [] when no device identity is enriched (caller should fall back
        to read_assets presence). Returns [{"ip","vendor","model"}] -- the richer input for CVE correlation."""
        merged: dict = {}
        for direction in ("source", "destination"):
            ipf = f"{direction}.ip"
            mf = f"{direction}.device.manufacturer"
            df = f"{direction}.device.device_type"
            try:
                resp = self._request("POST", f"/agg/{ipf},{mf},{df}",
                                     {"from": time_from, "to": "now", "limit": limit})
            except OSError:
                continue
            for ip, rec in _parse_agg_identities(resp, ipf, mf, df).items():
                cur = merged.setdefault(ip, {"ip": ip, "vendor": None, "model": None})
                if rec.get("vendor") and not cur["vendor"]:
                    cur["vendor"] = rec["vendor"]
                if rec.get("model") and not cur["model"]:
                    cur["model"] = rec["model"]
        return [r for r in merged.values() if r.get("vendor") or r.get("model")]

    # ── C: push a CVE finding into Malcolm's dashboards via the /mapi/event webhook ──
    def push_finding(self, device_ip: str, cve_id: str, title: str, cvss=None,
                     vendor: Optional[str] = None, model: Optional[str] = None,
                     firmware: Optional[str] = None) -> dict:
        """POST one icsScanner CVE finding to /mapi/event. It is indexed as a session record on the
        device IP, severity-mapped from CVSS, and viewable in Malcolm's dashboards. Returns the response."""
        body = {"source": {"ip": [device_ip]},
                "vulnerability": {"id": cve_id, "scanner": {"vendor": "icsScanner"}},
                "event": {"provider": "icsscanner", "kind": "alert", "category": ["vulnerability"]}}
        dev = {k: v for k, v in (("vendor", vendor), ("model", model), ("firmware", firmware)) if v}
        if dev:
            body["device"] = dev
        payload = {"alert": {
            "monitor": {"name": "icsScanner CVE correlation"},
            "trigger": {"name": title, "severity": cvss_to_severity(cvss)},
            "body": json.dumps(body),
        }}
        return self._request("POST", "/event", payload)

    def push_findings(self, findings: list) -> int:
        """Batch-push findings: each a dict with keys device_ip, cve_id, title, and optional
        cvss/vendor/model/firmware. Returns the count successfully posted (failures are skipped)."""
        n = 0
        for f in findings:
            try:
                self.push_finding(f["device_ip"], f["cve_id"], f.get("title", f["cve_id"]),
                                  cvss=f.get("cvss"), vendor=f.get("vendor"), model=f.get("model"),
                                  firmware=f.get("firmware"))
                n += 1
            except (OSError, KeyError, ValueError):
                continue
        return n
