# Usage Guide

How to actually run icsScanner — both the CLI (`icsscanner.py`) and the web UI
(`icsscanner-web.py`), which drive the exact same engine underneath. If you just want the
fastest path to a first scan, jump to "Quick start." Everything else is reference.

**AUTHORIZED USE ONLY — only scan devices you own or have explicit written permission to test.**
Both entrypoints print this warning on every run; it's not decoration.

## What this tool is

A safety-first active vulnerability scanner for ICS/OT protocols. For an active scan you give it a
small, explicit inventory (matching how ICS asset lists actually work: a known, bounded set of
devices, not a CIDR sweep) and it runs a registry of YAML-defined checks against them, mostly
factory-default-credential checks plus a handful of real CVEs. It also has a zero-transmit **passive
mode** (`discover sniff`) that *does* discover assets — from a SPAN/TAP or a pcap, sending nothing —
and can emit what it finds as a pre-hinted inventory for an active scan (see the README's "Passive
discovery" section and `lab-notes/passive-mode.md`). See `00-PROJECT-CHARTER.md` for the full
scope/architecture and `lab-notes/default-credentials-sweep.md` for where most of the check content
came from.

## Operating modes

The tool runs in three modes, grouped by how much they touch the network. The transmit posture is the
safety-critical distinction — choose by what the target environment permits.

| Mode | Transmits? | Use when | Commands |
|---|---|---|---|
| **Passive** | No — RX-only, zero packets (`discover sniff`) | Live OT where active probing is disallowed (safety, fragile legacy devices, change control) | `discover sniff` (SPAN/TAP/pcap/Zeek-logs); `discover passive` (ARP-listen + Sparkplug) |
| **Active scan** | Yes — probes, and opt-in logins | Assets you own or are explicitly authorized to test | `scan` (default CLI / policy / web UI); `discover active` (ARP sweep to find hosts) |
| **Malcolm interop** | Read-only API calls to *your own* Malcolm | You already run a Malcolm / Hedgehog passive stack | `discover malcolm` (read + correlate; `--push`); `discover sniff --push-malcolm` |

- **Passive.** `discover sniff` is the zero-transmit flagship: it reads a SPAN/mirror port, a TAP, a pcap,
  or an existing Zeek/ICSNPP sensor's logs, dissects ICS identity frames into an asset inventory,
  correlates CVEs, and (with `--detections`) matches the check corpus' signatures against the traffic.
  The capture socket is receive-only and never transmits. `discover sniff --emit-targets targets.yaml`
  hands the passive inventory to the active scanner as a pre-hinted inventory (still zero transmit).
  **Caveat on `discover passive`:** its ARP side is listen-only, but its Sparkplug path opens a read-only
  MQTT *subscribe* — that transmits a SUBSCRIBE to the broker, so it is **not** literally zero-packet like
  `discover sniff`. Don't point it at a live OT broker assuming zero transmit.
- **Active scan.** The default invocation (`scan`) runs the checks against targets you list; see Quick
  start and the CLI reference below. `discover active` is a secondary helper that broadcasts one ARP (or
  a MiCOM Courier RPC) per host in a subnet to find live hosts first. Both transmit; safe mode
  (fingerprint-only) is the default, destructive checks are opt-in behind the consent gate.
- **Malcolm interop.** See the "Malcolm interop" section below.

## Quick start

```bash
# 1. Copy the example inventory and point it at your own, authorized target(s).
cp templates/target-inventory.example.yaml my-inventory.yaml
# edit my-inventory.yaml — see "Target inventory format" below

# 2. Safe mode first (the default) — no destructive checks fire, just fingerprint gating.
python3 icsscanner.py --inventory my-inventory.yaml

# 3. When you're ready for real checks (real login attempts etc.), opt in explicitly.
python3 icsscanner.py --inventory my-inventory.yaml --include-destructive
```

Or start the web UI instead of the CLI:
```bash
python3 icsscanner-web.py
# then open http://127.0.0.1:8807/
```

## Safety model (read this before your first destructive run)

- **Safe mode is the default everywhere.** A check with `destructive: true` (almost every
  default-credential check — a real login attempt is inherently destructive-adjacent) never
  actually probes a target unless you explicitly opt in. In safe mode it still runs its
  fingerprint check and reports `likely-affected-fingerprint-only` if the target looks like a
  match, so you get useful signal without touching the target's auth.
- **Opting in requires an explicit, non-defaulted step**, both interfaces:
  - CLI: `--include-destructive` AND (an interactive `y` at a confirmation prompt, or `--yes`/`-y`
    to skip the prompt for scripted use).
  - Web UI: `include_destructive` in the request AND a second, explicit "Confirm and Run" click —
    the first submission only returns the list of targets/checks that *would* fire, nothing runs.
- **Fingerprint gating happens first, always**, before the safe-mode check even matters — a check
  with a `vendor:` precondition simply doesn't apply to a target whose live OUI/protocol probe
  doesn't match, destructive or not.
- **Rate limiting and aliveness polling** are always active (two-tier: a global cap and a
  per-target cap) — a target that stops responding gets its own remaining check queue aborted
  without affecting other targets in the same run.
- **The web UI has no authentication layer.** It binds `127.0.0.1` (localhost-only) by default
  for exactly this reason. `icsscanner-web.py --host 0.0.0.0` prints a loud warning — only do
  that on a trusted, isolated network, and understand that anyone who can reach that port can
  trigger scans.
- **A live fingerprint probe always wins over a declared `vendor`/`product` hint.** A target
  entry's `vendor:`/`product:` fields only take effect when active fingerprinting genuinely finds
  nothing (no MAC in the ARP cache, or an OUI this project hasn't verified yet) — they can never
  override what a target actually answers with. Still, a hint is operator-asserted, not verified:
  a wrong or stale one can unblock a destructive check against a device you didn't mean to
  narrow it to. Only set these when you're confident in them.

## Target inventory format

A YAML file, `targets:` at the top level. See `templates/target-inventory.example.yaml` for a
fully-commented version. Minimal example:

```yaml
targets:
  - host: 192.168.1.50
  - host: 192.168.1.60
    port: 502
    protocol: modbus
    vendor: schneider-electric      # fallback only if live fingerprinting finds nothing — see "Safety model" above
    product: modicon-m221
```

**`host:` is one exact IP or FQDN per entry — never a CIDR range.** An FQDN works today with no
extra config (it's just DNS-resolved at connect time, same as an IP). A CIDR range (`192.168.1.0/24`)
is **not supported, and deliberately not a goal** — `00-PROJECT-CHARTER.md` frames this project's
inventory model as matching "ICS reality of small known asset lists," not a broad network sweep;
nothing here expands a CIDR string into multiple targets. If you hand it one, it'll just be
treated as a single unresolvable hostname, not an error telling you why.

**Credentials, if a check needs them (e.g. OPC-UA session auth):** never plaintext in this file —
a `password:`/`secret:`/`token:`/`api_key:` field is a hard load-time error. Use a keyring
reference instead:
```yaml
  - host: 192.168.1.70
    port: 4840
    protocol: opcua
    credential:
      service: icsscanner-lab
      username: opcua-engineer
```
and set the actual secret once:
```bash
python3 -c "import keyring; keyring.set_password('icsscanner-lab', 'opcua-engineer', 'the-secret')"
```
On headless Linux (no D-Bus Secret Service — true for this project's own WSL2 dev environment),
set `ICSSCANNER_KEYRING_PASSWORD` first; see `feedback_keyring_wsl2.md` in memory or just try a
run — the error message tells you exactly what's missing. None of the default-credential checks
need this at all; they're testing *for* weak/default creds, not authenticating with known ones.

## Scan policy format (optional, bundles everything into one file)

`00-PROJECT-CHARTER.md` § Scope decided this as the primary invocation model — a policy YAML
bundles the inventory path + check selection + rate profile + output dir, and CLI flags override
individual fields for one-off tweaks without editing the file. See
`templates/scan-policy.example.yaml`:

```yaml
inventory: my-inventory.yaml
protocols: [http, telnet]
check_ids: []              # empty/omitted = every check matching protocols
include_destructive: false
max_concurrent_targets: 4
rate:
  global_delay_s: 0.1
  per_target_delay_s: 0.2
output_dir: ./output
```

```bash
python3 icsscanner.py --policy my-policy.yaml
python3 icsscanner.py --policy my-policy.yaml --include-destructive --yes   # override just this
```

## CLI reference (`icsscanner.py`)

Run `python3 icsscanner.py --help` for the authoritative list. Summary:

| Flag | Meaning |
|---|---|
| `--policy PATH` | Scan-policy YAML. Optional. |
| `--inventory PATH` | Target inventory YAML. Required if `--policy` isn't given; overrides the policy's `inventory:` if both are given. |
| `--protocol PROTO` | Restrict to this protocol. Repeatable. Overrides the policy's `protocols:`. |
| `--check-id ID` | Restrict to this check_id. Repeatable. Overrides the policy's `check_ids:`. |
| `--include-destructive` | Allow destructive checks to actually fire. |
| `--max-concurrent-targets N` | Bounded concurrency across targets. |
| `--output DIR` | Where the JSONL log + summary go. |
| `--yes` / `-y` | Skip the interactive destructive-run confirmation. |
| `--report-html` | Write a self-contained HTML report alongside the JSONL log. |
| `--report-csv` | Write a CSV report (one row per finding) alongside the JSONL log. |
| `--include-evidence` | Include raw evidence bytes (hex) in generated HTML/CSV reports. No effect without `--report-html`/`--report-csv`. Excluded by default. |

Threading/concurrency: targets run concurrently (a thread pool capped at
`--max-concurrent-targets`, default 4); each target's own check queue still runs sequentially and
stays rate-limited.

Results: a timestamped `icsscanner-<UTC-timestamp>.jsonl` in `--output` (one JSON record per
check result, plus `run_start`/`run_end`/`aliveness_failure`/`credential_error` diagnostic
sentinel records — see "What's logged" below) plus a printed text summary (counts by
status/protocol, and a confirmed-findings triage table if anything fired). `--report-html`/
`--report-csv` add a self-contained HTML report and/or a CSV (one row per confirmed/
fingerprint-only finding) next to the JSONL — both include a severity-band rollup (parsed from
each check's own `severity:` field, banded per the public CVSS score table — never re-scored,
see `02-DISCLOSURE-PLAYBOOK.md`) and clickable CVE links.

### What's logged per run

Beyond the one JSON record per check result (`status`, `confidence`, `severity`, `references`,
`destructive`, `description`, `evidence_hex`, etc.), every run also writes four kinds of
diagnostic sentinel records (`{"type": ..., "timestamp": ...}`, no `check_id` — filtered out of
check-result aggregation automatically) meant to answer "what did this run cover, and what went
wrong":

- **`run_start`** — target count/hosts, check count, protocols in scope, `include_destructive`,
  concurrency.
- **`run_end`** — total duration, and per-target outcome: `completed` or `aborted_early`.
- **`aliveness_failure`** — logged the moment a target stops responding mid-scan (the aliveness
  poll window expires): which check triggered it, how long it waited, how many remaining checks
  got skipped as a result. This is the direct answer to "what caused an issue with this
  endpoint" — one record, not something you have to infer from a run of per-check `error` rows.
- **`credential_error`** — a credential-resolution failure, if one occurs. Defensive-in-depth:
  no check currently calls `Target.resolve_credential()`, so this path isn't exercised by
  anything shipped today, but it's wired so the log stays self-contained evidence even once a
  check does.

`to_html()`'s report surfaces `run_start`/`run_end`/`aliveness_failure` in a "Diagnostics"
section at the top; the raw JSONL always has all of it if you're grepping directly.

## Web UI (`icsscanner-web.py`)

```bash
python3 icsscanner-web.py            # http://127.0.0.1:8807/
python3 icsscanner-web.py --port 9000
```

The page (`web/page.py`, self-contained — no CDN dependencies) is a single form:
1. Paste/edit a target inventory directly in the textarea (same format as the CLI's inventory
   file — no separate schema).
2. Protocol and check-id pickers are populated live from `GET /api/checks`, i.e. from whatever
   checks actually exist in `checks/` right now — never drifts out of sync with the registry.
3. Toggle "Include destructive checks," set concurrency/output dir.
4. "Run Scan." If destructive checks are in scope, the first click returns a confirmation dialog
   listing exactly what would fire — nothing has run yet. "Confirm and Run" is the second,
   explicit step that actually starts it (`POST /api/scan` with `confirmed: true`).
5. The run view polls `GET /api/jobs/<id>` roughly once a second and renders the same summary
   the CLI prints — totals, by-protocol/by-confidence/by-severity breakdowns, and a
   confirmed-findings triage table — plus links to download the raw JSONL log, a self-contained
   HTML report, and a CSV report. An "include raw evidence" checkbox controls whether the
   HTML/CSV downloads include response bytes (off by default).

HTTP API, if you want to script against it directly instead of the page:

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | The page itself. |
| `/api/checks` | GET | JSON list of every real (non-candidate) check: `check_id`, `protocol`, `destructive`, `description`, `cve_id`, `confidence`. |
| `/api/scan` | POST | Body: `{policy: {...}, inventory_yaml: "...", confirmed: bool}`. See below. |
| `/api/jobs/<id>` | GET | `{status, log_path, summary, error}` — `status` is `pending`/`running`/`done`/`error`. `summary` (once `done`/`error`) is `core/reporter.py:ScanReporter.build_summary()`'s own dict — the SAME aggregation the CLI text summary and the HTML/CSV renderers use, not a separate implementation: `total`, `confirmed`, `fingerprint_only`, `errors`, `by_protocol`, `by_confidence` (confirmed-only), `by_severity` (confirmed-only, CVSS-banded), `findings` (confirmed + fingerprint-only rows, each with `check_id`/`target`/`protocol`/`status`/`confidence`/`cve_id`/`can_id`/`severity_raw`/`severity_band`/`references`/`destructive`/`description`), `run_events` (the diagnostic sentinel records — see "What's logged per run" above). |
| `/api/jobs/<id>/log` | GET | Downloads that job's raw JSONL log (`Content-Disposition: attachment`). 404 if the job doesn't exist or hasn't produced a log yet. |
| `/api/jobs/<id>/report.html` | GET | Downloads a self-contained HTML report for that job. `?include_evidence=1` adds raw evidence bytes (off by default — a render-time choice, not a scan-time one; evidence is always captured in the JSONL regardless). Regenerated on each request, not cached. |
| `/api/jobs/<id>/report.csv` | GET | Downloads a CSV report (one row per finding). Same `?include_evidence=1` toggle. |

`policy` in the POST body accepts the same fields as a scan-policy YAML (`protocols`,
`check_ids`, `include_destructive`, `max_concurrent_targets`, `output_dir`) minus `inventory:` —
that comes from `inventory_yaml` instead, since a web form works with pasted content, not a
server-side file path. A request with `include_destructive: true` and `confirmed: false` (or
omitted) never runs anything — it returns `{requires_confirmation: true, targets: [...],
destructive_checks: [...]}` so a client can render its own confirmation UI. Only
`confirmed: true` starts a background job and returns `{job_id: "..."}` with HTTP 202.

## Malcolm interop

icsScanner is the CVE-correlation + detection layer that sits on top of an existing Malcolm / Hedgehog /
ICSNPP passive stack; it does not build or bundle one. Against a Malcolm you already run, it uses
Malcolm's own `mapi` REST API in both directions.

```bash
# READ — pull the passive asset inventory from a running Malcolm and correlate CVEs (no scan).
python3 icsscanner.py discover malcolm --url https://malcolm.example --cve

# READ with NetBox-enriched vendor/model identity -> model-level CVE matching.
python3 icsscanner.py discover malcolm --url https://malcolm.example --vendor-from-detail --cve

# PUSH — send the correlated findings back into Malcolm's dashboards.
python3 icsscanner.py discover malcolm --url https://malcolm.example --cve --push

# PUSH from a passive capture run.
python3 icsscanner.py discover sniff --pcap plant-span.pcap --cve --push-malcolm https://malcolm.example
```

Flags (both directions):

| Flag | Applies to | Meaning |
|---|---|---|
| `--url <https://host>` | `discover malcolm` | Your Malcolm base URL (the `mapi` endpoint is derived). |
| `--token <bearer>` | `discover malcolm` | Bearer token if your Malcolm requires auth. |
| `--insecure` | `discover malcolm` | Skip TLS verification (lab hosts only). |
| `--ip-field` / `--detail-field` | `discover malcolm` | Which indexed fields to aggregate on (defaults suit a stock Zeek index). |
| `--vendor-from-detail` | `discover malcolm` | Treat the detail field as a vendor/model (NetBox-enriched) for model-level matching. |
| `--since <when>` | `discover malcolm` | Time window for the aggregation. |
| `--cve` | both | Run CVE correlation over the pulled/observed inventory. |
| `--push` | `discover malcolm` | After correlating, push findings back via `POST /mapi/event`. |
| `--push-malcolm <url>` | `discover sniff` | Push a passive run's findings to this Malcolm. |
| `--malcolm-token` / `--malcolm-insecure` | `discover sniff` | Auth / TLS-skip for the sniff push path. |

Mechanics: reads use `POST /mapi/agg` (aggregation over the live index); writes use `POST /mapi/event`,
Malcolm's documented alert webhook (a session record viewable in its dashboards) — never a raw OpenSearch
write. `read_identities()` pulls NetBox-enriched `device.manufacturer` / `device_type` when
`NETBOX_ENRICHMENT` is enabled, and falls back to protocol-presence otherwise. This is the
connected-environment option; the on-disk `discover sniff --zeek-logs` ingest stays the default where
there is no live Malcolm to reach.

## Known limitations (real gaps, not hidden)

- **The version-gate corpus is sparse.** Version-range matching is built and wired
  (`core/version_match.py`; the gate suppresses a finding only when a device's firmware is *known* to be
  out of the advisory's affected range), and a target entry's `version` feeds it as `version_hint`. But
  few checks carry a `version` spec yet, so most findings are still "possibly affected" (a vendor+model
  match) rather than firmware-precise. Backfilling the CVE-anchored subset is in progress.
- **The version comparator is conservative on messy ICS firmware strings.** A version with a
  service-pack/build suffix (`V1.500 SP3`, `V1500-SP2`) or a mixed scheme is treated as not-comparable —
  the gate returns "unknown" and does **not** suppress, rather than risk a wrong comparison. Deliberate
  fail-safe: it never suppresses a real finding, but it also can't gate those devices by version.
- **Passive protocol depth varies.** Most passive parsers extract full identity, but a few are
  presence-level only (they confirm the protocol without a vendor/model), and the version gate can only
  act where discovery actually recovers a firmware string — not for every protocol or credential check.
- **The web UI is a single-operator local panel by design** — no authentication, no HTTPS, no multi-user
  job isolation; it binds `127.0.0.1`. A scope choice, not an oversight: a local control panel, not a
  multi-tenant service. Don't expose it beyond a trusted host without your own auth/TLS proxy in front.
- **Target inventories are exact host lists, not ranges.** Each target is one `host:` (IP or FQDN); the
  active scanner has no CIDR sweep (deliberate — small known asset lists; see "Target inventory format").
  For host discovery use `discover active` (ARP sweep) or the passive modes.

## Troubleshooting

- **"No targets in the inventory"** — your YAML's `targets:` list is empty, or the file wasn't
  found (check the path).
- **"No checks matched --protocol/--check-id"** — a typo'd protocol or check_id filters out
  everything; there's no validation that a given check_id actually exists, it just yields zero
  matches. Run without a filter, or check `/api/checks` (web) / a check's YAML file directly for
  the exact `check_id` string.
- **A YAML parse error** (either file) prints a clean one-line message citing the file and the
  parse issue — not a raw traceback.
- **Credential errors** (`CredentialResolutionError`/`InsecureKeyringBackendError`) print exactly
  what's missing and, on headless Linux, the exact `ICSSCANNER_KEYRING_PASSWORD` fix.
