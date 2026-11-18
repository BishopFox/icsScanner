# icsScanner

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
[![CI](https://github.com/BishopFox/icsscanner/actions/workflows/ci.yml/badge.svg)](https://github.com/BishopFox/icsscanner/actions/workflows/ci.yml)

A safety-first vulnerability scanner for ICS/OT protocols. It identifies devices and checks them against
known CVEs and insecure defaults — **actively** (probing an explicit, authorized target list) or
**passively** (reading a SPAN/TAP or pcap and transmitting nothing) — correlates findings to CVEs, and can
emit deployable detection content for Zeek, Suricata, Sigma, and Splunk.

> **Responsible use.** icsScanner can send active probes and authentication attempts to live industrial
> systems, where unexpected traffic can disrupt physical processes. **Only scan devices you own or are
> explicitly authorized to test.** Active checks are off by default (safe mode reports fingerprint-only);
> the passive mode (`discover sniff`) transmits nothing and is the right choice on live OT networks.
> See [SECURITY.md](SECURITY.md).

The check corpus spans many ICS/OT protocols. Most checks target factory-default credentials and insecure
defaults; the CVE-correlation candidates are built from structured vulnerability feeds — the ICS Advisory
Project, Japan's MyJVN, CISA's CSAF 2.0 OT advisories, and ENISA's EU Vulnerability Database. Reporting is
JSONL + a text summary, with HTML / CSV / SVG export. See `04-USAGE-GUIDE.md` for the full how-to, or
"Running a scan" below for the short version.

## Why this exists

Prior-art research found real ICS/OT vulnerability-scanning
coverage gaps: Nessus's SCADA plugin family is mature but closed/commercial; Nuclei and Metasploit's
ICS content is thin; nmap NSE covers fingerprinting well but has no CVE-level checks. Nobody has
an open, safety-first, actively extensible active-CVE-check layer for ICS. icsScanner fills that gap.

## Files in this project

| File | Purpose |
|---|---|
| `00-PROJECT-CHARTER.md` | Scope, decisions, phased milestones (0–5), LOE |
| `01-METHODOLOGY-AND-CHECKLISTS.md` | Safe active-check development method + the "is this a safe check?" gate |
| `02-DISCLOSURE-PLAYBOOK.md` | The `disclosure_status` contract for consuming upstream findings safely |
| `03-STYLE-AND-DECISIONS.md` | Identity, naming, and the private-for-now publication decision |
| `04-USAGE-GUIDE.md` | Full how-to: CLI + web UI, target inventory/scan policy formats, safety model, API reference, troubleshooting |
| `lab-notes/gap-survey-and-prior-art.md` | The 2026-08-12 prior-art sweep (Nessus, Nuclei, Metasploit, nmap NSE, geeknik/scada-scanner, ICS Advisory Project) |
| `lab-notes/check-inventory.md` | Mapping of own findings (both sibling projects) to planned checks, with disclosure status |
| `lab-notes/default-credentials-sweep.md` | Phase-by-phase log of the default-credentials sweep — most of the 98 checks' origin story |
| `core/` | Engine — registry, target/policy loading, safety/throttling layer, logging, reporting |
| `core/passive.py` / `core/detect_match.py` / `core/detections.py` | Zero-transmit passive mode — capture/dissect/inventory, native detection matching, the Observed-Activity report section |
| `checks/` | Check registry content, organized by protocol; `checks/candidates/` holds research-stage stubs, never executable |
| `detection-gen/` | Generates deployable detections (Sigma / Splunk-ESCU / Suricata / Zeek signature + ATT&CK-for-ICS policy) from the same `checks/` detection_hints |
| `icsscanner.py` | CLI driver — active `scan` and passive `discover sniff`; see above |
| `icsscanner-web.py` / `web/` | Web UI — a local control panel over the same engine |
| `templates/` | Example target-inventory and scan-policy YAML files |
| `lab-notes/passive-mode.md` | Passive-mode architecture + TSA system-requirements (sizing from the PNNL OT-IDS dataset) |

## Operating modes

Three ways to run it, grouped by how much they touch the network. Pick by what the target environment
allows — the transmit posture is the safety-critical distinction:

| Mode | Transmits? | Use when | Commands |
|---|---|---|---|
| **Passive** | No — RX-only, zero packets (`discover sniff`) | Live OT where active probing is disallowed (safety, fragile legacy devices, change control) | `discover sniff` (SPAN/TAP/pcap/Zeek-logs); `discover passive` (ARP-listen + Sparkplug — see the caveat below) |
| **Active scan** | Yes — sends probes, and opt-in logins | Assets you own or have explicit written permission to test | `scan` (default CLI / policy file / web UI); `discover active` (ARP sweep to find hosts first) |
| **Malcolm interop** | Read-only API calls to *your own* Malcolm | You already run a Malcolm / Hedgehog passive stack | `discover malcolm` (read inventory + correlate; `--push` sends findings back); `discover sniff --push-malcolm` (push a passive run's findings) |

Each mode is detailed below. `scan` and `discover sniff` are the primary commands; `discover active` /
`discover passive` are secondary discovery helpers within the Active / Passive modes. **Safe mode
(fingerprint-only, no destructive checks) is the default** in every mode that can transmit.

## Running a scan

Full detail in `04-USAGE-GUIDE.md`. Short version — three ways in, all driving the same engine:

```bash
# Ad hoc CLI: just point at a target inventory, optionally narrow by protocol/check-id.
python3 icsscanner.py --inventory templates/target-inventory.example.yaml --protocol http

# Policy-file CLI: bundles target inventory + check selection + rate profile + output dir into
# one reusable YAML (00-PROJECT-CHARTER.md § Scope — the decided invocation model). CLI flags
# below still override individual policy fields for a one-off tweak.
python3 icsscanner.py --policy templates/scan-policy.example.yaml

# Web UI: a form + run view at http://127.0.0.1:8807/ — same policy/inventory model, same
# safe-mode default, a two-step confirm click in place of the CLI's interactive prompt.
python3 icsscanner-web.py
```

Copy `templates/target-inventory.example.yaml` (and optionally `templates/scan-policy.example.yaml`)
before editing — don't scan straight from the template. **Only list devices you own or have
explicit written permission to test.** Each target is one exact `host:` — an IP or FQDN, never a
CIDR range; this is a deliberate scope decision (small known asset lists, not a network sweep
tool), not a missing feature — see `04-USAGE-GUIDE.md`.

Every check that actually does something (a real login attempt, etc.) is `destructive: true`.
**Safe mode is the default** — destructive checks report fingerprint-only and never fire unless
you pass `--include-destructive` (or set `include_destructive: true` in a policy file), and even
then `icsscanner.py` requires an explicit `y` at an interactive confirmation prompt (or `--yes`/
`-y` to skip it) before anything live happens. The web UI enforces the same thing as an explicit second "Confirm and Run" click instead of
a terminal prompt — the first submission only shows what *would* run. The web UI also has no
authentication and binds `127.0.0.1` (localhost-only) by default for that reason — see
`04-USAGE-GUIDE.md` before exposing it any wider.

`python3 icsscanner.py --help` lists every flag. Results land in `--output`'s directory (default
`./output`, already gitignored) as a timestamped `icsscanner-*.jsonl` plus a printed text summary.

## Passive discovery (zero-transmit)

For live OT networks where active probing is disallowed (safety, fragile legacy devices, change
control), `discover sniff` reads traffic and **sends nothing** — the capture socket is receive-only.
It dissects ICS identity frames into an asset inventory, correlates CVEs, and (with `--detections`)
matches the check corpus' own signatures against the traffic to produce an Observed-Activity section.
This was requested by TSA for its regulated sectors (pipeline, rail, aviation).

```bash
# Offline: dissect a capture file (no network, no transmit)
python3 icsscanner.py discover sniff --pcap plant-span.pcap --cve --detections --html

# Live: read a SPAN/mirror port or TAP for 300s (RX-only, promiscuous, zero packets sent)
sudo python3 icsscanner.py discover sniff --span eth1 --window 300 --cve --detections --csv

# Hybrid: ingest an existing Zeek/ICSNPP sensor's identity logs + its notice.log
python3 icsscanner.py discover sniff --zeek-logs /opt/zeek/logs/current --notice-log notice.log

# Hand the passive inventory to the active scanner as pre-hinted targets (still zero transmit)
python3 icsscanner.py discover sniff --pcap plant-span.pcap --emit-targets targets.yaml
python3 icsscanner.py --inventory targets.yaml          # then scan only what passive found
```

- `--detections` runs the signatures in-process (no external tool). `--notice-log` instead ingests a
  Zeek sensor's own detections (the Malcolm/Hedgehog path); both render the same section. A detection
  is traffic matching a check's signature, **not** a confirmed compromise — narrow (recon) vs broad
  (exploitation-class) is labelled, and matches correlate back to the discovered inventory.
- The same signatures ship as deployable Zeek/Suricata/Sigma/Splunk-ESCU rules via `detection-gen/`.
- `discover sniff` is the zero-transmit flagship. A lighter **`discover passive`** subcommand does ARP
  listen-only plus a read-only MQTT *subscribe* for Sparkplug B. **Caveat:** the ARP side sends nothing,
  but the Sparkplug path opens an MQTT subscribe — that transmits a SUBSCRIBE to the broker, so it is
  **not** literally zero-packet like `discover sniff`. Don't point it at a live OT broker assuming zero
  transmit.
- Full architecture and the TSA system-requirements notes: `lab-notes/passive-mode.md`.

If a target inventory entry has a `credential:` reference (auth-required checks like OPC-UA),
set it in the keyring first: `python3 -c "import keyring; keyring.set_password('service',
'username', 'the-secret')"`. On headless Linux (no D-Bus Secret Service — true for this project's
WSL2 dev environment) set `ICSSCANNER_KEYRING_PASSWORD` first too — see
`feedback_keyring_wsl2.md`. Not needed for any of the default-credentials checks; they're testing
*for* weak/default creds, not authenticating with known-good ones.

## Malcolm interop

icsScanner is the CVE-correlation + detection layer that sits **on top of** an existing Malcolm /
Hedgehog / ICSNPP passive stack — it does not build, bundle, or stand one up. If you already run Malcolm,
it talks to it through Malcolm's own `mapi` REST API, both directions, against your own host.

```bash
# READ: pull the passive asset inventory from a running Malcolm and correlate CVEs (no scan, no file hand-off).
python3 icsscanner.py discover malcolm --url https://malcolm.example --cve

# READ with richer identity: use a NetBox-enriched vendor/model field for model-level CVE matching.
python3 icsscanner.py discover malcolm --url https://malcolm.example --vendor-from-detail --cve

# PUSH: send the correlated CVE findings back into Malcolm's dashboards as session records.
python3 icsscanner.py discover malcolm --url https://malcolm.example --cve --push

# PUSH from a passive run: a SPAN/TAP/pcap sniff that also pushes its findings into Malcolm.
python3 icsscanner.py discover sniff --pcap plant-span.pcap --cve --push-malcolm https://malcolm.example
```

- **Read** uses `POST /mapi/agg` (aggregation over Malcolm's live index); **push** uses `POST /mapi/event`
  (Malcolm's documented alert webhook — a session record viewable in its dashboards), never a raw
  OpenSearch write. `read_identities()` pulls NetBox-enriched `device.manufacturer` / `device_type` when
  `NETBOX_ENRICHMENT` is on, for model-level correlation; it falls back to protocol-presence otherwise.
- Auth: add `--token <bearer>` if your Malcolm requires it, `--insecure` to skip TLS verification on a lab
  host (the sniff push path uses `--malcolm-token` / `--malcolm-insecure`).
- This is the connected-environment option. The air-gap-safe on-disk Zeek-log ingest
  (`discover sniff --zeek-logs`) stays the default where there is no live Malcolm to reach.

## Environment

Same WSL2/OneDrive setup as every project in this directory — see `03-STYLE-AND-DECISIONS.md` and
the memory files `feedback_python_pip.md`, `feedback_live_hardware_testing.md`.
