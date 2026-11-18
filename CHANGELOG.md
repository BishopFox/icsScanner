# Changelog

All notable changes to icsScanner are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses semantic versioning.

## [0.3.0] — 2026-11-17

First packaged release: a `pyproject.toml` with an `icsscanner` entry point and single-sourced version.

### Operating modes
- **Active scan** — safety-first checks against an explicit target inventory (default fingerprint-only;
  destructive checks are opt-in behind a consent gate). CLI, reusable policy files, and a localhost web UI.
- **Passive discovery (zero-transmit)** — `discover sniff` reads a SPAN/mirror port, TAP, pcap, or an
  existing Zeek/ICSNPP sensor's logs and never transmits, producing an asset inventory + CVE correlation,
  and (with `--detections`) an Observed-Activity section from the check corpus' own signatures.
- **Malcolm interop** — read a running Malcolm's asset inventory via `mapi` and push correlated CVE
  findings back into its dashboards (both directions), against an operator's own Malcolm.

### Discovery / protocol coverage
- Native passive parsers across many ICS protocols, several validated against real captures (including a
  Mitsubishi MELSOFT parser confirmed on a live GX Works capture, SLMP 3E/4E with MELSEC CPU-model
  extraction, Crestron UDP device-info, and IEC-61850 GOOSE/SV).
- Raw-IP and Linux-cooked pcap link types (mobile/VPN captures), and TLS handshake metadata with
  multi-segment certificate reassembly.

### Vulnerability correlation
- Version-range gating (`core/version_match.py`): a finding is suppressed only when a device's firmware is
  *known* to be outside the advisory's affected range. The comparator fails safe on non-semver ICS firmware
  strings (service-pack/build suffixes), never suppressing a real finding on an uncertain comparison.
- `scripts/backfill_versions.py` proposes version specs from NVD as a reviewed manifest (clean-semver,
  non-credential rows only), rather than a blind auto-edit.

### Detection content
- `detection-gen/` renders the check corpus' signatures as deployable Sigma / Splunk-ESCU / Suricata / Zeek
  rules, validated against labeled ICS pcaps.

### Reporting
- JSONL + text summary, plus HTML / CSV / SVG reports for both scan findings and the discovery inventory.

### Packaging
- `pip install -e .` (or `pip install .`) provides the `icsscanner` command; protocol-specific libraries
  install via the `full` extra. The check corpus, feed data, and web assets are bundled via package-data +
  `MANIFEST.in`, so a non-editable install is self-contained.
