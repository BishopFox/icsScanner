# icsScanner roadmap

icsScanner is a safety-first discovery and vulnerability-correlation tool for ICS/OT
networks. This document describes where the project is today and where it is going. It is
a statement of direction, not a commitment to dates: items move as coordinated-disclosure
timelines and field validation dictate.

## Principles

These do not change, and they shape every item below.

- **Safety first.** Active scanning defaults to passive fingerprinting. Any check that
  writes to a device or attempts a login is opt-in, behind an explicit consent gate. A
  zero-transmit passive mode reads a SPAN/mirror port, TAP, or pcap and never puts a
  packet on the wire.
- **Conservative, verified detection.** Signatures are derived from captured bytes, not
  written from memory, and are tested against benign OT traffic so they do not fire on
  normal engineering activity. Findings state what was observed and are explicit about
  what is not claimed.
- **Coordinated disclosure.** Only checks for public or vendor-fixed issues are included
  in this repository. Nothing here depends on an undisclosed vulnerability.

## Current status (0.3.x)

Working today:

- Three operating modes: active scan (safety-first, consent-gated), passive zero-transmit
  discovery (SPAN/TAP/pcap, or ingest from an existing Zeek/ICSNPP sensor), and Malcolm
  interop (read a running Malcolm's asset inventory and push correlated CVE findings back
  into its dashboards).
- Native passive identification across many ICS protocols, several validated against real
  packet captures.
- A check corpus with CVE / KEV / EPSS correlation and conservative severity.
- Detection export (Sigma, Splunk ESCU, Suricata, Zeek) generated from the check corpus
  and gated against benign traffic.
- A command-line interface, a localhost web UI, and reporting with CISA CPG and NIST CSF
  mapping.
- A packaged install (pyproject, console entry point) with continuous integration.

## Near-term: toward 1.0

The focus is precision and polish, not new surface.

- **Version-precise CVE correlation.** The version-comparison gate exists and fails safe.
  The next step is populating affected and fixed version ranges across the corpus, so an
  affected-version CVE is suppressed when the device's firmware is out of range. This
  turns "possibly affected" inventory into firmware-precise findings.
- **Release engineering.** Semantic-versioned, tagged releases; a published package;
  pinned dependencies.
- **Operator documentation.** A short quickstart, worked examples with sample captures, an
  authorization-and-scope guide, and troubleshooting.
- **A detection coverage matrix and a limitations page**, so users can see plainly what the
  tool does and does not establish.

## Medium-term

- Broader protocol and vendor identification, prioritized by sector exposure (water and
  wastewater first).
- Live-hardware validation of probes currently verified only against mocks.
- SIEM-friendly output (for example SARIF or structured export) alongside the existing
  report formats.
- A check-authoring guide and a growing public test suite, so contributors can add checks
  without weakening the safety and disclosure rules.

## Longer-term and exploratory

- A live behavioral-detection matcher, extending detection export from inventory
  signatures toward attacker-action detection.
- Deeper passive identity correlation from third-party sensor logs.
- Additional inventory-platform interop beyond Malcolm.

## Versioning and releases

The project uses semantic versioning. Before 1.0, the CLI and check schema may change
between minor versions. 1.0 marks a stable command-line interface and check format.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Two rules are
non-negotiable for any check contribution: it must be safe by default (no unsolicited
writes or logins), and it must reference a public or vendor-fixed issue.

## Known limitations

- Many checks are inventory-grade: they identify a device as a member of an affected
  product family, not that a specific unit is exploitable. Severity reflects documented
  impact, not a confirmed exploit against the target.
- Version suppression applies only where a clean, dotted-numeric version range is
  published and the device exposes its firmware in the same scheme. Mixed or suffixed
  version schemes are left uncompared rather than risk a wrong suppression.
- Passive identification is bounded by what the capture contains. A device that never
  speaks on the observed segment will not be seen.
- icsScanner complements, and does not replace, authenticated asset management and vendor
  advisories.
