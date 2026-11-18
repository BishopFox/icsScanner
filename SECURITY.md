# Security Policy

## Reporting a vulnerability in this tool

If you discover a security issue in icsScanner itself — for example, a way a check could be coerced into
probing an unintended target, a path that generates uncontrolled traffic, a credential-handling flaw, or a
privilege-escalation surface in the capture code — please report it privately.

Email: **research@bishopfox.com**

Please include:

- A description of the issue
- Steps to reproduce (target, full command line, relevant environment variables)
- Affected version (`icsscanner --version` or the commit SHA)
- Your assessment of impact

We aim to acknowledge new reports within 5 business days and provide a resolution timeline within 10
business days.

## Reporting a vulnerability in a scanned system

icsScanner is designed to surface issues in *third-party* ICS/OT devices and software. Findings against
those systems should be reported to the affected vendor under their coordinated-disclosure policy. Bishop
Fox is not a clearinghouse for vendor findings — please coordinate directly with the vendor (or a national
CERT / CISA where appropriate).

## Scope

In scope:

- Vulnerabilities in code under this repository
- Any way the tool can be made to send traffic to, or act against, a system other than the configured
  target
- Supply-chain risks in the install flow

Out of scope:

- Vulnerabilities in third-party dependencies (`scapy`, `paramiko`, `asyncua`, …) — report upstream
- Vulnerabilities in the ICS/OT devices or software that icsScanner scans — report to the vendor
- Findings produced *by* icsScanner against a target — those are output, not bugs in the tool

## Responsible use

icsScanner can send active probes and authentication attempts to live industrial systems. **Only scan
devices you own or are explicitly authorized to test.** Active checks are off by default (safe mode reports
fingerprint-only); destructive checks run only behind an explicit opt-in and consent prompt. The passive
mode (`discover sniff`) transmits nothing and is the appropriate choice on live OT networks.

## Safe harbor

Researchers acting in good faith to identify and report vulnerabilities under this policy will not be
subject to legal action by Bishop Fox.
