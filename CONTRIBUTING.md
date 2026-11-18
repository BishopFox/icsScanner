# Contributing

Thanks for your interest in improving icsScanner. This document covers reporting issues, setting up a
development environment, and the conventions that keep the project safe to run on live industrial networks.

## Reporting a security issue

**Do not open a public issue for a security problem in the tool itself.** Follow the private disclosure
process in [SECURITY.md](SECURITY.md) instead.

## Reporting bugs and requesting features

Use GitHub Issues for bug reports and feature requests. A good bug report includes:

- What you ran (target, full command line, relevant environment variables)
- What you expected to happen and what actually happened
- Affected version (`icsscanner --version` or the commit SHA)
- Sample output or log excerpts where applicable

## Development setup

```bash
git clone https://github.com/BishopFox/icsscanner.git
cd icsscanner

python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[full]"          # editable install + all per-check protocol libraries
```

Run the test suite (every smoke test + the corpus health check; exits non-zero on any failure):

```bash
bash scripts/run_tests.sh          # add -q for quiet (failures + summary only)
```

CI runs the same suite on every push and pull request across Python 3.10–3.12.

## Contributing a check

Checks are the heart of the project, and they run against live equipment — so they follow a safety method,
not just a code style. Before writing one, read **`01-METHODOLOGY-AND-CHECKLISTS.md`** (the "is this a safe
check?" gate) and **`00-PROJECT-CHARTER.md`** (scope). In short:

- **Safe by default.** Any check that does something observable to a target (a login attempt, a write, a
  state change) must set `destructive: true`. It then runs only when the operator opts in *and* passes the
  consent prompt; otherwise it reports fingerprint-only.
- **Fingerprint first.** A check asserts a target is affected only after identity (and, where available,
  firmware version) matches. Prefer the declarative executor (`kind: declarative`); use a native Python
  executor (`kind: native`, under a protocol's `native/` directory) only when the declarative steps can't
  express the logic.
- **Version gating.** If a CVE is fixed in a specific firmware, add a `fingerprint_precondition.version`
  spec (`{fixed|max|min|exact}`) with a *clean, comparable* version string. The gate suppresses a finding
  only when the device firmware is known to be out of range, and it fails safe on messy version strings —
  do not gate a default-credential / factory-behavior issue, which is version-agnostic.
- **Disclosure discipline.** Every check carries a `disclosure_status`. Only `public` and `disclosed-fixed`
  checks are shippable; an undisclosed finding stays out of a public build. Do not include a vendor's
  withheld credential/key material, local file paths, or private contact details in a check.

Add a smoke test under `tests/` for any new parser or executor, and run `python3 scripts/health_check.py`
(it must report `0 blockers`) before opening a pull request.

## Pull requests

- Keep changes focused; one logical change per PR.
- Make sure `bash scripts/run_tests.sh` and `scripts/health_check.py` are green.
- Describe what you changed and how you verified it (a real capture, a test, a reproduction).

By contributing, you agree that your contributions are licensed under the project's MIT License.
