# detection-gen

Generates network-detection templates (Sigma, Splunk ESCU, Suricata) from icsScanner's own check
YAML files — so every ICS/OT vulnerability icsScanner can actively probe for also ships with a
starting-point detection an analyst can deploy passively, in their own SIEM/IDS, without writing
one from scratch.

## Status (2026-08-21): pilot complete

7 icsScanner checks (spanning telnet, Modbus, FTP, HTTP, and S7comm) have hand-authored
`detection_hints:` metadata in their own check YAML (in `../checks/`), and all 3
renderers produce output that has been validated against the REAL tooling for each format:
`pySigma`, the community `idstools` Suricata rule parser, and `contentctl==5.6.0` (a full,
scaffolded ESCU content pack achieved a clean `contentctl validate` exit code 0). See
`lab-notes/format-research.md` for the format research itself and every real bug that
verification found and fixed, and `lab-notes/generator-design.md` for the scoping decisions this
project was built against.

## Design, in one paragraph

For each check, two independent template types are generated per format: **narrow** (this
scanner's own literal probe bytes — e.g. the exact credential string it tries) and **broad** (the
underlying vulnerability class in general — e.g. any login attempt with that credential shape,
not just this scanner's specific guess). A check may have no broad signature at all (an
intentional, honest design choice, not a bug) — see the Beckwith M-3425A check's empty
`broad.patterns: []` for a real example; the generator produces zero broad templates for it
rather than inventing a fake one.

`detection_hints:` lives directly in icsScanner's own check YAML (versioned with the check
itself), not in a separate detection-gen-side metadata store — a hybrid design where a check
without hints yet is a real, honestly-reported gap (`has_hints` is `False`), not silently treated
as "no vulnerability exists here."

## Usage

```
python3 generate.py --checks-dir ../checks --out output/
python3 generate.py --checks-dir ../checks --check-id <check_id> --formats sigma,escu
```

## Testing

```
python3 tests/smoke_test_check_loader.py
python3 tests/smoke_test_sigma.py
python3 tests/smoke_test_suricata.py
python3 tests/smoke_test_escu.py
python3 tests/smoke_test_generate.py
```

All entirely offline, reading the real pilot checks directly from `../checks/` (not
synthetic fixtures) and validating renderer output with the real installed libraries
(`pysigma`, `idstools`, `contentctl`'s own Pydantic models/constants) wherever that's possible
without needing a full scaffolded content pack. The one thing NOT reproduced in the automated
suite is a full `contentctl validate` run — that requires real cross-referenced Story/Macro/
Deployment files that are the analyst's own content-pack state, not something a generator's tests
should depend on existing; it was done once, by hand, as the verification step described in
`lab-notes/format-research.md`.

## Open items

See `lab-notes/generator-design.md`.
