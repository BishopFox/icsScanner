#!/usr/bin/env python3
"""Public release smoke test.

The only test shipped in the public export. It does not exercise any individual
check's probe behavior; it verifies the shipped artifact is internally consistent:
the CLI module imports, and the check registry loads and instantiates every check
present in the tree. Loading a native check imports its executor module, so a
missing shared helper or any broken import fails here. It passes on both the full
private tree and the disclosure-filtered public tree, since it asserts only what is
true of any valid tree (the richer per-check tests stay private).
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FAILURES = []


def check(desc, ok):
    print(("  [ok]   " if ok else "  [FAIL] ") + desc)
    if not ok:
        FAILURES.append(desc)


# 1. CLI entry point imports (guarded main, no scan on import)
try:
    import icsscanner  # noqa: F401

    check("icsscanner CLI module imports", True)
except Exception as e:  # noqa: BLE001
    check(f"icsscanner CLI module imports -> {type(e).__name__}: {e}", False)

# 2. registry loads + instantiates every check in the tree (imports each native
#    executor; a missing shared helper or broken import raises here)
try:
    from core.registry import CheckRegistry

    registry = CheckRegistry(str(ROOT / "checks")).load()
    loaded = registry.checks()
    check(f"check registry loads and instantiates {len(loaded)} checks with no import errors",
          len(loaded) > 0)
    check("registry exposes at least one disclosure-shippable check",
          len(registry.shippable()) > 0)
except Exception as e:  # noqa: BLE001
    check(f"check registry loads -> {type(e).__name__}: {e}", False)

if FAILURES:
    print(f"\n{len(FAILURES)} failure(s)")
    sys.exit(1)
print("\npublic smoke: all green")
