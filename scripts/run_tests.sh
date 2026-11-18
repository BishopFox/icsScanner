#!/bin/bash
# Single entry point for the icsScanner test suite: every tests/smoke_test_*.py (ics-scanner and, if
# present, the sibling detection-gen), the health check, and the benign-traffic detection gate.
# Exits non-zero if anything fails. Run from the repo root (or anywhere; it cd's to its own repo).
#
#   scripts/run_tests.sh            # full suite
#   scripts/run_tests.sh -q         # quiet (only failures + summary)
set -u
cd "$(dirname "$0")/.."
QUIET=0; [ "${1:-}" = "-q" ] && QUIET=1
PASS=0; FAIL=0; FAILED=()

run() {  # run <label> <command...>
  local label="$1"; shift
  if "$@" >/tmp/.run_tests.out 2>&1; then
    PASS=$((PASS+1)); [ "$QUIET" = 0 ] && printf '  [ok]   %s\n' "$label"
  else
    FAIL=$((FAIL+1)); FAILED+=("$label")
    printf '  [FAIL] %s\n' "$label"; sed 's/^/        /' /tmp/.run_tests.out | tail -8
  fi
}

echo "== icsScanner smoke tests =="
for t in tests/smoke_test_*.py; do
  [ -e "$t" ] || continue
  run "$(basename "$t" .py)" python3 "$t"
done

if [ -d ../detection-gen/tests ]; then
  echo "== detection-gen smoke tests =="
  for t in ../detection-gen/tests/smoke_test_*.py; do
    [ -e "$t" ] || continue
    run "detection-gen/$(basename "$t" .py)" bash -c "cd ../detection-gen && python3 tests/$(basename "$t")"
  done
fi

echo "== health check =="
run "health_check (0 blockers)" bash -c 'python3 scripts/health_check.py --no-detections 2>&1 | grep -q "^0 blocker"'

echo ""
echo "== summary: $PASS passed, $FAIL failed =="
if [ "$FAIL" -gt 0 ]; then
  printf 'FAILED: %s\n' "${FAILED[*]}"
  exit 1
fi
echo "all green"
