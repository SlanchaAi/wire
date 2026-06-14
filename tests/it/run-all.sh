#!/usr/bin/env bash
# Run every wire integration test (tests/it/NN-*.sh) against the real CLI and
# report a pass/fail summary. Exit nonzero if any test fails.
#
#   WIRE=./target/release/wire tests/it/run-all.sh
#
# Each test is self-contained: it boots its own relay(s), drives the shipped
# binary end-to-end, asserts on observable behaviour, and cleans up. These are
# integration tests — they exercise what a user/script actually runs, not the
# library internals `cargo test` covers.
set -uo pipefail
WIRE="${WIRE:-wire}"
# Resolve a relative binary PATH to absolute BEFORE we cd into tests/it/ —
# otherwise a relative WIRE (CI passes ./target/release/wire) no longer resolves
# from the new cwd. A bare command name (on PATH) is left untouched.
case "$WIRE" in
  */*) [ -e "$WIRE" ] && WIRE="$(cd "$(dirname "$WIRE")" && pwd)/$(basename "$WIRE")" ;;
esac
export WIRE
cd "$(dirname "$0")"
command -v "$WIRE" >/dev/null 2>&1 || { echo "wire binary not found ($WIRE) — set WIRE=path"; exit 1; }

echo "wire integration suite — binary: $($WIRE --version 2>/dev/null || echo "$WIRE")"
echo

pass=0; fail=0; failed=""
for t in [0-9]*-*.sh; do
  [ -e "$t" ] || continue
  if WIRE="$WIRE" bash "$t"; then
    pass=$((pass+1))
  else
    fail=$((fail+1)); failed="$failed $t"
    echo "  ↑ $t FAILED"
  fi
  echo
done

echo "════════════════════════════════════════"
echo "integration suite: $pass passed, $fail failed"
if [ "$fail" -ne 0 ]; then
  echo "failed:$failed"
  exit 1
fi
echo "all integration tests passed."
