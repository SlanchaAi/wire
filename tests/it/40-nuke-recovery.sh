#!/usr/bin/env bash
# Teardown + rebuild: nuke --dry-run must change nothing, --force must wipe the
# identity, and re-up must mint a fresh one. The "I broke it, start over" path.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
it_init

H="$(it_home box)"

step "mint an identity (offline is enough for the lifecycle check)"
w "$H" up --offline >/dev/null 2>&1
assert "identity exists" "w \"$H\" whoami --json | jq -e '.did | startswith(\"did:wire:\")'"
DID1="$(w "$H" whoami --json | jq -r .did)"

step "nuke --dry-run must list but change nothing"
w "$H" nuke --dry-run >/dev/null 2>&1 || true
assert "identity survived the dry-run" \
  "test \"\$(w \"$H\" whoami --json | jq -r .did)\" = \"$DID1\""

step "nuke --force must wipe the identity"
w "$H" nuke --force --json | jq -e 'has("removed_paths")' >/dev/null
assert "state is gone after --force" \
  "w \"$H\" whoami --json | jq -e '.initialized == false'"

step "re-up must mint a fresh identity"
w "$H" up --offline >/dev/null 2>&1
assert "fresh identity after re-up" \
  "w \"$H\" whoami --json | jq -e '.did | startswith(\"did:wire:\")'"

pass "nuke-recovery: dry-run safe, force wipes, re-up rebuilds OK"
