#!/usr/bin/env bash
# `wire up` onboarding: the one-command bootstrap against a relay, and the
# offline keygen path. Asserts the identity is minted from the keypair (no name
# typed) and the relay binding state matches the mode.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
it_init

RELAY="$(boot_relay 18920)"

step "wire up <relay> --no-local : full bootstrap (init + bind + claim + daemon)"
H="$(it_home up-online)"
# up claims the persona on the relay; a 409 on a taken handle is non-fatal, so
# tolerate a nonzero exit and assert the real outcome via whoami/relay-state.
w "$H" up "$RELAY" --no-local >/dev/null 2>&1 || true
assert "identity minted (did:wire persona)" \
  "w \"$H\" whoami --json | jq -e '.did | startswith(\"did:wire:\")'"
assert "handle == DID-derived persona (one-name)" \
  "test \"\$(w \"$H\" whoami --json | jq -r .handle)\" = \"\$(w \"$H\" whoami --json | jq -r '.did | split(\":\")[2] | split(\"-\")[0:2] | join(\"-\")')\""
assert "bound to the relay" \
  "jq -e --arg r \"$RELAY\" '.self.relay_url==\$r' \"$H/config/wire/relay.json\""
assert "wire here works post-up" "w \"$H\" here"

step "wire up --offline : keypair only, nothing bound"
O="$(it_home up-offline)"
w "$O" up --offline >/dev/null 2>&1
assert "offline identity minted" \
  "w \"$O\" whoami --json | jq -e '.did | startswith(\"did:wire:\")'"
assert "no relay bound in offline mode" \
  "test -z \"\$(jq -r '.self.relay_url // \"\"' \"$O/config/wire/relay.json\" 2>/dev/null)\""

step "offline conflicts with a relay arg (clap rejects)"
C="$(it_home up-conflict)"
assert "wire up @host --offline is rejected" \
  "! w \"$C\" up \"$RELAY\" --offline"

pass "onboarding: up bootstrap + up --offline OK"
