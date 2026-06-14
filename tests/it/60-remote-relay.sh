#!/usr/bin/env bash
# Federation routing over a REMOTE (non-loopback) relay. The other tests bind
# the relay on 127.0.0.1 — this binds it to the host's routable IP so the
# agents reach it the way they'd reach a real remote relay, exercising the
# federation path over a network interface (catches loopback-only assumptions:
# bind scope, advertised endpoint host, the userspace-netstack class of bugs).
set -euo pipefail
. "$(dirname "$0")/lib.sh"
it_init

IP="$(nonloopback_ip)"
if [ -z "$IP" ] || [ "$IP" = "127.0.0.1" ]; then
  echo "  (no non-loopback IPv4 on this host — skipping remote-relay test)"
  exit 0
fi
echo "→ remote relay bound to non-loopback $IP"
RELAY="$(boot_relay_on "$IP" 18950)"
A="$(it_home alice)"; B="$(it_home bob)"

step "two agents bind + claim on the remote relay ($IP)"
w "$A" init --relay "$RELAY" >/dev/null
w "$A" claim "$(handle_of "$A")" --public-url "$RELAY" >/dev/null
w "$B" init --relay "$RELAY" >/dev/null
AH="$(handle_of "$A")"; BH="$(handle_of "$B")"
pass "A=$AH  B=$BH on $IP"
# The self endpoint each agent advertises must point at the remote relay, not
# loopback — otherwise peers could never reach it from another host.
assert "A advertises the remote relay, not loopback" \
  "jq -e --arg ip \"$IP\" '[.self.endpoints[]?.relay_url, .self.relay_url] | map(select(.!=null)) | any(contains(\$ip))' \"$A/config/wire/relay.json\""

step "B pairs with A over the remote relay (handle@$IP)"
w "$B" add "$AH@$IP" --relay "$RELAY" --json >/dev/null
assert "A receives B's pending pair_drop via the remote relay" \
  "wait_until 20 'w \"$A\" pull --json; w \"$A\" pending --json | grep -q $BH'"
w "$A" accept "$BH" --json >/dev/null
w "$B" pull --json >/dev/null

step "bidirectional signed messages forwarded by the remote relay"
w "$A" send --queue "$BH" decision "hello over remote relay $IP" >/dev/null
w "$A" push --json >/dev/null
assert "B received A's message via the remote relay" \
  "wait_until 20 'w \"$B\" pull --json; w \"$B\" tail \"$AH\" --json | grep -q \"hello over remote relay $IP\"'"
w "$B" send --queue "$AH" decision "ack over $IP" >/dev/null
w "$B" push --json >/dev/null
assert "A received B's reply via the remote relay" \
  "wait_until 20 'w \"$A\" pull --json; w \"$A\" tail \"$BH\" --json | grep -q \"ack over $IP\"'"

pass "remote-relay: federation pair + bidirectional messaging over a non-loopback relay OK"
