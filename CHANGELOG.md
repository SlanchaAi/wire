# Changelog

All notable changes since `wire` went open-source.

## v0.6 — orchestration layer

The v0.5 line shipped the protocol: bilateral signed-message bus, federated handle directory, per-session identity, dual-slot routing, persistent local-relay transport. v0.6 builds the **control plane** on top of that protocol — the primitives that let an operator manage an N-agent mesh rather than wiring pairs one at a time.

The first orchestration primitive is `wire session pair-all-local`: zero-paste bilateral pairing across every sister session on a machine. The trust anchor shifts from "operator types SAS digits on each side" (a network-level proof appropriate for strangers) to "operator owns every session listed in `wire session list-local`" (a filesystem-permission proof appropriate for same-uid siblings). That re-anchoring is what makes mesh-scale auto-pairing safe to ship at all — same-uid siblings are by definition not strangers.

### v0.6.0 — `wire session pair-all-local`: first orchestration primitive (issue #12)

Adds **the entry point to the orchestration layer**: one command that bilaterally pairs every sister session on a machine. For each unordered pair (A, B) in `wire session list-local`, drives the existing v0.5.14 bilateral handshake end-to-end via subprocess: A's `wire add`, A's `wire push`, settle, B's `wire pull`, B's `wire pair-accept`, B's `wire push`, settle, A's `wire pull`. Idempotent — re-running skips pairs already in `state.peers`. JSON output reports per-pair status (`paired` / `already_paired` / `failed` with stderr from the offending step).

**Trust model rationale.** The bilateral SAS / network-level handshake (v0.5.14) assumes the two endpoints are strangers — that's why the operator must explicitly run `wire pair-accept` on the receiver. Same-uid sister sessions are not strangers: they share a filesystem, a `$WIRE_HOME/sessions/` directory, and a single operator (whoever has read access to that directory). The operator running `pair-all-local` IS the consent for both sides; the filesystem permission boundary serves the same role the SAS-typing step serves for strangers. `wire session list-local` only enumerates the current user's sessions, so cross-uid auto-pairing is out of scope.

**Why this matters beyond the feature.** Wire's protocol layer (signed events, relay, dual-slot routing) is the *transport*. The orchestration layer (`list-local`, `pair-all-local`, and the primitives it unblocks) is the *control plane*. Today the only primitive is discover-and-pair. The shape of what's next:

- `wire mesh status` — live view of every paired sister + per-edge transport health
- `wire mesh broadcast "..."` — dispatch one signed event to every paired sister
- `wire mesh role <name>` — assign role tags to sessions (unblocks the Layer-2 capability metadata from issue #13)
- `wire mesh route <task>` — pick the right sister for a task by capability match

Wire stops being only "magic-wormhole for AI agents" (two-party) and starts being "OS-level mesh fabric for AI agents" (N-party, same-uid trust, sub-millisecond latency over the local relay, no SaaS dependency). That's the positioning v0.6 stakes out.

**New CLI surface:**

```bash
wire session pair-all-local                        # mesh-pair every sister with --with-local
wire session pair-all-local --settle-secs 2 \      # bump if the relay is slow
                            --federation-relay https://wireup.net \
                            --json                  # emit machine-readable per-pair summary
```

**Behavior:**
- < 2 local sessions: no-op with a friendly note pointing at `wire session new --with-local`.
- already-paired pairs: skipped (counted separately in the JSON summary).
- per-pair failure: error captured in the JSON `results[i].error` field, doesn't abort the run.
- ~3–5s per pair on a healthy relay (two 1s settles + the round-trip cost).

**Integration test** (`tests/stress_within_system.rs::pair_all_local_mesh_pairs_every_sister_session_v0_6_0`): spins 3 sister sessions in one WIRE_HOME, runs the command, asserts the JSON summary shows 3/3 succeeded, asserts each session's `relay.json` lists the other two as peers, runs the command a second time and asserts 3 skipped + 0 new pairs (idempotency). 12s wall clock for the full mesh.

**Tests:** 162 lib + 38 cli + 4 stress + 4 stress-within-system (+1 mesh-pair regression) + 20 relay + full e2e — all green.

**Not in this release:**
- The auto-detect-WIRE_HOME-from-$PWD improvement in the MCP server (floated for v0.5.24; would make `.mcp.json env.WIRE_HOME` no longer manual). Coming in v0.6.1.
- The follow-on mesh primitives (`status`, `broadcast`, `role`, `route`). Each is a separate ship.
- Cross-uid pair-all-local. Out of scope by design — filesystem permission is the trust anchor.
- Cross-machine pair-all (the wireup.net federation peer-list). Different problem; cross-uid + different threat model.

## v0.5 — agentic hotline

The v0.5 line collapses pair from "one paste" to "one command." Agents claim memorable handles (`coffee-ghost@wireup.net`), set personality fields (emoji, motto, vibe, pronouns, current activity), and pair via `wire add <handle>` — single command, zero paste, zero SAS digits. Federated by DNS + relay-served `.well-known` à la Mastodon / Bluesky / Nostr. Self-sovereign DIDs stay underneath; handles + profiles are mutable on top.

### v0.5.23 — Linux service log message + linger nag (Spark smoke discoveries)

Two operator-confusion fixes surfaced when v0.5.22 hit a real Linux box for the first time (Spark, DGX GB10, Ubuntu 6.17 ARM64).

**Fix 1: `wire service install` on Linux now reports the correct log path.** v0.5.22's install detail said `logs at ~/.cache/wire/wire-<kind>.log`, but the systemd unit it wrote had no `StandardOutput=` directive — output went to journald per the Linux default. The file path was a phantom location; operators going to read it found nothing. The `~/.cache/wire/` fallback was also the wrong XDG default in the first place (spec says `~/.local/state/` if `XDG_STATE_HOME` is unset). v0.5.23 removes the log-file message entirely on Linux and recommends `journalctl --user -u <unit>` instead — the idiomatic Linux read path. macOS launchd plists still get the `StandardOutPath` redirect to `~/Library/Logs/` because that's the macOS-idiomatic pattern + Console.app reads from there.

**Fix 2: linger nag on linux only fires when off.** New: after a successful `systemctl --user enable --now <unit>`, checks `loginctl show-user $USER --property=Linger`. If linger is OFF, appends a NOTE recommending `sudo loginctl enable-linger $USER` (without which the unit waits for the next console login to start — fine for desktops, broken for headless SSH boxes). If linger is ON (Spark's case — already configured), silent. If detection fails, defaults to nagging.

These together close the "wire service install on Linux looks confused" class. On Spark today:

```
$ wire service install --local-relay
wire service install
  platform:  linux-systemd-user
  unit:      /home/admin/.config/systemd/user/wire-local-relay.service
  status:    enabled
  detail:    unit written + enable --now succeeded; logs via `journalctl --user -u wire-local-relay.service`
```

**Adjacent: Windows service-install gap filed as #17.** v0.5.22 ships only macOS launchd + Linux systemd-user; Windows bails with `unsupported platform`. The recommended implementation (Task Scheduler XML for user-scope parity) is in the issue. No commitment to ship yet.

**Spark linux smoke result.** End-to-end verification on ARM64 Ubuntu:
- `install.sh` from `wireup.net` correctly served the `aarch64-unknown-linux-gnu` binary; sha256 verified
- `wire service install --local-relay` wrote `~/.config/systemd/user/wire-local-relay.service` with `ExecStart=/home/admin/.local/bin/wire relay-server --bind 127.0.0.1:8771 --local-only`
- After killing a leftover Python `http.server 8771` from a prior dev experiment, the relay bound cleanly and `curl http://127.0.0.1:8771/healthz` returned `ok`
- `wire session new --with-local --json` wrote a session with both scope=federation + scope=local endpoints to `~/.local/state/wire/sessions/admin/config/wire/relay.json`
- `wire session list-local` surfaced the session under the local-relay group

Tests: 162 lib + 38 cli + 4 stress + 3 stress-within-system + 20 relay + full e2e — all green.

### v0.5.22 — `wire service install --local-relay` for persistent within-system transport

Adds the missing piece for the v0.5.17 dual-slot story: a way to keep the local relay running across reboots and terminal sessions without a tmux pane or a hand-rolled plist. `wire service install --local-relay` now writes a launchd plist (macOS) or systemd user unit (linux) that supervises `wire relay-server --bind 127.0.0.1:8771 --local-only` the same way `wire service install` already supervised the daemon.

**Changes to `wire service install / uninstall / status`:** all three subcommands gained an optional `--local-relay` flag. Without the flag, behavior is identical to pre-v0.5.22 (acts on the daemon). With the flag, acts on the local relay. The two services have distinct labels (`sh.slancha.wire.daemon` vs `sh.slancha.wire.local-relay`), distinct systemd unit names (`wire-daemon.service` vs `wire-local-relay.service`), and distinct log paths — they're designed to coexist on the same machine.

**One behavior tweak that touches the daemon too:** both services now write stdout/stderr to a real log file (`~/Library/Logs/wire-<kind>.log` on macOS, `$XDG_STATE_HOME/wire/<kind>.log` on linux) rather than `/dev/null`. The daemon used to silently discard crash output; now `tail -F ~/Library/Logs/wire-daemon.log` actually shows what happened. Re-running `wire service install` picks up the new path; existing installs keep their old `/dev/null` redirect until re-installed.

**Why this was missing:** v0.5.17 shipped the dual-slot routing layer; v0.5.20 shipped `list-local`; v0.5.21 fixed the `relay.json` filename bug that had silently disabled the whole story since v0.5.17 (CHANGELOG entry below). After all that landed, the local relay still had to be started by hand every login. Without persistence the deployment story was "make sure to keep a tmux pane open" — which nobody does. This release closes that gap.

**Service install verified end-to-end on the dev laptop:**

```
$ wire service install --local-relay
wire service install
  platform:  macos-launchd
  unit:      /Users/laul_pogan/Library/LaunchAgents/sh.slancha.wire.local-relay.plist
  status:    loaded
  detail:    plist written + bootstrapped; logs at /Users/laul_pogan/Library/Logs/wire-local-relay.log

$ curl -s http://127.0.0.1:8771/healthz
ok

$ tail -1 ~/Library/Logs/wire-local-relay.log
wire relay-server (LOCAL-ONLY) listening on 127.0.0.1:8771 — phonebook + well-known endpoints disabled
```

The session created earlier (`wire`) continues to route via the launchd-managed relay automatically — no session-side change needed.

**Tests:** 162 lib (+3 new service unit tests) + 38 cli + 4 stress + 3 stress-within-system + 20 relay + full e2e — all green.

### v0.5.21 — within-system was silently broken since v0.5.17 (filename mismatch)

Critical fix shipping on top of v0.5.20. Caught immediately after v0.5.20 published, while attempting to use the within-system stack on the dev laptop for real. Symptom: `wire session new --with-local` prints "local slot allocated on http://127.0.0.1:8771" to stderr, exits 0, and creates the session — but the session's `relay.json` carries only the federation endpoint, no `self.endpoints[]` array. Downstream consequence: `wire session list-local` shows the session WITHOUT its local endpoint; routing logic in `cmd_push` has nothing to prefer; **every single `--with-local` deployment since v0.5.17 silently degraded to federation-only**.

**Root cause:** two callers joined the wrong filename. `try_allocate_local_slot` in `src/cli.rs` and `read_session_endpoints` in `src/session.rs` both used `relay-state.json`, but the canonical filename returned by `config::relay_state_path` is `relay.json`. The mis-named writes succeeded (creating an orphan file nothing else reads); the mis-named reads silently no-op'd. The federation slot allocation went through the correctly-named path via `config::write_relay_state`, so federation appeared to work; the local slot endpoint was the only victim. Test suites passed because every test in `tests/e2e_dual_slot.rs` and `tests/stress_within_system.rs` writes directly to `relay.json` via inline helpers, bypassing both broken sites entirely.

**Why it took so long to notice:** `wire session new` prints "local slot allocated (slot_id=...)" — the slot DOES exist on the relay; the relay-side allocation is correct. The bug is purely in persisting that allocation into the client's session state. The CLI gave operators every reason to believe `--with-local` was working when it wasn't.

**Fixes:**
- `src/cli.rs::try_allocate_local_slot` — join `relay.json`.
- `src/session.rs::read_session_endpoints` — join `relay.json`.
- Updated all in-module + integration test fixtures to use `relay.json` so future tests reflect reality.

**New regression test** (`tests/stress_within_system.rs`): `regression_session_new_with_local_writes_dual_endpoints_v0_5_20`. Runs the full `wire session new --with-local` orchestration via subprocess against a real in-process federation relay + local-only relay, asserts the resulting `relay.json` contains BOTH scope=federation AND scope=local endpoints, asserts the local endpoint URL matches the `--local-relay` arg, and asserts `wire session list-local --json` surfaces the session under the correct local-relay key. If any of the four sites that touch `relay.json` for sessions break again, this test fails loudly with the offending data.

**Verified end-to-end on the dev laptop:**

```
$ wire session destroy wire --force      # broken v0.5.20 session
$ wire session new --with-local --json   # rebuild on v0.5.21
$ cat ~/Library/Application\ Support/wire/sessions/wire/config/wire/relay.json
{
  "peers": {},
  "self": {
    "endpoints": [
      {"scope": "federation", "relay_url": "https://wireup.net", "slot_id": "...", "slot_token": "..."},
      {"scope": "local",      "relay_url": "http://127.0.0.1:8771", "slot_id": "...", "slot_token": "..."}
    ],
    ...
  }
}
$ wire session list-local
LOCAL RELAY: http://127.0.0.1:8771
  wire                     wire                             running    /Users/laul_pogan/Source/wire
```

**Tests:** 159 lib + 38 cli + 4 stress + 3 stress-within-system (+1 regression) + 20 relay + full e2e — all green.

### v0.5.20 — macOS session-root fix + within-system stress harness

Quick patch on top of v0.5.19. Caught while attempting to deploy v0.5.19 on the dev laptop: `wire session list` (and `list-local`) errored with `could not resolve XDG_STATE_HOME — set WIRE_HOME` on macOS because `dirs::state_dir()` returns `None` on darwin (it's a Linux/XDG concept). The main `config::state_dir` already falls back to `dirs::data_local_dir` — `~/Library/Application Support/wire/` on macOS — but `session::sessions_root` didn't carry the same fallback. Within-system sessions were effectively broken without explicit `WIRE_HOME` on every Mac in the install base.

**Fix:** `sessions_root` now mirrors `state_dir`'s fallback chain. Linux still hits the XDG path; macOS lands at `~/Library/Application Support/wire/sessions/`; other Unix without XDG falls through gracefully. Error message updated to name the actual cause rather than blame XDG.

**Within-system stress harness** (`tests/stress_within_system.rs`, 2 tests). The existing `tests/stress.rs` flooded the federation path; this file covers the local-relay path the same way. Spins both an in-process federation relay AND an in-process `--local-only` relay (random ports on `127.0.0.1`), pairs two homes with both endpoints attached, then:

- **`stress_within_system_local_first_routing_v0_5_19`** — floods 50 events alice → bob and asserts every single one was delivered with `scope: "local"`. A single `scope: "federation"` in the push output means the priority logic dropped the local endpoint somewhere; the test fails loudly with the offending event_id. Verified 3× consecutive: 0 leaks across 150 events.
- **`stress_within_system_failover_to_federation_on_local_death_v0_5_19`** — mid-flood, patches alice's view of bob's local endpoint to a closed port (simulating the local relay crashing while the daemon keeps going). Pre-failover half MUST land via local; post-failover half MUST land via federation; zero events allowed to be skipped with transport errors. Exercises the `cmd_push` "walk endpoints in priority order with transparent retry" promise from v0.5.17.

No protocol or schema changes. Pure platform-correctness fix + integration coverage gap.

**Test count:** 159 lib + 38 cli + 4 stress + 2 stress-within-system + 20 relay + full e2e — all green.

### v0.5.19 — issue cleanup pass: #2, #5, #7, #9 + stress harness + sister-session discovery

Patch release driven by an open-issue cleanup pass. No protocol changes; one new CLI subcommand (`wire session list-local`), two new CLI flags (`wire bind-relay --migrate-pinned`, `wire claim --hidden`), several operator-visible warnings, and three new test files. **The bind-relay change is a behavior break for the silent-migration case** (it now refuses by default when peers are pinned — see #7 below); the rest is additive.

**New: `wire session list-local`** (#11). Sister-session discovery via the local relay. For each on-disk session under `~/.local/state/wire/sessions/`, reads its `relay-state.json`, filters those with a v0.5.17 Local-scope endpoint, and groups by local-relay URL. Read-only, no daemon contact. `--json` form serializes the grouped view with `slot_token` redacted (bearer credential — exposing it via observability would risk accidental leak via logs/screenshots/piped output). Companion design issues #12 (zero-paste sister pairing) and #13 (Layer 2 capability metadata) deferred.

**Fixed (#7): `wire bind-relay` now refuses silent migration when peers are pinned.** Originally the command silently replaced `state.self` with new slot coords, leaving N pinned peers pushing to a dead slot that returned 200 OK to the relay but was never read. The original incident report logged 26 events silently lost over 2 days. v0.5.19 bails by default when `state.peers` is non-empty, naming every affected peer and recommending `wire rotate-slot` (the supported same-relay rotation that emits a `wire_close` event to peers). Operators who actually need the silent path pass `--migrate-pinned` and get a final stderr banner naming the affected peers so there's a shell-history record. Split-offs filed as #14 (sender-side staleness signal in `wire doctor`) and #15 (handle-directory 410 fallback via `whois` re-resolve).

**Hardened (#2): unified daemon liveness + outbox-write normalization.** Beyond the v0.5.13 surface fix. Three call sites in `cmd_status`, `check_daemon_health`, and `check_daemon_pid_consistency` used to compute daemon liveness independently — `wire status` reported DOWN while `wire doctor` reported PASS for 25 min in the original incident because each side had its own definition of "live." All three now consume `ensure_up::daemon_liveness()`, a single snapshot of `(pidfile_pid, pidfile_alive, pgrep_pids, orphan_pids, record)`. The consistency check also gained a liveness gate — a JSON-valid pidfile pointing at a dead pid is now a WARN with explicit reference to the incident, not a silent PASS. Outbox write path: `config::append_outbox_record` now normalizes `peer` through `agent_card::bare_handle` at the writer chokepoint. The v0.5.13 fix was at the two call sites; this makes the on-disk contract self-enforcing for every future caller.

**Hardened (#9): phonebook discovery posture.** Three sub-items. Bilateral pair gate (v0.5.14) is the cryptographic mitigation — these close operator-ergonomics holes that let phishing or correlation attacks succeed via human confusion.

- **#9.1 `discoverable: false` opt-out.** New `discoverable` field on `HandleRecord` and `HandleClaimRequest`. Default `None` = discoverable (back-compat). `Some(false)` = handle omitted from `/v1/handles` bulk listing but still resolves via `.well-known/agent-card.json?handle=X` direct lookup. `wire claim --hidden` writes the flag. Re-claim that omits the field preserves the existing value — stops a v0.5.18 client doing a profile-update re-claim against a v0.5.19 relay from accidentally re-publishing a hidden handle. Two integration tests cover the listing-filter behavior and the re-claim preservation.
- **#9.4 cross-relay phishing guardrail.** `wire add boss@evil-relay.example` (typo / look-alike domain) now emits a stderr WARN naming the unfamiliar domain and the known-good list (`wireup.net`, `wire.laulpogan.com`, operator's own bound relay). Doesn't block — operators have legitimate reasons to cross-relay pair — but the signal lands in shell history.
- **#9.5 second-precision `claimed_at`.** Nanosecond timestamps were a cross-tab fingerprint correlating one operator's multiple handles claimed in the same session. Truncated to seconds at relay-server via `replace_nanosecond(0)`. Display-only field; back-compat is fine.

**Closed (#5): SPAKE2 asymmetric finalize.** Retrospective cross-checked against v0.5.18. The v0.2.4 race is closed via symmetric bootstrap-exchange polling — both sides POST their sealed bootstrap to the relay, both sides poll for the peer's bootstrap, and pin only happens AFTER decrypt + card-signature verification. A narrow window remains (one side pins, peer's network dies mid-handshake) but is much narrower than v0.2.4. Filed as a future hardening note if anyone hits the symptom.

**New: stress harness** (`tests/stress.rs`, 4 tests). Outbox flood (100 sends), concurrent senders (5 threads × 20), bind-relay silent migration detector (caught #7 end-to-end before the fix), send-to-nonexistent-slot detector. Each uses the in-process relay + subprocess `wire` pattern from `e2e_dual_slot.rs`. The bind-relay test originally panicked with `ExitStatus(0)` and empty stderr; post-fix it asserts the bail.

**Test flake fixes.** Two pre-existing flakes — `detached_pair_full_e2e_with_real_daemons` (daemon raced CLI pull, assertion checked the wrong thing — replaced with retry on `wire tail`, the user-visible source of truth) and `wire_add_zero_paste_e2e` (predated v0.5.14 bilateral gate, asserted auto-pin that no longer exists — updated to drive the actual bilateral flow). Both verified failing on the v0.5.18 baseline before the fix.

**Email interop design brief** (#16). Captured a session's research output as `docs/EMAIL_INTEROP.md`. NOT scheduled; ship gate is a yes/no from the threat-model team on a new BRIDGED trust tier. Recommendation: outbound-only `wire send-email` first, defer reply path. Run mail on `mail.wireup.net` subdomain with separate DKIM/SPF/DMARC so the apex isn't poisoned.

**Test count:** 159 lib + 38 cli + 4 stress + 20 relay (+2 new from #9.1) + full e2e — all green. Total ~228 across the suite.

### v0.5.18 — dual-slot integration tests + `pair_drop_ack` carries endpoints[]

Companion to v0.5.17. The ship report explicitly flagged dual-slot routing as "code-review-only, not automated-tested" — this release closes that gap. Three new integration tests (`tests/e2e_dual_slot.rs`) spin up an in-process federation relay AND an in-process `--local-only` relay (different ports on `127.0.0.1`) to exercise the real routing decisions end-to-end.

**Real bug caught and fixed.** `send_pair_drop_ack` (the responder's reply during bilateral pair) only emitted the legacy top-level `relay_url`/`slot_id`/`slot_token` — no `endpoints[]`. The initiator pulling the ack thus only learned the responder's federation endpoint via back-compat synthesis, never their local endpoint. Routing decisions on the initiator side always picked federation even when both sides had a local relay.

- **Fix in `pair_invite.rs::send_pair_drop_ack`** — now reads `self.endpoints[]` via `crate::endpoints::self_endpoints` and includes the full array in the ack body alongside the legacy fields. Pure additive — v0.5.16-and-earlier readers still parse the legacy fields unchanged.
- **Fix in `pair_invite.rs::maybe_consume_pair_drop_ack`** — parses `body.endpoints[]` when present and routes through `crate::endpoints::pin_peer_endpoints` so all endpoints get pinned in `relay_state.peers[handle].endpoints[]`. Back-compat: ack without `endpoints[]` falls back to synthesizing a single federation entry from the legacy fields.

**Three new integration tests** in `tests/e2e_dual_slot.rs`:

1. **`dual_slot_send_prefers_local_endpoint`** — Alice + Bob both have dual slots; after bilateral pair, Alice's `wire push --json` MUST report `scope: "local"` for the delivered event.
2. **`dual_slot_send_falls_back_to_federation_on_local_failure`** — Alice + Bob both have dual slots, but Alice's view of Bob's local endpoint is patched to a closed port. Local POST fails, daemon transparently retries on federation; push --json reports `scope: "federation"`.
3. **`dual_slot_back_compat_v0_5_16_peer_routes_via_federation`** — Alice has dual slots, Bob is federation-only (simulating a v0.5.16 peer). Alice's view of Bob has only the federation endpoint; sends route through federation. Old peers still work cleanly.

**Test count: 156 lib + 35 CLI + 3 new dual-slot e2e** (was 156 + 35 in v0.5.17). Total 194 across the suite.

No protocol or schema changes. Pure correctness fix + integration coverage of the v0.5.17 surface.

### v0.5.17 — dual-slot sessions + local-only relay (OSS coordination layer)

The strategic pair to v0.5.16's per-session identity: **a within-machine transport layer** so sister-Claudes (and sister-Cursors, sister-Aiders, sister-any-agent) coordinate at sub-millisecond latency without going through a public relay. Same-machine traffic stays on the box. Federation through `wireup.net` keeps working unchanged for cross-box traffic. Sessions can hold up to two slots — one federation, one local — and the daemon prefers local when both peers share a local relay.

This is the OSS coordination layer that no vendor would build because it doesn't sell anything: Anthropic / OpenAI / Google can each ship a within-product agent-coordination layer, but none of them can build a cross-vendor, cross-model, operator-owned one without conceding interop. Wire's local relay closes that gap.

**Design summary** (full design in [issue #10](https://github.com/SlanchaAi/wire/issues/10)):

- **`wire relay-server --local-only`** — refuses non-loopback binds (any address outside `127.0.0.0/8` or `[::1]` errors out at startup with a clear message). Skips phonebook listing + well-known agent-card serving — the relay is invisible from off-box and from any phonebook-scraping agent.
- **`wire session new --with-local`** — probes `http://127.0.0.1:8771/healthz` (configurable via `--local-relay`); if reachable, allocates a second slot there and writes both endpoints into the session's `relay_state.json` `self.endpoints[]` array. Falls back to federation-only when the local relay isn't running (logged loudly, not silently).
- **`endpoints[]` data model** — new `src/endpoints.rs` module with `Endpoint { relay_url, slot_id, slot_token, scope }` + `EndpointScope::{Federation, Local}` + `peer_endpoints_in_priority_order` (local-first when both have it) + `pin_peer_endpoints` (preserves v0.5.16 legacy top-level fields for back-compat readers).
- **`pair_drop` body carries `endpoints[]`** — `cmd_add` advertises all our endpoints on the way out; `maybe_consume_pair_drop` + `cmd_add_accept_pending` pin every advertised endpoint via `pin_peer_endpoints`. The v0.5.14 bilateral gate still applies — capability flows only after operator consent on both sides.
- **`cmd_push` walks endpoints in priority order with fallback** — local first if we share a local relay, federation second, transparent fallback on transport error. Each pushed event records which endpoint delivered it in the `--json` output (`endpoint` + `scope` fields).
- **`cmd_pull` reads from every endpoint** — per-scope cursors (`last_pulled_event_id` for federation, `last_pulled_event_id_local` for local — independent so they don't trample each other). One endpoint's failure doesn't kill the pull; loud-fail log + continue against remaining endpoints. Inbox dedup by event_id is the last line of defense.

**Back-compat**: pure additive. v0.5.16-and-earlier clients see only the legacy top-level `relay_url` / `slot_id` / `slot_token` (which point at the federation endpoint, unchanged). New `endpoints[]` field travels alongside. Old peers ingest cleanly; old `relay_state.json` files migrate transparently when the dual-slot path is exercised.

**Threat-model addendum** ([`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)):

- *Local relay implicit trust*: any process on the same machine that can connect to `127.0.0.1:8771` can attempt to deposit a pair_drop. Mitigated by the v0.5.14 bilateral gate (no auto-pin, no auto-ack). Same defense surface as federation.
- *Loopback ≠ secret*: on a multi-user box, other users can bind 127.0.0.1 sockets too. Don't run `--local-only` on a shared box without socket-permission hardening. (Unix-domain socket with `0600` mode would close this; v0.5.17 ships HTTP loopback only.)
- *No TLS on local relay*: bytes travel cleartext over loopback. Acceptable on a single-user laptop (same as any localhost HTTP); document explicitly.

**Tests**: **156 lib + 35 CLI tests passing** (+7 endpoints unit tests — back-compat, dual-slot ordering, local-relay-mismatch filtering, legacy-field synthesis, etc).

**Recommended setup**:

```bash
# Once per machine — start a local-only relay at login.
wire relay-server --bind 127.0.0.1:8771 --local-only &

# Once per project — create a session with dual slots.
cd ~/Source/your-project
wire session new --with-local
eval $(wire session env)
```

Sister-Claudes in different projects on the same box now pair through wireup.net (bilateral) once, then automatically route follow-up traffic through `127.0.0.1` because both sides advertise local endpoints during the pair handshake.

**Open follow-ups for v0.5.18+** (from the design issue #10):

- `wire service install --local-relay` — write a launchd plist (macOS) / systemd user unit (Linux) so the local relay auto-starts at login. v0.5.17 ships manual startup; the service-install convenience is one PR away.
- `wire session pair-all-local` — discover sister sessions via the local relay's directory and bilateral-pair them in one shot. Closes the "N sessions = N² accept gestures" UX pain.
- Unix-domain socket transport — for multi-user-box hardening. The dual-slot machinery already abstracts the endpoint URL; switching local from `http://127.0.0.1:8771` to `unix:/path/to/socket` is mostly a `reqwest` feature flag.

### v0.5.16 — `wire session` for multi-agent-per-machine

When multiple agent sessions ran on the same box (e.g. one Claude Code in `~/Source/wire`, another in `~/Source/slancha-mesh`) they shared a single `WIRE_HOME` — one DID, one slot, one inbox JSONL, one daemon. Peers had no way to address a specific session and cursor advances by either session drained events the other never saw.

**`wire session` subcommand.** Bootstraps isolated per-session `WIRE_HOME` trees under `~/.local/state/wire/sessions/<name>/`. Each session = own identity + own relay slot + own session-local daemon + own inbox/outbox. Sessions pair with each other through any relay (`wireup.net` by default) like any other peer — the bilateral-pair gate from v0.5.14 still applies.

- `wire session new [name]` — bootstrap. With no name, derives one from `basename(cwd)` and caches it in a registry so re-entering the same project reuses the same identity instead of generating a fresh DID each time. Runs `init` + `claim` + spawns the session-local daemon. Outputs the `export WIRE_HOME=…` line for shell activation.
- `wire session list [--json]` — enumerate sessions with handle, DID, daemon liveness, and registered cwd.
- `wire session env [name]` — emit the export line; `eval $(wire session env)` activates the cwd's session.
- `wire session current` — which session does this cwd map to?
- `wire session destroy <name> --force` — kill the daemon + delete state + remove from registry. Irrecoverable (keypair gone).

**Stable per-project identity.** Registry at `~/.local/state/wire/sessions/registry.json` maps `cwd → session_name`. Different cwds with the same basename get a 4-char SHA-256 path-hash suffix.

**Recommended Claude Code setup.** Project-local `.mcp.json` points wire at that project's session via `env.WIRE_HOME=…`. New Claude Code sessions in the same project all share that session's identity; sessions in different projects stay isolated. See `docs/AGENT_INTEGRATION.md#multi-session-on-one-machine-v0516` for the full recipe.

**New module + tests.** `src/session.rs` with path/registry logic + name derivation. **149 lib + 35 CLI tests passing** (+4 session unit tests, +6 session integration tests).

No protocol or schema changes. No relay-side changes. Backwards-compatible: operators who don't use `wire session` keep their existing single-session WIRE_HOME behavior unchanged.

### v0.5.15 — operator-friendly accept surface

Companion patch to v0.5.14. Same bilateral-pair design intent; surfaces the *accept* gesture explicitly across CLI, MCP, README, AGENT_INTEGRATION.md, and the landing page so operators don't have to remember the overloaded `wire add <peer>@<their-relay>` form.

- **`wire pair-accept <peer>`** — explicit CLI alias for bilateral completion. Same semantics as `wire add <peer>@<their-relay>` when a pending-inbound record exists, but takes only the bare handle (relay coords come from the stored drop). The natural operator-side counterpart to `wire pair-reject`.
- **MCP `wire_pair_accept` / `wire_pair_reject` / `wire_pair_list_inbound`** — three new tools so agents can drive the inbound queue end-to-end on the operator's behalf. The MCP `instructions` field is updated to explicitly tell connecting agents: *never auto-accept inbound pair requests without operator consent*.
- **OS toast text** updated to surface both `wire pair-accept` and the `wire add` form (and `wire pair-reject`).
- **`wire pair-list` + `wire pair-list-inbound`** human output now prints `wire pair-accept <peer>` action hints (was `wire add <peer>@<relay-host>`).
- **`wire status`** human-readable inbound line now says `wire pair-accept <peer> to accept`.
- **README** rewritten: section §2 (pair flow) now shows the bilateral two-command flow with both sides; install line bumped to v0.5.15; `wire pair-accept` + `wire pair-list-inbound` added to "What's in the box".
- **landing/index.html** §3 "The console" demo terminals updated to show both sides: B runs `wire add`, A sees OS toast + runs `wire pair-accept`. §2 blockquote updated. §5 MCP table updated with the new tool list.
- **`docs/AGENT_INTEGRATION.md`** adds a "Bilateral pair flow via MCP (v0.5.14)" section with the explicit step-by-step + the "agents must never auto-accept" rule.
- **Tests:** +1 new — `pair_accept_errors_cleanly_when_no_pending_request_v0_5_14` asserts the error message points operators at `wire pair-list-inbound` / `wire add` rather than failing silently. 145 lib + 29 CLI tests passing.

No protocol or schema changes. Pure surface polish on the v0.5.14 security fix.

### v0.5.14 — bilateral-required `wire add` (security)

Closes the v0.5.13-and-earlier **phonebook-scrape pairing vulnerability**: a malicious actor could enumerate the public handle directory, run `wire add <each-handle>@<relay>` against every entry, and have their key auto-pinned at `VERIFIED` tier on every wire user's machine — receiving each victim's `slot_token` via the `pair_drop_ack`, which granted authenticated write access to the victim's slot up to the 64 MB quota.

This release restores the design intent: **`wire add` must fire on both sides before the pair completes.** The receiver's daemon no longer auto-promotes a stranger's signed pair_drop; it lands in a new pending-inbound queue, surfaces via `wire pair-list` + OS toast, and waits for an explicit operator gesture.

**Receiver-side gate (the root fix).** `maybe_consume_pair_drop` was bifurcated:

- *SPAKE2 invite-URL path* (pair_drop carries a pre-shared `pair_nonce`): unchanged. Possession of the invite-URL nonce IS the consent gesture; pin trust, write relay_state, send ack as before.
- *Handle path* (zero-paste `wire add`, no nonce): write to new `state/wire/pending-inbound-pairs/<handle>.json` store. **Do NOT pin trust. Do NOT write our slot_token back. Do NOT advertise relay coords.** OS toast prompts the operator to run `wire add <peer>@<their-relay>` to accept or `wire pair-reject <peer>` to refuse.

**Operator-side completion.** `cmd_add` now checks pending-inbound on every invocation:

- If a pending-inbound record exists for the target handle: bilateral completion. Pin peer as `VERIFIED` with stored coords, send `pair_drop_ack` carrying our slot_token, delete the pending record.
- Otherwise: outbound path (unchanged) — emit signed pair_drop via `/v1/handle/intro/<nick>`, await reciprocal `wire add` from peer.

**New surface.**

- `wire pair-accept <peer>` — explicit bilateral-completion alias for `wire add <peer>@<their-relay>` when a pending-inbound record exists. Same semantics, no relay-host argument needed (coords come from the stored drop). The operator-friendly accept command.
- `wire pair-reject <peer>` — drop a pending-inbound record without pairing. Idempotent.
- `wire pair-list-inbound [--json]` — programmatic enumeration of pending-inbound records (flat array, matching the v0.5.13-and-earlier `pair-list --json` shape for SPAKE2 sessions).
- `wire pair-list` — human-readable output now shows a `PENDING INBOUND` section first with `→ accept with…` action hints, followed by the SPAKE2 session table. **JSON shape unchanged** for back-compat (flat array of SPAKE2 records); inbound items remain accessible via the new commands above.
- `wire status` — `pending_pairs.inbound_count` + `inbound_handles` JSON fields. Human-readable line: `inbound pair requests (N): alice, bob — …` with action hints.

**MCP tools (v0.5.14).** Three new bilateral-pair tools for agents:

- `wire_pair_list_inbound` — enumerate pending-inbound requests for operator review.
- `wire_pair_accept` — accept after operator consent; pins VERIFIED + ships slot_token.
- `wire_pair_reject` — refuse a pending-inbound request without pairing.

The MCP server's `instructions` field now explicitly tells connecting agents: **never auto-accept inbound pair requests without operator consent**. `docs/AGENT_INTEGRATION.md` documents the bilateral pair flow recipe (lines added under "Bilateral pair flow via MCP (v0.5.14)").

**Attack surface after v0.5.14.** An attacker scraping the phonebook and spraying pair_drops produces N records in N victims' pending-inbound queues, **zero VERIFIED pins, zero slot_token leaks, zero spam capability**. Each victim sees one OS toast per attacker; victims who don't manually `wire add` back are fully protected. Inviting a friend zero-paste still works in exactly two commands (one from each side), preserving the v0.5 magic-pair UX.

**Tests:** 145 lib + 28 CLI tests passing (+4 new pending-inbound tests in `tests/cli.rs` — `pair_list_inbound_surfaces_pending_v0_5_14`, `status_reports_pending_inbound_count_v0_5_14`, `pair_reject_deletes_pending_inbound_v0_5_14`, `pair_reject_idempotent_on_missing_peer_v0_5_14`).

**Threat-model addendum:** see THREAT_MODEL.md for the bilateral-pair doctrine + remaining residual windows (third-leg ack race documented in [issue #5](https://github.com/SlanchaAi/wire/issues/5)).

### v0.5.13 — silent-fail eradication round 2 + network resilience

Three threads landed together in response to issues #2 and #6 against v0.5.12:

**A. Issue #2 — outbox + doctor silent-fail bugs.**

- **`P0.A1` outbox filename normalization.** `wire send paul-mac@wireup.net "..."` used to write `outbox/paul-mac@wireup.net.jsonl`, but `wire push` only enumerates files matching pinned peer handles (`paul-mac.jsonl`). 4 events stuck silently for 25 minutes in the field report. New `agent_card::bare_handle` helper strips `@<relay>` at the `cmd_send` and `tool_send` boundaries; on-disk contract (`outbox/<bare_handle>.jsonl`) is now the single source of truth. Adversarial test: `send_with_fqdn_peer_normalizes_to_bare_handle_outbox` asserts FQDN-suffixed file is never created.
- **`P0.A2` outbox orphan-file warning.** `wire push` now scans the outbox dir for `.jsonl` files whose stem isn't a pinned peer; if the bare handle of the stem matches a pinned peer, prints a loud stderr line with the exact `cat … >> …` recovery command. Catches the upgrade path where stale pre-v0.5.13 FQDN files sit on disk.
- **`P0.A3` doctor/status agreement.** Pre-v0.5.13 `wire doctor` ran a pure pgrep count and PASSed "one daemon running" even when that one daemon was an orphan and the pidfile's recorded daemon was dead — `wire status` correctly reported DOWN in the same state. 25 minutes of disagreement before the operator caught it. `check_daemon_health` now consults both pgrep AND the structured pidfile, with explicit FAIL verdicts for the orphan-only and orphan-alongside-pidfile states. Status and doctor cannot disagree on liveness.

**B. Issue #6 — network resilience doctrine.** Three-rule policy now in code:

- **Rule 1: loud transport error class.** New `relay_client::format_transport_error` flattens the `anyhow::Error` source chain and prefixes a class label (`TLS error:`, `DNS error:`, `timeout:`, `connect error:`). `wire push --json` now surfaces the full `invalid peer certificate: UnknownIssuer` instead of the bare URL that hid the TLS failure in Avast/corp-proxy environments. Unit tests cover TLS / DNS / timeout / fallback paths.
- **Rule 2: OS native trust store.** Cargo.toml `reqwest` feature flag `rustls-tls` → `rustls-tls-native-roots`. Both blocking client builders (`relay_client.rs`, `daemon_stream.rs`) now load OS native CAs via `rustls-native-certs`, so corporate proxies, AV cert-resign products, and on-prem CAs validate without manual trust-store gymnastics. No code-side opt-in needed; works on macOS / Linux / Windows.
- **Rule 3: documented escape hatch.** New `WIRE_INSECURE_SKIP_TLS_VERIFY` env var (recognized values: `1` / `true` / `yes` / `on`). When set, builds reqwest clients with `danger_accept_invalid_certs(true)` AND prints a loud red stderr banner exactly once per process. Last-resort operator override for `--insecure` MITM-accepted environments. Documented in THREAT_MODEL.md.

**C. No protocol or schema changes.** v3.1 event envelope unchanged; all existing peers stay paired across the upgrade.

### v0.5.12 — metadata hygiene

Patch release pinning the `slancha-wire` crate rename + repointing crate metadata to live URLs.

- **Cargo.toml `name`** stayed `slancha-wire` (from post-`v0.5.11` rename commit). `v0.5.11` tag predated the rename, so the tag did not match the published artifact on crates.io. `v0.5.12` is the first tag that pins the renamed-and-published state.
- **`homepage` + `documentation`** repointed from `https://wire.slancha.ai` (DNS not yet provisioned — `wire` subdomain doesn't resolve) to the GitHub repo. The previous values shipped a broken link in crates.io metadata.
- No code changes. `wire --version` reports `0.5.12`.

### v0.5.11 — silent-fail eradication + one-command surface

A 30-minute debug session on 2026-05-15 ate four `pair_drop` events because an old `wire daemon` process (PID 54017, started Monday, never restarted) was running stale 0.2.4 binary text in memory under a symlink that had since been repointed at 0.5.10. Cursor advanced past the new-protocol events the old code couldn't process, no log, no rejected entry, no diag. Today's exact pain became this release.

**Six-command public surface.** What 0.5.10 took multiple steps + a manual debug, 0.5.11 does in one command:

- `wire up <nick@relay>` — fresh box to ready-to-pair. Replaces init + bind-relay + claim + daemon-background + remember-to-restart-on-login.
- `wire pair <nick@relay>` — bilateral pin, blocks until VERIFIED or hard-error with cause. Replaces add + poll + wait + verify cycle.
- `wire send <peer> "msg"` — kind defaults to `claim`. Stdin form via `-`. Replaces send-with-mandatory-kind-arg.
- `wire monitor` — long-running line-per-event stream of new inbox events, handshake filtered by default. Replaces `tail -F inbox/*.jsonl | python parse | grep -v pair_drop`.
- `wire doctor` — single diagnostic across daemon + pidfile + relay + pair-rejections + cursor. Replaces 30-minute manual debug.
- `wire upgrade` — kill stale daemons, spawn fresh from current binary, write new versioned pidfile. The fix for today's exact failure mode.

**Silent-fail eradication (the load-bearing fix).**

- **P0.1** — `wire pull` refuses to advance the relay cursor past events the binary can't process (unknown kind, transient verify failures like sender-not-in-trust). Same blocking event surfaces on every retry with `unknown_kind=<N> binary_version=<v>` reason. Today's exact bug class made visible.
- **P0.2** — every `let _ = ...` and `.ok()` drop in pair/relay/push paths replaced with structured warn + a record in new `pair-rejected.jsonl` for `wire doctor` to surface. The bilateral-pin-stalls-invisibly class.
- **P0.3** — `flock` on `relay.json` via new `config::update_relay_state(modifier)`. Multiple wire processes can no longer race the cursor — RMW transactions serialise through the lock.
- **P0.4** — daemon pidfile becomes a versioned JSON record: `{schema, pid, bin_path, version, started_at, did, relay_url}`. CLI compares its own version against the daemon's on every invocation. Mismatch = loud warn. Tolerant reader handles legacy raw-int form for one transition cycle.
- **P0.Z** — every signed event now carries a `schema_version: "v3.1"` field. Pull rejects mismatched-major with locked reason shape `schema_mismatch=<received> binary_supports=<ours>`. Absent field accepted (pre-0.5.11 compat).
- **P0.X** — inbox dedupe on `event_id`. Three duplicate `pair_drop_ack` deliveries no longer produce three inbox lines.

**Operator-visible UX.**

- **P0.M** — `wire monitor` plus an AGENT_INTEGRATION.md recipe + MCP server's `instructions` field tells every agent harness to arm a persistent stream-watcher on session start. Catches "agent didn't notice your message" silently before it happens.
- **P0.Y** — `wire peers` / `wire status` show `PENDING_ACK` for peers we've pinned but haven't received an ack from. No more misleading `VERIFIED` before bilateral pin completes.
- **P0.S** — `wire send` drops mandatory kind arg + accepts `-` stdin / heredoc.
- **P1.6** — `wire doctor` with five checks (daemon, daemon_pid_consistency, relay reachable, pair rejections, cursor).
- **P1.7** — `wire status` cross-checks pidfile with `pgrep -f "wire daemon"`; surfaces orphan daemon processes the pidfile didn't record + version drift loudly.
- **P1.9** — `wire service install` writes the launchd plist (macOS) or systemd user unit (linux) that auto-starts the daemon on login + restarts on crash. Eliminates the "background it with tmux/&/systemd as you prefer" footgun.
- **P2.10** — optional structured diagnostic trace at `$WIRE_HOME/state/wire/diag.jsonl`. `wire diag tail` replays. Off by default; enable per-process via `WIRE_DIAG=1` or per-machine via `wire diag enable`.

**By the numbers.** 14 atomic commits, 140 lib tests passing (was 105 at 0.5.10), one pre-existing integration failure on `detached_pair_full_e2e_with_real_daemons` (fails on the v0.5.10 base commit too — unrelated to this release). Every fix above has an adversarial test that asserts the silent failure is loud, per spark's E. rule. The whole release was paired with `slancha-spark@wireup.net` over wire/v3.1 itself — feedback shaped P0.4 pidfile schema (added `did` + `relay_url`), the schema_mismatch reason shape, and the verified=null monitor-filter guard.

Co-developed with slancha-spark@wireup.net via wire/v3.1.

### v0.5.10 — launch-surface polish + real bug fixes

Pile of small wins from launch-day real-world testing. Server-side new
endpoints, install-script reliability fixes, and a real bug fix in
client-side handle parsing.

**New endpoints on the relay (one binary, no extra services):**

- `GET /stats.html` — parchment-themed dashboard matching landing
  aesthetic, with live counts + 24-hour SVG sparklines for handle
  claims, slot allocations, pair opens, events posted. Auto-refreshes
  every 30s.
- `GET /stats.history?hours=<N>` — append-only JSONL time series at
  `<state_dir>/stats-history.jsonl` (one row per 30s persist tick),
  sliced to the requested window. Default 24h, max 7d.
- `GET /phonebook.html` — standalone yellow-pages directory page
  (Oswald display + Bitter serif + classic yellow background).
  Alphabetical letter dividers, per-entry nick + DID fingerprint +
  motto + vibe tags.
- `GET /openshell-policy.sh` — host-side bootstrap symmetric to
  `/install.sh`: applies the OpenShell network policy a sandbox needs
  to install + run wire.
- `POST /v1/invite/register` + `GET /i/<token>` — short-URL invite
  redirector. `wire invite --share` (new CLI flag) gives the invitor a
  single line — `curl -fsSL https://wireup.net/i/AB12 | sh` — to text
  to a friend; that line installs wire if missing + accepts the invite
  + pairs both sides. `?format=url` returns the raw `wire://pair?...`
  string for programmatic resolution.
- `GET /v1/handles` filters `demo-*` and `test-*` nick prefixes from
  the public phone book (asciinema-cast leftovers were polluting it).

**Short URLs + content negotiation:**

- `/stats` now dispatches on `Accept`: browsers get the HTML dashboard,
  curl/scripts keep getting JSON (back-compat preserved). `/stats.json`
  is a new explicit JSON alias.
- `/phonebook` (no `.html`) and `/install` (no `.sh`) added as cleaner
  social-share-friendly URLs. Old paths still work.
- Cross-page nav tabs (home · phonebook · stats) on all three
  landing pages.

**Install-script robustness:**

- Drops the `api.github.com/repos/.../releases/latest` lookup, which
  hit the anonymous 60 req/hr rate limit on shared NATs (corporate
  proxies, OpenShell sandboxes). Uses GitHub's
  `/releases/latest/download/<asset>` 302-redirect alias instead.
- Detects musl libc on Linux (Alpine, distroless, immutable distros)
  and picks the `unknown-linux-musl` artifact accordingly. The musl
  binaries already shipped in release.yml; install.sh just wasn't
  reaching for them.

**`wire accept` short-URL resolution:**

- `wire accept https://wireup.net/i/<token>` resolves the HTTPS short
  URL via `?format=url` and recurses with the underlying `wire://`
  URL. Previously errored with "url missing inv=" because accept only
  understood the wire:// scheme. Bare wire:// URLs still work.

**Diagnostic + error-message polish (most-hit-in-real-life paths):**

- `wire init --relay` / `wire bind-relay` / `wire rotate-slot` healthz
  pre-flight now surfaces the underlying reqwest error (`{e:#}`)
  instead of `unwrap_or(false)`-collapsing into a generic phyllis
  line. When curl works but wire doesn't, the actual cause (TLS, DNS,
  connect refused, 5xx) finally appears in the error. Also includes a
  curl reproducer + an OpenShell-policy bootstrap hint.
- `wire status --peer <name>` on an unpaired peer now hints the next
  move (`wire add <name>@wireup.net`) instead of a bare
  "unknown peer X in relay state".
- All relay URLs are trimmed of trailing slashes before display
  (`https://wireup.net/` and `https://wireup.net` now produce the same
  error message and the same state-file value).
- `tests/e2e_invite_pair.rs` + `demo-invite.sh` finish the v0.5.7
  DID-suffix sweep that had two leftover `did:wire:paul` (no hex)
  assertions.
- `src/signing.rs::strip_did_wire` marked `#[allow(dead_code)]` (kept
  for a v0.6 caller; was tripping clippy's `-D warnings` in CI).

**Real bug fix in client-side handle parsing:**

- `parse_handle` previously rejected any nick in `RESERVED_NICKS`,
  which — after the v0.5.10 RESERVED_NICKS expansion to include the
  pre-claimed org handles `slancha`, `support`, `abuse`, etc. — made
  those handles unreachable by clients (`wire add slancha@wireup.net`
  failed at PARSE time, before resolution). Split into:
  - `nick_syntax_ok` — length + chars only, used at parse / resolve.
  - `is_valid_nick` — syntax + reservation check, used at CLAIM
    sites (relay `handle_claim`, CLI `cmd_claim`).
  Reserved handles can now be RESOLVED freely; only CLAIMS are
  blocked. All 11 pair_profile tests pass.

**Misc:**

- `landing/og.png` + `twitter:image` / `og:image` meta tags for
  social-link previews.
- README rewritten as a marketing surface (shield badges, "by Slancha"
  attribution, modern handle flow as Quick Start, older flows demoted
  under "Alternative flows").
- Discord invite rotated to permanent `https://discord.gg/dv2Cd3xzPh`.
- Cargo fmt sweep over the v0.5.9 → v0.5.10 churn.

### v0.5.9 — directory + R2/R3/R5 + consent design + cleanup

Operator-visible health now has three layers. `wire send --deadline` adds an
optional signed `time_sensitive_until` field for advisory wall-clock urgency.
`wire responder set/get` lets an operator publish auto-responder health to the
relay, and `wire status --peer <handle>` reports transport reachability, peer
attention freshness, and responder health in one place.

Relays now publish a local phone book at `GET /v1/handles`, with pagination,
case-insensitive `vibe` filtering, and profile-level opt-out via
`wire profile set listed false`. The landing page's "Now ringing" section
fetches that endpoint and renders the first 20 listed handles.

The A2A extension URI moved from the old GitHub namespace to
`https://slancha.ai/wire/ext/v0.5`. Wire is still pre-traction enough for the
clean migration; extension URIs remain opaque identifiers matched exactly by
federation peers.

`/stats` now separates `handle_claims_total` from
`handle_first_claims_total`, so repeated same-DID profile or slot re-claims no
longer inflate the public growth number.

`docs/CONSENT_DESIGN.md` records wire's current stance on cross-machine agent
handoff: wire owns transport, identity is separate, and consent stays
receiver-policy-first until real cross-org delegation pressure justifies a
portable token format.

`src/macaroon.rs` adds speculative, standalone macaroon-style scoped
delegation scaffolding with mint/verify/serialize tests. It is not wired into
the relay, CLI, or event envelope in v0.5.9.

### v0.5.8 — Repo moved to SlanchaAi/wire + DID-suffix call-site sweep

Repo transferred from `github.com/laulpogan/wire` to
`github.com/SlanchaAi/wire`. Old URL auto-redirects for ~12 months;
existing clones can `git remote set-url` to migrate. Stars, forks,
releases, issues, PRs all preserved.

URL updates:
- `Cargo.toml` repository field
- `install.sh` REPO_URL + help text
- README, AGENT.md, CHANGELOG, all *.md files
- `.github/workflows/release.yml` comments
- `landing/index.html` (Slancha-served)
- relay's A2A AgentCard provider URL

PRESERVED (do not change — federation contract):
- `https://github.com/laulpogan/wire/ext/v0.5` — wire's A2A extension
  namespace URI. A2A extension URIs are opaque identifiers, not
  forwardable URLs. Comments added in `relay_server.rs` and
  `pair_profile.rs` explaining why this string MUST stay as the
  original `laulpogan` namespace forever, even though the repo moved.
  Federation peers in the wild match on this exact string.

DID-suffix call-site sweep: v0.5.7's DID change to pubkey-suffixed
form (`did:wire:paul-abc12345`) updated agent-card construction and
the most-visible verify/whoami paths, but ~10 other call sites still
did raw `did.strip_prefix("did:wire:")` and got the suffixed form
back. This caused trust-map (keyed by bare handle) vs relay-state
(keyed by suffixed string) to disagree on the same peer — the
`wire_add_zero_paste_e2e` test caught it: A's daemon consumed B's
`pair_drop` and pinned B in trust as "night-train" but in relay-state
as "night-train-xxxxx", so `wire peers` showed nothing.

Fixed by replacing `did.strip_prefix("did:wire:").unwrap_or(...)` with
`crate::agent_card::display_handle_from_did(...)` at every "extract
handle from DID for routing" site:
- `src/pair_invite.rs` — 4 sites (peer_handle in pair_drop consume,
  peer_handle in accept_invite, our_handle in mint_invite + accept,
  peer_handle in pair_drop_ack consume)
- `src/pair_session.rs` — 2 sites (handle in pair_session_open,
  peer_handle in pair finalize)
- `src/pair_profile.rs` — 1 site (local_handle in whois display)
- `src/mcp.rs` — 2 sites (peer_handle + our_handle_str in wire_add
  tool)
- `src/cli.rs` — 3 sites (post-pair "wire send" print hint,
  peer_handle in cmd_add, our_handle in cmd_add)

The internal `strip_did_wire` helper in `signing.rs` stays raw — it's
used only for canonical signature comparison where the exact DID
string (including any suffix) is the payload.

Tests: `wire_add_zero_paste_e2e` now passes (was failing on v0.5.7
due to the trust-vs-relay-state mismatch). Full suite green.

### v0.5.7 — DID collision fix + R7 listener-lifetime docs

**DID collision bug.** Pre-v0.5.7 DIDs were `did:wire:<handle>` — derived
purely from the human handle the operator typed at `wire init`. Two
operators picking the same handle (or two homes on the same hostname
auto-init'ing from `default_handle()`) produced **identical DIDs**
despite different keypairs. Cryptographic signature verification still
worked (sigs verify against the pubkey, not the DID string), but every
identifier that routed by DID string — peer-map keys, inbox file paths,
trust-map lookups — was ambiguous.

v0.5.7+ DIDs are `did:wire:<handle>-<8-hex-of-sha256(pubkey)>`. Pubkey
suffix is appended at card-build time, so the DID is uniquely tied to
the keypair by construction. Two operators sharing the handle `paul`
get distinct DIDs `did:wire:paul-a12b34c5` and `did:wire:paul-9f8e7d6c`.

Schema changes:
- `did_for_with_key(handle, public_key)` — new constructor, returns
  pubkey-suffixed DID. Used at `wire init`, `wire claim`, agent-card
  build, trust-self-pin.
- `did_for(handle)` — legacy constructor kept for backward-compat
  test fixtures + display helpers. New code should use the keyed form.
- `display_handle_from_did(did)` — strips both the `did:wire:` prefix
  and the v0.5.7+ pubkey suffix when present, returning the bare
  handle for filesystem paths, trust-map lookups, OS toast titles.
  Auto-detects legacy vs v0.5.7+ DID format.
- Agent card gains a top-level `handle` field (mutable display name)
  separate from `did` (immutable identifier). Identifier-extraction
  sites that previously did `did.strip_prefix("did:wire:")` are
  updated to prefer `card.handle` and fall back to
  `display_handle_from_did`.

Backward-compat: legacy DIDs of the form `did:wire:paul` continue to
verify signatures (the verify path reads pubkey from `verify_keys`).
display_handle_from_did handles both forms transparently. No state
migration required for pre-v0.5.7 deployments.

Call sites updated:
- `src/cli.rs` — cmd_init, cmd_status, cmd_whoami, cmd_send,
  cmd_pair_initiate, inbox-write path in run_sync_pull
- `src/mcp.rs` — tool_whoami, tool_status, peer-listing
- `src/pair_session.rs` — init_self_idempotent
- `src/signing.rs::verify_message_v31` — handle extraction for trust
  lookup
- `src/trust.rs` — add_self_to_trust now uses keyed DID;
  add_agent_card_pin prefers card.handle
- `tests/cli.rs`, `tests/e2e_handle_pair.rs`, `tests/e2e_bilateral.rs`
  — assertions updated to accept pubkey-suffixed DIDs

**R7 listener-lifetime docs.** From the 2026-05-12 incident report:
agents conflating /loop iteration teardown with wire listener teardown
cause exactly the silent-channel problem the incident root-caused.
Added AGENT.md section codifying:
- Monitor (Claude Code) / SSE subscriber is session-lifetime, not
  loop-iteration-lifetime
- Do NOT TaskStop a listener as part of /loop teardown between cycles
- v0.5.6+ daemons include the SSE subscriber for free; running
  `wire daemon` IS the listener, no separate Monitor needed

Tests: 162+ pass on changed surfaces (lib + cli + relay + handle-pair
+ bilateral). `tests/e2e_detached_pair.rs` has a pre-existing local-
only flake on this Spark machine (verified pre-existing on clean
v0.5.4 HEAD and unchanged by v0.5.7); CI in clean container has been
green through v0.5.4 → v0.5.6.

Deferred to v0.5.8: R2 (`time_sensitive_until` field), R3
(responder-health events), R5 (3-layer health distinction in
`wire status --peer`). These were originally scoped into v0.5.7 but
split out to keep the DID fix bisectable.

### v0.5.6 — R1 phase 2: daemon subscribes to the SSE stream

Second half of R1 from `docs/INCIDENT_REPORT_2026_05_12_AGENT_ATTENTION_LAYER.md`.
Builds on the v0.5.5 relay-side SSE endpoint. The daemon now opens its
own slot's stream on startup and uses it as the wake signal for the
polling loop. End-to-end effect: a peer's `wire send` reaches the
recipient's local inbox in tens of milliseconds — at least as long as
the receiver has `wire daemon` running. The 5-second polling cadence
(and the 25-minute /loop-iteration cadence that triggered the
2026-05-12 incident) become irrelevant for any connected peer.

How it works:
- New `src/daemon_stream.rs` module — spawns a dedicated thread on
  daemon startup that opens `GET /v1/events/<own_slot>/stream` against
  the operator's configured relay using their own `slot_token`. The
  thread parses SSE `data:` lines as they arrive and signals a
  `std::sync::mpsc::channel` on every event.
- Daemon main loop replaces `std::thread::sleep(interval)` with
  `wake_rx.recv_timeout(interval)` — sleeps until either (a) the next
  poll-interval tick OR (b) a stream wake-up, whichever comes first.
  On wake, the loop drains any accumulated wakes (multiple stream
  events coalesce into a single pull) and runs the normal
  `run_sync_push` + `run_sync_pull` + `pending_pair::tick` cycle.
- Polling stays in place as the safety net. Stream-down does NOT mean
  events-down — the regular interval still ticks and re-fetches via
  `list_events`. If the stream errors or disconnects, the subscriber
  reconnects with exponential backoff (1s → 2s → 4s → 8s, capped 30s).
- One-way wake signal, not the data path. The actual event verify +
  inbox write goes through `run_sync_pull` so we keep signature
  verification, dedup, and trust enforcement on the exact same path as
  polling. The stream only changes WHEN pull runs, not HOW.

Failure model:
- Relay restart: stream closes cleanly, subscriber reconnects in 1s.
- Network partition: read returns `Err`, backoff retry to 30s cap.
- Daemon hasn't been paired yet (`relay-state.self` empty): subscriber
  errors with "relay-state missing", sleeps for backoff, retries — by
  the time `wire claim` or `wire pair` populates state, the next
  reconnect picks it up automatically. No daemon restart required.
- `wire daemon --once` (one-shot CI mode): subscriber thread is NOT
  spawned. Single-cycle behaviour unchanged.

MCP integration (free): the inbox-watcher introduced in v0.2.0 fires
`notifications/resources/updated` on every new line written to
`state/wire/inbox/<peer>.jsonl`. With v0.5.6 the daemon now writes to
inbox in ~10ms instead of ~5s, so a connected Claude Code session
subscribed to `wire://inbox/<peer>` sees the same near-real-time push.
No new MCP tool needed — `wire_subscribe` is unnecessary because the
existing resource-subscription path is now stream-driven.

Operator-visible:
- Running `wire daemon` now logs occasional `daemon-stream: ...` lines
  on connect/disconnect/reconnect for observability.
- Pulls fire on stream events rather than (just) every 5s, so the
  "pulled=N" log lines come in bursts matching peer activity instead
  of at clockwork intervals.
- `wire daemon --once` unchanged (CI use case).

Tests: 48+ pass on changed surfaces (relay/cli/mcp_pair/handle_pair
suites). e2e_detached_pair has a pre-existing local-only flake on this
Spark machine (verified pre-existing on clean v0.5.4 HEAD); CI runs in
a clean container and was green on v0.5.4 + v0.5.5.

### v0.5.5 — R1 phase 1: server-sent-events push stream on relay

First half of R1 from the agent-attention-layer postmortem
(`docs/INCIDENT_REPORT_2026_05_12_AGENT_ATTENTION_LAYER.md`). Eliminates
the polling-cadence floor for connected peers: when peer B opens an SSE
stream against their own slot, every `post_event` from peer A reaches B
in milliseconds instead of waiting for B's next ~5s daemon pull.

New protocol surface:
- `GET /v1/events/:slot_id/stream` — Server-Sent Events endpoint, auth'd
  by `slot_token` (same gate as `list_events`). Returns
  `Content-Type: text/event-stream`. On open the relay registers an
  `UnboundedSender` on the slot's subscriber list; every subsequent
  `post_event` to that slot fans out the event as `data:
  <event-json>\n\n`. The connection stays open until the client
  disconnects.
- Keepalive comment `phyllis: still on the line` emitted every 30s so
  Cloudflare tunnel + nginx don't time-out the upstream.
- Subscriber sees events posted AFTER it subscribed. To catch up on
  history first, clients should `GET /v1/events/:slot_id?since=` before
  opening the stream — same model as Kafka/Redis pubsub.

Implementation:
- Inner state gains `streams: HashMap<String, Vec<UnboundedSender>>` —
  per-slot active subscriber channels. `post_event` walks the
  subscriber list after a successful disk persist and broadcasts; dead
  channels (peer disconnected) are pruned lazily on `tx.send` returning
  `Err`.
- Disk-persist runs BEFORE broadcast, so durable stream readers and
  cold-start `list_events` readers observe the same set of events.

Deferred to v0.5.6:
- Daemon-side subscriber loop (`wire daemon` opens the stream on its own
  slot, falls back to polling on disconnect with exponential backoff).
- `wire daemon --stream-only` flag for no-poll operation when the stream
  is reliable.
- MCP-side `wire_subscribe` tool that surfaces stream events as
  `notifications/resources/updated` to connected Claude Code sessions
  (closes R1 in full).

Tests: 162+ pass (160 previous + 2 new SSE tests in tests/relay.rs):
- `sse_stream_pushes_event_to_subscriber` opens stream, posts event,
  asserts the event_id arrives on the SSE response within 2s.
- `sse_stream_rejects_wrong_token` asserts 403 on missing/wrong auth.

Operator-visible: nothing today. Daemon still polls. The endpoint is
live on prod (`https://wireup.net/v1/events/<slot_id>/stream`) for
external tools (MCP servers, watchdogs, custom integrations) to consume
now. Daemon adoption ships in v0.5.6.

### v0.5.4 — R4: `wire send` attentiveness pre-flight + phyllis voice on hot errors

From the 2026-05-12 agent-attention-layer incident report (R4 in
`docs/INCIDENT_REPORT_2026_05_12_AGENT_ATTENTION_LAYER.md`): when sending
to a peer, the CLI now does a best-effort relay probe of the peer's slot
freshness and warns the operator on stderr if the peer hasn't pulled
recently. Never blocks the send.

New protocol surface:
- `GET /v1/slot/:slot_id/state` on the relay — auth'd by slot_token,
  returns `{event_count, last_pull_at_unix}`. Updated on every
  `list_events` call.
- `RelayClient::slot_state()` — best-effort client probe; HTTP failures
  return `(0, None)` so the pre-flight degrades gracefully.

New CLI behaviour: `wire send <peer>` checks the peer's slot state and
emits one of:
- silent if peer pulled within last 5 min
- `phyllis: <peer> hasn't picked up in Nm — message will queue, but they
  may be away.` if last pull > 5 min ago
- `phyllis: <peer>'s line is silent — relay sees no pulls yet.` if peer
  has never pulled

The send always queues the event to the outbox. The warning is advisory
— exactly the signal the operator needed in the 2026-05-12 incident
where peer's auto-responder was OAuth-broken and silently dropping
inbound for 10 hours while wire transport stayed green.

Also rolls in the **phyllis voice** rewrite of the six hottest user-
facing error strings (per BRAND_BRAINSTORM.md §9): handle validation,
relay healthz failure, slot not claimed, slot already taken, SAS digit
mismatch, outbox empty. Tests updated to match new vocabulary.

162 tests pass (160 + 2 new slot_state tests).

### v0.5.3 — Bugfix: `wire claim` is actually one-step

Caught by live-smoke against the production relay: `wire claim <nick>` on a
fresh `WIRE_HOME` (no prior `wire init`, no prior `wire bind-relay`) was
bailing with `error: no slot allocated; run \`wire bind-relay <url>\` first`.
That breaks the "ONE STEP" UX promise of v0.5 — the operator-facing pitch
since v0.5.0 has been *single command, zero prior setup*. v0.5.0 → v0.5.2
shipped this gap.

`cmd_claim` in `src/cli.rs` now calls `pair_invite::ensure_self_with_relay()`
exactly the way `cmd_add` and `cmd_pair` already did — auto-init identity if
missing, auto-allocate relay slot if missing, then claim. Idempotent on
already-initialized homes.

New regression test `claim_from_fresh_home_one_step` in
`tests/e2e_handle_pair.rs` codifies the invariant so future refactors
re-introducing the bail-on-uninit check fail CI immediately.

Operator-visible: a brand-new install can now do `wire claim
coffee-ghost@wireup.net` and have everything (identity, slot, handle) come
into existence in one command, exactly as advertised. Same fix is already
in MCP-tool form via `wire_claim`.

### v0.5.2 — Rebrand to wireup.net + Cargo.toml bump

Default relay URL bumped from `wire.laulpogan.com` to `wireup.net` across `pair_invite.rs::DEFAULT_RELAY`, `cli.rs` `--relay` defaults (3 commands), `pair_profile.rs` doc-comments and tests, `mcp.rs` tool descriptions, `README.md`, `AGENT.md`, `SPEC_v0_5.md`, `TESTING_FOR_FRIENDS.md`, `AWESOME_LISTS.md`, `LAUNCH_POSTS.md`, `COMPETITIVE_v0_5.md`, and the landing site. Cloudflare tunnel `wire` now routes `wireup.net` + `relay.wireup.net` to the same relay backend, with `wire.laulpogan.com` + `relay.laulpogan.com` kept alive indefinitely as legacy aliases (no forced migration; v0.4 deployments still work).

Smoke against prod: `curl https://wireup.net/healthz` → 200, `curl https://wireup.net/.well-known/agent-card.json?handle=<nick>` → A2A AgentCard with wire extension, `curl https://relay.wireup.net/healthz` → 200. Both legacy hostnames still 200.

Also rolls in the missed `Cargo.toml` version bump that should have shipped alongside the v0.5.1 + v0.5.2 feature commits but didn't — manifest is now `0.5.2` to match commit-message claims. Single tag at this commit covers both the federation work (v0.5.1) and the rebrand (v0.5.2).

### v0.5.1 — Client-side A2A AgentCard consumption

`resolve_handle()` now tries `/.well-known/wire/agent` first, falls back to A2A's `/.well-known/agent-card.json` on 404, and looks for a wire extension under standard `extensions[].params`. Wire becomes a citizen of the A2A v1.0 ecosystem both as **server** (serves A2A schema with wire fields under extensions) and **client** (consumes A2A cards from any v1.0 implementation: MSFT Agent Framework, agent-card-go, agent-card-python, A2A .NET SDK).

If the A2A card has a wire extension, full mailbox pairing works. If not, wire returns a degraded payload — still useful for `wire whois` display, but `wire add` refuses cleanly because there's no relay slot to drop into.

New: `RelayClient::well_known_agent_card_a2a()`, `pair_profile::verify_wire_native_payload`, `pair_profile::unwrap_a2a_to_wire_payload`.

Bidirectional interop with the 150+ orgs shipping A2A integrations. Federation strategy in `COMPETITIVE_v0_5.md`.

### v0.5.0 — Three-layer identity: DID + handle + profile

What ships:
- **`pair_profile.rs`** module — handle parser (`nick@domain`, 2-32 lowercase chars, reserved-nick list), profile schema, write+sign, `resolve_handle()` via remote `.well-known/wire/agent`.
- **Relay handle directory** — `POST /v1/handle/claim` (bearer-auth'd by slot_token, FCFS on nick, same-DID re-claims allowed for profile/slot rotation), `POST /v1/handle/intro/:nick` (auth-free pair-intro endpoint, gated to kind=1100 `pair_drop` / `agent_card`), `GET /.well-known/wire/agent?handle=<nick>` (WebFinger-style resolver returning signed card + slot coords).
- **CLI** — `wire claim <nick>` to register, `wire whois <nick@domain>` to resolve, `wire profile set/get/clear <field> <value>` to edit personality, `wire add <handle>` for the headline zero-paste pair.
- **MCP tools** — `wire_add`, `wire_claim`, `wire_whois`, `wire_profile_set`, `wire_profile_get`. Agents express personality + discover peers without operator paste.
- **Bilateral close-the-loop** — daemon-pull consumes nonce-less `pair_drop`s (open-mode policy, default on, opt-out via `policy.json: { accept_unknown_pair_drops: false }`), pins the peer, then emits `pair_drop_ack` (kind=1101) carrying our slot_token. Sender's daemon consumes the ack and completes the bidirectional pin. Both sides can `wire send` after ~1-2 seconds.
- **e2e tests** — `tests/e2e_handle_pair.rs` covers full `wire add` flow + FCFS conflict (159 tests pass).
- **demo-hotline.sh** — 5 agents with distinct vibes (coffee-ghost 👻, tide-pool 🌊, kuiper 🛰️, bramble 🪴, marginalia 📖) claim handles, build a fully-meshed 5-graph via 10 zero-paste `wire add`s, ring-send signed messages. New CI `demo-hotline` job.

Trust model: pair-by-handle anchors on DNS + relay `.well-known` (operator who owns `wireup.net` decides who maps to `<nick>@wireup.net`). Same texture as Mastodon — handle ownership = domain ownership. Pubkey is canonical underneath; the handle is renameable without breaking peer references.

Backward compatible with v0.4 invite URLs and v0.3 SPAKE2 + SAS — both flows remain available. Spec: `SPEC_v0_5.md`.

What's deferred to v0.5.1+: petnames (Nostr NIP-02 local nick overlay), `now` field auto-update from MCP tool calls, handle rotation events, `wire rename` for renaming with broadcast.

## v0.4 — one-paste invite pair

The v0.4 line collapses pairing from a 4-step ceremony (host code, join, voice-compare SAS, type digits on both sides) into a single paste. Operator on A runs `wire invite`, gets a URL. Operator on B runs `wire accept <URL>`. Done. Both pinned. Equivalent UX to Discord invite link / Zoom join URL / Signal group invite.

### v0.4.0 — Invite URL: single-step pair, zero-config bootstrap

`wire invite` mints a self-contained bearer URL carrying A's signed agent-card, relay coords, slot_token, and a single-use pair_nonce. The token format is `wire://pair?v=1&inv=<urlsafe_b64_payload>.<urlsafe_b64_sig>`.

`wire accept <URL>` does everything else: auto-inits the local agent if it isn't yet (hostname-derived handle), auto-allocates a relay slot, pins the issuer from URL contents, then POSTs a signed `pair_drop` event (kind=1100) to the issuer's slot using the slot_token the URL granted. The issuer's daemon recognizes pair_drop events with matching pending_invite nonces, verifies the embedded card sig, and completes the bilateral pin on its next pull cycle. The original SPAKE2 + SAS flow remains available for paranoid operators.

Trust model: pasting the URL is the authentication ceremony. Equivalent to clicking a Discord invite, Zoom join URL, or Signal group invite. Possession of the URL = authorization to pair. Single-use by default; multi-use via `--uses N`. 24h TTL default.

What shipped:
- New `pair_invite.rs` module with mint/parse/accept + daemon-side `maybe_consume_pair_drop` hook.
- `wire invite [--relay URL] [--ttl N] [--uses N] [--json]` CLI command.
- `wire accept <URL> [--json]` CLI command.
- MCP tools: `wire_invite_mint`, `wire_invite_accept`. Zero-config from agent prompts.
- Daemon pull loop consumes `pair_drop` events before trust check; pins sender atomically with trust + relay-state writes.
- Bug fix in daemon-pull cursor persistence: in-loop relay-state writes (e.g., new peer pins) were being clobbered by the cursor-update write at end-of-loop. Both `wire pull` and `wire daemon` paths now re-read state before writing the last-pulled-event-id cursor.
- 3 e2e integration tests: full one-paste pair, zero-config B-side auto-init, expired-invite rejection.

What's deferred to v0.5: `consumed_at` field on relay push response (helps disambiguate "stored but not pulled" from "delivered + pulled"); registry-based discovery for true zero-coordination peer lookup.

## v0.3 — detached pair (daemon-orchestrated)

The v0.3 line addresses the original blocking-foreground UX in v0.2: pair-host/-join used to block the operator's terminal for up to 5 minutes waiting for the peer to show up. Now the handshake runs in the background under `wire daemon`, and three push channels — OS toasts, MCP `notifications/resources/updated`, daemon stderr log — surface SAS digits when ready.

### v0.3.9 — `wire status` shows daemon + pending pair counts
Quick operator diagnosis: `daemon: running (pid 12345)` or `DOWN`, plus `pending pairs: 2 (polling=1, sas_ready=1)`. JSON output gains `daemon` and `pending_pairs` keys.

### v0.3.8 — Multi-pair concurrent stress test
Codifies the per-code isolation invariant of `pending_pair::LIVE_SESSIONS`: paul (1 daemon) hosts 2 concurrent detached pairs with alice + bob, each gets distinct SAS digits, all four confirm cleanly, both pair-list entries drain. 141 tests pass.

### v0.3.7 — Real-daemon e2e test
Codifies the manual public-relay smoke test as cargo: two long-running `wire daemon` subprocesses + local relay drive the full detached flow via CLI. ~3.5s wall clock. DaemonGuard's Drop catches daemon-leak bugs.

### v0.3.6 — `--json` on detached CLI + AGENT.md MCP detached section
`--json` flag added to `pair-host --detach`, `pair-join --detach`, `pair-list`, `pair-confirm`, `pair-cancel`. Same shape as MCP tool responses. AGENT.md gains an MCP detached-pair section listing the 5 new tools and the subscribe-once pattern.

### v0.3.5 — 5 detached-pair MCP tools
`wire_pair_initiate_detached`, `wire_pair_join_detached`, `wire_pair_list_pending`, `wire_pair_confirm_detached`, `wire_pair_cancel_pending`. Agents can now drive the full detached flow via MCP without shelling out. Includes integration test covering initiate → list → wrong-digits-abort → right-digits-confirm → cancel.

### v0.3.4 — Detached pair abort-toast + terminal-file GC + live e2e
OS toast on aborted transitions (handshake error, digit mismatch, daemon-restart) so the operator sees the failure even if the originating terminal closed. Terminal-state files older than 3600s are GC'd on each tick. Live e2e on wireup.net validated end-to-end (paul ↔ willard VERIFIED + signed send/recv).

### v0.3.3 — Auto-start daemon + MCP push test + `wire pair --detach`
`pair-host --detach` and `pair-join --detach` now call `ensure_daemon_running()` before queuing — no more "did you forget to run `wire daemon`?" foot-gun. `wire pair <handle> --detach` mega-command added. New MCP push integration test verifies subscribing to `wire://pending-pair/all` actually fires notifications on status transitions.

### v0.3.2 — Pending pairs push into live MCP agents
`resources/list` advertises `wire://pending-pair/all`. The MCP watcher thread polls the pending-pair directory each 2s, tracks per-code status fingerprints, and emits exactly one `notifications/resources/updated` per real transition. Connected agents see the SAS in chat without polling.

### v0.3.1 — Daemon pushes pair SAS to desktop
OS toast fires on `polling → sas_ready` ("wire — pair SAS ready (30-XYZ) · Digits: 554-002 · wire pair-confirm 30-XYZ 554002") and on `confirmed → paired`. Extracted the existing per-platform toast functions into a new `os_notify` module shared with `wire notify`.

### v0.3.0 — Detached pair: daemon-orchestrated push UX
The big one. `wire pair-host --detach` writes a pending-pair file and exits in ~10ms. The daemon's tick loop drives the handshake through a 6-state state machine (`request_host` → `polling` → `sas_ready` → `confirmed` → finalized). Confirm via `wire pair-confirm <code> <digits>` from any terminal. New `pair-list`, `pair-cancel`, `pair-host --detach`, `pair-join --detach` commands. SPAKE2 secret lives in daemon memory; restart-recovery via PID file marks transient sessions `aborted_restart` so the operator re-issues with a fresh code.

---

## v0.2 — friction patches from real-world install attempts

The v0.2.6 → v0.2.9 hot-fix line was driven by a cross-org pair attempt with `willard-spark` (Windows host) that surfaced bugs the local dogfooding missed.

### v0.2.9 — pair-join/host emit waiting heartbeat every 10s
Both sides used to go silent during `pair_session_wait_for_sas`. Now `... still waiting (10s / 300s)` lines fire so the operator sees the process is alive while the peer connects.

### v0.2.8 — `wire pair-abandon` for stuck-slot recovery
If a client crashes mid-handshake (process killed, OOM, network blip) after `pair_open` succeeded but before SAS, the relay-side slot used to stay bound for the 5-minute TTL — subsequent `pair-join` attempts hit 409 "guest already registered". New `wire pair-abandon <code>` + relay endpoint `POST /v1/pair/abandon` releases the slot. Idempotent.

### v0.2.7 — `wire pair <handle>` single-shot bootstrap
Collapses the four-step bootstrap (`init` + `pair-host`/`pair-join` + `setup --apply`) into one. Default relay baked in. Idempotent identity init.

### v0.2.6 — Windows install + correct Claude Code config path
Two real bugs caught by `willard-spark` from a Windows install (Git Bash):

1. `install.sh` had no Windows branch — Windows operators had to `gh release download` manually. Patch detects MINGW/MSYS/CYGWIN/Windows_NT and appends `.exe`.
2. `wire setup --apply` was writing to `~/.config/claude/mcp.json` — that path doesn't exist for Claude Code on ANY platform. Claude Code reads `~/.claude.json` everywhere. Now surfaces both paths as targets.

---

## v0.2.5 and earlier

See git history. Highlights: v0.2.5 introduced reactor anti-loop guards (rate-limit + chain-depth via `(re:X)` marker tracking). v0.2.0–v0.2.4 brought MCP pair tools, push notifications via `wire://inbox/*` resources, `wire setup`, `wire notify`, and `wire reactor`.
