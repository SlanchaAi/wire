# Changelog

All notable changes to wire are tracked here. Format: 
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), 
semver-ish.

Generated from git tag annotations; for richer context see 
the PR description linked in each section.


## [v0.9.5] — 2026-05-23

v0.9.5 — shell completions (bash/zsh/fish/elvish/powershell) + interactive init prompt


## [v0.9.4] — 2026-05-23

v0.9.4 — split wire accept into wire accept + wire accept-invite (kill smart-dispatch ambiguity)


## [v0.9.3] — 2026-05-23

v0.9.3 — conversational surfaces (wire here, prose pending, emoji fallback, README rewrite)


## [v0.9.2] — 2026-05-23

v0.9.2 — helpful errors (fuzzy resolution, miss-returns-empty in JSON, deprecation banner suppressed in JSON + once-per-session)


## [v0.9.1] — 2026-05-23

v0.9.1 — surface cleanup (hide deprecated, smart-default init, JSON-when-piped, quiet auto-detect)


## [v0.9.0] — 2026-05-23

v0.9.0 — clean cut

Six operator-facing verbs (was ~20):
  wire dial / send / pending / accept / reject / whois

One canonical public name per identity (DID-derived character).
Operator-rename is local-display-only — no longer publishes on
agent-card.

Structural fixes (silent-fail class closed):
- wire init refuses slotless sessions (root cause of 2026-05-23 incident)
- single self_primary_endpoint() reader everywhere
- wire send auto-pairs on miss for local sisters
- wire dial routes federation via @relay
- 12 legacy pair verbs collapse to 3 (pending/accept/reject)
- legacy verbs still work but emit deprecation banner (v1.0 removes)

PR #35 merged. Pre-existing test flake (detached_pair_survives_
daemon_restart_mid_handshake) carried over from main; unrelated.

Co-Authored-By: 🛡 noble-creek <wire+wire-b6f47edb@wire.id>


## [v0.7.5] — 2026-05-23

v0.7.5 — nickname-add + silent-fail pair_drop_ack fix


## [v0.7.3] — 2026-05-23

v0.7.3 — thorough cross-platform wire upgrade + AGENT.md §0.5

`wire upgrade` now sweeps daemons AND relay-servers, refreshes
installed service units to point at the new binary path before the
OS auto-respawns, and works on Windows (was hard-fail pre-0.7.3).

Cosmetic fix: `wire session list` now reports correct daemon
liveness on Windows (was always `down` because kill -0 is unix-only).

AGENT.md §0.5 redirects local agents to `wire session pair-all-local`
instead of the federation `wire pair-host` / `wire pair-join` flow
they kept reaching for.

New `src/platform.rs` exposes cross-platform process_alive /
find_processes_by_cmdline / kill_process primitives.

PR #32, merged. Full suite (193) green.

Co-Authored-By: 🛡 noble-creek <wire+wire-b6f47edb@wire.id>


## [v0.7.2] — 2026-05-23

v0.7.2 — Windows service backend (Task Scheduler)

Closes the cross-platform parity gap: `wire service install` and
`wire service install --local-relay` now register hidden, restart-
on-failure, run-at-logon scheduled tasks on Windows via schtasks.exe
+ Task Scheduler 1.2 XML.

LeastPrivilege + InteractiveToken — no UAC, no stored password.
Matches the user-scope footprint of launchd's gui/<uid> + systemd
--user paths.

PR #31, merged. Linux + macOS paths unchanged. Full release suite
(190 + 3 bind + 8 service) clean.

Co-Authored-By: 🛡 noble-creek <wire+wire-b6f47edb@wire.id>


## [v0.7.1] — 2026-05-23

v0.7.1 — wire session bind

Adds `wire session bind <name>` to attach an existing session to the
current cwd without going through destroy+new. Fixes the case where
a registered ancestor dir (e.g. `~/Source`) is shadowing leaf-project
identities, collapsing two CC sessions onto the same Character.

PR #28, merged 92af54b. Doc sweep 7b85d15.

Behavior:
- `wire session bind` (no name) auto-derives from basename(cwd)
- Errors loudly if the named session doesn't exist
- Idempotent: re-binding to the current binding is a no-op
- Re-binding to a different session overwrites with a stderr warning
- Uses update_registry (flock-serialized) so it composes safely with
  concurrent MCP auto-init writes

Tests: 3 new session_bind_* in tests/cli.rs. Full suite 190 + 3 pass.

Co-Authored-By: 🛡 noble-creek <wire+wire-b6f47edb@wire.id>


## [v0.7.0] — 2026-05-23

v0.7.0 — identity lifecycle + scope-aware routing + UDS transport

The v0.7.0-identity alpha track (22 commits) lands four arcs:

- Deterministic Character per session: DID-hash → emoji + adj-noun nickname
  + 256-color palette. Operator-stable visual ID across sessions, statusline,
  peer listings, commit trailers.
- `wire identity` lifecycle CLI: create / persist / publish / demote /
  rename / show / list / destroy. Anonymous-mode sessions (local-only,
  no federation) can be promoted to federation slots later; published
  identities can be demoted back to local-only.
- Operator-chosen overrides preserved across renames; palette stays
  DID-derived for hash-stability.

- EndpointScope enum unifies Federation / Local / Lan / Uds.
- Priority order: Uds → Local-loopback (with matching self) → Lan → Federation.
- Per-endpoint cursors for pull; per-endpoint dispatch for push.
- `post_event_to_endpoint(endpoint, event)` helper: scheme-aware POST
  that routes `unix://...` via uds_request, everything else via reqwest.

- Hand-rolled HTTP/1.1 over UnixStream (axum 0.7 serve is TcpListener-only).
- `wire relay-server --uds /path/to/sock` for same-host trust-anchored IPC.
- `wire session new --with-uds` allocates UDS slots.
- Same-uid, same-host sister-session shape — see project_wire_transport_substrate_research.

- Cross-machine same-network reachability between Federation and Local.
- Tailscale CGNAT (100.64.0.0/10) bind acceptance for `--local-only`.

- demo-hotline: fixed pair-accept-in-drain-loop regression (broken since
  v0.5.14 anti-phonebook-scrape change removed receiver auto-promote).
  All 5 ring sends now land. (#27)
- Clippy clean across all alpha-track commits.
- 190 tests pass.

- Holistic codebase audit at .planning/research/codebase-audit-2026-05-23.md
  with critique iteration. P0 priorities surfaced for v0.7.x and v0.8.

22 alpha commits preserved via merge commit (not squashed).

Co-Authored-By: 🐻 cedar-bayou <wire+wire-source-d8ae94a5@wire.id>

