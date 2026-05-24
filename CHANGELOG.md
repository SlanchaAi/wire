# Changelog

All notable changes to wire are tracked here. Format: 
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), 
semver-ish.

Generated from git tag annotations; for richer context see 
the PR description linked in each section.


## [v0.13.2] — 2026-05-24

**v0.13.2 — Windows hardening + `wire setup --statusline`.** Three Windows bugs (found by a paired Windows session dogfooding v0.13.1 over wire) plus the long-missing persona statusline and removal of the dead reactor:

- **relay.json torn-write fixed (CRITICAL).** A foreground `wire dial` racing the background daemon corrupted `relay.json`: both did a non-atomic, lockless `fs::write`, interleaving into invalid JSON ("trailing characters at line N") that broke ALL push/pull until hand-repaired. `write_relay_state` now writes via tmp+rename **and** holds the existing `relay.lock` flock (the RMW path calls an unlocked inner to avoid re-entrant deadlock). The race was cross-platform; Windows file-sharing semantics made it easy to hit.
- **`wire status` / `doctor` false-DOWN fixed.** Daemon-liveness had duplicate Linux/Unix-only copies (`ensure_up::pid_is_alive`, `daemon_liveness`'s `pgrep`, `ensure_up::process_alive`, `pending_pair::process_alive`) running `kill -0` / `pgrep` — absent on Windows → always false → daemon reported DOWN while alive. All now route through the already-Windows-correct `platform::process_alive` / `find_processes_by_cmdline` (tasklist / PowerShell CIM). Same root cause behind the `wire up` / `upgrade` 500 ms self-spawn probe orphaning `wire.exe`.
- **`wire setup --statusline`.** Installs a Claude Code statusLine showing your persona — liveness dot + emoji + nickname in the persona's accent color + cwd (`● 🪻 bright-camellia · ~/project`). Writes a bundled renderer + merges a `statusLine` block into settings.json (preserves keys, refuses to clobber invalid JSON, idempotent, `--remove` to uninstall, honors `$CLAUDE_CONFIG_DIR`). Closes the gap where personas existed but nothing installed the statusline that displays them.
- **`wire reactor` removed.** The `claude -p` shell-out reactor was superseded by live-session monitoring + auto-reply baked into the MCP instructions; removed the command, handler, helper, and landing section.
- **Same-box discovery fixed (v0.13 regression).** v0.13 moved session homes under `sessions/by-key/<hash>`, but `list_sessions` only scanned the top level (so every v0.13 session was invisible to `wire session list-local` / `pair-all-local`), and `sessions_root()`'s inside-session fallback only walked one level up (so an inside-session `WIRE_HOME` resolved to a nonexistent nested dir). Both fixed: `list_sessions` descends into `by-key/` (labeling each home by its persona), and `sessions_root()` walks up to the nearest `sessions` ancestor. Same-box sisters are visible to each other again. (The broader in-band local-pairing UX — additive `add-peer-slot`, loopback-relay dial, a leak-safe same-box pair verb — is tracked separately in `docs/V0_13_2_PLATFORM_HARDENING.md`.)
- **`wire upgrade` is now session-scoped — fixes daemon accumulation on Windows (critical).** Repeated `wire upgrade` spawned fresh daemons without killing the old ones (glossy-magnolia: 2→5→8→11 over three cycles — real multiple daemons racing the pull cursor). The old design was box-wide (kill every `wire daemon` process found, wipe every session's pidfile, respawn every session), which is wrong for a multi-session / shared-relay box AND broke on Windows: the CIM scan can't match the quoted `"...\wire.exe" daemon` command line (no contiguous `wire daemon`), so it found nothing to kill, then the respawn loop accumulated. `wire upgrade` now refreshes only THIS session: it kills this session's own daemon via its **pidfile pid** (reliable, CIM-independent) plus any TRUE orphans (`wire daemon` owned by no session), and SPARES sibling sessions' daemons and the shared `127.0.0.1:8771` relay-server (killing it would break every same-box session's loopback). Each session refreshes itself on its own `wire upgrade`.
- **`wire monitor` no longer dies silently.** wisp-blossom saw `wire monitor` exit 1 with zero output when a cursor-block (untrusted signer's pair event) tripped the watcher — indistinguishable from "still watching." The poll loop now surfaces the error to stderr and keeps watching instead of exiting on a swallowed `?`.
- **Re-dial no longer clobbers a peer's local endpoint or bleeds the federation token (E3-dial).** `wire dial peer@relay` (→ `cmd_add`) REPLACED the whole peer entry with a flat federation-only one and seeded the federation token from the entry's *top-level* `slot_token`. After a prior local `add-peer-slot`, that top-level token was the LOCAL token — so re-dialing made the federation endpoint inherit a stale local bearer (federation delivery would 401), and dropped the local endpoint entirely. Now the federation endpoint is merged additively into `endpoints[]` (local preserved), and its token is seeded only from a prior *federation* endpoint on the same relay (re-dial of an already-acked peer), never a local one — empty until the `pair_drop_ack` lands otherwise. (glossy-magnolia pinpointed the re-pin path; add-peer-slot itself was innocent.)
- **`wire add-peer-slot` is now additive (E3).** It used to REPLACE the whole peer entry, so pinning a local loopback slot clobbered the peer's federation endpoint — the peer became loopback-only and lost its public route (glossy-magnolia + wisp-blossom repro). Now it merges into the peer's `endpoints[]` (upsert by relay_url), mirroring `bind-relay`'s additive semantics, so a local slot ADDS to the federation route instead of dropping it.
- **Orphan-daemon detection is session-scoped (A2).** On a multi-session box (wire's core use case) every session runs its own daemon, but the orphan check flagged any `wire daemon` whose pid ≠ this session's pidfile as an orphan — so sibling sessions' legitimate daemons showed as orphans, `wire doctor` FAILed on a healthy shared box, and `wire upgrade` would cross-session-kill a sibling's daemon. A true orphan is now a wire daemon owned by NO session: detection excludes every session's pidfile pid (`session_daemon_pid` across `list_sessions`), not just the current one.
- **Daemon now services ALL slots, not just the primary (E2).** `run_sync_pull` (the background daemon's pull) only pulled `self_primary_endpoint` — the federation slot — so a session that additively bound a local loopback slot never had it serviced by the daemon (same-box loopback messages silently undelivered until a manual restart re-seeded the startup-only stream subscriber). Now it pulls every self endpoint with an independent per-slot cursor (`self.cursors.<slot_id>`), one endpoint's failure doesn't stall the others, and the legacy global cursor stays in sync with the primary for back-compat. (Manual `wire pull` was already multi-slot; this brings the daemon in line.)
- **No more phantom "?" sisters in `list-local` (E8).** `maybe_adopt_session_wire_home` created a session home unconditionally on every resolution — before any identity existed — so transient/probe session keys left permanent empty homes that surfaced as phantom handle-less sisters (degrading the same discovery the by-key fix restored). Homes are now created lazily on first real write, and `list_sessions` skips homes with no agent-card.

## [v0.13.1] — 2026-05-24

**v0.13.1 — one name, one command. Identity UX simplified; the last "same handle" leak closed.** A persona review found the one-name promise (v0.11) was still violated in several places, and that the real fix was to stop letting anyone *type* a name they will not get.

- **One-name now holds on EVERY init path.** `init_self_idempotent` — the auto-init used by `wire claim`, MCP `wire_init`, and all pairing — previously used the machine **hostname** (`default_handle()`) as the handle and never applied the persona derivation that `wire init` did. Result: every auto-initialized session on a box became `did:wire:<hostname>-<fp>`, all displaying the same hostname after the fp-strip — a second, more visible root of the Windows "every new session has the same handle" bug (v0.13 fixed the colliding HOME; this fixes the colliding displayed name). Both branches now derive the persona from the keypair fingerprint, so distinct sessions always get distinct fp-derived personas. Re-init with a different typed handle is now an idempotent no-op (the typed handle is vestigial) instead of an error.
- **Onboarding is one nickless command.** `wire up [relay]` does everything (init + bind + claim your persona + local dual-bind + daemon) and no longer takes a `<nick>` — your handle *is* your DID-derived persona, so there was never a name to type. Accepts `@wireup.net`, a bare host, a full URL, or nothing (defaults to the public relay).
- **`wire init`, `wire claim`, `wire identity publish` are hidden.** All three accepted a name the one-name rule ignores — terrible UX (you type `alice`, you get `winter-bay`; worse, on a fresh box the ignored name could be the invalid hostname and the command would fail). They are folded into `wire up` and removed from `--help`, kept callable for scripts/offline keygen. `wire init`'s handle arg is now `Option` (`None` = no typed name); `wire claim`/`wire_claim` coerce any typed nick to your persona (MCP `nick` is now optional + advisory).
- **`landing/install.sh` was stale.** The installer embedded in the relay and served at `wireup.net/install.sh` was an older, separate script showing a 3-step `init` → `claim` → `add` flow with the deprecated `wire add` verb — the first thing every new user saw, contradicting the model. Now byte-identical to the canonical root `install.sh` (one-command `wire up`, canonical `wire dial`, Windows MSYS/Cygwin detection, post-install `wire upgrade` stale-cleanup pass).
- **README quick-start** rewritten around `wire up` + the one-name model (dropped the pre-v0.11 `wire init alice` → `winter-bay (alice)` two-name example).

## [v0.13.0] — 2026-05-24

**v0.13 — session-keyed identity.** Replaces the cwd-registry + machine-wide-default session model with a host-agnostic session-key chain (`WIRE_SESSION_ID` > `CLAUDE_CODE_SESSION_ID` > legacy cwd-detect). Each session resolves to a unique, deterministic, cwd-independent WIRE_HOME (`sessions/by-key/<sha256(key)[:16]>`), so two sessions can never collapse onto a shared default. Fixes the Windows "every new session gets the same handle" bug at the root — there is no path string to mis-normalize or miss.

- **MCP startup auto-bootstraps** a fresh session home once (one-name init + federation slot + phonebook claim), so each session is its own reachable, claimed identity. Gated on `WIRE_MCP_SKIP_AUTO_UP` + already-initialized; best-effort on network.
- **Behavior change:** two windows in the same project are now DISTINCT identities (previously shared, via the bug). Existing sessions re-key on first run under v0.13.
- **Deferred:** migration bridge, GC of orphaned session homes (see the design spec). **The Windows fix is provisional until verified on a real Windows box.**

Design: `docs/superpowers/specs/2026-05-24-session-keyed-identity-design.md`.

## [v0.12.3] — 2026-05-24

**v0.12.3 — auto-collaborate, baked in.** The MCP server `instructions` (shipped in the binary, read by any agent that connects `wire mcp`) now DIRECT connecting agents to: (1) arm a persistent `wire monitor` stream-watcher on session start so peer messages surface live, and (2) reply to peer messages in their own live context without waiting for the operator to prompt them. Previously this was a soft "recommended"; now it's a baked-in directive, so anyone who installs wire gets auto-collaboration between paired agents — no per-machine hook required.

## [v0.12.2] — 2026-05-24

**v0.12.2 — persona rename cleanup.** Finishes the `character` → `persona` surface rename from v0.12.

Fixed:
- `wire session list` / `wire here` column header was still `CHARACTER` → now `PERSONA`.
- `wire init` one-name message said "DID-derived character" → "DID-derived persona".
- `docs/STATUSLINE.md` jq examples read the old `.character.palette` JSON key (returns `null` since v0.12's key rename) → fixed to `.persona.palette`, with persona terminology throughout and a naming note.

## [v0.12.1] — 2026-05-24

**v0.12.1 — `wire up` claims the persona; phonebook shows the face.** Closes the last one-name gap from v0.12.

Fixed:
- **`wire up <nick>@<relay>` now claims your DID-derived PERSONA, not the typed `<nick>`.** Under the v0.11 one-name rule the typed nick is vestigial (it can't select an identity), but `up`'s claim step was still registering it on the relay — re-opening a two-name split (claimed handle ≠ persona). `up` now resolves the persona from the freshly-inited card and claims that. It also no longer bails when the typed nick differs from the existing persona (the mismatch isn't an error — the nick is ignored).
- **Phonebook (`/v1/handles`) now shows the DID-derived emoji next to every name**, even when the claimant set no explicit profile emoji. The relay computes `Character::from_did(did).emoji` as a fallback, so `🦨 pine-puffin` renders instead of a bare `pine-puffin`.

## [v0.12.0] — 2026-05-24

**v0.12 — additive multi-relay, zero-config dual-bind, persona surfacing.** Onboarding and identity-surface polish on top of the v0.11 one-name rule.

Added:
- **`wire bind-relay` is additive.** Binding a new relay appends to `self.endpoints[]` instead of overwriting, so an agent can hold a local relay AND a federation relay simultaneously. New `--scope <federation|local|lan|uds>` (inferred from the URL by default) and `--replace` (the old destructive single-slot behavior, still guarded against black-holing pinned peers). A new-relay bind never black-holes pinned peers — resolves issue #7 by design.
- **`wire up` opportunistic local dual-bind.** After the federation bind+claim, `wire up` additively binds a local relay slot for sub-millisecond same-box sister routing. `--with-local <url>` overrides the default `http://127.0.0.1:8771` probe; `--no-local` opts out. Local relays carry no handle directory, so nothing is claimed there.

Changed:
- **Persona surfacing.** The serialized output key `character` → `persona` (and `character_override` → `persona_override`) in `wire whoami` / `here` / `peers`. MCP `wire_whoami` and `wire_peers` now include the persona (nickname + emoji + palette) — previously they emitted only the raw handle. `wire notify` OS toasts now show the persona (`wire ← 🦨 pine-puffin`) instead of the handle. The internal Rust `Character` type name is unchanged.

Fixed:
- **MCP `wire_dial`** read a required `handle` arg while the schema provided `name`, so every dial over MCP errored `missing 'handle'`. It now reads `name` and routes federation handles correctly.
- **MCP `wire_init` with `relay_url`** no longer no-ops the relay binding when the identity is already initialized but unbound — it binds the requested relay (additively) so a subsequent `wire claim` doesn't 404.

Breaking:
- Consumers parsing the `character` JSON key from `wire whoami` / `here` / `peers` (e.g. statusline scripts) must read `persona` instead.

## [v0.11.0] — 2026-05-23

**v0.11 — one immutable name.** The DID-derived character nickname IS the addressable handle. Operator-typed `wire init <name>` arg is ignored at init time; agent-card.handle is synthesized from the keypair fingerprint via Character::from_did so every peer sees you by the same name everywhere (statusline, `wire peers`, federation handle, inbox/outbox file path, route results, mesh-status, commit trailers). Closes the long-running "two names" footgun where a UI nickname could differ from the wire address.

Breaking:
- `wire identity rename` removed — there is no separate rename verb. If you want a different face, regenerate your identity (new DID → new character).
- `agent-card.handle` no longer reflects the `wire init <name>` argument. It is `Character::from_did(synthesized_did).nickname`. Init now prints "operator-typed `<X>` ignored in favor of DID-derived character `<Y>`. Peers will reach you as `<Y>`" when the two differ.
- Production code paths (already-paired check in `session pair-all-local`, `drive_bilateral_pair`, `cmd_session_mesh_status`) now key the in-memory peers map by handle, not session name — previously they conflated session name with handle and the local-sister pair-accept could fail when a session's directory name differed from its character.

Compat:
- `Character::from_did` now seeds from the 8-hex fingerprint suffix only (not the full DID string) to break the circular dependency where handle change → DID change → character change → infinite loop. Legacy DIDs without the `-<fp>` suffix fall through to the v0.10 seed-the-whole-DID behavior.
- Federation flow (`wire add <h>@<host>`) is unchanged on the wire — peers still reach you by your card handle, which is now always the character.

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

