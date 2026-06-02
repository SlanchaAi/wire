# Changelog

All notable changes to wire are tracked here. Format: 
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), 
semver-ish.

Generated from git tag annotations; for richer context see 
the PR description linked in each section.


## [v0.14.2] — 2026-06-01 (UNRELEASED)

**v0.14.2 — the multi-session ops batch: silent-send class closed, `--all-sessions` supervisor architecture lands, three hotfixes caught by live dogfood.**

honey-pine's 2026-06-01 multi-system dogfood (#162) surfaced an interlocking set of bugs that broke wire's daemon layer on any operator with more than one session: silent send failures, daemon-up-but-not-syncing on launchd, false-negative `wire status`, tier flap, notification storms. This release closes all of them and the architectural rework needed to keep them closed.

13 PRs since the v0.14.1 tag. No trust ladder change, no protocol bump (v3.2 still the constant). Operator action required after upgrade: re-run `wire service install` (idempotent) so the launchd plist / systemd unit picks up the new `wire daemon --all-sessions --interval 5` ProgramArguments. `wire upgrade` does this automatically when a service was previously installed.

### Silent-send class closed (honey-pine's #162 bug report)

- **Send-lifecycle log + `pending_push_count` (#167).** Each successful relay POST appends `<outbox_dir>/<peer>.pushed.jsonl` so the caller can audit "queued → pushed" lifecycle. `wire_status` (MCP) now surfaces `pending_push_count` — the count of events in the outbox that have NOT yet appeared in the pushed log. With `stale_sync == true`, that's the diagnostic for the silent-send class honey-pine reported.
- **Canonical `to:` DID on outbound send (#165).** Pre-fix `wire send` wrote `to: did:wire:<peer-handle>` (bare); peers running v0.14.x rejected on `to:` mismatch against their full `did:wire:<handle>-<fingerprint>`. `cmd_send` / `tool_send` now resolve the canonical pinned DID via the new `trust::resolve_peer_did`. This was THE silent-drop root cause; honey-pine's "BUG 1" closed.
- **Durable `bilateral_completed_at` field stops tier flap (#166).** `effective_peer_tier` previously read slot_token presence to compute "VERIFIED vs PENDING_ACK". Re-pinning peer endpoints (which legitimately rewrites the slot_token block) made the tier flap. `bilateral_completed_at` is set monotonically on receipt of pair_drop_ack; never cleared. `pin_peer_endpoints` preserves it across re-pin events.
- **Daemon-down lifecycle visibility (#163).** Per-process pidfile singleton guard with same-pid Drop preservation. `last_sync.json` written after every cycle so `wire_status` can report `last_sync_age_seconds` distinct from "any `wire daemon` process exists".
- **Send response includes `daemon_seen` + `stale_sync` (#164).** `wire_send` (MCP) annotates its response with daemon-health hints so a caller seeing `status: queued` immediately knows whether the daemon is actually running and pushing or just silently no-op'ing into an outbox no daemon will drain.
- **Stale `pending_inbound` clear on bilateral completion (#171).** When `maybe_consume_pair_drop_ack` flips a peer to bilateral-VERIFIED via the inbound ack path, any leftover `pending_inbound` record from the earlier pair_drop is cleared idempotently. Pre-fix: VERIFIED peer lingered in `pending_pairs.inbound_handles` ("sunlit-aurora" in honey-pine's report).
- **Daemon stream resilience (#168).** SSE subscriber's TCP keepalive tightened from 60s → 30s. New `stream_state.json` writer tracks `state` (connecting/connected/reconnecting/error), `last_event_at`, `reconnect_count`. Surfaces via `wire_status`. honey's "BUG 2" closed.

### Supervisor architecture (honey-pine's launchd diagnosis)

- **`wire daemon --all-sessions` supervisor (#170).** Multi-session orchestrator: reads the session registry, fork-execs one child `wire daemon` per initialized session with `WIRE_HOME` env pinned to that session's home dir. Per-machine singleton on `<sessions_root>/supervisor.pid`. 10s registry-poll, rapid-failure backoff (1s → 60s cap), session-removal kill, pre-spawn pidfile check so operator-spawned tmux daemons coexist. Launchd plist + systemd unit + Windows task XML ProgramArguments updated. Closes the launchd-blind cwd-resolves-default-WIRE_HOME failure mode honey-pine spent multiple sessions diagnosing.

- **🚨 Supervisor fork-bomb hotfix (#174).** Caught immediately via live dogfood of #170 on a 133-session box. Supervisor was passing `--session <character-name>` to each child as a belt-and-suspenders check, but `session_dir(name)` only resolves the legacy v0.6 top-level layout — v0.13 by-key sessions where `name` is the persona handle bailed. Fix: drop the redundant flag entirely; `WIRE_HOME` env is the sole contract.

- **🚨 TLS hotfix: `rustls-tls-native-roots` → `rustls-tls-webpki-roots` (#176).** Also caught via the same dogfood pass. Once the supervisor put every daemon in launchd, every TLS handshake to wireup.net failed `UnknownIssuer`: launchd-spawned processes don't inherit Aqua-session keychain access on macOS, so `rustls-native-certs` returned an empty root set. Mozilla's bundled webpki-roots work in any process context. Trade-off: corporate CA / AV-resign transparency lost; operators use the existing `WIRE_INSECURE_SKIP_TLS_VERIFY=1` escape hatch. Proper dual-roots verifier filed as #177.

- **`wire daemon --session <name>` resolves v0.13 by-key (#180).** Operator-facing counterpart to #174: `cmd_daemon`'s `--session` resolver now uses the new `session::find_session_home_by_name` which handles both v0.6 top-level and v0.13 by-key/persona-handle layouts.

### Multi-session observability (honey-pine's "wire daemon status" ask)

- **CLI status surface gap closer (#169).** `pending_push_count` + `stale_sync` + `stream_state` (added to MCP `wire_status` in #167/#168) hoisted into CLI `wire status`. Shared helpers in `config.rs` (`compute_pending_push_count`, `read_stream_state`, `stale_sync`) so MCP / CLI / future doctor stay in lock-step. Plain-text `wire status` adds three lines in operator-triage order: last sync → pending push → stream.

- **Orphan-pid session annotation (#173).** When `wire status` flags orphan `wire daemon` processes (pidfile pid ≠ pgrep), each one now annotates with cmdline + parsed `--session` arg. Helps operators distinguish a stale leftover from a legitimate per-session child the supervisor is managing.

- **Per-session pidfile walk for annotation (#175).** Post-#174 supervisor children no longer carry `--session` in their cmdline, so `parse_session_arg` misses them. New `session::pid_to_session_map` walks every session's `<home>/state/wire/daemon.pid` and builds `{pid: session_name}`. `cmd_status` consults the map first when annotating orphans; falls back to cmdline `--session` arg. Bonus: fixed a latent bug in `session::session_daemon_pid` where a legacy bare-integer pidfile silently returned None because the JSON parser swallowed it as a Number without a `.pid` field.

- **`wire supervisor` CLI (#178).** New top-level command. `wire status` answers "is THIS session syncing?"; `wire supervisor` answers "what is the supervisor (and every session's daemon) doing across the box?". Pretty output collapses to one summary line when every session is healthy; JSON emits the full per-session topology. Closes honey-pine's BUG 3 ("wire daemon status CLI") ask.

- **🚨 Cross-process toast dedup (#179).** Caught via live operator complaint within minutes of #176 landing. The 134-daemon supervisor turned the existing in-process `Mutex<HashMap>` toast dedup into theater — every daemon polled its own inbox, every daemon fired its own toast, the operator saw the same notification 134 times within seconds. Fix: cross-process atomic claim via `O_CREAT|O_EXCL` on a sha256-named touch file under `<cache_dir>/wire/toast-dedup/`. Once a key is claimed, no wire process anywhere on the host re-emits — ever. Bare `toast()` now defers to `toast_dedup()` with a content-hash key so the 5 legacy bare-toast sites inherit the cross-process guarantee without per-site changes.

### Identity / enrollment

- **`wire enroll republish` refreshes `capabilities[]` (#172, closes #126).** slate-lotus's v0.14.1 audit found that republish bumped `schema_version` v3.1 → v3.2 but left `capabilities=["wire/v3.1"]` stale, opening a stealth-skip vector for any future cap-gated feature. `rebuild_card_with_current_claims` now refreshes the wire/* entry to the binary's current `CARD_SCHEMA_VERSION` while preserving operator-defined non-wire caps (custom task tags, future feature flags) in their original order.

### RFC-004 (Willard's contributions)

- **AC-HP7 heartbeat body roundtrip proptest (#160).** Property-based test verifying that heartbeat bodies encode → relay → decode → re-encode → decode losslessly. WILLARDKLEIN.

### CI + repo hygiene

- **Re-run-friendly CI flake noted.** `uds_request_round_trips_200_with_body` hit again in this batch (the 4th observed instance per `feedback_uds_round_trips_ci_flake`). Recommend dedicated investigation alongside the dual-roots TLS work (#177); not yet a release blocker.

### Operator notes

- `wire upgrade` AUTOMATICALLY refreshes installed service units (rewrites plist / systemd unit with the new ProgramArguments). 0.14.1 → 0.14.2 operators don't need to manually re-run `wire service install` unless `wire upgrade` is skipped.
- The `--all-sessions` supervisor manages every session by default. To opt out (e.g. one specific session running in a tmux pane), the operator-spawned `wire daemon` claims the pidfile first and the supervisor's pre-spawn check honors it.
- Notification dedup state survives across daemon restarts. To re-see a notification class: `rm -rf ~/Library/Caches/wire/toast-dedup` (macOS) or `~/.cache/wire/toast-dedup` (linux).


## [v0.14.1] — 2026-05-30

**v0.14.1 — v0.14.x DX completion: identity layer visible end-to-end, operator quality-of-life fixes.**

Closes every documented v0.14.0 follow-up plus operator-felt UX gaps surfaced during heavy dogfooding. 12 PRs since the v0.14.0 tag, no trust ladder change, no protocol bump (v3.2 was already the constant). All cards remain backward-compatible with v3.1 readers.

### Identity layer visible end-to-end

- **CLI op-claims surfacing (#114).** `wire whoami` / `wire peers` / `wire whois` JSON + human output now surface inline `op_did` / `op_pubkey` / `op_cert` / `org_memberships` / `schema_version` when present on the stored card. Pre-patch: the marquee v0.14 identity layer existed on disk but was stripped by every read surface — operators couldn't tell from `wire whoami --json` whether enrollment had taken. Single helper `cli::op_claims_from_card` centralizes the field list; pre-v0.14 / unenrolled cards surface identically (no JSON `null`-spam).
- **MCP op-claims surfacing (#115).** `mcp__wire__wire_whoami` and `mcp__wire__wire_peers` extend the same shared helper, closing the parallel-serializer gap (CLI and MCP had separate hard-coded JSON shapes that both stripped op_*).
- **MCP `wire_whois` bare-nick (#122).** Previously rejected bare nicks with `missing '@' separator`, even when the nick was a pinned peer or local sister already in the trust ring. Now routes through `cli::resolve_name_to_target` first (mirroring `wire whois <name>` in the CLI), federation handles fall through unchanged. Closes the agent-discovery surface for v0.14's marquee identity layer.
- **`schema_version` write-side bump (#121).** Cards carrying op claims now emit `v3.2` (was stuck at `v3.1` despite v0.14 fields). Bumps at `agent_card::with_identity_claims` via the new `max_schema_version` helper. Monotonic — a card already at `v3.5` (hypothetical future extension peer) is NOT downgraded. Numeric parse so `v3.10 > v3.2` (not lexicographic). Readers can now discriminate "carries op claims" from the version field alone.
- **`wire enroll republish` (#110).** Rebuilds the stored card with the **current** enrollment state and republishes. Closes the enroll-after-`init` DX gap: claims are normally attached at card-build time, but an operator who enrolls AFTER `init` had a stored card that pre-dated the claims. Idempotent: not-enrolled rebuilds a claims-free card; not-bound prints "local only".

### Operator quality of life

- **`wire quiet on/off/status` (#117).** Operator kill switch for desktop toasts. File-based (`<config_dir>/quiet`) for per-session silence + env-based (`WIRE_NO_TOASTS=1`) for launchd-spawned daemons. Both check at the single `os_notify::toast` guard — disabled means disabled, no dedup leakage. Status reports mechanism (`via file` / `via env` / `none`).
- **`wire upgrade` warns about stale `wire mcp` server subprocesses (#123).** `wire upgrade --local` swaps daemons but not the `wire mcp` server subprocesses that Claude Code / Claude.app pin at session start (macOS mmap semantics keep the old code in already-open processes when the file path is replaced). Now `--check`, action-run, and the `--json` shape surface the stale MCP pid list with explicit "each Claude tab must `/mcp` reconnect" guidance. The MCP procs are NEVER added to the kill set — killing them would disconnect every tab's wire toolset until each one explicitly reconnects. Warn-only, behavior unchanged.
- **Drop redundant `WIRE_SESSION_ID` env mapping in `wire setup` (#124).** Closes the MCP Config Diagnostics validator warning `Missing environment variables: CLAUDE_CODE_SESSION_ID`. Modern Claude Code (verified 2026-05-30) propagates `CLAUDE_CODE_SESSION_ID` into every MCP subprocess by default; wire's `session::resolve_session_key` reads it natively as a fallback. The historical mapping `{"WIRE_SESSION_ID": "${CLAUDE_CODE_SESSION_ID}"}` was duplicating a value wire already had AND triggering the validator warning. Dropped from the `wire setup` template; the existing fallback chain preserves per-session identity exactly.
- **Notify-mode wiring (#112 → shipped via #113 by branch-state accident).** The receive-side `notify` org-policy mode parses to `FileOrgPolicy::Notify` and routes the pending-stash toast through an enriched org-aware path (`notify-pair:<handle>` dedup key, "org-verified pair request from `<handle>`" wording). Pre-patch: `notify` parsed-but-unwired since v0.14.0; the generic toast fired regardless. Default-deny + `ORG_VERIFIED` ceiling + auto-wins-over-notify property all preserved.

### CI + repo hygiene

- **CI serializes test threads (#111).** `cargo test --all-targets -- --test-threads=1` eliminates heavy-e2e parallel-self-contention (a busy-polling subprocess-spawning e2e was starving sibling real-daemon e2es under `--test-threads=$(nproc)`).
- **Dead code removed (#118).** `signing::strip_did_wire` (added with `#[allow(dead_code)]` "kept for v0.6 — once a caller exists" comment) was never adopted; `agent_card::display_handle_from_did` covers the same need. Repo `#[allow]` count 4 → 3.
- **Repo-wide format-arg modernization (#119).** `cargo clippy --fix -- -W clippy::uninlined_format_args` across 14 files: `format!("{}", x)` → `format!("{x}")` and the same for `println!` / `eprintln!` / `assert_eq!` / `panic!` / `anyhow!` / `bail!` / `write!`. Net −16 LOC.
- **RFC-001 typo fix (#109).** "doubled" → "tail length quadrupled (8 hex → 32 hex)" in the rationale for op/org DID suffix width.

### Docs

- **SSO connectors prompt (#113 + #116).** `docs/PROMPT_v0.15_sso_connectors.md` — self-contained, paste-able prompt for the v0.15 SSO-connector buildout (auth flow runner + token lifecycle + verify + group/role enumeration + SCIM 2.0 ingest + deprovisioning hooks + CLI + card-emit + receive-side branch). 21 providers spec'd; 9 hard constraints; 12-PR landing order. Iterated via #116 to fold in the v0.14.x regression-debug lessons (CLI+MCP serializers must stay in lock-step via the shared helper; dual-surface JSON-RPC tests; post-`/compact` branch-state verification; MCP-server-pin in `wire upgrade`).
- **Repo-scrub prompt (#120).** `docs/PROMPT_repo_scrub.md` — durable artifact encoding the bounded-cleanup discipline (5-phase order of operations, per-PR `done` definition, suggested cuts by priority, anti-patterns to instant-reject, stop conditions).

### Net diff

Lib: 341 → 355 tests (+14 across the surfacing + identity + cleanup PRs). No release-surface protocol change. No trust ladder mutation. Six cross-platform binaries (`aarch64-apple-darwin`, `x86_64-pc-windows-msvc`, `aarch64-unknown-linux-{gnu,musl}`, `x86_64-unknown-linux-{gnu,musl}`) + `.sha256`s built via `release.yml` on tag push.


## [v0.14.0] — 2026-05-29

**v0.14.0 — RFC-001 identity layer: operator + organization + project, fully-offline self-certifying.**

Ships the offline-minimal subset of [RFC-001](docs/rfc/0001-identity-layer.md) — three optional, orthogonal-axis claims on the agent-card (`op_did`, `org_memberships[]`, `project`), a new tier `ORG_VERIFIED` between `UNTRUSTED` and `VERIFIED`, and the smallest receive-side surface that closes the N²-pair-discovery problem inside trust scopes without weakening the v0.5.14 phonebook-scrape closure or the bilateral SAS invariant.

The shipped design is **fully-offline self-certifying.** Each card carries `op_pubkey` and a per-membership `org_pubkey` inline; each operator/org DID is a hash commitment to its key (`agent_card::long_fingerprint` = first 16 B of `sha256(pubkey)`), so an attacker can't substitute an inline pubkey without breaking the DID match. `identity::verify_op_cert` / `verify_member_cert` take the inline pubkeys directly — no resolver, no registry, no `did:web`, no DNS-TXT, no `/v1/org/claim` on the pairing hot path. (Those = v0.15, per the "Implementation status (as-built, v0.14)" note added to the RFC in #106.)

- **`wire enroll` CLI (#99, #102).** Three subcommands: `wire enroll op --handle <h>` mints this machine's operator root key + prints `op_did`; `wire enroll org-create --handle <h>` mints an organisation root key + prints `org_did`; `wire enroll org-add-member <op_did> --org <org_did>` issues a membership cert binding the operator to the org and stores it locally. Keys saved 0600 under `config/wire/{op.key, orgs/<sanitized>.key}`; memberships persisted in `config/wire/memberships.json`.
- **Card-emit wiring (#103, #104).** When an enrolled agent runs `wire init` / `pair_session::init_self`, the card-build path attaches `op_did` + `op_cert` + `op_pubkey` + every stored membership inline before signing. **Fail-soft:** a corrupt identity config (unparseable `memberships.json`, etc.) degrades to "no claims" + a stderr warning rather than breaking card-build — `init` / `up` are critical-path and must never fail because of a stored-config parse error. Not-enrolled cards are byte-identical to v0.13 cards; v3.2 readers tolerate both schemas.
- **Receive-side auto-pin (#101).** When a peer pair_drop arrives carrying a v3.2 card with a verified membership in an org the receiver has explicitly opted into (`config/wire/org_policies.json` → `{"orgs":{"<org_did>":{"inbound":"auto"}}}`), the receiver auto-pins the peer at `ORG_VERIFIED` and emits the pair_drop_ack — bypassing the default-deny pending gate for that org. **Fail-closed:** an empty / missing / malformed policy file → no auto-pin → default-deny intact. A peer whose membership doesn't commit to the inline org_pubkey (substitution attempt) is rejected at `evaluate_card_membership`.
- **`Tier::OrgVerified` < `Tier::Verified` (#90).** Strict by `trust::tier_order` (NOT a derived `Ord`). An auto-pinned org-mate satisfies `>= ORG_VERIFIED` policy checks but NOT `>= VERIFIED` — bilateral SAS (SPAKE2 invite path) or the `wire add` / `pair-accept` gesture is still the only path to VERIFIED. Property-tested in `tests/trust_ceiling_prop.rs`.
- **File-backed org policy (#95, #98).** Minimal receiver-side per-org store. Two modes: `auto` (auto-pin on contact, wired in v0.14), `notify` (eligible — designated UI surface, parsed but not yet wired into the live receive path; lands in v0.14.x). Empty/malformed → empty policy → no easing.
- **SSO provider-adapter trait (#100).** Pluggable seam (`SsoProvider::normalize`) over Google (`hd`), Azure AD (`tid`), Keycloak (realm), and a generic IdP — claims-shape normalization only. The verify path (binding an SSO identity to an `op_did` via a relay attestation) is deferred to v0.15 per the SSO amendment.
- **Live two-process e2e (#105 + #107).** `tests/e2e_org_verified.rs` drives the real `wire` binary across two `WIRE_HOME`s + an in-process relay: A enrolls op+org+self-membership → `wire init` (card carries claims) → A dials B → B (with `org_policies.json` auto-trusting A's org) pulls → B auto-pins A at `ORG_VERIFIED` purely from the offline membership. Negative control: non-member dialer still gated to pending. `#[ignore]`d (run via `cargo test --test e2e_org_verified -- --ignored --test-threads=1`) — heavy real-process e2e + a gentle 750 ms poll cadence to avoid starving the other real-daemon e2e binaries under `cargo test --all-targets`.
- **A2A interop docs (#91 — @dthoma1 / swift-harbor).** `docs/a2a-extension/wire-identity-v1.md` formalises wire as an A2A v1.0 AgentCard extension (URI `https://slancha.ai/wire/ext/v0.5`); `docs/did-methods/did-wire-method.md` is the `did:wire` method specification covering session / operator / organisation shapes (`<handle>-<8hex>` and `<handle>-<32hex>` of `sha256(pubkey)`); `docs/PROTOCOL.md` audited through v0.13.5 with the v3.2 additions inlined; an introductory blog at `docs/blog/wire-and-a2a.md` covers what wire adds on top of the A2A floor.
- **RFC-001 as-built alignment (#106).** Added "Implementation status (as-built, v0.14)" demarcating built (offline-minimal) vs deferred (DNS-TXT / `did:web` / wireup registry / roster bundle / SSO verify / cross-relay → v0.15). Fixed the §1 card snippet that had omitted the inline `op_pubkey` and per-membership `org_pubkey`.

Net: an operator who runs the three `wire enroll` commands once on each machine, then sets a one-line `org_policies.json` opt-in for any org they're willing to auto-pair with, eliminates the SAS dance for every session-pair inside that org — bilaterally, offline, on the v0.13 mailbox substrate. Wire-format additions are ≤ 2 KB per card, backward-compatible with v3.1 readers; nothing on the relay protocol changed.

Known follow-ups (v0.14.x): `wire enroll … --republish` (or rebuild-on-enroll) to close the DX gap that `enroll`-after-`init` doesn't republish claims today (card is built at init only); wire `notify` mode into the live receive surface; serialize the heavy real-daemon e2e binaries behind a dedicated `-- --ignored --test-threads=1` CI step.


## [v0.13.5] — 2026-05-25

**v0.13.5 — Reliable per-session identity (the PID-file adapter) + unexpanded-`${}` guard.**

v0.13.4's env-forward (`WIRE_SESSION_ID=${CLAUDE_CODE_SESSION_ID}`) proved unreliable: Claude Code only expands `${}` when the var is in its OWN env, which on a clean top-level terminal (esp. Windows CC 2.1.150) it is NOT — so CC passes the LITERAL string, which wire hashed into ONE fixed identity (every session in every folder collapsed onto one persona). Two fixes:

- **`${...}` literal guard** — `resolve_session_key` treats any unexpanded `${...}` value (and empty) as unset, so it never hashes a placeholder into a shared identity.
- **Claude Code PID-file adapter** (thanks @WILLARDKLEIN, #56) — when the session id isn't in the env, wire walks its parent-process chain to the owning `claude` process and reads `~/.claude/sessions/<pid>.json` → `sessionId`. Deterministic, race-free, zero env/handshake dependency, cross-platform — validated on Windows (3 concurrent terminals → 3 distinct personas) and macOS. The MCP server now recovers the SAME session id the CLI uses, so CLI and MCP unify on one per-session identity, stable across reconnects.

Net: true per-session identity everywhere, even when Claude Code doesn't put the session id in the MCP env. Ships a reference cross-platform proxy shim (`contrib/wire-mcp-proxy.py`) for builds without the native adapter.

## [v0.13.4] — 2026-05-25

**v0.13.4 — Per-session identity (MCP + Windows), statusline fix, group chat, `wire update`.**

- **Per-session identity, fixed on the MCP path — the Windows "same persona every session" bug.** Claude Code sets `CLAUDE_CODE_SESSION_ID` for Bash-tool subprocesses but NOT for the stdio MCP server, and the MCP `initialize` handshake carries no session id — so the MCP server had no per-session signal and fell back to cwd-detection, collapsing every Claude session under a shared dir (`~/Source`, `C:\Users\<user>`) onto ONE identity. Two fixes: (1) `wire setup` now writes the MCP entry with `"env": {"WIRE_SESSION_ID": "${CLAUDE_CODE_SESSION_ID}"}`, which Claude Code expands into the MCP env at launch (validated on Win10 — a fresh session resolves to a distinct by-key persona); (2) **cwd resolution is removed everywhere** — the MCP mints a distinct per-process identity when no session id is present, and the CLI never cwd-resolves. Identity is the session, period. **Re-run `wire setup --apply` on this version** — and note a PROJECT-scoped `.mcp.json` takes precedence over the global config, so make sure the env block landed in the file your host actually uses.
- **Statusline shows the session's own persona.** The bundled renderer bridges the `session_id` Claude Code passes on STDIN into `WIRE_SESSION_ID` before calling `wire whoami`, so the bottom-of-terminal persona matches the session (was resolving a cwd default / nothing).
- **Group chat** — `wire group create / add / send / tail / list / invite / join` + MCP `wire_group_*` tools. A group is a shared relay-room slot; the creator-signed roster carries each member's key (introduce-on-vouch), so members verify each other without pairing. `invite` mints a self-contained join code; redeemers land at Introduced tier.
- **`wire update` ≡ `wire upgrade`** — one verb (alias). Always checks crates.io; installs a newer release if there is one (cargo install, else prebuilt + SHA-256 self-replace), then does the atomic daemon swap. `--check` reports; `--local` skips the fetch.
- **CI:** GitHub Actions bumped off deprecated Node 20 (checkout@v5, upload-artifact@v7, download-artifact@v8).
- **Docs:** AGENTS.md + AGENT_INTEGRATION.md now document the v0.13 session-keyed identity model (were the stale pre-v0.13 cwd model).

## [v0.13.3] — 2026-05-25

**v0.13.3 — Group chat + one update command.**

- **`wire group` — bidirectional group chat.** `create / add / send / tail / list`. A group is a **shared relay-room slot**: the creator allocates one slot and its token is the room key, distributed only to vouched members; everyone posts + pulls that one slot (no relay change, no daemon auto-rebroadcast, no per-member credential mesh — chosen because a `slot_token` is a read+write credential, so direct member-to-member delivery would leak each member's personal mailbox token). Membership is a **creator-signed roster** with a `GroupTier` (creator/member/introduced) that is a SEPARATE axis from bilateral peer trust. `add` takes a bilaterally-VERIFIED peer (T22 consent) and distributes a `group_invite` carrying the signed roster + room coords. On ingesting an invite a member **introduce-pins** every other member — adds their key to trust at bilateral UNTRUSTED so their group messages verify, WITHOUT granting bilateral trust and never lowering an existing tier (the axes stay disjoint). Net: members who never paired with each other can post to the room and read each other's messages with a verified signature, vouched by the creator's signature in place of a direct SAS handshake. Verified live on wireup.net + by an e2e star-topology test (one member reads another's message verified though they never paired).
- **`wire update` ≡ `wire upgrade` — merged.** One verb (`update` is an alias). It ALWAYS checks crates.io; if a newer stable release is published it installs it (`cargo install slancha-wire` when a Rust toolchain is on PATH, else downloads + SHA-256-verifies the prebuilt release binary and self-replaces — toolchain-free), then runs the atomic daemon swap so the restart picks up the new binary. No newer version → it skips the install and just restarts. A crates.io/network failure degrades to a warning and never blocks the restart. `--check` reports the available update + the processes that would restart without acting; `--local` skips the crates.io check (offline / local dev build).

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

