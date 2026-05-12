# wire — session handoff (2026-05-11)

## Current state (resume here)

- **wire repo**: `/home/admin/Source/wire`. Branch `main` at `v0.3.13`, CI all 4 jobs green (clippy/test/fmt/demo-detached). 144 tests pass.
- **Public relay**: live at `https://wire.laulpogan.com` (systemd unit `wire-public-relay.service`). Validated end-to-end via manual smoke + CI demo-detached job.
- **Site**: `https://wire.laulpogan.com` landing redesigned (sixties-chic palette, Fraunces + Inter + Plex Mono, no phone illustration). Files at `/home/admin/wire-public/landing/`. Served by `wire-public-landing.service` (python http.server :8771).
- **Spark daemon**: `wire-daemon-coord-test.service` running for `paul-spark-021` ↔ `paul-mac` pair (pre-v0.3.0 binary; doesn't write daemon.pid).

## Operator's standing /loop directive

```
/loop fix A keep going, also test when feature is in a good spot
```

`A` = **detached pair line** (v0.3.0 → v0.3.13). Saturated. CI green. Every known invariant has a test. Further iters on A line yield marginal returns; current pattern is 1-hr fallback heartbeats with no-op iters.

## Detached pair line — what shipped (v0.3.0 → v0.3.13)

- v0.3.0 — daemon-orchestrated pending-pair state machine (`src/pending_pair.rs`). CLI: `wire pair-host --detach`, `pair-join --detach`, `pair-confirm`, `pair-list`, `pair-cancel`.
- v0.3.1 — OS toast on sas_ready / paired (new `os_notify` module).
- v0.3.2 — MCP `wire://pending-pair/all` resource + notifications/resources/updated push.
- v0.3.3 — auto-spawn daemon on detach commands + MCP push integration test + `wire pair --detach` mega-command.
- v0.3.4 — abort toast on mismatch / restart, terminal-state-file GC, live public relay e2e validated.
- v0.3.5 — 5 detached MCP tools: `wire_pair_initiate_detached`, `wire_pair_join_detached`, `wire_pair_list_pending`, `wire_pair_confirm_detached`, `wire_pair_cancel_pending`.
- v0.3.6 — `--json` flag on all detached CLI commands + AGENT.md MCP detached section.
- v0.3.7 — real-daemon e2e test in cargo (`tests/e2e_detached_pair.rs`).
- v0.3.8 — concurrent multi-pair stress test (paul hosts 2 pairs to alice + bob).
- v0.3.9 — `wire status` shows daemon liveness + pending pair counts by status.
- v0.3.10 — `wire pair-watch <code>` blocking CLI with exit-code outcomes + CI `demo-detached` job.
- v0.3.11 — `wire pair-list --watch` JSON-lines streaming for shell pipelines.
- v0.3.12 — **persistent SPAKE2**: daemon restart no longer kills handshakes. Seed-based reconstruction via `PakeSide::from_seed`. New `restore_pair_session`. PendingPair gains `pair_id`/`our_slot_id`/`our_slot_token`/`spake2_seed_b64`. Integration test proves restart mid-handshake completes successfully.
- v0.3.13 — clippy + fmt clean for Rust 1.95 (was failing CI from v0.3.10 onward).

## v0.2.x earlier ship line

- v0.2.6: install.sh Windows triples + correct Claude Code config path (`~/.claude.json`).
- v0.2.7: `wire pair <handle>` single-shot bootstrap.
- v0.2.8: `wire pair-abandon <code>` for stuck-slot recovery.
- v0.2.9: pair-join/host heartbeat every 10s.
- v0.2.5 and earlier: reactor + anti-loop guards + MCP pair tools + push.

See `CHANGELOG.md` in repo root for full per-release notes.

## Operator-blocked items

- **npm publish openclaw-channel-wire** — needs `npm adduser`. Task #56.
- **PyPI publish wire-langgraph** — operator-blocked.
- **willard pair on new wire** — paused since 2026-05-11T03:03Z willard message. Operator coordinating; no inbound for ~13hr (as of resume). New code-phrase + tailscale tag rejection still pending operator.
- **Mac side wire upgrade** — on v0.2.4; needs >= v0.2.5 (anti-loop) or v0.3.x (detached pair + persistent SPAKE2).

## How to resume the willard pair (when operator coordinates)

Paul side (this Spark) has v0.3.13. Detached path works:
```
wire pair-host --detach --relay https://wire.laulpogan.com
# returns code immediately; daemon auto-spawned
# share code with willard via whatever channel
wire pair-list                    # watch for sas_ready
wire pair-confirm <code> <digits> # operator types digits after voice-compare
```

Willard side has v0.2.5 (Windows install via `gh release download`). Either:
- willard upgrades to v0.3.13 + uses detached MCP tools, OR
- willard uses synchronous `wire pair-join <code> --relay https://wire.laulpogan.com` from CLI (still works against v0.3 relay).

Relay slots `21-Q267SN`, `30-UE2BZG`, `93-WY6DBB`, `53-CKWIA5` from earlier failed attempts have been abandoned (released via `wire pair-abandon`).

## Key paths

- Wire repo: `/home/admin/Source/wire/`
- Site source: `/home/admin/wire-public/landing/index.html`
- Spark wire data: `/home/admin/wire-spark-v021/`
- Legacy paul-willard coord (predecessor, not OSS wire): `/home/admin/wire/paul-willard-wire/`
- Demo scripts: `demo.sh` (v0.1 foreground), `demo-detached.sh` (v0.3 detached)

## Open friction signals (not yet acted on)

- Operator's reactor on legacy paul-willard-wire (Python `responder.py`) reportedly not processing inbox per willard's 2026-05-11T02:16Z complaint. Operator's domain.
- spark-472e Tailscale ACL: `tag:tagged-devices` rejected on willard's tailnet. Three operator-decide options A/B/C from willard's 03:03Z message.

## Notable design decisions

- **In-memory PakeSide is single point of fragility** for daemon-restart. v0.3.12 closed this with seed persistence. Daemon restart now restores live sessions from disk.
- **Three push channels for SAS**: OS toast (notify-send/osascript) + MCP notifications/resources/updated + daemon stderr log. N+1 redundancy.
- **CI catches integration regressions** that cargo test can't: `demo-detached` job runs the full bash flow. Caught real bugs in v0.3.10–v0.3.12 clippy line.
- **Sixties-chic site** has table-overflow fix (`.table-scroll` wrapper) and phone removed per operator iter.

## Memory: nothing critical saved

No new `~/.claude/projects/.../memory/` writes this session. Codebase + git history + CHANGELOG.md + this handoff doc are the persistent record.

## Resume prompt (paste this)

```
You're resuming wire OSS dev (https://github.com/SlanchaAi/wire). Read /home/admin/Source/wire/HANDOFF.md first — it captures state through 2026-05-11.

Current state: v0.3.13 shipped + tagged, CI green on all 4 jobs (clippy/test/fmt/demo-detached). 144 tests. Detached pair line (v0.3.0→v0.3.13) feature-complete + CI-validated. Operator running /loop "fix A keep going, also test when feature is in a good spot" but A is saturated — current iters are 1hr fallback no-ops.

Pending operator-decide: willard pair (paused since 2026-05-11T03:03Z), npm publish, Mac wire upgrade.

Resume in CAVEMAN MODE (full). Stay terse. Code/commits/PRs normal. /loop with same prompt: fix A keep going, also test when feature is in a good spot.
```
