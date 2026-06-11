# Session log — 2026-06-11 — host decay engines: why wire "keeps going down"

Operator observation: "this keeps happening" — wire found fully down (launchd
unit gone, MCP on ghost identity, stale session flood) repeatedly. Root-caused
to THREE independent decay engines; the two structural ones fixed on branch
`fix/host-decay-engines`.

## Engine 1 (THE smoking gun, found mid-session): unit test boots the host daemon out

`nuke::tests::execute_removes_dirs_and_mcp_entry` called the real
`NukePlan::execute()`, whose service-unit teardown is **machine-global** —
`with_temp_home` scopes WIRE_HOME paths but nothing scopes `launchctl bootout`.
**Every `cargo test --lib` run on the host removed
`sh.slancha.wire.daemon.plist` and killed the supervisor's whole process tree.**
Caught red-handed: running `cargo test --lib nuke` during this session printed
"Boot-out failed: 3: No such process" and took the live daemon down (restored
via `wire service install`).

Fix (fb53d77): unit teardown injected — `execute_with(uninstall_unit)`; only
the prod `execute()` wrapper reaches launchctl/systemd/schtasks; the test
passes a stub and asserts both unit kinds attempted. Proof: full lib suite
(439 passed) with `launchctl list | grep wire` intact after.

## Engine 2: husk accumulation (175 by-key dirs, regrew 9/minute after prune)

Every wire invocation under an agent session key mints
`sessions/by-key/<hash>/` (RFC-008 adoption), even read-only commands; nothing
deleted them. Host evidence: 19 by-key dirs, 18 husks (no private.key), 9 born
in one minute. The supervisor idle filter (7-day, `supervisor_eligible`) stops
the daemon fork-storm but leaves dirs.

Fix (0093b8b): hourly supervisor husk reaper. Reaps only when ALL hold:
16-lowercase-hex name / no identity / never synced / not registry-bound / no
live daemon / older than cutoff (48h default, `WIRE_HUSK_REAP_MAX_AGE_HOURS`,
0 disables). Future mtimes = young (clock skew never deletes). 9 unit tests,
one per keep-condition.

## Engine 3: nuke is machine-global even under temp WIRE_HOME

`wire nuke --force` from an agent/test context still tears down units + MCP
registrations + every daemon machine-wide (killed the host during v0.15
testing, per handoff).

Fix (fb53d77): host guard. nuke reads the **DEFAULT** registry
(`session::default_sessions_root`, WIRE_HOME deliberately ignored) and refuses
when cwd-bound sessions exist unless `--really-this-machine`. `--force` only
answers the typed prompt, not the guard. CI install-smoke unaffected (runner
default registry empty); `--dry-run` ungated. **Proven live on this host:**
`target/debug/wire nuke --force` refused, listed the 4 bound sessions, daemon
untouched, exit 1.

## Not fixed (acknowledged residuals)

- MCP ghost identity: `wire upgrade` doesn't restart `wire mcp` subprocesses
  (known memory; possible follow-up: version-drift self-exit).
- Lazy minting (don't mkdir by-key home on read-only commands) — would kill
  husk birth at source; more invasive, reaper makes it non-urgent.

## Gotchas relearned

- **Never pipe the gate**: first container-gate run was
  `./test-env/run.sh | tail -30` → exit 0 was tail's while Docker daemon was
  down. The gate-exit memory rule exists for exactly this. Re-ran bare.
- GitNexus PreToolUse hook returns irrelevant crypto symbols for many Bash
  commands — noise, not signal.

## Artifacts

- Branch `fix/host-decay-engines`: 0093b8b (reaper), fb53d77 (nuke guard +
  test stub).
- This file.
