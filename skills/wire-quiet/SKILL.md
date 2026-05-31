---
description: Silence wire desktop notifications (toasts). Use when user says "wire quiet", "mute wire", "stop the toasts", or is in a focus / demo context where macOS Notification Center spam is unwanted. File-based kill switch persists across daemon restarts; env-based variant (WIRE_NO_TOASTS=1) covers launchd-spawned daemons.
---

# wire-quiet

Operator kill switch for every wire desktop toast surface. Both file (`<config_dir>/quiet`) and env (`WIRE_NO_TOASTS=1`) routes funnel into a single guard at `os_notify::toast`. Disabled means disabled — no dedup leakage.

## When to use

- User says "wire quiet", "shut up wire", "stop wire notifications", "mute toasts"
- User is in a focus / demo / screen-share context
- Sustained probe-loss notifications (RFC-004, post-v0.15) are excessive

## Surface

### `wire quiet on` — silence

```bash
wire quiet on
```

Touches `<config_dir>/quiet`. Idempotent. Output reports the file path (per-session).

### `wire quiet off` — restore

```bash
wire quiet off
```

Removes the file. Idempotent (no error if already off). Warns if `WIRE_NO_TOASTS=1` is still set in the env — file-OFF doesn't override env-ON.

### `wire quiet status` — report

```bash
wire quiet status [--json]
```

Reports: `on` / `off` + mechanism (`via file` / `via env` / `none`).

## Multi-session / fleet-wide silence

If the operator wants every Claude tab's daemon silenced:

```bash
# Global env (launchd) — covers future-spawned daemons
launchctl setenv WIRE_NO_TOASTS 1

# Per-session file — covers every existing config_dir
find ~/Library/Application\ Support/wire/sessions/by-key -maxdepth 4 \
     -type d -name wire -exec touch {}/quiet \;

# Force respawn so the env propagates
pkill -f 'wire daemon'
```

## Reverse

```bash
launchctl unsetenv WIRE_NO_TOASTS
wire quiet off
```

## Reference

- v0.14.1 release notes (`README.md` §"Status — v0.14.1") for the kill-switch design.
- Memory: `feedback_wire_upgrade_skips_mcp_servers` — sister Claude sessions' wire mcp subprocesses need `/mcp` reconnect to pick up the silenced binary if `wire upgrade` ran.
