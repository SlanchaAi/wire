# Session log — 2026-05-12 — Fly.io relay deploy (Mac-claude)

## What

Migrated `wire-relay-server` from Spark-on-cloudflared-tunnel to Fly.io. App live at `https://wireup-relay.fly.dev`.

## Sequence

1. Operator registered Fly account (`pauljflogan@gmail.com`), created `slancha` org, installed `flyctl` to `~/.fly/bin/`, authed.
2. Mac-claude `git checkout fly-deploy-stub` from `SlanchaAi/wire`.
3. `flyctl launch --no-deploy --copy-config --name wireup-relay --org slancha --region iad --yes` — registered app. Note: `--copy-config` did not actually preserve our `fly.toml`; reverted via `git checkout fly.toml`.
4. `flyctl volumes create relay_state --size 1 --region iad --app wireup-relay --yes` — 1 GB encrypted volume in iad.
5. `flyctl deploy --app wireup-relay --remote-only` — depot-builder Rust release build, 1m 29s compile + push. Image 29 MB. Machine `5683e207c1e728` launched.
6. Smoke tests both pass:
   - `GET /healthz` → `ok`
   - `GET /.well-known/wire/agent?handle=nobody` → phyllis 404
7. `fly launch` had auto-created `.github/workflows/fly-deploy.yml` + `FLY_API_TOKEN` repo secret. Operator opted to keep (auto-deploy on main push).
8. Merged `fly-deploy-stub` → `main` (ff), pushed, deleted branch local+remote.

## Surprising / non-obvious

- **`fly launch --copy-config` lies.** It rewrites `fly.toml` from its scanner regardless. Stripped our SSE-critical settings (`auto_stop_machines=false`, `min_machines_running=1`, mount, env, http_service block). Saved by `git checkout fly.toml`. **Lesson:** always `git diff fly.toml` after `fly launch`; revert if clobbered. Mention in CLOUD_MIGRATION.md if hit again.
- **`fly launch` adds GitHub Actions workflow + FLY_API_TOKEN secret to the repo automatically.** CLOUD_MIGRATION.md called this "(Optional, future)". It's not optional — it ships by default. Either delete or accept auto-deploy. Operator accepted.
- **flyctl curl-installer does not modify PATH for the running shell.** Installed to `~/.fly/bin/` but not on PATH until new login shell. Mac-claude used `~/.fly/bin/flyctl` direct path initially.

## Outstanding (operator action required)

- **DNS cutover** (CF dashboard, `wireup.net` zone):
  - Add `CNAME relay → wireup-relay.fly.dev` (orange-cloud / proxied).
  - Replace apex `CNAME @ → wireup-relay.fly.dev` (orange-cloud) — currently points at Spark cloudflared.
  - Verify: `dig +short relay.wireup.net` returns CF IPs; `curl https://relay.wireup.net/healthz` → `ok`.
- **After DNS prop verifies** (~5 min):
  - Spark: `systemctl --user stop wire-public-relay; systemctl --user disable wire-public-relay`.
  - Spark cloudflared: comment out `wireup.net` + `relay.wireup.net` ingress blocks in `~/.cloudflared/wire-config.yml`. Keep `wire.laulpogan.com` legacy aliases.
  - `systemctl --user restart wire-public-tunnel`.
- **State migration (optional, skipped pre-launch).** Spark `relay-state/` stays as rollback backup ~1 month.

## Artifacts

- `Dockerfile` — two-stage Rust → debian:bookworm-slim, 29 MB final.
- `fly.toml` — shared-cpu-1x, 256 MB, iad, `auto_stop=false`, `min_machines_running=1`, mount `/data` → `relay_state` vol.
- `.dockerignore` — excludes `target/`, `.git/`, docs.
- `.github/workflows/fly-deploy.yml` — auto-deploy on main push.
- `docs/CLOUD_MIGRATION.md` — full deployment + rollback runbook.
- `docs/MAC_HANDOFF_2026_05_12.md` — Spark-claude → Mac-claude handoff.
- Fly app: `wireup-relay` org `slancha`, region `iad`, volume `vol_4y85zeyj69yzz2er` (`relay_state`).
- Public endpoint: `https://wireup-relay.fly.dev` — live.

## Cost

$0/mo on Fly hobby tier (shared-cpu-1x + 1 GB volume both free). Volume + machine snapshot retention 5d.

## Rollback

DNS-gated. Revert CF apex CNAME → old cloudflared record, `systemctl --user enable --now wire-public-relay` on Spark. ~2 min total.
