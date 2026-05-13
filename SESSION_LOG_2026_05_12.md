# Session log — 2026-05-12 — Spark → Fly cutover + landing in binary + /stats (Mac-claude)

## What

End-to-end migration of `wireup.net` (apex + relay) from Spark-cloudflared to Fly.io. Spark is no longer in the `wireup.net` data path. Landing site, wire endpoints, and usage telemetry all served from a single self-contained binary at `https://wireup.net`. `wire.laulpogan.com` legacy alias kept alive on Spark.

## Sequence

### Phase 1 — Initial Fly deploy
1. Operator registered Fly (`pauljflogan@gmail.com`), created `slancha` org, installed `flyctl` to `~/.fly/bin/`, authed.
2. `git checkout fly-deploy-stub` from `SlanchaAi/wire`.
3. `flyctl launch --no-deploy --copy-config --name wireup-relay --org slancha --region iad --yes` — registered app. `--copy-config` clobbered our `fly.toml`; reverted via `git checkout fly.toml`.
4. `flyctl volumes create relay_state --size 1 --region iad --app wireup-relay --yes` — 1 GB encrypted volume in iad.
5. `flyctl deploy --app wireup-relay --remote-only` — depot-builder Rust release build, 1m 29s compile + push. Image 29 MB. Machine `5683e207c1e728`.
6. Smoke tests: `/healthz` → `ok`, `/.well-known/wire/agent?handle=nobody` → phyllis 404.
7. Auto-deploy GitHub Actions workflow + FLY_API_TOKEN secret created automatically by `fly launch`. Kept.
8. Merged `fly-deploy-stub` → `main` (ff), pushed, deleted branch.

### Phase 2 — relay.wireup.net DNS cutover
1. CF DNS: `CNAME relay → wireup-relay.fly.dev` (proxied / orange-cloud).
2. `flyctl certs create relay.wireup.net` → behind CF orange-cloud needs ownership TXT + ACME challenge CNAME (both DNS-only). Added both. LE cert issued in ~30 sec.
3. End-to-end: `https://relay.wireup.net/healthz` 200 over CF universal cert.

### Phase 3 — Landing migration to CF Pages (abandoned)
1. Pulled `landing/index.html` + `favicon.svg` from Spark `~/wire-public/landing/` via scp.
2. Committed to repo at `landing/`, also added to `.dockerignore` initially.
3. `npx wrangler pages deploy landing --project-name=wireup-landing --branch=main` → `wireup-landing.pages.dev` live.
4. Wrote `landing/_redirects` with `200`-status rewrite rules forwarding `/healthz`, `/.well-known/wire/*`, `/v1/handle/*` to Fly. Redeployed.
5. **Discovered: CF Pages `_redirects` with status 200 (rewrite) only supports same-origin destinations, not external URLs.** External rewrites need Pages Functions or a Worker. Bailed on this path.

### Phase 4 — Landing baked into relay binary
1. Removed `landing/` from `.dockerignore`; added `COPY landing ./landing` to Dockerfile.
2. Added `GET /` (landing_index) + `GET /favicon.svg` (landing_favicon) handlers in `src/relay_server.rs`, embedding files via `include_bytes!`.
3. Pushed to main → CI auto-deploy → smoke tests pass on `wireup-relay.fly.dev/`.

### Phase 5 — wireup.net apex flip
1. CF DNS: deleted apex Tunnel record (Name `wireup.net`, Content `wire`, Proxied) — the cloudflared-tunnel binding to Spark. Added `CNAME @ → wireup-relay.fly.dev` (orange-cloud).
2. `flyctl certs create wireup.net` + ownership TXT + ACME CNAME (DNS-only). LE cert issued in ~4 min (slower than relay — Fly's validator polled later in cycle).
3. End-to-end: `https://wireup.net/` serves landing, `/healthz` 200, `/.well-known/wire/agent?handle=...` returns phyllis 404. TLS = CF universal cert covering `*.wireup.net` + `wireup.net`.

### Phase 6 — Spark partial decom
1. SSH'd to Spark, `cp ~/.cloudflared/wire-config.yml ~/.cloudflared/wire-config.yml.bak-pre-fly-cutover-20260513T021432Z`.
2. Rewrote `wire-config.yml` to comment out `wireup.net` (path-routed + apex) + `relay.wireup.net` ingress blocks. Kept `wire.laulpogan.com` + `relay.laulpogan.com` legacy aliases. Final `service: http_status:404` preserved.
3. `systemctl --user restart wire-public-tunnel`. wire-public-relay + wire-public-landing left running for legacy traffic.
4. Verified: legacy `https://wire.laulpogan.com/healthz` still 200; `wireup.net/healthz` now served by Fly.

### Phase 7 — /stats telemetry
1. Added `RelayCounters { boot_unix, handle_claims_total, slot_allocations_total, pair_opens_total, events_posted_total }` (AtomicU64s) to `Relay` struct.
2. Increments in `allocate_slot`, `post_event`, `pair_open` (only first-touch), `handle_claim`.
3. `GET /stats` handler returns JSON with the four counters + live in-memory state (`handles_active`, `slots_active`, `pair_slots_open`, `streams_active`) + `uptime_seconds` + `version` (from `CARGO_PKG_VERSION` env macro).
4. Public, no auth — aggregate counts, no DIDs/IPs/handles leaked.

### Phase 8 — Counter persistence
1. Added `CountersSnapshot` serde struct mirroring the AtomicU64s.
2. `Relay::new()` reads `<state_dir>/counters.json` if present, seeds atomics from values.
3. `Relay::persist_counters()` writes snapshot to disk.
4. `Relay::spawn_counter_persister()` background task: 30 s interval, calls `persist_counters` each tick.
5. `serve()` calls it on startup; final `persist_counters()` runs inside `with_graceful_shutdown` so SIGTERM (Fly redeploy or SIGINT locally) flushes counters before exit.
6. Loss bound: ≤30 s of counter increments on uncatchable crash. Acceptable for telemetry.

## Surprising / non-obvious

- **`fly launch --copy-config` rewrites `fly.toml` regardless.** Stripped our `auto_stop_machines=false`, `min_machines_running=1`, mount, env, http_service block. `git diff fly.toml` after `fly launch`; revert if clobbered.
- **`fly launch` ships GitHub Actions workflow + FLY_API_TOKEN secret by default.** CLOUD_MIGRATION.md called it "(Optional, future)". It's actually opt-out, not opt-in.
- **flyctl curl-installer does not modify the running shell's PATH.** Installs to `~/.fly/bin/`. New login shell or explicit `export PATH=$HOME/.fly/bin:$PATH` required. Mac-claude used full path initially.
- **CF Pages `_redirects` with status-200 rewrites only work for same-origin destinations.** External URLs (`https://wireup-relay.fly.dev/...`) silently fall through to the static index.html — every request returned the landing HTML during testing. External proxying needs Pages Functions or a Worker. Doc this if anyone hits it again.
- **CF orange-cloud + Fly cert validation needs ownership TXT + ACME challenge CNAME (both DNS-only / grey).** HTTP-01 challenge can't reach Fly when CF is proxying. DNS-01 via `wireup.net.ke5kp8r.flydns.net` delegation bypasses the proxy.
- **CF apex was a Tunnel record, not a CNAME.** Type "Tunnel" is a CF-specific record bound to a named cloudflared tunnel — can't be edited into a CNAME. Delete + re-add as CNAME.
- **`include_bytes!` path resolves relative to the source file (`src/relay_server.rs`).** Means the `landing/` directory must be in the Docker build context — adjust `.dockerignore` + Dockerfile `COPY`.
- **CF universal TLS cert SAN covers `wireup.net` + `*.wireup.net`.** No need to add `www.wireup.net` separately to Fly cert list (we didn't anyway; flagged for future if `www` becomes a thing).

## Artifacts on disk

- `Dockerfile` — two-stage Rust → debian:bookworm-slim. Final image ~29 MB after landing baked in.
- `fly.toml` — shared-cpu-1x, 256 MB, iad, `auto_stop=false`, `min_machines_running=1`, mount `/data` → `relay_state` vol.
- `.dockerignore` — excludes `docs/`, `examples/`, `target/`, `.github/`, `.claude/`. `landing/` kept.
- `.github/workflows/fly-deploy.yml` — auto-deploy on main push.
- `landing/index.html`, `landing/favicon.svg` — static landing, embedded in binary via `include_bytes!`.
- `docs/CLOUD_MIGRATION.md` — original Spark-side deployment runbook (now historical).
- `docs/MAC_HANDOFF_2026_05_12.md` — Spark-claude → Mac-claude handoff.
- `SESSION_LOG_2026_05_12.md` — this file.
- Fly app: `wireup-relay`, org `slancha`, region `iad`, volume `vol_4y85zeyj69yzz2er` (`relay_state`).
- CF DNS: `wireup.net` CNAME → `wireup-relay.fly.dev` (proxied); `relay.wireup.net` CNAME → same (proxied). Two `_acme-challenge` + `_fly-ownership` validation records (DNS-only).
- Spark backup: `~/.cloudflared/wire-config.yml.bak-pre-fly-cutover-20260513T021432Z`.

## Endpoints live

| URL | Backend | Purpose |
|---|---|---|
| `https://wireup.net/` | Fly relay (landing in binary) | landing page |
| `https://wireup.net/healthz` | Fly relay | health check |
| `https://wireup.net/stats` | Fly relay | usage counts JSON |
| `https://wireup.net/.well-known/wire/agent?handle=…` | Fly relay | handle directory lookup |
| `https://wireup.net/v1/*` | Fly relay | wire protocol (slot/pair/handle/events) |
| `https://wireup.net/favicon.svg` | Fly relay | favicon |
| `https://relay.wireup.net/*` | Fly relay (alias) | same as wireup.net |
| `https://wireup-relay.fly.dev/*` | Fly relay (Fly default) | same |
| `https://wire.laulpogan.com/*` | Spark wire-public-relay + landing | legacy (v0.4 clients) |

## Decisions

- **Skipped Spark state migration.** Existing handle claims against Spark are lost; new claims happen against Fly. Pre-launch / v0.5, acceptable.
- **Kept `wire.laulpogan.com` legacy alive on Spark.** Lets v0.4-era handles keep working. Spark services (wire-public-relay, wire-public-landing) stay running. Operator can do full Spark decom later if/when legacy traffic dries up.
- **Landing in the relay binary, not CF Pages.** CF Pages `_redirects` can't proxy externally; building a Pages Function or Worker just to route paths was more complexity than embedding 37 KB of static files in the Rust binary. One host serves everything.
- **`/stats` public, no auth.** Aggregate counts only. No DIDs/IPs/handles. Same posture as npm download counts, Plausible public dashboards.
- **Auto-deploy CI on main push, kept.** Was created by `fly launch` automatically; useful and operator opted to retain.

## Cost

$0/mo on Fly hobby tier (shared-cpu-1x + 1 GB volume both free). Volume + machine snapshot retention 5 d. First paid bump triggers around hundreds of concurrent SSE subscribers.

## Followups queued (not blocking)

- Switch wire client tools to default `relay_url = "https://wireup.net"` on claim (everything resolves to one host now).
- Delete unused CF Pages project `wireup-landing` once you're sure you won't roll back to it.
- Prune Spark `wire-public-relay-state/` backup after ~30 days.
- Consider lifetime handle counter that survives DID re-claims (currently `handle_claims_total` counts every claim including re-claims).
