# wire — test deployment runbook (laulpogan.com)

**Status:** v0.1 test deployment is LIVE — unified URL on `wire.laulpogan.com`.

| Path on `wire.laulpogan.com` | Backend | Purpose |
|---|---|---|
| `/healthz`, `/v1/*`, `/.well-known/*` | `127.0.0.1:8770` | `wire relay-server` (HTTP API) |
| everything else | `127.0.0.1:8771` | static landing page |

Legacy `relay.laulpogan.com` still works (same backend) during a grace period; will sunset after operators migrate to the unified URL.

All routed via Cloudflare Tunnel `wire` (id `96d4dc82-44b8-4ef3-9a30-8bca6f6ee265`) using path-based ingress rules.

## Components on Spark

```
~/.cloudflared/
  96d4dc82-44b8-4ef3-9a30-8bca6f6ee265.json   # tunnel credentials (mode 0600)
  wire-config.yml                              # ingress rules (relay + landing)

~/wire-public/
  relay-state/state/wire-relay/                # WIRE_HOME for the relay
    slots/<slot_id>.jsonl                      # per-slot event JSONL
    tokens.json                                # bearer tokens
  landing/index.html                           # landing page

~/.config/systemd/user/
  wire-public-relay.service                    # wire relay-server :8770
  wire-public-landing.service                  # python3 -m http.server :8771
  wire-public-tunnel.service                   # cloudflared --config wire-config.yml tunnel run wire
```

## Verify health

```bash
systemctl --user is-active wire-public-relay wire-public-landing wire-public-tunnel
# expect: active / active / active

curl -fsS https://relay.laulpogan.com/healthz
# expect: ok

curl -fsSI https://wire.laulpogan.com/ | head -1
# expect: HTTP/2 200
```

## Live-test the full flow against the public relay

```bash
WIRE=~/Source/wire/target/release/wire
PAUL=$(mktemp -d) WILLARD=$(mktemp -d)
WIRE_HOME=$PAUL    $WIRE init paul
WIRE_HOME=$WILLARD $WIRE init willard
# in terminal A:
WIRE_HOME=$PAUL    $WIRE pair-host --relay https://relay.laulpogan.com
# read code phrase aloud, then in terminal B:
WIRE_HOME=$WILLARD $WIRE pair-join <code> --relay https://relay.laulpogan.com
# both confirm SAS — done.
```

`tests/e2e_pair.rs` and `demo.sh` both passed against this deployment on launch
(2026-05-10) — see commit history.

## Operations

```bash
# logs
journalctl --user -u wire-public-relay -f
journalctl --user -u wire-public-landing -f
journalctl --user -u wire-public-tunnel -f

# restart after binary update
cargo build --release
systemctl --user restart wire-public-relay

# deploy new landing page
cp new-index.html ~/wire-public/landing/index.html
# (no restart needed; python http.server reads file each request)
```

## Disk / capacity

State dir grows linearly with traffic (~1 KiB per stored event, JSONL append-only).
v0.2 will add TTL compaction for ephemeral kinds (BACKLOG.md). Until then,
monitor with:

```bash
du -sh ~/wire-public/relay-state/
```

If it crosses ~1 GB, rotate by stopping the relay, archiving the JSONL files,
and restarting (state is reloaded from disk on Relay::new).

## Migration to slancha.ai (production cutover)

1. Create a new tunnel: `cloudflared tunnel create wire-prod`
2. Route DNS:
   ```
   cloudflared tunnel route dns wire-prod relay.slancha.ai
   cloudflared tunnel route dns wire-prod wire.slancha.ai
   ```
3. New config: `~/.cloudflared/wire-prod-config.yml` (same shape, prod credentials).
4. Decide migration mode:
   - **Hard cutover:** stop the laulpogan tunnel, point operators at slancha.
     Existing slot tokens stay valid; only the URL changes. Operators run
     `wire bind-relay https://relay.slancha.ai` to re-allocate.
   - **Dual-run for grace period:** point both `relay.laulpogan.com` and
     `relay.slancha.ai` at the same backend (single ingress with two hostname
     rules in the prod config). Sunset laulpogan after 30 days.
5. Update README + landing page URLs.
6. Update `install.sh` `WIRE_DIST_URL` default.

## Cancellation / takedown

```bash
systemctl --user disable --now wire-public-relay wire-public-landing wire-public-tunnel
cloudflared tunnel delete wire   # destroys tunnel; DNS records remain (clean up in CF dashboard)
rm -rf ~/wire-public/ ~/.cloudflared/wire-config.yml
```

State dir is the only thing worth backing up before a takedown — slot tokens
are reproducible from re-pairing, but historical events are not.

## Backups

Nightly tar of state dir to Backblaze B2 ($0.005/GB-mo) is BACKLOG'd. v0.1 test
deployment runs without backups — anyone whose pair tokens live ONLY here
should expect them to disappear if the Spark dies.
