# Cloud migration — wireup.net relay from Spark → Fly.io

Goal: take Spark (gb10) out of the public-facing data path. After this
migration, only the operator's dev work runs on Spark; the wireup.net
relay runs in a sandboxed Fly.io container with an ephemeral filesystem
+ a `/data` persistent volume.

Branch: `fly-deploy-stub` (this file lives here pre-merge).

## Files added in this branch

| File | Purpose |
|---|---|
| `Dockerfile` | Two-stage Rust build → debian:bookworm-slim runtime. ~50 MB final image. |
| `fly.toml` | Fly app config: 1 machine, 256 MB RAM, 1 GB volume, SSE-friendly timeouts. |
| `.dockerignore` | Trims build context (no `target/`, no `.git/`, no docs). |
| `docs/CLOUD_MIGRATION.md` | This file. |

Nothing in `src/` changes. The same `wire relay-server --bind 0.0.0.0:8770`
that runs on Spark today is what the container runs.

## Accounts the operator needs to register

### 1. Fly.io (REQUIRED for relay deploy)

- Sign up: <https://fly.io/app/sign-up>
- Free with GitHub or Google SSO
- **Credit card required** to verify the account, but the hobby plan
  covers shared-cpu-1x + 1 GB volume at $0 until you outgrow it. Card is
  not charged at v0.5 scale.
- Org: create a `slancha` (or similar) org, not `personal`. Lets you
  add Mac-claude / Will / future contributors as machine-users later
  without leaking under your personal Fly account.

### 2. Cloudflare account (ALREADY HAVE)

- wireup.net DNS lives here already.
- No new sign-up. Will need to add a CNAME at cutover time.

### 3. (Optional, future) Cloudflare Pages

- For migrating the landing page off Spark. Free, no new account needed
  (uses your existing CF account).
- Can defer indefinitely — landing on Spark python http.server has no
  attack surface (it serves a static file and that's it). The actual
  security win is moving the **relay** off Spark, not the landing.

### 4. (Optional) GitHub Actions auto-deploy

- When you want `git push origin main` to auto-deploy to Fly, add a
  `FLY_API_TOKEN` repo secret and a `.github/workflows/deploy-fly.yml`.
  Token from `fly tokens create deploy -x 999999h`. Not in this stub —
  add later if useful.

## CLI tools the operator needs to install on Mac

```bash
# flyctl — Fly's CLI. One-line install:
curl -L https://fly.io/install.sh | sh

# Add to PATH (installer prints the line; usually ~/.fly/bin):
export PATH="$HOME/.fly/bin:$PATH"   # add to .zshrc

# Auth (uses browser):
fly auth login
```

Verify:
```bash
fly --version       # → flyctl v0.x.x
fly orgs list       # → personal + slancha
```

## Deployment steps (Mac-claude or operator can run)

### Step 1 — Create the Fly app

From inside the cloned `SlanchaAi/wire` repo on `fly-deploy-stub` branch:

```bash
cd ~/Source/wire
git checkout fly-deploy-stub
fly launch --no-deploy --copy-config --name wireup-relay --org slancha --region iad
```

- `--no-deploy`: don't deploy yet, just register the app
- `--copy-config`: use the existing `fly.toml` rather than regenerating
- `--name wireup-relay`: app name (becomes `wireup-relay.fly.dev`)
- `--org slancha`: the org you created at registration
- `--region iad`: us-east-1 equivalent; closest to CF's primary North
  American edge. Change to `sjc` for west-coast, `fra` for Europe,
  `nrt` for Asia.

### Step 2 — Provision the persistent volume

```bash
fly volumes create relay_state --size 1 --region iad
```

- `--size 1`: 1 GB. Wire's slot state grows ~10 KB per active slot;
  1 GB covers 100k slots. Resize later with `fly volumes extend`.
- The volume name `relay_state` matches `fly.toml`'s `[[mounts]]` source.

### Step 3 — Deploy

```bash
fly deploy
```

First deploy takes ~3 min (Rust release build is slow in CI). Subsequent
deploys ~30 sec with build cache. Output ends with the deploy URL:
`https://wireup-relay.fly.dev`.

### Step 4 — Smoke test

```bash
curl -fsS https://wireup-relay.fly.dev/healthz
# → ok

curl -fsS https://wireup-relay.fly.dev/.well-known/wire/agent?handle=nobody
# → 404 phyllis: that number's been disconnected — "nobody" isn't claimed
```

Both responses prove the binary is running, the volume is mounted, the
HTTP route table is correct, and the phyllis-voiced error messages came
through unchanged.

### Step 5 — (Optional) Migrate Spark's slot state to Fly volume

```bash
# From Spark:
rsync -avz /home/admin/wire-public/relay-state/ \
  $(fly ssh sftp shell -a wireup-relay <<<'put -r ./relay-state /data')

# OR simpler — tar + upload + extract:
ssh $(fly ssh console -a wireup-relay) "rm -rf /data/wire-public-relay-state-backup"
fly ssh sftp shell -a wireup-relay <<<'put /tmp/spark-state.tar.gz /data/'
fly ssh console -a wireup-relay -C "tar xzf /data/spark-state.tar.gz -C /data/"
```

(Skip if you'd rather start fresh. Existing handles claimed on Spark
will need to re-claim on Fly. Pre-launch is a reasonable time to skip.)

### Step 6 — DNS cutover (Cloudflare dashboard)

In CF DNS for `wireup.net`:

1. **Add** `CNAME relay.wireup.net → wireup-relay.fly.dev` (orange-
   cloud / proxied). Fly issues the certificate via CF.
2. **Add** `CNAME wireup.net (apex) → wireup-relay.fly.dev` (orange-
   cloud). Replaces the current cloudflared-tunnel-to-Spark record.
3. Verify:
   ```bash
   dig +short relay.wireup.net  # CF IPs
   curl https://relay.wireup.net/healthz   # ok
   curl https://wireup.net/healthz         # ok
   ```

DNS propagation: 60 sec on CF edge, up to 5 min for stragglers.

### Step 7 — Decommission Spark relay

Once new traffic is hitting Fly and Spark's tunnel is no longer needed:

```bash
# Stop the Spark services (don't delete state yet — keep as backup):
systemctl --user stop wire-public-relay
systemctl --user disable wire-public-relay

# Spark cloudflared config: edit ~/.cloudflared/wire-config.yml
# Comment out (don't delete) the wireup.net + relay.wireup.net ingress
# blocks. Leave the wire.laulpogan.com legacy aliases pointing at Spark
# if you want existing v0.4 clients to keep working.

systemctl --user restart wire-public-tunnel

# Verify legacy still works:
curl https://wire.laulpogan.com/healthz   # → ok (still served by Spark)
```

Backup: `/home/admin/wire-public/relay-state/` stays on Spark untouched
for ~1 month as rollback insurance. Delete after you're satisfied with
Fly.

## What stays on Spark vs moves to Fly

| Component | Stays on Spark | Moves to Fly |
|---|---|---|
| `wire-relay-server` binary | ✗ (decommissioned) | ✓ |
| Slot state (`relay-state/`) | backup only | ✓ (`/data` volume) |
| `wire-public-landing` (static landing) | ✓ for now | (later, optionally CF Pages) |
| cloudflared tunnel | ✓ (legacy laulpogan only) | n/a |
| operator dev work + identity | ✓ | n/a |

## Rollback plan

DNS is the cutover gate. Any problem with Fly:

1. In CF DNS, change `wireup.net` apex CNAME back to point at the
   cloudflared tunnel record (or just delete the Fly CNAME — falls back
   to the prior tunnel record automatically).
2. Re-enable `wire-public-relay.service` on Spark:
   ```bash
   systemctl --user enable --now wire-public-relay
   ```
3. Spark's slot state was never touched during cutover. Traffic returns
   to Spark with no data loss.

Total rollback time: ~2 min (DNS cache).

## Cost estimate

| Resource | Plan | Cost |
|---|---|---|
| Fly.io hobby app, shared-cpu-1x, 256 MB | Free tier | $0 |
| Fly.io volume, 1 GB | Free tier covers first 3 GB | $0 |
| Cloudflare DNS + proxy | Free | $0 |
| Cloudflare Pages (if landing migrates) | Free | $0 |
| **Total** | | **$0 / mo** |

When you outgrow the free tier (~hundreds of concurrent SSE subscribers
or sustained CPU usage):
- `shared-cpu-2x` + 512 MB: ~$5/mo
- Add a second region (Fra or Sjc): another ~$5/mo

At wire's v0.5 scale, expect to stay at $0/mo for the first ~year.

## Security posture after migration

What the move actually buys:

- **Reduced blast radius**: relay-server bug now compromises a Fly
  container, not the operator's training/identity machine.
- **Image-based deploys**: every release is a clean container build
  from the SlanchaAi/wire repo. No drift between deployed binary and
  source.
- **Managed TLS**: Fly + CF handle cert rotation. No manual cert
  refresh.
- **DDoS at the edge**: CF orange-cloud absorbs L3/L4 floods before
  they reach Fly.
- **No inbound port on Spark**: actually true today via cloudflared
  tunnel, but the new architecture also doesn't have outbound-tunnel
  dependencies on Spark for production traffic.

What it doesn't buy:

- AGPL still applies: anyone running `wire-relay-server` (you, Fly,
  future forks) must publish source modifications under AGPL. Same as
  today.
- Authentication surface: relay still has no admin auth (no admin
  endpoints exist; slot tokens authenticate per-slot). If you add admin
  endpoints later (rate limits, abuse handling), `fly secrets set` for
  any auth token.
- Backups: Fly volumes aren't auto-snapshotted. Add a cron job that
  `tar`s `/data` to R2/S3 nightly if point-in-time recovery matters
  (it doesn't yet at v0.5 — slot data is ephemeral by design).

## When to merge this branch

Merge `fly-deploy-stub` → `main` **after the first successful deploy**:

1. Run Steps 1-4 above.
2. If `https://wireup-relay.fly.dev/healthz` returns `ok`, merge.
3. DNS cutover (Step 6) can happen pre- or post-merge.

Don't merge before a successful deploy — having `Dockerfile` + `fly.toml`
on main without a corresponding Fly app is confusing for future readers.

## Mac-claude resumption pointer

When Mac-claude reads this doc:

- Branch is `fly-deploy-stub`. Stub files are present. No Fly app exists
  yet (operator hasn't registered).
- Operator needs to: (1) sign up at fly.io, (2) install flyctl on Mac,
  (3) `fly auth login`. Then Mac-claude can run Steps 1-6.
- DNS cutover step requires CF dashboard click. Mac-claude can prep the
  command-line equivalent via `cloudflared` if operator prefers, but the
  CF web UI is simpler for a one-time cutover.
