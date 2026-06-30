# wire — container deployment kit

Artifacts to package + deploy wire in a container. **Optional.** The common
path is the native binary (`curl install.sh | sh`); containers exist mainly
for operators running a public-good relay or fitting wire into an existing
k8s / Fly / Cloud Run stack. If neither applies, use [native install](../INSTALL.md).

The Dockerfile produces a single distroless static image (~13 MB) that runs
every wire role — pick at `CMD` time.

For the **validated container-hardening recipe** (`--read-only --cap-drop=ALL
--no-new-privileges …`), pairing inside sandboxes, OpenShell egress policy, and
AI-security scanners, see [`docs/SANDBOXES.md`](../docs/SANDBOXES.md).

## Build

```bash
# from repo root:
docker build -f deploy/Dockerfile -t wire:local .

# or with podman:
podman build -f deploy/Dockerfile -t wire:local .
```

Multi-arch (linux/amd64 + linux/arm64) via buildx:

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t wire:local --load .
```

## Run

### Public-good relay

```bash
docker run -d --name wire-relay \
  -v wire-relay-state:/data \
  -p 127.0.0.1:8770:8770 \
  --memory=1g --cpus=0.5 \
  --restart=unless-stopped \
  wire:local
```

Pair with a TLS-terminating edge in front (Cloudflare Tunnel sidecar, Caddy, nginx, k8s ingress). The relay binds 0.0.0.0:8770 inside the container — host port maps decide what's exposed.

### Long-running sync daemon

```bash
docker run -d --name wire-daemon \
  -v wire-daemon-state:/data \
  --memory=256m --cpus=0.2 \
  wire:local wire daemon --interval 5
```

### One-shot CLI ops

```bash
# init + pair-host
docker run -it --rm \
  -v wire-state:/data \
  wire:local wire init paul --relay https://relay.slancha.ai

docker run -it --rm \
  -v wire-state:/data \
  wire:local wire pair-host --relay https://relay.slancha.ai
```

### MCP server (for agent runtimes that mount a wire container)

```bash
docker run -i --rm \
  -v wire-state:/data \
  wire:local wire mcp
```

## docker-compose two-node demo

```bash
docker compose up --build       # relay + daemon
docker compose exec daemon wire init paul --relay http://relay:8770
```

See `compose.yml` in repo root.

## Why distroless

- No shell → no shell injection
- No package manager → no `curl | sh` from inside container
- `nonroot` user by default (uid 65532) → no root access on filesystem mounts
- ~13 MB total image vs ~150 MB for ubuntu base — smaller attack surface, faster pulls
- Same binary as bare-metal install — no behavior drift

## Hardening flags worth adding (Docker)

```bash
docker run --read-only \
  --tmpfs /tmp \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --pids-limit=200 \
  -v wire-state:/data \
  wire:local
```

`--read-only` is fine because wire only writes under `/data` (mounted volume). `--cap-drop=ALL` works because the relay opens TCP from non-privileged ports only (8770 > 1024).

## Kubernetes

The image works as-is in any pod spec. Persistent state via PVC mounted at `/data`. Liveness probe: `wire --version` (distroless has no curl). Readiness probe: TCP socket on 8770. ResourceQuota/LimitRange enforce the same caps the systemd unit does.

Helm chart is BACKLOG'd — out of v0.1 scope.

## Fly.io / Railway / Render / Cloud Run

All accept the Dockerfile directly. Set `PORT`/`bind` accordingly:

```bash
# fly.toml
[http_service]
  internal_port = 8770
  force_https = true
[mounts]
  source = "wire_state"
  destination = "/data"
```

Cloud Run: relay-server is fine but cold-starts will lose pair-slot state every scale-to-zero. Use min-instances=1 for production.

## Limitations

- The build image needs network for `cargo fetch` of 294 deps (~30s on first build, ~5s with cache via `--mount=type=cache`).
- Distroless has no glibc → wire built must be musl-linked (the `Dockerfile` does this via `rust:1.88-alpine`).
- No `journalctl` inside the container; logs go to stdout/stderr → use `docker logs` or your aggregator.
