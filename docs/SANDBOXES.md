# Running wire in sandboxes

How to install, run, and pair `wire` inside container / egress-restricted /
AI-security-scanner sandboxes — and the one footgun (custom-port relays) plus its
fix. Everything in the **Docker** section below was validated in-situ on
2026-06-29 against the `deploy/Dockerfile` image (distroless musl static, 12.8 MB).

## Docker

`deploy/Dockerfile` builds one ~13 MB distroless image that runs every wire role
(relay-server / daemon / mcp / client) — pick the role at `CMD`. See
[`deploy/README.md`](../deploy/README.md) for the build + role matrix.

### Hardening flags — validated

wire writes **only** under `$WIRE_HOME` (`/data` in the image), opens TCP from
non-privileged ports, and needs no Linux capabilities. So the full container
hardening set works as-is — verified: `wire --version`, `wire whoami`,
`wire up <relay>` (mint identity + bind + claim + start daemon), and a
container-to-container encrypted message round-trip all succeed under:

```bash
docker run --rm \
  --read-only \                       # root FS immutable; state goes to the volume
  --tmpfs /tmp \                      # distroless has no writable /tmp
  --cap-drop=ALL \                   # wire needs no capabilities
  --security-opt=no-new-privileges \
  --pids-limit=200 \
  -v wire-state:/data \              # the ONLY writable path wire needs
  wire:local wire up http://relay:8770 --no-local
```

`--read-only` holds because wire's persistent writes (config, identity key, inbox
JSONL, slot cursors, atomic tmp+rename) land under `/data` — and the one path that
writes elsewhere, `wire identity create --anonymous` (which stages under the system
temp dir, i.e. `/tmp`), is covered by the `--tmpfs /tmp` in the recipe. Don't drop
`--tmpfs /tmp` on the assumption "everything goes to /data". `--cap-drop=ALL` holds
because the relay binds 8770 (> 1024) and clients open only outbound sockets.

### Two-node round-trip in containers

`deploy/compose.yml` brings up a relay + a daemon. To prove a full pair +
message between two *separate* container identities, see the
"custom-port relays" note below — on a non-wireup relay you must pair with the
**invite flow**, not `wire dial <handle>`.

## Custom-port / loopback / sandbox relays — use the invite flow

A wire **federation handle** is `nick@domain` and assumes a public, port-less
HTTPS domain (e.g. `alice@wireup.net`, implicitly `:443`). The domain validator
(`src/pair_profile.rs::is_valid_domain`) **rejects any `:port` suffix** — the `:`
fails its per-label character check — so a custom-port relay can't be named in a
handle at all. (A bare single-label host like `nick@relay` *passes* the validator
but then fails at DNS/TCP, not with a clean error.) So inside a sandbox where the
relay is `http://relay:8770` or `http://127.0.0.1:8771`:

```text
wire dial knit-ash@relay:8770  ->  error: domain "relay:8770" invalid
                                   — must be lowercase ASCII, dot-separated
```

**This is expected.** Pair via the invite flow instead, which carries the full
relay URL (port included) in the invite token and bypasses handle resolution
entirely — validated container-to-container on a `:8770` relay:

```bash
# On peer A (already `wire up`-ed against the local relay):
A_INVITE=$(wire invite --relay http://relay:8770 --json | jq -r .invite_url)

# On peer B:
wire accept-invite "$A_INVITE"     # pins A, exchanges signed cards
wire send <A-persona> "hello"      # now A is a pinned peer; bare nick resolves
```

Same-box sibling sessions (one `$WIRE_HOME`, distinct `WIRE_SESSION_ID`) can use
bare-nick `wire dial` directly — they resolve as local sisters, not federation.
See `scripts/hello-world-validate.sh` for that path.

> Limitation tracked: relaxing `is_valid_domain` to accept `host:port` for
> local/loopback scope (so `wire dial` works to a sandbox relay) is the E4 item
> in `docs/V0_13_2_PLATFORM_HARDENING.md`. Until that lands, the invite flow is
> the supported sandbox-relay pairing path.

## OpenShell (egress-policy sandboxes)

`landing/openshell-policy.sh` (also served at `https://wireup.net/openshell-policy.sh`)
runs on the OpenShell **host** and grants a named sandbox the minimum egress wire
needs: GitHub release assets (install) + `wireup.net` (runtime), nothing else.

```bash
curl -fsSL https://wireup.net/openshell-policy.sh | bash -s <sandbox-name>
# then, inside the sandbox:
curl -fsSL https://wireup.net/install.sh | sh
wire init <handle> --relay https://wireup.net
```

The runtime allow-list is wireup.net-only (single relay). Pairing against a
handle on a **different** relay domain needs that domain added to the policy's
`--add-endpoint` / `--add-allow` set.

**Drift guard:** `tests/openshell_policy_coverage.rs` asserts the policy's
allow-list covers every relay route `src/relay_client.rs` calls — so a new
client call can't silently get refused inside the sandbox. (It caught a missing
`DELETE /v1/handle/claim/:nick` allow that broke handle-release in-sandbox.)
If you add a relay call to the client, add it to `REQUIRED_ROUTES` in that test
and to the `wire_runtime` rule in the policy.

## AI-security scanners (Traceforce, etc.)

AI-posture scanners inventory the AI agents + MCP servers on a device and score
them. wire shows up as **both** a CLI on `PATH` and a configured **MCP server**
(the `wire` entry in an agent's MCP config). Two things to know:

- wire is not (yet) in such registries' curated MCP catalogs, so it is flagged
  as an **unknown / unvetted** MCP until added. Its risk profile is dominated by
  the traits that define it: it egresses to a relay (not a local-only MCP), runs
  a persistent daemon, and passes inbound peer messages into the agent's context.
- The clean dimension: wire's MCP tools are **messaging only** — no shell
  execution, package management, or destructive local commands.

To scan wire in isolation (without exposing a whole host's MCP inventory to the
scanner vendor), run the scanner inside a throwaway container whose only MCP is
wire, rather than installing the host agent on a daily-driver machine.
