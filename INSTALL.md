# Installing wire

Pick the path that matches your situation.

## 1. Pre-built binary (one-liner, recommended)

Once a release tag is published:

```bash
curl -fsSL https://wire.slancha.ai/install.sh | sh
```

What the script does:
- Detects your OS + arch (Linux / macOS, x86_64 / arm64)
- Downloads the matching pre-built binary from GitHub Releases
- Verifies SHA-256 against the sibling `.sha256` file
- Installs to `~/.local/bin/wire` (preferred if on `$PATH`) or `/usr/local/bin/wire` with sudo

Override defaults via env or flags:

```bash
WIRE_REPO_URL=https://github.com/your-fork/wire \
WIRE_DIST_URL=https://your-host/dist \
PREFIX=~/bin \
curl -fsSL https://wire.slancha.ai/install.sh | sh
```

## 2. From source (cargo)

If pre-built binary unavailable, install.sh falls back to this. You can also do it directly:

```bash
git clone https://github.com/SlanchaAi/wire
cd wire
cargo build --release
./target/release/wire --version

# Install to ~/.cargo/bin/
cargo install --path . --bin wire
```

Requires Rust 1.88+ (edition 2024). [rustup.rs](https://rustup.rs) installs Rust in 60 seconds.

## 3. Package managers (planned)

| Manager | Status | When |
|---|---|---|
| Homebrew (`brew install wire`) | planned | post-public-launch |
| AUR (`pacman -S wire-bin`) | planned | post-public-launch |
| Nix flake | planned | post-public-launch |
| Scoop / winget | planned | post-public-launch |
| crates.io (`cargo install wire`) | planned | post-public-launch |

Tracking in [BACKLOG.md](BACKLOG.md) under "Distribution + tooling."

## 4. Verify the install

```bash
$ wire --version
wire 0.2.0

$ wire --help
Magic-wormhole for AI agents — bilateral signed-message bus
...
```

## 5. First-run setup

```bash
# Generate keypair (offline, no network)
$ wire init paul

# Optional: combine with relay-slot allocation in one step
$ wire init paul --relay https://relay.slancha.ai

# Or bind a relay later
$ wire bind-relay https://relay.slancha.ai
```

Public-good test relay: `https://relay.laulpogan.com`. Production relay (when migrated): `https://relay.slancha.ai`. Or self-host with `wire relay-server` (see below).

## 6. Pair with a peer

```bash
# Operator A (you):
$ wire pair-host --relay <url>
share this code phrase with your peer:
    73-2QXC4P
# read aloud over voice / signal / phone

# Operator B (peer, different machine):
$ wire pair-join 73-2QXC4P --relay <url>
SAS digits: 384-217
[y/N]: y
paired with did:wire:paul
```

Both terminals show the same 6-digit SAS — they read aloud, both type `y`, agent-cards exchange under AEAD-encryption, trust auto-pinned at VERIFIED.

## 7. Optional — long-running daemon

Foreground:

```bash
$ wire daemon --interval 5
wire daemon: syncing every 5s. SIGINT to stop.
```

systemd user unit (auto-restart, auto-start at login):

```bash
cp examples/systemd/wire-daemon.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now wire-daemon
journalctl --user -u wire-daemon -f
```

## 8. Optional — self-host the relay

```bash
$ wire relay-server --bind 127.0.0.1:8770
wire relay-server listening on 127.0.0.1:8770
```

Pair this with a TLS-terminating edge (Cloudflare Tunnel, Tailscale Funnel, Caddy, nginx). The relay doesn't terminate TLS itself.

systemd unit:

```bash
cp examples/systemd/wire-relay-server.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now wire-relay-server
```

See [DEPLOY_TEST.md](DEPLOY_TEST.md) for a fully-worked deployment recipe with Cloudflare Tunnel.

## 9. MCP integration

For AI agents (Claude Desktop, Claude Code, Cursor, Cline, Zed, anything MCP-aware):

```json
{
  "mcpServers": {
    "wire": {"command": "wire", "args": ["mcp"]}
  }
}
```

After restart the agent has:

**Tools** (10):
- Always agent-safe: `wire_whoami`, `wire_peers`, `wire_send`, `wire_tail`, `wire_verify`
- Identity: `wire_init` (idempotent — same handle no-op, different handle errors)
- Pairing (SAS-typed-back is the gate): `wire_pair_initiate`, `wire_pair_join`, `wire_pair_check`, `wire_pair_confirm`

**Resources** (`application/x-ndjson`):
- `wire://inbox/all` — recent verified events across all pinned peers
- `wire://inbox/<peer>` — recent verified events from a specific peer

The pair flow is now fully agent-callable. The user types the 6 SAS digits back into chat to satisfy `wire_pair_confirm`; mismatch aborts permanently. See [docs/AGENT_INTEGRATION.md](docs/AGENT_INTEGRATION.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) (T10/T14).

## 10. OS-level event notifications (`wire notify`)

```bash
# Fire desktop toasts on each new verified inbox event
wire notify --interval 2

# Filter to one peer
wire notify --peer willard

# Pipe JSONL to other tools instead of OS toast
wire notify --json | jq .

# Single sweep + exit (cron / smoke)
wire notify --once
```

Platform shim: `notify-send` on Linux, `osascript display notification` on macOS, stderr fallback on Windows (BurntToast/WinRT bindings v0.2.1).

Cursor at `$WIRE_HOME/state/wire/notify.cursor` persists across restarts.

systemd user unit:

```bash
cp examples/systemd/wire-notify.service ~/.config/systemd/user/
systemctl --user enable --now wire-notify
```

## 11. OpenClaw plugin

For OpenClaw users (npm publish pending — operator must `npm adduser` first):

```bash
npm install @slancha/openclaw-channel-wire
```

Then register the channel per OpenClaw's plugin API. See [github.com/laulpogan/openclaw-channel-wire](https://github.com/laulpogan/openclaw-channel-wire) for details.

---

## Uninstall

```bash
rm ~/.local/bin/wire
rm -rf ~/.config/wire ~/.local/state/wire
systemctl --user disable --now wire-daemon wire-relay-server 2>/dev/null
rm ~/.config/systemd/user/wire-daemon.service ~/.config/systemd/user/wire-relay-server.service
```

That's it. No registry, no system files outside your home dir.
