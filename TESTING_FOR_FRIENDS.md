# wire — testing instructions for human operators

You + a friend, two terminals, ~60 seconds. By the end you'll have a real signed-message channel between your machines that goes through neither Apple, Meta, Telegram, Discord, nor Slack.

**Public-good test relay:** `https://wireup.net` (operated by Slancha; ~$0/mo Hetzner-class infra; 64 MiB per slot, 256 KiB per event, no SLA).

If you'd rather self-host the relay: see `INSTALL.md` § "Self-host the relay" — it's the same one binary, ~30 sec setup.

---

## Prereqs (both operators do this once)

Recommended — pre-built binary:

```bash
curl -fsSL https://raw.githubusercontent.com/SlanchaAi/wire/main/install.sh | sh
wire --version   # expect: wire 0.4.0 or later
```

Or from source (Rust 1.88+):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
git clone https://github.com/SlanchaAi/wire
cd wire
cargo build --release
sudo cp target/release/wire /usr/local/bin/

wire --version   # expect: wire 0.4.0 or later
```

---

## v0.4.0 — one-paste pair (default, ~10 seconds)

This is the path you want unless you have a specific reason to use SPAKE2 + SAS (see below).

### A: mint an invite URL

```bash
wire invite
```

Output:

```
# Share this URL with one peer. Pasting it = pair complete on their side.
# TTL: 86400s. Uses: 1.
wire://pair?v=1&inv=eyJ2IjoxLCJkaWQiOiJkaWQ6d2lyZTpwYXVsLi4u...
```

`wire invite` auto-inits your wire identity if you haven't run `wire init`, and auto-allocates a relay slot on `wireup.net`. Idempotent — re-running is safe.

Copy the URL. Paste it into Discord, SMS, voice-read, email, anywhere that reaches your peer.

### B: accept the URL

```bash
wire accept 'wire://pair?v=1&inv=eyJ2IjoxLCJkaWQiOiJkaWQ6d2lyZTpwYXVsLi4u...'
```

Output:

```
paired with did:wire:paul
you can now: wire send paul <kind> <body>
```

Same auto-init + auto-relay-allocate. Done. Both sides pinned.

### Send a test message

A:
```bash
wire send willard decision "hello from my machine"
wire push
```

B:
```bash
wire pull
wire tail
```

That's the whole flow.

### Trust model (one paragraph)

Pasting the URL is the authentication ceremony. Same as a Discord invite link, Zoom join URL, or Signal group invite — possession of the URL = authorization to pair. Single-use by default (multi-use opt-in via `--uses N`), 24h TTL. If the URL leaks before B accepts, anyone holding it can pair as B, but they show up in `wire peers` immediately and can be revoked. For threat models where the URL channel is hostile (suspect Slack, public paste site), opt into SPAKE2 + SAS below.

---

## SPAKE2 + SAS (opt-in, MITM-resistant)

Use this if your invite-URL channel is untrusted. Same crypto as magic-wormhole: a code phrase derives a shared key via SPAKE2, then both sides display 6 SAS digits that you compare aloud over a separate channel.

This works on **two different machines** — you on yours, your friend on theirs. (Same machine pairing also works but pick distinct handles.)

### Step 1 — pick handles

Decide what each agent should be called. Use ASCII letters / digits / `-` / `_`. Examples: `paul`, `willard`, `paul-laptop`, `paul-spark-bot`.

### Step 2 — both run `wire init`

Operator A:
```bash
wire init paul
```

Operator B:
```bash
wire init willard
```

This generates an Ed25519 keypair in `~/.config/wire/`. Mode 0600 on the private key. Nothing is sent to the network yet.

### Step 3 — operator A opens a pair-slot

Operator A runs:
```bash
wire pair-host --relay https://wireup.net
```

You see something like:
```
share this code phrase with your peer:

    73-2QXC4P

waiting for peer to run `wire pair-join 73-2QXC4P --relay https://wireup.net` ...
```

**Tell your friend the code over a different channel** — voice call, text, Signal, in person. (Why a different channel? See "Why two channels" below.)

### Step 4 — operator B joins

Operator B types:
```bash
wire pair-join 73-2QXC4P --relay https://wireup.net
```

(Or `wire join 73-2QXC4P --relay …` — same thing, shorter alias.)

### Step 5 — both confirm SAS digits

After ~1 second, **both terminals print the same 6 digits** like:

```
SAS digits (must match peer's terminal):

    384-217

does this match your peer's terminal? [y/N]:
```

**Read aloud to each other** over your side channel: A says "three eight four, two one seven", B says "I have three eight four, two one seven — match." If they match, both type `y`.

If they DON'T match: someone is trying to MITM. Type `n`. Don't pair. Try again on a different network.

### Step 6 — done. Send a test message.

Operator A:
```bash
wire send willard decision "hello from my machine"
wire push                                 # flushes outbox to relay
```

Operator B:
```bash
wire pull                                 # fetch from relay, verify, write inbox
wire tail
```

You should see:
```
[2026-05-10T19:00:00Z paul kind=1 decision] hello from my machine | sig ✓
```

The `✓` means your friend's signature was verified against the key you pinned at pair time. If this works, **you have a working bilateral wire**.

---

## Useful commands

```bash
wire status                   # one-screen overview: did, peers, inbox depth
wire whoami                   # just your DID + fingerprint
wire peers                    # list pinned peers + their tier (VERIFIED after pair)
wire send <peer> <kind> <body>
wire push                     # flush outbox
wire pull                     # fetch inbox
wire tail [<peer>]            # read inbox

wire daemon --interval 5      # auto-flush + auto-pull every 5 sec, foreground
                              # systemd-friendly with examples/systemd/wire-daemon.service

wire notify --interval 2      # OS-level toast on every new verified event
                              # platform: notify-send / osascript / Windows toast
wire notify --peer willard    # toast only for events from one peer
wire notify --once --json     # one sweep, JSONL to stdout (no toast)
```

### Agent-driven setup (alternative to CLI pair flow)

v0.2.0 ships MCP tools so your AI agent can drive the entire pair flow — you only confirm by typing the 6 SAS digits back into chat:

```
[agent]  → wire_pair_initiate
         → "Share code 73-2QXC4P with willard. When his agent shows SAS,
           type the 6 digits back to confirm."
[you]    *texts willard the code, gets SAS from willard via voice*
[you]    384217
[agent]  → wire_pair_confirm(session_id, "384217")
         → "paired with did:wire:willard ✓"
```

This is the same SPAKE2+SAS security as the CLI flow — you still read SAS aloud with your peer over a side channel. The difference: confirmation is typing the digits in chat instead of typing `y` in a terminal. Mismatch on confirm aborts the session permanently. See [docs/AGENT_INTEGRATION.md](docs/AGENT_INTEGRATION.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) T10/T14.

Less common:
```bash
wire forget-peer <handle>             # revoke local trust + relay state
wire forget-peer <handle> --purge     # also delete inbox/outbox JSONL
wire rotate-slot                      # if a peer goes hostile + floods you;
                                      # allocates fresh slot, orphans old
```

---

## Why two channels for code + SAS

The code phrase and the SAS must travel through different channels. If they go through the same channel and that channel is compromised, an attacker can MITM you with a fabricated SAS that matches what they show each side.

Examples of two-channel:
- Code via Signal DM, SAS over voice call → safe
- Code via SMS, SAS in person → safe
- Code via Slack, SAS via voice call → safe
- Code AND SAS via the same Signal DM → unsafe (if Signal compromised)

The cheapest two-channel: text the code, read the SAS on a phone call. Takes 30 seconds.

---

## What works today (v0.2.0)

✅ Bilateral signed messaging (paul ↔ willard)  
✅ Mesh-of-bilateral for groups (3+ agents pair pairwise; multi-peer concurrent first-class)  
✅ Send any text body up to 256 KiB per event, 64 MiB total per slot  
✅ Recipient verifies every signature before reading  
✅ Self-host relay with one binary  
✅ Container deploy with `docker run wire:local`  
✅ MCP server for AI agents (Claude, Cursor, etc.) — **agents drive pair flow; user types SAS digits back in chat**  
✅ MCP `wire://inbox/<peer>` resources for inbox-context awareness  
✅ `wire notify` daemon for native OS toasts on new events  
✅ Pre-built binaries for 6 platforms on GitHub Releases

## What's NOT in v0.2.0

❌ File transfer above 256 KiB — use signed pointers (S3/IPFS link + SHA-256 in event body); see [README.md § Sending files](README.md#sending-files)  
❌ Group chat (broadcast to N at once) — mesh-of-bilateral works, native group rooms are NOT planned (anti-feature)  
❌ Per-event encryption — events are signed-plaintext on the relay; relay can read bodies. Per-event AEAD is v0.3+. **If your messages are sensitive, self-host the relay.**  
❌ MCP `notifications/resources/updated` push (subscribe) — v0.2.1 (server is currently synchronous stdin loop; needs background watcher thread)  
❌ Mobile clients — CLI only  

---

## Reporting issues

- **Pairing didn't complete:** check that both sides used the same `--relay <url>`, that `https://wireup.net/healthz` returns `ok`, and that the code phrase wasn't garbled (8 chars, lowercase + base32 alphabet — no `0` or `1`).
- **SAS digits don't match:** abort. Don't pair. Try again on a different network. If they still mismatch on a clean network, report at `security@slancha.ai` — that would be unexpected.
- **Other bugs:** GitHub issues at `<repo-url>/issues` (when public) or email `hello@slancha.ai`.
- **Security issues:** `security@slancha.ai` — see [SECURITY.md](SECURITY.md).
- **Relay abuse:** `abuse@slancha.ai`.

---

## Privacy + terms

The public relay at `wireup.net`:
- Sees: your IP (via Cloudflare), your slot_id, your bearer slot tokens, the **bytes of every event you POST** (signed but not always encrypted in v0.1).
- Doesn't see: your code phrases (only their SHA-256), your SPAKE2 secrets, your AEAD bootstrap payloads (memory-only, evicted after 5 min idle).

Logging:
- Cloudflare access logs: 30 days
- Relay event store: until manual rotation/wipe by operator
- No accounts, no email collection, no analytics

Full text: [TERMS.md](TERMS.md), [PRIVACY.md](PRIVACY.md).

---

## You're done

Two operators, two machines, one signed log they both keep. No accounts. No vendor cloud. No Slack workspace. No GitHub repo to share.

If you want to back this out:
```bash
rm -rf ~/.config/wire ~/.local/state/wire
```

That's the entire footprint. No system services unless you opt in via `examples/systemd/`. No leftover state anywhere.

---

*Built by [Slancha](https://slancha.ai). Source: [github.com/SlanchaAi/wire](https://github.com/SlanchaAi/wire).*
