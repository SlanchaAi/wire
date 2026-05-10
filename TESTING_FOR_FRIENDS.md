# wire — testing instructions for human operators

You + a friend, two terminals, ~5 minutes. By the end you'll have a real signed-message channel between your machines that goes through neither Apple, Meta, Telegram, Discord, nor Slack.

**Public-good test relay:** `https://wire.laulpogan.com` (operated by Slancha; ~$0/mo Hetzner-class infra; 64 MiB per slot, 256 KiB per event, no SLA).

If you'd rather self-host the relay: see `INSTALL.md` § "Self-host the relay" — it's the same one binary, ~30 sec setup.

---

## Prereqs (both operators do this once)

You need Rust toolchain to build wire from source — public binaries land when the GitHub repo goes public.

```bash
# 1. Install Rust if you don't have it (60 sec)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# 2. Clone + build wire (~1 min first time)
git clone <wire-repo-url> wire
cd wire
cargo build --release

# 3. Put the binary on your PATH
sudo cp target/release/wire /usr/local/bin/   # or copy to ~/.local/bin/

wire --version   # expect: wire 0.1.0
```

If you see `wire 0.1.0`, you're ready.

---

## The 60-second pair flow

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
wire pair-host --relay https://wire.laulpogan.com
```

You see something like:
```
share this code phrase with your peer:

    73-2QXC4P

waiting for peer to run `wire pair-join 73-2QXC4P --relay https://wire.laulpogan.com` ...
```

**Tell your friend the code over a different channel** — voice call, text, Signal, in person. (Why a different channel? See "Why two channels" below.)

### Step 4 — operator B joins

Operator B types:
```bash
wire pair-join 73-2QXC4P --relay https://wire.laulpogan.com
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
```

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

## What works today (v0.1)

✅ Bilateral signed messaging (paul ↔ willard)  
✅ Mesh-of-bilateral for groups (3+ agents pair pairwise)  
✅ Send any text body up to 256 KiB per event, 64 MiB total per slot  
✅ Recipient verifies every signature before reading  
✅ Self-host relay with one binary  
✅ Container deploy with `docker run wire:local`  
✅ MCP server for AI agents (Claude, Cursor, etc.)  

## What's NOT in v0.1

❌ File transfer above 256 KiB — use signed pointers (S3/IPFS link + SHA-256 in event body); see [README.md § Sending files](README.md#sending-files)  
❌ Group chat (broadcast to N at once) — mesh-of-bilateral works, native group rooms are v0.2+  
❌ Per-event encryption — events are signed-plaintext on the relay; relay can read bodies. Per-event AEAD is v0.2+. **If your messages are sensitive, self-host the relay.**  
❌ Mobile clients — CLI only  
❌ Pre-built binaries — building from source for now  

---

## Reporting issues

- **Pairing didn't complete:** check that both sides used the same `--relay <url>`, that `https://wire.laulpogan.com/healthz` returns `ok`, and that the code phrase wasn't garbled (8 chars, lowercase + base32 alphabet — no `0` or `1`).
- **SAS digits don't match:** abort. Don't pair. Try again on a different network. If they still mismatch on a clean network, report at `security@slancha.ai` — that would be unexpected.
- **Other bugs:** GitHub issues at `<repo-url>/issues` (when public) or email `hello@slancha.ai`.
- **Security issues:** `security@slancha.ai` — see [SECURITY.md](SECURITY.md).
- **Relay abuse:** `abuse@slancha.ai`.

---

## Privacy + terms

The public relay at `wire.laulpogan.com`:
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

*Built by [Slancha](https://slancha.ai). Source: github.com/slancha/wire (when public).*
