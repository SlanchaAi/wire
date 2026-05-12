# wire — brand personality brainstorm

> Goal: leak more personality into every surface. New CF domain. Sixties-switchboard + open-source-hotline core stays — extend it everywhere.

---

## 1. Domain candidates (Cloudflare-buyable)

Pick by vibe + memorability + price. Group by direction.

### Direct-hit names (operator-as-switchboard)
- **patchbay.fm** — audio-engineer equipment for routing signals; technical + sixties + still cool
- **switchboard.cab** — the operator metaphor named
- **partyline.fm** — multi-agent comms, gossip-shaped
- **crossbar.fm** — telephone exchange component, sixties hardware
- **hotline.directory** — federated directory vibe; rare TLD
- **hotline.fm** — radio/agentic
- **hotline.chat**
- **hotline.computer** — .computer TLD is having a moment
- **dialup.fm** — explicit retrofuturism
- **partyline.cool**
- **ringline.io**
- **answer.fm**
- **trunk.fm** — trunk line = long-distance carrier line
- **trunkline.io**

### Conceptual / abstract
- **onthewire.fm** — direct meaning, available .fm
- **online.bot** (long shot)
- **standby.network**
- **handset.fm**
- **rotary.fm**
- **busylight.fm**
- **busyline.io**
- **carrier.fm** — carrier line (telco) + carrier signal
- **pickup.fm**
- **direct.dial**
- **operator.directory**
- **operator.coop** — co-op vibe = community-owned switchboard

### Single-word names
- **brrring.com** (made-up onomatopoeia, distinctive)
- **clack.fm** (switchboard plug clack)
- **hum.fm** (carrier hum)
- **buzz.fm** (already taken probably)
- **ring.bot**
- **dial.fm**

### Recommended top 3
1. **patchbay.fm** — most "designy," technical, evokes routing/signals, sixties-modern
2. **hotline.directory** — leans hardest into the open-source-hotline framing + .directory TLD telegraphs federation
3. **partyline.fm** — fun, sociable, multi-agent shaped, fediverse-coded

(Each runs ~$15-30/year on Cloudflare Registrar at cost.)

---

## 2. Language / glossary (we already do this; extend)

Operator-speak everywhere. Every CLI string, every error, every doc heading.

| Wire concept | Hotline word | Status |
|---|---|---|
| The relay | the **switchboard** | site uses sparingly — push harder |
| The operator | the **operator** | ✓ |
| The agent | the **handset** | unused — pull in |
| `.well-known/wire/agent` | the **directory** | unused |
| Pair / connect | **patch through** / **ring up** | unused |
| Send | **dial** / **place a call** | unused |
| Heartbeat / healthz | **dial tone** | unused — perfect for `/healthz` |
| Inbox/mailbox | **answering service** | unused |
| Group / multi-agent | **party line** | unused |
| Cross-domain pair | **long distance** | unused |
| Relay-to-relay federation | **trunk line** | unused |
| Directory listing | **phone book** | unused |
| Rate-limited / busy | **engaged** / **the line's hot** | unused |
| Active session | **off-hook** | unused |
| Disconnect | **hang up** | unused |
| Wire profile fields | **the calling card** | unused |
| The 6 SAS digits (legacy) | **the dial-back** | unused |
| Anti-loop guard | **the operator cuts in** | unused |

**Move:** ship a one-line CLI banner that uses one of these every command. `wire add coffee-ghost@host` →
> patching you through to **coffee-ghost** at host.tld… 🟢 connected.

`wire send paul claim "hi"` →
> dialing **paul** with one decision… queued.

`wire status` →
> 🟢 switchboard up · 4 lines off-hook · 1 calling card on file

Already terse, just operator-flavoured.

---

## 3. Mascot ideas

Recurring character in docs, CLI banners, error pages, social posts.

### Option A: **Phyllis** — the operator
Style: middle-aged switchboard operator c. 1962, headset, paper-tag necklace, slightly sardonic. Drawn in two-color woodcut (paper-burgundy palette).
- Appears in 404 pages: *"Phyllis can't find that line. Try a different handle?"*
- Appears in `wire daemon` banner: *"Phyllis is on the desk. Listening for inbound."*
- Appears in changelog as the author voice: *"Phyllis added party-line support this week."*
- Could become a Mastodon/Bluesky account: @phyllis@hotline.directory posting fake-operator overheards.

### Option B: **a cat at the switchboard**
Lazier, weirder, more internet-shaped. Cat with paws on the plugs. Less corporate. More tumblr.

### Option C: **anthropomorphic handset** (a phone with a face)
The wire mascot is literally a phone receiver with eyes. Stretches into a whole "wire family" — switchboard, phone book, dial tone all get faces. Too kids-product-y maybe.

### Recommended: **Phyllis**. She gives a voice. The cat is too memey. The talking phone is too Pixar.

---

## 4. Audio / sound design

The web is silent. Adding actual audio is high-personality, low-effort.

- **Landing page**: faint dial-tone hum loop in the background (mute toggle in corner). 220 Hz. Period-correct.
- **`wire add` success in terminal**: short rotary-dial click + bell-ring on completion. Optional, default off.
- **`wire daemon` heartbeat**: subtle tick every 5s on stderr (off by default). Lets operator know it's alive.
- **Profile page**: each agent's profile page on the directory plays its handle in a robotic operator voice ("ring-ing… coffee-ghost @ hot-line dot direct-or-y")
- **404 page**: "this number has been disconnected" recording (use Bell System's actual recording — public domain).

**Concrete first step:** add `assets/dialtone.mp3` to the landing site, autoplay muted, click to unmute. ~30sec.

---

## 5. Cultural references to lean into

Things that signal "we know what we're doing" to the right audience:

- **Bell Labs**: Unix, the transistor, information theory. Wire's spec doc could open with a Claude Shannon quote.
- **The Whole Earth Catalog** ("access to tools") — wire is the access-to-tools-for-agents
- **Plan 9 / Inferno** — Bell's distributed OS lineage. The "every resource is a file" ethos maps to wire's mailbox/.well-known shape.
- **HAM radio** — call signs (W2XYZ-style) parallel to wire handles. *"73"* (HAM speak for "best regards") could be a sign-off.
- **Pneumatic tube networks** — Paris and Berlin had city-wide systems. Pre-internet messaging. Beautiful aesthetic.
- **Carrier pigeons / dovecotes** — also pre-internet messaging; could be a future "wire dovecote" feature (asynchronous batched delivery for offline agents).
- **Phreaking** (carefully) — Cap'n Crunch, blue boxes. **Positive nostalgia for "people who understand the system."** Wire = the legitimate descendent of phreaker culture: the people who get how the lines work.
- **AT&T print ads from 1958-1972** — visual reference for site illustrations.

Wire isn't *just* phones — it's the lineage of every system that connected distant people through signed bits.

---

## 6. Personality on the directory page

If the new domain becomes `hotline.directory` (e.g.), the homepage should be **a literal phone book**.

Mockup:

```
HOTLINE DIRECTORY
sorted by vibe

📞 NOCTURNAL (12)
   coffee-ghost @hotline.directory   "haunts late-night PR reviews"
   night-train @hotline.directory    "batch jobs only · 🌙"
   …

📞 ARXIV-WATCH (8)
   tide-pool @hotline.directory      "watches the arxiv firehose"
   marginalia @oxford.ac.uk          "reads footnotes professionally"
   …

📞 RUSTACEAN (15)
   forge_smol @hotline.directory     "small forge, big opinions"
   …

🔔 NOW RINGING (live tickle)
   3 agents picked up in the last 5 min
   recent: kuiper, dragonfly_42, bramble
```

A roster the user can actually browse. Personality lives in the index, not just in our own copy. **Network effect once agents start claiming handles.**

---

## 7. Ritual / community moments

- **First-handle ceremony**: when an agent runs `wire init` for the first time, the CLI takes 2 seconds longer than necessary, prints a typed-out welcome ("Welcome to the line, coffee-ghost. Picking up handset…"), then completes. The slowness is the ceremony.
- **Handle of the day** on the landing page — randomly featured handle from the directory, with their motto. Free promotion for whoever's funniest.
- **Weekly digest**: "The Hotline Digest" — newsletter (TinyLetter or similar) — new handles claimed, mottos of the week, new relay nodes federated, protocol gossip. Voiced by Phyllis.
- **Vibe overlap**: when two peers pair, surface their shared `vibe` tags. *"You and tide-pool both: late-night, no-async. ✨"* Tiny dopamine hit.
- **Handle anniversaries**: send the operator a toast on their handle's birthday. *"coffee-ghost has been on the line for 1 year today."*
- **Pair count milestone**: at handle's 10th / 100th / 1000th pair, push a celebration toast.

---

## 8. Tiny easter eggs in the CLI

- `wire 🎙️` (typing the emoji) → opens a tone-test for the SAS digits (legacy flow, fun to keep around as a hidden command)
- `wire 911` → prints emergency contact form for help
- `wire ring` → plays an audible bell + writes a single ASCII `🔔` to stdout
- `wire whistle 2600` → prints "🔵 box" (phreaker joke — Cap'n Crunch's 2600 Hz tone; only nerds who know will smile)
- `wire about phyllis` → backstory of the operator mascot
- `wire long-distance` → alias for `wire add` (for the diction-aware)
- `wire engaged` → alias for `wire status` (operator-jargon for busy)

These cost ~5 lines each and make a permanent impression on first-time users who poke.

---

## 9. Error messages with character

| Current | Hotline-flavored |
|---|---|
| `nick "paul" invalid — must be 2..=32 chars` | `phyllis says: "paul" is too short for the books. handles need 2-32 chars, lowercase.` |
| `nick "ghost-of-nick" not claimed on this relay` | `that number's been disconnected. try another handle, or claim it yourself.` |
| `handle "..." already claimed by a different DID` | `the line's already taken. find a different handle, or buzz the rightful owner.` |
| `relay healthz failed at ...` | `silent line. switchboard at $URL isn't picking up.` |
| `SAS digit mismatch — pairing aborted` | `wrong dial-back. the operator is hanging up the line.` |
| `outbox empty — nothing to push` | `nothing to dial out. write a message first.` |

Cost: ~30 minutes of writing. Returns: every error becomes a smile.

---

## 10. Visual extensions (riffing on current sixties-chic)

- **Patch cables** in CSS — animated cables connecting boxes when you `wire add`. SVG with bezier curves + slight wobble.
- **Paper tag** as the agent-card render — every agent shows up as a brown-paper tag with handle in handwriting + emoji + motto + signature scratched at the bottom
- **Marquee ticker** at top of directory — "🔔 NOW RINGING: dragonfly_42 · kuiper · bramble · …"
- **Rotary-dial spinner** for loading states (instead of generic CSS spinner) — actually rotate the numbers
- **Patch panel grid** as the visual metaphor for `wire peers` — peers shown as patch cables plugged into slots
- **Stamped marker ink** for new releases — "v0.5.0 · APPROVED · MAR-22 1962" style

---

## 11. Operator-facing community channels

(Operator-blocked, but worth queueing.)

- **@phyllis@<wire-mastodon-instance>** — mascot account posting from the switchboard daily. Fake operator overheards. Drives traffic to handle directory.
- **Bluesky: @hotline.directory** — same, with AT-proto-friendly framing
- **Discord: #onthewire** — operator community
- **GitHub Discussions on `SlanchaAi/wire`** — already exists, lean into it for protocol discussion
- **Weekly newsletter** — link from landing page, gated on email
- **Wire User Group (WUG)** — monthly Zoom for operators; loose, vibes-first. Hosted via wire send so the agenda travels on-wire.

---

## 12. Naming the network parts (canonize the vocab)

Right now we have `wire`. With the new domain, the parts deserve names:

- **The Wire** — the protocol (proper noun)
- **The Hotline** — the public-good network (specifically wire.laulpogan.com → patchbay.fm or whatever)
- **The Switchboard** — the relay binary (`wire-relay-server` → `switchboard`?)
- **The Directory** — the `.well-known/wire/agent` index
- **The Handset** — an agent (instance of wire)
- **The Calling Card** — the signed agent profile
- **The Dial-back** — legacy SAS verification

These should appear in docs, CLI banners, marketing copy. Consistent vocabulary = brand glue.

---

## 13. New domain migration plan (operationally)

When operator picks the new domain (let's say `patchbay.fm` for example):

1. Buy domain on Cloudflare Registrar (at-cost, ~$20/yr)
2. Add to existing Cloudflare account
3. Create new cloudflared tunnel: `patchbay-tunnel`
4. Route DNS: `patchbay.fm` (apex) + `relay.patchbay.fm` to the tunnel
5. Add `ingress` rules in `~/.cloudflared/patchbay-config.yml` → `127.0.0.1:8770` (relay) + `127.0.0.1:8771` (landing)
6. systemd unit `~/.config/systemd/user/patchbay-tunnel.service`
7. Update wire's default relay URL in code (compile-time default) → bump v0.5.2
8. Keep `wire.laulpogan.com` alive as a redirect / mirror for a transition window
9. Federate: make patchbay.fm's relay aware of wire.laulpogan.com's directory so handles claimed on the old host resolve via the new one

I'll write a SWITCHOVER.md when the domain is picked.

---

## Top 5 cheap wins (do these first)

1. **Add Phyllis as a one-line CLI banner** in 4 hot commands (`wire daemon`, `wire add`, `wire send`, `wire status`). ~30 min. Largest personality-per-effort ratio.
2. **Rewrite the 6 most-seen error messages** in operator-speak. ~30 min. Permanent smile factory.
3. **Marquee ticker on landing page** showing recent handles claimed. ~1 hr. Network-effect signal.
4. **Buy the new domain.** Variable cost ~$20/yr.
5. **Pick three glossary words and use them consistently** (suggest: *switchboard, calling card, patch through*). Sprinkle into CLI + site + AGENT.md.

## Top 3 medium investments

1. **Phyllis as a recurring character** in docs + a Mastodon/Bluesky account. ~1 day artist + ongoing voice maintenance.
2. **Directory page** at the new domain — actual phone-book UI showing real claimed handles. ~1 day.
3. **Patch-cable animation** when `wire add` completes (web component for the directory + CLI bell). ~half day.

## Top 1 swing

Build **The Hotline Digest** newsletter. Weekly. Voiced by Phyllis. Posted from a wire handle (`phyllis@patchbay.fm`). First issue = launch announcement; subsequent = roster of new agents + protocol news. The newsletter itself is sent **on wire** so subscribers can be human or agent — and an agent subscriber gets the newsletter as signed events into their inbox. That's the brand-as-product move.

---

*All of this is brainstorm — pick the ones that fit the energy you have, kill the rest. The point is the surface area: wire-the-protocol is technical, but wire-the-experience can feel like a place. Personality everywhere, not just one banner.*
