# RFC-007: Nostr transport binding (wire-as-NIPs) — additive, wireup.net stays canonical

**Status:** Draft <!-- Draft | Discussion | Accepted | Rejected | Implemented | Superseded -->
**Tracking:** <issue TBD> (promotes `BACKLOG.md:17`)
**Author:** Claude Code agent (paired w/ @laulpogan)
**Date:** 2026-06-05
**Target:** v0.2+ (additive transport binding; not a v0.15 break)
**Question this answers:** How does wire reuse the existing ~10k-relay Nostr network + NIP-44 DMs for reach and interop — **without abandoning wireup.net or forcing any migration**?

---

## TL;DR

- **wireup.net is NOT replaced. It is repositioned and strengthened.** This RFC adds Nostr as a *second* transport binding **alongside** the existing HTTP-slot relay. wireup.net stays the default relay, the identity anchor, the brand front door, and the federation hub — and *gains* a Nostr endpoint so it federates into the wider network instead of sitting outside it.
- The reuse is nearly free because **wire events are already ~90% Nostr events**: `src/signing.rs:1` is "Ed25519 sign-over-event_id (Nostr NIP-01 style)", the kind ranges (`KIND_RANGES`, `signing.rs:52`) are NIP-01's, and `did:wire:<handle>-<fp>` shares the Ed25519 keypair with `did:key`/`npub`. The binding is a transport swap (~250 LOC HTTP↔WebSocket), not a protocol rewrite.
- **Identity interop for free:** a `did:wire` and an `npub` are the same Ed25519 key, so wire agents become addressable on Nostr and Nostr humans become addressable from wire — with wireup.net remaining the `.well-known` resolver and signed-card anchor (`docs/did-methods/`, `docs/a2a-extension/`).
- **NIP-44 DMs satisfy RFC-006's reserved `enc`** — adopting the Nostr binding gives us the encrypted-body path we reserve for, using a battle-tested spec instead of bespoke crypto (the `reuse > build` principle, RFC-006).
- **Zero forced migration.** Existing HTTP-slot peers are untouched. Nostr is opt-in, per-relay/per-peer. Self-hosted / wireup-grade relays stay recommended for high-volume agent traffic (public relays spam-filter bots — see Security).

## Motivation

The `reuse > build` principle (RFC-006, ratified 2026-06-05) says: lean on other people's primitives where the work isn't wire's seam. The single largest reuse lever on the board is `BACKLOG.md:17` — speak Nostr:

- **Reach.** ~10k existing Nostr relays (Damus, primal, nos.lol, …) + a social user base means wire agents can pair and message **without every operator self-hosting a relay**, and can address humans on Nostr (and vice-versa). Network effect wire cannot manufacture alone.
- **Encryption for free.** NIP-44 v2 is exactly the DM-encryption RFC-006 reserves for. Reuse it; don't author it.
- **Substrate, not app.** Wire's defensible work is the signed-mailbox seam + identity tiers, not running pipes. Nostr is a pipe wire can borrow.

**But the constraint is non-negotiable: do not lose wireup.net.** wireup.net is the default relay, the landing page compiled into the relay binary ([[project_wire_release_surfaces]]), the federation hub for same-box and cross-machine sister sessions, and the identity/well-known anchor. A naive "just move to Nostr" throws all of that away and dissolves the brand. This RFC exists to get the reuse **while keeping — and strengthening — wireup.net.**

## Design

### 1. Transport binding, not transport replacement

Introduce a `Transport` abstraction with two implementations:

- **`HttpSlot`** — today's relay (`src/relay_client.rs`, `relay_server.rs`): POST signed event to a slot, GET to pull. **Unchanged. Default.**
- **`NostrWs`** — new: WebSocket NIP-01 (`EVENT` / `REQ` / `EOSE`), pubkey-addressed, filter-subscribed.

The per-peer record (`relay_state.peers[*]`) gains an optional `transport` discriminator (default `http_slot`). A peer reachable via Nostr carries `transport: "nostr"`, a relay URL set (`wss://…`), and the peer's `npub` (= its `did:wire` key). Wire picks the binding per peer; the rest of the stack (sign → deliver → pull → verify) is binding-agnostic.

### 2. wireup.net: dual-protocol, default, strengthened

wireup.net runs **both** bindings:

1. The existing HTTP-slot relay (default for wire-native peers, same as today).
2. A **Nostr relay endpoint** (`wss://relay.wireup.net` or the same host) so wireup.net is itself a first-class node in the Nostr network.

This is the crux of "don't lose wireup.net." wireup.net is not bypassed by Nostr — it **becomes the agent-grade relay** in an interoperable network:

- **It stays the default.** New sessions bind wireup.net first, exactly as today.
- **It stays the identity anchor.** `did:wire` resolution + the signed agent-card + the A2A `.well-known` (`docs/a2a-extension/`) keep living on wireup.net regardless of which transport carries messages. An `npub` is reachable, but the *verified card* comes from wireup.net.
- **It gains a defensible niche.** Public Nostr relays spam-filter bots (`BACKLOG.md:17` caveat). wireup.net is the relay that **welcomes agent traffic** — high-volume, bot-first, no human-engagement heuristics. In a network where the free relays reject bots, the agent-grade relay is *more* valuable, not less. Network effect flows **into** wireup.net.
- **It federates instead of isolating.** Today wireup.net is an island wire-only relay. With a Nostr endpoint it interoperates — wire's reach grows while wireup.net stays the front door.

### 3. The mapping is small because wire is already Nostr-shaped

| wire today | Nostr | Gap |
|---|---|---|
| `event_id = sha256(canonical(body))`, `signing.rs:128` | NIP-01 event id (sha256 over serialized fields) | canonicalization differs in field set/order — a defined re-serialization, not new crypto |
| Ed25519 sign-over-event_id, `signing.rs:1` | NIP-01 schnorr/secp **(see Open Q)** | **key-curve mismatch** — Nostr is secp256k1, wire is Ed25519. Either dual-key, or a wire-NIP allowing Ed25519. The real open question. |
| `KIND_RANGES` 1000/10000/20000/30000, `signing.rs:52` | NIP-01 regular/replaceable/ephemeral ranges | already aligned by construction |
| `did:wire:<handle>-<fp>` | `npub` / `did:key` | same key bytes (modulo curve), interchangeable handle ↔ npub |

The published NIPs (`BACKLOG.md:17`):
- **NIP-W1** — SAS pairing: `kind 21001` SPAKE2 messages + `kind 21002` sealed bootstrap (reuses `src/pair_session.rs` seal).
- **NIP-W2** — signed agent-card with capability advertisement (`kind 10001` replaceable).
- **NIP-W3** — tier-trust client convention (UNTRUSTED/ORG_VERIFIED/VERIFIED as a client-side reading, never relay-enforced).
- **DMs** — reuse **NIP-44 v2** directly (satisfies RFC-006's `enc` reservation), **NIP-17** for sealed/metadata-private DMs.

### 4. Coexistence + fallback

- A peer may be reachable on HTTP-slot, Nostr, or both. Multi-relay redundancy (`THREAT_MODEL.md` v0.3 candidate) composes naturally: publish to wireup.net **and** N public relays; pull from whichever answers.
- No flag-day. Operators opt a peer/relay into Nostr; everything else stays HTTP-slot. wireup.net default unchanged.

## Security

- **Encryption:** NIP-44 v2 is the win — closes the relay-sees-plaintext gap (`THREAT_MODEL.md` T1) with a vetted spec. NIP-17 hides DM metadata from relays. **Reuse, not build.**
- **Public-relay availability / eclipse:** a public relay can drop or withhold events (same as the T-relay threat today, now spread across many operators). Mitigation: multi-relay publish + wireup.net as the always-trusted home relay. **This is a reason wireup.net must stay — it's the relay you control.**
- **Bot spam-filtering:** public relays may silently filter agent traffic → delivery gaps that look like censorship. Mitigation: wireup.net (agent-grade) as the guaranteed path; public relays as reach, not as the only path.
- **npub correlation:** publishing to public relays exposes the same metadata (pubkey, timing, IP) wireup.net already sees, but to more parties. Document; operators who care use NIP-17 + Tor/overlay (`THREAT_MODEL.md:272`).
- **Curve mismatch is a security-relevant decision** (Open Q1): dual-key (Ed25519 for wire-native + secp256k1 for Nostr) widens the key-management surface; a single Ed25519-over-Nostr NIP keeps one key but needs ecosystem buy-in. Resolve before shipping.

## Out of scope

- **Replacing the HTTP-slot transport.** It stays, default. This RFC is purely additive.
- **Replacing or deprecating wireup.net.** Explicitly forbidden by this RFC's framing — wireup.net is load-bearing brand + infra + identity anchor.
- **Group rooms / MLS** — separate track (`BACKLOG.md:71`, deferred); Nostr group constructs (NIP-29) are a *future* RFC, not this one.
- **Forcing existing peers to migrate.** Never.

## Acceptance criteria

1. **Additive proof:** with the Nostr binding compiled in but no peer opted in, every existing HTTP-slot e2e (`tests/e2e_bilateral.rs` et al.) passes unchanged. Owner: implementer.
2. **wireup.net preserved:** default bind is still wireup.net HTTP-slot; `did:wire` resolution + signed card still served from wireup.net; no code path makes a public Nostr relay the identity authority. Measured: bind/resolve integration test. Owner: @laulpogan.
3. **Round-trip over Nostr:** two wire agents pair (NIP-W1) and exchange a NIP-44 DM via a third-party Nostr relay, verified end-to-end. Owner: implementer.
4. **KILL CRITERION:** if the Ed25519↔secp256k1 curve gap forces either (a) maintaining two identity keypairs per agent, or (b) a wire-specific NIP that no public relay will carry — and neither is acceptable — **abandon the public-relay-reuse goal** and keep Nostr only as a self-hosted-relay wire format. The reuse value collapses without the public network; say so honestly rather than shipping a Nostr binding nobody else speaks.

## Open questions

- **Q1 (blocking): curve. — RESOLVED 2026-06-05 → Option 1.** See the [curve-derivation spike](./0007-spike-curve-derivation.md). Survey verdict: **dual-key, secp256k1 marked transport-only, cross-signed by the Ed25519 identity key.** Option 2 (Ed25519 NIP) is NACK'd upstream (Nostr NIP PR #1522); Option 3 (HKDF-derive secp from Ed25519) has no standard equating the two keys and re-creates the cross-curve anti-pattern SLIP-0010 exists to prevent — its safe subset (single seed → SLIP-0010 → *distinct* key) collapses into Option 1. ONE-NAME invariant preserved: identity stays Ed25519, the Nostr key is a cross-signed transport endpoint via an additive `nostr_pubkey` card field. This unblocks D3.
- **Q2: wireup.net topology.** Same host serving HTTP-slot + `wss://`, or a separate `relay.wireup.net` Nostr node bridged to the slot store? Owner: infra.
- **Q3: default relay set.** Which public relays (if any) does wire default-publish to, vs opt-in only? Spam-filter risk argues opt-in. Owner: @laulpogan.
- **Q4: npub UX.** How does a `did:wire` ↔ `npub` map surface to operators without confusing the one-name invariant ([[project_wire_one_name_invariant]])?

## Alternatives considered

- **Nostr-only (drop wireup.net).** The reuse-maximalist position. **Rejected hard** — loses the brand, the embedded landing, the federation hub, the identity anchor, and the agent-grade-relay niche. The entire point of this RFC is reuse *without* that loss.
- **Stay HTTP-slot only.** Status quo. Rejected: forfeits the reach, the public-relay TAM, the human↔agent addressing, and a free NIP-44 encryption path.
- **ActivityPub instead of Nostr.** Bigger network (Fediverse), but actor/server model needs reachable HTTP servers and doesn't share wire's keypair-as-identity. Nostr's relay+pubkey model is a near-exact structural match to wire's slot+DID model — far lower impedance. Rejected in favor of Nostr; AP remains a possible future gateway, not the transport.
- **DIDComm mediators.** Closest semantic match (already noted), but low ecosystem momentum and no existing public-relay network to reuse. Rejected: reuse value is the existing 10k relays, which DIDComm lacks.

## Sources

- `BACKLOG.md:17` — Nostr-as-NIPs, ~250 LOC transport swap, NIP-W1/W2/W3, NIP-44 DMs, public-relay TAM + spam-filter caveat. [internal, primary]
- `src/signing.rs:1,52,128` — wire events already NIP-01-shaped (sign-over-event_id, NIP-01 kind ranges). [internal, primary]
- `docs/did-methods/did-wire-method.md`, `docs/a2a-extension/` — wireup.net as resolver / well-known identity anchor. [internal, primary]
- RFC-006 — `reuse > build` principle; `enc` reservation that NIP-44 satisfies. [internal, primary]
- NIP-01 (events/relays), NIP-44 v2 (encrypted payloads), NIP-17 (private DMs), NIP-29 (groups, future). [P, github.com/nostr-protocol/nips, 85]
