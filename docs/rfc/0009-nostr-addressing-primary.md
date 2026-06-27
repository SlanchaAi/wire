# RFC-009: Nostr-addressing as the primary delivery path (on wire-operated relays)

**Status:** Discussion <!-- Draft | Discussion | Accepted | Rejected | Implemented | Superseded -->
**Tracking:** [#355](https://github.com/SlanchaAi/wire/issues/355)
**Author:** Claude Code agent (paired w/ @laulpogan)
**Date:** 2026-06-27
**Target:** v0.17 (post-1.0; explicitly NOT a soak-window change)
**Question this answers:** Should wire invert RFC-007's precedence — make pubkey-addressed publish/filter the *primary* delivery semantics on **wire-operated** relays — to remove the structural `PENDING_ACK` window and the single-mailbox outage surface, and retire the bespoke slot+token relay?

---

## TL;DR

- **Recommendation: yes — but post-1.0 (v0.17), scoped to wire-OPERATED relays (not public Nostr), and NOT justified by `PENDING_ACK`.** This is the inversion of [RFC-007](0007-nostr-transport-binding.md): that RFC added Nostr as an *additive fallback*; this one proposes making pubkey-addressing the *primary* delivery semantics.
- **The real trigger is resilience + maintenance burden, not the gap.** The wireup.net saturation outage (one stateful mailbox, can't horizontal-scale) and ~5 relay-hardening PRs in June (#336/#342/#347/#348) are the case. `PENDING_ACK` — now honestly surfaced by #354 — is the *symptom that raised the question*, but it's a minor labeled wart and the wrong reason to swap a substrate.
- **What it buys:** pubkey-addressing removes the `PENDING_ACK` window *structurally* (no per-peer write-credential to wait for), and publish-to-N / read-from-N replaces one-slot-per-peer (kills the single-relay SPOF). It also lets us **retire** the bespoke slot/token/SSE machinery in `relay_server.rs` for a standard Nostr relay (a build-vs-buy win).
- **What it costs (honestly):** the `slot_token` is the relay's write-authz (T11). On wire-operated relays, NIP-42 AUTH (writes gated to the trust ring) + receiver-side pin-filter replace it at the *same* trust boundary as wireup.net today. The recipient `p`-tag is in clear, so **public-relay** delivery is gated on **NIP-17** metadata privacy — currently named in RFC-007 but **unbuilt**.
- **Identity is unchanged.** Ed25519 DID, the one-name invariant, signed cards, `ORG_VERIFIED` — all transport-independent. This is a **verb** change, not a **noun** change.

## Motivation

`PENDING_ACK` is the symptom that exposed the question, but acting *because* of it would be a cannon on a fly. The actual drivers:

1. **Outage class.** wireup.net is a single stateful relay instance (one volume, no horizontal scale — [[project_wire_relay_ops]]). The June saturation outage (#342 capacity band-aid; #347 the under-lock-clone root cause) is structural to "one mailbox per peer on one relay." A relay *fleet* with publish-to-N / read-from-N is the durable answer; the slot model can't express it (a slot lives on exactly one relay).
2. **Maintenance burden.** `relay_server.rs` absorbed ~5 hardening PRs in June alone — SSE-subscriber ceilings (#336), under-lock clone + dead-sub leak (#347), intro-time sweep off the hot lock (#348), capacity (#342). That is real ongoing cost for a bespoke mailbox that an off-the-shelf Nostr relay (strfry, nostr-rs-relay) provides — store-and-forward, pubkey filters, NIP-42 AUTH, NIP-13 PoW — already hardened by a wider community.
3. **Structural costs of slot+token.** The `PENDING_ACK` window (a peer is pinned but its `slot_token` is empty until the `pair_drop_ack` lands — see #354, `src/trust.rs::effective_tier`), the one-slot-per-peer SPOF, and the token-bleed/clobber bug class (RFC-006 Part B; #344 `cmd_rotate_slot` clobbering endpoints) are all artifacts of capability-at-the-relay.

What's painful *today*: a single relay outage takes a peer offline; a freshly-paired peer can't send until the ack lands; and we hand-harden a mailbox instead of configuring a relay.

## Design

### 0. Relationship to RFC-007

RFC-007 introduced a `Transport` abstraction with `HttpSlot` (default) and `NostrWs` (additive), and the send path already falls back to Nostr (`src/send.rs::sync_send` → `deliver_over_nostr`, gated on `peer_nostr_transport` + a local secp key). **This RFC inverts the precedence** and follows the consequence to the relay: make pubkey-addressing primary, and retire the slot machinery rather than carry both forever.

### 1. Delivery semantics: address by key, publish, filter

- **No per-peer slot, no write-token.** A peer is addressed by its **transport pubkey** (the secp x-only key wire already mints for the RFC-007 D3 path; `peer_nostr_transport` in `src/endpoints.rs`). To send: publish a signed, `wire-x25519.v1`-sealed event `p`-tagged to the peer's pubkey, to the peer's configured **relay set**.
- **Receive = subscribe + pin-verify.** The daemon `REQ`-subscribes its own pubkey across its relay set; every event is signature-verified and dropped unless the sender is pinned (the existing receiver-side trust gate). This is the spam defense on the read side.
- **No `PENDING_ACK`.** There is no credential to wait for: the instant I hold your pubkey (from your pinned card) I can address you. The gap disappears by construction.

### 2. "wire-operated relays", not public ones

The operator runs (or wireup.net provides) Nostr relays with **NIP-42 AUTH** gating writes to the trust ring — *not* open-write. This is the crux that keeps the threat boundary identical to today:

- wireup.net **becomes a Nostr relay** (RFC-007 already proposed this) — now as the *primary* semantics, fronted by a **fleet** (≥2) for resilience. Per-company / self-hosted relays follow [RFC-003](0003-per-company-relays.md).
- Writes are AUTH-gated to pinned identities, so a stranger cannot fill your inbox (the property `slot_token` gave us). Reads are pin-filtered.
- The metadata a wire-operated relay sees is exactly what wireup.net sees today — no spread to strangers.

### 3. Pairing simplifies (consent becomes pin, not token issuance)

Today the bilateral handshake exists to *exchange write-capabilities* (`pair_drop` → `pair_drop_ack` carrying `slot_token`s). With pubkey-addressing there is no capability to exchange:

- **Dial** = "I publish a `pair_drop` event to your npub announcing my card." No token-free `/v1/handle/intro` bootstrap needed (the path Herman hardened in #334 folds into a normal addressed publish).
- **Consent** = the receiving operator **pins** the sender (the existing accept gate), after which the pin-filter surfaces their messages. Operator consent is preserved — it moves from "issue you a token" to "add you to my read filter."

### 4. Coexistence + retirement

- `relay_state.peers[*].transport` precedence flips to prefer `nostr`; `HttpSlot` stays for **one release** as fallback, then is removed for all but the private-single-box tier (open Q4).
- **Retired** (the build-vs-buy win): slot allocation, `slot_token` bearer-auth, per-slot SSE push, intro-slot bootstrap — the bulk of `relay_server.rs` — replaced by a configured Nostr relay + a thin NIP-42 policy hook.
- Identity, cards, `.well-known` resolution, tiers: **unchanged**, transport-independent.

## Security

Cross-ref `docs/THREAT_MODEL.md` (T1, T10/T11/T14) and [RFC-006 confidentiality sequencing](0006-confidentiality-roadmap-sequencing.md).

- **Write-authz (T11).** `slot_token` is removed. Replacement on wire-operated relays: **NIP-42 AUTH** (writes accepted only from trust-ring identities) + **receiver pin-filter** (drop unpinned senders). *On a public relay there is no per-recipient write-cap* → inbox-fill DoS; hence the wire-operated-relays scoping, plus NIP-13 PoW / paid-relay if public is ever used.
- **Metadata.** Verified: the Nostr send `p`-tags the recipient **in clear** (`src/nostr_event.rs::wire_to_nostr_addressed`: `p_tag = ["p", peer_xonly_hex]`). On a wire-operated relay this exposes who→whom to the **same** party that sees it today. On a **public** relay it spreads to many parties (RFC-007 §Security, "npub correlation"). **NIP-17/gift-wrap is the hard precondition for any public-relay delivery** — it is named in RFC-007 but not implemented.
- **Content confidentiality (T1).** Unchanged — `wire-x25519.v1` body sealing carries over verbatim (THREAT_MODEL T1). Note: the discriminator is deliberately `wire-x25519.v1`, **not** `nip44.v2`, so wire DMs are intentionally **not** readable by third-party Nostr clients — there is no free DM-interop dividend, and "go native" does not make wire a Nostr-DM citizen.
- **Key rotation / takeover.** Addressing-by-key makes the transport pubkey load-bearing for *delivery*, not just fallback. A rotated identity must re-publish its new transport pubkey in its signed card; the DID-as-key-commitment succession rule ([RFC-001](0001-identity-layer.md)) governs it. Grindable-nick pin-overwrite (#245) is unaffected (still keyed by DID).

## Out of scope

- **Public Nostr relay delivery** — deferred until NIP-17 lands; this RFC is wire-operated-relays only.
- **NIP-17 / gift-wrap implementation** — its own RFC on the RFC-006 confidentiality track.
- **Third-party Nostr-client DM interop** — precluded by the deliberate `wire-x25519.v1` ≠ `nip44.v2` choice; not a goal.
- **Any 1.0 / soak-window change** — this is v0.17. 1.0 ships on the current substrate and soaks.
- **Immediate `HttpSlot` removal** — one-release coexistence minimum.

## Acceptance criteria

Each: threshold · how measured · owner. Includes a kill criterion.

1. **No-gap delivery** — a freshly-paired peer receives a message with **zero** `PENDING_ACK` window (no ack round-trip). *Measured:* e2e dial→send→deliver asserting no intermediate ack event. *Owner:* impl.
2. **Outage survival** — with an N≥2 wire-operated relay set, killing one relay mid-stream drops **0** delivered messages (publish/read failover). *Measured:* e2e that kills a relay and asserts continuity. *Owner:* impl.
3. **Write-abuse parity** — a write to a wire-operated relay from a non-trust-ring identity is **rejected** (NIP-42 AUTH), matching the `slot_token` reject posture. *Measured:* reject-matrix test. *Owner:* security.
4. **Net simplification** — the retired slot/token/SSE LOC **exceeds** the Nostr-integration LOC added (this is a reduction, not a sidecar). *Measured:* diff stat on `relay_server.rs` + new code.
5. **KILL CRITERION** — abandon (keep slot+token primary) if *either*: (a) NIP-42-gated wire relays cannot hold the current write-abuse posture without per-relay operating cost exceeding today's single mailbox; **or** (b) the clear-`p`-tag metadata exposure cannot be held to the current trust boundary without first shipping NIP-17.

## Open questions

- **Q1 — key curve.** Keep the dual-key model (Ed25519 identity + secp transport, as RFC-007 D3 does today) or push a wire-NIP allowing Ed25519-native events? *Decision point:* before impl. *Owner:* @laulpogan. (Inherits RFC-007's central open question.)
- **Q2 — relay fleet ownership.** Does wireup.net operate the fleet, or do operators self-host per [RFC-003](0003-per-company-relays.md) deployment tiers? *Decision point:* deployment-tier ratification.
- **Q3 — consent semantics.** Is receiver-side pin sufficient operator-consent, or do we keep an explicit accept event for auditability? *Owner:* security.
- **Q4 — retire vs coexist.** How long does `HttpSlot` survive — one release, or indefinitely for the private-single-box tier where a controlled mailbox is fine? *Owner:* @laulpogan.
- **Q5 — relay implementation.** strfry vs nostr-rs-relay vs a thin wire relay — which, and what does the NIP-42 trust-ring policy hook look like?

## Alternatives considered

- **Do nothing (slot+token stays primary).** Valid: `PENDING_ACK` is now labeled (#354), so the gap is minor. *Why not:* it leaves the outage class (single mailbox per peer) and the ongoing relay-hardening burden in place. The outage was real, not hypothetical.
- **Public-relay native ("just go on Nostr").** Rejected: metadata spread to strangers without NIP-17, open-write inbox-fill abuse without per-recipient caps, and — because sealing is `wire-x25519.v1` not `nip44.v2` — *no* free third-party DM interop to show for it. All cost, little of the imagined upside.
- **Horizontal-scale the bespoke mailbox.** Addresses resilience but not `PENDING_ACK`, and keeps (grows) the maintenance burden; the single stateful instance can't horizontal-scale today without distributed-slot work that re-implements what a Nostr relay already does.

## Sources

Code/primary citations, inline above: `src/nostr_event.rs::wire_to_nostr_addressed` (clear `p`-tag), `src/send.rs::sync_send` + `deliver_over_nostr` (existing fallback), `src/endpoints.rs::peer_nostr_transport`, `src/relay_server.rs` (slot/token bearer-auth, "Token holder may read + write"), `src/trust.rs::effective_tier` (`PENDING_ACK`), `docs/THREAT_MODEL.md` T1, [RFC-007](0007-nostr-transport-binding.md) §Security (npub correlation / NIP-17), [RFC-006](0006-confidentiality-roadmap-sequencing.md), [RFC-003](0003-per-company-relays.md), [RFC-001](0001-identity-layer.md). Outage history: [[project_wire_relay_ops]] / #342 / #347. `[P, wire repo @ d9b47f8, 95]`.
