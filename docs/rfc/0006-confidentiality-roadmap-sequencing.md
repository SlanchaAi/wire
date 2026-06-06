# RFC-006: Confidentiality & group-crypto roadmap — consolidation + v0.15-window sequencing

**Status:** Draft <!-- Draft | Discussion | Accepted | Rejected | Implemented | Superseded -->
**Tracking:** <issue TBD>
**Author:** Claude Code agent (paired w/ @laulpogan)
**Date:** 2026-06-05
**Target:** v0.15.0 sequencing decision (rides the RFC-005 break window) — implementation v0.2/v0.3 line per existing backlog
**Question this answers:** Wire's per-event encryption is a *deliberately deferred* v0.1 decision with the standards already picked. Does the deferred work change the signed-event wire format such that it must ride the RFC-005 (v0.15) break-freely window — or is it additive and safely later?

---

## TL;DR

- **This RFC discovers nothing.** Every confidentiality primitive below is already chosen and scoped in `BACKLOG.md` / `THREAT_MODEL.md` / `ANTI_FEATURES.md`. Its only new content is **one sequencing decision** forced by RFC-005.
- Wire's confidentiality posture is **intentional and documented**: v0.1 events are signed-but-plaintext, relay-observable *by design* (`THREAT_MODEL.md:21,40`), with self-hosting as the mitigation and NIP-44 named as the v0.2+ upgrade (`BACKLOG.md:22`).
- **The one open question:** does NIP-44 body-encryption break the event format (encrypted `body` vs plaintext `body`)? If **breaking**, pull a format-version bump into the v0.15 break (RFC-005) so we don't break twice. If **additive** (an `enc` discriminator on the body, unknown-field-tolerant), it needs no special sequencing and stays on the v0.2 line.
- **Recommendation:** make the v0.15 event schema **encryption-ready but not encryption-requiring** — reserve the `enc` field + a `v4` major now (one-line schema reservation), ship plaintext default, land NIP-44 as additive in v0.2. Costs ~nothing now, removes the second-break risk.
- Group crypto (MLS) stays gated on "group rooms become real" (`BACKLOG.md:71`, `ANTI_FEATURES.md:13`) — **no change**; this RFC only asks that the group event envelope inherit the same `enc`-ready reservation.

## Guiding principle (ratified 2026-06-05): reuse > build

**Reuse other people's primitives wherever we can.** Wire's defensible work is the *seam* (signed-mailbox substrate + identity tiers), not re-implementing cryptography or transport that battle-tested crates already provide. This RFC's recommendations follow that rule: it picks **already-chosen external crates** (NIP-44, vodozemac, OpenMLS) and reserves schema for them, rather than authoring any new crypto. Where wire already reuses — Nostr NIP-01 events, W3C `did:wire`, the A2A AgentCard extension, SPAKE2/SAS — that is the model, not the exception. A backlog item that *replaces* wire-bespoke code with a standard crate (e.g. `BACKLOG.md:70` vodozemac swapping `seal_bootstrap`; `BACKLOG.md:17` reusing the ~10k existing Nostr relays instead of self-host-only) is **prioritized over** anything that grows wire's own crypto/transport surface.

## Motivation

RFC-005 establishes v0.15.0 as a **breaking, no-production-users** window: "break freely, no migration." Four phases remove deprecated MCP/CLI/on-disk surface.

Separately — and decided earlier — wire's per-event confidentiality is deferred:

- `THREAT_MODEL.md:21` — *"all event bodies are Ed25519-signed but **not encrypted** in v0.1… Per-event encryption (NIP-44 v2 or DIDComm authcrypt) is a v0.2+ candidate."*
- `THREAT_MODEL.md:40` — *"This is by design — wire events are not confidential against the relay in v0.1. Self-host the relay if your threat model demands relay-blind storage."*
- `BACKLOG.md:22` — *"Per-kind encryption policy (NIP-44 v2 preferred over DIDComm authcrypt)."*
- `BACKLOG.md:70` — vodozemac (Matrix Olm Double Ratchet) for FS/PCS, ~300 LOC, local to `sas.rs`.
- `BACKLOG.md:71` — MLS (OpenMLS / mls-rs) for **v0.3+ group rooms**, gated on real demand.
- `ANTI_FEATURES.md:13` — native group rooms deferred; mesh-of-bilateral (SyncThing precedent).

These two decisions were made independently and **have not been reconciled**. The confidentiality roadmap predates the v0.15 break window. The collision: if shipping NIP-44 later changes the wire format, and v0.15 is *the* sanctioned format break, then deferring encryption past v0.15 means **eating a second breaking change** for the same users — exactly what the no-production-users window exists to avoid.

Nobody hits this today (pre-launch, [[project_wire_launch_brand_lock]]). That is precisely why it must be decided now: the free break window is open and closes when the first real user lands.

## Design

### The format question (the whole RFC)

Today a signed event carries a plaintext `body` object; `event_id = sha256(canonical(body…))` and the Ed25519 signature commits to it (`src/signing.rs:128,194`). Pull-side consumers read `body` internals for routing/display (`src/pull.rs`).

Two ways NIP-44 could land:

**(A) Additive — body-discriminated encryption.** Add an optional `enc` field to the event body:
```jsonc
{ "kind": 1000, "enc": "nip44.v2", "body": { "ct": "<base64 NIP-44 ciphertext>" } }
```
Plaintext events omit `enc`. `event_id`/signature mechanics are unchanged (they commit to whatever `body` is). Unknown-field-tolerant parsers (wire's documented norm, RFC-001 §field-additive) ignore `enc` they don't understand and simply can't read the ciphertext. **No format break.** This is the same carrier discipline as [[project_wire_event_kind_carrier_rule]]: ride existing kinds, discriminate in the body.

**(B) Breaking — new event shape / major bump.** If NIP-44 adoption also reshapes canonicalization, key-id semantics (a separate X25519 DH key vs the Ed25519 signer — wire today has **only** Ed25519, no DH key on the card per `src/agent_card.rs`), or makes encryption mandatory per-kind, then pull-side that assumes plaintext `body` breaks → `schema_major` bump (`v3` → `v4`, `src/signing.rs:34,42`).

The DH-key point is the crux: NIP-44 needs an X25519 shared secret. Wire signs with Ed25519 and ships no encryption key on the agent-card. Adding a DH public key to the card is **additive** (new optional card field), but *using* it to gate readability is the real change. The Double-Ratchet path (`BACKLOG.md:70`, vodozemac) derives its channel from the existing SPAKE2 pairing secret — which wire **already establishes** (`src/pair_session.rs` `aead_key`) but currently discards after the bootstrap seal. That secret could seed a persisted per-pair ratchet with no new card field at all.

### Recommendation: reserve now, encrypt later

Make v0.15's event schema **encryption-ready, not encryption-requiring**:

1. **Reserve the `enc` body field** in the v0.15 schema doc (`docs/PROTOCOL.md`) — declared, optional, absent-means-plaintext. One paragraph, no code.
2. **Reserve a `dh_pubkey` optional agent-card field** (X25519), unset in v0.15. Documents the slot so adding it in v0.2 is field-additive, not a card-schema break.
3. **Keep `schema_version` at v3.x** but document that `enc`-bearing events remain v3 (additive) — so NIP-44 lands **without** a major bump if path (A) holds.
4. Ship v0.15 **plaintext-default**, unchanged behavior. Confidentiality work stays on the v0.2 (DM) / v0.3 (group) line exactly as backlogged.

Net: ~3 paragraphs of schema reservation in v0.15 buy the option to land NIP-44 additively later. If we *don't* reserve and NIP-44 turns out to need path (B), we pay a second break. The reservation is cheap insurance against that.

### Group envelope (no scope change)

Group rooms remain deferred (`ANTI_FEATURES.md:13`). The only ask: when group events ride the shared room slot (`src/group.rs`), they use the **same event envelope** as DMs, so the `enc` reservation covers them for free when MLS lands (`BACKLOG.md:71`). No group crypto is built or redesigned here. The existing model — creator-signed roster, bearer `slot_token` room key, kick = rotate-slot — is the documented v0.1/v0.2 posture and is **out of scope** to change.

## Security

This RFC **opens no new surface** — it ships only schema-doc reservations. It *touches* the confidentiality threat (`THREAT_MODEL.md` T1) by keeping the door open to close it additively.

Honest residual, unchanged by this RFC and stated for the record so the group case is as explicit as the DM case already is:

- **Relay sees plaintext** (DMs and group) until NIP-44/MLS land. Documented, by design, mitigated by self-hosting. (T1.)
- **Group has no forward secrecy / post-compromise security / cryptographic eviction**: a kicked member who cached the `slot_token` and prior messages retains plaintext until slot rotation; rotation re-keys *write access*, not past content. This is the *same* v0.1 confidentiality posture as DMs, but unlike T1 it is **not yet written in `THREAT_MODEL.md`**. **Action: add a group-confidentiality entry to `THREAT_MODEL.md`** mirroring T1, so the deferral is documented rather than implicit. (This is the one genuine documentation gap the code pass surfaced.)
- No pre-rotation: key add/revoke exists (`kind=1101/1102`, `active` flag, `src/signing.rs:276`) but the next key is not pre-committed, so a compromised current key can race a rotation. KERI-class hardening; low priority; note only.

## Out of scope

- **Building** NIP-44, vodozemac, or MLS — those stay on the v0.2/v0.3 backlog lines unchanged.
- Redesigning group crypto or the `slot_token` room-key model.
- Adding an X25519 key to the card *in v0.15* (only reserving the field).
- DIDComm authcrypt — already lost to NIP-44 in `BACKLOG.md:22`; not relitigated.
- A2A data-plane message model — wire already bridges A2A at the relay well-known (`docs/a2a-extension/`); the internal Nostr-NIP-01 envelope is a deliberate, working choice, not in scope to replace.

## Acceptance criteria

1. **Decision recorded:** v0.15 ships the `enc` + `dh_pubkey` schema reservations (path-A-ready) OR an explicit ruling that NIP-44 will be path (B) and is therefore pulled into a v0.15 phase. Measured: merged diff to `docs/PROTOCOL.md` + RFC-005 phase list. Owner: @laulpogan.
2. **Group confidentiality documented:** a T-numbered entry in `THREAT_MODEL.md` covering group plaintext + no-FS/PCS/eviction, parity with T1. Measured: grep `THREAT_MODEL.md` for a group-confidentiality threat. Owner: maintainer.
3. **No second break:** if encryption ships post-v0.15 via path (A), `schema_major` stays `v3` and a pre-v0.15 plaintext reader still parses (ignores `enc`). Measured: round-trip test, plaintext reader vs `enc`-bearing event. Owner: implementer of the v0.2 encryption PR.
4. **KILL CRITERION:** if analysis shows NIP-44 is unavoidably path (B) (e.g. canonicalization must change), **abandon the "reserve now" recommendation** — there is nothing to reserve, and the decision collapses to a binary "pull NIP-44 into v0.15 or accept a second break." Record which.

## Open questions

- **Path A or B? — RESOLVED → A (additive, stay v3).** Proven by the path-A fixture `signing.rs::enc_bearing_event_verifies_additively_path_a` (PR #228): an `enc`-bearing event signs + verifies with zero encryption-aware code, so NIP-44 needs no `v4` bump.
- **Ratchet vs DH-on-card? — RESOLVED → NIP-44 (X25519 `dh_pubkey`), defer vodozemac.** See the [vodozemac-vs-NIP-44 spike](./0006-spike-vodozemac-vs-nip44.md). vodozemac does NOT key from the SPAKE2 secret (it runs its own Curve25519 X3DH; the `BACKLOG.md:70` "seal swap" framing is a category error, ~800–1500 LOC not 300), its Double-Ratchet PCS only partially delivers for store-and-forward/passive-replier peers, and it doesn't compose with Nostr interop. NIP-44 is stateless, store-and-forward-clean, and gives the Nostr-DM path — accept "no FS/PCS," mitigate with relay TTL + Ed25519 integrity. vodozemac deferred unless a concrete threat model demands per-message FS for bidirectionally-active high-value pairs.
- **Does group ride DM encryption or wait for MLS?** If DM NIP-44 lands in v0.2 and groups in v0.3, is there a plaintext-group gap to flag louder? Owner: maintainer.

## Alternatives considered

- **Do nothing.** Leave confidentiality on the v0.2/v0.3 backlog, untouched by the v0.15 break. Valid if NIP-44 is path (A) — but we don't *know* that yet, and finding out after v0.15 freezes is the second-break risk. Rejected in favor of the cheap reservation that makes "do nothing later" safe.
- **Pull full NIP-44 into v0.15.** Maximal: encrypt now while breaking is free. Rejected: it front-loads ~300+ LOC of crypto + an X25519/ratchet decision into a release whose stated job (RFC-005) is *removal*, not addition. Schema reservation gets 90% of the safety at 1% of the work.
- **The dramatic version** ("rip the bespoke stack, adopt DIDComm/MLS/A2A wholesale"). Rejected: it misreads deliberate, documented deferrals as oversights. Wire already adopted the standards that fit (NIP-01, W3C `did:wire`, A2A extension, SPAKE2/SAS) and backlogged the rest (NIP-44, vodozemac, MLS) with crates and LOC. There is no NIH to undo.

## Sources

- `docs/THREAT_MODEL.md` T1 (§21–54) — v0.1 plaintext-by-design + NIP-44/authcrypt deferral + self-host mitigation. [internal, primary]
- `BACKLOG.md:17,22,63,70,71` — NIP-44 choice, vodozemac FS/PCS, MLS group rooms, SLIM/AGNTCY MLS gateway, Nostr-as-NIPs. [internal, primary]
- `ANTI_FEATURES.md:13` — native-group-rooms deferral, mesh-of-bilateral. [internal, primary]
- `docs/rfc/0005-remove-backwards-compat.md` — the v0.15 break-freely window. [internal, primary]
- `docs/did-methods/did-wire-method.md` — `did:wire` as a W3C DID v1.0 method. [internal, primary]
- `docs/a2a-extension/wire-identity-v1.md` — wire as first-class A2A AgentCard citizen. [internal, primary]
- NIP-44 v2 (encrypted payloads), MLS RFC 9420 (async group key agreement), DIDComm v2.1 (authcrypt) — external standards named in the backlog; not re-summarized here. [P, IETF/DIF/nostr, 85]
