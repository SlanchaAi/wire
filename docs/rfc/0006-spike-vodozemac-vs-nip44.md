# RFC-006 Spike — DM encryption route (vodozemac vs NIP-44): RESOLVED → NIP-44, defer D2

**Status:** Resolved <!-- spike companion to RFC-006 §Open-Questions Q2 -->
**Date:** 2026-06-06
**Resolves:** RFC-006 Q2 (FS/PCS ratchet vs DH-on-card) + corrects `BACKLOG.md:70`
**Verdict:** **NIP-44 for the DM payload layer now. Defer vodozemac (D2) — its backlog framing is a category error.**

---

## Why this spike exists

RFC-006 Q2 framed two routes for encrypting wire's bilateral DMs:
- **vodozemac** (Matrix Olm Double Ratchet) — FS/PCS, "from the pairing secret," `BACKLOG.md:70` est. ~300 LOC.
- **NIP-44 v2** (X25519 ECDH + ChaCha20) — no FS/PCS, simpler, Nostr-DM interop.

Before coding D2, the assumption "swap `seal_bootstrap`/`open_bootstrap` for vodozemac, keyed by the SPAKE2 secret" was verified against vodozemac's actual API. **It is false.**

## Findings (verified against vodozemac's API + the Olm/NIP-44 specs)

1. **vodozemac cannot be keyed by wire's SPAKE2 secret.** Its Olm `Account`/`Session` run their *own* X3DH-style handshake over **Curve25519** identity + one-time keys; there is no entry point accepting an external pre-shared secret. `create_outbound_session(cfg, identity_key, one_time_key)` / `create_inbound_session(cfg, their_identity_key, pre_key_message)` derive the root key from DH over prekeys, not from any caller secret. [P, docs.rs/vodozemac 0.10, 95] The backlog's "swap the seal" framing treats vodozemac as a symmetric AEAD you key with SPAKE2 output — it isn't. SPAKE2/SAS would survive only as the human-verified MITM defense authenticating a Curve25519 **prekey exchange**.

2. **Real cost ≫ 300 LOC.** wire is Ed25519-only with plaintext messages. Olm requires: a new Curve25519 identity key + a published, replenished pool of signed one-time keys; prekey exchange folded into pairing; and **per-message stateful session persistence** (Olm `Session` mutates on every encrypt/decrypt — must `pickle()` + atomic-write per peer per message, survive daemon crashes). Realistic: **~800–1500 LOC + an irreversible state migration**, not 300. [S, derived from API surface, 60]

3. **Store-and-forward stresses the ratchet; PCS only partially delivers.** Bilateral = Olm (not Megolm). Olm gives FS every message, but **PCS only advances when both peers send** (DH ratchet steps) — wire's often-passive repliers stall it. vodozemac caps skipped keys (MAX_MESSAGE_KEYS=40/chain, ×5 chains; MAX_MESSAGE_GAP=2000) → beyond the gap a message is **permanently undecryptable**. Hours offline is fine (in-order buffered messages decrypt), but the local daemon makes **session-state loss** likelier than Matrix's server-buffered world assumes. [P, vodozemac source + Double-Ratchet spec, 85]

4. **NIP-44 fits wire's shape.** Static conversation key (`conv(a,B)==conv(b,A)`), stateless, no per-message persisted state — clean under store-and-forward + intermittent peers. Spec is explicit: **no FS, no PCS**; mitigate with relay-side TTL/deletion + wire's existing Ed25519 signing for integrity. Bonus: the X25519 conv-key path gives the **Nostr-DM interop** RFC-007 wants. [P, NIP-44 v2 spec, 90]

5. **They don't compose.** Olm ciphertext isn't Nostr-readable, so "both" buys nothing — picking vodozemac forfeits the interop NIP-44 buys. Not an and; an or.

6. vodozemac: Apache-2.0, v0.10 (pre-1.0), one Least Authority audit (no significant findings), matrix-org-maintained. MSRV `[TBD: verify Cargo.toml rust-version]`. [P, matrix-org/vodozemac, 85]

## Verdict

- **Q2 → NIP-44** for the DM payload layer (the `enc: "nip44.v2"` container reserved in PROTOCOL.md §2.4, consumed by D1). Accept "no FS/PCS"; mitigate with relay TTL + Ed25519 integrity. Reuses a vetted spec, stays stateless, composes with the Nostr binding (RFC-007), removes the state-loss footgun.
- **Defer vodozemac (D2).** Re-scope it honestly if a concrete threat model ever demands per-message FS for high-value, **bidirectionally-active** peer pairs — as a real subsystem (Curve25519 identity + prekeys + persisted sessions), never a "seal swap." Measure wire's real send/reply ratio first (PCS-stall severity depends on it).
- **Correct `BACKLOG.md:70`** — the "vodozemac swap of seal_bootstrap, ~300 LOC, FS/PCS per message" line is mis-scoped; it does not key from the pairing secret and is 3–5× the LOC.

## Implications for the roadmap (#227)

- **D1 (NIP-44)** is the DM-encryption route. Unblocked: `enc`/`dh_pubkey` reservations already shipped (PR #228); D1 adds the X25519 `dh_pubkey` + the NIP-44 seal/open over the `enc` body.
- **D2 (vodozemac)** → deferred with rationale (not "todo," "don't unless the threat model changes").

## Thin-evidence flags

- LOC estimate is architectural, not measured. PCS-stall severity depends on wire's live send/reply ratio (unmeasured). vodozemac MSRV unconfirmed.

## Sources

[vodozemac docs.rs](https://docs.rs/vodozemac) · [matrix-org/vodozemac](https://github.com/matrix-org/vodozemac) · [NIP-44 v2 spec](https://github.com/nostr-protocol/nips/blob/master/44.md) · [Signal Double Ratchet spec](https://signal.org/docs/specifications/doubleratchet/)
