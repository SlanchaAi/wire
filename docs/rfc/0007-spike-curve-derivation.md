# RFC-007 Spike — the curve gap (Ed25519 ↔ secp256k1): RESOLVED → Option 1

**Status:** Resolved <!-- spike companion to RFC-007 §Open-Questions Q1 -->
**Date:** 2026-06-05
**Resolves:** RFC-007 Q1 (the binding gate on the Nostr transport binding)
**Verdict:** **Option 1 — dual-key, secp256k1 marked transport-only, cross-signed by the Ed25519 identity key.**

---

## The question

Wire identities are Ed25519. Nostr verifies **secp256k1/schnorr**; public relays (Damus, primal, nos.lol) reject anything else. How does a wire agent that owns ONE Ed25519 key participate on Nostr without maintaining a second, independently-managed identity?

Three options were on the table (RFC-007 Q1):
1. **Dual-key** — separate secp256k1 transport key, explicitly NOT an identity anchor.
2. **Ed25519 NIP** — push Nostr to accept Ed25519 (advocacy).
3. **HKDF derivation** — derive the secp256k1 key deterministically from the Ed25519 seed (single-key UX) — *only if a vetted derivation exists.*

## Findings (survey, 2026-06-05)

1. **Seed→per-curve derivation is standardized; scalar→scalar across curves is the anti-pattern.** SLIP-0010 derives *separate* master keys per curve from one seed using curve-specific HMAC keys, and exists **specifically to avoid** reusing a scalar across curves of different group order: *"different private and public key pairs should be used for these curves."* [P, github.com/satoshilabs/slips/slip-0010, 90] No standard (SLIP-0010, BIP-32, did:key Multikey) blesses "this secp256k1 key **is** this Ed25519 identity" — each curve's key is its own verification method.

2. **No clean prior art bridges Ed25519 identities onto Nostr.** did:nostr *generates* a fresh secp256k1 key rather than importing an Ed25519 one; the closest cross-curve work (sec-ed-cert) keeps the two keys **separate and cross-signed**, not derived. [P, nostrcg.github.io/did-nostr, 70] [S, github.com/eolszewski/sec-ed-cert, 40] *(Absence-of-evidence from negative search, not proof.)*

3. **Nostr is actively rejecting alternate curves.** NIP PR #1522 ("Multiple Public Key Types") is **NACK'd by core maintainers** ("This is insanity… NACK" — pablof7z; "same problem DIDs have with 200 methods… NACK" — Vitor Pamplona). Near-zero relay adoption. **Option 2 is advocacy against a closed door.** [P, github.com/nostr-protocol/nips/pull/1522, 85]

4. **HKDF-derive-a-secp-scalar is safe *as primitive*, unsafe *as identity claim*.** HKDF (RFC 5869) over a seed with rejection-sampling into `[1, n-1]` is standard and sound. [P, datatracker.ietf.org/doc/rfc5869, 90] The risky part is **semantic** — asserting the derived key is the same principal re-creates the cross-curve correlation that SLIP-0010 was written to prevent.

## Verdict — Option 1

**Dual-key, secp256k1 transport-only, cross-signed.** It is the only path with standards backing (SLIP-0010 per-curve separation), zero novel crypto, and no upstream dependency.

- **Single-seed UX is still available the legitimate way:** generate the Nostr key via SLIP-0010 *from the same seed* (one backup phrase) — but it is a **distinct** key, not a re-encoding of the Ed25519 scalar.
- **Bind identity to Ed25519; cross-sign the secp key.** Wire emits a signed statement *"npub X is my Nostr transport"* (Ed25519 over the secp pubkey). This preserves the [ONE-NAME invariant](../../) — the Nostr key is a transport endpoint, **never** a persona/identity anchor. It rides the `dh_pubkey`-style additive card slot (a `nostr_pubkey` transport field), consistent with RFC-006's reservation discipline.
- **Reject Option 2** (maintainer NACK, no relay path). **Reject Option 3 as specced** — not because the KDF is unsafe, but because no standard equates the two keys, and folding the secp key into identity is the anti-pattern. The safe subset of Option 3 (single seed → SLIP-0010 → distinct key) *collapses into Option 1*.

## Implications for RFC-007

- Q1 → **resolved, Option 1.** Unblocks RFC-007 D3 (the Nostr transport binding).
- Adds a card field `nostr_pubkey` (secp256k1, transport-only) + an Ed25519 cross-sig, both additive — fold into the same v0.15 reservation family as `enc` / `dh_pubkey` if desired, or land with the binding in v0.2.
- Wire's ONE-NAME invariant is **preserved**: a wire agent has one Ed25519 identity and an optional cross-signed Nostr *transport endpoint*.

## Thin-evidence flags

- The "scalar reuse across curves is unsafe" claim leans on SLIP-0010's design rationale + a secondary paper, not a recovered cryptographer quote. [T, moderncrypto curves thread, 30]
- "Nobody derives Ed25519→Nostr" is from negative search results, not an exhaustive audit.

## Sources

[SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) · [Nostr NIP PR #1522](https://github.com/nostr-protocol/nips/pull/1522) · [did:nostr](https://nostrcg.github.io/did-nostr/) · [RFC 5869 HKDF](https://datatracker.ietf.org/doc/html/rfc5869) · [sec-ed-cert cross-signing](https://github.com/eolszewski/sec-ed-cert)
