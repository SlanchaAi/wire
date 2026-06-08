# RFC-006 D1 — NIP-44-style DM body encryption (implementation design)

**Status:** Draft <!-- Draft | Discussion | Accepted | Rejected | Implemented | Superseded -->
**Tracking:** <issue TBD>
**Author:** Claude Code agent (paired w/ @laulpogan)
**Date:** 2026-06-06
**Target:** v0.2 (DM-encryption line); schema reservations land in v0.15 per [RFC-006 roadmap](./0006-confidentiality-roadmap-sequencing.md)
**Resolves:** RFC-006 open-Q "Ratchet vs DH-on-card?" → NIP-44 symmetric core; this doc is the implementation-grade design for the DM (D1) milestone.
**Question this answers:** Given RFC-006 picked NIP-44's symmetric envelope and reserved an X25519 `dh_pubkey` card slot, *exactly* how does wire encrypt the DM body — which curve keys the conversation, which crates land, where the hooks sit, and what the adversarial review forces us to change before we cut code?

---

## TL;DR

- **Curve resolved: X25519, not secp256k1.** D1 encrypts wire's own Ed25519-signed events on wire's own relay. Zero Nostr-readability requirement (that lives in RFC-007/D3 over a *separate* cross-signed secp transport key — see [the curve-derivation spike](./0007-spike-curve-derivation.md)). secp coupling in D1 buys no interop and widens key management. Wire identities are Ed25519 → X25519 derives cleanly; RFC-006 already reserved an X25519 `dh_pubkey` slot (`PROTOCOL.md:71`) for exactly this.
- **This is NOT NIP-44 v2 on the wire.** It is NIP-44's *symmetric envelope* over an X25519 IKM. It is named honestly so no Nostr reader ever mis-decrypts a wire body: `enc` discriminator = **`wire-x25519.v1`** (not `nip44.v2`), HKDF salt = **`wire-x25519-v1`** (not `nip44-v2`), and the X25519 zero-shared-secret is rejected before key derivation.
- **2 new crates**, both pure-Rust and already in-family: `chacha20` (raw stream — the in-tree `chacha20poly1305` is AEAD, the wrong primitive for encrypt-then-MAC) and `x25519-dalek` (same dalek org as in-tree `ed25519-dalek 2`). `k256`/`nostr`/`subtle` are *not* needed.
- **Five adversarial-review findings folded into the design below** (not appended as caveats): (1) the symmetric layer has *zero* standalone direction/sender binding — all cross-context safety is load-bearing on the outer Ed25519 signature, so `open()` MUST never run on an unverified event, and we bind context into the HKDF `info` as defence-in-depth; (2) the Ed25519→X25519 derivation is specified to the byte (`clamp(SHA-512(seed)[0..32])`) with a committed cross-derivation golden vector, because getting it wrong fails *silently*; (3) decrypt-on-**read**, not decrypt-on-write — writing a plaintext body back into a signed event produces an unverifiable frankenstein; (4) the CLI and MCP send skeletons are unified (both emit `schema_version: v3.1`) *before* the seal hook, because they diverge today and that field gates compat; (5) a one-paragraph reconciliation that the X25519 choice forfeits no Nostr interop the spike's tiebreaker promised — that interop was always going to live in RFC-007's secp transport key.

---

## 0. Curve fork — RESOLVED, and its consequences carried through

**Decision: X25519, NOT secp256k1.** D1 encrypts wire's *own* Ed25519-signed events on wire's *own* relay. It has zero Nostr-readability requirement — that is a D3/RFC-007 concern requiring the *whole* Nostr envelope (schnorr sig + NIP-01 EVENT + secp transport key), not just the conversation-key curve. Paying secp coupling in D1 buys zero interop and widens key-management surface (forces every peer to carry/cross-sign a secp transport key to DM on wire's own transport). Wire identities are Ed25519 → X25519 derives cleanly (Montgomery birational map). RFC-006 already reserved an **X25519** `dh_pubkey` card slot (`PROTOCOL.md:71`) for exactly this.

Three consequences are carried through the entire design — these are the load-bearing deltas vs. literal NIP-44 v2:

| # | Consequence | Where it lands |
|---|---|---|
| C1 | **This is NOT NIP-44 v2 on the wire.** It is "NIP-44's symmetric envelope over X25519 IKM." Named honestly so no future Nostr reader mistakes a wire body for spec NIP-44 and mis-decrypts. | `enc` discriminator = `"wire-x25519.v1"`, **not** `"nip44.v2"`. Requires editing `PROTOCOL.md:150` (which currently shows `nip44.v2` as the example). |
| C2 | **HKDF salt changes** away from literal `"nip44-v2"` for domain separation, so identical plaintext never collides with a real NIP-44 keystream. | salt = `"wire-x25519-v1"` (§1). |
| C3 | **IKM is the raw 32-byte X25519 output**, not a serialized x-coordinate. X25519 can yield an all-zero shared secret on low-order/contributory points — **reject all-zero before HKDF** (RFC 7748 §6.1). | §1 derivation, mandatory zero-check. |

Everything downstream of the conversation key (per-message HKDF-Expand, ChaCha20, HMAC-SHA256, padding, byte layout) is curve-agnostic and carries over from NIP-44 v2 **unchanged**, inheriting NIP-44's vetted construction. The security argument rests on the IKM being a uniformly-unpredictable 32-byte DH secret; X25519 satisfies that as well as secp256k1. [P, NIP-44 v2 spec + RFC 7748, 85]

**Residual forfeit (documented, accepted):** we lose any third-party review done specifically against the secp256k1+NIP-44 *pairing*. Mitigated by treating this as wire-custom, documenting C1–C3 in `PROTOCOL.md`, and conformance-testing the curve-agnostic symmetric core against the official vectors (§7, with curve-bound layers excluded).

### 0a. Interop reconciliation (review finding #5 — folded in)

The vodozemac-vs-NIP-44 spike ([`0006-spike-vodozemac-vs-nip44.md:26,28,34`](./0006-spike-vodozemac-vs-nip44.md)) picked NIP-44 partly because "the X25519 conv-key path gives the Nostr-DM interop RFC-007 wants," and dinged vodozemac because "Olm ciphertext isn't Nostr-readable." **That tiebreaker does not apply to D1's own bytes, and this design states so explicitly so the stale rationale does not stand unqualified:**

- Real Nostr NIP-44 derives its conversation key from a **secp256k1** ECDH (Nostr identities *are* secp256k1). D1 derives from **X25519** with a different salt (`wire-x25519-v1`) and a renamed discriminator (`wire-x25519.v1`). Therefore a D1 ciphertext is **not** decryptable by any Nostr client, and a Nostr NIP-44 DM is **not** decryptable by D1 — *regardless of curve*.
- This forfeits **nothing** that secp-in-D1 would have bought, because Nostr readability needs the whole Nostr envelope over the **secp transport key**, which [`0007-spike-curve-derivation.md`](./0007-spike-curve-derivation.md) already resolved to live on a *separate* cross-signed `nostr_pubkey` (Option 1), not on the wire identity's DH key.
- **Honest framing:** D1 over wire's own relay is wire-private-by-design and was never going to be Nostr-readable. Cross-ecosystem interop is real but lives in **RFC-007/D3** via the secp transport key + NIP-17/NIP-44-over-secp. *(A one-line correction note is added to `0006-spike-vodozemac-vs-nip44.md:26/28` in the §10 doc step.)*

---

## 1. Conversation-key derivation (chosen curve + exact steps)

```text
shared = X25519(our_x25519_priv, peer_dh_pubkey)        // 32 bytes, RFC 7748
REJECT if shared == [0u8; 32]                            // C3: contributory/low-order guard
conversation_key = HKDF-Extract(hash = SHA256,
                                 salt = b"wire-x25519-v1",  // C2: domain-separated, NOT "nip44-v2"
                                 IKM  = shared)              // C3: raw output, NOT hashed, NOT an x-coord
// conversation_key = 32-byte HMAC-SHA256 PRK
```

- **Symmetry invariant holds natively:** `X25519(a, B) == X25519(b, A)` ⇒ `conv(a,B) == conv(b,A)`, role-independent. One long-term per-pair static key, reused across all messages between the pair.
- Inputs: our `x25519.key` (new on-disk file, §5) + peer's `dh_pubkey` read from `trust.json` `agents[<handle>].card.dh_pubkey` (§3).

### 1a. Ed25519 → X25519 derivation — specified to the byte (review finding #2 — folded in)

The brief's "derive from the seed (Montgomery map)" is **underspecified and a silent-failure footgun**: a wrong derivation still yields a *stable* 32-byte key that round-trips with itself, so the intra-process symmetry test (§7) passes while two independent re-implementations derive **mismatched** public keys and every cross-peer message fails to decrypt. The normative construction is therefore pinned exactly:

```text
// NORMATIVE — copy into PROTOCOL.md verbatim
h               = SHA-512(ed25519_seed_32)          // the 32-byte Ed25519 *seed*, not the public key
x25519_scalar   = clamp(h[0..32])                   // RFC 7748 §5 clamping (clear bits 0,1,2 of byte0; clear bit7, set bit6 of byte31)
x25519_pub      = x25519_scalar · basepoint         // Montgomery-u of the scalar's point
```

- This is **not** a birational map of the Ed25519 *public* key; it is the same scalar Ed25519 *signs* with (`clamp(SHA-512(seed)[0..32])`), so X25519 and Ed25519 share one root scalar by construction.
- **Implementation rule:** use `ed25519-dalek`'s expanded-secret-key path to obtain that scalar rather than hand-rolling `to_montgomery` on the public key — this provably ties the X25519 scalar to the signing scalar and removes the chance of a divergent hand-rolled derivation.
- **Loud-failure lock:** a **committed cross-derivation golden vector** — fixed `ed25519_seed` → expected `x25519_pub` → expected `conversation_key` against a fixed peer pub — so any future re-implementation or `dalek`-version bump that changes the derivation fails *in CI*, not silently in the field (§7).
- Seed-reuse is a deliberate single-root choice; its cryptographic-coupling trade-off is open-Q #2 and gated on a security pass before lock (§11).

## 2. Per-message construction (implementation-grade, encrypt-then-MAC)

**`Seal(conversation_key, plaintext_utf8) -> base64_payload`:**

```text
1. nonce = CSPRNG(32)                       // payload nonce; MUST be fresh per message, NOT content-derived
2. assert conversation_key.len()==32 && nonce.len()==32
3. keys = HKDF-Expand(SHA256, PRK=conversation_key, info=context_info, L=76)   // info = nonce ‖ ctx (§2c)
       chacha_key   = keys[0..32]           // 32B
       chacha_nonce = keys[32..44]          // 12B  ← distinct from the 32B payload nonce
       hmac_key     = keys[44..76]          // 32B
4. padded = pad(plaintext)                  // §2a
5. ciphertext = ChaCha20(key=chacha_key, nonce=chacha_nonce, counter=0, data=padded)   // RAW stream, RFC 8439 — NOT AEAD
6. mac = HMAC-SHA256(hmac_key, concat(nonce, ciphertext))    // AAD = the 32B payload nonce, exactly 32B
7. payload = base64_std_padded( concat([0x02], nonce, ciphertext, mac) )   // RFC 4648 WITH '=' padding
```

The inner version byte stays `0x02` (the symmetric envelope is byte-identical to NIP-44 v2's). The curve difference is signalled by the **outer** `enc` discriminator, not the inner byte — a wire reader never feeds this to a NIP-44 lib because the discriminator is `wire-x25519.v1`.

**§2a — Padding (verbatim from NIP-44, length-hiding):**

```text
calc_padded_len(L):                          # L = unpadded plaintext length, 1..=65535
  if L <= 32: return 32
  next_power = 1 << (floor(log2(L-1)) + 1)
  chunk = 32 if next_power <= 256 else next_power/8
  return chunk * (floor((L-1)/chunk) + 1)

pad(pt):   buf = u16_be(len(pt)) || pt || zeros( calc_padded_len(len(pt)) - len(pt) )
unpad(buf):
  L   = u16_be(buf[0..2])
  out = buf[2 .. 2+L]
  if L==0 OR len(out)!=L OR len(buf) != 2 + calc_padded_len(L): FAIL("invalid padding")
  return utf8(out)
```

Plaintext bounds: **1..=65535 bytes**. The 2-byte length prefix is prepended; the encrypted buffer is `2 + calc_padded_len(L)` bytes. All three `unpad` checks are mandatory (prevents length-tamper / padding-oracle).

**§2b — Byte layout:** `version(1=0x02) ‖ nonce(32) ‖ ciphertext(2+calc_padded_len) ‖ mac(32)`. Raw payload 99..65603 B; base64 132..87472 chars.

**§2c — Context binding in HKDF `info` (review finding #1 — folded in).** The symmetric layer alone provides **zero** sender/recipient/direction binding: the conversation key is identical in both directions (`conv(a,B)==conv(b,A)`), the MAC covers only `nonce ‖ ciphertext`, and open is keyed on the `from` handle. A captured A→B ciphertext re-injected as B→A would decrypt cleanly *under the symmetric layer alone*. Today this is saved **solely** by the outer Ed25519 signature, which commits to `from`/`to`/`event_id` over the canonical body (`signing.rs:261-313`) and is verified *before* decrypt (`pull.rs:230`). To remove the sole reliance and make the inner layer itself context-bound:

```text
context_info = nonce(32) ‖ u16_be(len from) ‖ from ‖ u16_be(len to) ‖ to
```

is fed as the HKDF-Expand `info` (step 3). **Length-prefixed, not 0x00-separated** (as implemented): injective regardless of the identity charset, since `from`/`to` are the **verbatim signed-event DIDs** (which contain `:` and `-`), not bare handles. This binds the per-message keys to direction, so a reflected/cross-direction ciphertext derives different `chacha_key`/`hmac_key` and fails the MAC even if an attacker could somehow bypass the signature. Binding them costs nothing and is covered by the golden + direction-binding tests (§7). **This is defence-in-depth, not a replacement for verify-before-open** — see §4 for the hard ordering invariant.

**`Open(conversation_key, base64_payload, from, to) -> plaintext` — strict order:**

```text
1. if payload[0]=='#': FAIL("version not supported")     // reserved future non-b64 encoding guard
2. assert 132 <= len(payload) <= 87472                    // b64 DoS bound
   raw = base64_decode(payload); assert 99 <= len(raw) <= 65603
   version,nonce,ciphertext,mac = split(raw)
   if version != 0x02: FAIL("version not supported")
3. keys = HKDF-Expand(... info = nonce ‖ u16(len from) ‖ from ‖ u16(len to) ‖ to ...)  // SAME context (§2c)
4. mac' = HMAC-SHA256(hmac_key, concat(nonce, ciphertext))
   if !constant_time_eq(mac', mac): FAIL                  // CONSTANT-TIME, BEFORE decrypt
5. padded = ChaCha20(chacha_key, chacha_nonce, 0, ciphertext)
6. return unpad(padded)
```

Step 4 (MAC verify) **strictly precedes** step 5 (decrypt). Use `hmac::Mac::verify_slice` (constant-time internally) — no direct `subtle` dep needed.

## 3. `dh_pubkey` lifecycle — generate / emit / exchange / pin

> **Merge note (v0.15, #236):** SAS/SPAKE2 pairing was removed — **dial (signed `pair_drop`) is now the sole pairing path**, and `init_self_idempotent` moved to `src/init.rs`. This section is updated to that flow; the dh_pubkey still rides the signed card, so the mechanism is unchanged in substance, only the carrier path is renamed.

- **Generate:** at `init.rs::init_self_idempotent` (keygen `:111`, card build `:124`). Mint the X25519 keypair *together with* identity so card `dh_pubkey` and stored `x25519.key` are co-minted. Derive per §1a from the Ed25519 identity seed so it is stable + re-derivable; store the private scalar at `config_dir()/x25519.key` mode 0600 (§5).
- **Emit on card:** `agent_card.rs::build_agent_card` — add top-level `"dh_pubkey": b64(x25519_pub)`, **parallel to** `verify_keys`, never inside it (`PROTOCOL.md §1`). `card_canonical` hashes all fields except `signature`, so adding it before `sign_agent_card` makes the self-signature cover it automatically — **no signing change**. Add reader `card_dh_pubkey(card) -> Option<&str>` next to `card_op_did`.
- **Exchange via dial (`pair_drop`) — zero new payload field:** dial (`cli.rs::cmd_dial`) builds + POSTs a signed `kind=1100 pair_drop` event carrying our own card; the receiver's daemon consumes it via `pair_invite.rs::maybe_consume_pair_drop`. Since the card already carries `dh_pubkey`, the X25519 key rides the existing **Ed25519-signed** card inside the pair_drop — no new field, no SPAKE2/AEAD bootstrap (that flow is gone). The card's self-signature + the receiver's pin are the integrity gate; a stripped/substituted `dh_pubkey` breaks the card signature → rejected before pin.
- **Pin per peer:** receiver verifies the card (`pair_invite.rs:341`, `verify_agent_card`) and pins via `add_agent_card_pin` (`pair_invite.rs:387` → `trust.rs`), which stores the **entire** peer card under `agents[handle].card` ⇒ `dh_pubkey` is automatically persisted in `trust.json` and self-signature-verified by construction. Read at derivation time via `trust["agents"][handle]["card"]["dh_pubkey"]`.

## 4. Code hooks — seal-on-send / open-on-pull (signing stays body-agnostic)

The path-A invariant (an enc-bearing event signs/verifies with zero crypto-aware code) is already proven by `signing.rs:469-507` (`enc_bearing_event_verifies_additively_path_a`). Hooks sit **around** sign/verify, never inside.

### 4a. Unify the send skeletons FIRST (review finding #4 — folded in)

Before any seal hook lands, **the CLI and MCP event skeletons must be made identical on `schema_version`.** Today they diverge: the CLI event (`cli.rs:4395`) includes `"schema_version": EVENT_SCHEMA_VERSION` (= `v3.1`); the MCP event (`mcp.rs:1425-1432`) has **no** `schema_version` field and rides the legacy-accept path (`pull.rs:147` — absent ⇒ accept). The §6 compat argument ("enc-bearing events stay v3.1 so they pass the schema gate") is therefore **only true for CLI-originated** encrypted events; an MCP-originated one passes by being schema-*less* (legacy), and any future code that gates `enc` on `schema_version >= v3.x` would silently drop MCP-sent encrypted messages into the legacy bucket. The shared seal helper does **not** fix this — it wraps *body*, not the *skeleton*.

**Fix (step 0 of the hook work):** factor the event-skeleton build into the same shared helper as the seal (or, minimally, add `"schema_version": EVENT_SCHEMA_VERSION` to the MCP event at `mcp.rs:1425`) so both paths emit `v3.1`. The CLI↔MCP e2e (§7) **asserts the on-wire event carries `schema_version == v3.1` in both directions**.

### 4b. Seal — BOTH send entry points (producer-vs-consumer duplication; memory: `feedback_routing_tests_catch_what_review_misses`)

- CLI: `cli.rs:4394-4406` — between event build and `sign_message_v31` (`:4405→:4406`).
- MCP: `mcp.rs:1425-1438` — between event build and sign (`:1431→:1438`).

```rust
// after the (now-unified) event skeleton w/ schema_version=v3.1 + "body": body_value, BEFORE sign:
if let Some(ck) = conversation_key_for_peer(peer)? {       // None ⇒ plaintext (default)
    let ct = wire_x25519_seal(&ck, &body_value, from, to)?;   // base64, §2 (context-bound info)
    event["enc"]  = json!("wire-x25519.v1");               // C1: NOT "nip44.v2"
    event["body"] = json!({ "ct": ct });
}
let signed = sign_message_v31(&event, &sk_seed, &pk_bytes, &handle)?;  // UNCHANGED, body-agnostic
```

`sign_message_v31` (`:199-230`), `compute_event_id` (`:133`), `EVENT_SCHEMA_VERSION` (`:39` = `v3.1`) all untouched. The signature commits to `{ct}` opaquely (`PROTOCOL.md §2.4:155`). Factor `wire_x25519_seal` + `conversation_key_for_peer` into one shared helper so CLI and MCP call the *same* code — eliminating the divergent-path bug class.

Group send (`cli.rs:9086 cmd_group_send`) stays **plaintext for D1** (RFC-006 defers the group envelope to MLS) but reuses the same envelope so the hook is portable later.

### 4c. Open — decrypt-on-READ, after verification (review findings #1 + #3 — folded in)

**The brief's decrypt-on-write is mis-wired and is rejected.** The real inbox writer at `pull.rs:262` does `serde_json::to_vec(event)` on the whole borrowed `&Value` event — it never writes a standalone `body` field. To land a plaintext `body_out`, the design would have to clone+mutate the event and persist the clone; the moment it does, the stored line carries a **plaintext body** alongside the original `event_id`/`signature` that were computed over `{ct}` ⇒ the at-rest object is an **unverifiable frankenstein** (re-verification recomputes `event_id` over the now-plaintext body and fails).

**Chosen: decrypt-on-read.** Persist the verbatim signed event (ciphertext body) exactly as `pull.rs:262` already does — preserving `event_id`/`signature` integrity at rest — and decrypt at the two **read** surfaces:

1. `cli.rs:5169-5175` (inbox tail / display)
2. the `wire://inbox` MCP resource

Both call the same `wire_x25519_open` helper. (This is the §11 open-Q-1 "alternative" — the inbox-integrity break promotes it from deferred-if-needed to **the correct default**. It is also strictly *better* at-rest posture: ciphertext, not plaintext, sits in `inbox/<peer>.jsonl`.)

**Hard ordering invariant (load-bearing — review finding #1).** The symmetric layer has no standalone authenticity or direction binding; sender-authenticity, recipient-binding, and replay/reflection resistance come **solely** from the outer Ed25519 signature + `event_id`. Therefore:

- `wire_x25519_open` **MUST NEVER** be called on a body that has not passed `verify_message_v31`. The pull path verifies first (`pull.rs:230`) and persists only verified events, so a read-surface decrypt is reading an already-verified line — *but this is a property of the write path, and the read surfaces must not be reachable from any unverified source.*
- Add a **code-level invariant**: `wire_x25519_open`'s call sites are grep-auditable and documented as "verified-events-only." Pull-side persistence of an event is the verification gate; the read surfaces decrypt persisted (hence verified) lines only.
- This verify-then-open ordering is a **hard gate, re-proven at every new call site**, not a note. The §2c context-binding (`from`/`to` in HKDF `info`) is the defence-in-depth backstop so that even a hypothetical unverified-open does not silently accept a reflected ciphertext.

Read-surface sketch:

```rust
// at cli.rs:5169 display AND the wire://inbox MCP resource — same helper:
let body_out = match event.get("enc").and_then(|e| e.as_str()) {
    Some("wire-x25519.v1") => {
        match conversation_key_for_peer(&from).ok().flatten()
            .and_then(|ck| event["body"]["ct"].as_str()
                .and_then(|ct| wire_x25519_open(&ck, ct, &from, &to).ok())) {
            Some(pt) => pt,                          // decrypted for display only
            None     => json!("<encrypted: cannot read>"),  // surface, do not crash
        }
    }
    _ => event["body"].clone(),                      // no enc / unknown enc → as-is
};
```

The on-disk line is **never** rewritten; only the rendered view is decrypted.

## 5. Conversation-key caching + storage

- **X25519 private key:** new file `config_dir()/x25519.key` (alongside `private.key`/`agent-card.json`/`trust.json` per `config.rs:31,:53-60`), mode **0600**. Co-minted at `init_self_idempotent`.
- **Peer `dh_pubkey`:** already persisted in `trust.json` `agents[<h>].card.dh_pubkey` (§3) — no new per-peer field.
- **Conversation key:** **derived on demand, cached in-process only.** X25519 + HKDF-Extract is cheap; the conversation key is a derived secret (not a new root) — **do not persist it** (avoids a second at-rest secret + invalidation complexity). Optional `HashMap<handle, [u8;32]>` memo in the daemon process, dropped on restart.
- **Cache invalidation on re-pin/rotation:** the in-process memo MUST be keyed so that a peer card re-pin (new `dh_pubkey`) **invalidates** the stale entry — invalidate on any `add_agent_card_pin` for the handle, or key the memo on `(handle, dh_pubkey)` so a rotated key misses and re-derives. A bare `handle`-keyed cache that never invalidates would keep deriving against a stale peer key after rotation.
- `conversation_key_for_peer(peer) -> Result<Option<[u8;32]>>` returns `None` when the peer has no `dh_pubkey` (legacy peer ⇒ plaintext fallback) or our `x25519.key` is absent.

## 6. Backward-compat (plaintext + unknown-enc tolerance)

- **Plaintext peers (no `enc`):** the seal hook is gated on `Some(ck)`; the open path matches only `Some("wire-x25519.v1")`. Absent ⇒ both are no-ops ⇒ today's path is byte-identical. Plaintext stays the **v0.15 ship default** (writers MUST NOT emit `enc` per `PROTOCOL.md:143`; D1 enables it in v0.2).
- **Unknown / unopenable `enc`:** an unrecognized discriminator, a missing peer `dh_pubkey`, or an open-failure ⇒ the event is persisted **verbatim** (ciphertext at rest, the decrypt-on-read default) and the read surface renders "encrypted, cannot read." **CRITICAL:** this MUST NOT route into the transient-reject branch (`pull.rs:285-307`) — that **blocks the cursor** (`pull.rs:21-32`) and wedges the whole pull on one undecryptable event. `enc`-failure is *terminal-for-readability*, not transient. It matches the existing verbatim-write Ok path (`:262`).
- **`schema_major` gate untouched:** `pull.rs:147-164` rejects only on major mismatch; enc-bearing events stay `v3.1` (after §4a unification, in *both* CLI and MCP directions) so they pass. Fixture `signing.rs:469` is the regression lock.

## 7. Test plan

**Conformance (symmetric core, against official vectors):** vendor `paulmillr/nip44` `nip44.vectors.json` as a dev-dep fixture; pin its SHA-256. Because we swapped curve+salt (C1–C3), test **only the curve-agnostic layers** — the `get_conversation_key` and full `encrypt_decrypt` vectors are NOT applicable (they bind secp + `nip44-v2` salt). Applicable:

- `valid.calc_padded_len` — pure padding formula, fully applicable. **Run first.**
- `valid.get_message_keys` — HKDF-Expand split (given a `conversation_key`): **applicable** — feed the vector's `conversation_key` directly, verify `{chacha_key, chacha_nonce, hmac_key}` slicing + ChaCha/HMAC. NB: with §2c context-binding, the upstream vector exercises the `info=nonce`-only path; run it against an explicit `info=nonce` test seam so the upstream bytes still validate the HKDF/ChaCha/HMAC plumbing, and validate the *context-bound* `info` against wire's own golden set below.
- **Wire-specific golden set (committed):** `{ed25519_seed, x25519_priv_a, x25519_priv_b, x25519_pub, conversation_key, nonce, from, to, plaintext, payload}` — locks (i) the §1a `seed → x25519_pub` derivation (review finding #2), (ii) the X25519 + `wire-x25519-v1`-salt conversation key, and (iii) the §2c context-bound payload. The seed→pub mapping is mandatory in this set, not just `conversation_key → payload`.

**Functional:**

- **Round-trip:** `seal(ck,m,from,to)` then `open(ck,·,from,to) == m` across lengths {1, 31, 32, 33, 256, 257, 65535}; assert payload length == expected bucket.
- **Symmetry:** `conv(a,B) == conv(b,A)`.
- **Cross-derivation golden (review finding #2):** fixed seed → expected `x25519_pub` → expected `conversation_key` with a fixed peer pub. Fails loudly on any dalek-version / derivation drift. *(The intra-process symmetry test cannot catch a wrong-but-stable derivation; this vector is the only thing that does.)*
- **Direction binding (review finding #1):** `open` with swapped `(from,to)` MUST fail the MAC (context-info mismatch) — proves reflection resistance at the symmetric layer independent of the signature.
- **Zero-IKM guard (C3):** craft a low-order peer point ⇒ derivation returns an error, never reaching HKDF.
- **Tamper (each MUST fail, pre-decrypt where applicable):** flip 1 ciphertext byte; flip 1 nonce byte; flip 1 mac byte; truncate; swap version to `0x01`/`0x03`; `'#'`-prefix; bad padding (length-prefix > slice). Assert MAC failure is caught **pre-decrypt**.
- **At-rest integrity (review finding #3):** persist a sealed event, re-read the JSONL line, re-run `verify_message_v31` — MUST still verify (proves decrypt-on-read leaves `event_id`/`signature` intact).
- **CLI↔MCP encrypted round-trip e2e:** real daemon — CLI sends sealed → MCP peer pulls + reads decrypted, AND MCP sends sealed → CLI reads decrypted; **assert the on-wire event carries `schema_version == v3.1` in both directions** (review finding #4). Gate `#[ignore]` + `serial` per `feedback_heavy_e2e_subprocess_contention`.
- **Backward-compat:** a plaintext peer round-trips byte-identical; a peer with unknown `enc` ⇒ the event lands verbatim, the cursor advances (assert no wedge), no transient-reject.
- **Cache invalidation (§5):** re-pin a peer with a new `dh_pubkey`, assert the next derive uses the new key, not the memoized stale one.
- **Regression lock:** `signing.rs:469` path-A fixture stays green.

**Gate before merge** (`feedback_release_gate_fmt_clippy` + `feedback_gate_exit_not_through_pipe`): `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test` — check `$?` on the **bare** command, never piped through `tail`/`head`.

## 8. Security non-goals (documented) + mitigations

**Non-goals (inherited from NIP-44 + our variant — MUST land in `PROTOCOL.md §2.4`):**

- **No forward secrecy** — static conversation key, no ratchet; key compromise decrypts all *past* messages.
- **No post-compromise security** — compromise decrypts all *future* messages.
- **No deniability** — the outer event is Ed25519-signed; provable a key signed it.
- **No post-quantum security.**
- **Limited size leak** — padding buckets length, does not constant-pad.
- **Metadata leak** — the relay sees IP + `created_at`; the pairing graph is relay-visible.
- **No standalone inner-layer authenticity** — the symmetric envelope is confidentiality + integrity-of-ciphertext only; **all** sender/recipient/direction/replay safety derives from the outer Ed25519 signature (§2c context-binding is defence-in-depth, not a substitute). `open()` MUST NOT run on an unverified event (§4c).
- **No third-party review of the X25519 + wire-salt pairing** (C1 residual) — only the symmetric core is vetted.
- **No Nostr interop on D1 bytes** (§0a) — by design; Nostr-DM interop lives in RFC-007/D3 over the secp transport key.

**Mitigations:**

- **Relay TTL** — send only to trusted relays; relay deletes events after a TTL (NIP-44-documented; partial FS mitigation).
- **Ed25519 integrity** — every body (cipher or plain) is signed; the MAC is over the ciphertext *and* the outer signature covers `{ct}`, so tamper is caught at two layers, and open never runs on an unverified event (§4c).
- **Context-bound HKDF `info`** (§2c) — reflection/cross-direction ciphertext fails the MAC at the symmetric layer too.
- **Constant-time MAC** (`verify_slice`) — no padding-oracle timing.
- **Zero-IKM reject** (C3) — no all-zero conversation key.
- **Ciphertext at rest** (decrypt-on-read, §4c) — `inbox/<peer>.jsonl` holds ciphertext, not plaintext; host FS perms (config dir 0700, keys 0600) backstop.

## 9. Crate additions

| Crate | Status | Justification |
|---|---|---|
| `chacha20` (default feat) | **NEW direct** | Raw ChaCha20 stream (RFC 8439). In-tree `chacha20poly1305` is AEAD — **wrong primitive** for encrypt-then-MAC. `chacha20poly1305` already depends on `chacha20` transitively ⇒ promoting it to a direct dep adds ~0 compiled code. MIT OR Apache-2.0. |
| `x25519-dalek` (v2) | **NEW direct** | X25519 ECDH. Same dalek-cryptography org as in-tree `ed25519-dalek 2`; pure-Rust, returns the 32-byte shared secret directly (no point to serialize). Pairs with `ed25519-dalek`'s seed for the §1a derivation. MIT. *(Chosen over `k256`/secp — the X25519 decision makes secp unnecessary and keeps us on the existing dalek stack.)* |
| `hkdf 0.12` | in tree | HKDF-Extract + Expand. No new dep. |
| `hmac 0.12` | in tree | HMAC-SHA256 + constant-time `verify_slice`. No new dep. |
| `sha2 0.10` | in tree | SHA-256 + SHA-512 (§1a derivation). No new dep. |
| `rand` / `rand_chacha` | in tree | 32-byte nonce CSPRNG. No new dep. |
| `subtle` | **not needed** | `hmac::Mac::verify_slice` is constant-time. |
| `nostr` crate | **rejected** | Drags the full Nostr event model + secp256k1 (rust-bitcoin C dep), conflicts with the all-RustCrypto+dalek stack, and is moot under the X25519 decision. |

Net new: **2 crates** (`chacha20`, `x25519-dalek`), both pure-Rust, license-clean (MIT / MIT-OR-Apache-2.0), matching wire's existing dalek + RustCrypto stack.

## 10. Phased implementation checklist

1. **Crypto core (no wire wiring):** `src/enc/wire_x25519.rs` — `calc_padded_len`/`pad`/`unpad`, `derive_x25519_scalar` (§1a, clamped SHA-512 of seed), `derive_conversation_key`, `seal`, `open` (context-bound `info`). Unit-test against `calc_padded_len` + `get_message_keys` vectors + the committed golden set (incl. **seed→pub**) + the tamper + direction-binding set. Zero integration risk.
2. **Crate deps:** add `chacha20`, `x25519-dalek` to `Cargo.toml`; `cargo build`.
3. **X25519 key mint + storage:** `x25519.key` (0600) co-minted at `init_self_idempotent` (`init.rs:111/124`), derived per §1a from the Ed25519 seed.
4. **Card emit/read:** `dh_pubkey` in `build_agent_card` (`agent_card.rs:205`); `card_dh_pubkey` reader (`:400`); confirm `card_canonical` covers it (`:432`). Test: card round-trips + self-sig verifies with the field present.
5. **Pin verification:** confirm `add_agent_card_pin` persists `dh_pubkey` (`trust.rs:197`) — should be automatic; add a pin-then-read test.
6. **`conversation_key_for_peer` helper** + in-process memo with **rotation-aware invalidation** (§5). Returns `None` for legacy peers.
7. **Unify send skeletons (review finding #4):** add `schema_version=v3.1` to the MCP event (`mcp.rs:1425`) / factor the skeleton into the shared helper, **before** the seal hook.
8. **Seal hook in BOTH** `cli.rs:4405` and `mcp.rs:1431` via the shared helper. Discriminator `wire-x25519.v1`; pass `from`/`to` into `seal`.
9. **Decrypt-on-READ hooks (review finding #3):** decrypt at `cli.rs:5169` tail + the `wire://inbox` MCP resource. Persist events verbatim (no body rewrite). Verbatim fallback on unknown/unopenable `enc`; **no transient-reject** (no cursor wedge).
10. **Backward-compat + e2e tests:** plaintext byte-identical; unknown-enc no-wedge; at-rest re-verify; CLI↔MCP encrypted round-trip (`#[ignore]` + `serial`) asserting `schema_version==v3.1` both directions; cache-invalidation-on-rotation.
11. **Docs:** update `PROTOCOL.md §2.4` — change the example discriminator `nip44.v2` → `wire-x25519.v1`, document C1–C3, the salt, the **normative §1a derivation bytes**, the §2c context-binding, and the §8 non-goals; flip `dh_pubkey`/`enc` from "reserved, unset" to "active in v0.2." Update RFC-006 with the resolved curve + C1–C3. Add the §0a correction note to `0006-spike-vodozemac-vs-nip44.md:26/28`.
12. **Gate:** `cargo fmt --check && cargo clippy -D warnings && cargo test` (check `$?` on bare commands, never piped).

## 11. Open questions

1. **At-rest ciphertext — RESOLVED → decrypt-on-read** (review finding #3). decrypt-on-write would persist a plaintext body against a `{ct}`-computed signature ⇒ an unverifiable at-rest event. Decrypt-on-read keeps `inbox/<peer>.jsonl` as verifiable ciphertext at rest. Cost: the open hook lives at *two* read surfaces (`cli.rs:5169` + `wire://inbox` MCP resource) — both gated verified-events-only (§4c). **Closed for D1.** Owner: implementer.
2. **X25519 key derivation source — RESOLVED 2026-06-06 → derive from the Ed25519 seed** (`clamp(SHA-512(seed)[0..32])`, §1a). Decided by @laulpogan. Rationale: Ed25519↔X25519 is a *same-curve* (Curve25519) representation conversion — standard practice (libsodium `crypto_sign_ed25519_sk_to_curve25519`, Signal, age) and explicitly **not** the cross-curve scalar-reuse anti-pattern SLIP-0010 warns about (that was Ed25519→secp256k1, a different curve — see [`0007-spike-curve-derivation.md`](./0007-spike-curve-derivation.md)). Accepted residual: the signing key also performs DH (one compromise = both); judged acceptable for v0.2 against the simplicity / single-backup / re-derivability win. The independent-random-key alternative remains available if a later threat model demands separation. The §1a golden vector locks the derivation so a `dalek`-version drift fails in CI.
3. **PROTOCOL.md normative conflict — mandatory edit.** `:150` names `nip44.v2` as *the* example discriminator and §2.4 ties `enc` to "NIP-44 v2." Under the X25519 decision this is misleading; the step-11 doc edit is **mandatory, not cosmetic**, or the spec ships self-contradicting the implementation. Owner: implementer.
4. **Group encryption** deferred to MLS (RFC-006); D1 leaves group send plaintext. Confirm acceptable for the v0.2 surface. Owner: maintainer.

## Out of scope

- **Forward secrecy / PCS** (vodozemac / Double Ratchet) — RFC-006 deferred; D1 accepts "no FS/PCS," mitigated by relay TTL + Ed25519 integrity.
- **Group envelope encryption** (MLS) — RFC-006 v0.3 line; D1 group send stays plaintext over the shared room slot.
- **Nostr-DM interop** — RFC-007/D3 over the separate secp transport key; D1 bytes are wire-private by design (§0a).
- **DIDComm authcrypt** — already lost to NIP-44 in `BACKLOG.md:22`; not relitigated.
- **secp256k1 in D1** — superseded by the X25519 decision (§0); `k256`/`nostr` crates explicitly rejected (§9).

## Sources

- NIP-44 v2 (encrypted payloads — symmetric envelope, padding, encrypt-then-MAC, message-keys split). [P, github.com/nostr-protocol/nips/44, 85]
- RFC 7748 (X25519, clamping §5, all-zero/contributory reject §6.1). [P, datatracker.ietf.org/doc/rfc7748, 90]
- RFC 8439 (ChaCha20 raw stream). [P, datatracker.ietf.org/doc/rfc8439, 90]
- RFC 5869 (HKDF Extract/Expand). [P, datatracker.ietf.org/doc/rfc5869, 90]
- [`0006-confidentiality-roadmap-sequencing.md`](./0006-confidentiality-roadmap-sequencing.md) — the NIP-44 choice, the `enc`/`dh_pubkey` reservations, path-A additivity. [internal, primary]
- [`0006-spike-vodozemac-vs-nip44.md`](./0006-spike-vodozemac-vs-nip44.md) — why NIP-44 over vodozemac (with the §0a interop-tiebreaker correction). [internal, primary]
- [`0007-spike-curve-derivation.md`](./0007-spike-curve-derivation.md) — secp transport key Option 1; Nostr interop is *not* on the wire DH key. [internal, primary]
- `paulmillr/nip44` `nip44.vectors.json` — conformance vectors (curve-agnostic layers only). [P, github.com/paulmillr/nip44, 80]
- In-tree code (line refs approximate post-v0.15 merge): `src/signing.rs` (sign/verify/event_id + the path-A fixture), `src/pull.rs` (verify gate, schema-major gate, cursor/transient-reject), `src/agent_card.rs` (`build_agent_card`/`card_canonical`/`card_op_did`), `src/trust.rs` (`add_agent_card_pin`), `src/init.rs` (`init_self_idempotent`), `src/pair_invite.rs` (`pair_drop` make/consume, `verify_agent_card`, pin — dial-only pairing post-#236), `src/cli.rs` + `src/mcp.rs` (send skeletons + inbox read surfaces), `src/config.rs`, `docs/PROTOCOL.md §1/§2.4`. [internal, primary]
