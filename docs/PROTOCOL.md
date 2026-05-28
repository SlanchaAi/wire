# wire protocol — v0.1 (extended through v0.13.5)

This document defines the wire format that two `wire` implementations must agree on to interoperate. The Rust implementation in this repository is the reference; this document is normative.

> **Audit status:** This document was originally written for wire v0.1. The core message-signing rules (§§ 2, 3) and the agent-card crypto layer (§ 1) remain accurate through v0.13.5. Sections later in the doc note where the v0.13 reality has moved past the original v0.1 scoping (federation, handle directories, group rooms, RFC-001 identity layer). For the formal A2A interoperability surface see [`a2a-extension/wire-identity-v1.md`](a2a-extension/wire-identity-v1.md); for the operator/org identity layer see [RFC-001](rfc/0001-identity-layer.md).

## Conventions

- All multi-byte integers are big-endian.
- All hashes are SHA-256.
- All signatures are Ed25519 (RFC 8032).
- All base64 is RFC 4648 standard alphabet, no line wrapping, with padding.
- All hex is lowercase.
- Times are RFC 3339 / ISO 8601 with `Z` suffix (UTC).
- "MUST" / "SHOULD" / "MAY" follow RFC 2119 semantics.

## 1. Identity — DID + agent-card

Every wire endpoint has a stable identity backed by an Ed25519 keypair. The DID is `did:wire:<handle>` where `<handle>` is `[A-Za-z0-9_-]+`.

The signed **agent-card** binds the DID to one or more public keys plus capabilities and policies. v0.1 schema (`schema_version: "v3.1"`):

```json
{
  "schema_version": "v3.1",
  "did": "did:wire:paul",
  "name": "Paul",
  "capabilities": ["wire/v3.1"],
  "verify_keys": {
    "ed25519:paul:b2e5aae7": {
      "key": "<base64-encoded 32-byte Ed25519 public key>",
      "alg": "ed25519",
      "active": true
    }
  },
  "policies": {"max_message_body_kb": 64},
  "signature": "<base64-encoded Ed25519 signature>"
}
```

> **v3.2 / RFC-001 additions (`schema_version: "v3.2"`, default capability `wire/v3.2`):**
>
> v3.2 cards MAY additionally carry an operator-identity claim and any number of organisation-membership claims. These are optional; a v3.2 card without them is wire-compatible with v3.1 readers (the `verify_agent_card` routine does not inspect `schema_version` and `verify_keys`-only cards continue to verify).
>
> ```jsonc
> {
>   "schema_version": "v3.2",
>   "did": "did:wire:paul-b2e5aae7",                              // v0.5.7+: pubkey-suffixed
>   "op_did": "did:wire:op:alice-<32hex>",                        // RFC-001 §1
>   "op_cert": "<base64 Ed25519 sig: operator over session DID>", // verify with op pubkey
>   "org_memberships": [{
>     "org_did": "did:wire:org:acme-<32hex>",
>     "member_cert": "<base64 Ed25519 sig: org over op_did>"
>   }],
>   ...
> }
> ```
>
> Cert primitives live in `src/identity.rs` (`sign_did_cert` / `verify_op_cert` / `verify_member_cert`). The 16-byte (32-hex) fingerprint for operator and organisation DIDs is computed by `agent_card::long_fingerprint`. See the [did:wire method spec](did-methods/did-wire-method.md) for the full DID shape catalogue.

**v0.13 DID format note:** since v0.5.7 the per-session DID is **pubkey-suffixed** (`did:wire:<handle>-<8hex>`) to prevent handle collisions across distinct keypairs. v0.1 cards using the bare `did:wire:<handle>` form remain verifiable for backward compatibility but new claims always carry the suffix.

**Key id format:** `<handle>:<fingerprint>` where fingerprint = first 8 hex chars of SHA-256(public_key_bytes). Cards on disk prefix this with `ed25519:` to allow algorithm migration in v0.2+.

**Signing rule:** signature is Ed25519 over `card_canonical(card)` — see §3 below — with `signature` field absent. To verify, strip `signature`, recompute the canonical bytes, run `Ed25519_Verify(verify_keys[*].key, canonical_bytes, signature)`.

Cards with empty or malformed `verify_keys` MUST be rejected.

## 2. Events — kinds, structure, signing

Events are signed JSON objects. v0.1 mandatory fields:

```json
{
  "timestamp": "2026-05-10T03:46:01Z",
  "from": "did:wire:paul",
  "to": "did:wire:willard",
  "type": "decision",
  "kind": 1,
  "body": "ship the v0.1 demo",
  "event_id": "<64-char hex SHA-256>",
  "public_key_id": "paul:b2e5aae7",
  "signature": "<base64 Ed25519 signature>"
}
```

### 2.1 Kind ranges (Nostr-compatible)

| Range | Class | Semantics |
|------:|------:|----------|
| 1000–9999 | regular | persistent — relays SHOULD store indefinitely |
| 10000–19999 | replaceable | latest-by-(`from`, kind) wins |
| 20000–29999 | ephemeral | best-effort — relays MAY drop after delivery |
| 30000–39999 | addressable | replaceable, with optional `d` tag for namespacing |

**Special-cased out-of-range kinds (Nostr / heartbeat compatibility):**

| kind | name | class |
|---:|------|------|
| 1 | decision | regular |
| 100 | heartbeat | ephemeral |

v0.1 ships these named kinds:

| kind | name | description |
|---:|------|-------------|
| 1 | decision | Nostr-compat short message |
| 100 | heartbeat | liveness ping |
| 1000 | decision | wire-native decision |
| 1001 | claim | assertion or proposal |
| 1002 | ack | acknowledgement |
| 1100 | agent_card | self-card or peer-card update |
| 1101 | trust_add_key | add a verify key |
| 1102 | trust_revoke_key | revoke a verify key |
| 1200 | wire_open | bilateral wire establishment |
| 1201 | wire_close | bilateral wire teardown |

Kinds reserved for v0.2+: `1900` (file_share), `1901` (file_revoke), `10500` (registry_revocation). v0.1 implementations MUST NOT send or accept these. See `ANTI_FEATURES.md`.

### 2.2 event_id and signing

`event_id = hex(SHA-256(canonical(event, strict=true)))` — see §3 for canonical, where `strict=true` excludes `event_id` itself.

Signing: `signature = base64(Ed25519_Sign(private_key, hex_decode(event_id)))`. The signature commits to the 32-byte raw event_id digest, which transitively commits to the canonical body. This is the Nostr NIP-01 sign-over-id pattern; it lets relays cite events by id without re-canonicalizing the body.

### 2.3 Verification rules

To verify a received event:

1. Recompute `event_id'` from the body. Reject if `event_id' != event_id`.
2. Resolve `public_key_id` to a public key in the trust state. Reject if unknown or marked `active: false`.
3. `Ed25519_Verify(public_key, hex_decode(event_id), base64_decode(signature))`. Reject on failure.
4. Reject if `to` is set and does not match the recipient's own DID.

The `from` field MAY be the bare handle (`paul`) or fully-qualified DID (`did:wire:paul`). Verifiers MUST accept both forms.

## 3. Canonical form

Canonical JSON serialization is the input to all hashing and signing. Rules:

1. Object keys serialize in lexicographic byte order.
2. No whitespace anywhere; separators are `","` and `":"`.
3. UTF-8 throughout. Non-ASCII characters are NOT `\u`-escaped.
4. **Top-level** fields `signature` and `public_key_id` are always stripped before serialization.
5. **Top-level** field `event_id` is stripped iff `strict=true`.

Strict mode is used when computing event_id (the field cannot reference itself). Non-strict mode is used everywhere else (verification, transport).

## 4. Trust state

Each agent maintains a local trust state, persisted to `~/.config/wire/trust.json`:

```json
{
  "version": 1,
  "agents": {
    "paul": {
      "tier": "ATTESTED",
      "did": "did:wire:paul",
      "public_keys": [
        {
          "key_id": "paul:b2e5aae7",
          "key": "<base64 pub>",
          "added_at": "<rfc3339>",
          "active": true
        }
      ]
    },
    "willard": {
      "tier": "VERIFIED",
      "did": "did:wire:willard",
      "card": { ... full signed card ... },
      "pinned_at": "<rfc3339>",
      "verified_at": "<rfc3339>"
    }
  }
}
```

### 4.1 Tiers

| Tier | Promotion path | Acceptance |
|------|----------------|-----------|
| `UNTRUSTED` | initial pin | events ignored |
| `ORG_VERIFIED` | `member_cert` verifies against an accepted org (RFC-001 §5, v3.2+) | events accepted with org-policy gating only; does NOT satisfy `>= VERIFIED` checks |
| `VERIFIED` | SAS confirm or `wire pin` of signed card | events accepted |
| `ATTESTED` | self-attestation only | self events accepted |
| `TRUSTED` | reserved for v0.2+ | reserved |

Promotion is **one-way**. `UNTRUSTED → ORG_VERIFIED → VERIFIED → ATTESTED`. `promote_to_verified` accepts either `UNTRUSTED` or `ORG_VERIFIED` as source per RFC-001 §5 ("a SAS-paired peer that happens to share our org is recorded at VERIFIED, not downgraded"). Reverting requires removing the agent record entirely. The strict `ORG_VERIFIED < VERIFIED` invariant is property-tested in `tests/trust_ceiling_prop.rs`.

## 5. Pairing — SPAKE2 + SAS + AEAD

### 5.1 Code phrase

Format: `NN-XXXXXX` where `NN` is two random decimal digits and `XXXXXX` is six random base32 characters from the RFC 4648 alphabet (`A-Z2-7`, no `0/1` ambiguity). Total entropy ~36.6 bits.

Operators read this aloud over a side channel they trust.

### 5.2 SPAKE2 handshake

Both sides instantiate `Spake2<Ed25519Group>::start_symmetric` with:
- `password = code_phrase.as_bytes()`
- `identity = pair_id_from_relay`

`pair_id_from_relay` is a 16-byte random hex string the relay assigns when the host opens a pair-slot keyed by `code_hash = SHA-256("wire/v1 code-phrase" || code_phrase)`. Including `pair_id` in the SPAKE2 identity prevents crosstalk between concurrent pairings on the same relay.

Both sides exchange SPAKE2 messages via the relay's `/v1/pair` endpoints (see §6.4) and call `finish()` on the peer's message to derive a 32-byte shared secret.

### 5.3 Short Authentication String (SAS)

Both sides compute identically:

```
sas = SHA-256("wire/v1 sas" || spake_key || sorted_pubkeys)
sas_digits = (last_4_bytes_be(sas) % 1_000_000) zero-padded to 6 digits
```

Format displayed: `XXX-XXX` (split for readability). Operators verify by reading aloud.

If digits do not match, MITM is suspected. Operators MUST refuse confirmation; the implementation MUST NOT proceed with the bootstrap exchange.

### 5.4 AEAD bootstrap

After SAS confirmation, both sides:

1. Derive a ChaCha20-Poly1305 key: `aead_key = HKDF-SHA256(salt=code_hash, ikm=spake_key, info="wire/v1 bootstrap-aead", L=32)`.
2. Build a bootstrap payload: `{"card": <signed-card>, "relay_url": <url>, "slot_id": <id>, "slot_token": <token>}`.
3. Seal: random 12-byte nonce + ChaCha20-Poly1305 over canonical JSON of the payload. Wire format: `nonce || ciphertext+tag`.
4. POST to `/v1/pair/<pair_id>/bootstrap` with role=host|guest.
5. Poll `/v1/pair/<pair_id>?as_role=host|guest` for the peer's sealed payload.
6. Open with `aead_key`. AEAD failure → abort pairing; do not retry.
7. `verify_agent_card` on peer's card. Bad signature → abort.
8. Pin peer's card at tier `VERIFIED`. Save peer's relay coordinates.

## 6. Relay HTTP endpoints

The reference relay binds to an arbitrary host:port. All endpoints emit JSON responses; errors include `{"error": "<msg>"}`.

### 6.1 `GET /healthz`

Returns `200 OK` with body `ok\n`. Liveness check; no auth.

### 6.2 `POST /v1/slot/allocate`

Allocates an event-slot. Request body: `{"handle": "<optional>"}`. Response: `{"slot_id": "<32-hex>", "slot_token": "<64-hex>"}`. The token is a bearer for both reads and writes.

### 6.3 Event slots

- `POST /v1/events/<slot_id>` body `{"event": <signed-event>}`, `Authorization: Bearer <slot_token>` — stores or dedupes by `event_id`. Response: `{"event_id": "<id>", "status": "stored"|"duplicate"}`. Body cap: 256 KiB. Returns 401/403 on bad/missing token, 404 on unknown slot, 413 on body cap exceeded.
- `GET /v1/events/<slot_id>?since=<event_id>&limit=<n>`, bearer auth — returns `[<event>, ...]` from after `since` (exclusive). Default limit 100, max 1000.

### 6.4 Pair slots

Pair slots are ephemeral, in-memory only. A relay restart aborts in-progress pairings; clients MUST handle this by retrying.

- `POST /v1/pair` body `{"code_hash": "<hex>", "msg": "<base64-spake-msg>", "role": "host"|"guest"}`. Response: `{"pair_id": "<32-hex>"}`. Host registers first; guest finds the existing slot via `code_hash`. Same role registering twice for one slot returns `409 Conflict`.
- `GET /v1/pair/<pair_id>?as_role=host|guest`. Returns the OTHER side's data: `{"peer_msg": "<b64>"|null, "peer_bootstrap": "<b64>"|null}`. Returns 404 on unknown `pair_id`.
- `POST /v1/pair/<pair_id>/bootstrap` body `{"role": "host"|"guest", "sealed": "<base64>"}`. Stores the sealed bootstrap payload from our side.

The relay performs no Ed25519 verification, no PAKE arithmetic, no decryption. It is a dumb pipe. Trust is established and verified entirely client-side.

## 7. Persistence

The reference implementation stores events to `<state_dir>/slots/<slot_id>.jsonl` (append-only, one event per line) and tokens to `<state_dir>/tokens.json`. Pair slots are NOT persisted.

A relay MUST reload event slots and tokens on startup to provide restart-recovery. Pair slots MUST start empty.

## 8. Forward compatibility

- Unknown top-level fields in events MUST be preserved verbatim through canonicalization. Implementations MUST NOT drop fields they don't recognize.
- New `kind` ids in unused range slots are forward-compatible: an old verifier sees an unknown kind and routes by class (regular/replaceable/ephemeral/addressable). Application logic decides whether to accept or skip.
- New top-level fields in agent-cards are similarly preserved.
- Schema bumps (e.g. `schema_version: "v4.0"`) require a migration path documented at the time of bump.

## 9. What this protocol does NOT specify

- ~~Discovery (pairings are out-of-band; no DHT, no registry in v0.1)~~ — **superseded.** v0.5+ ships a handle directory served via `GET /.well-known/agent-card.json?handle=<nick>`; see [`a2a-extension/wire-identity-v1.md`](a2a-extension/wire-identity-v1.md).
- ~~Group rooms (mesh-of-bilateral only — see `ANTI_FEATURES.md`)~~ — **superseded.** v0.13.3+ ships shared-slot group rooms via `wire group create / invite / join / send / tail` (see `src/group.rs`).
- Message encryption above the wire layer (events are signed-plaintext today; encryption pending NIP-44 v2 or DIDComm authcrypt in a future revision).
- Spam control (relay accepts any signed event under the body cap; rate limiting is operator-side).
- File transfer above 256 KiB (deferred; not currently implemented).
- ~~Federation between relays (each pair shares one relay; cross-relay roaming is v0.3+)~~ — **superseded.** v0.5+ resolves `<handle>@<relay>` via `.well-known` lookup against the relay's domain; peers behind different relays pair through the federation directly.

## 10. Revision notes

| Wire version | Schema | Notable protocol changes |
| --- | --- | --- |
| v0.1 | v3.1 | Initial spec — bilateral SAS, single-relay, mesh-of-pairs. |
| v0.5.7 | v3.1 | Pubkey-suffixed DIDs (`did:wire:<handle>-<8hex>`) to prevent handle collisions. |
| v0.5 | v3.1 | Federated handle directory + `.well-known/agent-card.json`; A2A v1.0 AgentCard emission with wire as an A2A extension. |
| v0.6 | v3.1 | Mesh / local-sister sessions + intra-machine pair-all. |
| v0.13.3 | v3.1 | Group rooms via shared relay slot. |
| v0.13.5 | v3.2 | RFC-001 Phase 0 — operator + organisation identity claims on the card, `Tier::OrgVerified`, `identity::*` cert primitives. Backward-compatible with v3.1 readers. |
