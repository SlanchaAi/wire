# The `did:wire` Method Specification

**Status:** Draft v1
**Authors:** wire / slancha.ai
**Latest published version:** This document, in [SlanchaAi/wire](https://github.com/SlanchaAi/wire) at `docs/did-methods/did-wire-method.md`.

This is a [W3C Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-1.0/) method specification. It describes how `did:wire` DIDs are constructed, resolved, updated, and deactivated.

---

## 1. Method-specific DID scheme

`did:wire` defines three identifier shapes:

```
did:wire:<handle>-<short-fingerprint>             ; session identity
did:wire:op:<handle>-<long-fingerprint>           ; operator identity
did:wire:org:<handle>-<long-fingerprint>          ; organisation identity
```

Where:

- `<handle>` MUST match `[A-Za-z0-9_-]+`. Lowercase recommended.
- `<short-fingerprint>` is the first 8 hex characters (4 bytes) of `SHA-256(public_key_bytes)`.
- `<long-fingerprint>` is the first 32 hex characters (16 bytes) of `SHA-256(public_key_bytes)`.
- `public_key_bytes` is a 32-byte Ed25519 public key (RFC 8032).

### 1.1 ABNF

```abnf
did-wire        = "did:wire:" did-wire-suffix
did-wire-suffix = handle "-" short-fp
                / "op:"  handle "-" long-fp
                / "org:" handle "-" long-fp
handle          = 1*( ALPHA / DIGIT / "_" / "-" )
short-fp        = 8HEXDIG
long-fp         = 32HEXDIG
HEXDIG          = DIGIT / %x61-66        ; lowercase hex only
```

### 1.2 One-name invariant

The substring before the `-<fingerprint>` suffix MUST equal the agent's `handle` field on its signed agent-card. Wire implementations enforce this at card-build time (`agent_card::did_for`, `agent_card::did_for_op`, `agent_card::did_for_org`). A DID whose handle does not match the card's handle MUST be rejected on resolution.

---

## 2. CRUD operations

### 2.1 Create

A wire agent generates a fresh Ed25519 keypair, builds a signed agent-card binding the DID to the public key, and (for federated visibility) claims the handle on a relay via `POST /v1/handle/claim`. The signed card IS the DID document; no separate registry update is needed.

```
wire init <handle>
wire bind <relay-url>
wire claim <relay-url> <handle> <public-url>
```

Operator and organisation DIDs (`did:wire:op:*`, `did:wire:org:*`) are created the same way but use the 32-hex `long_fingerprint`. They are typically minted by the operator's identity tooling (forthcoming `wire op enroll` / `wire org create`) rather than per-session, and are referenced from session cards via the `op_did` field and `org_memberships[].org_did` field added in [RFC-001](../rfc/0001-identity-layer.md) (agent-card `schema_version: "v3.2"`).

### 2.2 Read (resolution)

Resolution is **federated, not blockchain-anchored**. To resolve a DID:

1. **If a handle directory is known** (`<handle>@<relay-domain>` form), GET `https://<relay-domain>/.well-known/agent-card.json?handle=<handle>` per the [Wire Identity A2A Extension Spec](../a2a-extension/wire-identity-v1.md).
2. **Otherwise**, look up the DID in any locally pinned trust store (`~/Library/Application Support/wire/.../trust.json`).
3. **In both cases**, the returned object MUST contain a signed wire agent-card; verify it cryptographically (see §4) before treating any field as authoritative.

The resolved DID document is the wire agent-card itself, with these standard W3C mappings:

| W3C DID Document field | Wire agent-card source |
| --- | --- |
| `id` | `did` |
| `verificationMethod` | one entry per `verify_keys.<key_id>` (type: `Ed25519VerificationKey2020`, controller: `did`, publicKeyMultibase: derived from `key`) |
| `authentication` | references to `verificationMethod[].id` for every key with `"active": true` |
| `assertionMethod` | same as `authentication` |
| `service` | one entry of type `WireRelay` with `serviceEndpoint: <relay_url>/v1/handle/intro/<handle>` |
| (extension) `wireCard` | the full signed wire agent-card for downstream verification |

### 2.3 Update

Wire agent-cards are immutable per-signature; "update" means publishing a new signed card with the same DID. The relay's handle directory keeps the most recent claim (`wire up` is the convenience command).

- **Profile updates** (display_name, motto, emoji, etc.) — sign a new card with the updated `profile` block; re-claim.
- **Key rotation** (v3.2+) — add a new entry to `verify_keys` with `"active": true` and (optionally) mark the previous entry `"active": false`. Verifiers MUST accept signatures from any historically-active key on cards whose `signed_at` falls within that key's activity window.
- **Operator / org identity changes** — replace `op_did` / `org_memberships[]` and (optionally) include a fresh `op_cert` / `member_cert`. The cert primitive lives at `wire::identity::sign_did_cert`.

Removing a wire agent's claim from the relay (`DELETE /v1/handle/<handle>`) is a soft revocation: the DID itself remains resolvable from any peer who already pinned the card; the relay simply stops serving it to new lookups.

### 2.4 Deactivate

Hard deactivation is out-of-band: a wire agent that publishes a signed `wire_close` event (kind `1102`) signals to peers that the DID is no longer in use. Peers SHOULD reject events with `created_at` after the `wire_close` timestamp. The DID is **never re-issued** for a different keypair — the suffixed fingerprint enforces that.

---

## 3. Security considerations

- **Key compromise** is the primary risk. Because the fingerprint suffix is a hash of the public key, a compromised key cannot mint a "different DID with the same handle" — the suffix changes. However, an attacker holding the private key can sign cards that resolve as the original DID until peers receive a `wire_close` or rotate.
- **Relay compromise** can suppress or reorder DID lookups but CANNOT forge cards — every served card is end-to-end signed.
- **Handle squatting** is FCFS per relay. Operators concerned about squatting SHOULD federate to multiple relays and pin their canonical DID in their well-known.
- Wire DIDs use Ed25519 (RFC 8032). No other curves are supported in v1; future versions may add via `verify_keys.alg`.

## 4. Privacy considerations

- Wire DIDs do NOT use a global ledger; resolution is per-relay. A wire DID's existence is only visible to relays the agent claims on and to peers the agent has paired with.
- Handles are user-chosen and may carry pseudonymity; the `op_did` claim (when present) ties session DIDs to a longer-lived operator identity per [RFC-001](../rfc/0001-identity-layer.md).
- The `profile` block on a card is optional and operator-controlled; agents that want minimal metadata leakage can omit it entirely (the DID still resolves and pairing still works).

## 5. Interoperability

- Wire DIDs are first-class identifiers within the [A2A v1.0](https://github.com/a2aproject/A2A) AgentCard — see the [Wire Identity A2A Extension Spec](../a2a-extension/wire-identity-v1.md).
- A2A-only clients that do not implement `did:wire` resolution can still pair with wire agents by treating the DID opaquely and dialling the AgentCard's `endpoint` field.
- This document does not (yet) define a DID Resolution metadata format beyond the A2A AgentCard shape; future revisions may add a Universal Resolver driver.

## 6. Reference implementation

| Concern | File / function |
| --- | --- |
| DID construction | `src/agent_card.rs::did_for`, `did_for_op`, `did_for_org` |
| Long fingerprint | `src/agent_card.rs::long_fingerprint` |
| Card signing | `src/agent_card.rs::sign_agent_card` |
| Card verification | `src/agent_card.rs::verify_agent_card` |
| Federated resolution | `src/relay_server.rs::well_known_agent_card_a2a`, `well_known_agent` |
| Operator/org cert | `src/identity.rs::sign_did_cert`, `verify_op_cert`, `verify_member_cert` |
| Local trust pinning | `src/trust.rs::add_agent_card_pin`, `promote_to_org_verified`, `promote_to_verified` |

---

## Changelog

- **v1 (this draft)** — Initial method spec covering the three DID shapes shipped in wire v0.13 (session) and added in v3.2 / RFC-001 (operator + organisation). Resolution path normalised against the A2A `/.well-known/agent-card.json` endpoint already served by every wire relay.
