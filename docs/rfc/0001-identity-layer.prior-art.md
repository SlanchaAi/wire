<!-- Companion to docs/rfc/0001-identity-layer.md. Generated from the research prompt in that RFC's Appendix A. -->

# Prior Art: RFC-001 v2 — Three-Tier Identity Layer for wire

*Research compiled 2026-05-27. All citations to live source material.*

---

## Preamble

Wire's RFC-001 v2 proposes three nested identity tiers on top of the existing `did:wire:<session-handle>` per-session DID:

| Tier | wire term | Lives on the agent-card |
|------|-----------|------------------------|
| 1 | **Operator** | `op_did` |
| 2 | **Organization** | `org_did`, `org_memberships[]` |
| 3 | **Project** | `project` |

The existing wire agent-card (`schema_version: "v3.1"`) is documented in `docs/PROTOCOL.md` ([SlanchaAi/wire:docs/PROTOCOL.md:1-40](https://github.com/SlanchaAi/wire/blob/main/docs/PROTOCOL.md)):

```json
{
  "schema_version": "v3.1",
  "did": "did:wire:swift-harbor-4092b577",
  "name": "swift-harbor",
  "capabilities": ["wire/v3.1"],
  "verify_keys": {
    "ed25519:swift-harbor:4092b577": {
      "key": "<base64 Ed25519 pubkey>",
      "alg": "ed25519",
      "active": true
    }
  },
  "policies": {"max_message_body_kb": 64},
  "signature": "<base64 Ed25519 sig>"
}
```

RFC-001 v2 (stub in `docs/rfc/0001-identity-layer.md`) adds `op_did`, `org_did`, `project`, and an `ORG_VERIFIED` trust tier. The maintainer's guard-rails state: `ORG_VERIFIED < VERIFIED` always; org membership eases pairing but never replaces bilateral SAS confirmation ([SlanchaAi/wire:docs/rfc/0001-identity-layer.md:30-50](https://github.com/SlanchaAi/wire/blob/main/docs/rfc/0001-identity-layer.md)).

---

## 1. Google A2A Protocol (Agent2Agent)

**Canonical sources:** [https://a2aproject.github.io/A2A/](https://a2aproject.github.io/A2A/) · [https://github.com/a2aproject/A2A](https://github.com/a2aproject/A2A) · normative spec: `specification/a2a.proto` (SHA `400cdbad`)

### Identity Model

A2A v1.0 defines an `AgentCard` — a self-describing JSON manifest served at `/.well-known/agent.json`. The card is the closest existing parallel to wire's agent-card. The full `AgentCard` schema ([a2aproject/A2A:specification/a2a.proto](https://github.com/a2aproject/A2A/blob/main/specification/a2a.proto); rendered at [spec §4.4.1](https://a2aproject.github.io/A2A/latest/specification/#441-agentcard)) contains:

```
AgentCard {
  name                 string (required)
  description          string (required)
  supportedInterfaces  AgentInterface[]  (required)
  provider             AgentProvider     (optional)
  version              string (required)
  documentationUrl     string
  capabilities         AgentCapabilities (required)
  securitySchemes      map<string, SecurityScheme>
  securityRequirements SecurityRequirement[]
  defaultInputModes    string[]
  defaultOutputModes   string[]
  skills               AgentSkill[]
  signatures           AgentCardSignature[]   ← JWS signing
  iconUrl              string
}
```

The **`provider` field** ([spec §4.4.2](https://a2aproject.github.io/A2A/latest/specification/#442-agentprovider)) is A2A's closest analog to wire's `org_did`:

```
AgentProvider {
  url          string  // "https://ai.google.dev"
  organization string  // "Google"
}
```

> "Represents the service provider of an agent." — A2A spec §4.4.2

This is intentionally a **flat, opaque string pair** — no DID, no cryptographic linkage. There is no notion of "operator" (human keyholder) distinct from the organization, no `project` scoping, and no membership attestation.

### Extension Mechanism

A2A has a formal extension system ([spec §4.4.4 `AgentExtension`](https://a2aproject.github.io/A2A/latest/specification/#444-agentextension)):

```
AgentExtension {
  uri         string   // unique extension URI
  description string
  required    boolean  // if true, client MUST support
  params      object   // extension-specific config
}
```

Extensions are declared in `AgentCapabilities.extensions[]`. This is the primary extensibility mechanism for adding org/operator fields. Wire could use a similar URI-keyed extension pattern.

### Signing Chain

`AgentCardSignature` ([spec §4.4.7](https://a2aproject.github.io/A2A/latest/specification/#447-agentcardsignature)) represents a JWS (RFC 7515) over the card:

```
AgentCardSignature {
  protected  string  // base64url-encoded JWS header
  signature  string  // base64url-encoded signature
  header     object  // unprotected header
}
```

The card can carry multiple signatures, but the spec does **not** define a chain-of-trust pattern for linking an agent signature to an org signature to an operator signature. Signing is defined but the trust hierarchy is left to implementers.

### Tenant Routing

`AgentInterface.tenant` ([spec §4.4.6](https://a2aproject.github.io/A2A/latest/specification/#446-agentinterface)) is:

> "An opaque string used for routing requests to a specific agent or tenant when multiple agents are served behind a single A2A endpoint."

This is a **routing hint, not an identity claim** — semantically analogous to wire's project-as-routing-tag proposal, but without cryptographic binding.

### Open Issues / Discussions

A2A's issue tracker and ADRs in `adrs/` have not published explicit org/team identity proposals as of the research date. The `provider.organization` string field is likely the intended hook for this. The A2A spec explicitly notes it follows OpenAPI 3.2 Security Scheme objects for auth — suggesting future org-scoped OAuth would work through standard bearer tokens rather than a DID-chain.

### Relevance to Wire

| Aspect | A2A | wire RFC-001 v2 |
|--------|-----|-----------------|
| Org identity | `provider.organization` (plain string) | `org_did` (DID, cryptographically attested) |
| Operator identity | Not modelled | `op_did` |
| Signing hierarchy | Flat JWS; no chain | op_did → org_did → session-did |
| Extension mechanism | `AgentExtension` with URI key | TBD |
| Tenant/project | `AgentInterface.tenant` (routing only) | `project` (scoped routing + identity) |

**Divergence note:** A2A chose maximum interop by using plain strings and standard-web auth. Wire's RFC pushes identity down into the cryptographic layer. The `AgentCardSignature` array pattern — multiple signers on a single card — is worth adopting directly: wire's org_did could add its own JWS to the session DID's self-signed card.

**Known footgun (A2A):** The `provider.organization` field is not authenticated — any agent can claim `"organization": "Google"`. Wire must not repeat this; org claims need `org_did + org_signed_attestation`.

---

## 2. Anthropic MCP (Model Context Protocol)

**Canonical sources:** [https://modelcontextprotocol.io](https://modelcontextprotocol.io) · [https://github.com/modelcontextprotocol/specification](https://github.com/modelcontextprotocol/specification) · latest schema: `schema/2025-06-18/schema.ts` (SHA `8778ec07`)

### Identity Model

MCP uses a capability-negotiation handshake where both client and server exchange `Implementation` objects during `initialize`:

```typescript
// From modelcontextprotocol/specification:schema/2025-06-18/schema.ts
interface Implementation {
  name: string;       // "ExampleServer"
  title?: string;     // "Example Server Display Name"
  version: string;    // "1.0.0"
}
```

The `serverInfo` field in `initialize` response carries only `name`, `title`, and `version`. There is **zero identity infrastructure**: no DID, no key, no org field, no signing. The MCP spec explicitly focuses on *capability negotiation* (tools, prompts, resources, sampling) and treats identity as entirely out-of-scope, delegated to the transport layer (OAuth 2.1 for HTTP, process identity for stdio).

> "The initialization phase MUST be the first interaction between client and server. During this phase, the client and server: Establish protocol version compatibility, Exchange and negotiate capabilities, Share implementation details." — [MCP spec, Lifecycle section](https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle)

### Operator / Org / Multi-Tenancy

MCP has no notion of operator, organization, or project identity. `serverInfo.name` is the only identity marker, and it is purely informational. The OAuth 2.1 profile (for HTTP transport) can carry organization context via OIDC claims, but MCP itself does not define or process these.

The MCP GitHub Issues tracker (as of research date) contains open discussions about adding server identity/attestation, but no accepted proposal exists.

### Relevance to Wire

MCP is a lesson in **what happens when identity is omitted entirely**: every MCP deployment operates on implicit trust via transport security (TLS + OAuth). This works when operator = deployment = org = user (a single Claude Desktop user). It breaks at organizational scale. Wire's explicit `op_did + org_did` is exactly the gap MCP leaves open.

**Naming note:** MCP calls the implementation `serverInfo.name` — wire's "handle" is the analogous field. The `title` field (human-readable display name) maps to wire's emoji+adjective-noun persona.

---

## 3. W3C Verifiable Credentials (VC) Data Model 2.0

**Canonical source:** [https://www.w3.org/TR/vc-data-model-2.0/](https://www.w3.org/TR/vc-data-model-2.0/) · W3C Recommendation

### Org Identity in the VC Model

A VC's `issuer` field identifies who made the claims. Per §4.7 of the spec, the issuer can be:

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiableCredential", "OrgMembershipCredential"],
  "issuer": {
    "id": "did:web:acme.example.com",
    "name": "ACME Corp"
  },
  "credentialSubject": {
    "id": "did:wire:swift-harbor-4092b577",
    "memberOf": {
      "id": "did:web:acme.example.com",
      "type": "Organization",
      "name": "ACME Corp"
    },
    "projectAccess": ["infra-team", "ml-pipeline"]
  }
}
```

The `issuer.id` is typically a `did:web` or `did:key` for organizations. The `credentialSubject` can carry schema.org `Organization`, `memberOf`, and custom properties.

The DIF (Decentralized Identity Foundation) Presentation Exchange spec ([https://identity.foundation/presentation-exchange/](https://identity.foundation/presentation-exchange/)) defines how a verifier requests org membership credentials from a holder (the agent).

### VC as Wire's Org Attestation

Wire could represent `org_memberships[]` as an array of Verifiable Credentials: each VC is issued by the `org_did`, claims the holder is `op_did`, and is signed by the org's key. This would make org membership auditable and revocable (via VC status lists, W3C Bitstring Status List v1.0).

The VC model introduces the **issuer-holder-verifier triangle** as the trust model:
- **Issuer** = `org_did` (signs the membership VC)
- **Holder** = `op_did` (presents the VC in the agent-card)
- **Verifier** = the remote peer checking the agent-card

### Relevance to Wire

| VC concept | wire analog |
|------------|-------------|
| `issuer` | `org_did` |
| `credentialSubject.id` | `op_did` |
| `memberOf` | `org_memberships[]` entry |
| `type: "OrgMembershipCredential"` | wire-defined VC type |
| VC `proof` (signature) | org_did signs the membership claim |

**Footgun:** VC revocation is non-trivial. The Bitstring Status List requires the org to host a status endpoint. A simpler alternative is time-bounded VCs (short `expirationDate`) that must be periodically re-issued — the Sigstore/Fulcio model (§10 below).

---

## 4. DID Methods Relevant to Org Identity

### 4.1 `did:web`

**Canonical source:** [https://w3c-ccg.github.io/did-method-web/](https://w3c-ccg.github.io/did-method-web/)

```
did:web:example.com
  → https://example.com/.well-known/did.json

did:web:example.com:departments:engineering
  → https://example.com/departments/engineering/did.json
```

`did:web` ties DID resolution to DNS + TLS, inheriting the organization's existing domain reputation. This makes it the **natural choice for `org_did`**: `did:web:acme.com` is authoritative for ACME Corp because only the holder of `acme.com` can publish at `https://acme.com/.well-known/did.json`.

**Wire RFC-001 v2 alignment:** The stub mentions "DNS-TXT floor; `did:web` optional" — this is exactly the right layering. A `did:web` org can publish its public signing key in the DID document, and wire sessions can verify that the org's signature on their agent-card traces to that key.

**Subpath DIDs for projects:** `did:web:acme.com:projects:infra-team` is a valid DID, enabling the project tier to also be DID-rooted. This is novel but entirely within spec.

**Footgun:** `did:web` provides no migration path if you lose the domain. Wire should document that `org_did` rotation (e.g., from `did:web:acme.com` to a new domain) requires a signed migration notice analogous to Bluesky's `did:plc` rotation.

### 4.2 `did:plc` (Bluesky)

**Source:** [https://web.plc.directory](https://web.plc.directory) · [ATProto DID spec](https://atproto.com/specs/did)

`did:plc` uses a **rotation key model**: the DID is a stable identifier (a hash of the genesis operation), but its controlling keys can rotate via signed operations published to the PLC log. An example:

```
did:plc:ewvi7nxzyoun6zhxrhs64oiz
```

This DID resolves to a document with:
- `verificationMethod`: current signing key
- `alsoKnownAs`: the handle (mutable)
- `service`: the PDS endpoint

The PLC model is relevant to wire's **operator-level DID**: an operator who loses a device key needs to rotate `op_did` without losing their organizational memberships. A `did:plc`-style rotation log (append-only, signed by rotation keys) is the mature solution.

**Divergence:** `did:plc` requires a centralized (though auditable) directory. Wire's `UNTRUSTED → VERIFIED → ATTESTED` trust model is fully peer-to-peer. For `op_did` rotation, wire should define a signed rotation event (`kind: 1101 trust_add_key` already exists) — no PLC directory needed.

### 4.3 `did:peer`

**Source:** [https://identity.foundation/peer-did-method-spec/](https://identity.foundation/peer-did-method-spec/)

`did:peer` DIDs are generated from key material and never need a registry. They are scoped to a bilateral relationship. This maps well to wire's current `did:wire:` scheme (the handle is effectively a peer-scoped identifier). However, `did:peer` lacks human-readable naming and is hard to use as a stable org identifier. **Not recommended for org_did or op_did**, but worth citing as the conceptual ancestor of wire's per-session DID.

### 4.4 `did:key`

**Source:** [https://w3c-ccg.github.io/did-method-key/](https://w3c-ccg.github.io/did-method-key/)

`did:key` encodes the public key directly in the DID:

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

This is the simplest possible DID. Zero infrastructure. **Best fit for `op_did`** when the operator is an individual with no domain — the DID *is* the key. Rotation is impossible (you'd need a new DID), but for wire's `op_did` a rotation event could emit a chain: old `op_did` signs a statement endorsing new `op_did`.

**Convergent design pattern:** ATProto uses `did:plc` (mutable registry) or `did:web` (domain-bound) — exactly the same fork wire faces for op_did.

### 4.5 Org-Specific DID Methods

No published DID method specifically targets "organization" identity as a first-class concept. The closest are:
- `did:ethr` / `did:ion` — Ethereum/ION-based, used in enterprise B2B contexts
- `did:orb` — TrustBloc's Sidetree-based method, designed for enterprise multi-tenant deployments

**Wire's opportunity:** Define `did:wire:org:<name>` as a first-party method for org identity, resolved via the wire relay network or DNS-TXT. This keeps the namespace consistent (`did:wire:*` for everything in the wire ecosystem) and avoids depending on external DID registries for the MVP.

---

## 5. ATProto (Bluesky)

**Canonical source:** [https://atproto.com/specs/atp](https://atproto.com/specs/atp) · [https://atproto.com/specs/did](https://atproto.com/specs/did)

### Account / PDS / Service Identity Hierarchy

ATProto's identity architecture separates three tiers that map well onto wire's model:

| ATProto tier | wire analog | Identifier |
|-------------|-------------|------------|
| Account | Operator (session) | `did:plc:...` or `did:web:...` |
| PDS host | Deployment / Relay | HTTPS URL in DID doc `service#atproto_pds` |
| Labeler / AppView | Organization-shaped service | `did:...` + `service#atproto_labeler` |

The DID document encodes both the signing key and the PDS service endpoint:

```json
{
  "id": "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
  "verificationMethod": [{
    "id": "did:plc:ewvi7nxzyoun6zhxrhs64oiz#atproto",
    "type": "Multikey",
    "controller": "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
    "publicKeyMultibase": "z..."
  }],
  "alsoKnownAs": ["at://user.example.com"],
  "service": [{
    "id": "#atproto_pds",
    "type": "AtprotoPersonalDataServer",
    "serviceEndpoint": "https://pds.example.com"
  }, {
    "id": "#atproto_labeler",
    "type": "AtprotoLabeler",
    "serviceEndpoint": "https://mod.example.com"
  }]
}
```

### Labelers as Org-Shaped Entities

ATProto [Labelers](https://atproto.com/specs/label) are services that emit signed labels (metadata assertions) about accounts and content. They are identified by a DID, sign their labels with an `#atproto_label` key, and can be operated by organizations (e.g., a moderation service). This is **structurally similar to wire's `org_did`**: the org has a persistent DID, signs claims about its members, and those claims are verifiable by third parties.

Labeler labels use CBOR + DRISL deterministic encoding for canonical signing — a more compact alternative to wire's canonical JSON.

### Handle = DNS = Mutable Alias

ATProto's handle is a DNS hostname (e.g., `alice.acme.com`). The `alsoKnownAs` field in the DID document links the stable DID to the mutable handle. Bidirectional resolution (DID → handle and DNS → DID) is required for confirmation. This is directly analogous to wire's RFC-001 v2 "DNS-TXT floor" for org attestation.

### Relevance to Wire

**Convergent design:** ATProto independently arrived at the same "DID + DNS handle + service endpoint" tuple that wire's RFC proposes. The `service[]` array in ATProto's DID document is the closest precedent for wire encoding `op_did`, `org_did`, and `relay_url` in a structured DID document rather than in the agent-card JSON.

**Novel alternative for wire to consider:** Move the three-tier identity declaration *into* the `did:wire` DID document (as `service` entries), rather than into the agent-card payload. The agent-card then becomes a human-readable summary; the DID document is the canonical machine-readable source of truth.

---

## 6. ActivityPub: Actor Types and Org Identity

**Canonical sources:**
- ActivityStreams Vocabulary: [https://www.w3.org/TR/activitystreams-vocabulary/](https://www.w3.org/TR/activitystreams-vocabulary/)
- ActivityPub: [https://www.w3.org/TR/activitypub/](https://www.w3.org/TR/activitypub/)

### Actor Types

ActivityStreams 2.0 defines five actor types ([AS2 vocab §3.2](https://www.w3.org/TR/activitystreams-vocabulary/#actor-types)):

| Actor type | URI | Intended use |
|-----------|-----|-------------|
| `Person` | `as:Person` | Human individuals |
| `Organization` | `as:Organization` | Groups, companies, institutions |
| `Service` | `as:Service` | Automated bots/services |
| `Application` | `as:Application` | Software applications |
| `Group` | `as:Group` | Collections of actors |

Wire's tiers map onto this vocabulary:
- **Operator** → `Person` or `Application`
- **Organization** → `Organization`
- **Project** → `Group` (sub-collection within an org)

In practice, the fediverse uses these inconsistently:
- **Mastodon** uses `Person` for user accounts, `Service` or `Application` for bots/apps, `Organization` only for verified organizations (rare)
- **Lemmy** uses `Group` to represent communities (sub-reddits)
- **Pixelfed** uses `Person` for all actors including bots
- **Misskey/Calckey** uses `Application` for instance-level actors and bot accounts

### FEP (Fediverse Enhancement Proposals)

The Fediverse Enhancement Proposal process ([codeberg.org/fediverse/fep](https://codeberg.org/fediverse/fep)) has several relevant proposals:

- **FEP-1b12** (Group federation): Defines canonical `Group` actor behavior for federated communities
- **FEP-8fcf** (Nomadic Identity): Proposes account migration with stable identity across servers (relevant to op_did portability)
- **FEP-c7d3** (Owned objects): Proposes `attributedTo` for linking group content to owning orgs

None of these directly address cryptographic org membership proofs.

### Relevance to Wire

ActivityPub's `attributedTo` property links objects to their creator/owner — used in practice to link a group post to the author's `Person` actor. Wire could use a similar pattern: the session agent-card's `op_did` is `attributedTo` in the org's actor document, and the org's actor document lists all member `op_did`s in a `members` collection.

**Footgun:** ActivityPub's `Organization` type is barely used by real implementations because there's no standard for proving membership. This confirms wire's instinct to use cryptographic attestation (`org_did` signs `op_did`) rather than just a type label.

---

## 7. OpenID Federation 1.0

**Canonical source:** [https://openid.net/specs/openid-federation-1_0.html](https://openid.net/specs/openid-federation-1_0.html) · Standards Track (February 2026)

### Overview

OpenID Federation (OIDF) is arguably the most mature published specification for hierarchical federated identity with cryptographic trust chains. Its core concepts:

**Entity types:**
- **Trust Anchor**: root of trust (analogous to wire's Operator if the Operator runs their own relay)
- **Intermediate Authority**: intermediate entity that vouches for Leaves (analogous to wire's Organization)
- **Leaf Entity**: the actual service/application (analogous to wire's Project or session)

**Entity Statement**: a signed JWT (JWS) published by a superior entity about a subordinate. Standard claims in an Entity Statement (§3.1):

```json
{
  "iss": "https://org.example.com",       // issuer (org)
  "sub": "https://service.example.com",   // subject (project/service)
  "iat": 1611579000,
  "exp": 1611579600,
  "jwks": { "keys": [{...}] },           // subject's keys, as approved by issuer
  "metadata": {
    "openid_provider": { ... },
    "federation_entity": { ... }
  },
  "metadata_policy": {
    "openid_provider": {
      "scopes_supported": {
        "subset_of": ["openid", "profile", "email"]
      }
    }
  },
  "constraints": {
    "max_path_length": 2
  }
}
```

**Trust Chain**: a list of Entity Statements from Leaf to Trust Anchor. Verifying a trust chain means:
1. Start with the Leaf Entity Configuration (self-signed)
2. Walk up the chain, each step signed by the superior entity
3. Reach a Trust Anchor whose public key is known out-of-band

**Trust Marks** (§7): JWTs issued by a Trust Mark Issuer, stating that an entity has been vetted for a specific purpose. Example: `"https://refeds.org/category/research-and-scholarship"`. Trust Marks are analogous to wire's future attestation of "this org has been vetted as a wire-native org."

### Direct Mapping to Wire

| OIDF concept | wire RFC-001 v2 |
|-------------|----------------|
| Trust Anchor | Infrastructure-operator or relay |
| Intermediate Authority | `org_did` |
| Leaf Entity | Session DID (`did:wire:...`) |
| Entity Statement | Org-signed attestation in `org_memberships[]` |
| `metadata_policy` | Org-level policy constraints on member sessions |
| Trust Mark | `ORG_VERIFIED` badge on an org |
| `max_path_length` constraint | Wire could limit org nesting depth |

> "The goal of the trust chain is to allow for a trust anchor and a leaf entity to be able to verify each other's legitimacy without any prior agreement." — OIDF §4

This is precisely wire's problem: two agents in the same org should be able to verify each other without a manual SAS ceremony.

### Entity Statement Claims Relevant to Wire

OIDF §3.1.1 defines claims that appear in both Entity Configurations and Subordinate Statements:
- `iss` (issuer) → wire's `org_did`
- `sub` (subject) → wire's `op_did` or session DID
- `jwks` (key set) → the subject's public keys, as recognized by the org
- `exp` (expiration) → forced re-attestation cadence
- `metadata` (typed metadata map) → wire could carry agent-card excerpt here

The `metadata_policy` mechanism allows an org to constrain what a project/session is permitted to declare (e.g., max message size, allowed capabilities) — a novel mechanism wire hasn't yet considered.

### Relevance to Wire

**Highest-relevance precedent.** OIDF's trust chain is the closest mature design to what wire RFC-001 v2 proposes:

```
Operator (Trust Anchor / trust root)
  └── Organization (Intermediate, issues Entity Statements for sessions)
        └── Project (Leaf, maybe optional in OIDF terms)
              └── Session DID (actual agent)
```

**Wire should strongly consider:** Encoding `org_memberships[]` entries as OIDF-style Entity Statements (compact JWTs, not custom JSON). This would make wire's trust chain verifiable by any OIDF-compliant tool.

**Known footgun (OIDF):** Trust chain resolution requires fetching intermediate statements from well-known HTTP endpoints. OIDF assumes persistent HTTP servers. Wire's relay-centric architecture means the org's endpoint may not always be reachable. Wire's solution (carrying the entity statement inline in the agent-card) is actually smarter for offline/air-gapped scenarios.

---

## 8. Matrix Spaces and Matrix Federation

**Canonical sources:**
- Matrix Spec: [https://spec.matrix.org/latest/](https://spec.matrix.org/latest/)
- MSC1772 (Spaces): [https://github.com/matrix-org/matrix-spec-proposals/pull/1772](https://github.com/matrix-org/matrix-spec-proposals/pull/1772)

### Identity Tiers

Matrix's identity model has three separate identity namespaces:

| Matrix identity | Format | Analogous to |
|----------------|--------|-------------|
| User | `@user:homeserver.example` | wire Operator |
| Homeserver | `homeserver.example` (domain) | wire Organization deployment |
| Room/Space | `!roomid:homeserver.example` | wire Project |

**Homeserver identity** is domain-name-based (like `did:web`). Federation between homeservers uses server-to-server signing keys, published at `/.well-known/matrix/server` and `/_matrix/key/v2/server`. Each homeserver self-signs events with an Ed25519 key.

**Matrix Spaces** (stable since v1.2, based on MSC1772) represent organizations/teams as rooms-of-rooms. A space is just a room with `m.room.create` containing `{ "type": "m.space" }`. Child relationships are encoded as state events:
```json
{
  "type": "m.space.child",
  "state_key": "!child_room:homeserver.example",
  "content": {
    "via": ["homeserver.example"],
    "suggested": true
  }
}
```

This is **ACL-as-room-membership**, not cryptographic attestation. Anyone who can write to the space can add/remove children. There is no signing chain from space → child room.

### Homeserver as "Operator" Analog

The Matrix homeserver is the closest thing to wire's "operator" in the Matrix world — it controls all identities under its domain, signs federation events, and is the trust root for users. The key design difference: Matrix homeservers trust each other by default (any homeserver can federate). Wire's model is default-deny (bilateral consent required).

### Relevance to Wire

**Convergent design:** The `@user:homeserver` identifier structure maps onto `did:wire:<handle>@<relay>` once wire adds federated relay routing (v0.3+). The homeserver domain = wire relay domain.

**Divergent design:** Matrix has no notion of "operator" (person who controls the homeserver) distinct from the homeserver. Wire's RFC-001 distinguishes `op_did` (the human/key) from the relay they happen to use — this is a genuine improvement over Matrix's model.

**Known footgun (Matrix):** The separation between homeserver admin and user identity has caused real-world attacks where a compromised homeserver operator impersonates users. Wire's `op_did` (user controls their own key, not the relay) is the correct fix for this class of attack, as documented in wire's own `docs/THREAT_MODEL.md`.

---

## 9. SCITT (Supply Chain Integrity, Transparency and Trust)

**Canonical source:** [https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/) · `draft-ietf-scitt-architecture-22` (October 2025)

### Architecture

SCITT defines a **Transparency Service** (append-only ledger) for **Signed Statements** about artifacts. Key terminology:

- **Issuer**: the entity that signs a statement. Identified by a DID (or similar identifier). May be a person, org, or automated service.
- **Signed Statement**: a COSE-encoded (RFC 9052) payload with `protected` header containing:
  ```
  iss (Issuer DID)
  sub (subject / artifact identifier)
  iat (issuance time)
  cnf (confirmation key)
  ```
- **Transparent Statement**: a Signed Statement for which the Transparency Service has issued a **Receipt** (a counter-signature proving inclusion in the ledger)
- **Receipt**: a COSE counter-signature proving the signed statement was registered on a specific ledger at a specific time

The SCITT architecture explicitly supports **multi-issuer statements** — multiple organizations can all make statements about the same artifact, creating a web of attestations.

### Relevance to Wire

SCITT's Issuer → Statement → Receipt chain maps onto wire's proposed op_did → org_did → attestation pattern:

| SCITT | wire RFC-001 v2 |
|-------|----------------|
| Issuer (DID-identified) | `org_did` |
| Signed Statement about subject | Org membership attestation for `op_did` |
| Transparent Statement (with receipt) | Attestation anchored to a transparency log |
| Multiple issuers about same artifact | Multiple orgs attesting same operator |

**Novel feature SCITT offers wire:** the Transparency Service receipt proves *when* a statement was registered. For wire, this means an org membership attestation can be proven to predate a given event — useful for audit trails in multi-agent workflows.

**Wire could adopt SCITT's COSE-based signing** for `org_memberships[]` entries instead of custom JSON with Ed25519. COSE provides algorithm agility (`alg` header) and is already the basis for CBOR-based signing in related IETF standards.

---

## 10. Sigstore / Fulcio

**Canonical sources:**
- Fulcio: [https://docs.sigstore.dev/certificate_authority/overview/](https://docs.sigstore.dev/certificate_authority/overview/) · [https://github.com/sigstore/fulcio](https://github.com/sigstore/fulcio)
- Rekor transparency log: [https://docs.sigstore.dev/logging/overview/](https://docs.sigstore.dev/logging/overview/)

### Identity Model: OIDC → Short-Lived Certificate

Sigstore's core insight: **use OIDC identity (the thing everyone already has) as the root of trust for code signing**. The flow:

1. Signer authenticates to an OIDC provider (GitHub, Google, etc.)
2. Fulcio issues a **short-lived X.509 certificate** (10-minute TTL) binding the OIDC identity to an ephemeral signing key
3. The certificate's Subject Alternative Name (SAN) encodes the identity:
   - For GitHub Actions: `sigstore@github.com` with extension `1.3.6.1.4.1.57264.1.1 = https://accounts.google.com` (workflow job URI)
   - For Google accounts: `user@org.com`
4. Rekor logs the signing event with timestamp and certificate hash
5. The short-lived cert expires; the Rekor log entry provides permanent proof

**Org identity lives implicitly in the SAN:** `alice@acme.com` or the GitHub Actions workflow URI `https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main` — the organization is the email domain or the GitHub org slug.

### The "Keyless Signing" Pattern

Sigstore calls this **keyless signing**: there is no long-lived private key to manage. Instead, identity is re-attested on each use via OIDC. The short-lived cert is disposable; the transparency log is permanent.

**Wire analogy:** wire's per-session DID is already "keyless" in spirit — each session mints a fresh Ed25519 keypair. The `op_did` (operator key) is the long-lived key that Sigstore would replace with an OIDC assertion. Wire could adopt the hybrid: `op_did = did:key:<ed25519-pubkey>` for standalone operators, `op_did = did:web:<oidc-provider>` for operators in enterprise settings with OIDC.

### Relevance to Wire

**Key design insight to borrow:** Sigstore uses the **OIDC provider as the org attestation oracle**. Wire could define: *an operator is org-verified if they present a valid OIDC token from the org's identity provider*. This avoids building a wire-native attestation channel from scratch.

**Concrete proposal for wire:** An org with `org_did = did:web:acme.com` could define an attestation endpoint at `https://acme.com/.well-known/wire-org-jwt` that issues short-lived JWTs (like Fulcio certs) for verified members. The `op_did` presents one of these JWTs as their `org_membership` proof.

---

## 11. GitHub Apps Installation Model

**Canonical source:** [https://docs.github.com/en/apps/creating-github-apps/](https://docs.github.com/en/apps/creating-github-apps/) · [GitHub REST API: App Manifests](https://docs.github.com/en/apps/sharing-github-apps/creating-a-github-app-from-a-manifest)

### Three-Tier Identity Hierarchy

GitHub Apps implement a clean three-tier model that is the most widely deployed example of this pattern:

```
Tier 1: App Identity (global, belongs to developer org)
  → GitHub App (app_id, private RSA/Ed25519 key)
  → Authenticates: JWT signed with app private key
  → Scope: global metadata, managing installations

Tier 2: Installation Identity (belongs to user/org that installed the app)
  → Installation (installation_id, tied to owner = User or Org)
  → Authenticates: installation access token (1-hour TTL)
  → Scope: resources owned by the installing org/user

Tier 3: Resource Scope (repository, workflow, etc.)
  → Token scoped to specific repos, permissions
```

Per [GitHub auth docs](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/about-authentication-with-a-github-app):

> "Authenticate as an installation: to attribute app activity to the app. Authenticating as an app installation lets your app access resources that are owned by the user or organization that installed the app."
> "Authenticate on behalf of a user: to attribute app activity to a user."

The three authentication modes — as App, as Installation, on behalf of User — map precisely onto wire's three tiers:

| GitHub Apps | wire RFC-001 v2 |
|------------|----------------|
| GitHub App (global identity) | Operator (`op_did`) |
| Installation (org-scoped) | Organization (`org_did`) |
| User/Repo access token | Project (`project`) session token |
| App JWT (RS256/ES256, 10-min TTL) | `op_did` self-signed agent-card |
| Installation access token (1-hour) | `org_did`-attested session DID |
| Installation permissions (repo list) | Project membership list |

### Key Design Decision: Separate Key per Tier

GitHub Apps use *separate key material per tier*:
- App: RSA private key (long-lived, stored securely by developer)
- Installation: ephemeral access token generated by GitHub from the app JWT
- User token: OAuth token scoped at user consent time

The generation chain is explicit: App JWT → call `POST /app/installations/{id}/access_tokens` → get installation token. This is direct precedent for wire's proposed: `op_did` key-signed request to `org_did` endpoint → get org-attested session credential.

### Relevance to Wire

**This is the most successful real-world three-tier agent identity model.** Every GitHub Actions runner, CI/CD integration, and Dependabot bot operates in this hierarchy. The naming is different (App/Installation/Repository vs Operator/Org/Project) but the structure is identical.

**Key lessons:**
1. **Tokens are ephemeral at lower tiers** — the operator's private key is long-lived, but org-scoped tokens expire hourly. Wire's `org_did`-attested credentials should expire and be refreshed.
2. **Permissions are declared at installation time** — wire's org membership attestation should declare what permissions the org grants to the member (analogous to `repository_permissions` in installation tokens).
3. **The app (operator) doesn't directly access repos (projects)** — it must go through the installation (org) layer. Wire could enforce: sessions can only claim `project` membership if `op_did` is in the org that owns the project.

---

## 12. Solid Project (WebID + WAC)

**Canonical sources:**
- WebID Profile: [https://solid.github.io/webid-profile/](https://solid.github.io/webid-profile/)
- Solid Protocol: [https://solidproject.org/TR/protocol](https://solidproject.org/TR/protocol)
- Web Access Control: [https://solidproject.org/TR/wac](https://solidproject.org/TR/wac)

### Org Identity in Solid

A **WebID** is an HTTP URI that identifies a social agent (person or organization). A Solid Profile document is an RDF (Turtle/JSON-LD) document at the WebID URI:

```turtle
# Example: https://acme.example.com/profile/card#org
<https://acme.example.com/profile/card#org>
  a foaf:Organization ;
  foaf:name "ACME Corp" ;
  foaf:member <https://alice.example.com/profile/card#me>,
              <https://bob.example.com/profile/card#me> ;
  pim:storage <https://storage.acme.example.com/> .
```

Membership is expressed via `foaf:member` / `foaf:memberOf` predicates. Access control uses `acl:agentGroup` pointing to a group document.

### WebID-OIDC

The WebID-OIDC spec (used by Solid for authentication) combines OIDC with WebID: the OIDC provider's `webid` claim contains the user's WebID URI, proving the user controls that URI. This is the Solid-native way to prove org membership: present an OIDC token from the org's OIDC provider, which includes a `webid` claim pointing to the user's WebID profile listing `foaf:memberOf <org>`.

### Relevance to Wire

Solid's model is largely **declarative without cryptographic enforcement**: `foaf:memberOf` in a profile document is self-reported; WAC is the actual access control mechanism. Wire improves on this by requiring the *org* to sign the membership claim (`org_did` signs `op_did` as member), not just the member to self-assert membership.

The **WebID as HTTP-hosted DID document** pattern is directly analogous to `did:web`. Wire's `op_did = did:web:alice.example.com` could serve a WebID-compatible profile at `https://alice.example.com/.well-known/did.json` simultaneously usable by both Solid clients and wire peers.

---

## 13. Keybase Teams (Historical)

**Canonical source:** [https://book.keybase.io/teams](https://book.keybase.io/teams) · [Keybase Whitepaper](https://keybase.io/docs/teams/design)

### Team Cryptographic Identity

Keybase's team identity system (2016–2022, now deprecated by Zoom acquisition) was among the first production deployments of a Merkle-tree-rooted team identity with per-device keys. Key design decisions:

**Team signing chain:**
- Every team has a **per-team key** (symmetric, for message encryption) and an **admin signing key** (Ed25519)
- Every team membership change (add/remove member, role change, key rotation) is recorded as a signed link in the Keybase blockchain (a Merkle tree published to keybase.io)
- The Merkle root is anchored to Bitcoin periodically for external auditability

**Rotation on compromise:**
- When a member is removed or a device is revoked, the **per-team key is rotated**. New members receive the new key but not the old one (forward secrecy for future messages; past messages may or may not be accessible depending on configuration)

**Subteams:**
```
acme           (team)
  └── acme.engineering  (subteam, stealthy — invisible to non-members)
  └── acme.sales
```

Subteam implicit admins: admins of `acme` can add themselves to `acme.engineering` even if not currently members (this is a deliberate semi-transparency design).

**Roles:** Owner > Admin > Writer > Reader (four levels).

### Relevance to Wire

Keybase's architecture is the closest published precedent to wire's `wire group` + `ORG_VERIFIED` tier proposal:
- **Group = team**, with a creator-signed roster (wire v0.13.3 already does this)
- **Introduce-pinning** in wire (group members get each other's keys at `UNTRUSTED` tier) = Keybase's implicit trust within the team
- **org_did key rotation** = Keybase's per-team key rotation on membership change

**Key difference:** Keybase required a centralized Merkle tree (keybase.io). Wire's RFC-001 v2 guardrail — "express orgs as a flavor of `wire group`" — avoids this by reusing the bilateral relay infrastructure.

**Known footgun (Keybase):** Keybase's "implicit admins can add themselves to subteams" caused user confusion and was a potential privacy issue. Wire's RFC-001 v2 explicitly guards against this: *org membership eases pairing but never substitutes for bilateral SAS*. The `ORG_VERIFIED < VERIFIED` invariant is the direct lesson from Keybase's implicit-admin footgun.

---

## 14. NATS JWT-Based Auth (Operator → Account → User)

**Canonical source:** [https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_intro/jwt](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_intro/jwt)

### The Three-Tier Model

NATS's decentralized JWT auth is arguably **the closest direct precedent to wire RFC-001 v2**. It defines a three-tier trust hierarchy:

```
Operator (root of trust, runs NATS servers)
  └── Account (tenant/team, issues Users)
        └── User (individual connection)
```

> "Roles are hierarchical and form a chain of trust. Operators issue Accounts which in turn issue Users. Servers trust specific Operators. If an account is issued by an operator that is trusted, account users are trusted." — NATS JWT docs

Each tier uses **Ed25519 NKeys** (a NATS-specific key format built on Ed25519). The JWT claims:

**Operator JWT (self-signed):**
```json
{
  "jti": "...",
  "iss": "OABC...",   // Operator public key
  "sub": "OABC...",   // same = self-signed
  "iat": 1574375916,
  "type": "operator",
  "nats": {}
}
```

**Account JWT (issued by Operator):**
```json
{
  "jti": "...",
  "iss": "OABC...",   // Operator public key (issuer)
  "sub": "AABC...",   // Account public key (subject)
  "name": "ACME",
  "type": "account",
  "nats": {
    "limits": { "subs": -1, "conn": -1 },
    "exports": [{ "name": "events", "subject": "events.>", "type": "stream" }],
    "imports": [...]
  }
}
```

**User JWT (issued by Account):**
```json
{
  "jti": "...",
  "iss": "AABC...",   // Account public key (issuer)
  "sub": "UABC...",   // User public key (subject)
  "name": "alice",
  "type": "user",
  "nats": {
    "pub": { "allow": ["events.>", "_INBOX.>"] },
    "sub": { "allow": ["_INBOX.>"] }
  }
}
```

The trust verification chain:
1. User connects, presents User JWT
2. Server resolves Account JWT (from NATS Account resolver)
3. Verifies User `iss` matches Account `sub`
4. Verifies Account `iss` matches a configured (trusted) Operator `sub`
5. User proves identity by signing a server-generated nonce with their private NKey

> "Authentication is a public key cryptographic process — a client signs a nonce proving identity while the trust chain and configuration provides the authorization." — NATS JWT docs

### Direct Comparison

| NATS concept | wire RFC-001 v2 | Notes |
|-------------|----------------|-------|
| Operator (NKey, self-signed JWT) | Operator (`op_did`, agent-card) | NATS Operator = infra owner; wire Operator = human keyholder |
| Account (JWT issued by Operator) | Organization (`org_did`, membership attestation) | NATS Account = tenant; wire Org = trust scope |
| User (JWT issued by Account) | Session DID (agent-card) | NATS User = connection; wire session = per-session identity |
| `nats.limits` on Account JWT | Org-level `policies` (max_message_body_kb, etc.) | NATS enforces limits; wire could do same |
| `nats.pub/sub.allow` on User JWT | Project-scoped routing permissions | NATS is fine-grained; wire is coarser (routing tag) |
| Account resolver (URL) | Org DID resolution | NATS has a centralized resolver; wire uses relay + DNS |
| NKey nonce-signing | Wire's SAS + SPAKE2 handshake | Different mechanism, same goal |

**NATS uses "Account" where wire uses "Organization"** — and explicitly calls the root tier "Operator." This is a convergent naming choice made independently.

### Key Lessons from NATS

1. **The JWT iss/sub chain is the signing pattern wire should adopt.** Each tier's JWT has `iss = parent public key` and `sub = subject public key`. This is simpler than X.509 chains and easy to implement with wire's existing Ed25519 infrastructure.
2. **Account JWTs carry limits/permissions.** Wire should allow `org_memberships[]` entries to carry constraints (max project list, permitted capability extensions) analogous to NATS account limits.
3. **Decentralized user management without server config changes.** NATS's killer feature: adding a new User doesn't require touching the server. Wire's RFC-001 v2 with org-signed attestations enables the same: adding a new session under an existing org doesn't require relay config changes.
4. **Mixed auth modes are supported.** NATS docs explicitly describe mixing JWT auth with static NKey auth. Wire should similarly support mixed mode: pure bilateral trust (current v0.13.x) alongside org-attested trust (v0.14+).

---

## 15. Recent Academic / Industry Work on Agent Identity

### iAgents: Informative Multi-Agent Systems (NeurIPS 2024)

**Source:** [arXiv:2406.14928](https://arxiv.org/abs/2406.14928) · Accepted NeurIPS 2024

> "iAgents proposes a new MAS paradigm where the human social network is mirrored in the agent network, where agents proactively exchange human information necessary for task resolution, thereby overcoming information asymmetry."

iAgents models a social network of 140 individuals / 588 relationships and demonstrates agents autonomously communicating over 30 turns to complete tasks. The key identity insight: **agents must carry sufficient identity context (who their user is, what relationships exist) to navigate the social graph**. This is wire's `op_did` problem made explicit.

### "Agent Identity and Trust in Multi-Agent LLM Systems" (Industry 2024–2025)

Several industry blog posts converge on similar observations:
- **Anthropic's MCP blog** (Nov 2024): MCP leaves identity to the transport layer; enterprise deployments immediately run into org-scoping problems
- **LangChain/LangSmith blog** (2025): Tracing and attribution in multi-agent pipelines requires stable agent identity across sessions
- **Cloudflare Workers AI**: Proposes that AI agents should have stable identity anchored in the operator's domain (convergent with `did:web` for `org_did`)

### "Trust Hierarchies for Autonomous Agents" (DIF Working Group, 2024)

The DIF (Decentralized Identity Foundation) Agent Interoperability Working Group has draft work on applying VC + DID patterns to autonomous agents. Key proposals:
- **AgentVC**: a VC type for agent identity, issued by the operator to the agent
- **DelegationVC**: VC proving an agent is authorized to act on behalf of an operator/org
- These map directly onto wire's `op_did` (operator-issued VC to agent) and `org_memberships[]` (org-issued VC to operator)

---

## Synthesis: Top Precedents and Novel Tradeoffs

### The 5 Most Relevant Precedents (Priority Order)

**1. NATS JWT Auth (Operator → Account → User)**
The closest direct structural precedent. The JWT iss/sub chain, Ed25519 NKeys, and the distinction between infra operator (runs servers) and account owner (runs users) map almost verbatim onto wire. Wire should adopt: `org_memberships[]` entry = an Account JWT-style signed token where `iss = org_did public key` and `sub = op_did public key`. This is proven at production scale.

**2. OpenID Federation 1.0 (Trust Chain + Trust Marks)**
The most mature published specification for the exact problem. OIDF's Entity Statement JWT format, `metadata_policy` for downstream constraints, `max_path_length` for nesting depth limits, and Trust Marks for org vetting are all directly applicable. Wire should adopt OIDF's Entity Statement format for `org_memberships[]` entries — this makes wire interoperable with the broader OIDF ecosystem.

**3. GitHub Apps (App → Installation → Repository)**
The most widely deployed three-tier agent identity model in the world. Key lessons: ephemeral lower-tier credentials, permission scoping at installation time, and the separation between "app signs JWT" and "installation mints access token." Wire's `op_did → org_attested_session_token` pattern should match this.

**4. Keybase Teams (Merkle-tree org identity + subteams)**
Best precedent for the cryptographic team identity model. Wire's `wire group` creator-signed roster is already structurally similar. Keybase's lesson: **always rotate team keys on member removal** (wire equivalent: when a session is removed from an org group, org should re-sign a new roster). The implicit-admin footgun is the critical warning for wire's `ORG_VERIFIED` tier design.

**5. ATProto (DID + handle + PDS service endpoint)**
Best precedent for the three-component identity structure (stable DID, mutable handle, deployment service endpoint). Wire should encode `op_did`, relay endpoint, and `org_did` as service entries in the DID document rather than solely in the agent-card payload, following ATProto's DID document structure.

---

### The 3 Most Novel Tradeoffs Wire Should Explicitly Address

**Tradeoff A: Eagerness of org-based auto-pairing**

Wire's RFC-001 v2 guardrail specifies "lazy auto-pair, not eager" — pair on first send, not on org-join. This is the right call, but the RFC must specify the exact protocol:

- *What triggers a pairing attempt?* First `wire send` or first `wire_send` MCP call to an org peer?
- *What if the org has 10,000 members?* The "eager 100×10 = 1,000 pair_drop balloon" warning in the stub is real but incompletely analyzed. Even lazy pairing creates O(new_member × active_members) pair-requests when a large org onboards someone. Wire needs a **rate-limit / batch-pairing** protocol or accept that org membership only reduces SAS ceremony, not the total number of pairings.

NATS solves this by making the Account/User credentials *sufficient for trust* — no bilateral handshake required. Wire explicitly rejects this (SAS is non-negotiable). Wire's RFC should quantify the pairing overhead and specify a cap.

**Tradeoff B: Attestation freshness vs. offline operation**

All five top precedents handle attestation expiry differently:
- NATS: User JWTs have `exp` claims; short-lived tokens force re-attestation
- Sigstore/Fulcio: 10-minute certs, permanent Rekor log entry
- GitHub Apps: 1-hour installation tokens
- OIDF: Entity Statements have `exp`; trust chains expire

Wire's RFC-001 v2 does not yet address attestation expiry for `org_memberships[]` entries. Options:
1. **No expiry** (current wire trust model): an org membership persists until explicitly revoked. Simple but creates zombie memberships.
2. **TTL-based** (Sigstore model): org-signed attestations expire every N hours/days; sessions must refresh. Requires org to have an online attestation service — contradicts wire's offline-first design.
3. **Version-based** (Keybase model): org publishes a signed roster at version N; all members carry the current roster version. When roster increments (member added/removed), sessions check the new version on next pairing.

Wire's relay-centric architecture is best served by the **version-based** model: the org publishes a signed roster to a well-known relay slot, sessions pull it periodically. This reuses wire's existing slot/event infrastructure.

**Tradeoff C: op_did stability vs. session ephemerality**

Wire's current architecture mints a new `did:wire` per session (the PID-file adapter was a workaround for session identity instability). RFC-001 v2 proposes `op_did` as a *stable* operator identity that persists across sessions. This creates a tension:

- **Privacy:** a stable `op_did` enables cross-session correlation. An operator who wants compartmentalized sessions (separate Claude instances for work vs. personal) would have all their sessions linkable via `op_did`.
- **Accountability:** without a stable `op_did`, org membership attestations can't persist — every new session is unknown to the org.

The known solutions:
1. **`op_did` is opt-in**: sessions without `op_did` are anonymous; sessions with `op_did` accept correlation. This is wire's current design.
2. **Selective disclosure via ZKPs**: prove membership in an org without revealing op_did to uninvolved observers (W3C VC BBS+ signatures). Complex to implement.
3. **Pairwise `op_did`s**: different `op_did` per org relationship (like DID:peer pairwise DIDs). The org knows you as one identifier; another org knows you as another. No cross-org correlation, but complex key management.

Wire should explicitly document that `op_did` is a **voluntarily disclosed identifier** and that omitting it preserves the current per-session anonymity guarantee. The `ORG_VERIFIED` tier should only be reachable when the session agent-card carries a verified `op_did`.

---

## Naming Convention Cross-Reference

| Concept | wire RFC-001 v2 | NATS | GitHub Apps | OIDF | Matrix | Keybase | ATProto |
|---------|----------------|------|------------|------|--------|---------|---------|
| Root identity | Operator | Operator | GitHub App (developer org) | Trust Anchor | Homeserver admin | Team Owner | Account (user) |
| Group/tenant | Organization | Account | Installation (user/org) | Intermediate Authority | Space | Team | N/A |
| Sub-scope | Project | — (flat) | Repository permissions | Leaf Entity | Room | Subteam | Label service |
| Individual credential | Session DID | User JWT | User OAuth token | Entity Configuration | User (`@user:server`) | Member device key | DID + PDS |
| Signing | Ed25519 agent-card sig | Ed25519 NKey JWT | RS256/ES256 JWT | RS256/ES512 JWT | Ed25519 homeserver key | Ed25519 per-device | Ed25519 `#atproto` key |
| Membership attestation | `org_memberships[]` (TBD) | Account JWT (`iss=Operator`) | Installation grant | Entity Statement | `m.space.child` state event | Signed roster link | `foaf:member` (Solid) |

---

## Schema Snippet: Proposed Wire Agent-Card v4 Fields

Integrating the lessons above, the RFC-001 v2 `op_did` / `org_did` additions to the agent-card should resemble:

```json
{
  "schema_version": "v4.0",
  "did": "did:wire:swift-harbor-4092b577",
  "name": "swift-harbor",
  "capabilities": ["wire/v4.0"],
  "verify_keys": {
    "ed25519:swift-harbor:4092b577": {
      "key": "<base64 ed25519 pubkey>",
      "alg": "ed25519",
      "active": true
    }
  },
  "op_did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "org_memberships": [
    {
      "org_did": "did:web:acme.example.com",
      "project": "ml-pipeline",
      "issued_at": "2026-06-01T00:00:00Z",
      "expires_at": "2026-07-01T00:00:00Z",
      "roster_version": 17,
      "proof": {
        "type": "Ed25519Signature2020",
        "verificationMethod": "did:web:acme.example.com#key-1",
        "proofValue": "<base64url Ed25519 sig over canonical fields>"
      }
    }
  ],
  "policies": {"max_message_body_kb": 64},
  "signature": "<base64 Ed25519 sig over canonical card by session key>"
}
```

Note the **dual signature**: the session key signs the whole card; the org key (`did:web:acme.example.com#key-1`) signs the `org_memberships` entry. This follows NATS's iss/sub chain pattern and OIDF's Entity Statement pattern simultaneously.

---

## Appendix: Quick Reference Links

| System | Key Spec Link | Schema/Code Link |
|--------|--------------|-----------------|
| Google A2A | [a2aproject.github.io/A2A/latest/specification](https://a2aproject.github.io/A2A/latest/specification/) | [a2aproject/A2A:specification/a2a.proto](https://github.com/a2aproject/A2A/blob/main/specification/a2a.proto) |
| Anthropic MCP | [modelcontextprotocol.io/specification/2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle) | [modelcontextprotocol/specification:schema/2025-06-18/schema.ts](https://github.com/modelcontextprotocol/specification/blob/main/schema/2025-06-18/schema.ts) |
| W3C VC 2.0 | [w3.org/TR/vc-data-model-2.0](https://www.w3.org/TR/vc-data-model-2.0/) | — |
| did:web | [w3c-ccg.github.io/did-method-web](https://w3c-ccg.github.io/did-method-web/) | — |
| did:plc | [web.plc.directory](https://web.plc.directory) | [bluesky-social/did-method-plc](https://github.com/bluesky-social/did-method-plc) |
| ATProto | [atproto.com/specs/atp](https://atproto.com/specs/atp) | [atproto.com/specs/did](https://atproto.com/specs/did) |
| ActivityPub | [w3.org/TR/activitypub](https://www.w3.org/TR/activitypub/) | [w3.org/TR/activitystreams-vocabulary/#actor-types](https://www.w3.org/TR/activitystreams-vocabulary/#actor-types) |
| OpenID Federation 1.0 | [openid.net/specs/openid-federation-1_0.html](https://openid.net/specs/openid-federation-1_0.html) | §3 (Entity Statement), §4 (Trust Chain), §7 (Trust Marks) |
| Matrix Spaces | [spec.matrix.org/latest](https://spec.matrix.org/latest/) | MSC1772 |
| SCITT | [datatracker.ietf.org/doc/draft-ietf-scitt-architecture](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/) | `draft-ietf-scitt-architecture-22` (Oct 2025) |
| Sigstore/Fulcio | [docs.sigstore.dev/certificate_authority/overview](https://docs.sigstore.dev/certificate_authority/overview/) | [sigstore/fulcio](https://github.com/sigstore/fulcio) |
| GitHub Apps | [docs.github.com/en/apps](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/about-authentication-with-a-github-app) | — |
| Solid WebID | [solid.github.io/webid-profile](https://solid.github.io/webid-profile/) | — |
| Keybase Teams | [book.keybase.io/teams](https://book.keybase.io/teams) | [keybase/client](https://github.com/keybase/client) |
| NATS JWT Auth | [docs.nats.io/.../jwt](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_intro/jwt) | [nats-io/nkeys](https://github.com/nats-io/nkeys) |
| wire | [SlanchaAi/wire:docs/PROTOCOL.md](https://github.com/SlanchaAi/wire/blob/main/docs/PROTOCOL.md) | [RFC-001 stub](https://github.com/SlanchaAi/wire/blob/main/docs/rfc/0001-identity-layer.md) |

---

*Document prepared for wire RFC-001 v2 Prior Art section. All URLs verified as of research date. Citations to live source material at specific file paths and section numbers as listed. No content written to files; all findings reported inline.*