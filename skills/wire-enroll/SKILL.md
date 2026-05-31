---
description: Enroll operator + organization identity per RFC-001 (the v0.14 identity layer). Use when the user wants to mint an op_did (long-lived operator anchor), create an org_did, issue/import member_certs, or republish their card with current enrollment. Personal-tier operators always carry a signing-key op_did regardless of SSO opt-in — wire-rooted identity is the security anchor.
---

# wire-enroll

The v0.14 RFC-001 identity layer surface. Each verb writes 0600 keys under `<config_dir>/wire/` and emits the corresponding `did:wire:op:*` / `did:wire:org:*` anchor.

## When to use

- User says "enroll", "mint op_did", "create org", "set up org identity"
- User wants to compose with the org-membership auto-pair lane (RFC-001 §3)
- Personal-tier user wants the signing-key anchor that's always present (per most-secure-default lock in RFC-003 deployment-tiers amendment)

## Surface

### `wire enroll op` — mint operator identity

```bash
wire enroll op
```

Mints `op.key` (Ed25519, 32 bytes, 0600) under `<config_dir>/wire/`. Prints `op_did` (`did:wire:op:operator-<32hex>`). **This is the wire-rooted signing-key anchor — required for the personal-tier identity surface; never optional.** SSO is purely additive attestation; the op_did + op_cert chain verifying offline is the cryptographic identity.

### `wire enroll org-create` — mint organization identity

```bash
wire enroll org-create --handle <orgname>
```

Mints `orgs/<sanitized-handle>.key` + prints `org_did` (`did:wire:org:<handle>-<32hex>`) and `org_pubkey`. The org root key is the single load-bearing secret of org-tier deployment — treat as a sealed credential.

### `wire enroll org-add-member` — issue a membership cert

```bash
wire enroll org-add-member <op_did> --org <org_did>
```

Issues a `member_cert` binding the operator to the org. Use the JSON output to distribute to the operator's session.

### `wire enroll republish` — refresh card with current enrollment

```bash
wire enroll republish
```

Rebuilds the stored card with the current `op_did` + `org_memberships[]` + bumps `schema_version` to v3.2 (if op claims present per the monotonic bump rule). Closes the enroll-after-init DX gap from v0.13: claims attach normally at card-build time, but an operator who enrolls AFTER `init` has a stored card pre-dating the claims.

## Verify enrollment

```bash
wire whoami --json | jq '.op_did, .org_memberships, .schema_version'
```

After enrollment, expect:
- `op_did`: `did:wire:op:operator-<32hex>`
- `org_memberships`: array of `{org_did, org_pubkey, member_cert}` triples
- `schema_version`: `v3.2`

## Auto-pair lane setup (receive side)

For peers in an org I trust to auto-pair without SAS gesture, create `<config_dir>/wire/org_policies.json`:

```json
{
  "orgs": {
    "did:wire:org:<their-org>-<32hex>": { "inbound": "auto" }
  }
}
```

Default-deny preserved for non-listed orgs. Auto-pin reaches ORG_VERIFIED only — VERIFIED still requires SAS.

## Most-secure-default lock (paul directive)

Personal-tier identity is always anchored at the wire-native Ed25519 signing key. No third-party SSO required. SSO is recognition + bootstrap convenience layer; never replaces the wire-rooted op_did. See RFC-003 deployment-tiers amendment §"Identity — most-secure default = wire-rooted signing key, ALWAYS".

## Reference

- RFC-001 identity layer: `docs/rfc/0001-identity-layer.md`.
- RFC-003 deployment-tiers amendment: `docs/rfc/0003-per-company-relays.amendment-deployment-tiers.md`.
- v0.15 SSO connectors (planned): `docs/PROMPT_v0.15_sso_connectors.md`.
