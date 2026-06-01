# wire deployment tiers — personal vs organizational

**Status:** v0.15 operator guide
**Source RFCs:** [RFC-003](rfc/0003-per-company-relays.md) + [RFC-003 deployment-tiers amendment](rfc/0003-per-company-relays.amendment-deployment-tiers.md) (PRs #133/#134)
**Audience:** operators standing up wire — solo, fleet, or company.

Wire ships in **two deployment tiers**. They run the same binary and the same hybrid topology; the split is a deployment recommendation, not a protocol fork. The trigger between them is **operator count ≥ 2**, not size or compliance.

| Axis | Personal | Organizational |
|---|---|---|
| # operators | 1 | ≥ 2 |
| Relay | `wireup.net` (default) | Own relay (default), e.g. `relay.company.com` |
| SSO | Optional QoL — proves `op_did` = `github.com/<user>` | Load-bearing — IdP attests "operator ∈ org tenant" |
| Slot-binding gate | None (public phonebook) | Member-only (AC-DT1) |
| Compliance posture | Operator's stance | Often externally driven |
| Cost | $0 | < $5/mo |
| Onboarding | None (works out of `wire up`) | < 30 min |

**Wire-rooted signing key is the anchor in both tiers** (per signing-key-first lock, [PR #134](https://github.com/SlanchaAi/wire/pull/134)). SSO is attestation gloss; the operator's `op_did` cryptographic identity stands without any IdP. A personal-tier operator who never opts into SSO still has a fully-functional, peer-verifiable, offline-self-certifying identity. Same for organizational-tier members whose IdP is unreachable.

---

## Personal-tier walkthrough — solo fleet on `wireup.net`

Use when: one human, N sessions, N devices.

```bash
# 1. Install (5 sec)
$ cargo install slancha-wire        # or download install.ps1 on Windows
$ wire up                           # init + bind-relay + persona + daemon

# 2. Enroll your operator anchor (10 sec, no IdP required)
$ wire enroll op --handle willard
→ operator enrolled
  op_did:    did:wire:op:willard-<32hex>
  op_pubkey: <b64>
  key saved 0600 at ~/.config/wire/op.key

# 3. Republish your card so peers see the op claim
$ wire enroll republish
→ card rebuilt with current enrollment
  op_did: did:wire:op:willard-<32hex>
  published to phonebook: https://wireup.net

# 4. (OPTIONAL) Anchor your op_did at your personal domain for nick@domain.com discovery
#    Add the following TXT record at your DNS provider:
#    _wire-org.willardk.com. IN TXT "did=did:wire:op:willard-<32hex>; v=1"
#    Note: did= accepts both did:wire:org:* and did:wire:op:* (RFC-001 §A, RFC-003 §2)

# 5. (OPTIONAL) Add consumer-OAuth SSO attestation (v0.15+, PR #92 adapter)
$ wire enroll op --sso github      # one-shot OAuth, no IdP infra
# Now peers see "this op_did is also github.com/willard"
```

That's it. Your sessions on every device share the `willard` op anchor. Pairing with peers stays bilateral SPAKE2+SAS for first contact; your own sister sessions auto-pair via the existing v0.14 mesh.

**You do NOT need to run your own relay.** `wireup.net` is the shared public-good infra for personal-tier fleets.

**When to promote to organizational-tier:** the moment a second human shares your `org_did`. One human across N sessions stays personal-tier forever.

---

## Organizational-tier walkthrough — multi-operator company

Use when: ≥ 2 distinct humans share a trust scope (team, company, family).

```bash
# 1. Mint the org anchor (founding operator runs this once)
$ wire enroll org-create --handle company --json
{"org_did": "did:wire:org:company-<32hex>", "org_pubkey": "<b64>"}
# Treat ~/.config/wire/orgs/did_wire_org_company-<32hex>.key as a SEALED secret.
# Offline storage + hardware-backed where possible + documented rotation plan.

# 2. Stand up the relay
#    Recommended: Cloudflare Tunnel → home Spark / VPS / fly.io
#    HTTP relay at: https://relay.company.com (subdomain-split, RFC-003 §3)
#    Apex DNS-TXT:
#    _wire-org.company.com. IN TXT
#      "did=did:wire:org:company-<32hex>; \
#       relay=https://relay.company.com; \
#       sso_iss=https://company.okta.com/oauth2/default; \
#       sso_tenant=<okta-tenant-id>; \
#       v=1"

# 3. Each operator enrolls + the founder issues their member cert
#    (founder, on machine A)
$ wire enroll org-add-member did:wire:op:darby-<32hex> \
      --org did:wire:org:company-<32hex> --json
{"org_did": "...", "org_pubkey": "...", "member_cert": "..."}

# 4. New operator imports the bundle (PR #159, v0.14.2+)
#    (darby, on machine B)
$ wire enroll org-import-member-cert --bundle '<json>'
→ membership imported (validates op_did/org_did/pubkey/cert before persist)
$ wire enroll republish

# 5. Each operator binds to the company relay
$ wire bind-relay https://relay.company.com
# Relay verifies inline member_cert against pinned org_pubkey before allowing
# the bind (AC-DT1 slot-binding gate). Non-members get 403:
# {"error": "org_membership_required", "anchor_org": "did:wire:org:company-..."}

# 6. (v0.15) SSO at session start
$ wire init --sso okta              # IdP-mediated session-key attestation
# Peer pair_drops carry sso_attest envelope → ORG_VERIFIED on first contact
# (no SAS dance required for org-mates already in the Okta tenant)
```

**Pairing model going forward:**

| Scenario | Path |
|---|---|
| Stranger first-contact | SPAKE2+SAS → VERIFIED (unchanged) |
| Org-mate, both enrolled | pair_drop → `AutoOrgVerified` → ORG_VERIFIED (offline cert chain) |
| Org-mate via SSO (v0.15+) | OIDC JWT envelope → ORG_VERIFIED (no SAS dance) |
| Cross-org peer | DNS-TXT auto-resolves other org's anchor + relay; falls to manual SAS unless receiver-side `org_policies.json` allows |

**Offboarding** an employee from the Okta tenant → next `sso_epoch_advance` flushes cached attestation within the grace window (default 24h) → demotion to DNS-TXT floor → next pair fails verification → UNTRUSTED.

**The slot-binding gate (AC-DT1) is what makes "your relay" sovereign.** Without it, an org-tier relay is only branding. With it, only members can bind slots, and the verification check is offline (presenter's signed card + inline `member_cert` against locally-pinned `org_pubkey`).

---

## Migration: personal → organizational

A solo operator becoming an org (a second operator joins):

1. **Mint `org_did`** if not yet present — `wire enroll org-create --handle <company>`. Mint org root key (sealed credential).
2. **Spin up own relay** at `relay.company.com` (RFC-003 §6 v0.14.x supported this; v0.15 hardens).
3. **Publish DNS-TXT pin** with `did=`, `relay=`, SSO fields optional initially.
4. **Issue `member_cert`** for both operators (founder + newcomer). Both run `wire enroll org-import-member-cert` + `wire enroll republish`.
5. **Bind to company relay.** Existing wireup binding can stay for cross-fleet discoverability per hybrid topology.
6. **Receivers re-resolve** on next DNS-TXT refresh (≤ 24h). No manual re-pair.

Reverse migration (org → personal, last operator drops out): possible but loses the auto-pair lane. Recommended: keep `org_did` anchored even at N=1.

---

## Trust invariants (both tiers)

These hold regardless of which tier you deploy:

- **Wire-rooted signing key is the anchor.** SSO is attestation gloss, additive never substitutive. Operator stays sovereign over their own identity even when the IdP is unreachable or compromised.
- **Bilateral SPAKE2+SAS preserved for `VERIFIED`.** SSO + org-cert paths reach `ORG_VERIFIED` only. No SSO attestation, no org membership, and no `responder_state` claim ever promotes a peer to `VERIFIED`.
- **DNS-TXT is the offline anchor.** A peer whose DNS-TXT resolves but whose IdP/relay is unreachable retains prior `ORG_VERIFIED` state; new SSO-mediated upgrades require fresh JWKS reachability.
- **Cross-relay trust delegation = NONE.** A relay does NOT speak for any identity except as transport. Receivers verify offline against pinned material; relay said-so is forever distrusted.
- **Offline cert chain is non-negotiable.** The pairing hot path never makes network calls. DNS-TXT + JWKS resolution happens at bind/refresh time, never at pair-time.

---

## See also

- [RFC-003](rfc/0003-per-company-relays.md) — hybrid topology, DNS-TXT shape, A2A parity
- [RFC-003 deployment-tiers amendment](rfc/0003-per-company-relays.amendment-deployment-tiers.md) — the full design space behind this walkthrough
- [RFC-001](rfc/0001-identity-layer.md) — operator / org / project identity layer
- [RFC-001 SSO amendment](rfc/0001-identity-layer.amendment-sso.md) — §B `sso_attest` envelope, §B.1 `op_pseudonym`
- [PR #134](https://github.com/SlanchaAi/wire/pull/134) — signing-key-first lock (personal-tier sovereignty)
- [Issue #137](https://github.com/SlanchaAi/wire/issues/137) — v0.15 implementation tracking (this guide is AC-DT2)
