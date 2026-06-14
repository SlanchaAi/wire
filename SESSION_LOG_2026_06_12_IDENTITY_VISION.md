# Session log — 2026-06-12 — identity-vision v0.15 build-out

Full-auto session. Goal: "build out the full identity system vision" beyond the
offline-minimal subset v0.14 shipped. Surveyed RFC-001 (+ SSO/filtering
amendments) and the as-built identity code, mapped vision→built→gaps, and
shipped the highest-leverage, offline-testable, gated increments as four PRs.

## What v0.14 had already shipped (the floor)
Offline cert primitives (`identity.rs`: sign/verify op+member certs), the
offline membership chain (`org_membership::evaluate_card_membership`), the
ORG_VERIFIED tier + one-way promotion (`trust.rs`), the per-org policy store
(`org_policy.rs`), `pair_decision`, enrollment producers (`enroll.rs`), and a
DNS-TXT *parser* (`relay_client.rs`) + SSO scaffold (`sso_provider.rs`).

## Key design finding (load-bearing across the session)
**A wire DID is a hash commitment to its key**: `op_did =
did:wire:op:<handle>-<32hex sha256(pubkey)>` (and same for org/session). Two
consequences that shaped the work:
- Project/key features must respect that the *key* is the identity.
- **Key rotation can't keep the DID** — rotating mints a new DID. So rotation is
  a *succession* (old key signs old→new), not an in-place swap. The RFC only
  sketched T19/T20; this was the real fork, resolved as a domain-separated
  succession cert.

## Shipped — four gated PRs (all branch-first, container-gated, NOT merged)

| PR | Feature | RFC | Files |
|----|---------|-----|-------|
| **#256** | per-peer **block-peer** (T16 rogue-admin containment) | §Sec T16 / AC4 | `blocklist.rs` (new), gate in `pair_invite.rs`, CLI in `pairing.rs` |
| **#257** | **project fan-out** `wire send-project` + `wire project` | §6 | `trust::project_recipients`, `comms::cmd_send_project`, `identity::cmd_project` |
| **#258** | **DNS-TXT org binding** `wire org bind/list/forget` | §2 / amend-sso §A | `org_bind.rs` (new, DoH resolver), `OrgCommand` |
| **#259** | op/org **key rotation** via succession-cert | T19/T20 | `identity::sign/verify_succession_cert`, `wire enroll rotate-op-key/rotate-org-key`, `config::append_succession_record` |

### #256 block-peer
`config/wire/blocklist.json`, DID-keyed (session OR op_did → mute all sessions).
Gates the inbound-pair handle path before any pin/pending stash (returns
`Ok(None)` — no fingerprint). Fail-safe to empty. Bilateral SAS out of scope
(explicit operator gesture overrides). e2e proves AC4 containment in the real
binary.

### #257 project fan-out
`project` was a dead card field (set by nobody, routed on by nobody). Added the
setter (`wire project <tag>`, rewrites+re-signs+republishes the card) and the
router (`wire send-project <tag>` → fan one signed event to every pinned peer at
tier ≥ ORG_VERIFIED with matching `project`). Tier floor is the trust gate;
project tag only selects. N one-to-one pushes (no broadcast primitive).

### #258 DNS-TXT org binding
The §2 trust floor: `wire org bind acme.com` resolves `_wire-org.acme.com` TXT,
extracts the `org_did`, writes the per-org policy. **DoH over the existing
reqwest** — no new DNS crate; `WIRE_DOH_URL` override; `TxtResolver` trait for
hermetic tests. Resolution is policy-setup-time only — the pairing hot path
stays fully offline. Rejects personal-tier op DIDs. Fake-DoH e2e covers the
full bind→list→forget loop.

### #259 key rotation
Succession cert = old key signs `wire-succession-v1|<kind>|<old_did>|<new_did>`
(domain-separated from op/member certs, proven both directions). Rotate verbs
mint a new keypair (new DID), self-verify the cert, append to `succession.jsonl`
BEFORE committing the new key, print manual re-enroll next steps. Receiver-side
auto-migration deferred (RFC says so explicitly); the cert is recorded for it.

## Deferred (documented, not built — need server/network or are speculative)
- SSO/OIDC channel (amendment-sso §B–E): network + 90-day kill criterion.
- Roster-bundle pull (§3/§7): needs deployed relay endpoints.
- wireup-registry `/v1/org/claim` producer endpoint (§2): producer side.
- Receiver-side succession auto-migration (T19/T20): follow-up to #259.
- RFC-006 dual-representation consolidation: fork-storm-adjacent infra, separate.

## Process notes
- Every PR gated through `./test-env/run.sh` (CI-mirror, pinned rust 1.88) before
  push; #256/#257/#258 confirmed green on GitHub's Mac/Linux/Windows matrix.
- Two gate catches: pinned-rustfmt reflow on a new test (wrote test after the
  last `cargo fmt`), and clippy `ptr_arg` (`&PathBuf`→`&Path`) in a test helper.
- No MCP tools added (CLI-first); the #255 agent-docs guard stays green since
  no `tool_defs()` changed. MCP exposure (`wire_send_project`, `wire_block_peer`,
  `wire_org_bind`) is an obvious fast-follow.

## Status
All four PRs open, container-gate-green, awaiting human merge. Nothing merged
(standing rule). No publish.
