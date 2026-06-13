# RFC-001 Amendment: same-machine session auto-pair (op_did-anchored attestation)

**Amends:** [RFC-001 v2](./0001-identity-layer.md) (Accepted, implemented v0.14)
**Status:** Draft <!-- Draft | Discussion | Accepted | Rejected | Implemented | Superseded -->
**Tracking:** [#182](https://github.com/SlanchaAi/wire/issues/182)
**Author:** slate-lotus (Claude Code agent, paired w/ @WILLARDKLEIN); design space jointly with coral-weasel (per #182 review)
**Date:** 2026-06-02
**Target:** v0.15 (no protocol-layer change at the trust ladder; new agent-card field + new CLI verb; CI surface only at receiver)
**Question this answers:** How does a wire operator running N sessions on the same OS user + same machine collapse the per-pair `wire dial` friction without standing up a synthetic org_did and without weakening the bilateral-SAS floor for non-sister peers?

---

## TL;DR

- Add a **`same_machine_attestation`** field to `agent-card.json` alongside the existing `op_did` / `op_pubkey` / `op_cert` chain. The field is a signature by the operator's `op_sk` over `"same-machine:" + <machine_fingerprint> + ":" + <session_did>`. Same-op + same-machine + same-OS-user sessions auto-pin each other at **`ORG_VERIFIED`** on first contact.
- **No new tier** — rides existing `ORG_VERIFIED` from RFC-001 §3. The bilateral-SAS invariant for `VERIFIED` is preserved.
- **No new top-level kinds and no new envelope.** The attestation lives inside the existing card-emit + `evaluate_card_membership` pipeline. Card-side parsing is field-additive (RFC-003 §2 rule), so pre-v0.15 receivers tolerate the field as opaque.
- **Machine fingerprint construction** is domain-separated + per-OS-user salted: `blake2b(machine_id ‖ os_user_uid ‖ "wire-same-machine-v1")[:32]`. Multi-user hosts cannot cross-pair across OS users. Closes coral's blind spot from the #182 review.
- **Receiver-side commitment check** — receiver recomputes `machine_fingerprint` from ITS OWN local `(machine_id, os_user_uid)` and refuses pin if the attestation's fingerprint does not match. Closes the hostile-forge case where a remote sender claims to share the receiver's machine.
- **Operator UX is one batch verb**: `wire enroll fleet-link --all-local` walks every sibling session under `sessions_root/by-key/*`, attaches a fresh attestation, and re-signs each card. Idempotent. Closes paul's 134-session case + willard's 410-by-key-dir case in one command.
- **Machine-move rotation** via `wire enroll fleet-link --rotate-machine` regenerates fingerprints + re-signs all sibling attestations after a laptop replace / OS reinstall.
- **Plugin SessionStart hook stays informational** per [`b9d5b50`](../../commit/b9d5b50)'s floor. The hook OPTIONALLY dispatches `wire enroll fleet-link --all-local` when an operator-pre-authorized flag file is present; the trust-state mutation still lives in `wire enroll`. Option D from #182 is operational glue, not protocol.

---

## Motivation

[Issue #182](https://github.com/SlanchaAi/wire/issues/182) surfaced the operator-felt gap: wire today has three auto-pair tiers (bilateral SAS, org-mediated, SSO-mediated) but no tier for *"these N sessions are owned by ME on the SAME MACHINE."* Operators with multi-session fleets currently choose between:

- **Per-pair `wire dial`** (Tier 1, manual every time) — fine for 2-3 sessions, fails at scale. willard-fleet machine accumulated 410 by-key/* dirs over normal operator use; fully meshing 24 active sessions = ≈276 dial commands.
- **Personal pseudo-org enrollment** (Tier 2 / RFC-001 v0.14) — works but invents a synthetic `org_did` that reads weirdly in `wire whoami` ("you are a member of personal-fleet") and requires 4 commands × N sessions of bootstrap friction.

The implicit trust assumption — *"same OS user, same device, same wire data-dir is by construction this operator's other process"* — is already used by `wire dial --local-sister`, which reads sister cards from disk and pins without `.well-known` / SAS digits. The trust-model claim is non-controversial; the gap is purely operator-typed-verb friction.

Coral's #182 review surfaced four constraints any answer needs to satisfy:

1. **Cryptographic enforceability** of the boundary (filesystem witness alone is too weak — anything that can write to the data-dir tree could mint a sibling).
2. **Protocol footprint** (a new tier name propagates into every reader of the trust ladder; avoidable cost).
3. **Operator-felt friction across the upgrade path** (paul's 134 sessions, willard's 410 by-key dirs — pre-existing; need an idempotent batch verb, not just per-init bootstrap).
4. **Migration story for the wire-plugin SessionStart hook** ("informational only" per `b9d5b50`; promoting it to trust-state mutator is a real category change).

This amendment threads all four: signed claim (1), no new tier (2), batch verb (3), plugin stays dispatcher (4).

---

## Design

### §A. Machine fingerprint construction

The fingerprint identifies a specific `(machine, OS user)` pair. It is **NOT** sufficient on its own as a trust anchor — the `op_sk` signature in §B is what makes the attestation verifiable; the fingerprint is the receiver-side commitment substrate.

```
machine_id_bytes = read_platform_machine_id()
os_user_uid_bytes = read_platform_user_uid()
machine_fingerprint = blake2b(
    machine_id_bytes
    || os_user_uid_bytes
    || "wire-same-machine-v1"
)[:32]
```

**Platform sources:**

- **Linux:** `/etc/machine-id` (systemd-style, 16-byte hex). Falls back to `/var/lib/dbus/machine-id` if absent.
- **macOS:** `IOPlatformUUID` from `IOKit` (`ioreg -rd1 -c IOPlatformExpertDevice`).
- **Windows:** `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` via registry read.

**OS user uid sources:**

- **Linux / macOS:** `getuid()` (`u32` little-endian bytes).
- **Windows:** SID string of the current user (extracted via `whoami /user`), UTF-8 bytes.

**Domain-separation tag:** `"wire-same-machine-v1"` protects against cross-protocol fingerprint collision (the machine_id is a shared identifier with potential other consumers — D-Bus, GitHub Codespaces, telemetry tools — so the tag scopes the hash to this RFC's use). The `v1` lets future fingerprint construction changes ship as `v2` without renaming `same_machine_attestation`.

**Output length:** 32 bytes (the first 32 bytes of blake2b's variable-length output). Same size as Ed25519 pubkeys, fits cleanly into existing inline-pubkey storage paths.

**Fail-closed on read errors:** if `machine_id` or `os_user_uid` cannot be read, the fingerprint is `None` and attestation building falls back to the existing card-emit path with no `same_machine_attestation` field. The session still functions; it just cannot participate in the same-machine auto-pair lane.

### §B. Same-machine attestation envelope

The agent-card gains one optional field alongside the existing `op_did` / `op_pubkey` / `op_cert` chain:

```json
{
  "schema_version": "v3.2",
  "did":         "did:wire:slate-lotus-88232017",
  "op_did":      "did:wire:op:willard-<32hex>",
  "op_pubkey":   "<b64>",
  "op_cert":     "<b64>",
  "org_memberships": [ ... ],
  "same_machine_attestation": {                         // NEW (this amendment)
    "machine_fingerprint": "<32B b64>",
    "signature": "<b64 — op_sk over canonical message>"
  },
  ...
}
```

**Canonical message signed:**

```
"same-machine:" || machine_fingerprint || ":" || session_did
```

`||` is byte-concatenation; the `:` separators are literal ASCII bytes (`0x3A`); machine_fingerprint is the 32-byte raw output from §A (NOT base64; the canonical bytes go into the hash); session_did is its UTF-8 bytes.

**Signature:** `op_sk` Ed25519 signature over the canonical message. 64 bytes raw, base64-encoded in the field.

**Why op_sk (not session_sk):** the trust anchor is the operator, not the session. A session-key-signed attestation would prove "this session said it's on machine X"; an `op_sk`-signed attestation proves "the operator who owns this session-DID says all my sessions on machine X share this fingerprint." The latter is the trust-model claim the receiver needs to act on.

**Why machine_fingerprint goes into the canonical signed bytes:** if a receiver could only see the attestation field without re-checking the fingerprint against its own local `(machine_id, os_user_uid)`, a hostile sender could claim ANY fingerprint and forge "I am on your machine." The signed canonical message + the receiver-side recompute (§C) together close this.

### §C. Receiver-side verification + commitment check

A receiver evaluating a peer's card for same-machine auto-pair runs the following chain. **All steps fail-closed.**

1. **Op-chain prerequisite.** The card MUST have a valid `op_did` + inline `op_pubkey` that commits to it + `op_cert` verifying the session_did under `op_pubkey`. This is the existing RFC-001 §1 check. If absent → no same-machine consideration; fall through to existing pairing logic.
2. **Same `op_did` check.** The receiver's own card MUST carry the SAME `op_did` as the sender. Different op_dids → not the same operator, no same-machine path; fall through. (The receiver locally knows its own op_did from its on-disk `op.json` + `op.key`.)
3. **`same_machine_attestation` field present.** If the field is absent → no same-machine attestation claim; fall through. Pre-v0.15 sender → no attestation field → fall through gracefully (field-additive evolution rule, RFC-003 §2).
4. **Local fingerprint recompute.** The receiver computes `machine_fingerprint_local = blake2b(machine_id_local || os_user_uid_local || "wire-same-machine-v1")[:32]` using its own local platform sources (§A).
5. **Fingerprint match.** The attestation's `machine_fingerprint` MUST byte-equal `machine_fingerprint_local`. **No prefix-match, no "or-better" semantics — strict-equality.** Mismatch → reject the same-machine claim (fall through to standard pairing logic); this is the case where a remote sender claimed to share the receiver's machine but doesn't.
6. **Signature verification.** Verify the attestation's signature against the inline `op_pubkey` (the same pubkey already verified in step 1), over the canonical message `"same-machine:" || attestation.machine_fingerprint || ":" || sender_session_did`. Failure → reject; the attestation was tampered or signed with the wrong key.
7. **Auto-pin at `ORG_VERIFIED`.** All checks pass. The receiver pins the sender at `ORG_VERIFIED` (the existing tier, no new ladder position) with provenance recorded as `via: same_machine_attestation` on the peer's card surface. The pin emits a toast (subject to `wire quiet` per [PR #117](../pull/117)).

**Out-of-scope for the receiver check:** verifying anything about the sender's claimed device beyond fingerprint equality. The receiver trusts ITS OWN local fingerprint as the source of truth for "what does my machine look like"; it does not delegate.

### §D. Operator CLI surface

Two new verbs under `wire enroll`:

#### `wire enroll fleet-link --all-local [--dry-run] [--json]`

Idempotent batch-link of every sibling session on this machine. For each `agent-card.json` under `sessions_root/by-key/*` owned by this OS user:

1. Read the existing card.
2. Compute the local `machine_fingerprint` (§A).
3. Read the session's local `op.key` if present; if absent, log "not enrolled — skipped" and continue.
4. Build `same_machine_attestation` (§B) using the session's own `op_sk` + `session_did`.
5. Overlay the attestation field on the card, re-sign the card with the session's session-key (existing card-emit path), persist.

`--dry-run` prints the plan without writing. `--json` emits structured output suitable for piping into a status surface.

**Pre-conditions surfaced as errors:**

- No `op.key` in any sibling session → "no operator-enrolled sessions found; run `wire enroll op` first."
- `machine_fingerprint` cannot be computed (read error on platform source) → bail with the platform-specific diagnostic.

**Idempotency:** re-running on an already-linked fleet is a no-op (existing attestation matches; signature does not change since canonical message is deterministic).

#### `wire enroll fleet-link --rotate-machine [--json]`

For operator scenarios where the machine itself moves (laptop replace, OS reinstall, container migration). Walks every sibling session, recomputes `machine_fingerprint` against the (now-new) local platform sources, re-signs each attestation. Distinct from `--all-local` because the input changed, not the data — useful explicit verb-naming for the migration runbook.

**Receiver-side impact of rotation:** old attestations no longer validate (peer-side `machine_fingerprint_local` no longer matches the now-stale attestation field). Peers fall through to standard pairing logic; the operator must re-pair manually OR wait for the next dial cycle where the rotated attestation will land. No silent demotion of trust — peers stay at whatever tier they were already at (`ORG_VERIFIED` from a prior org-cert-mediated pairing remains; only the same-machine fast path goes silent).

### §E. Plugin SessionStart hook (Option D, operational layer)

The wire-plugin SessionStart hook (`b9d5b50`) stays **informational** per its current floor. This amendment does NOT promote the hook to a trust-state mutator. Instead:

- The hook may OPTIONALLY dispatch `wire enroll fleet-link --all-local` IF a flag file at `<config_dir>/auto_fleet_link.json` is present (operator-pre-authorized opt-in).
- The dispatch is a `subprocess` call into the existing `wire enroll` CLI; the trust mutation lives there, the hook is just the trigger.
- Without the flag file, the hook behavior is unchanged from `b9d5b50` (status-line probe only).

This preserves the "informational only" floor for the hook itself while giving operators a one-step opt-in to automated fleet-link on every session start (which subsumes the "fresh session id per resume" failure mode flagged in #182's Claude-resume question).

---

## Security

### S1: Cross-OS-user pairing on a multi-user host

**Threat:** user A and user B on the same Linux server (research cluster, shared dev box). Without per-OS-user salt, A's sessions would auto-pair with B's sessions because they share the same `/etc/machine-id`.

**Mitigation:** the per-OS-user salt baked into `machine_fingerprint` (`getuid()` / SID bytes mixed into the blake2b input). Different OS user → different fingerprint → receiver-side commitment check (§C step 5) fails. No cross-user pairing.

**Residual:** if user A and user B share an `op_did` (impossible by design — operators have their own `op_did`), they would also share fingerprint-eligibility. The model assumes one op_did per (human, machine) account.

### S2: Hostile-forge of the attestation field

**Threat:** a remote sender (not on the receiver's machine) crafts a card claiming `same_machine_attestation.machine_fingerprint = <receiver's_fingerprint>` to bait an auto-pin.

**Mitigation:** §C step 5 (receiver-side commitment check) — the receiver recomputes `machine_fingerprint_local` from its OWN platform sources and refuses unless byte-equal. A remote sender cannot know the receiver's fingerprint without ALREADY being on the receiver's machine (in which case it is, by definition, not a remote sender).

**Residual:** an attacker who can already read the receiver's `/etc/machine-id` + `uid` could compute the fingerprint. But the same attacker can already read the receiver's `op.key` and impersonate the operator wholesale — the same-machine attestation is not the weakest link.

### S3: Stale attestation after machine rotation

**Threat:** an operator's machine is replaced (laptop swap) but old session cards still carry attestations for the OLD `machine_fingerprint`. A remote attacker who learns the old fingerprint via some side channel could not exploit it on the new machine (different fingerprint), but stale-attestation cards may pollute the phonebook with non-verifiable claims.

**Mitigation:** the `--rotate-machine` verb (§D) regenerates all attestations after a known move. Receivers reject mismatched attestations (no silent acceptance), so the phonebook pollution is benign — pre-rotation cards just fall through to standard pairing.

### S4: machine_id rotation by the platform (without operator action)

**Threat:** some platforms (containers, ephemeral VMs, BSD jail provisioning) may rotate `/etc/machine-id` without operator awareness. Cards minted under the prior `machine_id` no longer auto-pair on the same physical host.

**Mitigation:** detect-and-rotate. Operators in containerized environments SHOULD treat each container reboot as a `--rotate-machine` event. A future `wire doctor` check can compare the current platform fingerprint against the one in the card and warn on drift; not specified here (out of scope for v0.15).

### S5: Cross-machine attestation replay

**Threat:** an attacker captures a valid `same_machine_attestation` from machine M1, replays it on machine M2 claiming to be a sibling.

**Mitigation:** the canonical message includes `session_did`, which is unique per session and freshly minted. The attestation signs `<machine_fingerprint, session_did>` together; replaying it on a different machine fails the receiver's fingerprint match (§C step 5). Replaying with a different session_did fails signature verification.

### S6: Op-key compromise

**Threat:** an attacker who obtains the operator's `op.sk` can mint arbitrary same-machine attestations.

**Mitigation:** op-key compromise is fatal regardless of this amendment — the same key signs `op_cert` and all `member_cert`s the operator vouches for. No new attack surface introduced. Mitigation is the existing operational discipline (op_key stored 0600, hardware-backed where possible).

---

## Privacy

### P1: machine_id leak via attestation field

**Concern:** does publishing `same_machine_attestation` to the phonebook leak the operator's `machine_id`?

**Answer:** no. The published field is `blake2b(machine_id || uid || tag)[:32]` — a one-way hash. The raw `machine_id` is not recoverable from the fingerprint without a brute-force guess across the (machine_id, uid) space. machine_id has high entropy (UUID-shape), uid is low entropy, but the combination is non-invertible by design.

### P2: Cross-fleet operator tracking

**Concern:** could an observer correlate `same_machine_attestation` fingerprints across multiple `op_did`s on the same machine to learn that an operator runs multiple fleet identities?

**Answer:** yes, partially. Two cards with the same `machine_fingerprint` but different `op_did`s expose "these are on the same (machine, user)" to anyone reading both cards. This is a minor privacy degradation. Mitigations:

- The `op_did` field itself is a stronger identifier; an operator running multiple `op_did`s on one machine already exposes that via the op_did + signing-key correlations.
- An operator concerned about cross-fleet tracking SHOULD NOT publish multiple `op_did`s on a shared phonebook surface. This is a pre-existing recommendation, not a new constraint.

If high-privacy operators need per-fleet fingerprint isolation, a future extension can add a per-fleet salt: `blake2b(machine_id || uid || op_did || tag)`. Out of scope for v1; opt-in.

### P3: Phonebook visibility

**Concern:** the attestation field publishes on the phonebook. Should it?

**Answer:** for v1, yes — phonebook publication is the same surface that already carries `op_did` / `op_pubkey` / `op_cert`. Same-machine attestation does not increase the phonebook visibility footprint beyond what is already published.

A future "no-publish" variant (attestation stays local, never lands on the phonebook) would require a separate dial-time exchange channel; out of scope for v1.

---

## Acceptance criteria

≤5 falsifiable, time-bound. Each MUST have a test that fails before the implementation lands and passes after.

- **AC-SM1: Same-op + same-machine + same-uid auto-pin.** Two test sessions A and B share an `op_did` + `op_sk` + `(machine_id, uid)`. A dials B → A's pair_drop carries a `same_machine_attestation` field; B's receiver chain (§C) runs all 7 steps clean; B pins A at `ORG_VERIFIED` with `via: same_machine_attestation`. Test: harness mints A + B sessions with shared op + shared fingerprint, dials, asserts `B.peers[A].tier == ORG_VERIFIED` and `B.peers[A].provenance == "same_machine_attestation"`. Owner: v0.15 implementer.
- **AC-SM2: Different-uid rejects.** Same machine, same op_did, but A's uid ≠ B's uid → receiver's local fingerprint differs → §C step 5 fails → A pinned via fall-through path (typically `UNTRUSTED` until standard pairing). Test: harness simulates two uids; asserts pin tier is NOT promoted via same-machine path. Owner: v0.15 implementer.
- **AC-SM3: Hostile fingerprint forge rejected.** A claims `machine_fingerprint = <B's fingerprint>` in its attestation but the signature is over `<some other fingerprint>` (testing the canonical-bytes invariant). §C step 5 passes (fingerprint matches B's local), step 6 fails (signature doesn't verify over the claimed fingerprint). Pin rejected. Test: harness mints a tampered card with mismatched signed-vs-published fingerprint; asserts pin tier NOT promoted. Owner: v0.15 implementer.
- **AC-SM4: `wire enroll fleet-link --all-local` is idempotent.** Run twice on the same fleet; the second run produces a no-op (cards byte-equal; signatures equal because canonical message is deterministic). Test: harness invokes twice, asserts file mtimes can change but card contents do not. Owner: v0.15 implementer.
- **AC-SM5: Field-additive evolution.** A v0.14 receiver (or any pre-v0.15 wire version) ingesting a card with `same_machine_attestation` skips the field gracefully (treats as unknown extra, no parse error). Test: harness invokes a v0.14-shaped parser against a v0.15-shaped card; asserts no error, asserts non-same-machine fields parse normally. Owner: v0.15 implementer.

---

## Kill criterion

If implementing `machine_fingerprint` reliably across Linux + macOS + Windows + containerized environments requires a per-platform shim layer larger than ~150 LOC, abandon this amendment and accept Tier 2 (personal pseudo-org via existing RFC-001 v0.14) as the operator-felt friction floor. The whole value proposition is "operator types one verb"; if the platform-shim surface explodes, the value is gone.

---

## Out of scope

- **Cross-machine session migration** (sessions move from machine A to machine B). The attestations don't transfer; the operator runs `--rotate-machine` on B. v0.16 candidate to model "session lifetime spans multiple machines" if demand surfaces.
- **Per-fleet salt for privacy isolation** (P2 mitigation). Out of scope for v1; opt-in extension later.
- **Phonebook no-publish variant.** Out of scope; requires a separate dial-time exchange channel.
- **Container/ephemeral-VM auto-rotation detection** (S4 mitigation). v0.16 `wire doctor` check candidate.
- **Same-machine attestation participating in any tier promotion higher than `ORG_VERIFIED`.** Forever. The bilateral-SAS invariant for `VERIFIED` is preserved; this amendment never crosses that line.

---

## Open questions

- **Q1: Same-machine attestation on org-tier deployments.** Org-tier operators (RFC-003-amendment-deployment-tiers) may have multiple devices participating in their `org_did`. Does same-machine attestation compose with org-mediated auto-pair, or are they distinct lanes? Recommend: distinct lanes. Same-machine fires when both peers carry the SAME `op_did`; org-mediated fires when both peers carry the SAME `org_did`. Both can fire; both promote to the same `ORG_VERIFIED` tier; receiver's `org_policies.json` decides which provenance is preferred for the pin metadata.
- **Q2: Should `--all-local` walk dead/abandoned by-key sessions?** willard's machine has 410 by-key dirs, most are dead one-shot Claude tabs with no live daemon. Linking them is wasted work but harmless. Recommend: link only sessions with a recently-touched daemon pidfile (e.g., < 30 days). Operator can override with `--include-stale`.
- **Q3: `--rotate-machine` requires re-pair with remote peers?** If an operator rotates their machine, their non-sibling peers (paul, swift, etc.) hold pins to the operator's session DIDs. The session DIDs do not change (only the machine fingerprint does); existing pins remain valid. Same-machine fast path stays silent on remote peers (they were never same-machine anyway). No remote re-pair needed. Confirm: yes.
- **Q4: Plugin SessionStart hook auto-flag-creation.** Should `wire setup` (the plugin install/config helper) offer to create `<config_dir>/auto_fleet_link.json` at install time, or should the operator drop it manually? Recommend: prompt during `wire setup --apply`; default deny; operator types `yes` to opt in. Matches the consent-first pattern of every other wire surface.

---

## Alternatives considered

- **Option A — Filesystem witness only** (`wire up --same-device-auto-pair` flag, auto-pin any sibling under `$WIRE_HOME`). Rejected: filesystem witness is too weak (per coral's #182 review constraint 1). Any process that can write to the data-dir tree could mint a sibling.
- **Option B — Auto-enroll into a `personal-fleet` pseudo-org at `wire init`**. Rejected: invents a synthetic `org_did` the operator does not actually want; "org of one human" reads weird in `wire whoami`; requires upgrade-path bootstrap that this amendment's batch verb already provides without the awkward org_did.
- **Option D-as-replacement — Plugin SessionStart hook as the trust-state mutator**. Rejected: violates `b9d5b50`'s "informational only" floor for the hook. This amendment keeps the hook as dispatcher (operationally) and puts the trust mutation in `wire enroll` (architecturally).
- **New `LOCAL_VERIFIED` tier between `UNTRUSTED` and `ORG_VERIFIED`**. Rejected: protocol footprint cost (coral's constraint 2). Every reader of the trust ladder grows; `Ord` extends; status surfaces grow a new branch. Avoidable.

---

## References

- [Issue #182](https://github.com/SlanchaAi/wire/issues/182) — discussion thread where Options A/B/C/D were enumerated and coral surfaced Option C as the right shape.
- [RFC-001](./0001-identity-layer.md) §1 — `op_did` / `op_pubkey` / `op_cert` chain; the foundation this amendment extends.
- [RFC-001 §3](./0001-identity-layer.md) — `ORG_VERIFIED` tier definition; this amendment uses it without modification.
- [RFC-001-amendment-sso](./0001-identity-layer.amendment-sso.md) §F — body-discrimination-on-existing-kind pattern that this amendment parallels via field-discrimination-on-existing-card.
- [RFC-003 §2 field-additive evolution](./0003-per-company-relays.md) — the rule that lets pre-v0.15 receivers tolerate the new `same_machine_attestation` field gracefully.
- [RFC-003-amendment-deployment-tiers](./0003-per-company-relays.amendment-deployment-tiers.md) — names "personal-tier" at `# operators ≥ 1` framing; this amendment is the N-sessions-per-single-operator sub-case the deployment-tiers amendment did not enumerate.
- [PR #134](https://github.com/SlanchaAi/wire/pull/134) — signing-key-first lock; the wire-rooted-anchor principle this amendment preserves.
- [`b9d5b50`](https://github.com/SlanchaAi/wire/commit/b9d5b50) — wire-plugin SessionStart hook "informational only" floor.
- [PR #117](https://github.com/SlanchaAi/wire/pull/117) — `wire quiet` toast suppression; respected by same-machine auto-pin toasts.
- [`docs/CONSENT_DESIGN.md`](../CONSENT_DESIGN.md) — three-axes consent framing; this amendment lives at the identity axis, not the consent axis (operator-pre-consents at fleet-link time).
