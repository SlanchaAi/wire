# Revision Plan: efficient-agent-comms RFC
Generated: 2026-05-26
Personas: integrator, maintainer/strategy, implementer, interop/ecosystem, quality
All 4 code-grounded findings independently verified against src/ + THREAT_MODEL.md.

## BLOCKERS (must fix before circulation)
- [B1 Implementer/Integrator] FACTUAL: `kind` is `u32` (signing.rs:60); `decision`/`ack` are the `type` string. RFC conflated them. → Rewrite encoding: do NOT claim kind carries names.
- [B2 Implementer, verified pull.rs:7] Unknown `kind` BLOCKS the peer cursor → adding per-intent kinds deadlocks un-upgraded peers; "forward-compatible" false. → REDESIGN: use ONE registered `coord` kind (ships before any vocab content) with the intent in the BODY. Vocab evolves as body-schema, never new kinds → cursor never blocks.
- [B3 Interop, verified THREAT_MODEL T1] FACTUAL: "relay can't read bodies" is FALSE in v0.1 (signed-plaintext). → Remove. Security property = signature-integrity (no forgery), NOT confidentiality. Coded body no less readable than prose.
- [B4 Implementer, verified] `capabilities` is display-only; negotiation invented. → Reframe as TO-BUILD (per-peer cap store + send-time read + format select). State plainly it doesn't exist today.
- [B5 Sponsor] No kill criterion (KPIs only "pause/revisit"). → Add explicit abandon: KPI3 <20% end-to-end @60d → kill.
- [B6 Integrator/Interop/Sponsor] No receiver behavior for unknown intent / version skew / malformed body / group broadcast. → Specify: unknown intent → opaque/prose + warn; malformed → structured error event; version pinned per-peer w/ min-floor; group → sender intersects caps or prose.
- [B7 Quality/Implementer] KPI owners unassigned; harness+corpus don't exist (real corpus ≈7 prose msgs); sequencing inverted. → Assign owners; mark [TBD: to-build]; PR1 = measure-first; KPI1 threshold [TBD: baseline].

## MAJOR (must fix before review)
- [M1 Integrator] Reframe value: semantic determinism (no LLM re-interpret) > raw token count. Lead with it.
- [M2 Integrator] Cold-start wedge: honest "day-one value low until peer adoption; wedge = same-operator fleets (both ends yours)."
- [M3 Integrator/Implementer] Add "who this doesn't serve": sandboxed/file-system agents, no-card agents; pointer-deref → 0 for sandboxed.
- [M4 Integrator/Quality] Prose/code boundary must be MECHANICAL (intent-set membership), not LLM "is this routine" judgment (= the regex-for-intelligent-output anti-pattern). MUST→advisory note.
- [M5 Sponsor/Interop] Add GOVERNANCE section: ESMTP-success vs XMPP-fail precedent; state stance on upstream-A2A (propose as extension namespace vs own as wire-specific); registry + deprecation path.
- [M6 Sponsor] Note opportunity cost vs locked identity-first / A2A-adapter roadmap.
- [M7 Implementer/Integrator] "Pointers not payloads" = NEW feature, not a generalization; highest-ROI but separate milestone; sandboxed caveat.
- [M8 Quality] "substantially invertible" → "92% recovery on ≤32-token sequences; degrades on longer/precise content."
- [M9 Quality] Define "routine coordination" = membership in the closed intent set; KPI2 exclusion defined a priori.
- [M10 Quality] KPI1 threshold [TBD: baseline — token-count corpus before locking 60%].
- [M11 Quality/Sponsor] Move triage-embedding to Out-of-Scope/v2; note it INHERITS the cross-model alignment problem (needs shared embedding model) — same wall as the rejected path. Drop "earns its place."
- [M12 Sponsor/Interop] Note Blocker A (token I/O) is a vendor-API constraint, not physics — true for interop target, dissolves for homogeneous fleet.

## MINOR (fix cheap ones)
- Hedges: "genuinely" x2, "maximum intent", "most token waste" (uncited) → cut/qualify.
- "reasoning from token semantics [90]" → reframe as derived inference from the API token contract.
- Pin "event_id = body hash" to PROTOCOL.md.
- File a tracking issue for latent-comms future track (dangling "tracked as").
- Log: note vec2text 2025 reproduction is referenced not quoted; flag Interlat 24× as peak/task-specific.

## Cross-persona conflicts
- None material. All five converge: architecture (negotiated caps + coded body + mandatory prose fallback) is ESMTP-shaped and sound; the failures are factual errors, invented mechanisms, and missing operational/governance spec — fixable without redesigning the core. The B2 redesign (single `coord` kind) actually simplifies.

## Applied edits (this revision)
- [x] B1 encoding corrected (single `coord` kind + body intent; kind is u32)
- [x] B2 cursor-block sidestepped via single-kind design
- [x] B3 relay-can't-read claim removed/corrected
- [x] B4 negotiation marked to-build
- [x] B5 kill criterion added
- [x] B6 receiver/version/group/malformed behavior specified
- [x] B7 owners + [TBD] + measure-first sequencing
- [x] M1–M12 applied
- [x] minors applied where cheap
