# Show HN draft — wire (STAGED)

Status: staged behind the live-link step. Positioning now LOCKED to Hyperagent's
campaign copy (2026-06-05) so all surfaces match. Voice pass (slancha-voice) optional
before Paul posts. Final go + visual sign-off = Paul.

Canonical spine (Hyperagent, campaign-owned): **"a phone line for your AI agents."**
One-liner divergence flagged to Hyperagent (08:04 vs 08:16 wording) — using the later
08:16 cut below; awaiting its confirm on the exact README/landing string.

---

## Title (HN ≤ 80 chars — pick one)

1. Show HN: wire – a phone line for your AI agents (encrypted, peer-to-peer, Rust)
2. Show HN: wire – agent-to-agent comms, no vendor in the middle
3. Show HN: wire – self-hostable encrypted messaging for AI agents

## Body (first comment)

Hi HN. wire is a phone line for your AI agents: end-to-end encrypted, peer-to-peer,
MCP-native. Agents dial each other by name and pick up mid-context; you run the relay,
so there's no vendor in the middle.

It's a small Rust CLI. Each side mints its own cryptographic identity, two agents pair
once with a short verification code (think Signal safety numbers), and from then on
every message is signed end-to-end. The relay in the middle only stores-and-forwards
ciphertext — it never sees plaintext and isn't an account you log into. You can run it
yourself.

Why I built it: most agent stacks route everything through a vendor's cloud and identity
system. I wanted agents that can establish trust and exchange signed messages without
anyone in the middle owning the namespace or the transport.

How it works:
- `wire init` → a DID-backed identity plus a persona name *derived from your key*. You
  don't pick the name — your name IS your key, so nobody can squat or spoof a handle.
- `wire pair-host` / `wire pair-join <code>` → SPAKE2 pairing; both terminals show
  matching SAS digits you confirm. No CA, no account.
- `wire send` / `pull` / `tail` → signed events; the receiver verifies every signature
  and rejects anything that doesn't check out.

Handles federate via signed agent-cards at `.well-known` (like Mastodon/Bluesky), so
there's no central directory. It's MCP-native and federates with A2A — it complements
them, it doesn't replace them.

[demo MP4/GIF — two agents mint identities, pair via SAS, send a signed message, receiver
verifies it. ~60s.]

Licensing is split by component so operators stay sovereign:
> The relay is the one component with the leverage to become a vendor — so it's
> **AGPL-3.0**. Run a modified relay as a network service and AGPL §13 obliges you to
> offer your changes' source to its users; a hosted relay can never quietly fork away
> from the open one. That's operator sovereignty written into the license. The **client
> is MIT** so you can embed it in anything, including closed software; the **protocol is
> Apache-2.0** — permissive plus an explicit patent grant — so anyone can reimplement
> wire cleanly.

It's early (pre-1.0; API may break — there's a Status & API stability note in the README).

Repo: https://github.com/SlanchaAi/wire

Would love feedback on the identity model and the relay trust boundary.

---

### Prepared rebuttals (for the thread — Hyperagent-owned framing, positive-statement only)

**"Isn't this just AgentWire?"**
> wire is local-first and self-hostable — your two agents talk directly, no vendor in the
> middle. Signed peer-to-peer, and each side keeps its own log. Handles federate via signed
> agent-cards at `.well-known` (like Mastodon/Bluesky), so no central directory. And the
> AGPL relay means nobody can close-fork it into a proprietary rival. Complements A2A + MCP
> rather than competing.

(Anyone forcing a literal feature-by-feature vs AgentWire → Paul, not copy. No unverifiable
head-to-head claims.)

**"Why not just use Signal/Matrix/email?"** — Those carry the bytes fine, but they bind
identity to a phone number / homeserver / mail provider. wire's identity is the keypair
itself (DID-derived persona), and the relay is a dumb pipe you own — the trust boundary is
the SAS pairing, not a provider account.

**"Is the relay a single point of failure/trust?"** — It store-and-forwards ciphertext only;
it can drop or delay but can't read or forge (signatures verify receiver-side). AGPL-3.0 so
you can self-host. Federation via signed agent-cards is the decentralization path.

---

### Open items before Paul posts
- Confirm exact canonical one-liner string for title/body (08:04 vs 08:16 divergence) — Hyperagent.
- Visual sign-off on the demo loop — Paul.
- "@laulpogan is agent-operated" disclosure beat — Paul's positioning call (Hyperagent flagged).
- Pick Tue–Thu AM-PT submit day Paul can babysit ~2-3h.
