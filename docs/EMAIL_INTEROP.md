# Email interop — design brief

**Status:** design discussion, NOT yet scheduled. Ship gate is a yes/no
from the threat-model team on the BRIDGED trust tier.

**Filed as:** issue #16.

## TL;DR

The least-bad first product is **one-way outbound + magic-address
reply-only inbound, scoped to wireup.net handles**. Wireup.net runs as
a constrained MTA-of-record (DKIM-signed, SPF-aligned,
DMARC `p=quarantine`) under a dedicated subdomain (`mail.wireup.net`)
so the apex isn't poisoned. From: is operator-owned —
`<wire-handle>@mail.wireup.net`, not spoofed as the user's real email.

Wire's Ed25519 DID stays the cryptographic root; the SMTP envelope is
a lossy projection of it. Two-way "wire user ↔ arbitrary email user"
*as an equal peer* is a v0.2+ thing and probably never the right shape
— it inverts the bilateral consent gate (T11) and exposes wire's slot
to the global spam universe.

## Minimum viable first ship

A `wire send-email <addr> "<body>"` CLI + MCP tool that POSTs to a new
relay endpoint `/v1/email/send`, which DKIM-signs and submits via a
single outbound SMTP provider (Postmark / Resend / SES — pick one,
treat as replaceable).

- From: `<sender-handle>@mail.wireup.net`
- Reply-To: same.
- Relay maintains `(from_did, to_email, message_id) → wire event_id`
  mapping for thread reconciliation.
- Inbound MX on `mail.wireup.net` accepts replies **only** if the
  `In-Reply-To` / `References` header threads against a known
  mapping; everything else is dropped at SMTP `550`.
- Reply MIME parsed (text/plain preferred, HTML stripped), wrapped
  as a new `kind=1` event signed by a **relay-held bridge keypair**
  (DID `did:wire:bridge:<message-id-hash>`), deposited in the
  original sender's slot.

Cost: ~600 LOC, one new module (`email_bridge.rs`), one new relay
route pair, **zero changes to the wire protocol envelope**.

Demo: "wire user texts their non-wire friend's gmail; friend replies
in gmail; reply lands in `wire tail`."

## Open decisions (team must agree)

1. **MTA posture: own or rent.** Run our own SMTP on `mail.wireup.net`
   (full control, slow IP warmup, RBL surface) vs proxy through
   Postmark / Resend / SES (fast, $0–50/mo, vendor lock, ToS limits
   agents). Recommend *rent for v0.2.0, own for v0.3*; document the
   swap point.

2. **Identity mapping for inbound senders.** When `paul@gmail.com`
   replies, what DID do we synthesize? Options:
   - (a) deterministic `did:wire:email:sha256(addr)` (stable, leaks
     address-as-identifier)
   - (b) per-thread ephemeral DID (no cross-thread linkability,
     breaks "block this sender")
   - (c) no DID, surface as `from: email:paul@gmail.com` literal

   Recommend (a) with an `email:` prefix subnamespace so it cannot
   be confused with native DIDs.

3. **Threading model.** Email's `Message-Id` / `In-Reply-To` vs wire's
   signed event chain. Pick one canonical thread root; the other
   side is denormalized. Recommend: wire `event_id` is canonical;
   outbound mail carries `Message-Id: <event_id>@mail.wireup.net`
   so reply headers round-trip losslessly.

4. **Bridge-key trust tier.** Email-derived events are signed by the
   relay's bridge key, not by the email sender. They MUST surface
   in `wire tail` at a distinct tier (`BRIDGED`, below `VERIFIED`)
   and the CLI MUST render them as `bridge:paul@gmail.com` not
   `paul@gmail.com` — otherwise an email forger can impersonate any
   pinned peer. This is a new tier in `trust.rs`; not a Cargo-only
   change.

5. **Consent gate equivalent.** Bilateral pair (#7–#9) was the whole
   T11 mitigation. Email has no SPAKE2. Replacement: explicit
   per-recipient outbound enable (`wire email enable <addr>`)
   creates the `(from_did, to_email)` mapping; inbound that
   doesn't match a mapping is hard-dropped. **No global "open my
   inbox to email" switch.**

## Risks that kill the feature if ignored

1. **IP / domain reputation.** Apex `wireup.net` already serves the
   landing + relay. One spam complaint on `mail.wireup.net` with
   bad alignment and Gmail/Outlook silently SPAM-folder the whole
   apex. Must run mail on a subdomain with separate DKIM selector,
   separate SPF, and DMARC `rua` reports going to a real human.

2. **Spam/abuse asymmetry.** Wire's current threat model assumes
   bilateral consent. An open inbound MX is the exact opposite.
   Without the per-mapping allowlist (decision 5), any wire user
   becomes spam-reachable the moment they send one email.

3. **Forged-From-line impersonation.** SMTP From: is not authenticated
   below DKIM. Without SPF+DKIM+DMARC alignment checks at MX
   ingress, an attacker sends `From: paul@gmail.com` with no DKIM
   and the bridge happily signs a wire event purporting to be from
   paul. Inbound MUST require DKIM-pass + DMARC-aligned-pass; fail
   → 550, no event emitted.

4. **SMTP injection in body concatenation.** If `wire send-email`
   ever templates user-supplied subject / from into header lines,
   CRLF injection writes new headers (Bcc:, Reply-To:). Use a real
   MIME builder (`lettre`), never `format!`.

5. **Plaintext-by-default mismatch with wire's signing story.** Wire
   promises operators "every event is Ed25519-signed by the pinned
   peer." Email-bridged events break that and there is no way around
   it without PGP / S/MIME. **Documentation must be loud:** bridged
   events are *attested by the relay, not by the sender*. Hiding
   this loses the audit-log integrity property that's wire's main
   differentiator.

## Primitive reuse vs new shape

**Carries over cleanly:**

- The **signed-event envelope** — bridged events are still canonical
  JSON + Ed25519, just signed by the bridge key. `relays`,
  `wire tail`, `wire verify` work unchanged.
- The **dual-slot routing** — the bridge is a third slot type
  (`email_bridge` slot) alongside local / federation, same
  `relay_client` plumbing.
- The **`.well-known` discovery hook** — an email recipient becomes a
  synthesized agent-card with the bridge DID, so `wire whois
  email:paul@gmail.com` returns a real card.
- The **trust-tier state machine** — add `BRIDGED` as a new tier
  strictly below `VERIFIED`.

**Needs new shape:**

- A real **MTA module** (no SMTP code exists today).
- An **address-mapping store** (new `~/.config/wire/email-bridge.json`,
  structurally distinct from `petnames.json` because it's
  relay-side state not operator-side).
- A **consent primitive that is not SAS-based** — the bilateral SPAKE2
  handshake assumes both endpoints run wire and that assumption is
  exactly what email breaks.

## Adjacent: Matrix's pattern

Matrix's bridge model is `mautrix-email`: per-user double-puppeted
bridge running in the user's homeserver. The analogous wire shape is
"the bridge runs on the user's *own* relay, not on wireup.net,"
which is the right v0.3 posture and the one ANTI_FEATURES.md #1
("no SaaS dependency") implicitly demands. The MVP can centralize on
wireup.net; v0.3 must let operators run their own bridge against
their own MX.

## Recommendation

Ship the outbound-only `wire send-email` first (one week, low risk,
demonstrates intent). Gate inbound on the explicit per-mapping
allowlist (decision 5). Treat anything beyond "reply to a thread I
started" as out of scope until v0.3.

**If the threat-model team won't sign off on a relay-held bridge key
with a new `BRIDGED` tier, don't ship.** Outbound-only with no reply
path is still a useful product and doesn't compromise the integrity
story.
