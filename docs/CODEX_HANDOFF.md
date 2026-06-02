# Codex Handoff — v0.5.9 implementation batch

**Branch:** `codex/v0.5.9-batch` (create from `main`)
**Target:** ship all 8 tasks below as separate commits on that branch
**Repo:** `SlanchaAi/wire` @ HEAD (`ff22a18` as of this writing)
**Audience:** Codex (OpenAI). Single agent doing serial implementation work.

This doc captures what to build, how to verify each piece, and where the
judgment calls are. Each task is self-contained — Codex should be able to
tackle them in the listed order without needing additional context beyond
this file + the in-repo code.

## Before starting (one-time setup)

```bash
git checkout main
git pull --ff-only
git checkout -b codex/v0.5.9-batch
```

Confirm baseline:

```bash
cargo build --release        # should succeed
cargo test --release         # full suite, expect green except possibly
                             # tests/e2e_detached_pair.rs (pre-existing
                             # local-only flake; CI is green on it)
cargo fmt --all --check      # must be clean
cargo clippy --release       # warnings ok, no errors
```

If any of those fail before you start, stop. Don't begin work on a broken
baseline. Open an issue / report back instead.

## House rules

- **One commit per task.** Atomic. Each commit message starts with the
  task ID in brackets (e.g. `[a] migrate A2A extension URI to slancha.ai`).
- **Tests pass before commit.** Run `cargo test --release` + `cargo fmt
  --all --check` + `cargo clippy --release` before each commit. If a task
  modifies tests, the modification must be defensible (matching schema
  change, not loosening the assertion to make a bug pass).
- **No version bump per task.** Only the final commit on this branch bumps
  `Cargo.toml` + `tests/cli.rs` version assertion + `CHANGELOG.md` to
  `v0.5.9`. See task `final` below.
- **Don't touch unrelated code.** Each task's diff should be reviewable in
  isolation. If a refactor would help, leave a comment in the commit body
  and skip it — don't bundle.
- **Phyllis voice on new user-facing strings.** Style established in
  v0.5.4. Examples: `phyllis: <peer>'s line is silent`, `phyllis: that
  number's been disconnected`. Tone = sixties-switchboard-operator,
  technical content preserved.
- **A2A extension URI stays exact-string-matched.** See task `a` —
  there's one URI the protocol treats as an opaque identifier. Don't
  generalize the comparison even when migrating the string.
- **If blocked:** add a `## Blocked` section to a `BLOCKED.md` file at
  repo root with what stopped you + what info you'd need to unstick.
  Continue with the next task. Don't sit.

## Task order (suggested)

Tasks ordered cheapest-first to build confidence. Each task notes
dependencies on prior tasks.

---

## [a] Migrate A2A extension URI from laulpogan to slancha.ai

**Why:** wire's A2A extension URI is currently
`https://github.com/laulpogan/wire/ext/v0.5`. The repo moved to
`SlanchaAi/wire`. The URI is opaque-identifier-matched by federation
peers, and right now wire is the only consumer in the wild, so migration
is free. We want the namespace under a stable domain (slancha.ai owned by
the org) rather than tied to GitHub specifically.

**Target URI:** `https://slancha.ai/wire/ext/v0.5`

**Files to touch:**
- `src/relay_server.rs` — find the line containing
  `"uri": "https://github.com/laulpogan/wire/ext/v0.5",` (inside the
  `well_known_agent_card_a2a` handler). Update to new URI. Update the
  preceding block-comment to drop the "MUST stay forever as laulpogan"
  framing — that was overcautious. Replace with a short note that
  extension URIs are opaque namespace identifiers and changing them is
  a coordinated federation-spec bump.
- `src/pair_profile.rs` — find the line containing
  `.starts_with("https://github.com/laulpogan/wire/ext")`. Update to
  match the new prefix. Drop the matching comment.
- `CHANGELOG.md` — add a line under the v0.5.9 section (you'll create
  v0.5.9 in the `final` task) noting the migration. Skip until the
  `final` task creates the section.

**Test command:**
```bash
cargo test --release --test relay
cargo test --release --lib agent_card
```

**Acceptance:**
- Both file edits applied. `grep -rn "laulpogan/wire/ext" src/` returns 0
  matches.
- `cargo test --release` full suite green.
- The well-known-agent-card-a2a endpoint now returns
  `extensions[0].uri = "https://slancha.ai/wire/ext/v0.5"`. Verify with a
  unit test or smoke against a local relay:
  ```bash
  cargo run --release --bin wire -- relay-server --bind 127.0.0.1:18770 &
  PID=$!
  sleep 1
  # claim a handle, then query:
  # (or just hit the endpoint after a claim from a fresh home)
  kill $PID
  ```

**Non-goals:**
- Don't add a transition-window "accept both old and new URI" matcher.
  Wire is pre-traction; no external consumers depend on the old URI.
  Clean cut.
- Don't update `docs/MAC_HANDOFF_2026_05_12.md` or
  `docs/CLOUD_MIGRATION.md` references to the old URI — those are
  historical context, not live spec.

**Commit message:**
```
[a] migrate A2A extension URI to slancha.ai namespace

The extension URI is an opaque identifier matched by federation peers,
not a forwardable URL. Wire is the only consumer in the wild at v0.5,
so the migration is free. Targeting slancha.ai (the org domain) instead
of github.com/laulpogan decouples the namespace from any future repo
moves.

- src/relay_server.rs: extension URI in AgentCard
- src/pair_profile.rs: matcher prefix in A2A extension recognition

Replaces the overcautious "MUST stay forever" comment in both files
with a note that extension URIs are namespace identifiers and changing
them is a coordinated federation-spec bump.
```

---

## [b] Lifetime handle counter (split first-claims from re-claims)

**Why:** `RelayCounters.handle_claims_total` currently increments on
every `POST /v1/handle/claim` including re-claims by the same DID (which
happen on profile rotation / slot rotation). For the public `/stats`
endpoint, the more meaningful number is "how many distinct handles have
ever been claimed" — first-claims only. Re-claims tell us about
operator activity, not user growth.

**Files to touch:**
- `src/relay_server.rs`:
  - Add `handle_first_claims_total: AtomicU64` to `RelayCounters` struct.
  - Add same to `CountersSnapshot` struct + serde derive.
  - In `handle_claim` handler: increment `handle_claims_total` on every
    request (existing behavior); additionally increment
    `handle_first_claims_total` ONLY when the response status is
    "claimed" (i.e., the nick was not already in the handles directory).
    Don't increment on same-DID re-claims (status="re-claimed") or 409
    conflicts.
  - In `GET /stats` JSON response: surface
    `handle_first_claims_total` alongside `handle_claims_total`.
  - In `Relay::new` (counter-loading path): also load
    `handle_first_claims_total` from `counters.json`, default 0 for
    pre-v0.5.9 snapshots.
  - In `persist_counters`: include the new field in the serialized
    snapshot.

**Test command:**
```bash
cargo test --release --test relay
cargo test --release --lib
```

**Acceptance:**
- Add or extend a relay test that claims a nick once + verifies the
  counters JSON shows both `handle_claims_total = 1` and
  `handle_first_claims_total = 1`.
- Then runs a same-DID re-claim and verifies `handle_claims_total = 2`
  but `handle_first_claims_total = 1`.
- Smoke against a running local relay:
  ```bash
  curl http://127.0.0.1:18770/stats
  # expect both fields present in JSON
  ```

**Non-goals:**
- Don't add a per-handle history log — aggregate counter only.
- Don't worry about migration of `counters.json` from pre-v0.5.9
  installs. The default-0-if-missing handling in `Relay::new` covers it.

**Commit message:**
```
[b] /stats: split handle_first_claims_total from handle_claims_total

handle_claims_total now counts every POST /v1/handle/claim including
profile-rotation re-claims by the same DID. The more interesting public
metric for "user growth" is first-claims only. Adds the new counter
alongside the existing one (don't break the old number — both are
useful).

- src/relay_server.rs: RelayCounters + CountersSnapshot + handle_claim
  + /stats handler + persist/load paths
- tests/relay.rs: test asserting re-claim increments
  handle_claims_total but not handle_first_claims_total
```

---

## [c] R2: `time_sensitive_until` event field + `--deadline` CLI flag

**Why:** From `docs/INCIDENT_REPORT_2026_05_12_AGENT_ATTENTION_LAYER.md`
recommendation R2. Today's `priority: low|normal|high` is too coarse and
not bound to wall-clock deadlines. Adding an optional `time_sensitive_until`
RFC 3339 timestamp lets receivers distinguish "ack within 30 min for v8
smoke train" from "ack whenever." Receiver-side handling is advisory in
v0.5.9 — just surface the deadline in `wire tail` output. Future versions
can raise polling cadence or fire louder OS toast near the deadline.

**Files to touch:**
- `src/cli.rs`:
  - Add `--deadline <DURATION>` flag to the `Send` clap subcommand.
    Accept formats: `30m`, `2h`, `1d`, or an absolute RFC 3339 timestamp.
    Pass through to `cmd_send`.
  - In `cmd_send`: if `--deadline` was provided, parse it (now + duration
    OR explicit RFC 3339) and include `time_sensitive_until: "<iso>"` as
    a top-level field on the signed event JSON alongside `from`, `to`,
    `kind`, `body`, etc. Field is omitted entirely if no flag passed.
  - `cmd_tail` formatting (or wherever `wire tail` renders events):
    when `time_sensitive_until` is present on an event, display
    `⏰ deadline: <iso>` or `⏰ X min remaining` on the same line as the
    event header.
- `src/signing.rs` (or wherever the canonical event-id is computed): if
  the canonical-event-id calculation walks event fields, ensure
  `time_sensitive_until` is included so signature verification picks up
  any tampering of the deadline. Should be automatic if the canonical
  form is "all top-level fields excluding signature + event_id sorted
  by key" — verify by reading the canonical impl.
- `src/mcp.rs`: add `time_sensitive_until` as an optional param on
  `wire_send` MCP tool. Same parsing as the CLI flag.

**Test command:**
```bash
cargo test --release
```

**Acceptance:**
- `wire send peer kind body --deadline 30m` produces a delivered (or
  `--queue`d) event whose JSON contains a `time_sensitive_until` field
  exactly 30 minutes in the future, signed.
- `wire verify <event-with-deadline>.json` still verifies after the
  field is added (sig covers the new field).
- `wire tail peer --json` includes the field unchanged on the receiver
  side.
- `wire tail peer` (non-JSON) renders the deadline visibly.
- New tests in `tests/cli.rs` or `tests/e2e_bilateral.rs` covering at
  least: roundtrip with deadline preserved + verified, no-deadline path
  unchanged.

**Non-goals:**
- **DON'T implement receiver-side urgency behavior** (faster polling,
  louder toast). That's v0.6 work. R2 phase 1 is just: schema +
  send-side flag + tail display.
- Don't add a `--priority` flag (deprecating the field). The existing
  `priority` field on events stays unchanged.
- Don't add SLA / deadline-expiry semantics. The field is informational
  in v0.5.9.

**Commit message:**
```
[c] R2 v1: time_sensitive_until event field + --deadline CLI flag

From the agent-attention-layer incident (docs/INCIDENT_REPORT_...).
Adds an optional RFC 3339 deadline as a top-level event field; sender
opts in via `wire send --deadline 30m` (or absolute RFC 3339). Receiver
displays the deadline in wire tail output.

Schema is forward-compatible: events without time_sensitive_until parse
unchanged. Sig verification covers the new field via the existing
canonical-form computation.

Deferred to v0.6: receiver-side urgency behavior (faster polling near
deadline, escalated OS toast). v0.5.9 surfaces the deadline; behavior
stays advisory.

- src/cli.rs: --deadline flag + duration/RFC3339 parser + cmd_send
  passthrough + tail display
- src/mcp.rs: wire_send MCP tool param parity
- src/signing.rs: confirm canonical-form covers new field (likely no
  change needed; verify and document)
- tests: roundtrip with deadline, sig verify, no-deadline path
```

---

## [d] R3: responder-health events + relay slot_state extension

**Why:** From R3. When an operator's auto-responder daemon breaks
(OAuth expired, claude subprocess dead, rate-limited), peers see
"silent" indistinguishably from "healthy but no reply needed." Adding
a responder-health event the operator can emit, surfaced via the
existing `/v1/slot/:slot_id/state` endpoint, gives senders a way to
diagnose before adding more time-sensitive asks.

**Files to touch:**
- `src/relay_server.rs`:
  - Extend `Inner` struct with `responder_health: HashMap<String,
    ResponderHealthRecord>` keyed by slot_id.
  - Define `ResponderHealthRecord { status, reason, last_success_at,
    set_at }`. `status` is an enum-ish string: "online", "offline",
    "oauth_locked", "rate_limited", "degraded". `reason` is optional
    free-text. `last_success_at` + `set_at` are RFC 3339.
  - Add `POST /v1/slot/:slot_id/responder-health` handler, auth'd by
    slot_token (same bearer pattern as list_events). Body is the
    `ResponderHealthRecord` JSON. Stores in-memory in Inner; persists
    to `<state_dir>/responder-health/<slot_id>.json` on each set.
  - Extend `GET /v1/slot/:slot_id/state` JSON response: include
    `responder_health` field with the most recent record or `null` if
    none set.
  - On startup in `Relay::new`: load any persisted records from disk.
- `src/cli.rs`:
  - Add `wire responder set <status> [--reason <text>]` subcommand.
    Reads relay-state for own slot_id + slot_token, POSTs the record
    to the relay's `/v1/slot/:slot_id/responder-health` endpoint.
  - `wire responder get [<peer>]` — read state from relay (own or
    peer's), print formatted.
  - Both with `--json` flag for machine output.
- `src/relay_client.rs`:
  - Add `responder_health_set(slot_id, slot_token, record)` and
    `responder_health_get(slot_id, slot_token)` methods (or extend
    the existing `slot_state` method to surface the new field — which
    it should, automatically, if you keep it on slot_state).

**Test command:**
```bash
cargo test --release --test relay
cargo test --release --test cli
```

**Acceptance:**
- POST /v1/slot/:slot_id/responder-health with a valid bearer + body
  returns 200; GET /v1/slot/:slot_id/state then shows the record.
- Wrong bearer returns 403.
- CLI roundtrip: set with `wire responder set offline --reason "OAuth
  expired"`, retrieve with `wire responder get`. Matches.
- Persistence: relay restart preserves the most recent record.
- New tests cover both success + auth-fail cases for the endpoint and
  CLI roundtrip.

**Non-goals:**
- **Don't auto-emit responder-health events from any existing daemon.**
  The CLI command is operator-driven. Auto-emission is v0.6 work.
- Don't define a wire event kind for this (kind=1500 was floated; not
  using it for v0.5.9). The endpoint + state are out-of-band relative
  to the event stream — meta-information about the slot, not events
  flowing through it.
- Don't add a global "responders dashboard" — per-slot only.

**Commit message:**
```
[d] R3: responder-health endpoint + CLI

From the agent-attention-layer incident. When the operator's auto-
responder daemon breaks (OAuth, rate-limit, etc.), peers see "silent"
indistinguishably from "healthy + no reply needed." This commit gives
the operator a way to publish their responder's health and gives
peers a way to read it.

- POST /v1/slot/:slot_id/responder-health — auth'd, persisted, per-slot
- GET /v1/slot/:slot_id/state — extended with responder_health field
- wire responder set <status> [--reason <text>] CLI
- wire responder get [<peer>] CLI
- relay_client: set + get convenience methods

Out of band of the event stream. Slot owner emits via CLI, peer reads
via slot_state. Auto-emission from a daemon is deferred to v0.6.
```

---

## [e] R5: `wire status --peer <handle>` 3-layer health (depends on d)

**Why:** From R5. The incident report calls for distinguishing three
health dimensions: transport (relay reachable), agent attention (last
pull observed), auto-responder (last responder-health event). v0.5.9
already has the data for all three; this task just exposes it via a
single CLI command.

**Files to touch:**
- `src/cli.rs`:
  - Extend the existing `wire status` subcommand with a new
    `--peer <handle>` flag. When passed, look up the peer in relay-state,
    fetch their slot_state from the relay (using the slot_token we hold
    from pair), and render three rows:
    ```
    📞 transport      ✅ relay reachable (<latency>ms)
    👂 attention      ✅ last pull 23s ago
                      (or:  ⚠ last pull 18m ago — they may be away
                       or:  ❌ never pulled since our last reset)
    🤖 auto-responder ✅ online   (last_success: 2026-05-15T20:14Z)
                      (or:  ⚠ degraded — rate_limited
                       or:  ❌ offline — OAuth expired)
                      (or:  — not reported)
    ```
  - Without `--peer`, `wire status` behaves as before (own state).
  - `--json` output: structured `{transport: {...}, attention: {...},
    responder: {...}}`.

**Test command:**
```bash
cargo test --release --test cli
```

**Acceptance:**
- `wire status --peer <handle>` produces the 3-row output for a paired
  peer.
- `wire status --peer <unknown-handle>` errors cleanly.
- `--json` mode parses to the documented schema.
- New tests cover at least: paired peer with no responder-health
  reported (responder = "—"), peer with stale attention (>5 min), peer
  with offline responder-health.

**Non-goals:**
- Don't probe ALL paired peers at once (`wire status` with no `--peer`
  stays scoped to self).
- Don't surface raw slot_id / slot_token in human output.

**Commit message:**
```
[e] R5: wire status --peer <handle> shows 3-layer health

Single CLI surface for transport / attention / auto-responder. Builds
on R4 (slot pull tracking) and R3 (responder-health endpoint). Lets
the operator diagnose "is this peer reachable, awake, and answering?"
in one query.

- src/cli.rs: --peer flag + 3-row formatter + --json schema
- tests: paired peer happy path, no-responder-reported, stale attention
```

---

## [g] Directory endpoint + landing phone-book UI

**Why:** Driven by the Reddit comment thread. Today wire's discovery is
single-handle resolve (`/.well-known/wire/agent?handle=X`). Adding a
listing endpoint `GET /v1/handles` gives a federated phone book:
every relay publishes its own roster, no global registry. Pairs with a
phone-book UI on the landing page.

**Files to touch:**
- `src/relay_server.rs`:
  - Add `GET /v1/handles` handler. Query params: `?cursor=<nick>` for
    pagination (after-cursor exclusive), `?limit=N` default 100 max 500,
    `?vibe=<tag>` optional filter (case-insensitive match against any
    element of the profile's `vibe` array).
  - Response shape: `{handles: [{nick, did, profile: {emoji, motto,
    vibe, pronouns, now}, claimed_at}, ...], next_cursor: <nick> | null}`.
    Profile fields are pulled from the stored card; omit private/
    operator-only fields.
  - Respect a per-handle `listed: false` opt-out: if `card.profile.listed`
    is `false`, the handle is excluded from the listing. Default = listed.
  - Auth: none — public endpoint. Same posture as `/stats`.
- `src/pair_profile.rs`:
  - Add `listed` to `PROFILE_FIELDS` so `wire profile set listed
    false` works.
- `landing/index.html`:
  - Add a "Now Ringing" / phone-book section that fetches
    `/v1/handles?limit=20` on page load, renders each handle as a
    one-row entry (emoji, nick, motto, vibe). Group by first vibe tag
    if present. Match the existing typewriter / parchment aesthetic.
  - Show a "more →" link to a future paginated browser; for v0.5.9
    just the first 20.
  - JS should be vanilla, no framework. Use `fetch()` + DOM updates.
  - Failure mode: if the endpoint 404s or errors, hide the section
    silently rather than show a broken state.

**Test command:**
```bash
cargo test --release --test relay
cargo test --release --lib pair_profile
# manual:
cargo run --release --bin wire -- relay-server --bind 127.0.0.1:18770 &
# claim a couple of handles against it, set profiles, then:
curl http://127.0.0.1:18770/v1/handles
curl 'http://127.0.0.1:18770/v1/handles?vibe=nocturnal'
```

**Acceptance:**
- Endpoint returns the correct shape with pagination working
  (`cursor=` resumes after the given nick).
- Vibe filter is case-insensitive and matches any element of the array.
- `wire profile set listed false` opts a handle out of the listing.
- Landing fetches + renders without breaking the existing layout.
- New tests cover endpoint + listed-false-opt-out + pagination + vibe
  filter.

**Non-goals:**
- Don't add full-text search across motto / now. Only vibe filter for
  v0.5.9.
- Don't add a separate `/v1/handles/<nick>` route — the existing
  `/.well-known/wire/agent?handle=<nick>` is the single-handle path.
- Don't paginate the landing UI; show first 20 and link "more".

**Commit message:**
```
[g] /v1/handles directory endpoint + landing phone-book UI

Adds a paginated listing of claimed handles on a relay, filterable
by vibe. Federated phone-book pattern — every relay publishes its
own roster, no global registry. Pairs with a "Now Ringing" section
on the landing page that fetches + renders 20 handles.

Privacy: per-handle opt-out via `wire profile set listed false`.
Default is listed=true.

- src/relay_server.rs: GET /v1/handles handler + pagination + vibe
  filter + listed opt-out
- src/pair_profile.rs: listed in PROFILE_FIELDS
- landing/index.html: phone-book section, vanilla-JS fetch + render
- tests: pagination, vibe filter, listed-false opt-out
```

---

## [f] `docs/CONSENT_DESIGN.md` — spec-shape design doc

**Why:** Reddit-driven. The cross-machine consent boundary is the
unsolved spec-shape question for agent comms. Wire doesn't solve it
in v0.5.9, but capturing the design space + wire's stance now means
future contributors (and the original Reddit commenter) know what
wire intentionally doesn't do and why.

**This is the one task in this batch that's docs-only and judgment-
heavy.** Codex can draft from the outline below; the operator will
review + edit for tone. Don't try to "solve" consent in this doc —
document the trade-space, name where wire sits, and flag what would
change wire's stance.

**Files to touch:**
- `docs/CONSENT_DESIGN.md` (new) — covers:
  - **Problem statement**: MCP assumes consent boundary at the host
    (human-in-the-loop). Cross-machine handoff breaks that. Second-hop
    agent needs either (a) to ask its human (UX hell), (b) a pre-signed
    delegation token, or (c) a receiver-side policy.
  - **Three design axes**: transport, identity, consent. Wire is
    explicitly the transport layer; identity and consent are separable
    concerns.
  - **Two consent patterns**:
    - Macaroon-style scoped tokens (sender-side: operator pre-signs
      `{agent_a may send to agent_b, kind=X, TTL=24h, auto-execute up
      to 5/hr}`, token rides in envelope, receiver verifies).
    - Receiver-side policy (sender includes `requested_authority` hint,
      receiver consults local `policy.json`, decides auto/ask/deny).
  - **Wire's v0.5 stance**: receiver-side policy. Why: keeps relay
    ciphertext-only (security property worth keeping), keeps the
    protocol dumb, doesn't bake consent into the wire envelope.
  - **What changes wire's stance**: if cross-org delegation becomes
    common-enough to need a uniform format, macaroon path may win.
    Trigger: more than one external project asking for it.
  - **What v0.5.9 ships**: the `requested_authority` advisory field
    on events (sender-side hint only). No receiver-side policy
    enforcement yet — that's v0.6.

**Test command:**
None (docs only). But run `cargo build --release` to make sure no
inadvertent code changes leaked into other files.

**Acceptance:**
- File exists at `docs/CONSENT_DESIGN.md`.
- Covers the bullets above.
- Reads as a design doc, not advocacy or marketing.
- Cross-links to `docs/INCIDENT_REPORT_2026_05_12_AGENT_ATTENTION_LAYER.md`
  (where the consent question first surfaced as a corollary of R2-R5)
  and to the Reddit thread URL if you have it (operator may know).
- Doesn't claim wire solves consent. The doc's job is to name the
  problem and document wire's position.

**Non-goals:**
- **Don't implement anything.** This task is the doc only. If task
  [c] (R2 `time_sensitive_until`) is already shipped, mention it as
  an example of "what protocol-level advisory metadata looks like" —
  but don't add a `requested_authority` field as part of this commit.
- Don't survey every consent system ever (UCAN, ZCAP, OAuth scopes,
  capabilities). Mention macaroons + receiver-side policy as the two
  patterns wire ping-pongs between; keep the rest out.

**Commit message:**
```
[f] docs: CONSENT_DESIGN — wire's stance on cross-machine handoff

Captures the design space surfaced by the Reddit thread on agent-comms
spec gaps. Wire is transport-only by design; consent + identity are
separable concerns. v0.5.x lands on receiver-side policy as the v0.x
direction (keeps relay ciphertext-only, keeps protocol dumb).
Macaroon-style scoped tokens are the alternative we'd ship if cross-
org delegation patterns harden.

This is a design doc, not a roadmap. Captures intent + trade-space,
doesn't bind future versions.
```

---

## [h] Macaroon-style scoped delegation tokens (speculative)

**Why:** Long-term direction from the consent design (task f). NOT
production-bound — this task is research-grade scaffolding so we have
a starting point if v0.6 commits to the macaroon path.

**Caveats:**
- **This is speculative.** Codex should attempt it but if blocked,
  ship a partial commit + write up the blocker in `BLOCKED.md` and
  move on. Don't sink half a day on it at the expense of [a]-[g].
- **Don't merge into the relay or CLI's main paths.** Implementation
  goes in a new `src/macaroon.rs` module + `tests/macaroon.rs`. No
  integration with `wire send` or relay handlers yet.
- **Crate choice**: prefer an existing Rust macaroon crate (e.g.,
  `libmacaroons-rs` or `branca` for a simpler token format if
  macaroon impls are stale). If no clean dep exists, write a minimal
  HMAC-chain prototype based on the original macaroon paper (Stanford
  2014). The prototype is just to prove the design fits wire's event
  envelope.

**Files to touch:**
- `src/macaroon.rs` (new):
  - `Macaroon` struct: `{root_key_id, identifier, caveats:
    Vec<Caveat>, signature}`.
  - `Caveat` enum: `Sender(Did)`, `Recipient(Did)`, `Kind(u32)`,
    `Expiry(rfc3339)`, `MaxRate(u32, Duration)`.
  - `mint(root_key, identifier, caveats) -> Macaroon`.
  - `verify(macaroon, root_key, context) -> Result<()>`. `context`
    is what the receiver knows at verify-time (sender did, recipient
    did, event kind, current time).
  - `serialize` / `deserialize` to/from base64.
- `tests/macaroon.rs` (new):
  - mint + verify happy path
  - expiry caveat rejects after TTL
  - sender caveat rejects mismatched sender
  - tampering rejects (modify signature)
- `Cargo.toml`: add dep if using a crate.
- Add a 1-paragraph section to `CONSENT_DESIGN.md` (already created
  in task f) pointing at the new module as the speculative
  implementation, with a "not used in production yet" disclaimer.

**Test command:**
```bash
cargo test --release --test macaroon
```

**Acceptance:**
- Module compiles. Tests pass.
- No new dependency added without justification (prefer write-it-
  ourselves prototype over heavy/abandoned crates).
- CONSENT_DESIGN.md updated with the pointer + disclaimer.

**Non-goals:**
- **Don't wire macaroons into the relay or CLI.** Module is stand-
  alone scaffolding.
- Don't ship macaroon-in-envelope on wire events. That's v0.6+.

**If blocked:**
- Add to `BLOCKED.md` at repo root: what you tried, what didn't work,
  what info would help. Skip and move on.

**Commit message:**
```
[h] speculative: src/macaroon.rs scaffolding (not production-bound)

Prototype macaroon-style scoped token implementation for future
consent-layer work. Lives in its own module, not wired into the relay
or CLI. Provides mint/verify/serialize + 4 unit tests. Captures the
shape wire would ship if v0.6+ commits to the macaroon path described
in CONSENT_DESIGN.md.

Marked speculative: this is research-grade. The relay still treats
events as ciphertext-only + sigs; consent is still receiver-policy
in v0.5.x.
```

---

## [final] Version bump + CHANGELOG + branch sanity check

**Why:** After all 8 tasks are committed, wrap with a single commit
that bumps the version, fills in the CHANGELOG section, and runs the
final full-suite check.

**Files to touch:**
- `Cargo.toml`: version `0.5.8` → `0.5.9`.
- `Cargo.lock`: regenerate via `cargo build --release` (will update
  the wire workspace entry).
- `tests/cli.rs`: version assertion `"0.5.8"` → `"0.5.9"`.
- `CHANGELOG.md`: new section under v0.5 line:
  ```
  ### v0.5.9 — directory + R2/R3/R5 + consent design + cleanup

  ...
  ```
  Pull a short paragraph per task ([a] through [h]) from the commit
  messages. Lead with the most operator-visible (R2/R3/R5 + directory),
  then the cleanups ([a] [b]), then docs ([f]) + speculative ([h]).
- `README.md`: update the `**Status:**` line to mention v0.5.9 +
  highlight the directory + 3-layer health additions.

**Test command:**
```bash
cargo test --release       # full suite green
cargo fmt --all --check
cargo clippy --release
cargo run --release --bin wire -- --version   # → wire 0.5.9
```

**Acceptance:**
- All three checks pass.
- `wire --version` reports 0.5.9.
- CHANGELOG accurately summarizes the batch.
- Branch is rebased on latest main (in case `main` advanced during
  the batch).

**Push:**
```bash
git push -u origin codex/v0.5.9-batch
```

Don't tag v0.5.9 or merge to main. Operator reviews + tags + merges.

**Commit message:**
```
[final] v0.5.9 bump + CHANGELOG + status

Bumps Cargo.toml, tests/cli.rs version assertion, CHANGELOG.md, and
README status line. All 8 task commits ([a] through [h]) on this
branch combine into the v0.5.9 release. Operator reviews the branch
and tags + merges to main.
```

---

## Definition of done for the branch

- 9 commits on `codex/v0.5.9-batch`: one per task [a]-[h] plus [final].
- `cargo test --release` green (modulo the pre-existing
  e2e_detached_pair local-only flake; CI verifies clean container).
- `cargo fmt --all --check` clean.
- `cargo clippy --release` no errors.
- `wire --version` → `wire 0.5.9`.
- `CHANGELOG.md` v0.5.9 section is accurate + concise.
- `BLOCKED.md` exists ONLY if at least one task was blocked.
- Branch pushed to origin.

## If you finish early

Run a fresh smoke against a local relay covering:
1. `wire claim alice@local-relay`
2. `wire add bob@local-relay` (set up second home)
3. `wire send bob decision "hi" --deadline 30m` ([c])
4. `wire responder set offline --reason test` ([d])
5. `wire status --peer bob` ([e])
6. `curl http://127.0.0.1:18770/v1/handles` ([g])
7. `curl http://127.0.0.1:18770/.well-known/agent-card.json?handle=alice | jq .extensions[0].uri` ([a])
8. `curl http://127.0.0.1:18770/stats | jq .handle_first_claims_total` ([b])

If any of those return unexpected results, capture the actual vs
expected output in `BLOCKED.md` and report back. Don't try to fix
forward without confirming the design.

## Out of scope for this batch

These were considered and explicitly deferred:
- **Wire-client default-relay update** (followup queued in
  SESSION_LOG_2026_05_12). Already done since v0.5.2 (`DEFAULT_RELAY
  = "https://wireup.net"`). No-op.
- **CF Pages project cleanup** (operator-side, CF dashboard click).
- **Spark wire-public-relay-state pruning** (operator-side, calendar
  task).
- **R2 receiver-side urgency behavior** (deferred to v0.6).
- **R3 daemon auto-emission of responder-health** (deferred to v0.6).
- **Wire `--require-sas` flag for opt-back-into-SPAKE2** — already
  exists from earlier work.
- **Federation-spec proper RFC for the wire A2A extension** — wait
  until external A2A consumers exist.

If Codex sees a tempting refactor that touches more than one task's
files, **don't do it.** Atomic commits per task is the goal. Refactor
in a separate v0.5.10 if it's genuinely useful.
