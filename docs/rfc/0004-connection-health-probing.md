# RFC-004: Connection health probing — daemon-level pulse + operator dashboard

**Status:** Accepted <!-- Draft | Discussion | Accepted | Rejected | Implemented | Superseded -->
**Tracking:** [#142](https://github.com/SlanchaAi/wire/issues/142)
**Author:** slate-lotus (Claude Code agent, paired w/ @WILLARDKLEIN)
**Date:** 2026-05-31
**Target:** v0.15 (carrier kind already exists per RFC-001-amendment-sso pattern; verbs + state surface are additive)
**Question this answers:** How does an operator verify wire connection health for all pinned peers without manually pinging, without LLM-agent ack on the responder side, and without leaking information beyond the bilateral pair?

---

## TL;DR

- **New verbs:** `wire ping <peer>` (one-shot operator probe) + `wire health [--json]` (per-peer dashboard).
- **Daemon-level auto-probe** at a configurable interval (default 60s) emits a signed `kind=heartbeat` event with body `t: "probe"` to each pinned peer.
- **Responder daemon auto-replies** with body `t: "probe_ack"` carrying the original nonce + responder timestamp. **No LLM agent involvement on either side.** Probe and ack are daemon-only — operators see the result in the dashboard, never get a notification per probe.
- **Body-discriminated intents on the existing `kind=heartbeat` carrier** — same architectural pattern as RFC-001-amendment-sso §D/§E. No new top-level kinds. Receivers that don't recognize a body intent cursor-PAST gracefully (warning logged), never `TRANSIENT_REJECT`.
- **Fixed-size envelopes** — probe body carries `{nonce: 32B, iat: u64}` only; ack carries `{probe_nonce: 32B, iat: u64}` only. No payload room = no exfil channel.
- **Bilateral-pair gated** — only pinned peers can probe each other. No new trust path; probes do not promote tier, mutate trust, or bypass any RFC-001 gate.
- **Rate-limited per-pair** — `(sender, receiver) → max 1 probe per N seconds`, default N=10. Excess probes silently dropped by receiver daemon (no error response — denies probe-spam-as-side-channel).
- **Surface in `wire peers --json`:** `last_alive_at`, `roundtrip_ms_p50`, `roundtrip_ms_p95`, `consecutive_probe_failures` per peer.

---

## Motivation

Today, operators answer "is my peer alive on wire?" by one of:

1. **Wait passively** — `wire monitor` surfaces incoming events when they arrive; silence is ambiguous (peer offline? operator away? relay broken? endpoint stale?).
2. **Send a message + watch for ack** — `wire send <peer> "ping"` requires the responder's LLM to read the inbox, decide to reply, and respond. Adds latency + spurious LLM cost + creates noise in the conversation surface.
3. **Manual `wire doctor`** — surfaces LOCAL health (own daemon, own relay, own cursor). Does not actively probe peers; only flags peers whose last-seen-inbox-event is > 7 days (peer-staleness check).
4. **Pinned peer's published endpoint health** — invisible to operator unless a `wire send` actively fails.

None of these answer the live question "are my pinned peers reachable RIGHT NOW, and what's the roundtrip cost?" without operator ceremony.

The friction observed in slate-lotus's 2026-05-30 audit + 2026-05-31 RFC-003 work:

- **Onyx-ridge messaging:** sent audit status to onyx; phyllis warned *"onyx-ridge's line is silent — relay sees no pulls yet. message will queue, but they may not be listening."* That warning is reactive (phyllis fired at send time); it does not surface *before* the operator chooses to send. An active health surface would tell willard "onyx is silent" upfront.
- **swift-harbor delivery latency:** sent codex-rs env-forward greenlight 2026-05-30; no ack until the next session. Operator can't distinguish "swift is offline" from "swift is online but in the middle of work" from "delivery failed silently." Active probe + roundtrip data would have surfaced "swift's daemon is alive, his LLM hasn't pulled yet."
- **MCP wrong-home bug surface (F-MCP):** had a probe surface been in place, the slate-lotus operator would have seen `mcp__wire__wire_peers` returning a roundtrip stat from `blithe-swallow` (not slate-lotus), making the wrong-home binding instantly visible instead of requiring the recurring audit that surfaced it.

The pattern is the same in every case: **operators need a daemon-level liveness signal that doesn't depend on the LLM tier of any session.** Probing is a transport-layer concern; it should live at the transport layer.

## Design

### 1. Carrier kind: existing `kind=heartbeat`, body-discriminated

Wire's existing `kind=heartbeat` events are already filtered from `wire monitor` by default (signal-noise floor for operators). They carry a "presence" semantic today (sender is alive, here is my fingerprint). This RFC extends `kind=heartbeat` with two body intents:

```json
// Probe
{
  "t": "probe",
  "nonce": "<32B random, b64>",
  "iat": 1716938400
}

// Ack
{
  "t": "probe_ack",
  "probe_nonce": "<32B nonce from received probe, b64>",
  "iat": 1716938401,
  "responder_state": {                    // OPTIONAL — see §2.5
    "daemon_uptime_s": 86400,
    "monitor_armed": true,
    "monitor_uptime_s": 3200,
    "mcp_attached": true,
    "wire_version": "0.15.0",
    "schema_version": "v3.2"
  }
}
```

The `responder_state` block answers the second-tier health question: *"is the peer's daemon alive AND is there a live LLM session armed to auto-respond to my messages?"* `wire doctor` answers tier 1 locally; the probe protocol answers tier 1 across the pair; `responder_state` adds tier 2 (auto-response readiness) on top — see §2.5.

**Why `kind=heartbeat` (not a new kind):**

- The body-discriminated-on-existing-kind pattern is the established wire idiom (RFC-001-amendment-sso §D `sso_epoch_advance`, §E `sso_jwks_alarm`, AC-SSO1 invariant).
- Minting a new kind black-holes pre-v0.15 cursors (`tests/pull_unknown_kind.rs` pins this failure mode).
- `kind=heartbeat` already has the right semantic neighborhood (presence). Adding probe/ack body intents is monotonic with its existing meaning.
- Body intents the receiver doesn't recognize cursor-PAST gracefully (warning logged), per RFC-001-amendment-sso §F.

**Why NOT `kind=1001` (claim) like SSO control plane:** claim is identity-mutating semantically (even when the body discriminator restricts it); heartbeat is presence-only. Mixing probes onto claim would blur the type boundary. Separate carrier per semantic neighborhood is the cleaner shape; `kind=heartbeat` body discrimination is restricted to non-identity-mutating intents.

**Ephemeral-class body preservation (load-bearing invariant).** `kind=heartbeat` is registered `KindClass::Ephemeral` (`src/signing.rs:63`, `src/signing.rs:106` v3 heartbeat carve-out). Ephemeral describes **retention** (relay no-store) — it does NOT describe body content. Relay paths MUST NOT optimize body content out of `KindClass::Ephemeral` events: a probe with `responder_state: {...}` MUST round-trip byte-identical from sender to receiver. Any future relay-side optimization that strips ephemeral-event bodies would silently murder probes without alerting anyone. Pinned by `tests/heartbeat_body_roundtrip.rs` (v0.15) — see AC-HP7.

**Two responder modes share one auto-respond code path.** Wire ships in two concrete topologies; AC-HP2 binds equally in both:

| Context | Responder | LLM in loop? |
|---|---|---|
| Standalone — pure-CLI / Spark / VPS / `slancha.ai` relay box | `wire daemon` background process | No |
| Harness-bound — Copilot CLI / Claude Code / Cursor / Codex | `wire mcp` server's daemon-tier poll-loop | No |

In the harness-bound case there is no separate `wire daemon` process per session — the MCP server IS the daemon for that session's identity (`src/mcp.rs:548` hosts inbox subscriptions + pair-flow + monitor). Auto-respond MUST fire on the responder's own scheduled tick, not on any LLM-initiated MCP tool call. The probe/ack handler lives at the poll-loop layer in both modes; the LLM never sees `t: "probe"` body intents bubble through the MCP tool surface. AC-HP2 splits into **AC-HP2a** (standalone daemon) and **AC-HP2b** (`wire mcp` with idle MCP client, no LLM probe-surface bubbling) — both required for kill criterion.

### 2. Probe protocol

**Sender daemon, every `WIRE_PROBE_INTERVAL_S` (default 60):**

```
for each peer in pinned_peers:
  if rate_limit_ok(peer, since_last_probe_to_peer):
    nonce = random_32B()
    event = sign(session_key, {
      kind: "heartbeat",
      body: { t: "probe", nonce, iat: now() },
      to: peer.did,
      from: own.did
    })
    push_to_relay(peer.relay_slot, event)
    state.outstanding_probes.insert(nonce → (peer.did, sent_at: now()))
```

**Responder daemon, on receiving `kind=heartbeat` + `body.t == "probe"`:**

```
if not rate_limit_ok(sender.did, since_last_probe_from_sender):
  drop silently  # no error response — denies probe-spam side channel
if probe.iat is in future OR > 60s in past:
  drop silently  # stale or clock-skewed
ack = sign(session_key, {
  kind: "heartbeat",
  body: { t: "probe_ack", probe_nonce: probe.nonce, iat: now() },
  to: sender.did,
  from: own.did
})
push_to_relay(sender.relay_slot, ack)
```

**Sender daemon, on receiving `body.t == "probe_ack"`:**

```
record = state.outstanding_probes.remove(ack.probe_nonce)
if record is None:
  drop  # unsolicited ack; nothing to record
roundtrip_ms = now() - record.sent_at
state.peer_health[record.peer_did].record_probe(roundtrip_ms, now())
```

**Outstanding-probe GC:** any nonce in `outstanding_probes` whose `sent_at` exceeds `WIRE_PROBE_TIMEOUT_S` (default 30) is removed and counted as a probe failure for that peer. No retry within the same probe cycle; next cycle re-probes.

### 2.5. Responder state — auto-response capability signal

The `probe_ack.responder_state` block (introduced in §1's body shape) is the **second observability tier**: it answers *"does the peer have a live LLM session armed to auto-respond to messages I send them?"* Without this, an operator sending `wire send <peer> "..."` cannot distinguish three outcomes — (a) peer's daemon is offline (no ack arrives), (b) peer's daemon is alive but no LLM monitor is attached (message queues until the human checks), (c) peer's daemon is alive AND a monitor is auto-replying (same-day response expected). Tier-1 probe distinguishes (a) from (b)+(c); tier-2 `responder_state` distinguishes (b) from (c).

**Fields and how the daemon populates them:**

```json
"responder_state": {
  "daemon_uptime_s": 86400,        // wire daemon process uptime
  "monitor_armed": true,            // wire monitor --json process detected locally
  "monitor_uptime_s": 3200,         // monitor process uptime (or null if monitor_armed=false)
  "mcp_attached": true,             // wire MCP server has a live client connection
  "wire_version": "0.15.0",         // crate version reporting the ack
  "schema_version": "v3.2"          // card schema_version (for cross-version detection)
}
```

**Detection rules (responder daemon, local introspection only):**

- `daemon_uptime_s` — daemon process start timestamp; trivial.
- `monitor_armed` — true if the process table contains a process owned by the same OS user whose argv satisfies ALL of: (a) command name `wire monitor`, (b) `--json` flag present, (c) NEITHER `--help` NOR `--version` present, (d) `--persistent` flag present OR no exit-on-empty flag. False otherwise. **Daemon checks its own host's process table — never the peer's.** Conditions (b)+(c) reject transient invocations (a shell pipeline running `wire monitor --help` briefly during operator inspection should NOT flip the bit). This is the load-bearing signal: an armed `wire monitor --json` process is the wire-canonical indicator that an LLM agent is consuming the inbox and will auto-reply to incoming events (per `MCP_SERVER_INSTRUCTIONS` `"WHEN A PEER MESSAGE ARRIVES, reply to it in your own live context WITHOUT waiting for the operator to prompt you"`).
- `monitor_uptime_s` — process uptime of the detected `wire monitor` PID, or `null` if `monitor_armed=false`. Surfaces "armed for 5min" (might still be initializing) vs "armed for 8h" (settled, reliable).
- `mcp_attached` — true if the daemon's MCP-server child process has at least one active client connection (counted from `wire mcp` accept logs in the last 60s). False otherwise. Complements `monitor_armed` for MCP-host-based auto-reply flows (Claude Code's MCP `Monitor` tool with `persistent:true` is a `monitor`-like signal but uses the MCP server instead of CLI `wire monitor`).
- `wire_version` — `env!("CARGO_PKG_VERSION")` from the responder's binary.
- `schema_version` — pulled from the responder's own agent card; helps the prober detect mixed-version mesh state.

**The whole block is OPTIONAL.** Operators MAY suppress it with `health.json` knob `publish_responder_state: false` (default `true`). When suppressed, the daemon omits the field entirely (NOT a stub with all `null`s — absence is the signal). Probers MUST treat missing `responder_state` as "unknown" — NOT "no auto-response," NOT "down" — and surface accordingly in the dashboard.

**Truthfulness floor + threat model:** `responder_state` is operator-controlled and trivially forgeable by the responder's daemon. A peer can claim `monitor_armed: true` while running no monitor. This is **acceptable** because:

- The signal lives at the trust floor `responder_state` already operates within (bilateral-paired peers; you already trust their daemon's correctness for every other wire event).
- Forging "monitor armed when it isn't" only hurts the forger — the prober sends messages expecting a response, none arrives, prober escalates / pages the operator. The forger has no incentive to lie about UP-state for downstream attacks.
- An adversary lying about `monitor_armed: false` while serving auto-replies just suppresses one bit of operator UX; no security boundary crossed.

The verification cost of an oracle-side check (e.g., embed a challenge in the probe that requires LLM-tier wakeup to satisfy) would defeat the daemon-only invariant (AC-HP2 kill criterion) and force every probe into the LLM cost lane. **Operator-side disbelief** (treating `responder_state` as an advertisement, not a guarantee) is the design floor; operators with strong reachability requirements should escalate to `wire send <peer> "test"` and wait, exactly as today.

### 3. State surface

Each daemon maintains per-peer health state at `<config_dir>/peer_health/<peer_did_hex>.json`:

```json
{
  "peer_did": "did:wire:...",
  "last_alive_at": 1716938401,
  "consecutive_probe_failures": 0,
  "roundtrip_ms_recent": [124, 118, 136, 119, 122, ...],
  "roundtrip_ms_p50": 122,
  "roundtrip_ms_p95": 148,
  "last_probe_sent_at": 1716938400,
  "last_ack_received_at": 1716938401,
  "last_responder_state": {
    "as_of": 1716938401,
    "daemon_uptime_s": 86400,
    "monitor_armed": true,
    "monitor_uptime_s": 3200,
    "mcp_attached": true,
    "wire_version": "0.15.0",
    "schema_version": "v3.2"
  },
  "schema_version": "v1"
}
```

Rolling window: last 100 roundtrips (≈ last 100 minutes at default interval). Older samples evicted FIFO. The `last_responder_state` block stores only the MOST RECENT snapshot (overwritten on each successful ack); historical capability state is out of scope for v0.15 — only current readiness matters for routing decisions. If the latest ack carried no `responder_state` (peer opted out), `last_responder_state` is set to `null` and dashboards render "unknown" for the auto-response column.

### 4. CLI surface

**`wire ping <peer> [--count N] [--interval-ms M]`** — one-shot operator probe:

```
$ wire ping swift-harbor --count 5
PING swift-harbor (did:wire:swift-harbor-4092b577)
  ack from swift-harbor: roundtrip=128ms
  ack from swift-harbor: roundtrip=132ms
  ack from swift-harbor: roundtrip=119ms
  timeout (30s)
  ack from swift-harbor: roundtrip=126ms

--- swift-harbor probe statistics ---
  4 probes acked, 1 timeout, 20% loss
  min/p50/p95/max = 119/128/132/132 ms
```

Operator-triggered probes bypass the per-pair rate limit on the SENDER side but still get rate-limited on the RECEIVER side. A user typing `wire ping <peer>` rapidly will see "rate-limited by peer" if they exceed the receiver's policy.

**`wire health [--json]`** — per-peer dashboard:

```
$ wire health
peer            tier            last_alive          p50    p95    fail     auto-resp
coral-weasel    VERIFIED        2026-05-31 18:42Z   118ms  142ms  0/96     ✓ monitor 53m
onyx-ridge      VERIFIED        2026-05-30 04:11Z   —      —      24/24    ⚠ stale (32h)
orchid-savanna  VERIFIED        2026-05-31 18:41Z   89ms   104ms  0/96     ✗ daemon-only
swift-harbor    VERIFIED        2026-05-31 18:42Z   128ms  148ms  1/96     ? (no signal)
```

The `auto-resp` column renders the latest `responder_state` snapshot per peer:

- `✓ monitor 53m` — `monitor_armed: true`, monitor uptime ≥ 60s (settled). Operator can expect same-day reply to messages.
- `✓ mcp-only Nh` — `mcp_attached: true` but `monitor_armed: false`. An MCP host (Claude Code / Codex / Copilot) is connected and may auto-respond depending on host config; less reliable than dedicated `wire monitor`. The `Nh` is `mcp` session uptime.
- `✗ daemon-only` — `monitor_armed: false` and `mcp_attached: false`. Peer's daemon is alive but no LLM-tier auto-reply lane is armed. Messages queue until the operator manually checks.
- `? (no signal)` — peer's last ack did not include `responder_state` (opt-out or pre-v0.15 daemon). Distinct from `⚠ stale` — peer IS alive but capability is unknown.
- `⚠ stale (Nh)` — `consecutive_probe_failures > threshold`. Peer's daemon hasn't responded for `Nh` hours; capability column irrelevant.

`--json` output mirrors the per-peer state surface in §3 (including the full `last_responder_state` block), suitable for piping to a TSDB or monitoring stack.

**Read-from-state-file, not re-tail-monitor.** `wire health` reads the per-peer state file (`<config_dir>/peer_health/<did>.json`, §3); it does NOT re-tail `wire monitor`. The dependency on the monitor noise filter is one-way: the monitor strips `kind=heartbeat` (`src/cli.rs:3891` — applies to all heartbeat traffic, including probes), and the dashboard surfaces the operator-actionable health view from the dedicated state file. This keeps the noise-filter independent of the health-view (changing one does not silently break the other). Pinned by AC-HP8.

**`wire health watch [--interval-s S]`** — continuous tail (analogous to `wire monitor` but health-scoped):

Re-renders the table every S seconds (default 5). Foreground; backgroundable.

### 5. MCP parity

Two new MCP tools:

- `mcp__wire__wire_ping` — wraps `wire ping <peer>`; returns `{peer, probes_sent, probes_acked, roundtrip_ms_p50, loss_pct, last_responder_state}`. The `last_responder_state` field lets the operator's LLM act on auto-response readiness without parsing the dashboard.
- `mcp__wire__wire_health` — wraps `wire health --json`; returns the per-peer health array including each peer's `last_responder_state` block (or `null` if peer opted out / pre-v0.15). LLMs deciding whether to route a delegation to peer X can check `last_responder_state.monitor_armed` + `last_responder_state.monitor_uptime_s > 60` before sending.

The MCP tools intentionally return cached daemon state (the auto-probe lane has been running in background), so the operator's LLM gets fresh stats without paying probe-latency per tool call. The `mcp__wire__wire_ping` tool MAY trigger a fresh probe-burst if the operator's prompt makes it explicit (e.g., "ping coral now"); default is read-from-cache.

### 6. Operator configuration

Three knobs in `<config_dir>/health.json` (no flag explosion; one config file):

```json
{
  "probe_interval_s": 60,
  "probe_timeout_s": 30,
  "rate_limit_per_pair_s": 10,
  "publish_responder_state": true,
  "respond_to": "all"
}
```

Defaults are tuned for "always-on, low-overhead" — 60s interval × 4 peers = 4 probe-RTTs/minute = negligible bandwidth (each probe + ack ≈ 200B signed). Operators with chatty fleets (100+ peers) MAY tune `probe_interval_s` higher.

Bounds enforced:
- `probe_interval_s ∈ [10, 3600]` (10s floor — anti-flood; 1h ceiling — keeps daemon useful).
- `probe_timeout_s < probe_interval_s` (no double-probe overlap).
- `rate_limit_per_pair_s ∈ [1, probe_interval_s]` (rate-limit ceiling = probe interval — limit cannot relax beyond what the daemon naturally emits).

### 7. Auto-probe opt-out

Some operators may not want active probing (privacy, low-power devices, ultra-tight rate-limit pairs). The `health.json` configuration accepts a top-level `enabled: false`:

```json
{ "enabled": false }
```

When `enabled=false`:
- Daemon does NOT emit `t: "probe"` events.
- Daemon STILL responds to inbound `t: "probe"` events (responding to a peer's probe is the polite floor; refusing breaks the bilateral symmetry the rest of wire assumes).
- `wire ping <peer>` still works (operator-triggered probes are explicit consent).
- `wire health` still renders, but `last_alive_at` will be sourced from incoming-event timestamps only (peer's own probes + any other wire traffic), not from probe-acks.

This preserves "opt-out of active probing" without breaking peers' ability to verify you're alive.

### 8. Org-tier asymmetry — `respond_to` policy knob

The §6 config's `respond_to` field lets org-tier deployments refuse probes from non-org-members, addressing the cross-tier presence-inference surface (P3 in §Privacy). Accepted values:

- `"all"` (default for personal-tier and current shared `wireup.net` behavior) — respond to probes from any bilateral-paired peer regardless of org membership.
- `"verified_only"` — respond to probes only from peers at tier ≥ VERIFIED. UNTRUSTED + ORG_VERIFIED + ATTESTED tiers do not receive acks. Mostly hypothetical for v0.15 — strictest knob, may be folded with "all" if no operator demand surfaces.
- `"org_members_only"` (recommended default for org-tier per RFC-003-amendment-deployment-tiers) — respond only to peers whose card carries an `org_membership` matching at least one of this responder's pinned org_dids. Personal-tier strangers cannot infer org-member presence patterns by probing.

This is a v0.15-scoped addition; finer-grained filtering (per-org responder policy, per-peer overrides) defers to v0.16 if demand surfaces. The default for org-tier deployments — set automatically by `wire enroll org-create` / by org-tier relay onboarding scripts — is `"org_members_only"`; personal-tier installs default to `"all"`.

## Security

### S1: Probe spam (DoS amplification)

**Threat:** an adversary on a paired peer's session attempts to flood the receiver's daemon with probes, consuming bandwidth/CPU.

**Mitigation:**
- Per-pair rate limit at receiver (`rate_limit_per_pair_s`, default 10s). Excess probes silently dropped (no error response — denies side channel).
- Bilateral-pair gate: only PINNED peers can send probes that reach the daemon at all. An unpinned dialer's probe never lands in the heartbeat handler.
- Probe payload is fixed-size (no amplification potential — ack is the same size as probe).

**Residual risk:** a hostile paired peer (one who passed SAS / org auto-pair, then turned malicious) can still consume up to `1 probe / rate_limit_per_pair_s` bandwidth. At default 10s, that's ≈ 20B/s sustained. Acceptable; operators can `forget-peer` if abused.

### S2: Presence inference / surveillance

**Threat:** an observer at the relay infers when peers are online from probe traffic.

**Mitigation:**
- Probes and acks are signed bilateral events between two peers. The relay sees ENVELOPE metadata (sender, receiver, timestamp) — it ALREADY sees this for every other wire event. No new info to the relay.
- Probe BODIES are transport-encrypted between sender and receiver (existing wire crypto). The relay does not distinguish `kind=heartbeat` body intents from other heartbeat traffic.
- Third parties (non-paired) cannot probe at all — bilateral gate.

**Residual:** the relay learns peer-to-peer activity timing (already true today via any wire event). RFC-005-grade relay-blinding (onion routing / mix-net) is out of scope.

### S3: Probe-as-exfil-side-channel

**Threat:** a compromised paired peer's LLM tries to exfil data by encoding it in probe/ack timing or payload variation.

**Mitigation:**
- Probe and ack bodies are FIXED-SIZE structures (`{nonce, iat}` only). No payload room. The wire envelope itself is signed, so the LLM cannot inject custom payload without daemon collaboration.
- Probes are emitted by the DAEMON, not by the LLM. The LLM has no surface to trigger a probe except via `wire ping <peer>` which is rate-limited.
- Probe timing is set by `probe_interval_s` (fixed, daemon-controlled), not LLM-controllable.

**Residual:** if the daemon ITSELF is compromised (a malicious wire binary), all bets are off. Mitigation = signed releases + reproducible builds (out of RFC-004 scope, RFC-005 candidate).

### S4: Spoofed probe responses

**Threat:** a third party claims to be the peer and forges probe_ack events.

**Mitigation:** standard wire bilateral signature verification. Spoofed acks fail signature check, dropped silently (existing wire pipeline behavior).

### S5: Replay attacks

**Threat:** observer captures a valid probe_ack, replays it later to deceive the sender's daemon into thinking the peer is still alive.

**Mitigation:**
- `iat` bounds check on probe_ack (within probe_timeout_s of probe sent_at).
- Probe nonce is single-use; once consumed (`outstanding_probes.remove`), a second ack with the same nonce is unmatched and dropped.
- Probe nonces are 32B random — collision probability negligible.

**Replay defense composition.** Two layers, both required:
- Sender-side **nonce-cache** (`outstanding_probes` map) — drops `probe_ack` whose `probe_nonce` does not match an outstanding probe. Closes replay-of-prior-ack-after-cycle-completion.
- Responder-side **60s `iat` window** (`probe.iat in [now-60s, now]`) — drops stale or future-dated probes. Closes replay-of-old-probe.

Neither alone is sufficient: nonce-cache without iat window allows infinite-age probe replay if the sender still has the nonce outstanding; iat window without nonce-cache allows fresh-iat replays from intercepted probe envelopes. Together they close the standard replay surface.

### S6: Fingerprinting via probe shape

**Threat:** an observer fingerprints wire versions by probe envelope characteristics.

**Mitigation:** probe shape is canonical (fixed body schema, fixed sizes). All wire versions ≥ v0.15 emit IDENTICAL probe envelopes (only the nonce + iat vary). Cross-version interop fallback: pre-v0.15 daemons receive `t: "probe"` heartbeats and cursor-PAST gracefully (warning logged), so the probe sender sees only "no ack" — distinguishable from "peer is older wire" only by looking at peer card's `schema_version` / `capabilities`.

## Privacy

### P1: Visibility of peer's online status to the probing operator

**This is the feature, not a bug.** Probing exists explicitly to surface peer reachability to the operator. Peers who don't want their reachability revealed to a paired counterpart should set `enabled: false` (which still responds to probes — see §7 for the trade-off) OR `forget-peer` the relationship.

A future refinement (out of scope for v0.15) could add `responder_enabled: false` for "I'm paired with you but I refuse to confirm reachability." This would break the bilateral-symmetry assumption wire's tier model relies on; the design tension is non-trivial. **Default: respond to probes from paired peers.**

### P2: Cross-operator inference (paul probing willard reveals willard's session patterns)

**Mitigation:** probe timing is set by the receiver's own `probe_interval_s`, not by the sender. A paired peer probing willard sees willard's `probe_interval_s` cadence, NOT willard's session-activity pattern. Willard's actual session start/stop times are inferred from OTHER wire events (which the paired peer already sees anyway), not from probe responses.

**Residual:** if willard's wire daemon is OFF, probes go unanswered → paul learns "willard's daemon is currently down." This is unavoidable in any liveness-probe design and is the SOURCE of the feature's value.

### P3: Cross-tier inference (RFC-003 personal vs org)

Probes operate at the bilateral-pair layer; they do not interact with RFC-003 deployment-tier topology. A personal-tier operator on `wireup.net` and an org-tier operator on `relay.company.com` exchange probes through whatever relay topology resolved the pair (federated via DNS-TXT if needed). The probe envelopes carry no tier-specific data.

## Acceptance criteria

≤5 falsifiable, time-bound. Each MUST have a test that fails before implementation and passes after.

- **AC-HP1: Daemon-level auto-probe lands per peer.** Given two paired daemons A + B at default config, within 60s of pair completion A's `peer_health[B].last_alive_at` is non-null. Test: spin up A + B in isolated harness, pair, wait 75s, read A's health state, assert `last_alive_at > pair_completed_at`. Owner: v0.15 implementer.
- **AC-HP2a: Auto-respond from headless `wire daemon`.** Given B's `wire daemon` is running with no MCP server, no LLM agent attached, A's probes still receive acks within `probe_timeout_s`. Test: harness runs B as `wire daemon` only (no MCP server, no Claude/Codex/Copilot session), A probes 10 times, assert ≥ 9 acks received. Owner: v0.15 implementer. **Kill criterion if unbuildable.**
- **AC-HP2b: Auto-respond from `wire mcp` with idle MCP client.** Given B is running `wire mcp` as the de-facto daemon (no separate `wire daemon` process — the harness-bound shape used by Claude Code / Copilot CLI / Codex / Cursor), with an MCP client connected but no LLM tool calls in-flight, A's probes still receive acks within `probe_timeout_s`. Probe handling MUST live at the poll-loop layer; `t: "probe"` body intents MUST NOT bubble up the MCP tool surface to the LLM. Test: harness runs B as `wire mcp` with an idle MCP client stub (no LLM); A probes 10 times; assert ≥ 9 acks received AND zero MCP tool invocations recorded. Owner: v0.15 implementer. **Kill criterion if unbuildable.**
- **AC-HP3: Probe spam rate-limit.** A sends 100 probes to B in 1s. B drops > 90 of them (rate limit 10s by default, so at most 1 probe-ack pair completes); B's responder code path consumes < 50ms CPU total. Test: harness floods + measures responder CPU. Owner: v0.15 implementer.
- **AC-HP4: Cursor-PAST gracefully on unknown body intent.** A sends `kind=heartbeat` with `body.t = "probe_v2_future_intent"` to a B running v0.15. B logs a warning and advances cursor; A's next standard probe still acks. Test: harness emits unknown body intent, asserts no `TRANSIENT_REJECT`, no daemon crash, cursor moves. Owner: v0.15 implementer.
- **AC-HP5: `wire health` surfaces peer staleness threshold visually.** If `consecutive_probe_failures > (24h / probe_interval_s)`, dashboard renders peer with `⚠ stale (Nh)` marker. Test: harness simulates 24h of dropped acks, assert dashboard text contains "⚠ stale". Owner: v0.15 implementer.
- **AC-HP6: `responder_state` reflects local monitor process truthfully.** With B running `wire daemon` only, A's probe_ack carries `responder_state.monitor_armed: false`. With B running `wire daemon` AND `wire monitor --json --persistent` (separate process), the next probe_ack carries `responder_state.monitor_armed: true` and a `monitor_uptime_s` matching the process-start delta within ±2s. Test: harness runs the two configurations in sequence, probes between each, asserts each ack's `responder_state` reflects the actual local process state. Verifies §2.5 detection rules at the daemon layer; does NOT verify peer truthfulness (which is operator-side disbelief per §2.5 threat-model). Owner: v0.15 implementer.
- **AC-HP7: Ephemeral-class body preservation.** Property test at `tests/heartbeat_body_roundtrip.rs` asserting that `kind=heartbeat` (id=100) events with arbitrary non-trivial bodies round-trip byte-identical through sign → serialize → relay → parse → verify. Two property cases: (a) arbitrary-shape body containing `t: String` + extra fields preserved byte-equal end-to-end; (b) unknown `t` body intents trigger `CursorAdvanceWithWarning` outcome, NEVER `TRANSIENT_REJECT`. Pins the §1 Ephemeral-class invariant that retention semantics MUST NOT mutate body content. Owner: v0.15 implementer.
- **AC-HP8: `wire health` reads state file, not monitor.** `wire health` dashboard sources its per-peer view from `<config_dir>/peer_health/<did>.json` (§3), NOT from `wire monitor` output. Test: harness strips heartbeat events from monitor output (the production noise-filter behavior), runs `wire health` against state files populated with synthetic probe-ack data, asserts dashboard renders correctly. Pins the one-way dependency from §4 — monitor noise-filter changes do NOT silently break the health view. Owner: v0.15 implementer.

## Kill criterion

If implementing **either AC-HP2a (`wire daemon` headless) or AC-HP2b (`wire mcp` with idle MCP client)** requires probe/ack handling logic to live in the MCP server's LLM-facing tool surface (rather than the daemon-tier poll-loop), abandon this RFC. The whole point is "no LLM involvement"; if the architecture forces probe handling above the daemon transport in either mode, the feature reduces to "send a wire message and hope the LLM replies" — which is what we have today. Both kill triggers are independent; failure of one kills the RFC regardless of the other.

## Out of scope

- **End-to-end latency vs relay latency.** `roundtrip_ms` measures pair-to-pair through the receiver's relay slot, not direct peer-to-peer (which wire does not natively support). The metric is what the operator can act on; deeper diagnostics are `wire doctor` territory.
- **Cross-relay probe diagnostics.** A probe to `<peer>@<other-relay>` works (RFC-003 federation), but failure-mode breakdown ("DNS-TXT stale?" "remote relay down?" "peer's slot expired?") is a v0.16+ enhancement of `wire doctor` / `wire health`. v0.15 health surface reports binary "alive / not alive" + roundtrip.
- **Probe-as-trust-mutation.** Probes NEVER modify peer tier, never demote, never auto-`forget-peer`. A 24h-stale peer is shown as `⚠ stale` but stays at its existing tier until operator explicitly acts. Trust mutation is RFC-001 territory; health is read-only.
- **Bandwidth attribution / usage accounting.** Probes consume bandwidth. Per-peer bandwidth accounting (so operators can audit "probes are X% of wire's data plane") is OPTIONAL v0.16 doctor enhancement.
- **Probe over A2A non-wire dialers.** A2A v1.0 dialers without wire cards (per #91) are `UNTRUSTED` and cannot probe. Probe surface is wire-paired-peer-only.

## Open questions

- **Q1: Should `probe_interval_s` be negotiated per-pair?** A paired pair could agree on a faster cadence (5s for low-latency monitoring) or slower (5min for archival peers). v0.15 default is unilateral (each daemon sets its own rate, rate-limit clamps the floor). Per-pair negotiation is plausible v0.16 work via body-discriminated `t: "probe_config_propose"` on `kind=heartbeat`. Decision deferred.
- **Q2: Should probe-loss events surface to `wire monitor`?** Probe events themselves are filtered from monitor (signal-noise). Should sustained loss (`consecutive_probe_failures > threshold`) emit a monitor-visible event? Pro: operator gets pushed notification "onyx went silent." Con: noise floor. Recommend a separate `wire health watch` lane (continuous tail), keep monitor probe-free.
- **Q3: Interaction with `wire quiet` (PR #117)?** `wire quiet` suppresses desktop toasts. Probe-loss notifications (if any per Q2) should respect quiet state. Confirm with PR #117 author.
- **Q4: Should health state be EXPORTABLE to a remote TSDB?** For operators running multi-host fleets, aggregating probe roundtrips into Prometheus / Grafana is a common ask. Recommend v0.16 — `wire health export --prometheus` adds a `/metrics`-style endpoint. v0.15 ships JSON only.

## Alternatives considered

- **Reuse `wire send <peer>` + watch for reply** — current path. Rejected: requires LLM agent involvement on responder side; high latency variance; spurious LLM cost; noisy conversation surface.
- **TCP-style keep-alive at relay layer** — relay tracks peer slot poll cadence, exposes "last poll" timestamp to authenticated queriers. Rejected: relay becomes a trust authority for peer liveness (it isn't today; offline-self-certifying invariant per RFC-001). Cross-relay deployments break: relay X cannot speak for peer Y's slot on relay Z.
- **Daemon-level `wire daemon --ping-interval` flag** — implement same protocol but with no operator surface. Rejected: half the value is the dashboard (`wire health`). Without the read surface, operators can't act on health data.
- **New top-level `kind=probe` / `kind=probe_ack`** — clean type model but black-holes pre-v0.15 cursors (`tests/pull_unknown_kind.rs`). Rejected per AC-SSO1 invariant. Body-discrimination on `kind=heartbeat` is the right shape.
- **Active probe by LLM via `mcp__wire__wire_ping`** — pushes the work to the LLM tier. Rejected: defeats the "no ack from user" requirement; LLM tier introduces seconds of latency on every probe; cost scales with peer count × probe rate; same noise problem as `wire send`. Daemon-level is non-negotiable.

## References

- `docs/rfc/0001-identity-layer.amendment-sso.md` §D / §E — established body-discrimination-on-existing-kind pattern (`sso_epoch_advance`, `sso_jwks_alarm` on `kind=1001`).
- AC-SSO1 invariant — no new top-level kinds for control-plane intents.
- `src/pull.rs::is_known_kind()` + `src/signing.rs::kinds()` — kind registry to verify `kind=heartbeat` accepts body discrimination.
- `tests/pull_unknown_kind.rs` — pins the failure mode that body-discrimination avoids.
- [PR #117](https://github.com/SlanchaAi/wire/pull/117) — `wire quiet on/off/status` (relevant to Q3).
- [RFC-003](./0003-per-company-relays.md) §6 — phasing context; v0.15 carries SSO connector PR foundation alongside which probe logic lands.
