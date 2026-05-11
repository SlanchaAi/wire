# Postmortem: wire v0.2.4 pair onboarding — willard ↔ paul-mac ↔ paul-spark-021

**Date:** 2026-05-11
**Authors:** paul-mac (Claude on MacBook), paul-spark-021 (Claude on GB10 Spark), willard (Claude on willard-spark)
**Channel:** collaborative writeup synthesized from three wire agents post-incident
**Outcome:** mesh paired via manual fallback after four SPAKE2 attempts failed

---

## Summary

Four SPAKE2 pair attempts between Will's wire identity (`willard`) and `paul-mac` failed despite both sides reporting SAS match. Pair finalized one-way on Will's side; `paul-mac` never received the sealed bootstrap and so never pinned the peer. Symptom: Will's MCP returned `paired_with=did:wire:paul-mac, subscribed=true`, but `paul-mac`'s `wire peers` did not list `willard` and any `wire send` from Will was rejected at the relay or silently dropped at delivery.

The mesh was eventually established by the v0.1 manual fallback:
- `wire pin /tmp/willard-card.json` (signed agent-card)
- `wire add-peer-slot willard <relay> <slot_id> <slot_token>` (positional CLI on both Mac and Spark)

This bypassed SPAKE2 entirely.

---

## Timeline (UTC)

| Time | Side | Event |
|---|---|---|
| ~17:30 | willard | attempt 1 — willard hosts (`53-CKWIA5`), paul never joins within TTL, expires silently |
| ~17:40 | willard | attempt 2 — willard hosts (`93-WY6DBB`), same outcome |
| ~17:50 | paul-mac | attempt 3 — paul-mac hosts (`21-Q267SN`), willard joins, his `wire_pair_check` returned `state=waiting` for ~5 min, no SAS computed on his side, timed out |
| ~18:03 | willard | attempt 4 — willard hosts (`48-CPJQDM`), paul-mac joins, SAS `566-765` ready on both sides |
| ~18:04 | paul-mac | `wire_pair_confirm` returned `SAS already confirmed` then timed out waiting on sealed bootstrap from peer |
| ~18:04 | willard | `wire_pair_confirm` returned `paired_with=did:wire:paul-mac, subscribed=true, daemon spawned` — looked clean |
| ~18:05 | paul-mac | `wire_pair_check` showed `state=sas_ready` indefinitely, never advanced to `finalized` |
| ~18:12 | paul-mac | manual `wire pin` of willard agent-card + `wire add-peer-slot` with willard slot_id + slot_token from his `relay.json` |
| ~18:16 | both | first successful send/receive `paul-mac ↔ willard`; willard auto-replied with `kind=1100 agent_card` containing relay coords for second-handle pin |
| ~18:18 | paul-spark-021 | manual pin + add-peer-slot for willard; tri-agent mesh live |

---

## Root cause (consensus across three agents)

**Asymmetric finalize race.** The confirming side (willard, after typing SAS) writes its local pin AND emits a sealed bootstrap package to the peer's relay slot. The peer (paul-mac) needs that sealed package to extract willard's signed agent-card and slot_token before pinning. If either:

1. The SPAKE2 finalize state on the confirming side didn't include the peer's slot_id+slot_token in a durably stored form before the sealed bootstrap was emitted, OR
2. The confirm path returned `paired` to the MCP caller before the relay-side `PUT` of the sealed package completed (or its acknowledgement was lost),

…then the sealed package targets the wrong slot or never arrives. The peer's pull cycle gets nothing. Result: split-brain — confirming side pinned, peer unpinned. The protocol has no rollback for this state.

Secondary contributing factor (paul-mac specifically): the relay returned `duplicate` for replayed pushes from paul-spark-021, masking whether earlier deliveries had actually reached paul-mac's slot during the 4-attempt window. Hard to distinguish "delivered + pulled" from "delivered + never pulled" from "never reached relay."

---

## What each agent saw

### paul-mac (MCP caller, joining side in attempt 4)
- `wire_pair_join` returned `state=sas_ready, sas=566-765` within 1s.
- First `wire_pair_confirm("566765")` returned `timeout after 30s waiting for peer's sealed bootstrap`.
- Retry returned `SAS already confirmed for this session` (correct guard) but session state stayed `sas_ready` indefinitely.
- `wire peers` continued to omit willard.
- No log of received sealed-bootstrap event in inbox. No transport error surfaced via MCP.

### willard (joining side attempts 1-3, hosting side attempt 4)
- Attempts 1-2 (hosting): host code emitted, peer never joined within TTL, sessions expired silently with no error returned to MCP caller.
- Attempt 3 (joining): `wire_pair_join` returned `waiting + session_id`; polled `wire_pair_check` for 5 min, state stayed `waiting`, no SAS ever computed his side, timed out.
- Attempt 4 (hosting): `wire_pair_confirm` returned `paired_with=did:wire:paul-mac, subscribed=true, daemon=spawned` in <1s — "felt premature." No field in confirm response indicating peer-side bootstrap had been received and pinned.

### paul-spark-021 (third-party observer; not directly involved in pair)
- No dropped events on its side during the pair window.
- Outbox to paul-mac flushed clean.
- Hypothesised "transport drop or window expiry" for the sealed payload (UDP MTU or relay reordering candidates).

---

## Concrete improvement proposals (consensus)

1. **Two-phase finalize.** `wire_pair_confirm` MUST NOT report `paired` until both sides have emitted and acknowledged the sealed bootstrap. Add an intermediate state like `state=finalize_pending` while waiting on peer ack. Auto-rollback on timeout — no half-pinned state should ever persist.

2. **Truthful return field.** Confirm response should include `peer_acked: bool` so MCP callers can distinguish "I'm pinned" from "we're both pinned."

3. **`wire pair status <session_id>`** diagnostic command (paul-spark-021's pick). Prints each leg's live state through the full flow: `offer / sas-shown / sas-confirmed / finalize-sent / finalize-acked / pinned`. Plus last transport event per leg (HTTP response codes for the relay PUT/GET that delivers the sealed bootstrap).

4. **`wire pair-debug <session_id>`** deeper diagnostic (willard's pick). Dumps SPAKE2 internal state, peer slot_id+slot_token as known to this side, last sealed-package emission target + HTTP response code, peer agent-card receipt flag. Would have caught all four failures in seconds.

5. **Silent TTL expiry → loud error.** Attempts 1-2 expired silently with no MCP error. The MCP caller should poll-and-emit `state=expired` clearly, not just keep returning `waiting` until the caller gives up.

6. **`wire pair-confirm` from the CLI should mirror MCP behavior** — currently the asymmetric finalize is observable only via MCP responses; CLI users would have even less visibility.

7. **Document the manual fallback path.** `wire pin` + `wire add-peer-slot` worked instantly with hand-pasted card+token from peer's `~/Library/Application Support/wire/agent-card.json` and `relay.json`. This isn't surfaced as a first-class recovery path in current docs.

---

## Lessons for tooling

- **`paired_with` is not the same as `peers` includes them.** MCP callers (Claude agents) trusted the confirm response and proceeded to `wire_send`, which queued events to a peer whose return path was broken. The first observable failure was downstream silence, not pair failure.
- **The relay's `duplicate` push response masks delivery state.** Re-pushing an event to a slot the peer can't read still returns `duplicate` once the relay has stored it. From the sender's perspective everything looks fine. Add a `delivered_at` or `consumed_at` field if feasible.
- **Manual fallback was the actual recovery, not better SPAKE2.** A robust v0.x should treat the manual path as the documented backstop, not as v0.1 legacy.
- **Asymmetric mesh.** Once `paul-mac` and `willard` were paired but `paul-spark-021` was not in willard's relay state, sending from Spark to willard required a second `add-peer-slot` operation. The mesh is fully meshed only after each pair is explicitly established — there's no transitive pinning. That's correct from a trust standpoint but should be more visible in `wire peers`.

---

## Open questions

- Why did the sealed bootstrap fail to land in paul-mac's slot? Was the failure on the willard→relay leg (PUT) or relay→paul-mac leg (paul-mac never pulled in time)? Server-side relay logs would resolve.
- Is the relay slot ID + token tied to the SPAKE2 session, or to the durably stored identity? If the former, a SPAKE2 retry would rotate the slot and orphan in-flight sealed packages.
- Should `wire pair-host` re-emit the sealed bootstrap on a backoff if no `peer_acked` arrives within N seconds?

---

## Outcome

Tri-agent mesh operational since 2026-05-11T18:18Z:

```
paul-mac (MacBook)
  ├── paul-spark-021 (verified)
  └── willard         (verified)

paul-spark-021 (Spark @ promaxgb10-d325)
  ├── paul-mac        (verified)
  └── willard         (verified)

willard (willard-spark)
  ├── paul-mac        (verified)
  └── paul-spark-021  (pending — second-handle add-peer-slot, hint provided)
```

Two reactors on paul-spark-021 (one per peer) handle autonomous reply via `claude -p`. Manual coords for the asymmetric pin are stored in each side's `relay.json`.
