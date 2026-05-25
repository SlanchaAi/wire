# Group chat (v0.13.3) — design

Goal: make + test group chat for wire. Build on existing primitives; collaborate with feral-blossom's membership core (`src/group.rs`, unpushed) where it exists.

## Principle (from the trust review)
Group membership is a **separate axis** from bilateral peer trust. A member's **GroupTier** (Creator / Member / Introduced) is group-scoped — it is NOT the `trust.rs` bilateral `Tier` (UNTRUSTED/VERIFIED/…). A peer can be bilaterally UNTRUSTED yet a group Member, or VERIFIED bilaterally but only INTRODUCED in a group. Keep the two ladders disjoint; never auto-promote bilateral trust from group membership.

## Model (`src/group.rs`)
```
GroupTier = Creator | Member | Introduced
Member    = { handle, did, tier }
Group     = { id, name, creator_did, epoch, members[], creator_sig }
```
- `id`: random 16-hex. `epoch`: u64, bumped on every roster mutation (T17 — orders revocations).
- `creator_sig`: creator's Ed25519 signature over canonical(id,name,creator_did,epoch,members). Authenticates the roster so a member can pin INTRODUCED peers on the creator's vouch even when the creator is offline.
- Persist at `config/wire/groups/<id>.json`. `load/save/list`.
- Consent (T22): `add_member` as **Member** requires the peer be bilaterally VERIFIED (you pin people you actually verified); **Introduced** members arrive only via the join-code path.

## Commands (composition over existing primitives)
1. `wire group create <name>` — new id, self=Creator, sign roster, persist.
2. `wire group add <group> <peer>` — add a bilaterally-VERIFIED pinned peer as Member; epoch++, re-sign.
3. `wire group send <group> <msg>` — **scoped mesh-broadcast** to the group's members (reuse `cmd_mesh_broadcast`'s fan-out, filtered to the member set, body tagged `{group_id, epoch, text}`, kind=group_msg).
4. `wire group tail <group>` — filter the inbox by `group_id` (reuse the monitor/tail read).
5. `wire group list` — groups + member tiers.
6. `wire group invite <group>` — mint a **multi-use** join code (reuse `mint_invite` with uses>1 + TTL) bound to `group_id`; redeemers land at **Introduced**, joins VISIBLE.
7. `wire group kick <group> <member>` — remove from roster, epoch++, re-sign; **T11 sender-token revocation** (rotate the group send credential so the kicked member can no longer post). Local-drop allowed without the creator (don't make the creator a single point of failure for kicks).

## Increments (test each)
- **I1 (MVP) — SHIPPED 2026-05-25 (commits fed60da model, 206896e commands+e2e):** model + create/add/send/tail/list + tests. Unit: roster sign/verify, tamper, epoch bump, GroupTier disjoint from bilateral Tier (8 tests, src/group.rs). E2e (tests/e2e_group.rs): relay + 3 agents, creator pairs both members (SAS→VERIFIED), creates group, adds both (epoch→2), refuses an unpaired peer, broadcasts 2 msgs; both members pull (2 written / 0 rejected) and tail by id with verified=true. **Scope: creator-broadcast only** (see Topology below) — a working *announce-style* group chat among verified members.
- **I2:** bidirectional chat via roster-vouched introductions (see Topology) + multi-use join-code → Introduced, visible joins (relay-enforced TTL+uses).
- **I3:** kick + T11 sender-token revocation (secure-eject); creator-offline local-drop.

## Topology constraint (the I1→I2 boundary — found while building I1)
Members are added by pairing each one with the **creator** (star), not pairwise. So in I1 a member can RECEIVE the creator's broadcast (it's paired with + pins the creator) but **cannot send to the group**, for two independent reasons:
1. **No coords.** A member has relay slot coords only for the creator, not for other members — nothing to push to.
2. **Trust gate.** Even with coords, the receiver's `verify_message_v31` rejects an event whose sender it hasn't pinned. Member-A is not in member-B's trust.

Bidirectional chat is therefore NOT a quick add on top of I1 — it needs the **introduce-on-vouch** mechanism that `GroupTier::Introduced` + `creator_sig` were designed for:
- The signed roster must carry **each member's relay endpoint(s)** (the creator knows them from pairing) so members learn where to reach each other.
- On ingesting a creator-signed roster, a member **pins the other members at `Introduced`** on the creator's vouch (creator_sig authenticates the roster across relays).
- `verify_message_v31` (or the group-msg accept path) must **accept `Introduced`-pinned senders** for `group_msg` events scoped to that group_id. This is the security-sensitive step: pinning a key you never SAS-verified, trusting the creator's signature instead. Scope it to group_msg + the specific group; never auto-promote bilateral Tier.

Until I2 ships this, members reply out-of-band (direct `wire send` to the creator) or the creator stays the hub. This finding sharpens I2 from "join code" into a concrete trust-model change.

## I2 architecture — LOCKED 2026-05-25 (operator: "build I2 bidirectional")
Three transports were on the table; the relay model decides between them.

**Finding:** a relay `slot_token` is a read+write bearer credential (`relay_server.rs`: "token holder may read + write that slot"; `post_event` sends `Bearer {slot_token}`). So:
- **(A) Direct member-to-member mesh** would require distributing each member's *personal* mailbox token to every other member — the credential leak the tracker's E6 already flags, and the harness blocks token-over-federation. **Rejected.**
- **(B) Creator-hub daemon re-fan** avoids new credentials but needs the creator's *daemon* to auto-rebroadcast peer messages — the auto-act surface we're keeping conservative. **Rejected** (don't grow daemon auto-act).
- **(C) Shared group slot = a real group room.** **CHOSEN.** A slot is already a shared-token mailbox (that's literally how paired peers work, `post_event` doc). The creator allocates ONE slot; its token is the **room key**. Everyone posts + pulls that one slot. No relay change, no daemon change, no per-member credential mesh.

**Mechanism:**
1. `group create` allocates a group slot on the creator's relay → `{relay_url, slot_id, slot_token}` stored in the Group. Self is added with its `key_id` + pubkey.
2. `group add <peer>` captures the peer's `did` + `key_id` + pubkey from the creator's trust (the peer is bilaterally VERIFIED), adds them to the signed roster, and pushes a **`group_invite`** event (the full Group incl. slot coords + creator-signed roster) to the peer over the existing paired channel.
3. **Member ingest** (lazy, at the top of any `group` command — no daemon): scan inbox for `group_invite` from a pinned creator; verify the event signature AND the roster `creator_sig`; materialize the local Group; **introduce-pin** every other member — write `trust.agents[handle] = {tier:"UNTRUSTED", did, public_keys:[{key_id, key, active}], introduced_via:<group_id>}`. Bilateral Tier stays UNTRUSTED (axes disjoint); the key is now present so `verify_message_v31` (key-presence, NOT tier-gated — confirmed) succeeds for that member's group messages.
4. `group send` signs a `group_msg` and `post_event`s it to the **group slot** (one post, not a fan-out).
5. `group tail` `list_events` the group slot, verifies each message against pinned keys, displays.

**Security properties (documented, inherent to a group room):**
- The group `slot_token` is a shared room key: any holder can post + read. Distributed ONLY to vouched (VERIFIED-by-creator) members over secure paired channels. A leaked token = room compromise → revocation = rotate the slot (the I3 kick mechanism).
- introduce-pin trusts the creator's *signature* over the roster in place of a SAS handshake. Scoped: it pins keys for group-message verification at bilateral UNTRUSTED; it never grants bilateral Tier and never auto-promotes.
- `creator_sig` authenticates the member→key bindings + slot coords; a member verifies it before pinning anything.

**Sub-increments:** I2a model+create/send/tail against the slot (single-identity test) · I2b invite distribution + member ingest/introduce-pin · I2c e2e bidirectional (member-A posts, member-B + creator read it verified).

## Open coordination
feral owns `src/group.rs` membership on its branch. I built the minimal model + commands per this spec (feral's was exploratory/unpushed); reconcile at merge. Transport layer (send/tail/invite/kick) is independent of model internals — interface is "the member-handle set for group G".
