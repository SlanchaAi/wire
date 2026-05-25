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
- **I1 (MVP, this pass):** model + create/add/send/tail/list + tests (unit: roster sign/verify, epoch bump, GroupTier disjoint from bilateral Tier; e2e: create→add VERIFIED peer→send→peer tails it). A working group chat among verified peers.
- **I2:** multi-use join-code → Introduced, visible joins (relay-enforced TTL+uses).
- **I3:** kick + T11 sender-token revocation (secure-eject); creator-offline local-drop.

## Open coordination
feral owns `src/group.rs` membership on its branch. If it pushes, adopt its model + I add commands 3–7 + tests. If not, I build the minimal model above and reconcile at merge. Transport layer (send/tail/invite/kick) is largely independent of the model internals — interface is "the member-handle set for group G".
