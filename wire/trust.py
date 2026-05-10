"""
Trust state machine — v0.1 minimal subset.

Tracks per-peer tier (UNTRUSTED → VERIFIED → ATTESTED → TRUSTED). v0.1 only
uses UNTRUSTED + VERIFIED actively (after SAS pairing). ATTESTED + TRUSTED
are reserved for v0.2+ when operator-initiated promotion semantics matter.

Storage: ~/.config/wire/trust.json (managed by wire/config.py).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from wire.signing import b64encode, make_key_id


# Tier semantics (v0.1):
# - UNTRUSTED: card pinned but SAS not yet confirmed; messages from this tier ignored
# - VERIFIED:  SAS confirmed bilateral; messages accepted
# - ATTESTED:  reserved (v0.2+)
# - TRUSTED:   reserved (v0.2+)
TIER_ORDER = {"UNTRUSTED": 0, "VERIFIED": 1, "ATTESTED": 2, "TRUSTED": 3}


def empty_trust() -> dict[str, Any]:
    """Return a fresh empty trust dict shape."""
    return {"version": 1, "agents": {}}


def get_tier(trust: Mapping[str, Any], peer_handle: str) -> str:
    """Return the tier string for a peer; 'UNTRUSTED' if absent."""
    agent = trust.get("agents", {}).get(peer_handle)
    if not agent:
        return "UNTRUSTED"
    return agent.get("tier", "UNTRUSTED")


def add_agent_card_pin(
    trust: dict[str, Any],
    card: Mapping[str, Any],
    *,
    tier: str = "UNTRUSTED",
) -> dict[str, Any]:
    """Pin a peer's agent-card into our trust state at the given tier.

    Default tier is UNTRUSTED — caller must run SAS confirmation before
    promoting via promote_to_verified().
    """
    did = card.get("did", "")
    if did.startswith("did:wire:"):
        handle = did[len("did:wire:"):]
    else:
        handle = did

    if not handle:
        raise ValueError(f"card has no resolvable handle (did={did!r})")

    agents = trust.setdefault("agents", {})
    public_keys = []
    for key_id_full, key_record in (card.get("verify_keys") or {}).items():
        # Strip the `ed25519:` algorithm prefix to match v3.1 trust.json shape
        if key_id_full.startswith("ed25519:"):
            key_id = key_id_full[len("ed25519:"):]
        else:
            key_id = key_id_full
        public_keys.append({
            "key_id": key_id,
            "key": key_record.get("key"),
            "added_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "active": True,
        })

    agents[handle] = {
        "tier": tier,
        "did": did,
        "public_keys": public_keys,
        "card": dict(card),
        "pinned_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    return trust


def promote_to_verified(trust: dict[str, Any], peer_handle: str) -> tuple[bool, str]:
    """Promote a peer from UNTRUSTED → VERIFIED. Caller MUST have run SAS first."""
    agent = trust.get("agents", {}).get(peer_handle)
    if not agent:
        return False, f"peer {peer_handle!r} not pinned"
    current = agent.get("tier", "UNTRUSTED")
    if current != "UNTRUSTED":
        return False, f"peer {peer_handle!r} already at tier {current!r} — promotion is one-way"
    agent["tier"] = "VERIFIED"
    agent["verified_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return True, "promoted"


def add_self_to_trust(
    trust: dict[str, Any],
    handle: str,
    public_key_bytes: bytes,
) -> dict[str, Any]:
    """Self-pin our own keypair into trust. ATTESTED tier (we attest to ourselves).

    Convenience for `wire init` — gives the operator a complete trust.json
    where verify_message_v31 can find self-signed messages without extra steps.
    """
    key_id = make_key_id(handle, public_key_bytes)
    agents = trust.setdefault("agents", {})
    agents[handle] = {
        "tier": "ATTESTED",
        "did": f"did:wire:{handle}",
        "public_keys": [{
            "key_id": key_id,
            "key": b64encode(public_key_bytes),
            "added_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "active": True,
        }],
    }
    return trust


__all__ = [
    "TIER_ORDER",
    "add_agent_card_pin",
    "add_self_to_trust",
    "empty_trust",
    "get_tier",
    "promote_to_verified",
]
