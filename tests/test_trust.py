"""Tests for wire/trust.py — minimal tier state machine for v0.1."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from wire.agent_card import build_agent_card, sign_agent_card
from wire.signing import generate_keypair
from wire.trust import (
    TIER_ORDER,
    add_agent_card_pin,
    add_self_to_trust,
    empty_trust,
    get_tier,
    promote_to_verified,
)


def test_empty_trust_shape():
    t = empty_trust()
    assert t == {"version": 1, "agents": {}}


def test_get_tier_unknown_returns_untrusted():
    assert get_tier(empty_trust(), "ghost") == "UNTRUSTED"


def test_add_agent_card_pin_defaults_untrusted():
    priv, pub = generate_keypair()
    card = sign_agent_card(build_agent_card("paul", pub), priv)
    trust = add_agent_card_pin(empty_trust(), card)
    assert get_tier(trust, "paul") == "UNTRUSTED"
    assert "paul" in trust["agents"]
    assert trust["agents"]["paul"]["did"] == "did:wire:paul"


def test_add_pin_strips_ed25519_prefix_from_key_id():
    priv, pub = generate_keypair()
    card = sign_agent_card(build_agent_card("paul", pub), priv)
    trust = add_agent_card_pin(empty_trust(), card)
    key_record = trust["agents"]["paul"]["public_keys"][0]
    assert ":" in key_record["key_id"]
    assert not key_record["key_id"].startswith("ed25519:")


def test_promote_to_verified_one_way():
    priv, pub = generate_keypair()
    card = sign_agent_card(build_agent_card("paul", pub), priv)
    trust = add_agent_card_pin(empty_trust(), card)
    ok, reason = promote_to_verified(trust, "paul")
    assert ok, reason
    assert get_tier(trust, "paul") == "VERIFIED"
    assert "verified_at" in trust["agents"]["paul"]


def test_promote_to_verified_idempotent_block():
    """Promotion is one-way; re-promoting an already-verified peer is a no-op error."""
    priv, pub = generate_keypair()
    card = sign_agent_card(build_agent_card("paul", pub), priv)
    trust = add_agent_card_pin(empty_trust(), card)
    promote_to_verified(trust, "paul")
    ok, reason = promote_to_verified(trust, "paul")
    assert not ok
    assert "VERIFIED" in reason


def test_promote_unknown_peer_fails():
    ok, reason = promote_to_verified(empty_trust(), "ghost")
    assert not ok
    assert "not pinned" in reason


def test_add_self_to_trust_attests():
    _, pub = generate_keypair()
    trust = add_self_to_trust(empty_trust(), "paul", pub)
    assert get_tier(trust, "paul") == "ATTESTED"
    assert trust["agents"]["paul"]["did"] == "did:wire:paul"


def test_tier_order_matches_promotion_semantics():
    assert TIER_ORDER["UNTRUSTED"] < TIER_ORDER["VERIFIED"]
    assert TIER_ORDER["VERIFIED"] < TIER_ORDER["ATTESTED"]
    assert TIER_ORDER["ATTESTED"] < TIER_ORDER["TRUSTED"]
