"""Tests for wire/agent_card.py — DID-anchored AgentCard + signed sig.

Cherry-picked + adapted from inter-agent-deaddrop-v3/tests/.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from wire.agent_card import (
    CARD_SCHEMA_VERSION,
    DID_METHOD,
    build_agent_card,
    card_canonical,
    compute_sas,
    did_for,
    sign_agent_card,
    verify_agent_card,
)
from wire.signing import b64encode, generate_keypair


# ---------- did_for ----------

def test_did_for_handle():
    assert did_for("paul") == "did:wire:paul"


def test_did_for_already_did_passthrough():
    assert did_for("did:wire:paul") == "did:wire:paul"
    assert did_for("did:key:abc") == "did:key:abc"  # any did: pass-through


def test_did_method_constant():
    assert DID_METHOD == "did:wire"


# ---------- build_agent_card ----------

def test_build_minimal_card():
    _, pub = generate_keypair()
    card = build_agent_card("paul", pub)
    assert card["schema_version"] == CARD_SCHEMA_VERSION
    assert card["did"] == "did:wire:paul"
    assert card["name"] == "Paul"
    assert "verify_keys" in card and len(card["verify_keys"]) == 1
    assert "policies" in card
    assert card["policies"]["max_message_body_kb"] == 64


def test_build_card_with_overrides():
    _, pub = generate_keypair()
    card = build_agent_card(
        "carol", pub,
        name="Carol's Agent",
        capabilities=["custom-cap"],
        max_body_kb=128,
    )
    assert card["name"] == "Carol's Agent"
    assert card["capabilities"] == ["custom-cap"]
    assert card["policies"]["max_message_body_kb"] == 128


def test_build_card_does_not_carry_v02_fields():
    """Anti-feature: v0.1 cards do NOT have registries/onboard_endpoint/wire_raw_url_template."""
    _, pub = generate_keypair()
    card = build_agent_card("paul", pub)
    for v02_field in ("registries", "onboard_endpoint", "wire_raw_url_template", "revoked_at"):
        assert v02_field not in card, f"v0.2+ field {v02_field} leaked into v0.1 card"


# ---------- canonical bytes ----------

def test_card_canonical_excludes_signature():
    card = {"schema_version": "v3.1", "did": "did:wire:paul", "signature": "sig"}
    out = card_canonical(card)
    assert b"signature" not in out


def test_card_canonical_sort_keys_stable():
    a = {"b": 1, "a": 2, "did": "did:wire:paul"}
    b = {"did": "did:wire:paul", "a": 2, "b": 1}
    assert card_canonical(a) == card_canonical(b)


# ---------- sign + verify roundtrip ----------

def test_sign_verify_roundtrip():
    priv, pub = generate_keypair()
    card = build_agent_card("paul", pub)
    signed = sign_agent_card(card, priv)
    assert "signature" in signed
    ok, reason = verify_agent_card(signed)
    assert ok, reason


def test_verify_rejects_unsigned_card():
    _, pub = generate_keypair()
    card = build_agent_card("paul", pub)
    ok, reason = verify_agent_card(card)
    assert not ok
    assert "signature" in reason


def test_verify_rejects_tampered_card():
    priv, pub = generate_keypair()
    signed = sign_agent_card(build_agent_card("paul", pub), priv)
    signed["name"] = "TamperedName"
    ok, reason = verify_agent_card(signed)
    assert not ok


def test_verify_rejects_card_with_no_verify_keys():
    priv, _ = generate_keypair()
    card = {"schema_version": "v3.1", "did": "did:wire:paul", "verify_keys": {}}
    signed = sign_agent_card(card, priv)
    ok, reason = verify_agent_card(signed)
    assert not ok
    assert "verify_keys" in reason


# ---------- compute_sas ----------

def test_compute_sas_is_6_digits():
    _, pub_a = generate_keypair()
    _, pub_b = generate_keypair()
    sas = compute_sas(pub_a, pub_b)
    assert len(sas) == 6
    assert sas.isdigit()


def test_compute_sas_bilateral_symmetric():
    """Either side computes the same digits regardless of input order."""
    _, pub_a = generate_keypair()
    _, pub_b = generate_keypair()
    assert compute_sas(pub_a, pub_b) == compute_sas(pub_b, pub_a)


def test_compute_sas_changes_with_inputs():
    _, pub_a = generate_keypair()
    _, pub_b = generate_keypair()
    _, pub_c = generate_keypair()
    sas_ab = compute_sas(pub_a, pub_b)
    sas_ac = compute_sas(pub_a, pub_c)
    assert sas_ab != sas_ac
