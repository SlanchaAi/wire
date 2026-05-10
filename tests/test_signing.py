"""Tests for wire/signing.py — sign-over-event_id (Nostr NIP-01).

Cherry-picked + adapted from inter-agent-deaddrop-v3/tests/test_v31_sign.py.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from wire.signing import (
    KIND_RANGES,
    KINDS,
    canonical,
    compute_event_id,
    fingerprint,
    generate_keypair,
    kind_class,
    make_key_id,
    sign_message_v31,
    verify_message_v31,
    b64encode,
)


def _trust_for(handle: str, pub: bytes) -> dict:
    key_id = make_key_id(handle, pub)
    return {"agents": {handle: {"public_keys": [{"key_id": key_id, "key": b64encode(pub), "active": True}]}}}


# ---------- canonical + event_id ----------

def test_canonical_excludes_signature_fields():
    msg = {"a": 1, "signature": "sig", "public_key_id": "id"}
    out = canonical(msg)
    assert b"signature" not in out
    assert b"public_key_id" not in out


def test_canonical_strict_excludes_event_id():
    msg = {"a": 1, "event_id": "deadbeef"}
    assert b"event_id" not in canonical(msg, strict_escapes=True)
    assert b"event_id" in canonical(msg, strict_escapes=False)


def test_canonical_sort_keys_stable():
    msg_a = {"b": 1, "a": 2}
    msg_b = {"a": 2, "b": 1}
    assert canonical(msg_a) == canonical(msg_b)


def test_compute_event_id_is_64_hex():
    msg = {"timestamp": "2026-05-10T00:00:00Z", "from": "paul", "type": "test"}
    eid = compute_event_id(msg)
    assert len(eid) == 64
    int(eid, 16)  # parses as hex


# ---------- KIND_RANGES + kind_class ----------

def test_kind_ranges_disjoint():
    """No kind belongs to >1 range."""
    seen = set()
    for cls, rng in KIND_RANGES.items():
        for k in rng:
            assert k not in seen, f"kind {k} in multiple ranges"
            seen.add(k)


def test_kind_class_known_ranges():
    assert kind_class(20000) == "ephemeral"
    assert kind_class(29999) == "ephemeral"
    assert kind_class(1000) == "regular"
    assert kind_class(9999) == "regular"
    assert kind_class(10000) == "replaceable"
    assert kind_class(19999) == "replaceable"
    assert kind_class(30000) == "addressable"


def test_kind_class_special_cases():
    """Documented out-of-range KINDS get explicit special-casing."""
    assert kind_class(1) == "regular"     # Nostr-compat decision
    assert kind_class(100) == "ephemeral"  # heartbeat


def test_kind_class_unknown_returns_none():
    assert kind_class(99999) is None
    assert kind_class(7) is None


def test_v01_does_not_ship_v02_kinds():
    """ANTI_FEATURES.md commitments: file_share/file_revoke/registry_revocation deferred."""
    for deferred_kind in (1900, 1901, 10500):
        assert deferred_kind not in KINDS, f"v0.2+ kind {deferred_kind} leaked into v0.1"


# ---------- fingerprint + make_key_id ----------

def test_fingerprint_is_8_hex():
    pub = b"\x00" * 32
    fp = fingerprint(pub)
    assert len(fp) == 8
    int(fp, 16)


def test_make_key_id_format():
    _, pub = generate_keypair()
    kid = make_key_id("paul", pub)
    assert kid.startswith("paul:")
    assert len(kid.split(":")[1]) == 8


# ---------- generate + sign + verify roundtrip ----------

def test_generate_keypair_returns_32_byte_pair():
    priv, pub = generate_keypair()
    assert len(priv) == 32
    assert len(pub) == 32


def test_sign_verify_roundtrip():
    priv, pub = generate_keypair()
    msg = {
        "timestamp": "2026-05-10T00:00:00Z",
        "from": "paul",
        "type": "decision",
        "kind": 1,
        "subject": "test",
        "body": {"content": "hello"},
    }
    signed = sign_message_v31(msg, priv, pub, "paul")
    assert "event_id" in signed
    assert "public_key_id" in signed
    assert "signature" in signed

    ok, reason = verify_message_v31(signed, _trust_for("paul", pub))
    assert ok, reason


def test_verify_rejects_tampered_body():
    priv, pub = generate_keypair()
    signed = sign_message_v31(
        {"from": "paul", "type": "decision", "body": {"content": "original"}},
        priv, pub, "paul",
    )
    # Tamper the body without re-signing
    signed["body"]["content"] = "tampered"
    ok, reason = verify_message_v31(signed, _trust_for("paul", pub))
    assert not ok
    assert "event_id mismatch" in reason


def test_verify_rejects_did_wire_prefix_in_from_when_aligned():
    """from field may carry did:wire:<handle>; verify still passes."""
    priv, pub = generate_keypair()
    signed = sign_message_v31(
        {"from": "did:wire:paul", "type": "decision", "body": {}},
        priv, pub, "paul",
    )
    ok, reason = verify_message_v31(signed, _trust_for("paul", pub))
    assert ok, reason


def test_verify_rejects_unknown_agent():
    priv, pub = generate_keypair()
    signed = sign_message_v31(
        {"from": "paul", "type": "decision", "body": {}},
        priv, pub, "paul",
    )
    trust = {"agents": {"willard": {"public_keys": []}}}
    ok, reason = verify_message_v31(signed, trust)
    assert not ok
    assert "not in trust" in reason


def test_verify_rejects_inactive_key():
    priv, pub = generate_keypair()
    signed = sign_message_v31(
        {"from": "paul", "type": "decision", "body": {}},
        priv, pub, "paul",
    )
    trust = _trust_for("paul", pub)
    trust["agents"]["paul"]["public_keys"][0]["active"] = False
    ok, reason = verify_message_v31(signed, trust)
    assert not ok
    assert "deactivated" in reason
