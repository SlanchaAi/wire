"""
Ed25519 signing for wire v0.1.

Signed-event format follows Nostr NIP-01: signature is computed over the raw
32 bytes of the event_id (sha256 of canonical body), not over the body itself.
Saves bytes vs full-body signing without weakening any guarantee.

Cherry-picked + minimized from inter-agent-deaddrop-v3/signing.py.
Dropped: v3.0 legacy sign_message/verify_message, signed_append_jsonl,
trust_add_key/trust_deactivate_key (those move to wire/trust.py if needed).
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Mapping

try:
    from nacl import signing as _signing
    _backend = "pynacl"
except ImportError:  # pragma: no cover - tested by exclusion
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives import serialization
        _backend = "cryptography"
    except ImportError:
        _backend = None


def _require_backend() -> None:
    if _backend is None:
        raise RuntimeError(
            "no Ed25519 backend installed. pip install pynacl OR pip install cryptography"
        )


def canonical(msg: Mapping[str, Any], strict_escapes: bool = False) -> bytes:
    """Canonical serialization for sign/verify. Excludes signing fields.

    strict_escapes=True: also exclude `event_id` from canonical input
    (event_id is derived from the canonical body).
    """
    excluded = {"public_key_id", "signature"}
    if strict_escapes:
        excluded.add("event_id")
    body = {k: v for k, v in msg.items() if k not in excluded}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_event_id(msg: Mapping[str, Any]) -> str:
    """64-hex sha256 over canonical(msg, strict_escapes=True)."""
    return hashlib.sha256(canonical(msg, strict_escapes=True)).hexdigest()


# v3.1 message kind ranges (Nostr NIP-01 inspired)
KIND_RANGES = {
    "ephemeral": range(20000, 30000),       # not archived after ack
    "regular": range(1000, 10000),          # archived
    "replaceable": range(10000, 20000),     # only latest kept per (pubkey, kind)
    "addressable": range(30000, 40000),     # latest per (kind, pubkey, d-tag)
}

KINDS = {
    100: "heartbeat",       # ephemeral, not archived
    1: "decision",          # regular text/decision (Nostr-compat)
    1100: "claim",
    1101: "release",
    1200: "ship",
    1201: "warning",
    1300: "feedback",
    1400: "incident",
    1500: "ack",
    1600: "proposal",
    1700: "correction",
    1800: "shutdown",
    10000: "agent_card",    # replaceable per pubkey
    10001: "trust_tier_announcement",
}

# v0.2+ kinds intentionally NOT shipped in v0.1: 1900 file_share, 1901 file_revoke,
# 10500 registry_revocation. See BACKLOG.md.


def kind_class(kind: int) -> str | None:
    """Return 'ephemeral' | 'regular' | 'replaceable' | 'addressable' or None.

    Documented out-of-range KINDS get explicit special-casing. kind=1 is
    regular (Nostr-compat); kind=100 is ephemeral (heartbeat).
    """
    for class_name, rng in KIND_RANGES.items():
        if kind in rng:
            return class_name
    if kind == 1:
        return "regular"
    if kind == 100:
        return "ephemeral"
    return None


def fingerprint(public_key_bytes: bytes) -> str:
    """8-hex-char fingerprint over raw public key bytes."""
    return hashlib.sha256(public_key_bytes).hexdigest()[:8]


def make_key_id(agent: str, public_key_bytes: bytes) -> str:
    return f"{agent}:{fingerprint(public_key_bytes)}"


# ---------- key generation ----------

def generate_keypair() -> tuple[bytes, bytes]:
    """Returns (private_key_bytes, public_key_bytes), both 32 bytes."""
    _require_backend()
    if _backend == "pynacl":
        sk = _signing.SigningKey.generate()
        return bytes(sk), bytes(sk.verify_key)
    if _backend == "cryptography":
        sk = Ed25519PrivateKey.generate()
        priv = sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub = sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return priv, pub
    raise RuntimeError(f"unreachable: backend={_backend}")


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


# ---------- sign / verify (v3.1 sign-over-event_id) ----------

def sign_message_v31(
    msg: Mapping[str, Any],
    private_key_bytes: bytes,
    public_key_bytes: bytes,
    agent: str,
) -> dict[str, Any]:
    """Compute event_id, sign over event_id bytes (32 raw, hex-decoded).

    Sender flow:
      1. compute_event_id(msg) -> 64-hex string
      2. sign over the 32 raw bytes (hex-decoded) using Ed25519
      3. attach event_id, public_key_id, signature
    """
    _require_backend()
    msg_dict = dict(msg)
    event_id = compute_event_id(msg_dict)
    raw_id = bytes.fromhex(event_id)

    if _backend == "pynacl":
        sk = _signing.SigningKey(private_key_bytes)
        sig = sk.sign(raw_id).signature
    elif _backend == "cryptography":
        sk = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        sig = sk.sign(raw_id)
    else:
        raise RuntimeError(f"unreachable: backend={_backend}")

    msg_dict["event_id"] = event_id
    msg_dict["public_key_id"] = make_key_id(agent, public_key_bytes)
    msg_dict["signature"] = b64encode(sig)
    return msg_dict


def verify_message_v31(
    signed_msg: Mapping[str, Any],
    trust: Mapping[str, Any],
) -> tuple[bool, str]:
    """Verify v3.1 signed message against trust dict.

    trust shape (subset):
        {"agents": {"<handle>": {"public_keys": [{"key_id": "...", "key": "<b64>", "active": True}]}}}

    Returns (ok, reason). reason is "" on success.
    """
    _require_backend()

    for field in ("event_id", "public_key_id", "signature"):
        if field not in signed_msg:
            return False, f"missing {field}"

    claimed_id = signed_msg["event_id"]
    recomputed = compute_event_id(signed_msg)
    if claimed_id != recomputed:
        return False, f"event_id mismatch: claimed={claimed_id[:16]}... recomputed={recomputed[:16]}..."

    raw_id = bytes.fromhex(claimed_id)

    key_id = signed_msg["public_key_id"]
    if ":" not in key_id:
        return False, f"malformed public_key_id: {key_id}"
    claimed_agent, _ = key_id.split(":", 1)

    # Allow did:wire:<handle> in from-field; strip prefix for compare.
    from_value = signed_msg.get("from", "")
    if from_value.startswith("did:wire:"):
        from_value = from_value[len("did:wire:"):]
    if from_value != claimed_agent:
        return False, f"from={signed_msg.get('from')!r} mismatches public_key_id agent={claimed_agent!r}"

    agents = trust.get("agents", {})
    agent_entry = agents.get(claimed_agent) or agents.get(f"did:wire:{claimed_agent}")
    if not agent_entry:
        return False, f"agent {claimed_agent!r} not in trust list"

    matching_keys = [k for k in agent_entry.get("public_keys", []) if k.get("key_id") == key_id]
    if not matching_keys:
        return False, f"key_id {key_id!r} not found for agent {claimed_agent!r}"

    key_record = matching_keys[0]
    if not key_record.get("active", True):
        return False, f"key_id {key_id!r} is deactivated"

    public_key_bytes = b64decode(key_record["key"])

    try:
        sig_bytes = b64decode(signed_msg["signature"])
    except Exception as e:
        return False, f"signature not valid base64: {e}"

    try:
        if _backend == "pynacl":
            from nacl.signing import VerifyKey
            VerifyKey(public_key_bytes).verify(raw_id, sig_bytes)
        elif _backend == "cryptography":
            Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(sig_bytes, raw_id)
    except Exception as e:
        return False, f"signature verification failed: {type(e).__name__}"

    return True, ""


__all__ = [
    "KIND_RANGES",
    "KINDS",
    "b64decode",
    "b64encode",
    "canonical",
    "compute_event_id",
    "fingerprint",
    "generate_keypair",
    "kind_class",
    "make_key_id",
    "sign_message_v31",
    "verify_message_v31",
]
