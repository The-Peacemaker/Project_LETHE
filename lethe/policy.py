"""Phase 8: Policy Engine (PCCP -- Policy-Constrained Ciphertext Packaging).

Every encrypted package rides inside a signed JSON envelope whose policy the
receiver cannot alter: max views, expiry, recipient, destruction mode. The
signature binds policy + integrity hash to the ciphertext under the sender's
ed25519 key, so any post-production edit invalidates the package.

    {
      "filename": "Mission.enc",
      "policy": {"max_views": 1, "expires_at": 1735689600,
                 "recipient": "officer-bravo", "destruction": "cryptographic_erasure"},
      "integrity_hash": "sha256:...",
      "signature": "ed25519:..."
    }
"""

import hashlib
import json
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

INTEGRITY = "sha256:"
SIG = "ed25519:"


class PolicyError(Exception):
    pass


class Policy:
    """The immutable access contract on an encrypted package."""

    __slots__ = ("max_views", "expires_at", "recipient", "destruction", "note")

    def __init__(self, max_views=1, expires_at=None, recipient="*",
                 destruction="cryptographic_erasure", note=""):
        self.max_views = int(max_views)
        self.expires_at = expires_at            # unix ts or None = no expiry
        self.recipient = recipient              # "*" = anyone with the key
        self.destruction = destruction
        self.note = note

    def as_dict(self):
        return {
            "max_views": self.max_views,
            "expires_at": self.expires_at,
            "recipient": self.recipient,
            "destruction": self.destruction,
            "note": self.note,
        }

    @staticmethod
    def from_dict(d):
        return Policy(**d)


class SignedEnvelope:
    """PCCP: policy + integrity hash + sender signature, one atomic blob."""

    def __init__(self, filename, policy: Policy, sender_pub: bytes,
                 integrity_hash=None, signature=None):
        self.filename = filename
        self.policy = policy
        self.sender_pub = sender_pub
        self.integrity_hash = integrity_hash
        self.signature = signature

    # ---------------------------------------------------------- building
    def canon(self) -> bytes:
        return json.dumps({
            "filename": self.filename,
            "policy": self.policy.as_dict(),
            "sender_pub": self.sender_pub.hex(),
            "integrity_hash": self.integrity_hash,
        }, sort_keys=True, separators=(",", ":")).encode()

    def to_dict(self):
        return {
            "filename": self.filename,
            "policy": self.policy.as_dict(),
            "sender_pub": self.sender_pub.hex(),
            "integrity_hash": self.integrity_hash,
            "signature": self.signature,
        }

    def save(self, path):
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @staticmethod
    def load(path) -> "SignedEnvelope":
        with open(path) as f:
            d = json.load(f)
        return SignedEnvelope(d["filename"], Policy.from_dict(d["policy"]),
                              bytes.fromhex(d["sender_pub"]),
                              d["integrity_hash"], d["signature"])

    # ---------------------------------------------------------- checking
    def verify_signature(self) -> bool:
        """Policy + integrity hash untampered: still what the sender signed."""
        if not (self.signature and self.integrity_hash):
            return False
        try:
            Ed25519PublicKey.from_public_bytes(self.sender_pub).verify(
                bytes.fromhex(self.signature[len(SIG):]), self.canon())
            return True
        except Exception:
            return False

    def check_integrity(self, ciphertext: bytes) -> bool:
        if not self.integrity_hash:
            return False
        expect = self.integrity_hash[len(INTEGRITY):]
        return hashlib.sha256(ciphertext).hexdigest() == expect


def seal_package(filename, policy: Policy, ciphertext: bytes,
                 sender_priv: Ed25519PrivateKey) -> SignedEnvelope:
    """Build a signed PCCP envelope; signature binds policy + integrity hash."""
    env = SignedEnvelope(filename, policy, sender_priv.public_key().public_bytes_raw())
    env.integrity_hash = INTEGRITY + hashlib.sha256(ciphertext).hexdigest()
    env.signature = SIG + sender_priv.sign(env.canon()).hex()
    return env


def enforce_policy(env: SignedEnvelope, viewer_id: str, now=None):
    """Phase-8 gatekeeper: every access is re-verified, zero-trust style."""
    now = int(time.time()) if now is None else int(now)
    if not env.verify_signature():
        raise PolicyError("envelope signature invalid -- policy tampered")
    p = env.policy
    if p.expires_at is not None and now > p.expires_at:
        raise PolicyError("policy expired -- access denied by timestamp")
    if p.recipient != "*" and p.recipient != viewer_id:
        raise PolicyError(f"recipient '{viewer_id}' not authorised -- access denied")
    if p.max_views < 1:
        raise PolicyError("view limit exhausted -- access denied")