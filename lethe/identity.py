"""Phase 1: Device Identity -- ed25519 keypair created on first launch.

The private key lives in a "keystore" (here, an owner-only file that stands
in for Android Keystore / a hardware-backed secure element). It never leaves
the device; only the 32-byte public key is ever shared.
"""

import os
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

RAW = serialization.Encoding.Raw


class DeviceIdentity:
    """An ed25519 identity for one device / user (the de facto device cert)."""

    def __init__(self, name="device"):
        self.uid = uuid.uuid4().bytes            # 16-byte device UUID
        self.name = name
        self._priv = Ed25519PrivateKey.generate()

    # ------------------------------------------------------------ public
    @property
    def public(self) -> bytes:
        """32-byte ed25519 public key."""
        return self._priv.public_key().public_bytes(RAW, serialization.PublicFormat.Raw)

    @property
    def verifier(self):
        return Ed25519PublicKey.from_public_bytes(self.public)

    def sign(self, data: bytes) -> bytes:
        """ed25519 signature over `data` (64 bytes)."""
        return self._priv.sign(data)

    def priv_bytes(self) -> bytes:
        """32-byte private key for persistence (the secret material)."""
        return self._priv.private_bytes(RAW, serialization.PrivateFormat.Raw,
                                        serialization.NoEncryption())

    def raw_priv(self):
        """The underlying ed25519 private key object (for envelope signing).

        Prefer `sign()` for protocol use; this accessor exists for the
        explicit sender-side packaging step and nothing else.
        """
        return self._priv


def identity_from_file(path, name=None):
    """Load an identity saved by `identity_to_file`; new keypair if missing."""
    if os.path.exists(path):
        with open(path, "rb") as f:
            raw = f.read(32)
        priv = Ed25519PrivateKey.from_private_bytes(raw)
        ident = DeviceIdentity(name or os.path.basename(path))
        ident._priv = priv
        return ident
    return DeviceIdentity(name or os.path.basename(path))


def identity_to_file(ident, path):
    """Persist the 32-byte private key with owner-only permissions.

    This simulates Android Keystore: the same key material that the
    secure element would hold, written as an opaque blob no other app
    should read.
    """
    with open(path, "wb") as f:
        f.write(ident.priv_bytes())
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass