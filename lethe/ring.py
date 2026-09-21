"""Phase 2: Ring Initialisation (NTAG215) -- the ring is a key, not a container.

Exactly four fields are written to the (approximately) 504 usable bytes of an
NTAG215 tag, here serialised to 96 bytes:

  Owner ID           |  16 bytes | UUID for this ring
  Device Public Key  |  32 bytes | ed25519 public key
  Recovery Code Hash |  16 bytes | SHA256(recovery_code)[:16]
  Signature          |  64 bytes | issuer's ed25519 signature (ed25519 sigs are 64)

The signature binds owner_id + device_pub + recovery_hash under a long-lived
"LETHE issuer" key (the provisioning authority). Any reader with the issuer
public key can verify the ring was genuinely manufactured by LETHE. A stolen
ring still cannot authenticate: finishing the protocol requires signing a
challenge with the device private key, which never leaves the keystore.
"""

import hashlib
import os
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from lethe.identity import DeviceIdentity

RAW = serialization.Encoding.Raw

RING_MAX_BYTES = 504                     # NTAG215 usable payload
OWNER = 16
DEVPUB = 32
REC = 16
SIG = 64
LAYOUT = f"!{OWNER}s{DEVPUB}s{REC}s{SIG}s"   # 96 bytes packed

# The LETHE issuing authority (simulated `provisioning script` on the laptop).
# A real build ships only ISSUER_PUB inside the app; the private half never
# leaves the factory laptop. Generated here so the demo is self-contained.
_ISSUER = Ed25519PrivateKey.generate()
ISSUER_PRIV = _ISSUER.private_bytes(RAW, serialization.PrivateFormat.Raw,
                                    serialization.NoEncryption())
ISSUER_PUB = _ISSUER.public_key().public_bytes(RAW, serialization.PublicFormat.Raw)


def _issuer_verifier():
    return Ed25519PublicKey.from_public_bytes(ISSUER_PUB)


class RingError(Exception):
    pass


class Ring:
    """A portable root of trust: the compressed NTAG215 payload."""

    __slots__ = ("owner_id", "device_pub", "recovery_hash", "signature")

    def __init__(self, owner_id, device_pub, recovery_hash, signature):
        if len(owner_id) != OWNER:
            raise RingError(f"Owner ID must be {OWNER} bytes")
        if len(device_pub) != DEVPUB:
            raise RingError("Device public key must be 32 bytes (ed25519)")
        if len(recovery_hash) != REC:
            raise RingError("Recovery code hash must be 16 bytes")
        if len(signature) != SIG:
            raise RingError("Signature must be 64 bytes (ed25519)")
        self.owner_id = owner_id
        self.device_pub = device_pub
        self.recovery_hash = recovery_hash
        self.signature = signature

    # ------------------------------------------------------------- bytes
    def pack(self) -> bytes:
        """96-byte payload -- comfortably inside the 504-byte NTAG215 area."""
        return struct.pack(LAYOUT, self.owner_id, self.device_pub,
                           self.recovery_hash, self.signature)

    @staticmethod
    def unpack(blob: bytes) -> "Ring":
        if blob is None or len(blob) > RING_MAX_BYTES:
            raise RingError(f"payload is not a valid NTAG215 image ({len(blob) or 0} bytes)")
        if len(blob) < struct.calcsize(LAYOUT):
            raise RingError("truncated ring image")
        a, b, c, d = struct.unpack(LAYOUT, blob[:struct.calcsize(LAYOUT)])
        return Ring(a, b, c, d)

    @property
    def size_bytes(self) -> int:
        return len(self.pack())

    # --------------------------------------------------------- attestation
    def _canon(self) -> bytes:
        return self.owner_id + self.device_pub + self.recovery_hash

    def verify(self, issuer_pub: bytes = ISSUER_PUB) -> bool:
        """True iff `issuer` genuinely manufactured this ring."""
        try:
            Ed25519PublicKey.from_public_bytes(issuer_pub).verify(
                self.signature, self._canon())
            return True
        except Exception:
            return False

    @staticmethod
    def short(pub: bytes) -> str:
        return pub.hex()[:8] + "..."


def provision_ring(device: DeviceIdentity, recovery_code: str,
                   issuer_priv: bytes = ISSUER_PRIV) -> Ring:
    """Provision a ring for `device` (run once, via the ACR122U laptop).

    Signature = issuer.sign(owner_id || device_pub || recovery_hash).
    """
    owner_id = os.urandom(16)
    recovery_hash = hashlib.sha256(recovery_code.encode()).digest()[:REC]
    canon = owner_id + device.public + recovery_hash
    sig = Ed25519PrivateKey.from_private_bytes(issuer_priv).sign(canon)
    return Ring(owner_id, device.public, recovery_hash, sig)