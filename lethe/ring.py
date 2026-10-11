"""Phase 2: Ring Initialisation (NTAG215) -- the ring is a key, not a container.

Exactly four fields are written to the (approximately) 504 usable bytes of an
NTAG215 tag, here serialised to 128 bytes:

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
LAYOUT = f"!{OWNER}s{DEVPUB}s{REC}s{SIG}s"   # 128 bytes packed

# The LETHE issuing authority (the factory provisioning laptop).
# Trust split: verifiers need ONLY the public half. `issuer.key` (private,
# owner-only, git-ignored) is touched solely by provision_ring(); every other
# path -- including verification on a receiving device -- uses `issuer.pub`.
# A shipped build therefore carries the public key file alone, never the
# private key. Persistence means rings provisioned in one run verify in later
# runs on any machine holding the same public key.
_ISSUER_DIR = os.path.dirname(os.path.abspath(__file__))
_ISSUER_PRIV_PATH = os.path.join(_ISSUER_DIR, "issuer.key")
_ISSUER_PUB_PATH = os.path.join(_ISSUER_DIR, "issuer.pub")


def _load_issuer_priv():
    """Private half -- provisioning only. Never import this elsewhere."""
    if os.path.exists(_ISSUER_PRIV_PATH):
        with open(_ISSUER_PRIV_PATH, "rb") as f:
            return Ed25519PrivateKey.from_private_bytes(f.read(32))
    key = Ed25519PrivateKey.generate()
    with open(_ISSUER_PRIV_PATH, "wb") as f:
        f.write(key.private_bytes(RAW, serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption()))
    try:
        os.chmod(_ISSUER_PRIV_PATH, 0o600)
    except OSError:
        pass
    _write_issuer_pub(key)
    return key


def _write_issuer_pub(key):
    with open(_ISSUER_PUB_PATH, "wb") as f:
        f.write(key.public_key().public_bytes(RAW,
                                              serialization.PublicFormat.Raw))


def _load_issuer_pub() -> bytes:
    """Public half -- the only issuer material a verifying device needs."""
    if os.path.exists(_ISSUER_PUB_PATH):
        with open(_ISSUER_PUB_PATH, "rb") as f:
            return f.read(32)
    if os.path.exists(_ISSUER_PRIV_PATH):
        with open(_ISSUER_PRIV_PATH, "rb") as f:
            key = Ed25519PrivateKey.from_private_bytes(f.read(32))
    else:
        key = _load_issuer_priv()   # first run ever: create the pair
    _write_issuer_pub(key)          # pin the public half for clones/verifiers
    return key.public_key().public_bytes(RAW, serialization.PublicFormat.Raw)


ISSUER_PUB = _load_issuer_pub()


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
        """128-byte payload -- comfortably inside the 504-byte NTAG215 area."""
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
                   issuer_priv: bytes = None) -> Ring:
    """Provision a ring for `device` (run once, via the factory laptop or an NFC phone).

    Signature = issuer.sign(owner_id || device_pub || recovery_hash).
    The issuer private key is loaded here and only here.
    """
    owner_id = os.urandom(16)
    recovery_hash = hashlib.sha256(recovery_code.encode()).digest()[:REC]
    canon = owner_id + device.public + recovery_hash
    if issuer_priv is None:
        issuer_priv = _load_issuer_priv().private_bytes(
            RAW, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    sig = Ed25519PrivateKey.from_private_bytes(issuer_priv).sign(canon)
    return Ring(owner_id, device.public, recovery_hash, sig)