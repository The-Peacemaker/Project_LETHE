"""Phase 5: Session Key Generation -- the heart of the protocol.

                    X25519 ECDH                HKDF-SHA256
  eph_priv + peer_pub  --->  shared_secret  --->  AES-256 session key
                           (never transmitted)

Both devices derive the identical key independently: the HKDF inputs are
the shared secret and the session identifier only, so any two peers that
complete the same tap necessarily agree. Trust scoring lives one layer up
as an admission gate in the handshake -- it never enters key derivation,
because asymmetric inputs would silently fork the key (see history).

Per-chunk key evolution (ratcheted FSKE) is designed but NOT enabled in
this prototype: the flight uses one session key with a fresh 96-bit GCM
nonce per 64 KB chunk. A ratchet is future work for multi-file sessions.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

AES_LEN = 32
CTX = b"LETHE:AES256-GCM:v1"


def new_eph():
    """One ephemeral X25519 keypair (destroyed after the session)."""
    return X25519PrivateKey.generate()


def eph_pub_bytes(eph_priv) -> bytes:
    return eph_priv.public_key().public_bytes_raw()


def shared_x25519(eph_priv, peer_pub_bytes: bytes) -> bytes:
    """ECDH shared secret (32 bytes).

    Rejects malformed peers and the all-zero shared secret per RFC 7748:
    a low-order or zero peer public value must never yield a usable key.
    """
    if len(peer_pub_bytes) != 32:
        raise ValueError("X25519 public keys are 32 bytes")
    if peer_pub_bytes == b"\x00" * 32:
        raise ValueError("X25519 peer public key must not be all zero")
    peer = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared = eph_priv.exchange(peer)
    if shared == b"\x00" * 32:
        raise ValueError("X25519 shared secret is all zero -- aborting")
    return shared


def derive_aes_keys(shared_secret: bytes, session_id: bytes):
    """HKDF the shared secret down to the AES-256 session key.

    Deterministic function of (secret, session_id) only -- both sides agree
    by construction, regardless of any admission-gate scoring upstream.
    """
    hk = HKDF(algorithm=hashes.SHA256(), length=AES_LEN,
              salt=session_id, info=CTX)
    return hk.derive(shared_secret)


def zero_buf(buf: bytearray):
    """Overwrite a mutable key buffer in place.

    Honest limit: CPython may retain immutable copies elsewhere (copies handed
    to AESGCM, GC arenas). This wipes the buffer we control; it is best
    effort, not a memory-safety proof -- stated openly.
    """
    for i in range(len(buf)):
        buf[i] = 0
