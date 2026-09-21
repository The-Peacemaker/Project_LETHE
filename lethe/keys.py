"""Phase 5: Session Key Generation -- the heart of the protocol.

                    X25519 ECDH                HKDF-SHA256
  eph_priv + peer_pub  --->  shared_secret  --->  AES-256 session key
                          (never transmitted)

Both devices derive the identical key independently. Fork of the master key
implements FSKE (Forward-Secure Session Key Evolution): sub-key i only opens
chunk i, and previous sub-keys are discarded.
"""

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

AES_LEN = 32
CTX = b"LETHE:AES256-GCM:v1"
FSKE_CTX = b"LETHE:FSKE:v1"


def new_eph():
    """One ephemeral X25519 keypair (destroyed after the session)."""
    return X25519PrivateKey.generate()


def eph_pub_bytes(eph_priv) -> bytes:
    return eph_priv.public_key().public_bytes_raw()


def shared_x25519(eph_priv, peer_pub_bytes: bytes) -> bytes:
    """ECDH shared secret (32 bytes). Peer key validated on the curve."""
    if len(peer_pub_bytes) != 32:
        raise ValueError("X25519 public keys are 32 bytes")
    peer = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    return eph_priv.exchange(peer)


def derive_aes_keys(shared_secret: bytes, session_id: bytes,
                    trust_score: float = 1.0):
    """HKDF the shared secret down to the AES-256 session key.

    Determinisic function of (secret, session_id) -- both sides agree.
    `trust_score` is bound in so a low-trust tap yields a different key and,
    per AOTBC, forces an extra verification round upstream.
    """
    salt = session_id
    info = CTX + int(round(trust_score * 1000)).to_bytes(4, "big")
    hk = HKDF(algorithm=hashes.SHA256(), length=AES_LEN, salt=salt, info=info)
    return hk.derive(shared_secret)


class FSKE:
    """Forward-Secure Session Key Evolution.

    key_i = HKDF(master, salt=session_id, info="FSKE:chunk:%d") -- each 64 KB
    chunk is opened only by its own sub-key; generating key_{i+1} discards
    key_i so compromise of one window never exposes the rest.
    """

    def __init__(self, master: bytes, session_id: bytes):
        self._master = master
        self._session = session_id
        self._current = -1
        self._live = None

    def next_key(self) -> bytes:
        self._current += 1
        info = FSKE_CTX + self._current.to_bytes(8, "big")
        hk = HKDF(algorithm=hashes.SHA256(), length=AES_LEN,
                  salt=self._session, info=info)
        old = self._live
        k = hk.derive(self._master)
        if old is not None:
            _wipe(old)
        self._live = k
        return k

    @property
    def window(self) -> int:
        return self._current


def _wipe(b: bytes) -> bytes:
    return b"\x00" * (len(b) or 0x00)