"""Cryptographic primitives used by the protocol:
SHA-256 hashing, expandable hashing, XOR masking, ECC-based hybrid encryption
(scalar randomness + AES-256-GCM), constant-time comparison."""

import hashlib
import hmac as _hmac
import os
from secrets import randbelow

from basepaper.curve import P, A, B, N, INF, mul, serialize, deserialize, GX, GY, BYTES


class CryptoError(Exception):
    pass


# ------------------------------------------------------------------ hashing
def h(data):
    """SHA-256 digest of data."""
    return hashlib.sha256(data).digest()


def h_ext(data, length):
    """Expandable hash: SHA-256 chained over a counter to yield `length` bytes."""
    out = b""
    counter = 0
    while len(out) < length:
        out += h(data + counter.to_bytes(4, "big"))
        counter += 1
    return out[:length]


def xor_bytes(a, b):
    """XOR of two byte strings, left-aligned to the shorter."""
    return bytes(x ^ y for x, y in zip(a, b))


def concat(*parts):
    return b"".join(parts)


# ------------------------------------------------------------------ keys on the curve
def keygen():
    private = randbelow(N - 1) + 1
    public = mul(private, (GX, GY))
    return private, public


def shared_secret(private, peer_public):
    return mul(private, peer_public)


# ------------------------------------------------------------------ ECC hybrid encryption (ECIES-style, AES-256-GCM)
def _aesgcm():
    from cryptography.hazmat.primitives.ciphers import aead
    return aead.AESGCM


def ecies_encrypt(public, plaintext):
    """Encrypt `plaintext` for `public` using ephemeral ECC keys + AES-256-GCM."""
    if plaintext is None:
        plaintext = b""
    r = randbelow(N - 1) + 1                     # ephemeral scalar r
    R = mul(r, (GX, GY))                          # ephemeral public key R = rG
    K = shared_secret(r, public)                  # shared point K = r*P_user
    key = h_ext(serialize(R) + serialize(K), 32)  # symmetric key derived from both points
    nonce = os.urandom(12)
    cipher = _aesgcm()(key)
    sealed = cipher.encrypt(nonce, plaintext, None)
    return serialize(R) + nonce + sealed


def ecies_decrypt(secret_scalar, blob):
    """Decrypt a blob produced by `ecies_encrypt`."""
    from basepaper.curve import is_identity

    serialized_height = 65  # 1 flag byte + 64 bytes of coordinates
    R = deserialize(blob[:serialized_height])
    if is_identity(R):
        raise CryptoError("received point at infinity")
    nonce = blob[serialized_height:serialized_height + 12]
    sealed = blob[serialized_height + 12:]
    K = shared_secret(secret_scalar, R)           # shared point K = d*R = rdG
    key = h_ext(serialize(R) + serialize(K), 32)
    cipher = _aesgcm()(key)
    try:
        return cipher.decrypt(nonce, sealed, None)
    except Exception:
        raise CryptoError("ciphertext authentication failed (tampered message)")


def ct_eq(a, b):
    """Constant-time equality of two byte strings."""
    return _hmac.compare_digest(a, b)