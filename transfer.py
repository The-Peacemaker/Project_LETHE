"""Offline file protection (LETHE bridge): the session key agreed during the
base-paper handshake protects a real file with AES-256-GCM, one chunk at a time.
Chunk format on disk:  nonce(12) | length(4) | ciphertext(+16 tag)."""

import os
import struct

from basepaper.primitives import _aesgcm

CHUNK = 64 * 1024
NONCE = 12


class TransferError(Exception):
    pass


def encrypt_file(sk, src, dst, chunk=CHUNK):
    """Encrypt `src` under the 32-byte session key `sk` into `dst`."""
    if len(sk) != 32:
        raise TransferError("session key must be 32 bytes (AES-256)")
    box = _aesgcm()(sk)
    frames = 0
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        while True:
            piece = fin.read(chunk)
            if not piece:
                break
            nonce = os.urandom(NONCE)
            sealed = box.encrypt(nonce, piece, None)
            fout.write(nonce + struct.pack(">I", len(sealed)) + sealed)
            frames += 1
    return frames


def decrypt_file(sk, src, dst):
    """Decrypt `src` under `sk` into `dst`; raises TransferError on tampering."""
    if len(sk) != 32:
        raise TransferError("session key must be 32 bytes (AES-256)")
    box = _aesgcm()(sk)
    try:
        with open(src, "rb") as fin, open(dst, "wb") as fout:
            while True:
                nonce = fin.read(NONCE)
                if not nonce:
                    break
                if len(nonce) != NONCE:
                    raise TransferError("truncated frame header")
                (n,) = struct.unpack(">I", fin.read(4))
                sealed = fin.read(n)
                if len(sealed) != n:
                    raise TransferError("truncated frame body")
                fout.write(box.decrypt(nonce, sealed, None))
    except TransferError:
        raise
    except Exception as exc:
        raise TransferError(f"authentication failed -- file rejected ({exc})")


def head_hex(path, n=48):
    """First `n` bytes of a file as hex, for showing plaintext vs noise."""
    with open(path, "rb") as f:
        return f.read(n).hex()