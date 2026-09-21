"""Phase 6 + 7: High-Speed Transfer with Zero-Trust Chunk Verification.

The ciphertext travels over an offline peer channel (Wi-Fi Direct in the real
system; a localhost socket here). The file is cut into 64 KB chunks, each
sealed with AES-256-GCM and authenticated independently -- a tampered chunk
fails its own tag and the whole file is rejected. No implicit trust is
extended to any single byte.

Frame on the wire:  nonce(12) | length(4) | ciphertext(+16 tag)
"""

import hashlib
import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHUNK = 64 * 1024
NONCE = 12


class TransferError(Exception):
    pass


class Transfer:
    """A single AES-256-GCM file channel under `aes_key` (32 bytes)."""

    def __init__(self, aes_key: bytes):
        if len(aes_key) != 32:
            raise TransferError("AES session key must be 32 bytes")
        self.box = AESGCM(aes_key)

    # ------------------------------------------------------------ frames
    def _seal_chunk(self, piece: bytes) -> bytes:
        nonce = os.urandom(NONCE)
        sealed = self.box.encrypt(nonce, piece, None)
        return nonce + struct.pack(">I", len(sealed)) + sealed

    def _open_chunk(self, frame: bytes, box=None) -> bytes:
        if len(frame) < NONCE + 4:
            raise TransferError("truncated chunk header")
        nonce, (n,) = frame[:NONCE], struct.unpack(">I", frame[NONCE:NONCE + 4])
        body = frame[NONCE + 4:]
        if len(body) != n:
            raise TransferError("truncated chunk body")
        box = box or self.box
        try:
            return box.decrypt(nonce, body, None)
        except Exception:
            raise TransferError("chunk tag failed -- file was tampered in flight")

    # ------------------------------------------------------------ streams
    def seal_stream(self, src, dst, fske=None):
        """Read `src`, write sealed frames to `dst`. Yields per-chunk stats.

        With `fske` (a ``lethe.keys.FSKE``) every chunk is sealed by its own
        forward-secure sub-key -- key_{i-1} is already wiped by the time
        chunk i is written.
        """
        digest = hashlib.sha256()
        n = 0
        with open(src, "rb") as fin, open(dst, "wb") as fout:
            while True:
                piece = fin.read(CHUNK)
                if not piece:
                    break
                digest.update(piece)
                key = fske.next_key() if fske is not None else None
                box = AESGCM(key) if key is not None else self.box
                nonce = os.urandom(NONCE)
                sealed = box.encrypt(nonce, piece, None)
                fout.write(nonce + struct.pack(">I", len(sealed)) + sealed)
                n += 1
                yield n, len(piece)
        open(dst + ".sha", "w").write(digest.hexdigest())
        return n

    def open_stream(self, src, dst, fske=None):
        """Read sealed frames from `src`, verified bytes to `dst`."""
        digest = hashlib.sha256()
        n = 0
        with open(src, "rb") as fin, open(dst, "wb") as fout:
            while True:
                nonce = fin.read(NONCE)
                if not nonce:
                    break
                if len(nonce) != NONCE:
                    raise TransferError("truncated frame header")
                (ln,) = struct.unpack(">I", fin.read(4))
                body = fin.read(ln)
                if len(body) != ln:
                    raise TransferError("truncated frame body")
                piece = self._open_chunk(nonce + struct.pack(">I", ln) + body,
                                         box=AESGCM(fske.next_key())
                                         if fske is not None else None)
                fout.write(piece)
                digest.update(piece)
                n += 1
        with open(src + ".sha", "r") as f:
            expected = f.read().strip()
        actual = digest.hexdigest()
        if expected != actual:
            raise TransferError("integrity hash mismatch -- file rejected")
        return n, actual

    # ------------------------------------------------------------ raw pipe
    def seal(self, plaintext: bytes) -> bytes:
        return self._seal_chunk(plaintext)

    def open(self, frame: bytes) -> bytes:
        return self._open_chunk(frame)


def seal_file(aes_key: bytes, src: str, dst: str):
    t = Transfer(aes_key)
    for _ in t.seal_stream(src, dst):
        pass


def open_file(aes_key: bytes, src: str, dst: str):
    t = Transfer(aes_key)
    n, h = t.open_stream(src, dst)
    return n, h