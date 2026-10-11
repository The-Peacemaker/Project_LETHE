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
    def seal_stream(self, src, dst):
        """Read `src`, write sealed frames to `dst`. Yields per-chunk stats.

        One session key seals every chunk; each chunk carries a fresh 96-bit
        nonce. The `.sha` manifest beside the sealed file is SHA-256 over the
        *ciphertext* (never the plaintext), so it leaks no plaintext oracle.
        """
        n = 0
        with open(src, "rb") as fin, open(dst, "wb") as fout:
            while True:
                piece = fin.read(CHUNK)
                if not piece:
                    break
                nonce = os.urandom(NONCE)
                sealed = self.box.encrypt(nonce, piece, None)
                fout.write(nonce + struct.pack(">I", len(sealed)) + sealed)
                n += 1
                yield n, len(piece)
        digest = hashlib.sha256()
        with open(dst, "rb") as f:
            for blk in iter(lambda: f.read(1 << 16), b""):
                digest.update(blk)
        open(dst + ".sha", "w").write(digest.hexdigest())
        return n

    def open_stream(self, src, dst):
        """Read sealed frames from `src`, verified bytes to `dst`.

        The ciphertext manifest is checked *before* any decryption, then every
        chunk tag is verified during the open. Either check failing rejects
        the whole file -- fail-closed.
        """
        digest = hashlib.sha256()
        with open(src, "rb") as f:
            for blk in iter(lambda: f.read(1 << 16), b""):
                digest.update(blk)
        try:
            with open(src + ".sha", "r") as f:
                expected = f.read().strip()
        except OSError:
            raise TransferError("integrity manifest missing -- file rejected")
        if expected != digest.hexdigest():
            raise TransferError("ciphertext manifest mismatch -- file rejected")
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
                piece = self._open_chunk(nonce + struct.pack(">I", ln) + body)
                fout.write(piece)
                n += 1
        return n, digest.hexdigest()

    # ------------------------------------------------------------ raw pipe
    def seal(self, plaintext: bytes) -> bytes:
        return self._seal_chunk(plaintext)

    def open(self, frame: bytes) -> bytes:
        return self._open_chunk(frame)


def seal_file(aes_key: bytes, src: str, dst: str):
    t = Transfer(aes_key)
    try:
        for _ in t.seal_stream(src, dst):
            pass
    except OSError as exc:
        raise TransferError(f"cannot read plaintext file: {exc}")


def open_file(aes_key: bytes, src: str, dst: str):
    t = Transfer(aes_key)
    try:
        n, h = t.open_stream(src, dst)
    except OSError as exc:
        raise TransferError(f"cannot read sealed file: {exc}")
    return n, h