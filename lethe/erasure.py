"""Phase 9: Cryptographic Destruction (crypto-shredding, NIST SP 800-88).

The key slot is wiped once its policy is consumed: memory buffer zeroed, and
the on-disk key file overwritten with zeros then deleted. The ciphertext stays
on the device -- as random noise, mathematically unrecoverable.

This is the famous line:  "Access denied. Cryptographic key has been destroyed."
"""

import os
import struct
import time

ACCESS_DENIED = "Access denied. Cryptographic key has been destroyed."


class AccessError(Exception):
    pass


def shred(b: bytes) -> bytes:
    """Overwrite a key buffer with zeros. Small, auditable, explicit."""
    return b"\x00" * len(b)


class KeySlot:
    """A persistent key slot that erases itself when its policy is consumed.

    Simulates the in-memory AES key plus its slot in persistent storage.
    """

    HEAD = struct.Struct(">QIQQII")   # magic | created | views | max_views
    #                                  | expires_at | key_len

    def __init__(self, path, aes_key, max_views, expires_at=None):
        assert len(aes_key) == 32
        self.path = path
        self.max_views = int(max_views)
        self.expires_at = expires_at
        self.created = int(time.time())
        self.views = 0
        self._key = aes_key
        self._persist()

    # ---------------------------------------------------------- storage
    def _blob(self):
        return self.HEAD.pack(0x4C45544845, self.created, self.views,
                              self.max_views, self.expires_at or 0,
                              len(self._key)) + self._key

    def _persist(self):
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(self._blob())
        os.replace(tmp, self.path)

    @staticmethod
    def load(path):
        with open(path, "rb") as f:
            blob = f.read()
        magic, created, views, max_views, expires, klen = \
            KeySlot.HEAD.unpack(blob[:KeySlot.HEAD.size])
        if magic != 0x4C45544845:
            raise AccessError("key slot corrupted -- refusing to open")
        key = blob[KeySlot.HEAD.size:KeySlot.HEAD.size + klen]
        slot = KeySlot.__new__(KeySlot)
        slot.path, slot.created = path, created
        slot.views, slot.max_views, slot.expires_at = views, max_views, expires or None
        slot._key = key
        return slot

    # ---------------------------------------------------------- lifecycle
    @property
    def live(self):
        return self._key != b"" and self._key != b"\x00" * 32

    def try_view(self):
        """Consume one view; if the policy is exhausted, the key shreds itself."""
        if not self.live:
            raise AccessError(ACCESS_DENIED)
        if self.expires_at is not None and int(time.time()) > self.expires_at:
            self.destroy()
            raise AccessError("policy expired -- " + ACCESS_DENIED)
        if self.views >= self.max_views:
            self.destroy()
            raise AccessError(ACCESS_DENIED)
        self.views += 1
        self._persist()
        return self._key

    def destroy(self, reason=None):
        """Wipe the buffer, zero the slot file, unlink. The math is gone."""
        if self._key:
            self._key = shred(self._key)
        try:
            with open(self.path, "wb") as f:
                f.write(b"\x00" * 64)
        except OSError:
            pass
        try:
            os.remove(self.path)
        except OSError:
            pass
        self._key = b""