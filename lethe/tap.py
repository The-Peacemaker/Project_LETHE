"""Phase 3: The Tap -- simulated NFC field.

The real system carries four things through the physical tap (an NDEF read
at < 10 cm): receiver public key, nonce, session metadata, challenge.
No file crosses this channel -- only trust information.

Hardware: NFC rings / ACR122U are not purchased yet, so `NfcField` stands in
for the electromagnetic field with a signed message file. The story on the
demo slide is literally true: only trust information moves here.
"""

import base64
import json
import os

from lethe.identity import DeviceIdentity
from lethe.ring import Ring


class TapError(Exception):
    pass


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _un64(s: str) -> bytes:
    return base64.b64decode(s.encode())


class NfcField:
    """One directory = one physical NFC field between sender and receiver."""

    def __init__(self, path):
        os.makedirs(path, exist_ok=True)
        self.path = path

    def put(self, msg: "TapMessage"):
        """Place a signed message into the field (the tap)."""
        with open(os.path.join(self.path, msg.tag + ".json"), "w") as f:
            json.dump(msg.to_dict(), f)

    def flush(self):
        for name in os.listdir(self.path):
            os.unlink(os.path.join(self.path, name))

    def take(self):
        """Pick up the latest message left in the field."""
        names = sorted(os.listdir(self.path))
        if not names:
            raise TapError("field is empty -- no tap detected")
        with open(os.path.join(self.path, names[-1])) as f:
            return TapMessage.from_dict(json.load(f))


class TapMessage:
    """A signed wrapper around the four tap fields + proof material."""

    def __init__(self, tag, sender_id, ring, eph_pub, nonce, challenge,
                 meta, signature, response=None):
        self.tag = tag                        # "tap1" | "tap2"
        self.sender_id = sender_id
        self.ring = ring                      # the sender's ring image
        self.eph_pub = eph_pub                # X25519 ephemeral public (32B)
        self.nonce = nonce                    # 16B fresh nonce
        self.challenge = challenge            # 32B random challenge
        self.meta = meta                      # session metadata dict
        self.signature = signature            # ed25519 over canon()
        self.response = response              # tap2 only: signed challenge

    # ------------------------------------------------------------ signing
    def canon(self) -> bytes:
        parts = [
            self.tag.encode(),
            self.sender_id.encode(),
            self.ring.pack(),
            self.eph_pub,
            self.nonce,
            self.challenge,
            json.dumps(self.meta, sort_keys=True).encode(),
        ]
        if self.response is not None:
            parts.append(self.response)
        return b"".join(parts)

    def verify(self) -> bool:
        """Signature validates against the sender's device public key."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import \
            Ed25519PublicKey
        try:
            Ed25519PublicKey.from_public_bytes(self.ring.device_pub).verify(
                self.signature, self.canon())
            return True
        except Exception:
            return False

    def to_dict(self):
        return {
            "tag": self.tag,
            "sender_id": self.sender_id,
            "ring": _b64(self.ring.pack()),
            "eph_pub": _b64(self.eph_pub),
            "nonce": _b64(self.nonce),
            "challenge": _b64(self.challenge),
            "meta": self.meta,
            "signature": _b64(self.signature),
            "response": _b64(self.response) if self.response else None,
        }

    @staticmethod
    def from_dict(d):
        return TapMessage(
            tag=d["tag"], sender_id=d["sender_id"],
            ring=Ring.unpack(_un64(d["ring"])),
            eph_pub=_un64(d["eph_pub"]), nonce=_un64(d["nonce"]),
            challenge=_un64(d["challenge"]), meta=d["meta"],
            signature=_un64(d["signature"]),
            response=_un64(d["response"]) if d.get("response") else None,
        )


def sign_message(tag, sender_id, identity: DeviceIdentity, ring: Ring,
                 eph_pub: bytes, nonce: bytes, challenge: bytes, meta: dict,
                 response: bytes = None) -> TapMessage:
    """Build a TapMessage signed by the device's keystore private key."""
    msg = TapMessage(tag, sender_id, ring, eph_pub, nonce, challenge, meta,
                     None, response)
    msg.signature = identity.sign(msg.canon())
    return msg


def verify_message(msg: TapMessage, issuer_pub: bytes) -> tuple:
    """Full tap audit: ring attestation + message signature.

    Returns (ring_ok, signature_ok); caller decides what to do next.
    """
    return msg.ring.verify(issuer_pub), msg.verify()