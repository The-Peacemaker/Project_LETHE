"""Phase 4 + 5 orchestrated: Mutual Authentication and Session Key.

`LetheDevice` encapsulates a device (identity + ring + keystore). Two devices
walk the handshake through the shared `NfcField`:

  1. bootstrap_tap      : sender taps -> trust-info lands in the field
  2. receive_tap        : receiver taps, verifies ring + signature, answers
                          the challenge, taps back its own half
  3. complete_handshake : sender verifies the answer; both derive the key

Attacker model respected here:
  - a forged tap fails signature verification (device key required)
  - a cloned/stolen ring alone fails: answering a challenge needs the
    keystore private key that never left the device
  - replay of a previous tap is rejected (nonce remembered, window checked)
"""

import os
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lethe.keys import (derive_aes_keys, eph_pub_bytes, new_eph,
                        shared_x25519)
from lethe.ring import Ring, ISSUER_PUB
from lethe.tap import NfcField, TapMessage, sign_message
from lethe.identity import DeviceIdentity

TP_WINDOW = 60           # seconds a tap stays fresh
REPLAY_MEMORY = 128      # nonces remembered per peer (FIFO)
AOTBC_MIN = 0.7          # admission gate: below this the tap is rejected
                         # fail-closed. No extra round exists in this build;
                         # the score never enters key derivation.


class HandshakeError(Exception):
    pass


class LetheDevice:
    """One LETHE device: a keystore identity bound to a provisioned ring."""

    def __init__(self, name, identity: DeviceIdentity, ring: Ring):
        self.name = name
        self.identity = identity
        self.ring = ring
        self._seen_nonces = {}   # ordered dict: nonce -> None (FIFO eviction)
        self._keys = {"session_id": None, "aes": None}

    # ------------------------------------------------------------ helpers
    def _remember(self, nonce):
        self._seen_nonces[nonce] = None
        while len(self._seen_nonces) > REPLAY_MEMORY:
            self._seen_nonces.pop(next(iter(self._seen_nonces)))  # oldest first

    def _audit(self, msg: TapMessage):
        if not msg.ring.verify(ISSUER_PUB):
            raise HandshakeError("ring signature invalid -- not made by LETHE")
        if not msg.verify():
            raise HandshakeError("tap signature invalid -- not signed by the ring holder")
        if abs(int(time.time()) - int(msg.meta.get("ts", 0))) > TP_WINDOW:
            raise HandshakeError("tap is stale -- timestamp outside window")
        if msg.nonce in self._seen_nonces:
            raise HandshakeError("replay detected -- nonce already seen")
        trust = float(msg.meta.get("trust_score", 1.0))
        if trust < AOTBC_MIN:
            raise HandshakeError(
                f"AOTBC: trust score {trust:.2f} < {AOTBC_MIN:.1f} -- "
                "tap rejected fail-closed (admission gate; no extra round "
                "in this build)")
        self._remember(msg.nonce)


def bootstrap_tap(dev: LetheDevice, field: NfcField, receiver_id: str,
                  trust_score: float = 1.0):
    """Sender taps first: ephemeral pub + challenge + metadata leave the ring.

    Exactly the four Phase-3 items cross this channel -- the file stays put.
    """
    eph = new_eph()
    meta = {
        "receiver": receiver_id,
        "sender": dev.name,
        "session": os.urandom(16).hex(),
        "ts": int(time.time()),
        "trust_score": round(trust_score, 3),
    }
    msg = sign_message("tap1", dev.name, dev.identity, dev.ring,
                       eph_pub_bytes(eph), os.urandom(16), os.urandom(32),
                       meta)
    field.put(msg)
    return eph, msg


def derive(dev: LetheDevice, eph, peer_pub: bytes, session_id: bytes):
    secret = shared_x25519(eph, peer_pub)
    dev._keys = {"session_id": session_id,
                 "aes": derive_aes_keys(secret, session_id)}
    return dev._keys["aes"]


def receive_tap(dev: LetheDevice, field: NfcField):
    """Receiver taps back: verify peer, sign the challenge, close the loop."""
    msg = field.take("tap1")
    dev._audit(msg)
    eph = new_eph()
    response = dev.identity.sign(msg.challenge)          # proof of keystore
    reply = sign_message(
        "tap2", dev.name, dev.identity, dev.ring,
        eph_pub_bytes(eph), os.urandom(16), msg.challenge,
        {"sender": dev.name,
         "receiver": msg.sender_id,
         "session": msg.meta["session"],
         "ts": int(time.time()),
         "trust_score": 1.0},
        response=response)
    field.put(reply)
    aes = derive(dev, eph, msg.eph_pub,
                 bytes.fromhex(msg.meta["session"]))
    return reply, aes


def complete_handshake(sender: LetheDevice, field: NfcField, sender_eph,
                       original: TapMessage):
    """Sender verifies the answer; both sides now hold the identical key."""
    msg = field.take("tap2")
    if msg.tag != "tap2":
        raise HandshakeError("expected a tap2 answer")
    if msg.meta.get("receiver") != sender.name:
        raise HandshakeError("answer addressed to someone else")
    if msg.meta.get("session") != original.meta["session"]:
        raise HandshakeError("session mismatch -- cross-wired transfer")
    if not msg.response:
        raise HandshakeError("peer never answered the challenge")
    if msg.challenge != original.challenge:
        raise HandshakeError("challenge mismatch -- peer signed a different nonce")
    sender._audit(msg)
    try:
        Ed25519PublicKey.from_public_bytes(msg.ring.device_pub).verify(
            msg.response, original.challenge)
    except Exception:
        raise HandshakeError("challenge-response failed -- authentication rejected")
    aes = derive(sender, sender_eph, msg.eph_pub,
                 bytes.fromhex(msg.meta["session"]))
    return aes, sender._keys["session_id"]