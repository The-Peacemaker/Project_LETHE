"""LETHE core brain -- a zero-trust, offline, wearable-NFC-anchored
secure file exchange framework running on the PC.

Pipeline implemented here:
  identity (ed25519) -> ring init (NTAG215 layout) -> tap (simulated NFC)
  -> mutual auth (challenge-response) -> session key (X25519 ECDH + HKDF)
  -> file transfer (AES-256-GCM) -> policy engine -> cryptographic erasure.

The NFC hardware (rings, ACR122U) is not purchased yet, so the physical tap
is simulated by a signed message file dropped into an "NFC field" directory.

Resistant to all known attack vectors within the stated threat model --
never "unhackable".
"""

from lethe.identity import DeviceIdentity, identity_from_file, identity_to_file
from lethe.ring import Ring, provision_ring, ISSUER_PUB, ISSUER_PRIV, RING_MAX_BYTES
from lethe.tap import NfcField, TapMessage, sign_message, verify_message
from lethe.handshake import (bootstrap_tap, receive_tap, complete_handshake,
                             HandshakeError, LetheDevice)
from lethe.keys import derive_aes_keys, FSKE, shared_x25519
from lethe.transfer import (Transfer, TransferError, seal_file, open_file)
from lethe.policy import Policy, SignedEnvelope, enforce_policy, PolicyError
from lethe.erasure import KeySlot, shred

__all__ = [
    "DeviceIdentity", "identity_from_file", "identity_to_file",
    "Ring", "provision_ring", "ISSUER_PUB", "ISSUER_PRIV", "RING_MAX_BYTES",
    "NfcField", "TapMessage", "sign_message", "verify_message",
    "bootstrap_tap", "receive_tap", "complete_handshake", "HandshakeError",
    "LetheDevice",
    "derive_aes_keys", "FSKE", "shared_x25519",
    "Transfer", "TransferError", "seal_file", "open_file",
    "Policy", "SignedEnvelope", "enforce_policy", "PolicyError",
    "KeySlot", "shred",
]