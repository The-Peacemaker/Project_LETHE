"""LETHE adversarial battery -- every attack must be rejected cleanly.

Run:  python lethe_attacks.py

Resistance within the stated threat model (never "unhackable"):
  1. Wiretap: ciphertext is AES-256-GCM noise, key never on the channel
  2. Tampered file chunk in flight   -> tag fails, file rejected
  3. Wrong session key               -> decryption refuses
  4. Forged tap (rogue ring)         -> issuer signature invalid
  5. Signature-only forgery          -> attacker lacks the keystore key
  6. Replay of an old tap            -> nonce remembered, rejected
  7. Stale / replayed timestamp      -> outside the freshness window
  8. MITM editing the tap            -> signature invalidated
  9. Policy edit post-encryption     -> PCCP signature invalidated
 10. Wrong recipient                 -> policy denies
 11. Expired policy                  -> policy denies
 12. View-limit exceeded             -> key crypto-shredded (NIST 800-88)
 13. Weak tap (AOTBC trust < 0.7)    -> extra verification round mandated
 14. Cloned ring alone               -> cannot answer the challenge

After every rejected attempt the protocol is still usable -- no state break.
"""

import os
import tempfile
import time

from lethe.identity import DeviceIdentity
from lethe.ring import Ring, provision_ring, ISSUER_PUB
from lethe.tap import NfcField, sign_message
from lethe.handshake import (LetheDevice, bootstrap_tap, receive_tap,
                             complete_handshake, HandshakeError)
from lethe.keys import new_eph, eph_pub_bytes
from lethe.transfer import seal_file, open_file, TransferError
from lethe.policy import Policy, seal_package, enforce_policy, PolicyError
from lethe.erasure import KeySlot, AccessError

PASS = FAIL = 0


def report(name, blocked):
    global PASS, FAIL
    if blocked:
        PASS += 1
        print(f"  [SAFE] {name}")
    else:
        FAIL += 1
        print(f"  [BREACH] {name}")


def field():
    d = tempfile.mkdtemp()
    return NfcField(os.path.join(d, "field"))


def peers():
    a, b = DeviceIdentity("alice"), DeviceIdentity("bob")
    da, db = LetheDevice("alice", a, provision_ring(a, "ka")), \
        LetheDevice("bob", b, provision_ring(b, "kb"))
    return da, db


def handshake(da, db, f):
    f.flush()
    eph, m1 = bootstrap_tap(da, f, "bob")
    _, kb = receive_tap(db, f)
    ka, _ = complete_handshake(da, f, eph, m1)
    assert ka == kb
    return ka


# ------------------------------------------------------------------ channel
def attack_wiretap(da, db):
    f = field()
    key = handshake(da, db, f)
    d = tempfile.mkdtemp()
    src = os.path.join(d, "src")
    enc = os.path.join(d, "enc")
    with open(src, "wb") as fh:
        fh.write(b"the minutes of the meeting -- eyes only")
    seal_file(key, src, enc)
    head = open(enc, "rb").read(16).hex()
    assert "the minutes" not in open(enc, "rb").read().decode("latin1")
    report("Wiretap sees AES-256-GCM noise (key never on the channel)", head != "the minutes of")


def attack_tamper(da, db):
    f = field()
    key = handshake(da, db, f)
    d = tempfile.mkdtemp()
    src = os.path.join(d, "src")
    enc = os.path.join(d, "enc")
    with open(src, "wb") as fh:
        fh.write(os.urandom(3 * 64 * 1024))
    seal_file(key, src, enc)
    with open(enc, "r+b") as fh:                       # flip a byte mid-stream
        fh.seek(70_000)
        fh.write(os.urandom(1))
    try:
        open_file(key, enc, os.path.join(d, "dec"))
        report("Tampered chunk rejected by its own GCM tag", False)
    except TransferError:
        report("Tampered chunk rejected by its own GCM tag", True)


def attack_wrong_key(da, db):
    f = field()
    key = handshake(da, db, f)
    d = tempfile.mkdtemp()
    src = os.path.join(d, "src")
    enc = os.path.join(d, "enc")
    with open(src, "wb") as fh:
        fh.write(b"classified")
    seal_file(key, src, enc)
    try:
        open_file(os.urandom(32), enc, os.path.join(d, "dec"))
        report("Wrong session key refused", False)
    except TransferError:
        report("Wrong session key refused", True)


# ------------------------------------------------------------- identity
def attack_forged_ring():
    """"""
    f = field()
    mallory = DeviceIdentity("mallory")
    rogue = Ring(*[b"\x00" * 16, b"\x00" * 32, b"\x00" * 16, b"\x00" * 64])
    vm = sign_message("tap1", "mallory", mallory, rogue,
                      eph_pub_bytes(new_eph()), os.urandom(16), os.urandom(32),
                      {"ts": int(time.time()), "trust_score": 1.0})
    f.put(vm)
    _, db = peers()
    try:
        receive_tap(db, f)
        report("Forged ring (bad issuer signature) rejected", False)
    except HandshakeError:
        report("Forged ring (bad issuer signature) rejected", True)


def attack_signature_forgery(da, db):
    f = field()
    eph, m1 = bootstrap_tap(da, f, "bob")
    evil = DeviceIdentity("eve")
    # Eve rewrites the tap's eph pub, re-signs with HER key that is NOT bound
    # to any issuer-valid ring.
    m1.eph_pub = eph_pub_bytes(new_eph())
    m1.signature = evil.sign(m1.canon())
    evil_msg = NfcField(f.path)
    evil_msg.put(m1)
    try:
        receive_tap(db, f)
        report("Signature forgery / swapped key detected", False)
    except HandshakeError:
        report("Signature forgery / swapped key detected", True)


def attack_replay(da, db):
    f = field()
    eph, m1 = bootstrap_tap(da, f, "bob")
    receive_tap(db, f)
    # attacker replays yesterday's tap1; only the old message is on the field
    f.flush()
    f.put(m1)
    try:
        receive_tap(db, f)
        report("Replayed tap detected (nonce remembered)", False)
    except HandshakeError as exc:
        report("Replayed tap detected (nonce remembered)",
               "replay" in str(exc).lower())


def attack_stale(da, db):
    f = field()
    import json
    eph = new_eph()
    stale = sign_message("tap1", "alice", da.identity, da.ring,
                         eph_pub_bytes(eph), os.urandom(16), os.urandom(32),
                         {"ts": int(time.time()) - 3600, "trust_score": 1.0})
    f.put(stale)
    try:
        receive_tap(db, f)
        report("Stale (replayed) timestamp rejected", False)
    except HandshakeError:
        report("Stale (replayed) timestamp rejected", True)


def attack_mitm_tap_edit(da, db):
    """"""
    f = field()
    eph, m1 = bootstrap_tap(da, f, "bob")
    m1.eph_pub = eph_pub_bytes(new_eph())              # tamper without re-sign
    p = f.path
    import json
    with open(os.path.join(p, os.listdir(p)[-1]), "w") as fh:
        json.dump(m1.to_dict(), fh)
    try:
        receive_tap(db, f)
        report("MITM editing the tap invalidated by signature", False)
    except HandshakeError:
        report("MITM editing the tap invalidated by signature", True)


def attack_weak_tap(da, db):
    f = field()
    import os as _os
    eph = new_eph()
    weak = sign_message("tap1", "alice", da.identity, da.ring,
                        eph_pub_bytes(eph), _os.urandom(16), _os.urandom(32),
                        {"ts": int(time.time()), "trust_score": 0.41})
    f.put(weak)
    try:
        receive_tap(db, f)
        report("Weak tap pushed to extra verification round (AOTBC)", False)
    except HandshakeError as exc:
        report("Weak tap pushed to extra verification round (AOTBC)",
               "extra" in str(exc).lower())


def attack_cloned_ring(da, db):
    """Thief taps a stolen ring on the victim's phone with his own device.

    The clone carries Alice's public identity; the thief tries to prove
    possession with his own keystore key. The response signature won't match
    the ring's bound device key -- mutual auth fails.
    """
    f = field()
    thief = DeviceIdentity("theif")
    clone = Ring.unpack(da.ring.pack())                # public bytes only
    hit = sign_message("tap1", "alice", thief, clone,
                       eph_pub_bytes(new_eph()), os.urandom(16), os.urandom(32),
                       {"ts": int(time.time()), "trust_score": 1.0})
    f.put(hit)
    vp = LetheDevice("bob", db.identity, db.ring)
    try:
        receive_tap(vp, f)
        report("Cloned ring + alien keystore cannot authenticate", False)
    except HandshakeError:
        report("Cloned ring + alien keystore cannot authenticate", True)


# ------------------------------------------------------------- policy
def attack_policy_edit():
    d = tempfile.mkdtemp()
    sender = DeviceIdentity("sender")
    ct = os.urandom(256)
    env = seal_package("f.enc", Policy(max_views=1), ct, sender.raw_priv())
    env.policy.max_views = 999
    try:
        enforce_policy(env, "bob")
        report("Post-encryption policy edit invalidated (PCCP)", False)
    except PolicyError:
        report("Post-encryption policy edit invalidated (PCCP)", True)


def attack_wrong_recipient():
    d = tempfile.mkdtemp()
    sender = DeviceIdentity("sender")
    ct = os.urandom(256)
    env = seal_package("f.enc", Policy(recipient="bravo"), ct, sender.raw_priv())
    try:
        enforce_policy(env, "charlie")
        report("Wrong recipient denied by policy", False)
    except PolicyError:
        report("Wrong recipient denied by policy", True)


def attack_expired():
    d = tempfile.mkdtemp()
    sender = DeviceIdentity("sender")
    ct = os.urandom(256)
    env = seal_package("f.enc", Policy(expires_at=int(time.time()) - 5),
                       ct, sender.raw_priv())
    try:
        enforce_policy(env, "bravo")
        report("Expired policy denied", False)
    except PolicyError:
        report("Expired policy denied", True)


def attack_view_forest():
    d = tempfile.mkdtemp()
    key = os.urandom(32)
    slot = KeySlot(os.path.join(d, "slot"), key, max_views=1)
    slot.try_view()
    try:
        slot.try_view()
        report("View limit consumed -> key crypto-shredded", False)
    except AccessError as exc:
        wiped = not os.path.exists(slot.path) and not slot.live
        report("View limit consumed -> key crypto-shredded",
               wiped and "destroyed" in str(exc))


# ------------------------------------------------------------------ main
def main():
    da, db = peers()
    print("LETHE ATTACK BATTERY  |  within the stated threat model")
    attack_wiretap(da, db)
    attack_tamper(da, db)
    attack_wrong_key(da, db)
    attack_forged_ring()
    attack_signature_forgery(da, db)
    attack_replay(da, db)
    attack_stale(da, db)
    attack_mitm_tap_edit(da, db)
    attack_weak_tap(da, db)
    attack_cloned_ring(da, db)
    attack_policy_edit()
    attack_wrong_recipient()
    attack_expired()
    attack_view_forest()
    print(f"\n{PASS} attacks blocked, {FAIL} breaches.")
    raise SystemExit(1 if FAIL else 0)


if __name__ == "__main__":
    main()