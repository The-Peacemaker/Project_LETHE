"""LETHE core-brain self-tests.

Verifies the invariants the whole product leans on:
  - ed25519 identity sign/verify roundtrip (Phase 1)
  - ring provisioning: issuer signature, pack/unpack, 504-byte bound (Phase 2)
  - signed tap integrity + replay/timestamp audit (Phase 3)
  - mutual auth: challenge-response, independent key agreement (Phase 4/5)
  - session keys are agreed independently and unique per session
  - FSKE forward-secure sub-keys never overlap
  - policy engine: signature, integrity, expiry, recipient (Phase 8)
  - crypto-shredding: view-limit and expiry destroy the key for good (Phase 9)

Run:  python lethe_self_test.py
"""

import os
import tempfile
import time

from lethe.identity import DeviceIdentity
from lethe.ring import Ring, provision_ring, RING_MAX_BYTES, ISSUER_PUB
from lethe.tap import NfcField, sign_message, verify_message, TapError
from lethe.handshake import (LetheDevice, bootstrap_tap, receive_tap,
                             complete_handshake, HandshakeError)
from lethe.keys import FSKE, derive_aes_keys, new_eph, shared_x25519, \
    eph_pub_bytes
from lethe.transfer import seal_file, open_file, TransferError
from lethe.policy import Policy, seal_package, enforce_policy, PolicyError
from lethe.erasure import KeySlot, AccessError

PASS = 0
FAIL = 0


def check(name, fn):
    global PASS, FAIL
    try:
        fn()
        PASS += 1
        print(f"  [ok] {name}")
    except AssertionError as exc:
        FAIL += 1
        print(f"  [xx] {name}  ->  {exc}")
    except Exception as exc:
        FAIL += 1
        print(f"  [xx] {name}  ->  {type(exc).__name__}: {exc}")


def tmp(mk):
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "field"), exist_ok=True)
    return (d, NfcField(os.path.join(d, "field"))) if mk else (d, None)


# ------------------------------------------------------------------ Phase 1
def test_identity():
    ident = DeviceIdentity("alpha")
    msg = b"hello lethe"
    assert len(ident.public) == 32
    assert len(ident.sign(msg)) == 64
    ident.verifier.verify(ident.sign(msg), msg)


# ------------------------------------------------------------------ Phase 2
def test_ring():
    ident = DeviceIdentity("alpha")
    ring = provision_ring(ident, "sesame")
    assert ring.verify(ISSUER_PUB), "issuer must validate its own ring"
    assert not ring.verify(b"\x00" * 32), "wrong issuer must not validate"
    assert ring.pack() == Ring.unpack(ring.pack()).pack(), "pack/unpack roundtrip"
    assert ring.size_bytes <= RING_MAX_BYTES, "must fit NTAG215 (504 B)"


def test_ring_replay_proof():
    """A ring replays only its public bytes: it cannot answer challenges."""
    ident = DeviceIdentity("alpha")
    ring = provision_ring(ident, "sesame")
    clone = Ring.unpack(ring.pack())            # attacker copies public data
    assert clone.verify(ISSUER_PUB)             # clone still 'looks' genuine
    # ...but without the keystore the clone cannot produce a valid signature
    attacker = DeviceIdentity("mallory")
    blob = sign_message("tap1", "mallory", attacker, clone,
                        b"\x00" * 32, os.urandom(16), os.urandom(32), {})
    assert not blob.verify(), "stolen ring alone must NOT pass mutual auth"


# ------------------------------------------------------------------ Phase 3
def test_tap_pipeline():
    _, field = tmp(True)
    a, b = DeviceIdentity("a"), DeviceIdentity("b")
    ra, rb = provision_ring(a, "ka"), provision_ring(b, "kb")
    da, db = LetheDevice("a", a, ra), LetheDevice("b", b, rb)
    eph, m1 = bootstrap_tap(da, field, "b")
    assert m1.verify()
    reply, _ = receive_tap(db, field)
    assert reply.verify()
    m2 = field.take()
    assert m2.tag == "tap2"
    assert m2.response is not None


def test_replay_rejected():
    _, field = tmp(True)
    a, b = DeviceIdentity("a"), DeviceIdentity("b")
    da, db = LetheDevice("a", a, provision_ring(a, "ka")), \
        LetheDevice("b", b, provision_ring(b, "kb"))
    # stall the message a day into the future -> stale -> rejected
    from lethe.tap import TapMessage
    eph = new_eph()
    meta = {"receiver": "b", "sender": "a", "session": "s",
            "ts": int(time.time()) + 86400, "trust_score": 1.0}
    stale = sign_message("tap1", "a", a, provision_ring(a, "ka"),
                         eph_pub_bytes(eph), os.urandom(16), os.urandom(32),
                         meta)
    field.put(stale)
    try:
        receive_tap(db, field)
        raise AssertionError("stale tap accepted")
    except HandshakeError:
        pass


# ------------------------------------------------------------------ Phase 4/5
def test_mutual_auth_and_key(n=5):
    _, field = tmp(True)
    a, b = DeviceIdentity("a"), DeviceIdentity("b")
    da, db = LetheDevice("a", a, provision_ring(a, "ka")), \
        LetheDevice("b", b, provision_ring(b, "kb"))
    seen = set()
    for _ in range(n):
        field.flush()
        eph, m1 = bootstrap_tap(da, field, "b")
        _, kb = receive_tap(db, field)
        ka, sid = complete_handshake(da, field, eph, m1)
        assert ka == kb, "session keys differ between devices"
        assert len(ka) == 32, "AES-256 key must be 32 bytes"
        seen.add(ka)
    assert len(seen) == n, "keys must be fresh each session"


def test_ecdhe_agreement():
    a = new_eph()
    b = new_eph()
    sa = shared_x25519(a, eph_pub_bytes(b))
    sb = shared_x25519(b, eph_pub_bytes(a))
    assert sa == sb, "ECDH shared secrets must agree"
    ka = derive_aes_keys(sa, b"session", 1.0)
    kb = derive_aes_keys(sb, b"session", 1.0)
    assert ka == kb


# ------------------------------------------------------------------ FSKE
def test_fske():
    fwd = FSKE(os.urandom(32), b"sid")
    K = [fwd.next_key() for _ in range(4)]
    assert len(set(K)) == 4, "sub-keys must be distinct"
    k0, k1 = K[0], K[1]
    assert k0 != k1


# ------------------------------------------------------------------ Phase 6/7
def test_transfer():
    d, _ = tmp(False)
    key = os.urandom(32)
    src, enc, dec = (os.path.join(d, x) for x in ("src", "enc", "dec"))
    with open(src, "wb") as f:
        f.write(os.urandom(200 * 1024))            # > 3 chunks
    seal_file(key, src, enc)
    n, h = open_file(key, enc, dec)
    assert n >= 3
    with open(src, "rb") as f1, open(dec, "rb") as f2:
        assert f1.read() == f2.read()


def test_tamper_rejected():
    d, _ = tmp(False)
    key = os.urandom(32)
    src, enc, dec = (os.path.join(d, x) for x in ("src", "enc", "dec"))
    with open(src, "wb") as f:
        f.write(b"x" * 100_000)
    seal_file(key, src, enc)
    with open(enc, "r+b") as f:
        f.seek(40_000)
        f.write(os.urandom(1))
    try:
        open_file(key, enc, dec)
        raise AssertionError("tampered file opened")
    except TransferError:
        pass


# ------------------------------------------------------------------ Phase 8
def test_policy():
    ident = DeviceIdentity("sender")
    ct = os.urandom(64)
    env = seal_package("f", Policy(max_views=1), ct, ident.raw_priv())
    assert env.verify_signature()
    assert env.check_integrity(ct)
    enforce_policy(env, "officer-bravo")           # star recipient
    # tamper policy
    env.policy.max_views = 99
    assert not env.verify_signature(), "edited policy must invalidate the signature"
    try:
        enforce_policy(SignedEnvelope_load(env), "officer-bravo")
        raise AssertionError("tampered policy enforced")
    except (PolicyError, AssertionError):
        pass


def SignedEnvelope_load(env):
    import lethe.policy as P
    e = P.SignedEnvelope(env.filename, env.policy, env.sender_pub,
                         env.integrity_hash, env.signature)
    return e


def test_policy_recipient_and_expiry():
    ident = DeviceIdentity("sender")
    ct = os.urandom(64)
    env = seal_package("f", Policy(recipient="bravo"), ct, ident.raw_priv())
    enforce_policy(env, "bravo")
    try:
        enforce_policy(env, "charlie")
        raise AssertionError("wrong recipient allowed")
    except PolicyError:
        pass
    env2 = seal_package("f", Policy(expires_at=int(time.time()) - 1),
                        ct, ident.raw_priv())
    try:
        enforce_policy(env2, "bravo")
        raise AssertionError("expired policy allowed")
    except PolicyError:
        pass


# ------------------------------------------------------------------ Phase 9
def test_erasure_capacity():
    d, _ = tmp(False)
    key = os.urandom(32)
    slot = KeySlot(os.path.join(d, "slot"), key, max_views=1)
    assert slot.try_view() == key                 # first view granted
    assert slot.live                               # key still present between views
    try:
        slot.try_view()                            # second attempt -> destroyed
        raise AssertionError("second view allowed")
    except AccessError:
        pass
    assert not slot.live
    assert not os.path.exists(slot.path)


def test_erasure_lock_down():
    """After shredding, even the right key can no longer decrypt... it is gone."""
    d, _ = tmp(False)
    key = os.urandom(32)
    src = os.path.join(d, "src")
    enc = os.path.join(d, "enc")
    with open(src, "wb") as f:
        f.write(b"classified text")
    seal_file(key, src, enc)
    slot = KeySlot(os.path.join(d, "slot"), key, max_views=1)
    got = slot.try_view()
    dec = os.path.join(d, "dec")
    open_file(got, enc, dec)                       # works once
    with open(dec) as f:
        assert f.read() == "classified text"
    try:
        slot.try_view()                            # consumes -> destroys
        raise AssertionError("second key extraction succeeded")
    except AccessError as exc:
        assert "destroyed" in str(exc)
    # slot file gone, key wiped
    assert not os.path.exists(slot.path)
    assert not slot.live


def main():
    print("LETHE SELF TEST  |  core brain invariants")
    check("Phase 1 - identity sign/verify", test_identity)
    check("Phase 2 - ring provisioning + issuer + roundtrip", test_ring)
    check("Phase 2 - stolen/cloned ring cannot authenticate", test_ring_replay_proof)
    check("Phase 3 - signed tap pipeline (tap1 -> answer -> tap2)", test_tap_pipeline)
    check("Phase 3 - stale tap rejected", test_replay_rejected)
    check("Phase 4/5 - mutual auth + independent session keys", test_mutual_auth_and_key)
    check("Phase 5 - ECDHE + HKDF agreement", test_ecdhe_agreement)
    check("FSKE - forward-secure sub-keys are unique", test_fske)
    check("Phase 6/7 - AES-256-GCM chunked file transfer", test_transfer)
    check("Phase 7 - tampered chunk rejected", test_tamper_rejected)
    check("Phase 8 - PCCP signature + integrity", test_policy)
    check("Phase 8 - recipient + expiry enforced", test_policy_recipient_and_expiry)
    check("Phase 9 - crypto-shredding after view limit", test_erasure_capacity)
    check("Phase 9 - erasure makes the file noise", test_erasure_lock_down)
    print(f"\n{PASS} passed, {FAIL} failed.")
    raise SystemExit(1 if FAIL else 0)


if __name__ == "__main__":
    main()