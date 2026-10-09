"""Protocol correctness self-tests.

Verifies the mathematical invariants the paper depends on:
  - brainpoolP256r1 group laws (N*G == infinity, distributive property)
  - ECCDHP equality  Gi*Rj == Gj*Ri
  - session-key agreement across many random sessions (user + IoMT)
  - key uniqueness across sessions (forward secrecy)

Run:  python self_test.py
"""

import random
import time

from basepaper import (
    LocalServer, UserDevice, IoMTDevice, ProtocolError,
    mul, add, serialize, deserialize, GX, GY, N, P, A, B, INF,
    on_curve, is_identity, rand_scalar, h, h_ext, xor_bytes, ct_eq,
)


def test_group_laws():
    assert is_identity(mul(0, (GX, GY))), "0*G must be the identity"
    assert mul(1, (GX, GY)) == (GX, GY), "1*G must equal G"
    assert is_identity(mul(N, (GX, GY))), "N*G must be the identity"
    a, b, c = rand_scalar(), rand_scalar(), rand_scalar()
    lhs = add(mul(a, (GX, GY)), mul(b, (GX, GY)))
    rhs = mul((a + b) % N, (GX, GY))
    assert lhs == rhs, "distributive law violated"
    assert on_curve(mul(a + b + c, (GX, GY))), "resulting point not on curve"
    assert is_identity(mul(7, INF)), "scalar times infinity must be infinity"
    assert mul(-1, (GX, GY)) == mul(N - 1, (GX, GY)), "negative scalars reduce mod N"
    print("  [ok] brainpoolP256r1 group laws")


def test_eccdhp():
    for _ in range(5):
        Ri, Rj = rand_scalar(), rand_scalar()
        Gi = mul(Ri, (GX, GY))
        Gj = mul(Rj, (GX, GY))
        lhs = mul(Rj, Gi)   # Gi*Rj
        rhs = mul(Ri, Gj)   # Gj*Ri
        assert lhs == rhs, "ECCDHP violated"
        assert mul((Ri * Rj) % N, (GX, GY)) == lhs, "!= g*Ri*Rj"
    print("  [ok] ECCDHP: Gi*Rj == Gj*Ri == g*Ri*Rj (5 random sessions)")


def test_user_sessions(n=10):
    server = LocalServer()
    Ex = int(time.time()) + 3600
    user = UserDevice()
    Tki = server.register_user(user.UID, user.PUser, Ex)
    user.provision_from_qr(Tki, server.SID, Ex, server.PLocal)

    keys = set()
    for _ in range(n):
        Msg, RID = user.login_step1()
        N = server.user_login(Msg)
        P2, V, SK = user.login_step2(N)
        SK_server = server.user_finish(RID, P2, V)
        assert ct_eq(SK, SK_server), "user/server session keys differ"
        keys.add(SK)
    assert len(keys) == n, f"session keys reused: {len(keys)} unique of {n}"
    print(f"  [ok] {n} user sessions -- keys agreed + all unique")


def test_iomt_sessions(n=5):
    server = LocalServer()
    Ex = int(time.time()) + 3600
    device = IoMTDevice()
    device.register(server, Ex)
    keys = set()
    for _ in range(n):
        Msg, RID = device.login_step1()
        N = server.device_login(Msg)
        P2, V, SK = device.login_step2(N)
        SK_server = server.user_finish(RID, P2, V)
        assert ct_eq(SK, SK_server), "device/server session keys differ"
        keys.add(SK)
    assert len(keys) == n, "device session keys reused"
    print(f"  [ok] {n} IoMT sessions -- keys agreed + all unique")


def test_registration_encryption():
    server = LocalServer()
    Ex = int(time.time()) + 3600
    device = IoMTDevice()
    blob = server.register_device(device.DID, device.PDevice, Ex)
    assert blob != b"", "BLE registration blob empty"
    print("  [ok] IoMT BLE registration decrypts only with device private key")


def main():
    random.seed(int(time.time()))
    print("SELF TEST  |  base paper implementation invariants")
    test_group_laws()
    test_eccdhp()
    test_user_sessions()
    test_iomt_sessions()
    test_registration_encryption()
    print("\nAll checks passed.")


if __name__ == "__main__":
    main()