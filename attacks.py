"""Security analysis of the base-paper implementation.

Each "attempt" reproduces one attack from the paper's informal security
analysis (Sec. IV-A: replay, MITM, impersonation, DoS, eavesdropping,
tampering, invalid points, forward secrecy).

Every attack must FAIL -- if any prints VULNERABLE the protocol is broken.

Run:  python attacks.py
"""

import time

from basepaper import (
    LocalServer, UserDevice, IoMTDevice, ProtocolError,
    mul, serialize, deserialize, rand_scalar, GX, GY, h, xor_bytes, h_ext,
    ecies_encrypt, ecies_decrypt, ct_eq,
)
from basepaper.entities import _frame, _point_bytes, _unframe
from basepaper.primitives import concat


def fresh_user(server, Ex):
    user = UserDevice()
    Tki = server.register_user(user.UID, user.PUser, Ex)
    user.provision_from_qr(Tki, server.SID, Ex, server.PLocal)
    return user


def complete_user_run(server, user):
    Msg, RID = user.login_step1()
    N = server.user_login(Msg)
    P2, V, SK = user.login_step2(N)
    SK_server = server.user_finish(RID, P2, V)
    assert ct_eq(SK, SK_server)
    return Msg, N, P2, V, SK


def attempt(name, attacker):
    print(f"\n  [*] {name}")
    try:
        result = attacker()
        if result is None:
            print("      SAFE -- check passed (no vulnerability found)")
        else:
            print(f"      VULNERABLE -- attack succeeded: {result}")
    except ProtocolError as exc:
        print(f"      SAFE -- rejected: {exc}")


def main():
    Ex = int(time.time()) + 3600
    print("SECURITY ANALYSIS  |  Maarouf et al. (2024) implementation")
    print("Every entry must print SAFE (the paper's defense in action).\n")

    # ------------------------------------------------ 1. Replay of message M
    def replay_M():
        server = LocalServer()
        user = fresh_user(server, Ex)
        Msg1, RID1 = user.login_step1()
        N1 = server.user_login(Msg1)
        P2, V, SK = user.login_step2(N1)
        server.user_finish(RID1, P2, V)
        # attacker replays old M in a fresh session
        Msg_replay = Msg1
        N2 = server.user_login(Msg_replay)   # steps fresh Rj, new Gj
        # attacker cannot decrypt N2 (encrypted for user's public key)
        # and cannot compute P2 without Ri (ECCDHP)
        bogus_P2 = h(concat(b"x", _point_bytes(mul(rand_scalar(), (GX, GY)))))
        server.user_finish(RID1, bogus_P2, b"")
        return "replayed session completed with old credentials"

    # ------------------------------------------------ 2. Replay of (P2, V) from old session
    def replay_P2V():
        server = LocalServer()
        user = fresh_user(server, Ex)
        Msg1, RID1 = user.login_step1()
        N1 = server.user_login(Msg1)
        P2old, Vold, SKold = user.login_step2(N1)
        server.user_finish(RID1, P2old, Vold)
        # new session, attacker replays the *old* (P2, V)
        Msg2, RID2 = user.login_step1()
        N2 = server.user_login(Msg2)
        server.user_finish(RID2, P2old, Vold)
        return "old session tokens accepted in a new session"

    # ------------------------------------------------ 3. Forward secrecy: SK reuse
    def forward_secrecy():
        server = LocalServer()
        user = fresh_user(server, Ex)
        _, _, _, _, SK1 = complete_user_run(server, user)
        _, _, _, _, SK2 = complete_user_run(server, user)
        if SK1 == SK2:
            return "session key reused across sessions (no forward secrecy)"
        return None  # OK -- keys differ

    # ------------------------------------------------ 4. MITM: tamper message M
    def tamper_M():
        server = LocalServer()
        user = fresh_user(server, Ex)
        Msg, RID = user.login_step1()
        corrupted = Msg[:-1] + bytes([Msg[-1] ^ 1])
        server.user_login(corrupted)
        return "server accepted corrupted M"

    # ------------------------------------------------ 5. MITM: forge a fresh M (attacker impersonates the user)
    def forge_M():
        server = LocalServer()
        user = fresh_user(server, Ex)
        # attacker does NOT own a registered token; builds M with a forged token
        attacker = UserDevice()
        attacker.UID = user.UID  # tries to impersonate the real identity
        fake_tk = b"\x00" * 32
        attacker.provision_from_qr(fake_tk, server.SID, Ex, server.PLocal)
        Msg, RID = attacker.login_step1()
        server.user_login(Msg)
        return "attacker authenticated as user with forged token"

    # ------------------------------------------------ 6. Impersonation: unknown UIDi
    def unknown_uid():
        server = LocalServer()
        unknown = UserDevice()   # a device that was never registered
        fake_tk = b"\x00" * 32
        unknown.provision_from_qr(fake_tk, server.SID, Ex, server.PLocal)
        Msg, RID = unknown.login_step1()
        server.user_login(Msg)
        return "unregistered device authenticated"

    # ------------------------------------------------ 7. Expired token (Ex in the past)
    def expired_token():
        server = LocalServer()
        user = fresh_user(server, Ex - 7200)   # token created 2 h in the past
        Msg, RID = user.login_step1()
        server.user_login(Msg)
        return "expired token accepted"

    # ------------------------------------------------ 8. DoS: duplicate registration
    def duplicate_registration():
        server = LocalServer()
        user = fresh_user(server, Ex)
        server.register_user(user.UID, user.PUser, Ex)
        return "duplicate registration accepted (DoS possible)"

    # ------------------------------------------------ 9. Tamper: corrupt encrypted V
    def tamper_V():
        server = LocalServer()
        user = fresh_user(server, Ex)
        Msg1, RID1 = user.login_step1()
        N1 = server.user_login(Msg1)
        P2, V, SK = user.login_step2(N1)
        corrupted = V[:-1] + bytes([V[-1] ^ 0xFF])
        server.user_finish(RID1, P2, corrupted)
        return "corrupted V accepted"

    # ------------------------------------------------ 10. Off-curve point injection
    def offcurve_Gi():
        server = LocalServer()
        user = fresh_user(server, Ex)
        Tki = server._token(user.UID, Ex)
        # attacker crafts RID with the real token but an invalid Gi point
        bogus_gi = b"\x02" + b"\x01" * 64     # (1, 1) is NOT on brainpoolP256r1
        from basepaper.primitives import h_ext, xor_bytes
        token_field = concat(Tki, user.UID, Ex.to_bytes(8, "big"))
        mask = h_ext(bogus_gi, 32 + 16 + 8)
        RID = xor_bytes(token_field, mask)
        M = ecies_encrypt(server.PLocal, _frame(RID, bogus_gi, h(b"b")))
        server.user_login(M)
        return "off-curve point accepted"

    attempt("1.  Replay of message M", replay_M)
    attempt("2.  Replay of old (P2, V)", replay_P2V)
    attempt("3.  Forward secrecy (SK must differ per session)", forward_secrecy)
    attempt("4.  MITM -- corrupt M", tamper_M)
    attempt("5.  Impersonation -- forged token", forge_M)
    attempt("6.  Impersonation -- unregistered UIDi", unknown_uid)
    attempt("7.  Expired token", expired_token)
    attempt("8.  DoS -- duplicate registration", duplicate_registration)
    attempt("9.  Tamper -- corrupt V", tamper_V)
    attempt("10. Off-curve point Gi", offcurve_Gi)

    print("\nIf all entries are SAFE, the protocol resists these attacks.")


if __name__ == "__main__":
    main()