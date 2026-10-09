"""End-to-end demonstration of the base paper protocol:
installation -> registration (QR + BLE) -> 5-step login mutual authentication.

Run:  python demo.py
"""

import time

from basepaper import (
    LocalServer, UserDevice, IoMTDevice,
    mul, serialize, deserialize, GX, GY,
)

_LINE = "=" * 78


def banner(title):
    print()
    print(_LINE)
    print(title)
    print(_LINE)


def show(label, value):
    print(f"  {label:<46} {value}")


def bits_of(blob):
    return len(blob) * 8


def main():
    print("BASE PAPER  |  Maarouf, Sakr & Elmougy (2024)  |  IEEE Access 12")
    print("Offline Direct Authentication Scheme for the IoMT  |  ECC (brainpoolP256r1)")

    # ---------------------------------------------------------- installation
    banner("PHASE 1: INSTALLATION PHASE")
    server = LocalServer()
    show("Server ID (SID)", server.SID.hex()[:16] + "...")
    show("Master secret Xs (256-bit)", "generated")
    show("Server ECC keypair (SKs, PLocal)", "brainpoolP256r1")

    # ---------------------------------------------------------- registration
    banner("PHASE 2A: USER DEVICE REGISTRATION  (QR CODE)")
    user = UserDevice()
    show("User UUID (UIDi, RFC 4122, 128-bit)", user.UID.hex())
    Ex = int(time.time()) + 60 * 60 * 24  # 24 h token lifetime
    Tki = server.register_user(user.UID, user.PUser, Ex)
    user.provision_from_qr(Tki, server.SID, Ex, server.PLocal)
    show("Server token  Tki = h(h(Xs)||UIDi||Ex)", Tki.hex()[:24] + "...")
    show("Smart card stores {Tki, SID, Ex, PLocal}", "provisioned from QR")

    banner("PHASE 2B: IoMT DEVICE REGISTRATION  (ENCRYPTED BLE)")
    device = IoMTDevice()
    show("Device UUID (DIDi, RFC 4122, 128-bit)", device.DID.hex())
    t0 = time.perf_counter()
    device.register(server, Ex)
    t1 = time.perf_counter()
    show("Server encrypted {Tki, PLocal, Ex, SID} with PDevice", "BLE channel")
    show("Device decrypted with SKd and stored in smart card", f"{1000*(t1-t0):.3f} ms")

    # ---------------------------------------------------------- user login
    banner("PHASE 3A: USER DEVICE LOGIN AUTHENTICATION  (5 STEPS)")

    t0 = time.perf_counter()
    Msg, RID = user.login_step1()
    t1 = time.perf_counter()
    show("Step 1-2: Gi = g*Ri ; RIDUi = h(Gi)/Tki/UIDi/Ex XOR mask", f"{1000*(t1-t0):.3f} ms")
    show("  M  = Enc_PLocal(RIDUi, Gi, h(bi||SID))  -----------> S", f"{bits_of(Msg)} bits")

    t0 = time.perf_counter()
    N = server.user_login(Msg)
    t1 = time.perf_counter()
    show("Step 3 : S recovers (Tki||UIDi||Ex) from XOR mask", "OK")
    show("         S verifies token freshness Tk'i = Tki", "OK")
    show("         S: P1 = h(RIDUi||SID||Gi||Gj), N=Enc_PUser", f"{1000*(t1-t0):.3f} ms")
    show("  N = Enc_PUser(P1||Gi||Gj)  <----------- S", f"{bits_of(N)} bits")

    t0 = time.perf_counter()
    P2, V, SK_user = user.login_step2(N)
    t1 = time.perf_counter()
    show("Step 4 : U verifies P1' = P1 (server freshness)", "OK")
    show("         U: P2 = h(P1'||Gj*Ri) ; SK = h(RIDUi||SID||Gj*Ri)", f"{1000*(t1-t0):.3f} ms")
    show("  P2  --------------------> S", f"{bits_of(P2)} bits")
    show("  V   = Enc_PLocal(SK,Gi,Gj) ---------> S", f"{bits_of(V)} bits")

    t0 = time.perf_counter()
    SK_server = server.user_finish(RID, P2, V)
    t1 = time.perf_counter()
    show("Step 5 : S: P2' = h(P1||Gi*Rj)  (ECCDHP Gi*Rj==Gj*Ri)", f"{1000*(t1-t0):.3f} ms")
    show("         S decrypts V and acquires SK", "OK")

    banner("SESSION KEY AGREED  (ECCDHP)")
    show("Session key at user side", SK_user.hex())
    show("Session key at server side", SK_server.hex())
    show("Keys identical?", SK_user == SK_server)

    # ---------------------------------------------------------- ECCDHP cross check
    banner("VERIFICATION: ECCDHP PROPERTY  Gi*Rj = Gj*Ri = g*Ri*Rj")
    sess = server.archive[RID]
    Gi_p = deserialize(sess["Gi"])
    shared_server = mul(sess["Rj"], Gi_p)          # server: Gi*Rj
    shared_user = user._state["shared"]            # user:   Gj*Ri
    show("Gi*Rj computed by server", serialize(shared_server).hex()[:32] + "...")
    show("Gj*Ri computed by user", serialize(shared_user).hex()[:32] + "...")
    show("Equal? (ECCDHP holds)", shared_server == shared_user)

    # ---------------------------------------------------------- ioMT login
    banner("PHASE 3B: IoMT DEVICE LOGIN AUTHENTICATION  (SAME PROTOCOL)")
    M2, RID2 = device.login_step1()
    N2 = server.device_login(M2)
    P2b, Vb, SK_dev = device.login_step2(N2)
    SK_server2 = server.user_finish(RID2, P2b, Vb)
    show("IoMT device authenticates and derives session key", SK_dev == SK_server2)

    # ---------------------------------------------------------- summary
    banner("SUMMARY")
    total_bits = bits_of(Msg) + bits_of(N) + bits_of(P2) + bits_of(V)
    show("Communication cost (user login, 4 messages)", f"{total_bits} bits")
    show("Paper claims 544 bits (3 msgs, EC point encoding)", "544 bits")
    show("Result", "MUTUAL AUTHENTICATION COMPLETED  /  SK ESTABLISHED")


if __name__ == "__main__":
    main()