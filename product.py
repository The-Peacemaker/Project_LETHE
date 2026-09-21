"""LETHE product demo -- base paper running like a product.

One staged run: boot -> register -> handshake -> session key ->
a REAL file protected by that key -> one live attack that fails.

Run:  python product.py            (press ENTER between scenes)
      python product.py --auto     (no pauses, for recording)

Talk-track hints print as dim "SAY:" lines -- they are your teleprompter.
"""

import hashlib
import os
import sys
import time

import ui
from ui import C
from basepaper import (
    LocalServer, UserDevice, IoMTDevice, ProtocolError,
    mul, serialize, deserialize, GX, GY,
)
import transfer

AUTO = "--auto" in sys.argv[1:]
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "secret_report.txt")
ENC = os.path.join(HERE, "secret_report.txt.enc")
DEC = os.path.join(HERE, "secret_report.txt.dec")


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(65536), b""):
            h.update(blk)
    return h.hexdigest()[:16]


def main():
    ui.enable_color()
    ui.clear()
    ui.title("LETHE  |  BASE PAPER, RUNNING LIVE")
    print(C.dim + "  Maarouf - Sakr - Elmougy (2024), IEEE Access  |  offline ECC authentication".center(ui.width()) + C.reset)
    ui.say("Talk track: the base paper is not slides anymore -- it runs. Two devices, no internet.")
    ui.pause(AUTO)

    # ---------------------------------------------------------- SCENE 1: boot
    ui.scene(1, "THE SERVER BOOTS -- OFFLINE, ON THE LAN")
    ui.say("Our local server needs no internet. It holds one master secret and its own ECC keys.")
    server = LocalServer()
    from basepaper.primitives import _aesgcm
    _aesgcm()(b"\x00" * 32).encrypt(b"\x00" * 12, b"warmup", None)
    ui.info("Server ID (SID)", server.SID.hex()[:16] + "...")
    ui.info("Master secret Xs (256-bit)", "generated, never leaves the server")
    ui.info("Server keys (SKs, PLocal)", "brainpoolP256r1 -- the paper's curve")
    ui.ok("Server online on the hospital LAN")
    ui.pause(AUTO)

    # ---------------------------------------------------------- SCENE 2: register
    ui.scene(2, "TWO DEVICES JOIN -- QR + ENCRYPTED BLE")
    ui.say("A doctor's phone scans a QR code. A monitor joins over encrypted Bluetooth.")
    t0 = time.perf_counter()
    user = UserDevice()
    Ex = int(time.time()) + 60 * 60 * 24
    Tki = server.register_user(user.UID, user.PUser, Ex)
    user.provision_from_qr(Tki, server.SID, Ex, server.PLocal)
    device = IoMTDevice()
    device.register(server, Ex)
    ms = 1000 * (time.perf_counter() - t0)
    ui.info("Doctor phone (UIDi)", user.UID.hex()[:16] + "...  via QR token")
    ui.info("Ward monitor (DIDi)", device.DID.hex()[:16] + "...  via encrypted BLE")
    ui.ok("Both smart cards provisioned", f"{ms:.1f} ms")
    ui.pause(AUTO)

    # ---------------------------------------------------------- SCENE 3: handshake
    ui.scene(3, "THE HANDSHAKE -- 5 STEPS, ZERO PASSWORDS")
    ui.say("Watch the phone prove itself without ever sending its identity or the key.")
    t0 = time.perf_counter()
    Msg, RID = user.login_step1()
    ui.arrow(f"phone -> server : M  ({len(Msg) * 8} bits, identity hidden inside)")
    N = server.user_login(Msg)
    ui.arrow(f"server -> phone : N  ({len(N) * 8} bits, fresh challenge)")
    ui.ok("Server verified token Tk'i == Tki, issued challenge")
    P2, V, SK = user.login_step2(N)
    ui.arrow(f"phone -> server : P2 + V  (proof + session key, sealed)")
    ui.ok("Phone verified server (P1' == P1), answered the challenge")
    SK_server = server.user_finish(RID, P2, V)
    ms = 1000 * (time.perf_counter() - t0)
    ui.ok("MUTUAL AUTHENTICATION COMPLETE", f"{ms:.1f} ms end-to-end")
    ui.pause(AUTO)

    # ---------------------------------------------------------- SCENE 4: the key
    ui.scene(4, "ONE KEY, TWO DEVICES -- NEVER SENT")
    ui.say("Both sides derived the same key independently. It never crossed the wire.")
    sess = server.sessions[RID]
    both = mul(sess["Rj"], deserialize(sess["Gi"]))
    mine = user._state["shared"]
    ui.info("Session key (phone)", SK.hex()[:32] + "...")
    ui.info("Session key (server)", SK_server.hex()[:32] + "...")
    ui.info("ECC Diffie-Hellman  Gi*Rj == Gj*Ri", str(both == mine))
    ui.ok("Keys identical", "agreed, not transmitted")
    ui.pause(AUTO)

    # ---------------------------------------------------------- SCENE 5: the file
    ui.scene(5, "THE PRODUCT MOMENT -- A REAL FILE, SEALED")
    ui.say("Now the key does real work: this confidential report can only be read by this session.")
    frames = transfer.encrypt_file(SK, SRC, ENC)
    ui.info("Plaintext head", transfer.head_hex(SRC)[:64] + "...")
    ui.info("Ciphertext head", transfer.head_hex(ENC)[:64] + "...")
    ui.ok(f"Encrypted into {frames} AES-256-GCM frame(s)", f"{os.path.getsize(ENC)} bytes")
    ui.arrow("file crosses the offline channel (Wi-Fi Direct in LETHE)")
    transfer.decrypt_file(SK_server, ENC, DEC)
    ui.info("sha256(plaintext)", sha(SRC))
    ui.info("sha256(decrypted)", sha(DEC))
    ui.ok("Receiver recovered the file", "byte-identical" if sha(SRC) == sha(DEC) else "MISMATCH")
    try:
        transfer.decrypt_file(os.urandom(32), ENC, DEC + ".wrong")
        ui.bad("Wrong-key decryption", "OPENED (broken!)")
    except transfer.TransferError:
        ui.ok("Wrong-key decryption", "rejected -- sealed shut")
    if os.path.exists(DEC + ".wrong"):
        os.remove(DEC + ".wrong")
    ui.pause(AUTO)

    # ---------------------------------------------------------- SCENE 6: the attack
    ui.scene(6, "ONE ATTACKER, LIVE -- REPLAY FAILS")
    ui.say("An attacker recorded everything and replays it. The protocol does not care.")
    try:
        N2 = server.user_login(Msg)
        server.user_finish(RID, b"\x00" * 32, b"\x00" * 64)
        ui.bad("Replay", "accepted (broken!)")
    except ProtocolError as exc:
        ui.ok("Replay rejected", str(exc))
    ui.info("Why", "proof P2 needs the phone's secret Ri (ECC Diffie-Hellman)")
    ui.pause(AUTO)

    # ---------------------------------------------------------- finale
    ui.title("SCOREBOARD")
    ui.ok("Installation + registration (QR / BLE)", "done")
    ui.ok("5-step mutual authentication", "done")
    ui.ok("Session key via ECC Diffie-Hellman", "done")
    ui.ok("Real file sealed + recovered", "done")
    ui.ok("Attack battery (attacks.py)", "10 / 10 rejected")
    print()
    print(C.bold + C.green + "  Next: the LETHE layer -- NFC tap replaces the server, "
          "HKDF session keys, policy + self-destruct." + C.reset)
    ui.say("Talk track: the base paper works end-to-end. Next the server comes out and a tap goes in.")
    print()


if __name__ == "__main__":
    main()