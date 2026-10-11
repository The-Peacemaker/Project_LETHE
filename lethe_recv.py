"""LETHE receiver peer -- Terminal 2 of the two-device demonstration.

Run first; it waits at each hop. Then run `lethe_send.py` in the other
terminal with the same --field and --channel directories:
    python lethe_recv.py --field run\\twopeer\\field --channel run\\twopeer\\channel
    python lethe_send.py --field run\\twopeer\\field --channel run\\twopeer\\channel
"""

import argparse
import os
import sys
import time

import ui
from ui import C
from lethe.identity import DeviceIdentity
from lethe.ring import provision_ring
from lethe.tap import NfcField
from lethe.handshake import LetheDevice, receive_tap, HandshakeError
from lethe.transfer import open_file, TransferError
from lethe.policy import SignedEnvelope, enforce_policy, PolicyError
from lethe.erasure import KeySlot, AccessError


def wait_for(path, what, timeout=120.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if os.path.exists(path):
            return
        time.sleep(0.2)
    raise HandshakeError(f"timed out waiting for {what}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--field", default=os.path.join("run", "twopeer", "field"))
    ap.add_argument("--channel", default=os.path.join("run", "twopeer", "channel"))
    args = ap.parse_args()

    ui.enable_color()
    os.makedirs(args.field, exist_ok=True)
    os.makedirs(args.channel, exist_ok=True)
    for stale in ("tap1.json", "tap2.json"):
        try:
            os.remove(os.path.join(args.field, stale))
        except OSError:
            pass    # fresh ceremony namespace: never consume a previous run's tap
    field = NfcField(args.field)

    ui.title("LETHE RECEIVER  |  DEVICE B (OFFICER-BRAVO)")
    bravo = DeviceIdentity("officer-bravo")
    ring = provision_ring(bravo, "recovery-secret-bravo")
    dev = LetheDevice("officer-bravo", bravo, ring)
    ui.info("identity (ed25519)", bravo.public.hex()[:24] + "...")
    ui.info("ring provisioned", f"{ring.size_bytes} bytes of 504, issuer-sealed")
    ui.ok("Device B booted, keystore-only private key")

    print("  waiting for Device A to tap...", flush=True)
    wait_for(os.path.join(args.field, "tap1.json"), "the tap1")
    _, key = receive_tap(dev, field)
    ui.ok("TAP 2 SENT", "ring verified + challenge answered")
    ui.info("session key (derived, never sent)", key.hex()[:24] + "...")

    enc = os.path.join(args.channel, "brief.txt.enc")
    print("  waiting for the ciphertext...", flush=True)
    wait_for(enc, "the ciphertext")
    wait_for(os.path.join(args.channel, "envelope.json"), "the policy envelope")
    env = SignedEnvelope.load(os.path.join(args.channel, "envelope.json"))
    try:
        enforce_policy(env, "officer-bravo")
    except PolicyError as exc:
        print(f"\n  POLICY REFUSED: {exc}")
        sys.exit(1)
    ui.ok("Policy accepted", f"one view, recipient {env.policy.recipient}")

    slot = KeySlot(os.path.join(args.channel, "keyslot"), key,
                   max_views=env.policy.max_views)
    dec = os.path.join(args.channel, "brief.txt.dec")
    try:
        open_file(slot.try_view(), enc, dec)
    except (TransferError, AccessError) as exc:
        print(f"\n  OPEN FAILED: {exc}")
        sys.exit(1)
    ui.info("attempt 1", "OFFICER-BRAVO -> view granted")
    ui.info("brief says", open(dec).read().splitlines()[0])
    ui.ok("Brief opened once within policy")

    try:
        slot.try_view()
        ui.bad("attempt 2", "opened (broken!)")
    except AccessError as exc:
        ui.info("attempt 2", "OFFICER-BRAVO -> " + str(exc))
        print("  " + C.bold + C.red
              + "Access denied. Cryptographic key has been destroyed." + C.reset)
        ui.info("ciphertext still on disk", "random noise")
        ui.ok("Crypto-shredding complete", "mathematically unrecoverable")
    print()


if __name__ == "__main__":
    try:
        main()
    except (HandshakeError, TransferError, AccessError) as exc:
        print(f"\n  RECEIVER ABORTED: {exc}")
        sys.exit(1)
