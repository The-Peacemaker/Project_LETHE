"""LETHE sender peer -- Terminal 1 of the two-device demonstration.

One process = one device. This peer and `lethe_recv.py` share only two
directories (the NFC field and the channel), exactly as two phones would share
only radio hops. No identities, rings, or keys are pre-shared: each side
generates its own, and trust crosses via the taps alone.

Run the receiver first (it waits), then this sender:
    python lethe_recv.py --field run\\twopeer\\field --channel run\\twopeer\\channel
    python lethe_send.py --field run\\twopeer\\field --channel run\\twopeer\\channel
"""

import argparse
import os
import shutil
import sys
import time

import ui
from ui import C
from lethe.identity import DeviceIdentity
from lethe.ring import provision_ring
from lethe.tap import NfcField
from lethe.handshake import (LetheDevice, bootstrap_tap, complete_handshake,
                             HandshakeError)
from lethe.transfer import seal_file
from lethe.policy import Policy, seal_package

BRIEF = ("OPERATION LETHE -- the river of forgetting.\n"
         "Grid reference 32.0542 N, 76.5046 E.\n"
         "Exfil window: 0300-0330. One reader. No copies.\n"
         "This brief self-destructs after a single view.\n")


def wait_for(field_file, what, timeout=120.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if os.path.exists(field_file):
            return
        time.sleep(0.2)
    raise HandshakeError(f"timed out waiting for {what}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--field", default=os.path.join("run", "twopeer", "field"))
    ap.add_argument("--channel", default=os.path.join("run", "twopeer", "channel"))
    args = ap.parse_args()

    ui.enable_color()
    for d in (args.field, args.channel):
        if os.path.exists(d):
            shutil.rmtree(d)
        os.makedirs(d)
    field = NfcField(args.field)

    ui.title("LETHE SENDER  |  DEVICE A (OFFICER-ALPHA)")
    alpha = DeviceIdentity("officer-alpha")
    ring = provision_ring(alpha, "recovery-secret-alpha")
    dev = LetheDevice("officer-alpha", alpha, ring)
    ui.info("identity (ed25519)", alpha.public.hex()[:24] + "...")
    ui.info("ring provisioned", f"{ring.size_bytes} bytes of 504, issuer-sealed")
    ui.ok("Device A booted, keystore-only private key")

    eph, m1 = bootstrap_tap(dev, field, "officer-bravo")
    ui.arrow("TAP 1 in the field: receiver key, nonce, challenge, metadata (signed)")
    ui.info("challenge", "0x" + m1.challenge.hex()[:8] + "...")
    print("  waiting for Device B to tap back...", flush=True)
    wait_for(os.path.join(args.field, "tap2.json"), "the tap2 answer")

    key, session = complete_handshake(dev, field, eph, m1)
    ui.ok("MUTUAL AUTHENTICATION COMPLETE", "challenge answered + verified")
    ui.info("session key (derived, never sent)", key.hex()[:24] + "...")

    src = os.path.join(args.channel, "brief.txt")
    enc = src + ".enc"
    with open(src, "w") as f:
        f.write(BRIEF)
    seal_file(key, src, enc)
    policy = Policy(max_views=1, recipient="officer-bravo",
                    note="one view, then ash")
    env = seal_package("brief.txt.enc", policy, open(enc, "rb").read(),
                       alpha.raw_priv())
    env.save(os.path.join(args.channel, "envelope.json"))
    ui.ok(f"Brief sealed ({os.path.getsize(enc)} bytes) + policy signed", "in channel")
    ui.arrow("ciphertext handed to the channel -- Device B, over to you")
    print()


if __name__ == "__main__":
    try:
        main()
    except HandshakeError as exc:
        print(f"\n  SENDER ABORTED: {exc}")
        sys.exit(1)
