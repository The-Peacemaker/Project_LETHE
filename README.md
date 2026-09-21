# LETHE — Core Brain (with the Base Paper grounding)

Two layers live in this folder:

1. **Base paper implementation** — Maarouf, Sakr & Elmougy (IEEE Access, 2024),
   DOI 10.1109/ACCESS.2024.3458424: offline ECC mutual authentication on
   brainpoolP256r1.
2. **LETHE core brain** — the product we are actually building: a zero-trust,
   offline, wearable-NFC-anchored secure file exchange. Runs headless on this
   PC today; the physical ring (NTAG215), ACR122U reader and Wi-Fi Direct hop
   are on the roadmap.

## The LETHE layer (the thing we are using)

| Module | Phase | What it proves |
|---|---|---|
| `lethe/identity.py` | 1 | ed25519 device identity, keystore-only private key |
| `lethe/ring.py` | 2 | NTAG215 payload — Owner ID(16) + Device Pub(32) + Recovery Hash(16) + Signature(64) = **128 B of 504 B**, issuer-attested |
| `lethe/tap.py` | 3 | Simulated NFC field — signed "tap" carrying only receiver key, nonce, metadata, challenge. Never a file |
| `lethe/handshake.py` | 4+5 | Mutual auth (challenge-response) + X25519 ECDH → HKDF-SHA256 → AES-256 session key, derived twice, sent never |
| `lethe/transfer.py` | 6+7 | AES-256-GCM 64 KB chunks, each verified; tamper = whole-file rejection |
| `lethe/policy.py` | 8 | PCCP signed envelope: max_views, expires_at, recipient, erasure-mode |
| `lethe/erasure.py` | 9 | Crypto-shredding key slot (NIST SP 800-88) — "Access denied. Cryptographic key has been destroyed." |
| `lethe/keys.py` | 5+ | FSKE forward-secure sub-keys (HKDF chain, previous key wiped per chunk) |

## The LETHE product demo (what to show)

```powershell
cd "C:\Users\bened\Documents\MAIN PROJECT\Implementation"
python lethe_product.py        # staged, press ENTER between scenes
python lethe_product.py --auto # straight run, for recording
python lethe_self_test.py      # 14 invariants
python lethe_attacks.py        # 14 attacks, all blocked
```

Eight scenes walk the whole protocol: two identities born → two rings
provisioned → alpha taps (only trust crosses the channel) → mutual
authentication → the key derived twice and never sent → the file flies as
verified AES-256-GCM chunks → the signed one-view policy → the second attempt
meets **"Access denied. Cryptographic key has been destroyed."** while the
ciphertext sits on disk as noise. Dim `SAY:` lines are the talk track.

## Base paper layer (grounding + status)

The full protocol of the base paper is implemented and green in `basepaper/` —
see the section below for the exact mapping.

```powershell
python product.py    # base-paper product demo (6 scenes)
python demo.py       # install -> register -> mutual auth -> session key
python attacks.py    # 10/10 attacks from the paper rejected
python self_test.py  # group laws, ECCDHP, forward secrecy
```

## Protocol mapping (Maarouf et al. 2024)

### Installation phase (paper Sec. III-A)
- 128-bit UUID (RFC 4122) per entity, ECC keypair on brainpoolP256r1,
  256-bit long-term master secret `Xs`.

### Registration phase (paper Sec. III-B)
- **User device (QR):** server computes `Tki = h(h(Xs) || UIDi || Ex)` and
  issues `{Tki, PLocal, Ex, SID}` via a QR code; device stores it in the smart card.
  (`LocalServer.register_user`, `UserDevice.provision_from_qr`)
- **IoMT device (BLE):** device sends `{DIDi, PDevice}`; the server encrypts the
  same credential bundle with `PDevice` and the device decrypts with its private key.
  (`LocalServer.register_device`, `IoMTDevice.register`)

### Login authentication phase (paper Sec. III-C, Fig. 10/11)
Five steps, message-identical to the paper:

1. Device picks ephemeral `Ri`, computes `Gi = g*Ri`,
   anonymous ID `RIDUi = h(Gi) XOR (Tki || UIDi || Ex)`, plus `h(bi || SID)`;
   sends `M = Enc_PLocal(RIDUi, Gi, h(bi||SID))`.   (`login_step1`)
2. Server decrypts, recovers `(Tki || UIDi || Ex)`, checks the token freshness
   `Tk'i = h(h(Xs) || UIDi || Ex)`; picks `Rj`, computes `Gj = g*Rj`,
   `P1 = h(RIDUi || SID || Gi || Gj)`; replies
   `N = Enc_PUser(P1 || Gi || Gj)`.                  (`user_login`)
3. Device decrypts `N`, verifies `P1' = P1` fresh, computes
   `P2 = h(P1' || Gj*Ri)` and `SK = h(RIDUi || SID || Gj*Ri)`;
   sends `P2` and `V = Enc_PLocal(SK, Gi, Gj)`.     (`login_step2`)
4. Server verifies `P2' = h(P1 || Gi*Rj)` using the **ECCDHP property**
   `Gi*Rj = Gj*Ri = g*Ri*Rj`, then decrypts `V` to obtain `SK`. (`user_finish`)

Result: **mutual authentication** and a shared session key that is never
transmitted on the channel.

## Security analysis reproduced (`attacks.py`)

Replay of `M` / old `(P2,V)`, forward secrecy (fresh keys per session),
MITM (ciphertext corruption + forged token), impersonation, expired token,
duplicate-registration DoS, tampering, and off-curve point injection — each
is rejected, matching the paper's informal analysis (Sec. IV-A).

## Status

Base paper:
- [x] Installation + registration (QR / BLE) complete
- [x] 5-step login mutual authentication complete
- [x] ECCDHP session-key agreement verified
- [x] Attack analysis reproduced (10/10 rejected)
- [x] Demo + self-test green

LETHE core brain:
- [x] Phase 1-2: identities + rings (128 B of 504 B, issuer-attested)
- [x] Phase 3: tap simulation (trust-only channel)
- [x] Phase 4-5: mutual auth + X25519 ECDH → HKDF → AES-256 (never sent)
- [x] Phase 6-7: AES-256-GCM chunked flight, verified chunk-by-chunk
- [x] Phase 8: PCCP signed policy envelope (max_views / expiry / recipient)
- [x] Phase 9: crypto-shredding key slot — second view meets the line
- [x] Self-test green (14 invariants) + attack battery (14/14 blocked)

## Next steps (hardware + hardening)

- NFC rings (NTAG215) + ACR122U reader on order; swap `NfcField` for real tap
- Wi-Fi Direct socket between two devices (Phase 6)
- TERA ring attestation + AOTBC trust scoring on real RSSI data
- CoRDe duress PIN, policy update without re-encryption
- Tamarin formal model (parallel)