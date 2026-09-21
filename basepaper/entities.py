"""Protocol entities implementing Maarouf et al. 2024:

Installation phase  -> UUID (RFC 4122), brainpoolP256r1 keypairs, master secret Xs.
Registration phase  -> user device via QR-code token, IoMT device via encrypted BLE token.
Login auth phase    -> 5-step mutual authentication + session key via the ECCDHP property
                       Gi*Rj = Gj*Ri = g*Ri*Rj.
"""

import os
import struct
import time
import uuid

from basepaper.curve import mul, serialize, deserialize, on_curve, is_identity, rand_scalar, GX, GY, N
from basepaper.primitives import (
    h, h_ext, xor_bytes, concat, keygen, shared_secret,
    ecies_encrypt, ecies_decrypt, ct_eq, CryptoError,
)

EX_BYTES = 8
UID_BYTES = 16
HASH_BYTES = 32


class ProtocolError(Exception):
    pass


def _decrypt(scalar, blob):
    try:
        return ecies_decrypt(scalar, blob)
    except CryptoError as exc:
        raise ProtocolError(str(exc))


def _expect_point(blob, label):
    pt = deserialize(blob)
    if is_identity(pt):
        raise ProtocolError(f"{label} is the point at infinity")
    if not on_curve(pt):
        raise ProtocolError(f"{label} is not a valid point on the curve")
    return pt


# ------------------------------------------------------------------ tiny framing
def _frame(*fields):
    out = b""
    for f in fields:
        out += struct.pack(">I", len(f)) + f
    return out


def _unframe(blob):
    parts = []
    i = 0
    while i < len(blob):
        (n,) = struct.unpack(">I", blob[i:i + 4])
        i += 4
        parts.append(blob[i:i + n])
        i += n
    return parts


def _point_bytes(pt):
    return serialize(pt)


def _lifetime():
    return time.time()


# ------------------------------------------------------------------ Local Server
class LocalServer:
    """S: holds Xs (256-bit master secret), an ECC keypair (SKs, PLocal), SID and a
    registry of users/devices. Authenticates both parties offline (LAN only)."""

    def __init__(self, sid=None):
        self.SID = sid if sid is not None else uuid.uuid4().bytes
        self.Xs = os.urandom(32)                  # 256-bit long-term master secret
        self.SKs, self.PLocal = keygen()          # server ECC keypair
        self.users = {}                           # UIDi -> {"P": PUser, "Ex": Ex}
        self.devices = {}                         # DIDi -> {"P": PDevice, "Ex": Ex}
        self.sessions = {}                        # RID  -> ephemeral state

    # ---------------------------- registration: user device (QR) ----------------------------
    def register_user(self, UID, PUser, Ex):
        if UID in self.users:
            raise ProtocolError("UIDi already registered (duplicate registration rejected)")
        self.users[UID] = {"P": PUser, "Ex": Ex}
        return self._token(UID, Ex)

    # ---------------------------- registration: IoMT device (encrypted BLE) ----------------------------
    def register_device(self, DID, PDevice, Ex):
        if DID in self.devices:
            raise ProtocolError("DIDi already registered (duplicate registration rejected)")
        self.devices[DID] = {"P": PDevice, "Ex": Ex}
        Tki = self._token(DID, Ex)
        credentials = _frame(Tki, _point_bytes(self.PLocal), Ex.to_bytes(EX_BYTES, "big"), self.SID)
        return ecies_encrypt(PDevice, credentials)

    # ---------------------------- shared helpers ----------------------------
    def _token(self, identity, Ex):
        return h(concat(h(self.Xs), identity, Ex.to_bytes(EX_BYTES, "big")))

    def _recover(self, RID, Gi_bytes):
        mask = h_ext(Gi_bytes, HASH_BYTES + UID_BYTES + EX_BYTES)
        return xor_bytes(RID, mask)

    def _check_token(self, identity, Ex, received_tk):
        expected = self._token(identity, Ex)
        if not ct_eq(expected, received_tk):
            raise ProtocolError("token freshness check failed: Tk'i != Tki")
        if Ex < _lifetime():
            raise ProtocolError("token expired: Ex timestamp passed")

    # ---------------------------- 5-step login authentication ----------------------------
    def user_login(self, M_blob):
        return self._login(self.users, M_blob)

    def device_login(self, M_blob):
        return self._login(self.devices, M_blob)

    def _login(self, registry, M_blob):
        """Step 3 (server side). Returns message N encrypted for the client."""
        inner = _decrypt(self.SKs, M_blob)
        RID, Gi_bytes, h_bi_sid = _unframe(inner)
        _expect_point(Gi_bytes, "Gi")

        recovered = self._recover(RID, Gi_bytes)
        Tki_recv = recovered[:HASH_BYTES]
        ID = recovered[HASH_BYTES:HASH_BYTES + UID_BYTES]
        Ex = int.from_bytes(recovered[HASH_BYTES + UID_BYTES:], "big")

        rec = registry.get(ID)
        if rec is None:
            raise ProtocolError("identity not found in server database")
        self._check_token(ID, Ex, Tki_recv)

        Rj = rand_scalar()                        # step: server picks ephemeral Rj
        Gj = mul(Rj, (GX, GY))
        P1 = h(concat(RID, self.SID, Gi_bytes, _point_bytes(Gj)))

        self.sessions[RID] = {"P1": P1, "Gi": Gi_bytes, "Gj": Gj, "Rj": Rj}
        N_blob = ecies_encrypt(rec["P"], _frame(P1, Gi_bytes, _point_bytes(Gj)))
        return N_blob

    def user_finish(self, RID, P2, V_blob):
        """Step 5 (server side). Verifies P2 via ECCDHP and decrypts the session key."""
        sess = self.sessions.get(RID)
        if sess is None:
            raise ProtocolError("no active session for RID (replay?)")

        shared = mul(sess["Rj"], deserialize(sess["Gi"]))     # Gi*Rj  (ECCDHP)
        P2p = h(concat(sess["P1"], _point_bytes(shared)))
        if not ct_eq(P2p, P2):
            raise ProtocolError("P2 mismatch: server cannot derive P2' == P2")
        if not ct_eq(_point_bytes(sess["Gj"]), _point_bytes(mul(sess["Rj"], (GX, GY)))):
            raise ProtocolError("Gj integrity violation")

        inner = _decrypt(self.SKs, V_blob)
        SK, Gi_back, Gj_back = _unframe(inner)
        if not ct_eq(Gi_back, sess["Gi"]):
            raise ProtocolError("V tampered: Gi inside V does not match session")
        return SK


# ------------------------------------------------------------------ User Device
class UserDevice:
    """U_i: stores UIDi + keypair (SKu, PUser); smart card holds {Tki, SID, Ex, PLocal}
    provisioned by scanning the server's QR code during registration."""

    def __init__(self, uid=None):
        self.UID = uid if uid is not None else uuid.uuid4().bytes
        self.SKu, self.PUser = keygen()
        self.card = None            # {"Tki":..., "SID":..., "Ex":..., "PLocal":...}
        self._state = None

    # ---------------------------- registration: scan QR ----------------------------
    def provision_from_qr(self, Tki, SID, Ex, PLocal):
        self.card = {"Tki": Tki, "SID": SID, "Ex": Ex, "PLocal": PLocal}

    # ---------------------------- 5-step login authentication ----------------------------
    def login_step1(self):
        """Steps 1-2 (user side). Returns message M."""
        Ri = rand_scalar()
        Gi = mul(Ri, (GX, GY))
        Gi_bytes = _point_bytes(Gi)

        token_field = concat(self.card["Tki"], self.UID, self.card["Ex"].to_bytes(EX_BYTES, "big"))
        mask = h_ext(Gi_bytes, HASH_BYTES + UID_BYTES + EX_BYTES)
        RID = xor_bytes(token_field, mask)

        bi = os.urandom(UID_BYTES)
        h_bi_sid = h(concat(bi, self.card["SID"]))
        self._state = {"Ri": Ri, "Gi": Gi_bytes, "RID": RID}
        M_blob = ecies_encrypt(self.card["PLocal"], _frame(RID, Gi_bytes, h_bi_sid))
        return M_blob, RID

    def login_step2(self, N_blob):
        """Step 4 (user side). Returns (P2, V) and the derived session key."""
        inner = _decrypt(self.SKu, N_blob)
        P1, Gi_back, Gj_bytes = _unframe(inner)
        _expect_point(Gj_bytes, "Gj")
        if not ct_eq(Gi_back, self._state["Gi"]):
            raise ProtocolError("server echoed a different Gi")

        RID = self._state["RID"]
        SID = self.card["SID"]
        P1p = h(concat(RID, SID, self._state["Gi"], Gj_bytes))
        if not ct_eq(P1p, P1):
            raise ProtocolError("P1 fresh check failed: P1 != P1' (server not authentic)")

        shared = mul(self._state["Ri"], deserialize(Gj_bytes))     # Gj*Ri  (ECCDHP)
        P2 = h(concat(P1p, _point_bytes(shared)))
        SK = h(concat(RID, SID, _point_bytes(shared)))
        V_blob = ecies_encrypt(self.card["PLocal"],
                               _frame(SK, self._state["Gi"], Gj_bytes))
        self._state["shared"] = shared
        return P2, V_blob, SK


# ------------------------------------------------------------------ IoMT Device
class IoMTDevice:
    """D_i: same protocol, identity DIDi, smart card provisioned over an encrypted BLE
    registration (server encrypts credentials with PDevice)."""

    def __init__(self, did=None):
        self.DID = did if did is not None else uuid.uuid4().bytes
        self.SKd, self.PDevice = keygen()
        self.card = None
        self._state = None

    def register(self, server, Ex):
        blob = server.register_device(self.DID, self.PDevice, Ex)
        inner = _decrypt(self.SKd, blob)
        Tki, PLocal_bytes, ex_b, SID = _unframe(inner)
        self.card = {"Tki": Tki, "SID": SID, "Ex": int.from_bytes(ex_b, "big"),
                     "PLocal": deserialize(PLocal_bytes)}

    def login_step1(self):
        Ri = rand_scalar()
        Gi = mul(Ri, (GX, GY))
        Gi_bytes = _point_bytes(Gi)

        token_field = concat(self.card["Tki"], self.DID, self.card["Ex"].to_bytes(EX_BYTES, "big"))
        mask = h_ext(Gi_bytes, HASH_BYTES + UID_BYTES + EX_BYTES)
        RID = xor_bytes(token_field, mask)

        bi = os.urandom(UID_BYTES)
        h_bi_sid = h(concat(bi, self.card["SID"]))
        self._state = {"Ri": Ri, "Gi": Gi_bytes, "RID": RID}
        M_blob = ecies_encrypt(self.card["PLocal"], _frame(RID, Gi_bytes, h_bi_sid))
        return M_blob, RID

    def login_step2(self, N_blob):
        inner = _decrypt(self.SKd, N_blob)
        P1, Gi_back, Gj_bytes = _unframe(inner)
        _expect_point(Gj_bytes, "Gj")
        if not ct_eq(Gi_back, self._state["Gi"]):
            raise ProtocolError("server echoed a different Gi")

        RID = self._state["RID"]
        SID = self.card["SID"]
        P1p = h(concat(RID, SID, self._state["Gi"], Gj_bytes))
        if not ct_eq(P1p, P1):
            raise ProtocolError("P1 fresh check failed: P1 != P1' (server not authentic)")

        shared = mul(self._state["Ri"], deserialize(Gj_bytes))     # Gj*Ri  (ECCDHP)
        P2 = h(concat(P1p, _point_bytes(shared)))
        SK = h(concat(RID, SID, _point_bytes(shared)))
        V_blob = ecies_encrypt(self.card["PLocal"],
                               _frame(SK, self._state["Gi"], Gj_bytes))
        self._state["shared"] = shared
        return P2, V_blob, SK