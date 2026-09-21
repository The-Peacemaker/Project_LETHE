"""brainpoolP256r1 (RFC 5639) elliptic curve arithmetic, implemented from scratch
in Jacobian projective coordinates to avoid field inversions during scalar mult."""

from secrets import randbelow

# ------------------------------------------------------------------ curve params
P = int.from_bytes(bytes.fromhex(
    "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377"), "big")
A = int.from_bytes(bytes.fromhex(
    "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9"), "big")
B = int.from_bytes(bytes.fromhex(
    "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6"), "big")
GX = int.from_bytes(bytes.fromhex(
    "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262"), "big")
GY = int.from_bytes(bytes.fromhex(
    "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997"), "big")
N = int.from_bytes(bytes.fromhex(
    "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"), "big")

BYTES = 32
INF = None


# ------------------------------------------------------------------ field helpers
def _add(a, b):
    return (a + b) % P


def _sub(a, b):
    return (a - b) % P


def _mul(a, b):
    return (a * b) % P


def _inv(a):
    return pow(a, P - 2, P)


# ------------------------------------------------------------------ jacobian ops
def _dbl(X1, Y1, Z1):
    if Y1 == 0 or Z1 == 0:
        return INF
    S = _mul(4, _mul(X1, _mul(Y1, Y1)))
    M = _add(_mul(3, _mul(X1, X1)), _mul(A, _mul(_mul(Z1, Z1), _mul(Z1, Z1))))
    X3 = _sub(_mul(M, M), _mul(2, S))
    Y3 = _sub(_mul(M, _sub(S, X3)), _mul(8, _mul(_mul(Y1, Y1), _mul(Y1, Y1))))
    Z3 = _mul(2, _mul(Y1, Z1))
    return (X3, Y3, Z3)


def _add_jac(P, Q):
    if P is INF:
        return Q
    if Q is INF:
        return P
    X1, Y1, Z1 = P
    X2, Y2, Z2 = Q
    Z1Z1 = _mul(Z1, Z1)
    Z2Z2 = _mul(Z2, Z2)
    U1 = _mul(X1, Z2Z2)
    U2 = _mul(X2, Z1Z1)
    S1 = _mul(Y1, _mul(Z2, Z2Z2))
    S2 = _mul(Y2, _mul(Z1, Z1Z1))
    if U1 == U2:
        if S1 != S2:
            return INF
        return _dbl(X1, Y1, Z1)
    H = _sub(U2, U1)
    R = _sub(S2, S1)
    H2 = _mul(H, H)
    H3 = _mul(H, H2)
    U1H2 = _mul(U1, H2)
    X3 = _sub(_sub(_mul(R, R), H3), _mul(2, U1H2))
    Y3 = _sub(_mul(R, _sub(U1H2, X3)), _mul(S1, H3))
    Z3 = _mul(_mul(Z1, Z2), H)
    return (X3, Y3, Z3)


def _to_affine(Q):
    if Q is INF:
        return INF
    X, Y, Z = Q
    zi = _inv(Z)
    zi2 = _mul(zi, zi)
    x = _mul(X, zi2)
    y = _mul(Y, _mul(zi, zi2))
    return (x, y)


def mul(k, point):
    """Return k*P for integer k and affine point P."""
    if k % N == 0:
        return INF
    G_jac = (GX, GY, 1) if point == (GX, GY) else _lifty(point)
    R = INF
    while k:
        if k & 1:
            R = _add_jac(R, G_jac)
        G_jac = _dbl(*G_jac)
        k >>= 1
    return _to_affine(R)


def _lifty(point):
    x, y = point
    return (x, y, 1)


def add(p, q):
    if p is INF:
        return q
    if q is INF:
        return p
    return _to_affine(_add_jac(_lifty(p), _lifty(q)))


def on_curve(point):
    if point is INF:
        return True
    x, y = point
    lhs = _mul(y, y)
    rhs = _add(_add(_mul(x, _mul(x, x)), _mul(A, x)), B)
    return lhs == rhs


def is_identity(point):
    return point is INF


# ------------------------------------------------------------------ serialization
def serialize(point):
    import struct
    if point is INF:
        return b"\x00" + b"\x00" * 64
    x, y = point
    return b"\x02" + x.to_bytes(BYTES, "big") + y.to_bytes(BYTES, "big")


def deserialize(data):
    if data[0] == 0x00:
        return INF
    x = int.from_bytes(data[1:33], "big")
    y = int.from_bytes(data[33:65], "big")
    return (x, y)


def rand_scalar():
    return randbelow(N - 1) + 1