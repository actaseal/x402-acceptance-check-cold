"""Pure-Python, stdlib-only Ed25519 signature verification (RFC 8032).

Independent implementation written from the RFC's own equations, not
ported from or compared against any other codebase. Uses the standard
unified/extended twisted-Edwards coordinates for the curve
edwards25519 (RFC 8032 section 5.1) to make scalar multiplication and
point addition constant-structure and avoid special-casing the point
at infinity. Verification follows RFC 8032 section 5.1.7,
including the cofactor-multiplication form of the final check
(8*S*B == 8*R + 8*k*A), with one deliberate addition: a public key or R
that is itself a small-order point is refused (verify() returns False).
The RFC allows those, and under them a single signature verifies every
message, so this is stricter than the RFC on purpose.
"""
from __future__ import annotations

import hashlib

# --- field and curve constants (RFC 8032 section 5.1) ---
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493  # group order
D = (-121665 * pow(121666, P - 2, P)) % P  # curve constant d
I = pow(2, (P - 1) // 4, P)  # a square root of -1 mod p

# Base point B
BY = (4 * pow(5, P - 2, P)) % P
BX = None  # computed below via recover_x


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def _recover_x(y: int, sign: int) -> int:
    if y >= P:
        raise ValueError("y out of range")
    xx = (y * y - 1) * _inv(D * y * y + 1) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if (x * x - xx) % P != 0:
        raise ValueError("point is not on the curve")
    if x % 2 != sign:
        x = P - x
    return x


BX = _recover_x(BY, 0)
B = (BX % P, BY % P, 1, (BX * BY) % P)  # extended coords (X, Y, Z, T)


def _point_add(P1, P2):
    X1, Y1, Z1, T1 = P1
    X2, Y2, Z2, T2 = P2
    A = (Y1 - X1) * (Y2 - X2) % P
    Bb = (Y1 + X1) * (Y2 + X2) % P
    C = T1 * 2 * D % P * T2 % P
    Dd = Z1 * 2 % P * Z2 % P
    E = Bb - A
    F = Dd - C
    G = Dd + C
    H = Bb + A
    X3 = E * F % P
    Y3 = G * H % P
    T3 = E * H % P
    Z3 = F * G % P
    return (X3 % P, Y3 % P, Z3 % P, T3 % P)


IDENTITY = (0, 1, 1, 0)


def _point_mul(s: int, point):
    result = IDENTITY
    addend = point
    while s > 0:
        if s & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        s >>= 1
    return result


def _point_equal(P1, P2) -> bool:
    X1, Y1, Z1, _ = P1
    X2, Y2, Z2, _ = P2
    if (X1 * Z2 - X2 * Z1) % P != 0:
        return False
    if (Y1 * Z2 - Y2 * Z1) % P != 0:
        return False
    return True


def _decode_point(data: bytes):
    if len(data) != 32:
        raise ValueError("point must be 32 bytes")
    y = int.from_bytes(data, "little") & ((1 << 255) - 1)
    sign = (data[31] >> 7) & 1
    x = _recover_x(y, sign)
    return (x % P, y % P, 1, (x * y) % P)


def _encode_point(point) -> bytes:
    X, Y, Z, _ = point
    zinv = _inv(Z)
    x = (X * zinv) % P
    y = (Y * zinv) % P
    out = bytearray(y.to_bytes(32, "little"))
    out[31] = (out[31] & 0x7F) | ((x & 1) << 7)
    return bytes(out)


def _point_has_small_order(point) -> bool:
    return _point_equal(_point_mul(8, point), IDENTITY)


def is_small_order(data: bytes) -> bool:
    """True if the 32-byte encoding `data` is one of the 8 points whose
    order divides 8 (the identity among them). False for any other
    point, and also for bytes that are not a curve point at all (those
    are rejected separately, by verify())."""
    try:
        return _point_has_small_order(_decode_point(data))
    except ValueError:
        return False


def _point_is_torsion_free(point) -> bool:
    return _point_equal(_point_mul(L, point), IDENTITY)


def is_mixed_order(data: bytes) -> bool:
    """True if `data` encodes a curve point that is neither small-order nor in
    the prime-order subgroup ([L]P is not the identity). Whether a signature
    under such a key, or with such an R, verifies depends on whether a
    verifier uses the cofactored or the cofactorless RFC 8032 equation.
    False for small-order points, subgroup points and non-points."""
    try:
        point = _decode_point(data)
    except ValueError:
        return False
    return not _point_has_small_order(point) and not _point_is_torsion_free(point)


class Ed25519VerifyError(ValueError):
    """Raised for a malformed key/signature or a failed verification."""


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Returns True if `signature` over `message` verifies under
    `public_key` (all raw bytes: 32-byte public key, 64-byte
    signature). Returns False for a cryptographically failed
    signature; raises Ed25519VerifyError for structurally malformed
    input (wrong lengths, a public key or R that isn't a valid curve
    point, or S outside [0, L)). Also returns False, whatever the
    message, if the public key or R is a small-order point: RFC 8032
    does not require refusing those, but under such a key one signature
    (R = identity, S = 0) verifies every message, so accepting it would
    bind nobody. Also returns False if the public key or R is a
    mixed-order point (outside the prime-order subgroup), because two
    conforming RFC 8032 verifiers can disagree on such a signature."""
    if len(public_key) != 32:
        raise Ed25519VerifyError("public key must be 32 bytes")
    if len(signature) != 64:
        raise Ed25519VerifyError("signature must be 64 bytes")

    r_bytes = signature[:32]
    s_bytes = signature[32:]
    s = int.from_bytes(s_bytes, "little")
    if s >= L:
        raise Ed25519VerifyError("S is not canonically reduced mod L")

    try:
        a_point = _decode_point(public_key)
        r_point = _decode_point(r_bytes)
    except ValueError as exc:
        raise Ed25519VerifyError(str(exc)) from exc

    if _point_has_small_order(a_point) or _point_has_small_order(r_point):
        return False
    # A mixed-order key or R: the result would depend on which RFC 8032
    # equation the verifier uses, so refuse it.
    if not _point_is_torsion_free(a_point) or not _point_is_torsion_free(r_point):
        return False

    k = int.from_bytes(hashlib.sha512(r_bytes + public_key + message).digest(), "little") % L

    sb = _point_mul(s, B)
    r_plus_ka = _point_add(r_point, _point_mul(k, a_point))

    # Cofactor form of the check (RFC 8032 5.1.7): multiply both sides
    # by the cofactor 8 before comparing, so a small-order component in
    # R or A can't slip a forgery past a non-cofactored equality check.
    lhs = _point_mul(8, sb)
    rhs = _point_mul(8, r_plus_ka)
    return _point_equal(lhs, rhs)
