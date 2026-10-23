"""Ed25519 (RFC 8032), ECDSA P-256/P-384 and RSA PKCS#1 v1.5 / PSS
verification with Python integers. Verification only, standard library
only; not constant time, never use it to sign."""
import hashlib

# ---------------------------------------------------------------- Ed25519
P25519 = 2**255 - 19
L25519 = 2**252 + 27742317777372353535851937790883648493
D25519 = (-121665 * pow(121666, -1, P25519)) % P25519
I25519 = pow(2, (P25519 - 1) // 4, P25519)
IDENTITY = (0, 1, 1, 0)


def _ed_add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P25519
    b = (p[1] + p[0]) * (q[1] + q[0]) % P25519
    c = 2 * p[3] * q[3] * D25519 % P25519
    d = 2 * p[2] * q[2] % P25519
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P25519, g * h % P25519, f * g % P25519, e * h % P25519)


def _ed_mul(s, p):
    q = IDENTITY
    while s:
        if s & 1:
            q = _ed_add(q, p)
        p = _ed_add(p, p)
        s >>= 1
    return q


def _ed_eq(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % P25519 == 0 and (p[1] * q[2] - q[1] * p[2]) % P25519 == 0


def ed_decode(enc, *, canonical=True):
    """Point from 32 bytes, or None. canonical=True refuses y >= p."""
    if len(enc) != 32:
        return None
    y = int.from_bytes(enc, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if canonical and y >= P25519:
        return None
    y %= P25519
    u = (y * y - 1) % P25519
    v = (D25519 * y * y + 1) % P25519
    x = pow(u * pow(v, -1, P25519), (P25519 + 3) // 8, P25519)
    if (v * x * x - u) % P25519 != 0:
        x = x * I25519 % P25519
    if (v * x * x - u) % P25519 != 0:
        return None
    if x == 0 and sign:
        return None
    if (x & 1) != sign:
        x = P25519 - x
    return (x, y, 1, x * y % P25519)


_BY = 4 * pow(5, -1, P25519) % P25519
BASE = ed_decode(_BY.to_bytes(32, "little"))


def ed_prime_order(point):
    """True iff the point is not the identity and has order exactly L."""
    return not _ed_eq(point, IDENTITY) and _ed_eq(_ed_mul(L25519, point), IDENTITY)


def ed_key_ok(pub):
    """The profile's key rule: a canonical encoding (y < p) of a point of prime order."""
    a = ed_decode(pub, canonical=True)
    return a is not None and ed_prime_order(a)


def ed_verify(pub, msg, sig):
    if len(sig) != 64:
        return False
    a = ed_decode(pub, canonical=True)
    r = ed_decode(sig[:32], canonical=False)
    s = int.from_bytes(sig[32:], "little")
    if a is None or r is None or s >= L25519:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % L25519
    return _ed_eq(_ed_mul(s, BASE), _ed_add(r, _ed_mul(k, a)))


# ------------------------------------------------------------------ ECDSA
CURVES = {
    "1.2.840.10045.3.1.7": dict(  # P-256
        name="P-256",
        p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        a=-3,
        b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        gx=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        gy=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
        n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        size=32),
    "1.3.132.0.34": dict(  # P-384
        name="P-384",
        p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
        a=-3,
        b=0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
        gx=0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
        gy=0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
        n=0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
        size=48),
}


def _ec_add(c, p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    p = c["p"]
    if p1[0] == p2[0]:
        if (p1[1] + p2[1]) % p == 0:
            return None
        lam = (3 * p1[0] * p1[0] + c["a"]) * pow(2 * p1[1], -1, p) % p
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, p) % p
    x = (lam * lam - p1[0] - p2[0]) % p
    return (x, (lam * (p1[0] - x) - p1[1]) % p)


def _ec_mul(c, k, pt):
    r = None
    while k:
        if k & 1:
            r = _ec_add(c, r, pt)
        pt = _ec_add(c, pt, pt)
        k >>= 1
    return r


def ec_on_curve(c, pt):
    x, y = pt
    p = c["p"]
    return 0 <= x < p and 0 <= y < p and (y * y - (x * x * x + c["a"] * x + c["b"])) % p == 0


def ecdsa_verify(curve_oid, point_bytes, digest, r, s):
    """Verify (r, s) over an already-hashed message; the leftmost bits of the
    digest are used (FIPS 186-4)."""
    c = CURVES[curve_oid]
    size = c["size"]
    if len(point_bytes) != 1 + 2 * size or point_bytes[0] != 4:
        return False
    q = (int.from_bytes(point_bytes[1:1 + size], "big"), int.from_bytes(point_bytes[1 + size:], "big"))
    n = c["n"]
    if not ec_on_curve(c, q) or not (1 <= r < n and 1 <= s < n):
        return False
    e = int.from_bytes(digest, "big")
    excess = len(digest) * 8 - n.bit_length()
    if excess > 0:
        e >>= excess
    w = pow(s, -1, n)
    pt = _ec_add(c, _ec_mul(c, e * w % n, (c["gx"], c["gy"])), _ec_mul(c, r * w % n, q))
    return pt is not None and pt[0] % n == r


# -------------------------------------------------------------------- RSA
_DIGEST_INFO = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def rsa_pkcs1_verify(n, e, hash_name, digest, sig):
    k = (n.bit_length() + 7) // 8
    if len(sig) != k or int.from_bytes(sig, "big") >= n:
        return False
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    t = _DIGEST_INFO[hash_name] + digest
    if k < len(t) + 11:
        return False
    return em == b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def _mgf1(seed, length, hash_name):
    out, counter = b"", 0
    while len(out) < length:
        out += hashlib.new(hash_name, seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def rsa_pss_verify(n, e, hash_name, mgf_hash, salt_len, digest, sig):
    k = (n.bit_length() + 7) // 8
    if len(sig) != k or int.from_bytes(sig, "big") >= n:
        return False
    em_bits = n.bit_length() - 1
    em_len = (em_bits + 7) // 8
    m = pow(int.from_bytes(sig, "big"), e, n)
    if m.bit_length() > em_bits:
        return False
    em = m.to_bytes(em_len, "big")
    h_len = len(digest)
    if em_len < h_len + salt_len + 2 or em[-1] != 0xBC:
        return False
    masked, h = em[:em_len - h_len - 1], em[em_len - h_len - 1:-1]
    top_zero_bits = 8 * em_len - em_bits
    if top_zero_bits and masked[0] >> (8 - top_zero_bits):
        return False
    db = bytes(a ^ b for a, b in zip(masked, _mgf1(h, len(masked), mgf_hash)))
    if top_zero_bits:
        db = bytes([db[0] & (0xFF >> top_zero_bits)]) + db[1:]
    pad = em_len - h_len - salt_len - 2
    if db[:pad] != b"\x00" * pad or db[pad] != 1:
        return False
    salt = db[len(db) - salt_len:] if salt_len else b""
    return hashlib.new(hash_name, b"\x00" * 8 + digest + salt).digest() == h
