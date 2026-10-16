"""ed25519_verify.verify() on its own must refuse small-order public keys and
small-order R (return False), so it is safe to use standalone. The key_unresolved /
signature_invalid split is checker.py's and is covered by test_acceptance_conformance.

Run:  python3 -m unittest discover -s tests
"""
import hashlib
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import ed25519_verify as E  # noqa: E402

# The 8 points whose order divides 8 (identity, order 2, two of order 4, four of order 8).
SMALL_ORDER = {
    "identity": "0100000000000000000000000000000000000000000000000000000000000000",
    "order-2": "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "order-4-a": "0000000000000000000000000000000000000000000000000000000000000000",
    "order-4-b": "0000000000000000000000000000000000000000000000000000000000000080",
    "order-8-a": "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "order-8-b": "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "order-8-c": "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "order-8-d": "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
}
SMALL_ORDER = {k: bytes.fromhex(v) for k, v in SMALL_ORDER.items()}
IDENTITY = SMALL_ORDER["identity"]


def _keypair(seed: bytes):
    """RFC 8032 5.1.5: returns (scalar a, prefix, public key bytes)."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:], E._encode_point(E._point_mul(a, E.B))


def _sign(seed: bytes, msg: bytes) -> tuple[bytes, bytes]:
    a, prefix, pub = _keypair(seed)
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % E.L
    r_enc = E._encode_point(E._point_mul(r, E.B))
    k = int.from_bytes(hashlib.sha512(r_enc + pub + msg).digest(), "little") % E.L
    return pub, r_enc + ((r + k * a) % E.L).to_bytes(32, "little")


class SmallOrderTable(unittest.TestCase):
    def test_the_eight_encodings_are_distinct_small_order_points(self):
        points = set()
        for name, raw in SMALL_ORDER.items():
            with self.subTest(point=name):
                pt = E._decode_point(raw)
                self.assertTrue(E._point_equal(E._point_mul(8, pt), E.IDENTITY))
                points.add((pt[0] * pow(pt[2], E.P - 2, E.P) % E.P, pt[1] * pow(pt[2], E.P - 2, E.P) % E.P))
        self.assertEqual(len(points), 8)


class VerifyRefusesSmallOrder(unittest.TestCase):
    def test_identity_key_forged_signature(self):
        # R = identity, S = 0 verifies every message under the identity key.
        for msg in (b"", b"any message", b"x" * 1000):
            with self.subTest(msg=msg[:8]):
                self.assertIs(E.verify(IDENTITY, msg, IDENTITY + bytes(32)), False)

    def test_every_small_order_key_with_a_signature_that_satisfies_the_cofactored_equation(self):
        # 8A = identity for these, so R = [S]B satisfies 8[S]B = 8R + 8[k]A for every message.
        s = 5
        r_enc = E._encode_point(E._point_mul(s, E.B))
        for name, key in SMALL_ORDER.items():
            with self.subTest(key=name):
                self.assertIs(E.verify(key, b"message", r_enc + s.to_bytes(32, "little")), False)

    def test_every_small_order_R_under_a_real_key(self):
        # R small-order, S = k*a mod L: passes [S]B = R + [k]A for the real key (the
        # acc-small-order-r-real-key shape). A small-order R is refused.
        a, _, pub = _keypair(b"\x07" * 32)
        msg = b"message"
        for name, r_enc in SMALL_ORDER.items():
            with self.subTest(R=name):
                k = int.from_bytes(hashlib.sha512(r_enc + pub + msg).digest(), "little") % E.L
                self.assertIs(E.verify(pub, msg, r_enc + ((k * a) % E.L).to_bytes(32, "little")), False)



def _torsion_point():
    return E._decode_point(SMALL_ORDER["order-8-a"])


class VerifyRefusesMixedOrder(unittest.TestCase):
    """Sentence 9: a key or R outside the prime-order subgroup ([L]P is not the
    identity) but not small-order. Whether such a signature verifies depends on
    the RFC 8032 equation a verifier uses, so verify() refuses both."""

    def _mixed_key_signature(self, msg):
        a, prefix, pub = _keypair(b"seed-mixed-key")
        mixed = E._encode_point(E._point_add(E._decode_point(pub), _torsion_point()))
        r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % E.L
        r_enc = E._encode_point(E._point_mul(r, E.B))
        k = int.from_bytes(hashlib.sha512(r_enc + mixed + msg).digest(), "little") % E.L
        return mixed, r_enc + ((r + k * a) % E.L).to_bytes(32, "little")

    def _mixed_r_signature(self, msg):
        a, prefix, pub = _keypair(b"seed-mixed-r")
        r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % E.L
        r_enc = E._encode_point(E._point_add(E._point_mul(r, E.B), _torsion_point()))
        k = int.from_bytes(hashlib.sha512(r_enc + pub + msg).digest(), "little") % E.L
        return pub, r_enc + ((r + k * a) % E.L).to_bytes(32, "little")

    def test_mixed_order_key_is_refused(self):
        msg = b"m"
        pub, sig = self._mixed_key_signature(msg)
        self.assertTrue(E.is_mixed_order(pub))
        self.assertFalse(E.verify(pub, msg, sig))

    def test_mixed_order_r_is_refused(self):
        msg = b"m"
        pub, sig = self._mixed_r_signature(msg)
        self.assertTrue(E.is_mixed_order(sig[:32]))
        self.assertFalse(E.verify(pub, msg, sig))

    def test_is_mixed_order_is_false_for_good_small_and_non_points(self):
        _, _, pub = _keypair(b"seed-good")
        self.assertFalse(E.is_mixed_order(pub))
        for name, enc in SMALL_ORDER.items():
            with self.subTest(point=name):
                self.assertFalse(E.is_mixed_order(enc))
        self.assertFalse(E.is_mixed_order(b"\x02" + b"\x00" * 31))

class VerifyStillWorks(unittest.TestCase):
    def test_genuine_signature_verifies(self):
        for seed in (b"\x01" * 32, b"\x07" * 32, bytes(range(32))):
            for msg in (b"", b"11 bytes ok.", bytes(64), b"y" * 1000):
                with self.subTest(seed=seed[:2], n=len(msg)):
                    pub, sig = _sign(seed, msg)
                    self.assertIs(E.verify(pub, msg, sig), True)

    def test_tampered_message_or_signature_is_false(self):
        pub, sig = _sign(b"\x01" * 32, b"message")
        self.assertIs(E.verify(pub, b"messagE", sig), False)
        bad = bytearray(sig)
        bad[40] ^= 1
        self.assertIs(E.verify(pub, b"message", bytes(bad)), False)

    def test_structurally_malformed_input_still_raises(self):
        pub, sig = _sign(b"\x01" * 32, b"m")
        with self.assertRaises(E.Ed25519VerifyError):
            E.verify(pub[:31], b"m", sig)
        with self.assertRaises(E.Ed25519VerifyError):
            E.verify(pub, b"m", sig[:63])
        with self.assertRaises(E.Ed25519VerifyError):  # S not reduced mod L
            E.verify(pub, b"m", sig[:32] + E.L.to_bytes(32, "little"))


if __name__ == "__main__":
    unittest.main()
