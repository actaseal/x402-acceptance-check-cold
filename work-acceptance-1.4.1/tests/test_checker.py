"""Checker tests. The 57-vector test needs the vectors: set WA_VECTORS to a
directory holding vectors/*.json at maximusrufus/work-acceptance-record@bc5a138,
or let it fetch them (network); it skips when neither is possible.

    python -I -m unittest discover -s tests          (from this folder, with sys.path set by the tests)
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import run_vectors  # noqa: E402
import wa_check  # noqa: E402
import wa_crypto  # noqa: E402

# the 11 double classes of stillmarcus24/assurance-run#2 (JSON text, RFC 8785 text)
DOUBLES = [("1e-5", "0.00001"), ("1e-7", "1e-7"), ("1.2345678901234568e+20", "123456789012345680000"),
           ("0.1", "0.1"), ("1e21", "1e+21"), ("1e100", "1e+100"), ("5e-324", "5e-324"),
           ("1.0", "1"), ("100.0", "100"), ("-0.0", "0"), ("3.0e2", "300")]


class Jcs(unittest.TestCase):
    def test_double_classes(self):
        for text, want in DOUBLES:
            with self.subTest(text):
                self.assertEqual(wa_check.jcs(json.loads(text)), want)

    @unittest.skipUnless(shutil.which("node"), "node not on PATH")
    def test_double_classes_equal_node(self):
        script = "for (const t of JSON.parse(process.argv[1])) console.log(JSON.stringify(JSON.parse(t)));"
        out = subprocess.run(["node", "-e", script, json.dumps([t for t, _ in DOUBLES])],
                             capture_output=True, text=True, check=True).stdout.split()
        self.assertEqual(out, [w for _, w in DOUBLES])

    def test_keys_sort_by_utf16_unit(self):
        self.assertEqual(wa_check.jcs({"￿": 1, "\U0001F600": 2}), '{"\U0001F600":2,"￿":1}')


class Crypto(unittest.TestCase):
    def test_curve_constants_are_self_consistent(self):
        for c in wa_crypto.CURVES.values():
            g = (c["gx"], c["gy"])
            self.assertTrue(wa_crypto.ec_on_curve(c, g))
            self.assertIsNone(wa_crypto._ec_mul(c, c["n"], g))

    def test_key_rule(self):
        self.assertTrue(wa_crypto.ed_key_ok(bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")))
        self.assertFalse(wa_crypto.ed_key_ok(bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000")))  # neutral
        self.assertFalse(wa_crypto.ed_key_ok(bytes.fromhex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")))  # y = p + 1... non-canonical

    def test_rfc8032_vector_1(self):
        pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        self.assertTrue(wa_crypto.ed_verify(pub, b"", sig))
        self.assertFalse(wa_crypto.ed_verify(pub, b"x", sig))


def _vectors_dir():
    d = os.environ.get("WA_VECTORS")
    if d and os.path.isdir(d):
        return d
    tmp = tempfile.mkdtemp(prefix="wa-vectors-")
    try:
        run_vectors.fetch(tmp)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        return None
    return tmp


class Vectors(unittest.TestCase):
    def test_all_57_agree(self):
        d = _vectors_dir()
        if d is None:
            self.skipTest("vectors unavailable (no WA_VECTORS, no network)")
        results = run_vectors.run(run_vectors.load([d]))
        self.assertEqual(len(results), 57)
        bad = {k: (got, exp) for k, (ok, got, exp) in results.items() if not ok}
        self.assertEqual(bad, {})

    def test_a_crash_is_a_disagreement(self):
        d = _vectors_dir()
        if d is None:
            self.skipTest("vectors unavailable")
        files = run_vectors.load([d])[:1]

        def boom(_):
            raise RuntimeError("x")
        (ok, got, _), = run_vectors.run(files, check=boom).values()
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
