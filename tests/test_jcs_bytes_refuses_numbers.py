"""_jcs_bytes serialises string-only records. A number would be written by
Python's json.dumps (1.0, -0.0, 1e-05), not by RFC 8785's ECMAScript
Number::toString, so the digest would silently not be a JCS digest.
It must refuse instead. No network: this file does not load the vectors.

Run:  python3 -m unittest discover -s tests -p 'test_jcs_bytes*'
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import checker  # noqa: E402


class JcsBytesRefusesNumbers(unittest.TestCase):
    def test_strings_still_serialise_as_jcs(self):
        self.assertEqual(
            checker._jcs_bytes({"b": "é", "a": {"d": "x", "c": "y"}}),
            '{"a":{"c":"y","d":"x"},"b":"é"}'.encode("utf-8"),
        )

    def test_refuses_every_number_wherever_it_sits(self):
        for bad in (1, 1.0, -0.0, 1e-5, 1e21, 100.0, 0, 2**70):
            for rec in ({"k": bad}, {"o": {"k": bad}}, {"l": ["s", bad]}, [bad], bad):
                with self.subTest(value=repr(bad), shape=repr(rec)):
                    with self.assertRaises(ValueError):
                        checker._jcs_bytes(rec)

    def test_a_record_with_a_number_member_is_a_finding_not_a_crash(self):
        import copy
        import hashlib
        import json

        import run_vectors

        try:
            path = os.environ.get("ACCEPTANCE_VECTORS")
            data = run_vectors._load_vectors(["x", path] if path else ["x"])
        except Exception as exc:  # noqa: BLE001 - offline: the unit tests above still ran
            self.skipTest(f"vectors unavailable: {exc}")
        self.assertEqual(hashlib.sha256(data).hexdigest(), run_vectors.EXPECTED_SHA256)
        case = copy.deepcopy(
            next(v for v in json.loads(data)["vectors"] if v["id"] == "acc-accepted-verified")["case"]
        )
        self.assertNotIn("acceptance_member_invalid", checker.check_acceptance(copy.deepcopy(case))["conditions"])
        for bad in (1, 1.0, -0.0, 1e21):
            with self.subTest(value=repr(bad)):
                c = copy.deepcopy(case)
                self.assertIsInstance(c["accepted_record"], dict)
                c["accepted_record"]["n"] = bad
                out = checker.check_acceptance(c)
                self.assertIn("acceptance_member_invalid", out["conditions"])
                self.assertNotIn("acceptance_record_digest_mismatch", out["conditions"])


if __name__ == "__main__":
    unittest.main()
