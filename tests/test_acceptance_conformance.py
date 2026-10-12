"""One test class per conformance fix, each pinned to the published vectors
(sha256-checked via run_vectors.EXPECTED_SHA256) plus a few direct cases the
vectors do not cover.

Run:  ACCEPTANCE_VECTORS=/path/to/vectors.json python3 -m unittest discover -s tests
      (without the variable, the pinned upstream URL is fetched.)

"Agrees" is the upstream runner's definition: same result, same condition set,
and every other expected member (key_step, policy_refusal, disposition)
equal to what the checker returned.
"""
import copy
import hashlib
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import checker  # noqa: E402
import run_vectors  # noqa: E402


def _load():
    path = os.environ.get("ACCEPTANCE_VECTORS")
    data = run_vectors._load_vectors(["x", path] if path else ["x"])
    got = hashlib.sha256(data).hexdigest()
    if got != run_vectors.EXPECTED_SHA256:
        raise RuntimeError(f"vectors sha256 {got} != pinned {run_vectors.EXPECTED_SHA256}")
    return {v["id"]: v for v in json.loads(data)["vectors"]}


VECTORS = _load()


def agrees(vid):
    v = VECTORS[vid]
    got, exp = checker.check_acceptance(v["case"]), v["expect"]
    return (
        got["result"] == exp["result"]
        and set(got.get("conditions") or []) == set(exp["conditions"])
        and all(got.get(k) == x for k, x in exp.items() if k not in ("result", "conditions"))
    )


class VectorCase(unittest.TestCase):
    IDS: tuple = ()

    def test_vectors(self):
        for vid in self.IDS:
            with self.subTest(vector=vid):
                v = VECTORS[vid]
                got = checker.check_acceptance(v["case"])
                self.assertTrue(agrees(vid), f"expect={v['expect']} got={got}")


def _case(vid, **over):
    c = copy.deepcopy(VECTORS[vid]["case"])
    c.update(over)
    return c


# 1 -------------------------------------------------------------------------
class Fix1SmallOrder(VectorCase):
    IDS = (
        "acc-small-order-key-identity-forged-signature",
        "acc-small-order-key-identity-declared-complete",
        "acc-small-order-key-order-8-genuine-signature",
        "acc-small-order-r-real-key",
    )

    def test_duplicate_kid_first_entry_decides(self):
        # Sentence 8: the first Ed25519 entry for a kid is the one used.
        # A small-order first entry is therefore not rescued by a good second one.
        c = _case("acc-accepted-verified")
        keys = c["trust_material"]["keys"]
        good = next(k for k in keys if k["kid"] == "cp-1")
        bad = dict(good, x="AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")  # identity
        c["trust_material"]["keys"] = [bad, good]
        self.assertEqual(checker.check_acceptance(c)["result"], "key_unresolved")
        c["trust_material"]["keys"] = [good, bad]
        self.assertEqual(checker.check_acceptance(c)["result"], "verified")


# 2 -------------------------------------------------------------------------
class Fix2StrictBase64url(VectorCase):
    IDS = (
        "acc-envelope-signature-padded",
        "acc-envelope-signature-standard-alphabet",
        "acc-envelope-protected-not-json-object",
        "acc-envelope-payload-not-json-object",
    )

    def _with(self, member, fn):
        c = _case("acc-accepted-verified")
        c["acceptance"][member] = fn(c["acceptance"][member])
        return checker.check_acceptance(c)

    def test_padded_or_non_alphabet_member_is_malformed(self):
        for member in ("protected", "payload", "signature"):
            for name, fn in (
                ("padded", lambda s: s + "=" * (-len(s) % 4 or 1)),
                ("plus", lambda s: s[:-1] + "+"),
                ("slash", lambda s: s[:-1] + "/"),
                ("whitespace", lambda s: s[:4] + "\n" + s[4:]),
                ("impossible-length", lambda s: s[: len(s) // 4 * 4] + "A"),  # len % 4 == 1
            ):
                with self.subTest(member=member, mutation=name):
                    got = self._with(member, fn)
                    self.assertEqual((got["result"], got["conditions"]), ("malformed", ["acceptance_member_invalid"]))


# 3 -------------------------------------------------------------------------
class Fix3Version(VectorCase):
    IDS = ("acc-version-absent", "acc-version-not-string", "acc-version-other-value")


# 4 -------------------------------------------------------------------------
class Fix4SignatureInvalidModel(VectorCase):
    IDS = (
        "acc-key-unresolved",
        "acc-key-unresolved-declared-complete",
        "acc-key-unresolved-valid-signature-kid-not-in-trust-material",
        "acc-signature-invalid",
        "acc-signature-invalid-declared-complete",
        "acc-signature-invalid-one-byte-flipped",
        "acc-envelope-payload-not-json-object-signature-invalid",
        "acc-complete-not-boolean",
    )

    def test_signature_invalid_is_malformed_exit_1(self):
        got = checker.check_acceptance(VECTORS["acc-signature-invalid"]["case"])
        self.assertEqual((got["result"], got["exit_code"], got["conditions"]), ("malformed", 1, ["signature_invalid"]))

    def test_policy_refusal_only_for_json_true(self):
        for value in ("true", 1, "yes", [True]):
            with self.subTest(value=value):
                got = checker.check_acceptance(_case("acc-key-unresolved", trust_material_complete=value))
                self.assertEqual(got["result"], "key_unresolved")
                self.assertIsNone(got.get("policy_refusal"))
        got = checker.check_acceptance(_case("acc-key-unresolved", trust_material_complete=True))
        self.assertIs(got["policy_refusal"], True)


# 5 -------------------------------------------------------------------------
class Fix5Header(VectorCase):
    IDS = ("acc-header-alg-not-eddsa", "acc-header-no-kid")


# 6 -------------------------------------------------------------------------
class Fix6Timestamps(VectorCase):
    IDS = (
        "acc-accepted-at-no-fraction",
        "acc-accepted-at-offset-same-instant",
        "acc-outcome-at-no-fraction",
        "acc-same-instant-as-outcome-ok",
        "acc-precedes-outcome",
    )

    def test_outcome_at_spellings(self):
        for bad in (
            "2026-10-04T18:00:00Z", "2026-10-04T18:00:00.0Z", "2026-10-04T18:00:00.0000Z",
            "2026-10-04T18:00:00.000+00:00", "2026-10-04t18:00:00.000z", "2026-10-04 18:00:00.000Z",
            "2026-13-04T18:00:00.000Z", "2026-10-04T24:00:00.000Z", 20261004,
        ):
            with self.subTest(outcome_at=bad):
                c = _case("acc-accepted-verified")
                c["accepted_record"]["outcome_at"] = bad
                got = checker.check_acceptance(c)
                self.assertEqual(got["result"], "malformed")
                self.assertIn("acceptance_member_invalid", got["conditions"])
                self.assertNotIn("acceptance_precedes_outcome", got["conditions"])


# 7 -------------------------------------------------------------------------
class Fix7TypeCheckSuppression(VectorCase):
    IDS = (
        "acc-illtyped-digest-suppresses-mismatch",
        "acc-terms-digest-mismatch",
        "acc-outcome-digest-mismatch",
        "acc-record-digest-absent",
        "acc-record-digest-mismatch-replayed",
        "acc-report-all-two-mismatches",
    )

    def test_record_sha256_members_must_be_64_lowercase_hex(self):
        # The payload is signed, so only the relying party's record can be varied
        # without re-signing. An ill-typed record digest member raises
        # acceptance_member_invalid only: not the terms/outcome mismatch, and
        # not the record-digest mismatch that depends on the record being well-typed.
        for member in ("terms_sha256", "outcome_sha256"):
            for bad in ("not-hex", "A" * 64, "a" * 63, "a" * 65, "", 7, None):
                with self.subTest(member=member, value=bad):
                    c = _case("acc-accepted-verified")
                    c["accepted_record"][member] = bad
                    got = checker.check_acceptance(c)
                    self.assertEqual((got["result"], got["conditions"]), ("malformed", ["acceptance_member_invalid"]))


class AllVectors(unittest.TestCase):
    def test_every_vector_agrees(self):
        bad = [vid for vid in VECTORS if not agrees(vid)]
        self.assertEqual(bad, [])
        self.assertEqual(len(VECTORS), 46)


if __name__ == "__main__":
    unittest.main()
