"""The battery counts a kill only on a vector the unmodified checker passes."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mutate  # noqa: E402


def R(results, stopped_at=None):
    return {"results": results, "stopped_at": stopped_at}


class Classify(unittest.TestCase):
    PASSING = {"a", "b"}  # the unmodified checker also fails "c"

    def test_failing_only_on_a_baseline_failure_is_not_a_kill(self):
        self.assertEqual(mutate.classify(R({"a": True, "b": True, "c": False}), self.PASSING), ("survived", []))

    def test_failing_on_a_baseline_pass_is_a_kill(self):
        self.assertEqual(mutate.classify(R({"a": False, "b": True, "c": False}), self.PASSING), ("killed", ["a"]))

    def test_a_vector_missing_from_the_result_counts_as_failed(self):
        self.assertEqual(mutate.classify(R({}), self.PASSING), ("killed", ["a", "b"]))

    def test_stopping_early_on_a_baseline_pass_is_a_kill(self):
        self.assertEqual(mutate.classify(R({"a": False}, stopped_at="a"), self.PASSING), ("killed", ["a"]))

    def test_a_mutant_that_does_not_run_is_killed(self):
        self.assertEqual(mutate.classify({}, self.PASSING), ("killed", ["a", "b"]))

    def test_timeout_is_reported_apart(self):
        self.assertEqual(mutate.classify("timeout", self.PASSING), ("timeout", []))

    def test_a_checker_that_fails_everything_scores_nothing_when_baseline_does(self):
        self.assertEqual(mutate.classify(R({"a": False, "b": False, "c": False}), set()), ("survived", []))


class Operators(unittest.TestCase):
    def test_each_operator_changes_the_program(self):
        src = "def f(x, y):\n    if not x and y == 1:\n        return x + 2\n    return True\n"
        import ast
        sites = mutate.Sites()
        sites.visit(ast.parse(src))
        self.assertGreaterEqual(len(sites.sites), 7)
        outs = {mutate.apply_mutant(src, "m", i) for i in range(len(sites.sites))}
        self.assertEqual(len(outs), len(sites.sites))
        self.assertNotIn(ast.unparse(ast.parse(src)), outs)


if __name__ == "__main__":
    unittest.main()
