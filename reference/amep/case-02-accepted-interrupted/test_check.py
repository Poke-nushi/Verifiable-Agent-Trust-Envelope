"""Standard-library test for the AMEP case 2 comparison: python3 -B -m unittest reference/amep/case-02-accepted-interrupted/test_check.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check  # noqa: E402


class CaseTwoComparison(unittest.TestCase):
    def test_pins_inputs_and_verdict_records(self):
        problems, _ = check.check()
        self.assertEqual(problems, [])

    def test_the_handoff_rerun_waits_for_the_first_outcome(self):
        r = check.load(os.path.join(check.HERE, "expected-results.json"))["phases"]["z2-handoff-rerun"]["results"]
        self.assertEqual(r["i-2"]["gaps"], [{"need": "held_outcome", "ref": "i-1"}])
        self.assertEqual(r["i-2"]["outcome"], "unresolved")

    def test_a_changed_inventory_is_reported(self):
        real = check.records

        def altered(variant, history):
            out = real(variant, history)
            if variant == "partial-effects" and history == "after-handoff-history.json":
                return [(i, k, {**b, "inventory": {}} if k == "handoff" else b) for i, k, b in out]
            return out

        check.records = altered
        try:
            problems, _ = check.check()
        finally:
            check.records = real
        self.assertTrue(any(p.startswith("partial-effects: the inventory after the handoff") for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
