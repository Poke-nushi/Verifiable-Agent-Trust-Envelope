"""Standard-library test for the AMEP case 3 comparison: python3 -B -m unittest reference/amep/case-03-confirmed-nonexecution/test_check.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check  # noqa: E402


class CaseThreeComparison(unittest.TestCase):
    def test_pins_inputs_and_verdict_records(self):
        problems, _ = check.check()
        self.assertEqual(problems, [])

    def test_a_live_worker_holds_the_rerun(self):
        r = check.load(os.path.join(check.HERE, "expected-results.json"))["phases"]["l2-busy-rerun"]["results"]
        self.assertEqual(r["i-2"]["gaps"], [{"need": "held_outcome", "ref": "i-1"}])
        self.assertEqual(r["i-2"]["outcome"], "unresolved")

    def test_a_late_write_is_the_providers_to_answer_for(self):
        r = check.load(os.path.join(check.HERE, "expected-results.json"))["phases"]["f4-late-write"]["results"]
        self.assertEqual((r["i-1"]["outcome"], r["i-1"]["blame"]), ("violated", "server"))
        self.assertEqual(r["i-2"]["outcome"], "preserved")

    def test_an_unfenced_late_submit_is_reported(self):
        real = check.records

        def altered(variant, history):
            out = real(variant, history)
            if variant == "fenced-handoff" and history == "completed-history.json":
                return [(i, k, {**b, "reason": "accepted"} if k == "denied" else b) for i, k, b in out]
            return out

        check.records = altered
        try:
            problems, _ = check.check()
        finally:
            check.records = real
        self.assertTrue(any("late submit is not denied" in p for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
