"""Regression controls for the handoff CI checker's pass criteria."""
import copy
import unittest

from check_runtime_handoff_sample import EXPECTED, SUCCESS_REASONS, test_count, verify_scenarios


def successful_summary():
    rows = {}
    for name, (first, latest, first_coverage, latest_coverage, linkage) in EXPECTED.items():
        reason = (["POST_EXEC_ADMISSION_EXPIRED"] if linkage == "failed" else
                  ["ACTUAL_EXECUTION_TIMES_UNAVAILABLE"] if latest == "unresolved" else
                  list(SUCCESS_REASONS))
        rows[name] = {"first_effect": first, "latest_effect": latest,
                      "first_coverage": {"expected-post": first_coverage},
                      "latest_coverage": {"expected-post": latest_coverage},
                      "linkage": {"outcome": linkage, "reason_codes": reason},
                      "replay": {"capsules_reassessed": 2, "is_execution_ticket": False,
                                 "required_records_replayed": True}}
    return rows


class CheckerTests(unittest.TestCase):
    def test_successful_controls(self):
        self.assertEqual(test_count("Ran 52 tests in 1.0s\n\nOK\n", 52), 52)
        verify_scenarios(successful_summary())

    def test_zero_short_or_failed_test_inventory_is_not_a_pass(self):
        for stderr in ("", "Ran 0 tests in 0.0s\n\nOK\n", "Ran 51 tests in 1.0s\n\nOK\n",
                       "Ran 52 tests in 1.0s\n\nFAILED (failures=1)\n",
                       "Ran 52 tests in 1.0s\nOK\nRan 52 tests in 1.0s\nOK\n"):
            with self.subTest(stderr=stderr), self.assertRaises(RuntimeError):
                test_count(stderr, 52)

    def test_missing_or_extra_scenario_is_not_a_pass(self):
        summary = successful_summary()
        del summary["accepted-zero-effects"]
        with self.assertRaises(RuntimeError):
            verify_scenarios(summary)
        summary = successful_summary()
        summary["unexpected"] = copy.deepcopy(summary["a-completed-response-lost"])
        with self.assertRaises(RuntimeError):
            verify_scenarios(summary)

    def test_unknown_must_not_become_completed(self):
        summary = successful_summary()
        summary["accepted-partial-effects"]["latest_effect"] = "completed"
        with self.assertRaises(RuntimeError):
            verify_scenarios(summary)

    def test_handoff_must_keep_the_earlier_unknown(self):
        summary = successful_summary()
        summary["b-after-unaccepted-a"]["first_effect"] = "completed"
        with self.assertRaises(RuntimeError):
            verify_scenarios(summary)

    def test_completed_effect_does_not_hide_linkage_failure(self):
        summary = successful_summary()
        summary["effect-completed-outside-admission"]["linkage"]["reason_codes"] = ["ADMISSION_RECEIPT_LINKED"]
        with self.assertRaises(RuntimeError):
            verify_scenarios(summary)

    def test_successful_linkage_cannot_carry_failure_or_incomplete_reasons(self):
        for reasons in (["POST_EXEC_ADMISSION_EXPIRED"], SUCCESS_REASONS[:-1], list(reversed(SUCCESS_REASONS))):
            summary = successful_summary()
            summary["a-completed-response-lost"]["linkage"]["reason_codes"] = reasons
            with self.subTest(reasons=reasons), self.assertRaises(RuntimeError):
                verify_scenarios(summary)

    def test_replay_requires_strict_flags_and_actual_capsule_count(self):
        for key, value in (("is_execution_ticket", True), ("is_execution_ticket", 0),
                           ("required_records_replayed", False), ("required_records_replayed", 1),
                           ("capsules_reassessed", 0), ("capsules_reassessed", 2.0)):
            summary = successful_summary()
            summary["accepted-zero-effects"]["replay"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                verify_scenarios(summary)


if __name__ == "__main__":
    unittest.main()
