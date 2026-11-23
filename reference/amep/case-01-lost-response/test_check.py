"""Standard-library test for the AMEP case 1 comparison: python3 -B -m unittest reference/amep/case-01-lost-response/test_check.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check  # noqa: E402


class CaseOneComparison(unittest.TestCase):
    def test_pins_observation_and_verdict_records(self):
        problems, _ = check.check()
        self.assertEqual(problems, [])

    def test_the_observation_and_the_pending_ticket_name_the_same_attempt(self):
        (_, _, _, pending), = check.ticket("pending-history.json")
        (obs,) = check.unknown_observation()
        self.assertEqual(obs["claims"]["attempt_id"], pending["attempt_id"])
        self.assertEqual(check.ticket("pending-history.json")[0][1], check.ticket("recovered-history.json")[0][1])

    def test_the_unknown_observation_is_found_once(self):
        obs = check.unknown_observation()
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0]["claims"]["outcome"], "unknown")


if __name__ == "__main__":
    unittest.main()
