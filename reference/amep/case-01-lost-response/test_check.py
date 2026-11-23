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

    def test_the_recovered_ticket_bytes_hash_to_the_pending_ticket(self):
        (_, pending_sha, pending_raw, _), = check.ticket("pending-history.json")
        (_, _, recovered_raw, _), = check.ticket("recovered-history.json")
        self.assertEqual(recovered_raw, pending_sha)
        self.assertEqual(recovered_raw, pending_raw)

    def test_changed_recovered_ticket_bytes_are_reported(self):
        real = check.ticket

        def altered(history_file):
            found = real(history_file)
            if history_file == "recovered-history.json":
                index, record_sha, _, body = found[0]
                return [(index, record_sha, "0" * 64, body)]
            return found

        check.ticket = altered
        try:
            problems, _ = check.check()
        finally:
            check.ticket = real
        self.assertIn("the hash of the recovered ticket's bytes differs from the pending ticket's hash", problems)

    def test_the_unknown_observation_is_found_once(self):
        obs = check.unknown_observation()
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0]["claims"]["outcome"], "unknown")


if __name__ == "__main__":
    unittest.main()
