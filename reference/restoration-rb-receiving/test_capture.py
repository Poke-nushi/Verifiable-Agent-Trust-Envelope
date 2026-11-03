"""Capture regressions using the real local sample and disposable test keys."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from example_inputs import timestamp
import run_capture

SAMPLE = Path(__file__).resolve().parents[1] / "post-admission-revocation-sample/sample"
sys.path.insert(0, str(SAMPLE))
from fixture import BASE, Case
from provider import Provider


class CaptureTests(unittest.TestCase):
    def test_unknown_query_stops_before_saving_rb(self):
        original = Provider.query
        scenarios = ("no_commit", "commit_observed", "not_established")
        for failure_number, scenario in enumerate(scenarios, 1):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temp:
                calls = 0

                def fail_query(provider):
                    nonlocal calls
                    calls += 1
                    if calls == failure_number:
                        return {"status": "unknown", "accepted": None, "files": None, "native": None}
                    return original(provider)

                out = Path(temp) / "capture"
                with patch.object(Provider, "query", fail_query):
                    with self.assertRaisesRegex(ValueError, "capture query did not establish"):
                        run_capture.run(out)
                self.assertIs(Provider.query, original)
                self.assertFalse((out / scenario).exists())
                self.assertFalse((out / "SUMMARY.json").exists())

    def test_query_shape_and_known_outcome_are_required(self):
        for answer in (None, {}, {"status": "not_accepted", "accepted": False, "files": None},
                       {"status": "not_accepted", "accepted": False, "files": ""},
                       {"status": "not_accepted", "accepted": False, "files": {}},
                       {"status": "not_accepted", "accepted": 0, "files": []},
                       {"status": "unknown", "accepted": False, "files": []}):
            with self.subTest(answer=answer), tempfile.TemporaryDirectory() as temp:
                out = Path(temp) / "capture"
                with patch.object(Provider, "query", return_value=answer):
                    with self.assertRaisesRegex(ValueError, "capture query did not establish"):
                        run_capture.run(out)
                self.assertFalse((out / "no_commit").exists())
                self.assertFalse((out / "SUMMARY.json").exists())

    def test_query_inventory_must_match_verified_export(self):
        original = Provider.query
        mutations = (
            ("null entries", lambda q: q.update(files=[None, None])),
            ("missing field", lambda q: q["files"][0].pop("name")),
            ("changed digest", lambda q: q["files"][0].update(sha256="0" * 64)),
            ("boolean size", lambda q: q["files"][0].update(size=True)),
            ("float size", lambda q: q["files"][0].update(size=float(q["files"][0]["size"]))),
            ("duplicate file", lambda q: q["files"].__setitem__(1, dict(q["files"][0]))),
            ("reordered files", lambda q: q["files"].reverse()),
            ("non-JSON size", lambda q: q["files"][0].update(size={1})),
        )
        for failure_number, scenario in ((2, "commit_observed"), (3, "not_established")):
            for label, mutate in mutations:
                with self.subTest(scenario=scenario, mutation=label), tempfile.TemporaryDirectory() as temp:
                    calls = 0

                    def change_query(provider):
                        nonlocal calls
                        calls += 1
                        answer = original(provider)
                        if calls == failure_number:
                            mutate(answer)
                        return answer

                    out = Path(temp) / "capture"
                    with patch.object(Provider, "query", change_query):
                        with self.assertRaisesRegex(ValueError, "capture query did not establish"):
                            run_capture.run(out)
                    self.assertIs(Provider.query, original)
                    self.assertFalse((out / scenario).exists())
                    self.assertFalse((out / "SUMMARY.json").exists())
                    # The actual native evidence and prior successful RB stay
                    # available even though the damaged query is rejected.
                    native = json.loads((out / (scenario + "-provider") / "evidence.json").read_bytes())
                    self.assertEqual(native["observation"]["status"], "effect_observed")
                    self.assertEqual(len(native["observation"]["files"]), 2)
                    self.assertTrue((out / "no_commit" / "report.json").is_file())
                    if scenario == "not_established":
                        self.assertTrue((out / "commit_observed" / "CAPTURE.json").is_file())

    def test_query_inventory_object_key_order_is_irrelevant(self):
        original = Provider.query

        def reorder_keys(provider):
            answer = original(provider)
            answer["files"] = [dict(reversed(list(item.items()))) for item in answer["files"]]
            return answer

        with tempfile.TemporaryDirectory() as temp:
            with patch.object(Provider, "query", reorder_keys):
                result = run_capture.run(Path(temp) / "capture")
            self.assertEqual([row["observation_check"] for row in result["results"]],
                             ["consistent_under_local_assumptions", "consistent_under_local_assumptions", "not_established"])

    def test_failed_revocation_cannot_create_a_negative_rb(self):
        original = Provider.notify
        scenarios = ("no_commit", "commit_observed", "not_established")
        for failure_number, scenario in enumerate(scenarios, 1):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temp:
                calls = 0

                def fail_revocation(provider, raw):
                    nonlocal calls
                    calls += 1
                    return {"status": "not_stored"} if calls == failure_number else original(provider, raw)

                out = Path(temp) / "capture"
                with patch.object(Provider, "notify", fail_revocation):
                    with self.assertRaisesRegex(ValueError, "revocation"):
                        run_capture.run(out)
                self.assertIs(Provider.notify, original)
                self.assertFalse((out / scenario).exists())
                self.assertFalse((out / "SUMMARY.json").exists())

    def test_capture_times_are_measured_around_submit(self):
        original = Case.submit
        measured = []

        def measure(case, **overrides):
            began = case.clock()
            answer = original(case, **overrides)
            measured.append((began, case.clock()))
            return answer

        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "capture"
            with patch.object(Case, "submit", measure):
                result = run_capture.run(out)
            self.assertEqual(len(measured), 3)
            self.assertTrue(result["test_keys_deleted"])
            for row, (began, finished) in zip(result["results"], measured):
                directory = out / row["scenario"]
                observation = json.loads((directory / "observation.json").read_bytes())
                attempt = observation["attempts"][0]
                self.assertEqual(attempt["started_at"], timestamp(began - BASE))
                self.assertEqual(attempt["finished_at"], timestamp(finished - BASE))
                provenance = json.loads((directory / "CAPTURE.json").read_bytes())
                self.assertLess(attempt["finished_at"], provenance["query_at"])
                revocations = [e for e in provenance["harness_trace"] if e["event"] == "revocation_stored"]
                self.assertEqual(revocations, [{"event": "revocation_stored", "at": timestamp(1)}])
                self.assertTrue(provenance["native_reader"]["verified"])
            self.assertEqual([row["observation_check"] for row in result["results"]],
                             ["consistent_under_local_assumptions", "consistent_under_local_assumptions", "not_established"])

    def test_submission_outcome_must_agree_with_capture(self):
        original = Case.submit
        for failure_number, scenario in ((1, "no_commit"), (2, "commit_observed")):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temp:
                calls = 0

                def change_outcome(case, **overrides):
                    nonlocal calls
                    calls += 1
                    answer = original(case, **overrides)
                    if calls == failure_number:
                        if scenario == "no_commit":
                            answer["reason"] = "another_reason"
                        else:
                            answer["status"] = "unknown"
                    return answer

                out = Path(temp) / "capture"
                with patch.object(Case, "submit", change_outcome):
                    with self.assertRaisesRegex(ValueError, "submission"):
                        run_capture.run(out)
                self.assertFalse((out / scenario).exists())
                self.assertFalse((out / "SUMMARY.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
