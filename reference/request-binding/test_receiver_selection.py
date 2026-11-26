"""Check the fixed selection controls and the external-reader comparison."""

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


VECTORS = Path(__file__).resolve().parent / "receiver-selection"
CHECK = VECTORS / "check.py"


def run_checker(script, *args):
    return subprocess.run([sys.executable, "-I", "-B", str(script), *args],
                          capture_output=True, text=True, check=False)


class ReceiverSelectionTests(unittest.TestCase):
    def test_same_purchase_terms_distinct_request_and_operation_ids(self):
        operations, requests = [], []
        for label in ("A", "B"):
            packet = VECTORS / "deliveries" / label
            saved = (VECTORS / "receiver" / f"{label}.json").read_bytes()
            self.assertEqual(saved, (packet / "admission-request.json").read_bytes())
            operation = json.loads((packet / "original.json").read_bytes())
            request = json.loads(saved)
            self.assertEqual(request["transaction_id"], operation["operation_id"])
            self.assertEqual(operation["payload"]["amount"], {"currency": "USD", "value": "24.50"})
            operations.append(operation)
            requests.append(request)
        self.assertNotEqual(requests[0]["request_id"], requests[1]["request_id"])
        self.assertNotEqual(operations[0].pop("operation_id"), operations[1].pop("operation_id"))
        self.assertEqual(operations[0], operations[1])

    def test_same_id_control_changes_only_the_saved_expiry(self):
        selected = json.loads((VECTORS / "receiver/A-earlier-expiry.json").read_bytes())
        delivered = json.loads((VECTORS / "deliveries/A/admission-request.json").read_bytes())
        self.assertEqual(delivered["expires_at"], "2026-11-12T00:05:00Z")
        self.assertEqual(selected, {**delivered, "expires_at": "2026-11-12T00:04:59Z"})

    @unittest.skipUnless(importlib.util.find_spec("jsonschema"), "reference receipt reader requires jsonschema")
    def test_reference_replay(self):
        result = run_checker(CHECK)
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = json.loads(result.stdout)
        self.assertEqual(len(observed["cases"]), 6)
        self.assertEqual(observed, json.loads((VECTORS / "expected.json").read_bytes()))
        mixed = observed["cases"]["select-a-receive-a-with-b-result"]
        self.assertEqual(mixed["record_linkage"], "mismatch")
        self.assertIs(mixed["request_binding"]["pass"], True)
        earlier = observed["cases"]["select-a-earlier-expiry-receive-a"]
        self.assertEqual(earlier["record_linkage"], "matched")
        self.assertEqual(earlier["request_binding"]["selection_cause"], "ADMISSION_REFERENCE_MISMATCH")

    def test_comparator_detects_id_only_and_always_matched_readers(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "results.json"
            expected = (VECTORS / "expected.json").read_bytes()
            for case_id, wrong_field in (("select-a-earlier-expiry-receive-a", "request_binding"),
                                         ("select-a-receive-a-with-b-result", "record_linkage")):
                with self.subTest(case=case_id):
                    results = json.loads(expected)
                    results["cases"][case_id][wrong_field] = results["cases"]["select-a-receive-a"][wrong_field]
                    path.write_text(json.dumps(results), encoding="utf-8")
                    result = run_checker(CHECK, "--compare", str(path))
                    self.assertEqual(result.returncode, 1)
                    self.assertIn(case_id, result.stderr)

    def test_comparator_keeps_unchecked_false_and_numbers_distinct(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "results.json"
            original = json.loads((VECTORS / "expected.json").read_bytes())
            for case_id, wrong_value in (("no-selection-receive-b", False), ("select-a-receive-a", 1)):
                with self.subTest(case=case_id):
                    results = json.loads(json.dumps(original))
                    results["cases"][case_id]["request_binding"]["pass"] = wrong_value
                    path.write_text(json.dumps(results), encoding="utf-8")
                    result = run_checker(CHECK, "--compare", str(path))
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(case_id, result.stderr)

    def test_standalone_comparison_checks_original_bytes(self):
        with tempfile.TemporaryDirectory() as work:
            copy = Path(work) / "purchase vectors"
            shutil.copytree(VECTORS, copy)
            script = copy / "check.py"
            expected = copy / "expected.json"
            result = run_checker(script, "--compare", str(expected))
            self.assertEqual(result.returncode, 0, result.stderr)
            with (copy / "receiver/B.json").open("ab") as file:
                file.write(b"\n")
            result = run_checker(script, "--compare", str(expected))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SHA-256 mismatch for receiver/B.json", result.stderr)

    def test_comparator_rejects_missing_cases_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "results.json"
            expected = (VECTORS / "expected.json").read_text(encoding="utf-8")
            partial = json.loads(expected)
            del partial["cases"]["no-selection-receive-b"]
            duplicate = expected.replace('"cases":', '"cases": {}, "cases":', 1)
            for raw, error in ((json.dumps(partial), "case IDs"), (duplicate, "duplicate JSON key")):
                with self.subTest(error=error):
                    path.write_text(raw, encoding="utf-8")
                    result = run_checker(CHECK, "--compare", str(path))
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(error, result.stderr)


if __name__ == "__main__":
    unittest.main()
