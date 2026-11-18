"""Regression controls for the handoff CI checker's pass criteria."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from check_runtime_handoff_sample import (
    EXPECTED, SAMPLE, SUCCESS_REASONS, test_count, verify_scenarios, verify_shared_boundaries,
    verify_inventory,
)
from sync_runtime_handoff_sample import expected_files, INVENTORY_NAME


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
    def source_copy(self, directory):
        source = Path(directory) / "standalone"
        shutil.copytree(SAMPLE, source)
        # Construct an owned coherent fixture from the canonical current root;
        # never update the working package or the historical review evidence.
        for name, raw in expected_files(source).items():
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        verify_shared_boundaries(source)
        verify_inventory(source)
        return source

    def repin_manifest(self, source):
        path = source / "SOURCE-MANIFEST.json"
        value = json.loads(path.read_bytes())
        value["files"] = {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                          for name in value["files"]}
        path.write_text(json.dumps(value, indent=2) + "\n")

    def standalone_check(self, source):
        return subprocess.run(
            [sys.executable, "-E", "-s", "-B", str(source / "check_environment.py"), "--sources-only"],
            capture_output=True, text=True, timeout=30,
        )

    def test_self_consistent_package_cannot_drift_from_current_shared_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.source_copy(directory)
            name = "scripts/vate_conformance.py"
            runner = source / name
            runner.write_bytes(runner.read_bytes() + b"\n# Separate package change.\n")
            upstream_path = source / "UPSTREAM-SOURCES.json"
            upstream = json.loads(upstream_path.read_bytes())
            upstream["patched_files"][name]["sha256"] = hashlib.sha256(runner.read_bytes()).hexdigest()
            upstream_path.write_text(json.dumps(upstream))
            manifest_path = source / "SOURCE-MANIFEST.json"
            manifest = json.loads(manifest_path.read_bytes())
            for changed in (name, "UPSTREAM-SOURCES.json"):
                manifest["files"][changed] = hashlib.sha256((source / changed).read_bytes()).hexdigest()
            manifest_path.write_text(json.dumps(manifest))
            result = subprocess.run(
                [sys.executable, "-E", "-s", "-B", str(source / "check_environment.py"), "--sources-only"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "ok")
            with self.assertRaisesRegex(RuntimeError, "handoff source drift.*scripts/vate_conformance.py"):
                verify_shared_boundaries(source)

    def test_same_count_historical_source_substitution_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.source_copy(directory)
            target = "reference/minimal-al2-demo/trust_envelope_demo.py"
            upstream_path = source / "UPSTREAM-SOURCES.json"
            upstream = json.loads(upstream_path.read_bytes())
            count = len(upstream["unchanged_files"]) + len(upstream["patched_files"])
            for section in ("unchanged_files", "patched_files"):
                upstream[section].pop(target, None)
            upstream["unchanged_files"]["LICENSE"] = hashlib.sha256((source / "LICENSE").read_bytes()).hexdigest()
            self.assertEqual(len(upstream["unchanged_files"]) + len(upstream["patched_files"]), count)
            upstream_path.write_text(json.dumps(upstream))
            helper = source / target
            helper.write_bytes(helper.read_bytes() + b"\n# Drift hidden by the old count-only inventory.\n")
            self.repin_manifest(source)
            verify_inventory(source)
            for check in (expected_files, verify_shared_boundaries):
                with self.assertRaisesRegex(ValueError, "unexpected historical upstream inventory"):
                    check(source)
            result = self.standalone_check(source)
            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertEqual(json.loads(result.stdout)["error"], "invalid upstream provenance")

    def test_historical_commit_and_hashes_cannot_be_rewritten(self):
        for mutation in ("commit", "hash"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                source = self.source_copy(directory)
                path = source / "UPSTREAM-SOURCES.json"
                upstream = json.loads(path.read_bytes())
                if mutation == "commit":
                    upstream["upstream_commit"] = "0" * 40
                else:
                    upstream["patched_files"]["scripts/vate_conformance.py"]["upstream_sha256"] = "0" * 64
                path.write_text(json.dumps(upstream))
                self.repin_manifest(source)
                with self.assertRaisesRegex(ValueError, "unexpected historical upstream inventory"):
                    expected_files(source)
                self.assertEqual(self.standalone_check(source).returncode, 2)

    def test_shipped_canonical_inventory_is_a_whole_root_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.source_copy(directory)
            path = source / INVENTORY_NAME
            value = json.loads(path.read_bytes())
            value["package_files"].reverse()
            path.write_text(json.dumps(value))
            # Keep every candidate-facing digest coherent. The independent
            # repository contract must still reject different inventory bytes.
            upstream_path = source / "UPSTREAM-SOURCES.json"
            upstream = json.loads(upstream_path.read_bytes())
            upstream["added_files"][INVENTORY_NAME] = hashlib.sha256(path.read_bytes()).hexdigest()
            upstream_path.write_text(json.dumps(upstream))
            self.repin_manifest(source)
            self.assertEqual(self.standalone_check(source).returncode, 0)
            with self.assertRaisesRegex(RuntimeError, "handoff source drift.*runtime_handoff_inventory.json"):
                verify_shared_boundaries(source)

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
