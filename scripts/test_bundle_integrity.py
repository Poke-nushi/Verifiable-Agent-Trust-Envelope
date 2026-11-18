"""Report identity, failed comparisons, and typed corpus-index integrity."""
import argparse
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import vate_conformance as runner

try:
    import jsonschema
except ImportError:
    jsonschema = None

ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "conformance/request-binding-v1"


def read(path):
    return json.loads(path.read_bytes())


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


class BundleIntegrityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="vate-bundle-integrity-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.corpus = self.folder / "corpus"
        (self.corpus / "cases").mkdir(parents=True)
        shutil.copyfile(BINDING / "cases/allow.json", self.corpus / "cases/allow.json")
        shutil.copyfile(BINDING / "conformance-case.schema.json", self.corpus / "conformance-case.schema.json")
        shutil.copytree(BINDING / "fixtures/allow", self.folder / "allow")
        self.index = runner.make_corpus_index(self.corpus)
        write(self.corpus / "corpus.json", self.index)
        self.sut_path = self.folder / "sut.json"
        self.conf_path = self.folder / "conformance.json"
        self.impl_path = self.folder / "implementation.json"
        self.args = argparse.Namespace(corpus_root=str(self.corpus), report=str(self.conf_path),
                                       conformance_report_uri=str(self.conf_path))
        self.sut = self.load_sut()

    def load_sut(self, mode="fixtures"):
        sut = read(ROOT / f"examples/conformance/request-binding/sut-results-{mode}.json")
        sut["results"] = [sut["results"][0]]
        sut["corpus"]["digest"] = self.index["digest"]
        return sut

    def compare(self):
        write(self.sut_path, self.sut)
        report = runner.compare_sut_results(self.corpus, self.sut_path)
        return report, runner.make_implementation_report(self.args, report)

    def bundle(self, report, implementation, *, reference=False):
        write(self.conf_path, report)
        write(self.impl_path, implementation)
        return runner.verify_report_bundle(self.corpus, self.conf_path, self.impl_path,
                                           None if reference else self.sut_path)

    def assert_bundle(self, report, implementation, *, passed=True, check=None, reference=False):
        result = self.bundle(report, implementation, reference=reference)
        failures = [row["name"] for row in result["checks"] if not row["pass"]]
        self.assertEqual(result["status"], "pass" if passed else "fail", failures)
        if check:
            self.assertIn(check, failures)
        return result

    def test_identity_fields_cannot_be_changed_or_dropped(self):
        self.sut["implementation"].update(source="urn:example:source", commit="a" * 40, environment="local fixture")
        report, original = self.compare()
        self.assert_bundle(report, original)
        for field in ("name", "type", "version", "language", "source", "commit", "environment"):
            for replacement in ("changed", None, True, 1, 1.0, []):
                with self.subTest(field=field, replacement=replacement):
                    implementation = copy.deepcopy(original)
                    implementation["implementation"][field] = replacement
                    self.assert_bundle(report, implementation, passed=False, check="implementation_report.implementation")
            with self.subTest(field=field, removed=True):
                implementation = copy.deepcopy(original)
                del implementation["implementation"][field]
                self.assert_bundle(report, implementation, passed=False, check="implementation_report.implementation")

    def test_optional_identity_absence_is_preserved(self):
        report, original = self.compare()
        self.assert_bundle(report, original)
        for field in ("source", "commit", "environment"):
            with self.subTest(field=field):
                implementation = copy.deepcopy(original)
                implementation["implementation"][field] = "not submitted"
                self.assert_bundle(report, implementation, passed=False, check="implementation_report.implementation")

    def test_identity_extensions_remain_report_local(self):
        self.sut["implementation"]["annotations"] = {"reviewed": False, "revision": 1}
        report, implementation = self.compare()
        implementation["implementation"]["annotations"] = {"reviewed": True, "revision": 2}
        self.assert_bundle(report, implementation)

    def test_generation_defaults_do_not_make_invalid_sut_identity_valid(self):
        for field in ("name", "type", "version", "language"):
            with self.subTest(field=field):
                self.sut = self.load_sut()
                del self.sut["implementation"][field]
                report, implementation = self.compare()
                self.assertIsInstance(implementation["implementation"][field], str)
                self.assert_bundle(report, implementation, passed=False, check="sut_results.envelope")

    def test_optional_sut_identity_fields_follow_their_schema(self):
        for field in ("source", "commit"):
            for value in ("", None, True, 1, []):
                with self.subTest(field=field, value=value):
                    self.sut = self.load_sut()
                    self.sut["implementation"][field] = value
                    report, implementation = self.compare()
                    self.assertTrue(report.get("fatal_errors"), report)
                    self.assert_bundle(report, implementation, passed=False, check="sut_results.envelope")

    def test_untyped_sut_environment_extension_retains_its_existing_projection(self):
        # SUT source/commit are schema-defined strings; environment is an open
        # extension, copied into the implementation report only when a string.
        self.sut["implementation"]["environment"] = {"os": "synthetic"}
        report, implementation = self.compare()
        self.assertNotIn("environment", implementation["implementation"])
        self.assert_bundle(report, implementation)

    def test_reference_run_retains_cli_identity_without_sut(self):
        self.args.implementation_name = "Local reference checker"
        self.args.implementation_version = "fixture build"
        self.args.implementation_repo = "urn:example:reference"
        report = runner.run_corpus(self.corpus)
        implementation = runner.make_implementation_report(self.args, report)
        self.assertEqual(implementation["implementation"]["name"], "Local reference checker")
        self.assert_bundle(report, implementation, reference=True)

    def test_reference_run_failed_expectation_with_valid_binding(self):
        path = self.corpus / "cases/allow.json"
        case = read(path)
        case["expected"]["should_execute"] = False
        write(path, case)
        write(self.corpus / "corpus.json", runner.make_corpus_index(self.corpus))
        report = runner.run_corpus(self.corpus)
        self.assertEqual(report["summary"]["failed"], 1)
        implementation = runner.make_implementation_report(self.args, report)
        self.assert_bundle(report, implementation, reference=True)

    def test_binding_success_does_not_require_comparison_success(self):
        changes = ({"should_execute": False}, {"outcome": "deny"},
                   {"reason_codes": ["POLICY_MATCH"]}, {"status": "skipped"}, {"status": "error"})
        for mode in ("fixtures", "generated"):
            for change in changes:
                with self.subTest(mode=mode, change=change):
                    self.sut = self.load_sut(mode)
                    self.sut["results"][0].update(change)
                    report, implementation = self.compare()
                    self.assertEqual(report["summary"]["failed"], 1)
                    self.assertEqual(implementation["status"], "fail")
                    assessment = report["cases"][0]["request_binding"]["assessment"]
                    self.assertEqual(assessment["status"], "checked")
                    self.assertIs(assessment["pass"], True)
                    self.assertIs(assessment["binding_requirement_met"], True)
                    self.assert_bundle(report, implementation)

    def test_failed_comparison_does_not_hide_changed_raw_binding(self):
        self.sut["results"][0]["should_execute"] = False
        report, implementation = self.compare()
        original = self.folder / "allow/original.json"
        original.write_bytes(original.read_bytes() + b" ")
        self.assert_bundle(report, implementation, passed=False,
                           check="request_binding.request-binding-allow.recomputed")

    def test_invalid_binding_remains_invalid_after_regenerating_reports(self):
        original = self.folder / "allow/original.json"
        original.write_bytes(original.read_bytes() + b" ")
        report, implementation = self.compare()
        self.assertEqual(report["summary"]["failed"], 1)
        self.assert_bundle(report, implementation, passed=False,
                           check="request_binding.request-binding-allow.recomputed")

    def test_resealed_binding_assessment_cannot_replace_recomputation(self):
        report, _ = self.compare()
        for field, value in (("pass", 1), ("binding_requirement_met", False),
                             ("decision_allows_immediate_execution", False)):
            with self.subTest(field=field):
                changed = copy.deepcopy(report)
                changed["cases"][0]["request_binding"]["assessment"][field] = value
                implementation = runner.make_implementation_report(self.args, changed)
                self.assert_bundle(changed, implementation, passed=False,
                                   check="request_binding.request-binding-allow.recomputed")
        changed = copy.deepcopy(report)
        del changed["cases"][0]["request_binding"]
        self.assert_bundle(changed, runner.make_implementation_report(self.args, changed),
                           passed=False, check="request_binding.coverage")

    def test_index_boolean_is_not_a_number(self):
        report, implementation = self.compare()
        for value in (1, 1.0, "true", None):
            with self.subTest(value=value):
                index = copy.deepcopy(self.index)
                index["cases"][0]["expected_should_execute"] = value
                write(self.corpus / "corpus.json", index)
                self.assert_bundle(report, implementation, passed=False, check="corpus_index.cases.entries")

    def test_index_counts_are_not_booleans(self):
        report, implementation = self.compare()
        for key in ("case_count", "category_counts"):
            with self.subTest(key=key):
                index = copy.deepcopy(self.index)
                if key == "case_count":
                    index["summary"][key] = True
                else:
                    index["summary"][key]["positive"] = True
                write(self.corpus / "corpus.json", index)
                self.assert_bundle(report, implementation, passed=False, check=f"corpus_index.summary.{key}")

    def test_index_equivalent_json_numbers_and_annotations_remain_valid(self):
        report, implementation = self.compare()
        index = copy.deepcopy(self.index)
        index["summary"]["case_count"] = 1.0
        index["summary"]["category_counts"]["positive"] = 1.0
        index["annotation"] = {"revision": 1}
        write(self.corpus / "corpus.json", index)
        self.assert_bundle(report, implementation)

    def test_failed_comparison_bundle_through_cli(self):
        self.sut["results"][0]["should_execute"] = False
        write(self.sut_path, self.sut)
        base = [sys.executable, str(ROOT / "scripts/vate_conformance.py")]
        common = ["--corpus-root", str(self.corpus), "--sut-results", str(self.sut_path)]
        compared = subprocess.run(base + ["compare"] + common + ["--report", str(self.conf_path),
            "--implementation-report", str(self.impl_path)], capture_output=True, text=True, timeout=30)
        self.assertEqual(compared.returncode, 1, compared.stdout + compared.stderr)
        verified = subprocess.run(base + ["verify-bundle"] + common + ["--conformance-report", str(self.conf_path),
            "--implementation-report", str(self.impl_path), "--report", str(self.folder / "bundle.json")],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)

    def test_generated_paths_produce_compare_and_bundle_reports(self):
        base = [sys.executable, "-B", str(ROOT / "scripts/vate_conformance.py")]
        common = ["--corpus-root", str(self.corpus), "--sut-results", str(self.sut_path)]
        bundle_path = self.folder / "bundle.json"
        for artifact in ("admission_receipt", "post_execution_receipt"):
            for path, diagnostic in ((None, None), ("bad\x00.json", "NUL characters"),
                                     ("not-found.json", "file not found")):
                with self.subTest(artifact=artifact, path=path):
                    self.sut = self.load_sut("generated")
                    if path is not None:
                        self.sut["results"][0]["generated_artifacts"][artifact]["local_path"] = path
                    write(self.sut_path, self.sut)
                    for output in (self.conf_path, self.impl_path, bundle_path):
                        output.unlink(missing_ok=True)
                    compared = subprocess.run(base + ["compare"] + common + ["--report", str(self.conf_path),
                        "--implementation-report", str(self.impl_path)], capture_output=True, text=True, timeout=30)
                    self.assertEqual(compared.returncode, 0 if path is None else 1, compared.stderr)
                    self.assertEqual(compared.stderr, "")
                    report, implementation = read(self.conf_path), read(self.impl_path)
                    self.assertEqual(runner.conformance_report_contract_failures(report), [])
                    self.assertEqual(runner.implementation_report_contract_failures(implementation), [])
                    self.assertEqual(report["summary"]["failed"], 0 if path is None else 1)
                    if diagnostic:
                        self.assertIn(diagnostic, json.dumps(report))
                    # Fresh reports bind the mutated SUT bytes. Bundle failure
                    # must come from the artifact path, not stale outer digests.
                    verified = subprocess.run(base + ["verify-bundle"] + common + [
                        "--conformance-report", str(self.conf_path), "--implementation-report", str(self.impl_path),
                        "--report", str(bundle_path)], capture_output=True, text=True, timeout=30)
                    self.assertEqual(verified.returncode, 0 if path is None else 1, verified.stderr)
                    self.assertEqual(verified.stderr, "")
                    bundle = read(bundle_path)
                    self.assertEqual(bundle["status"], "pass" if path is None else "fail")
                    failed = [row for row in bundle["checks"] if not row["pass"]]
                    if diagnostic:
                        check = next(row for row in failed
                                     if row["name"] == "sut_results.generated_artifacts.request-binding-allow")
                        self.assertIn(artifact, check["details"])
                        self.assertIn(diagnostic, check["details"])
                        self.assertTrue(all(row["name"].startswith(("sut_results.generated_artifacts.",
                                                                   "request_binding.")) for row in failed), failed)
                    if jsonschema is not None:
                        for document, schema in ((report, "conformance-report"),
                                                 (implementation, "implementation-report"),
                                                 (bundle, "report-bundle-verification")):
                            jsonschema.Draft202012Validator(read(ROOT / f"schemas/{schema}.schema.json"),
                                format_checker=jsonschema.FormatChecker()).validate(document)

    def test_generated_uri_fallback_rejects_nul(self):
        reference = copy.deepcopy(self.load_sut("generated")["results"][0]["generated_artifacts"]["admission_receipt"])
        del reference["local_path"]
        reference["uri"] = "bad\x00.json"
        for binding_required in (False, True):
            with self.subTest(binding_required=binding_required):
                artifact, path, failures = runner.load_sut_generated_artifact(
                    reference, self.sut_path, "admission_receipt", require_request_binding=binding_required)
                self.assertIsNone(artifact)
                self.assertIsNone(path)
                self.assertTrue(any("NUL characters" in failure for failure in failures), failures)

    def test_generated_filesystem_exceptions_remain_structured(self):
        reference = self.load_sut("generated")["results"][0]["generated_artifacts"]["admission_receipt"]
        for error in (OSError("inspection unavailable"), ValueError("invalid path"),
                      RuntimeError("symlink loop on older Python")):
            for method in ("resolve", "is_symlink", "is_file"):
                with self.subTest(error=type(error).__name__, method=method):
                    effect = [self.folder, error] if method == "resolve" else error
                    with patch.object(Path, method, side_effect=effect):
                        artifact, path, failures = runner.load_sut_generated_artifact(
                            reference, self.sut_path, "admission_receipt", require_request_binding=True)
                    self.assertIsNone(artifact)
                    self.assertIsNone(path)
                    self.assertTrue(any(f"unable to inspect generated artifact path ({type(error).__name__})"
                                        in failure for failure in failures), failures)


if __name__ == "__main__":
    unittest.main()
