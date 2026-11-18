"""Ordinary runner/SUT/bundle checks, including digest-consistent attacks."""
from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import request_binding as b
import runner_binding as adapter

spec = importlib.util.spec_from_file_location("bound_runner_tests", b.ROOT / "scripts/vate_conformance.py")
if spec is None or spec.loader is None:
    raise RuntimeError("runner unavailable")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
CORPUS = b.ROOT / "conformance/request-binding-v1"
EXAMPLES = b.ROOT / "examples/conformance/request-binding"


def read(path):
    return json.loads(path.read_bytes())


def write(path, value):
    path.write_bytes(b.encode(value))


class RunnerBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.submitted = self.root / "sut"
        shutil.copytree(EXAMPLES, self.submitted)
        self.sut_path = self.submitted / "sut-results-generated.json"
        self.directory = self.submitted / "attenuate"

    def target(self, report):
        return next(case for case in report["cases"] if case["case_id"] == "request-binding-attenuate")

    def update_ref(self, key, filename):
        sut = read(self.sut_path)
        case = next(c for c in sut["results"] if c["case_id"] == "request-binding-attenuate")
        ref = case["request_binding_artifacts"] if key == "manifest" else case["generated_artifacts"][key]
        ref["digest"] = b.digest((self.directory / filename).read_bytes())
        write(self.sut_path, sut)

    def update_receipt(self, mutate):
        path = self.directory / "admission-receipt.json"
        receipt = read(path); mutate(receipt); write(path, receipt)
        self.update_ref("admission_receipt", path.name)
        post_path = self.directory / "post-execution.json"
        post = read(post_path); post["admission"]["digest"] = b.digest(b.encode(receipt)); write(post_path, post)
        self.update_ref("post_execution_receipt", post_path.name)

    def assert_binding_failure(self, text):
        report = runner.compare_sut_results(CORPUS, self.sut_path)
        case = self.target(report)
        self.assertFalse(case["pass"])
        self.assertTrue(case["request_binding"]["failures"])
        self.assertIn(text, " ".join(case["request_binding"]["failures"]))
        return report

    def write_bundle(self, report):
        report_path, implementation_path = self.root / "conformance.json", self.root / "implementation.json"
        # Let malformed report numbers reach the runner's report validator.
        report_path.write_text(json.dumps(report, sort_keys=True, separators=(",", ":")))
        args = argparse.Namespace(corpus_root=str(CORPUS), conformance_report_uri=str(report_path), report=str(report_path))
        implementation = runner.make_implementation_report(args, report)
        write(implementation_path, implementation)
        return report_path, implementation_path

    def test_sut_digest_annotations_preserve_binding_and_bundle_checks(self):
        for filename in ("sut-results-fixtures.json", "sut-results-generated.json"):
            with self.subTest(filename=filename):
                path = self.submitted / filename
                sut = read(path)
                for case in sut["results"]:
                    case["request_binding_artifacts"]["digest"]["note"] = "local annotation"
                    for ref in case.get("generated_artifacts", {}).values():
                        ref["digest"]["note"] = "local annotation"
                write(path, sut)
                report = runner.compare_sut_results(CORPUS, path)
                self.assertEqual(report["summary"]["failed"], 0, report)
                report_path, implementation_path = self.write_bundle(report)
                bundle = runner.verify_report_bundle(CORPUS, report_path, implementation_path, path)
                self.assertEqual(bundle["summary"]["failed"], 0, bundle)

    def test_manifest_digest_annotations_do_not_relax_algorithm_or_value(self):
        path = self.directory / "binding-manifest.json"
        expected = b.digest(path.read_bytes())
        for supplied in ({**expected, "alg": "sha-512"}, {**expected, "value": "0" * 64},
                         {"value": expected["value"]}):
            with self.subTest(supplied=supplied):
                supplied["note"] = "annotation does not authorize different bytes"
                with self.assertRaisesRegex(adapter.binding.Invalid, "MANIFEST_DIGEST_MISMATCH"):
                    adapter.load_manifest(path, supplied)

    def test_constraint_basis_matches_core_for_supported_decisions(self):
        for decision in ("allow", "deny", "attenuate"):
            for present in (True, False):
                with self.subTest(decision=decision, present=present):
                    receipt = {"decision": {"outcome": decision}, "request": {}}
                    requested = {"max_amount": {"currency": "USD", "value": "100"}}
                    if present:
                        receipt["request"]["constraints"] = requested
                    selected = requested if present else {}
                    if decision == "attenuate":
                        selected = {"max_amount": {"currency": "USD", "value": "25"}}
                        receipt["attenuation"] = {"effective_constraints": selected}
                    for module in (b.core, runner):
                        self.assertEqual(module.admitted_effective_constraints(receipt), selected)

    def test_constraint_basis_rejects_malformed_receipts_without_fallback(self):
        base = read(self.directory / "admission-receipt.json")
        invalid = [None, [], {}, {"decision": {}, "request": {}},
                   {"decision": {"outcome": []}, "request": {}},
                   {"decision": {"outcome": "allow"}, "request": None}]
        for value in (None, [], True, {}, "bad"):
            receipt = copy.deepcopy(base)
            receipt["attenuation"]["effective_constraints"] = value
            invalid.append(receipt)
            receipt = copy.deepcopy(base)
            receipt["request"]["constraints"] = value
            if value != {}:
                invalid.append(receipt)
        receipt = copy.deepcopy(base)
        del receipt["attenuation"]["effective_constraints"]
        invalid.append(receipt)
        for value in (None, [], {}, True):
            receipt = copy.deepcopy(base)
            receipt["attenuation"] = value
            invalid.append(receipt)
        for decision in ("allow", "deny"):
            receipt = copy.deepcopy(base)
            receipt["decision"]["outcome"] = decision
            invalid.append(receipt)
        for index, receipt in enumerate(invalid):
            with self.subTest(index=index):
                for module in (b.core, runner):
                    with self.assertRaises(ValueError):
                        module.admitted_effective_constraints(receipt)

    def test_runner_linkage_reports_invalid_basis_instead_of_raising(self):
        receipt = read(self.directory / "admission-receipt.json")
        post = read(self.directory / "post-execution.json")
        for value in (None, [], {}, True):
            with self.subTest(value=value):
                receipt["attenuation"]["effective_constraints"] = value
                post["admission"]["digest"] = runner.digest_descriptor(receipt)
                failures = runner.post_execution_side_effect_failures(receipt, post)
                self.assertEqual(len(failures), 1)
                self.assertIn("admission effective constraints invalid", failures[0])
                self.assertIn(failures[0], runner.post_execution_linkage_failures(receipt, post))
                self.assertEqual(runner.linkage_check_violation({}, {"kind": "effective_constraints"}, receipt, post),
                                 (True, None))

    def test_runner_linkage_rejects_selected_legacy_constraints(self):
        for decision in ("allow", "attenuate"):
            for name in ("max_amount_usd", "resource"):
                with self.subTest(decision=decision, name=name):
                    receipt = read(self.submitted / decision / "admission-receipt.json")
                    post = read(self.submitted / decision / "post-execution.json")
                    runner.admitted_effective_constraints(receipt)[name] = None
                    self.assertTrue(any("legacy alias" in message for message in
                                        runner.post_execution_side_effect_failures(receipt, post)))

    def test_non_ascii_timestamp_digits_are_rejected_before_the_datetime_parser(self):
        value = "2026-11-16T12:34:56.123456+09:00"
        for digits in ("０１２３４５６７８９", "٠١٢٣٤٥٦٧٨٩"):
            for index, char in enumerate(value):
                if char not in "0123456789":
                    continue
                changed = value[:index] + digits[int(char)] + value[index + 1:]
                for module in (b.core, runner):
                    with self.subTest(module=module.__name__, index=index, value=changed):
                        with mock.patch.object(module, "datetime") as parser:
                            with self.assertRaises(ValueError):
                                module.parse_time(changed)
                            parser.fromisoformat.assert_not_called()
        for valid in (value, "2026-11-16t12:34:56.1z", "2026-11-16T12:34:56Z"):
            self.assertEqual(b.core.parse_time(valid), runner.parse_time(valid))

    def assert_receipt_digest_relation(self, receipt, post, *, matches):
        case = {"artifacts": {"admission_receipt": str(self.directory / "admission-receipt.json")}}
        core_result = b.core.VateVerifier(verifier_id="urn:vate:digest-controls").validate_post_execution_linkage(receipt, post)
        self.assertEqual(core_result["outcome"], "success" if matches else "failed")
        failures = runner.post_execution_linkage_failures(receipt, post)
        self.assertEqual("admission digest mismatch" not in failures, matches)
        self.assertEqual(runner.linkage_check_violation(case, {"kind": "admission_digest"}, receipt, post),
                         (not matches, None))
        self.assertEqual(runner.admission_link_relation_state(receipt, post)["digest_match"], matches)

    def test_receipt_digest_annotations_preserve_all_linkage_comparisons(self):
        receipt = read(self.directory / "admission-receipt.json")
        post = read(self.directory / "post-execution.json")
        self.assert_receipt_digest_relation(receipt, post, matches=True)
        post["admission"]["digest"].update(note="retained", extension={"values": [None, True, 1]})
        self.assert_receipt_digest_relation(receipt, post, matches=True)

    def test_receipt_digest_annotations_do_not_relax_algorithm_or_value(self):
        receipt = read(self.directory / "admission-receipt.json")
        expected = runner.digest_descriptor(receipt)
        invalid = (None, [], {}, {"alg": "sha-256"}, {"value": expected["value"]},
                   {**expected, "alg": "sha-512"}, {**expected, "value": "0" * 64},
                   {**expected, "value": expected["value"][:63]},
                   {**expected, "value": expected["value"] + "0"},
                   {**expected, "value": expected["value"].upper()},
                   {**expected, "value": expected["value"] + "\n"},
                   {**expected, "value": True})
        for digest in invalid:
            with self.subTest(digest=digest):
                post = read(self.directory / "post-execution.json")
                post["admission"]["digest"] = copy.deepcopy(digest)
                if isinstance(digest, dict):
                    post["admission"]["digest"]["note"] = "annotation does not authorize different bytes"
                self.assert_receipt_digest_relation(receipt, post, matches=False)

    def test_admission_annotations_remain_in_digest_basis(self):
        path = self.directory / "admission-receipt.json"
        receipt = read(path)
        post = read(self.directory / "post-execution.json")
        receipt["note"] = "part of the hashed admission"
        write(path, receipt)
        self.assert_receipt_digest_relation(receipt, post, matches=False)
        post["admission"]["digest"] = {**runner.digest_descriptor(receipt), "note": "descriptor annotation"}
        self.assert_receipt_digest_relation(receipt, post, matches=True)

    def test_receipt_digest_annotations_preserve_generated_compare_and_bundle(self):
        path = self.directory / "post-execution.json"
        post = read(path)
        post["admission"]["digest"]["note"] = "receipt-internal annotation"
        write(path, post)
        self.update_ref("post_execution_receipt", path.name)
        report = runner.compare_sut_results(CORPUS, self.sut_path)
        self.assertEqual(report["summary"]["failed"], 0, report)
        paths = self.write_bundle(report)
        bundle = runner.verify_report_bundle(CORPUS, *paths, self.sut_path)
        self.assertEqual(bundle["summary"]["failed"], 0, bundle)

    def test_all_modes_and_bundle_recompute(self):
        run = runner.run_corpus(CORPUS)
        self.assertNotIn("fatal_errors", run)
        self.assertEqual(run["summary"], {"total": 4, "passed": 4, "failed": 0, "skipped": 0})
        for filename in ("sut-results-fixtures.json", "sut-results-generated.json"):
            sut_path = self.submitted / filename
            report = runner.compare_sut_results(CORPUS, sut_path)
            self.assertNotIn("fatal_errors", report)
            self.assertEqual(report["summary"]["passed"], 4)
            paths = self.write_bundle(report)
            bundle = runner.verify_report_bundle(CORPUS, *paths, sut_path)
            self.assertEqual(bundle["status"], "pass", bundle["checks"])
            self.assertEqual(len([c for c in bundle["checks"] if c["name"].startswith("request_binding.")]), 6)
            for case in report["cases"]:
                assessment = case["request_binding"]["assessment"]
                self.assertTrue(assessment["binding_requirement_met"])
                self.assertEqual(assessment["decision_allows_immediate_execution"], case["actual_should_execute"])

    def test_coverage_distinguishes_legacy_from_preimage_checks(self):
        legacy = runner.run_corpus(b.ROOT / "conformance/al2-vate-v0.3")
        self.assertEqual(legacy["summary"]["passed"], 76)
        self.assertEqual(legacy["request_binding_coverage"], {
            "required_cases": 0, "satisfied_cases": 0, "not_required_cases": 76, "all_cases_satisfied": False})
        bound = runner.run_corpus(CORPUS)
        self.assertEqual(bound["request_binding_coverage"], {
            "required_cases": 4, "satisfied_cases": 4, "not_required_cases": 0, "all_cases_satisfied": True})
        self.assertEqual(runner.request_binding_coverage([])["all_cases_satisfied"], False)

    def test_unavailable_binding_is_not_counted_as_satisfied(self):
        self.update_receipt(lambda receipt: receipt.pop("request_binding"))
        report = runner.compare_sut_results(CORPUS, self.sut_path)
        self.assertEqual(report["request_binding_coverage"], {
            "required_cases": 4, "satisfied_cases": 3, "not_required_cases": 0, "all_cases_satisfied": False})

    def test_coverage_tampering_or_deletion_cannot_pass_rehashed_bundle(self):
        original = runner.compare_sut_results(CORPUS, self.sut_path)
        mutations = (
            lambda report: report.pop("request_binding_coverage"),
            lambda report: report["request_binding_coverage"].update(required_cases=True),
            lambda report: report["request_binding_coverage"].update(satisfied_cases=4.0),
            lambda report: report["request_binding_coverage"].update(all_cases_satisfied=1),
            lambda report: self.target(report).update(request_binding_required=False),
            lambda report: self.target(report).pop("request_binding_required"),
        )
        for mutate in mutations:
            report = copy.deepcopy(original)
            mutate(report)
            paths = self.write_bundle(report)
            result = runner.verify_report_bundle(CORPUS, *paths, self.sut_path)
            self.assertEqual(result["status"], "fail", result["checks"])

    def test_missing_sut_manifest_fails_both_modes(self):
        for filename in ("sut-results-fixtures.json", "sut-results-generated.json"):
            self.sut_path = self.submitted / filename
            sut = read(self.sut_path)
            del next(c for c in sut["results"] if c["case_id"] == "request-binding-attenuate")["request_binding_artifacts"]
            write(self.sut_path, sut)
            self.assert_binding_failure("request_binding_artifacts")

    def test_stripped_declaration_and_rehashed_output_fails(self):
        self.update_receipt(lambda r: r.pop("request_binding"))
        report = self.assert_binding_failure("BINDING_NOT_DECLARED")
        self.assertIsNone(self.target(report)["request_binding"]["assessment"]["pass"])

    def test_rehashed_from_mismatch_fails(self):
        self.update_receipt(lambda r: r["attenuation"]["changes"][0].update({"from": "119.00"}))
        self.assert_binding_failure("ATTENUATION_FROM_MISMATCH")

    def test_rehashed_evidence_substitution_fails_compare_and_bundle(self):
        self.update_receipt(lambda r: r["evidence"][0]["digest"].update(value="0" * 64))
        report = self.assert_binding_failure("RECEIPT_EVIDENCE_MISMATCH")
        self.assertEqual(report["request_binding_coverage"]["satisfied_cases"], 3)
        # A submitted pass cannot replace recomputation, even with fresh report
        # and receipt digests and a correctly relinked post receipt.
        assessment = self.target(report)["request_binding"]["assessment"]
        assessment.update(status="checked", **{"pass": True}, binding_requirement_met=True)
        self.target(report)["request_binding"]["failures"] = []
        paths = self.write_bundle(report)
        verified = runner.verify_report_bundle(CORPUS, *paths, self.sut_path)
        self.assertEqual(verified["status"], "fail")
        self.assertTrue(any(c["pass"] is False and c["name"].startswith("request_binding.")
                            for c in verified["checks"]))

    def test_rehashed_widening_fails(self):
        self.update_receipt(lambda r: r["attenuation"]["changes"][0].update({"to": "121.00"}))
        self.assert_binding_failure("CONSTRAINT_NOT_NARROWED")

    def test_manifest_bytes_digest_mismatch_fails(self):
        path = self.directory / "binding-manifest.json"
        path.write_bytes(path.read_bytes() + b"\n")
        self.assert_binding_failure("MANIFEST_DIGEST_MISMATCH")

    def test_original_file_digest_mismatch_fails(self):
        path = self.directory / "original.json"
        path.write_bytes(path.read_bytes() + b"\n")
        self.assert_binding_failure("ARTIFACT_DIGEST_MISMATCH")

    def test_missing_original_file_fails(self):
        (self.directory / "original.json").unlink()
        self.assert_binding_failure("No such file")

    def test_manifest_paths_duplicates_and_shapes(self):
        path = self.directory / "binding-manifest.json"
        initial = read(path)
        for bad_path in ("../original.json", "/tmp/original.json", "https://example.com/a.json", "a.json\n"):
            manifest = copy.deepcopy(initial); manifest["artifacts"][0]["path"] = bad_path
            write(path, manifest); self.update_ref("manifest", path.name)
            self.assert_binding_failure("UNSAFE_ARTIFACT_PATH")
        manifest = copy.deepcopy(initial); manifest["artifacts"].append(manifest["artifacts"][0])
        write(path, manifest); self.update_ref("manifest", path.name)
        self.assert_binding_failure("DUPLICATE_ARTIFACT_URI")
        path.write_bytes(b'{"contract":"x","contract":"x","artifacts":[]}')
        self.update_ref("manifest", path.name)
        self.assert_binding_failure("DUPLICATE_JSON_KEY")

    def test_symlink_and_fifo_are_not_read(self):
        import os
        path = self.directory / "original.json"
        raw = path.read_bytes(); path.unlink()
        target = self.root / "elsewhere.json"; target.write_bytes(raw)
        path.symlink_to(target)
        with self.assertRaises(OSError): adapter.load_manifest(self.directory / "binding-manifest.json")
        path.unlink(); os.mkfifo(path)
        with self.assertRaisesRegex(ValueError, "NOT_A_REGULAR_FILE"):
            adapter.load_manifest(self.directory / "binding-manifest.json")

    def test_oversize_manifest_and_artifact(self):
        for filename in ("binding-manifest.json", "original.json"):
            path = self.directory / filename; old = path.read_bytes()
            path.write_bytes(b" " * (b.MAX_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "ARTIFACT_TOO_LARGE"):
                adapter.load_manifest(self.directory / "binding-manifest.json")
            path.write_bytes(old)

    def test_another_admission_is_not_the_receiver_pin(self):
        path = self.directory / "admission-request.json"
        request = read(path); request["principal"] = "did:example:another"; write(path, request)
        ref = b.reference(path.read_bytes())
        manifest_path = self.directory / "binding-manifest.json"
        manifest = read(manifest_path)
        entry = next(e for e in manifest["artifacts"] if e["path"] == path.name)
        entry.update(ref); write(manifest_path, manifest); self.update_ref("manifest", manifest_path.name)
        def mutate(r):
            r["request_binding"]["admission_request_ref"] = ref
            r["subject"]["principal"] = request["principal"]
        self.update_receipt(mutate)
        self.assert_binding_failure("ADMISSION_REFERENCE_MISMATCH")

    def test_reformatted_preimage_preserves_canonical_hash(self):
        path = self.directory / "original.json"
        original = read(path); path.write_text(json.dumps(original, indent=2) + "\n")
        ref = b.reference(path.read_bytes())
        manifest_path = self.directory / "binding-manifest.json"
        manifest = read(manifest_path)
        next(e for e in manifest["artifacts"] if e["path"] == path.name).update(ref)
        write(manifest_path, manifest); self.update_ref("manifest", manifest_path.name)
        self.update_receipt(lambda r: r["request_binding"].update(original_ref=ref))
        report = runner.compare_sut_results(CORPUS, self.sut_path)
        self.assertTrue(self.target(report)["pass"], self.target(report)["failures"])

    def test_bundle_rejects_forged_pass_even_with_all_report_digests_renewed(self):
        good = runner.compare_sut_results(CORPUS, self.sut_path)
        self.update_receipt(lambda r: r["attenuation"]["changes"][0].update({"from": "119.00"}))
        bad = self.assert_binding_failure("ATTENUATION_FROM_MISMATCH")
        forged = copy.deepcopy(good)
        # Retain the successful claims, but renew the SUT digest and linked
        # implementation report. Only re-reading semantics can reject this.
        forged["sut_results"] = bad["sut_results"]
        paths = self.write_bundle(forged)
        report = runner.verify_report_bundle(CORPUS, *paths, self.sut_path)
        self.assertEqual(report["status"], "fail")
        failed = [c["name"] for c in report["checks"] if not c["pass"]]
        self.assertIn("request_binding.request-binding-attenuate.recomputed", failed)

    def test_bundle_rejects_removed_assessment_with_renewed_report_digest(self):
        report = runner.compare_sut_results(CORPUS, self.sut_path)
        del self.target(report)["request_binding"]
        paths = self.write_bundle(report)
        result = runner.verify_report_bundle(CORPUS, *paths, self.sut_path)
        self.assertIn("request_binding.coverage", [c["name"] for c in result["checks"] if not c["pass"]])

    def test_run_checks_case_requirement_on_raw_receipt(self):
        corpus = self.root / "corpus"; shutil.copytree(CORPUS, corpus)
        for path in (corpus / "cases").glob("*.json"):
            case = read(path)
            for key, source in case["artifacts"].items():
                case["artifacts"][key] = str(corpus / Path(source).relative_to("conformance/request-binding-v1"))
            write(path, case)
        path = corpus / "fixtures/attenuate/admission-receipt.json"
        receipt = read(path); del receipt["request_binding"]; write(path, receipt)
        write(corpus / "corpus.json", runner.make_corpus_index(corpus))
        report = runner.run_corpus(corpus)
        self.assertFalse(self.target(report)["pass"])
        self.assertIn("BINDING_NOT_DECLARED", self.target(report)["request_binding"]["failures"])

    def test_unknown_required_contract_cannot_be_skipped(self):
        case = read(CORPUS / "cases/attenuate.json")
        case["request_binding"]["required_contract"] = "unknown"
        report = runner.evaluate_request_binding(case)
        self.assertIsNone(report["assessment"]["pass"])
        self.assertIn("UNSUPPORTED_BINDING_PROFILE", report["failures"])

    def test_generated_pair_identity_is_checked_on_positive_cases(self):
        good = runner.compare_sut_results(CORPUS, self.sut_path)
        path = self.directory / "post-execution.json"
        initial = read(path)
        for field, value in (("receipt_id", "unrelated"), ("uri", "urn:unrelated"),
                             ("digest", {"alg": "sha-256", "value": "f" * 64})):
            with self.subTest(field=field):
                post = copy.deepcopy(initial); post["admission"][field] = value
                write(path, post); self.update_ref("post_execution_receipt", path.name)
                bad = runner.compare_sut_results(CORPUS, self.sut_path)
                case = self.target(bad)
                self.assertFalse(case["pass"])
                self.assertIn("generated_artifacts.linkage", " ".join(case["failures"]))
                forged = copy.deepcopy(good); forged["sut_results"] = bad["sut_results"]
                checked = runner.verify_report_bundle(CORPUS, *self.write_bundle(forged), self.sut_path)
                self.assertEqual(checked["status"], "fail")
                failed = [c["name"] for c in checked["checks"] if not c["pass"]]
                self.assertIn("sut_results.generated_artifacts.request-binding-attenuate", failed)
                # The post-execution link is invalid; the admission's input
                # binding remains valid and must keep its separate verdict.
                binding = next(c for c in checked["checks"]
                               if c["name"] == "request_binding.request-binding-attenuate.recomputed")
                self.assertTrue(binding["pass"])

    def test_bundle_distinguishes_boolean_from_numbers(self):
        good = runner.compare_sut_results(CORPUS, self.sut_path)
        paths = [("pass",), ("binding_requirement_met",), ("decision_allows_immediate_execution",),
                 ("checks", 0, "pass")]
        for path in paths:
            for number in (1, 1.0):
                with self.subTest(path=path, number=repr(number)):
                    report = copy.deepcopy(good)
                    item = self.target(report)["request_binding"]["assessment"]
                    for part in path[:-1]: item = item[part]
                    item[path[-1]] = number
                    self.assertTrue(runner.conformance_case_contract_failures(self.target(report), "case"))
                    checked = runner.verify_report_bundle(CORPUS, *self.write_bundle(report), self.sut_path)
                    self.assertEqual(checked["status"], "fail")
                    self.assertIn("request_binding.request-binding-attenuate.recomputed",
                                  [c["name"] for c in checked["checks"] if not c["pass"]])

    def test_saved_assessment_shape_and_status_are_validated(self):
        report = runner.compare_sut_results(CORPUS, self.sut_path)
        initial = self.target(report)["request_binding"]
        mutations = [lambda x: x.update(extra=True), lambda x: x.pop("failures"),
            lambda x: x["assessment"].update(status="not_checked"),
            lambda x: x["assessment"].update(binding_requirement_met=False),
            lambda x: x["assessment"].update(checks=[]),
            lambda x: x["assessment"]["receipt_digest"].update(value="f" * 64 + "\n"),
            lambda x: x["assessment"]["checks"][0].update(status="not_checked"),
            lambda x: x["assessment"]["checks"][0].pop("pass")]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                value = copy.deepcopy(initial); mutate(value)
                self.assertTrue(runner.request_binding_report_contract_failures(value, "binding"))
        for case in report["cases"]:
            self.assertEqual(runner.request_binding_report_contract_failures(case["request_binding"], "binding"), [])

    def test_manifest_symlink_is_rejected_through_both_runner_modes(self):
        path = self.directory / "binding-manifest.json"
        target = self.directory / "manifest-real.json"
        path.rename(target); path.symlink_to(target.name)
        for filename in ("sut-results-fixtures.json", "sut-results-generated.json"):
            with self.subTest(mode=filename):
                self.sut_path = self.submitted / filename
                self.assert_binding_failure("symbolic links")

    def test_generated_receipt_symlink_is_rejected_before_reading(self):
        path = self.directory / "admission-receipt.json"
        target = self.directory / "receipt-real.json"
        path.rename(target); path.symlink_to(target.name)
        report = self.assert_binding_failure("symbolic links")
        self.assertIn("generated_artifacts.admission_receipt.local_path", " ".join(self.target(report)["failures"]))

    def test_manifest_parent_symlink_is_rejected(self):
        (self.submitted / "case-link").symlink_to("attenuate", target_is_directory=True)
        sut = read(self.sut_path)
        entry = next(c for c in sut["results"] if c["case_id"] == "request-binding-attenuate")
        entry["request_binding_artifacts"]["local_path"] = "case-link/binding-manifest.json"
        write(self.sut_path, sut)
        self.assert_binding_failure("symbolic links")

    def test_deep_generated_receipt_returns_a_failed_cli_report(self):
        path = self.directory / "admission-receipt.json"
        original = path.read_bytes()
        path.write_bytes(b'{"extra":' + b'[' * 20000 + b'0' + b']' * 20000 + b',' + original[1:])
        self.update_ref("admission_receipt", path.name)
        output = self.root / "deep-report.json"
        command = [sys.executable, str(b.ROOT / "scripts/vate_conformance.py"), "compare", "--corpus-root", str(CORPUS),
                   "--sut-results", str(self.sut_path), "--report", str(output)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)
        case = self.target(read(output))
        self.assertFalse(case["pass"])
        self.assertIn("JSON_DEPTH_EXCEEDED", " ".join(case["failures"]))

    def test_legacy_generated_loader_reports_parser_recursion_error(self):
        sut = read(self.sut_path)
        entry = next(c for c in sut["results"] if c["case_id"] == "request-binding-attenuate")
        with mock.patch.object(runner, "strict_json_loads", side_effect=RecursionError("depth limit")):
            artifact, _, failures = runner.load_sut_generated_artifact(
                entry["generated_artifacts"]["admission_receipt"], self.sut_path, "receipt")
        self.assertIsNone(artifact)
        self.assertIn("depth limit", " ".join(failures))

    def test_index_commands_select_the_indexed_corpus(self):
        for root in (CORPUS, self.root / "corpus with spaces"):
            with self.subTest(root=str(root)):
                if root != CORPUS: shutil.copytree(CORPUS, root)
                index = runner.make_corpus_index(root)
                for name, command in index["runner"].items():
                    argv = shlex.split(command)
                    self.assertEqual(argv[argv.index("--corpus-root") + 1], runner.display_path(root.resolve()))
                    if name == "index_command":
                        self.assertEqual(argv[argv.index("--out") + 1], runner.display_path((root / "corpus.json").resolve()))

if __name__ == "__main__":
    unittest.main()
