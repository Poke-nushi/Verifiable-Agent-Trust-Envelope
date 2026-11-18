"""Open digest descriptors bind alg/value; their containing bytes stay bound."""
import argparse
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import vate_conformance as runner

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "conformance/al2-vate-v0.3"


def read(path):
    return json.loads(path.read_bytes())


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def context(data):
    return next(row["artifacts"]["verification_context"][0] for row in data["results"]
                if row.get("artifacts", {}).get("verification_context"))


class DigestIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="vate-digest-identity-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.sut = read(ROOT / "examples/conformance/sut-results-pass.example.json")
        self.sut_path = self.folder / "sut.json"
        self.conf_path = self.folder / "conformance.json"
        self.impl_path = self.folder / "implementation.json"
        write(self.sut_path, self.sut)

    def implementation(self, report, corpus=CORPUS):
        args = argparse.Namespace(corpus_root=str(corpus), report=str(self.conf_path),
                                  conformance_report_uri=str(self.conf_path))
        return runner.make_implementation_report(args, report)

    def bundle(self, report, implementation, corpus=CORPUS):
        write(self.conf_path, report)
        write(self.impl_path, implementation)
        return runner.verify_report_bundle(corpus, self.conf_path, self.impl_path, self.sut_path)

    def assert_pass(self, report):
        self.assertFalse(report.get("fatal_errors"), report.get("fatal_errors"))
        self.assertEqual(report["summary"]["failed"], 0, report)

    def test_descriptor_identity_validates_both_sides(self):
        expected = {"alg": "sha-256", "value": "a" * 64}
        annotated = {**expected, "note": {"revision": 1, "reviewed": False}}
        self.assertTrue(runner.digest_descriptors_match(expected, annotated))
        self.assertTrue(runner.digest_descriptors_match(annotated, expected))
        for value in (None, {}, "a" * 64, {"alg": "sha-256"},
                      {**expected, "alg": "sha-512"}, {**expected, "value": True},
                      {**expected, "value": "A" * 64}, {**expected, "value": "a" * 64 + "\n"},
                      {**expected, "value": "a" * 63}, {**expected, "value": "b" * 64}):
            with self.subTest(value=value):
                self.assertFalse(runner.digest_descriptors_match(value, expected))
                self.assertFalse(runner.digest_descriptors_match(expected, value))

    def test_compare_and_cli_bundle_accept_annotations_without_dropping_them(self):
        self.sut["corpus"]["digest"]["note"] = "corpus annotation"
        context(self.sut)["digest"]["note"] = "artifact annotation"
        context(self.sut)["context_bindings"][0]["digest"]["note"] = "binding annotation"
        write(self.sut_path, self.sut)
        common = ["--corpus-root", str(CORPUS), "--sut-results", str(self.sut_path)]
        base = [sys.executable, str(ROOT / "scripts/vate_conformance.py")]
        compared = subprocess.run(base + ["compare"] + common + [
            "--report", str(self.conf_path), "--implementation-report", str(self.impl_path),
            "--conformance-report-uri", str(self.conf_path)], capture_output=True, text=True, timeout=30)
        self.assertEqual(compared.returncode, 0, compared.stdout + compared.stderr)
        self.assert_pass(read(self.conf_path))
        bundle_path = self.folder / "bundle.json"
        verified = subprocess.run(base + ["verify-bundle"] + common + [
            "--conformance-report", str(self.conf_path), "--implementation-report", str(self.impl_path),
            "--report", str(bundle_path)], capture_output=True, text=True, timeout=30)
        self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
        self.assertEqual(read(self.sut_path), self.sut)
        # An annotation still changes the bytes of the containing SUT. A saved
        # report must not accept later annotation edits without a new digest.
        self.sut["corpus"]["digest"]["note"] = "later edit"
        write(self.sut_path, self.sut)
        self.assertGreater(runner.verify_report_bundle(
            CORPUS, self.conf_path, self.impl_path, self.sut_path)["summary"]["failed"], 0)

    def test_compare_rejects_wrong_or_malformed_open_descriptors(self):
        targets = (
            lambda data: data["corpus"],
            lambda data: context(data),
            lambda data: context(data)["context_bindings"][0],
        )
        for index, target in enumerate(targets):
            for replacement in (None, {}, {"alg": "sha-512", "value": "0" * 64},
                                {"alg": "sha-256", "value": "0" * 64},
                                {"alg": "sha-256", "value": "0" * 64 + "\n"}):
                with self.subTest(target=index, replacement=replacement):
                    data = copy.deepcopy(self.sut)
                    target(data)["digest"] = replacement
                    write(self.sut_path, data)
                    report = runner.compare_sut_results(CORPUS, self.sut_path)
                    self.assertTrue(report.get("fatal_errors") or report["summary"]["failed"])

    def test_bundle_digest_surfaces_accept_annotations_and_reject_false_identity(self):
        baseline = runner.compare_sut_results(CORPUS, self.sut_path)
        self.assert_pass(baseline)
        targets = (("conformance", "corpus"), ("conformance", "sut_results"),
                   ("implementation", "corpus"), ("implementation", "conformance_report"))
        for document, field in targets:
            for mutation, valid in (({"note": "allowed annotation"}, True),
                                    ({"value": "0" * 64}, False),
                                    ({"alg": "sha-512"}, False),
                                    ({"value": True}, False)):
                with self.subTest(document=document, field=field, mutation=mutation):
                    report = copy.deepcopy(baseline)
                    if document == "conformance":
                        report[field]["digest"].update(mutation)
                    # Recompute the outer digest after changing the inner report.
                    implementation = self.implementation(report)
                    if document == "implementation":
                        implementation[field]["digest"].update(mutation)
                    bundle = self.bundle(report, implementation)
                    self.assertEqual(bundle["summary"]["failed"] == 0, valid, bundle)

    def test_corpus_index_digest_uses_the_same_identity_rule(self):
        corpus = self.folder / "corpus"
        shutil.copytree(CORPUS, corpus)
        index = runner.make_corpus_index(corpus)
        write(corpus / "corpus.json", index)
        self.sut["corpus"]["digest"] = index["digest"]
        write(self.sut_path, self.sut)
        report = runner.compare_sut_results(corpus, self.sut_path)
        self.assert_pass(report)
        implementation = self.implementation(report, corpus)
        for mutation, valid in (({"note": "corpus annotation"}, True),
                                ({"value": "0" * 64}, False), ({"alg": "sha-512"}, False)):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(index)
                changed["digest"].update(mutation)
                write(corpus / "corpus.json", changed)
                result = self.bundle(report, implementation, corpus)
                self.assertEqual(result["summary"]["failed"] == 0, valid, result)

    def test_policy_snapshot_content_and_cross_reference_identity(self):
        case = read(CORPUS / "cases/allow-valid-with-policy-snapshot.json")
        admission = runner.load_artifact(case, "admission_receipt")
        self.assertEqual(runner.evaluate_policy_snapshot_checks(case, admission, None), [])
        # Metadata's closed digest is unchanged; only the open receipt digest
        # carries an annotation. Both references still identify the same policy.
        metadata = {"policy_snapshot": copy.deepcopy(admission["policy"]["policy_snapshot"])}
        check = case["policy_snapshot_checks"][0]
        check["reference_paths"].append({"artifact": "a2a_metadata", "path": "policy_snapshot"})
        admission["policy"]["policy_snapshot"]["digest"]["note"] = "receipt annotation"
        self.assertEqual(runner.evaluate_policy_snapshot_checks(case, admission, metadata), [])
        for mutation in ({"value": "0" * 64}, {"alg": "sha-512"}, {"value": True}):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(admission)
                changed["policy"]["policy_snapshot"]["digest"].update(mutation)
                self.assertTrue(runner.evaluate_policy_snapshot_checks(case, changed, metadata))
        metadata["policy_snapshot"]["uri"] = "urn:other-policy"
        self.assertTrue(runner.evaluate_policy_snapshot_checks(case, admission, metadata))

    def test_policy_compare_fields_preserve_json_types(self):
        case = read(CORPUS / "cases/allow-valid-with-policy-snapshot.json")
        admission = runner.load_artifact(case, "admission_receipt")
        metadata = {"policy_snapshot": copy.deepcopy(admission["policy"]["policy_snapshot"])}
        check = case["policy_snapshot_checks"][0]
        check["reference_paths"].append({"artifact": "a2a_metadata", "path": "policy_snapshot"})
        check["compare_fields"] = ["annotation"]
        for left, right, valid in ((False, 0, False), (1, 1.0, True), (False, False, True)):
            with self.subTest(left=left, right=right):
                admission["policy"]["policy_snapshot"]["annotation"] = left
                metadata["policy_snapshot"]["annotation"] = right
                self.assertEqual(not runner.evaluate_policy_snapshot_checks(case, admission, metadata), valid)


if __name__ == "__main__":
    unittest.main()
