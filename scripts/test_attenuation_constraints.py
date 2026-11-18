"""Attenuation constraints and their execution gate in the reference runner."""
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
VALID = {"max_amount": {"currency": "USD", "value": "25.00"},
         "tool_allowlist": ["merchant.checkout.confirm"], "target_resource": "urn:example:resource",
         "approval": {"mode": "required"}, "expires_at": "2026-05-04T03:05:00Z",
         "approval.policy_ref": "urn:example:policy"}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def receipt_for(field, state):
    receipt = json.loads((ROOT / "examples/receipts/admission-attenuate-max-amount.example.json").read_bytes())
    target = receipt["attenuation"]["effective_constraints"]
    key = field
    if field == "approval.policy_ref":
        target["approval"] = {"mode": "required"}
        target, key = target["approval"], "policy_ref"
    target.pop(key, None)
    if state != "absent":
        target[key] = copy.deepcopy(VALID[field]) if state == "valid" else None if state == "null" else False
    return receipt


class AttenuationConstraintTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="vate-attenuation-constraints-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    def case(self, field, state):
        folder = self.folder / (field + "-" + state)
        receipt = receipt_for(field, state)
        artifact = folder / "receipt.json"
        write(artifact, receipt)
        corpus = folder / "corpus"
        write(corpus / "cases/constraint.json", {
            "version": "vate-conformance-0.3", "profile": runner.PROFILE, "case_id": "constraint",
            "title": "Optional attenuation constraint", "category": "positive",
            "purpose": "Check the declared constraint type at the ordinary runner boundary.",
            "artifacts": {"admission_receipt": str(artifact)},
            "expected": {"admission_decision": "attenuate", "should_execute": True,
                         "reason_codes": receipt["decision"]["reason_codes"], "checks": []},
            "attenuation_checks": [{"artifact": "admission_receipt", "source_path": "attenuation", "expect_valid": True}],
        })
        shutil.copyfile(ROOT / "conformance/al2-vate-v0.3/conformance-case.schema.json", corpus / "conformance-case.schema.json")
        index = runner.make_corpus_index(corpus)
        write(corpus / "corpus.json", index)
        ref = {"uri": str(artifact), "media_type": "application/vate-admission-receipt+json",
               "digest": {"alg": "sha-256", "value": runner.sha256_file(artifact)}}
        sut = {"version": runner.SUT_RESULTS_VERSION, "profile": runner.PROFILE,
               "generated_at": "2026-11-17T00:00:00Z", "artifact_mode": "generated-receipts",
               "implementation": {"name": "Synthetic constraint verifier", "type": "fixture", "version": "1", "language": "JSON"},
               "corpus": {"profile": runner.PROFILE, "digest": index["digest"]},
               "results": [{"case_id": "constraint", "status": "completed", "outcome": "attenuate", "should_execute": True,
                            "reason_codes": receipt["decision"]["reason_codes"], "checks": [],
                            "artifacts": {"admission_receipt": ref},
                            "generated_artifacts": {"admission_receipt": {**ref, "uri": "receipt.json"}}}]}
        write(folder / "sut.json", sut)
        return folder, corpus

    def test_shape_checks_distinguish_presence_from_null(self):
        for field in VALID:
            for state in ("absent", "valid", "null", "wrong_type"):
                with self.subTest(field=field, state=state):
                    receipt = receipt_for(field, state)
                    invalid = state in ("null", "wrong_type")
                    self.assertEqual(bool(runner.attenuation_validation_failures(receipt["attenuation"])), invalid)
                    self.assertEqual(bool(runner.generated_admission_receipt_shape_failures(receipt, "receipt")), invalid)

    def test_execution_gate_agrees_across_admission_and_both_linkage_paths(self):
        case = json.loads((ROOT / "conformance/al2-vate-v0.3/cases/post-execution-linkage-success.json").read_bytes())
        admission = runner.load_artifact(case, "admission_receipt")
        post = runner.load_artifact(case, "post_execution_receipt")
        check = {"kind": "admission_executable", "expect_valid": True, "reason_code": "POST_EXEC_ADMISSION_DENIED"}
        for fields, executable in (
            ({"mode": "narrow", "require_new_permit": False}, True),
            ({"mode": "deny_if_not_accepted", "require_new_permit": False}, True),
            ({"mode": "narrow", "require_new_permit": True}, False),
            ({"mode": "require_new_permit", "require_new_permit": False}, False),
            ({"mode": "narrow", "require_new_permit": 0}, False),
            ({"mode": "narrow"}, False),
            ({"mode": [], "require_new_permit": False}, False),
            ({"require_new_permit": False}, False),
        ):
            with self.subTest(fields=fields):
                receipt = copy.deepcopy(admission)
                attenuation = receipt["attenuation"]
                del attenuation["mode"], attenuation["require_new_permit"]
                attenuation.update(fields)
                post["admission"]["digest"] = runner.digest_descriptor(receipt)
                self.assertIs(runner.actual_should_execute(receipt), executable)
                self.assertEqual(runner.linkage_check_violation(case, check, receipt, post), (not executable, None))
                self.assertEqual(runner.post_execution_linkage_failures(receipt, post) == [], executable)

    def test_allow_requires_absent_attenuation(self):
        admission = {"decision": {"outcome": "allow"}}
        self.assertTrue(runner.actual_should_execute(admission))
        admission["attenuation"] = None
        self.assertFalse(runner.actual_should_execute(admission))

    def test_run_compare_and_bundle_reject_invalid_declared_constraints(self):
        for field in VALID:
            for state in ("absent", "valid", "null", "wrong_type"):
                with self.subTest(field=field, state=state):
                    folder, corpus = self.case(field, state)
                    invalid = state in ("null", "wrong_type")
                    report = runner.run_corpus(corpus)
                    self.assertEqual(report["summary"]["failed"], int(invalid))
                    report = runner.compare_sut_results(corpus, folder / "sut.json")
                    self.assertFalse(report.get("fatal_errors"), report.get("fatal_errors"))
                    self.assertEqual(report["summary"]["failed"], int(invalid))
                    report_path, impl_path = folder / "report.json", folder / "implementation.json"
                    args = argparse.Namespace(corpus_root=str(corpus), report=str(report_path), conformance_report_uri=str(report_path))
                    write(report_path, report)
                    write(impl_path, runner.make_implementation_report(args, report))
                    bundle = runner.verify_report_bundle(corpus, report_path, impl_path, folder / "sut.json")
                    self.assertEqual(bundle["status"], "fail" if invalid else "pass", bundle)
                    if invalid:
                        self.assertIn("sut_results.generated_artifacts.constraint", [row["name"] for row in bundle["checks"] if not row["pass"]])

    def test_cli_rejects_each_explicit_null(self):
        for field in VALID:
            folder, corpus = self.case(field, "null")
            for command in ("run", "compare"):
                with self.subTest(field=field, command=command):
                    args = [sys.executable, str(ROOT / "scripts/vate_conformance.py"), command,
                            "--corpus-root", str(corpus), "--report", str(folder / "cli-report.json")]
                    if command == "compare":
                        args += ["--sut-results", str(folder / "sut.json")]
                    done = subprocess.run(args, capture_output=True, text=True, timeout=30)
                    self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
                    self.assertEqual(done.stderr, "")

    def test_open_annotations_are_preserved(self):
        receipt = receipt_for("approval", "valid")
        constraints = receipt["attenuation"]["effective_constraints"]
        constraints["annotation"] = None
        constraints["approval"]["annotation"] = None
        constraints["max_amount"]["annotation"] = None
        before = copy.deepcopy(receipt)
        self.assertEqual(runner.attenuation_validation_failures(receipt["attenuation"]), [])
        self.assertEqual(runner.generated_admission_receipt_shape_failures(receipt, "receipt"), [])
        self.assertEqual(receipt, before)


if __name__ == "__main__":
    unittest.main()
