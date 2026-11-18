"""JSON type fidelity and exact amount limits at the public runner boundary."""
import argparse
import copy
from decimal import Decimal, DefaultContext, Inexact, localcontext
import hashlib
import json
from pathlib import Path
import subprocess
import shutil
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


class ConformanceBoundaryTests(unittest.TestCase):
    def test_projection_distinguishes_json_kinds_recursively(self):
        for expected, actual, equal in [(False, 0, False), (True, 1, False), (0, False, False),
                                         (1, True, False), (True, True, True), (False, False, True),
                                         (1, 1.0, True), (0, -0.0, True), ("1", 1, False), (None, 0, False)]:
            with self.subTest(expected=expected, actual=actual):
                self.assertEqual(not runner.semantic_projection_failures(
                    {"nested": [{"value": expected}]}, {"nested": [{"value": actual}]}, "receipt"), equal)

    def test_generated_receipts_compare_and_bundle_preserve_booleans(self):
        fixtures = [
            ("allow-ap2-hnp-preauthorized-mandate", "examples/interop/ap2-human-not-present-to-vate/vate-admission-receipt-ap2-hnp-valid.example.json",
             ["request", "constraints", "payment", "human_present"], False),
            ("allow-mcp-oauth-token-authority-bound", "examples/receipts/admission-allow-mcp-oauth-token-authority-bound.example.json",
             ["request", "transport", "oauth", "token_present"], True),
        ]
        for case_id, source, fields, expected in fixtures:
            for actual in (expected, int(expected), not expected):
                with self.subTest(case=case_id, actual=actual, kind=type(actual).__name__), tempfile.TemporaryDirectory() as folder:
                    folder = Path(folder)
                    artifact = read(ROOT / source)
                    target = artifact
                    for field in fields[:-1]:
                        target = target[field]
                    self.assertIs(target[fields[-1]], expected)
                    target[fields[-1]] = actual
                    receipt = folder / "receipt.json"
                    write(receipt, artifact)
                    sut = read(ROOT / "examples/conformance/sut-results-pass.example.json")
                    entry = next(row for row in sut["results"] if row["case_id"] == case_id)
                    entry["artifact_mode"] = "generated-receipts"
                    entry["generated_artifacts"] = {"admission_receipt": {
                        "uri": receipt.name, "media_type": "application/vate-admission-receipt+json",
                        "digest": {"alg": "sha-256", "value": hashlib.sha256(receipt.read_bytes()).hexdigest()}}}
                    result = folder / "sut.json"
                    report, implementation = folder / "report.json", folder / "implementation.json"
                    write(result, sut)
                    base = [sys.executable, str(ROOT / "scripts/vate_conformance.py")]
                    common = ["--corpus-root", str(CORPUS), "--sut-results", str(result)]
                    compared = subprocess.run(base + ["compare"] + common + ["--report", str(report),
                        "--implementation-report", str(implementation), "--conformance-report-uri", str(report),
                        "--implementation-report-uri", str(implementation)], capture_output=True, text=True, timeout=30)
                    valid = type(actual) is bool and actual is expected
                    self.assertEqual(compared.returncode, 0 if valid else 1, compared.stdout + compared.stderr)
                    selected = next(row for row in read(report)["cases"] if row["case_id"] == case_id)
                    self.assertEqual(selected["pass"], valid)
                    bundle = folder / "bundle.json"
                    checked = subprocess.run(base + ["verify-bundle"] + common + ["--conformance-report", str(report),
                        "--implementation-report", str(implementation), "--report", str(bundle)],
                        capture_output=True, text=True, timeout=30)
                    self.assertEqual(checked.returncode, 0 if valid else 1, checked.stdout + checked.stderr)

    def amount_failures(self, values, cap="25.00"):
        admission = {"decision": {"outcome": "allow"}, "request": {"constraints": {
            "max_amount": {"currency": "USD", "value": cap}}}}
        post = {"result": {"side_effects": [{"type": "payment_authorization", "amount": {
            "currency": "USD", "value": value}} for value in values]}}
        return list(runner.iter_post_execution_side_effect_failures(admission, post))

    def test_amounts_are_exact_under_ambient_precision_and_rounding(self):
        for precision in (3, 28, 100):
            with self.subTest(precision=precision), localcontext() as context:
                context.prec = precision
                context.traps[Inexact] = True
                self.assertEqual(self.amount_failures(["24.99", "0.01"]), [])
                self.assertEqual(self.amount_failures(["25.00", "0.000000000000000000000000000"]), [])
                for values in (["24.99", "0.02"], ["25.00", "0.000000000000000000000000001"],
                               ["0.000000000000000000000000001", "25.00"]):
                    self.assertEqual(self.amount_failures(values), ["side_effects aggregate amount exceeds admitted max_amount"])
                self.assertEqual(context.prec, precision)
                self.assertFalse(any(context.flags.values()))

    def test_explicit_context_preserves_large_amounts_and_default_settings(self):
        saved = DefaultContext.copy()
        try:
            DefaultContext.prec = 2
            DefaultContext.Emax = 2
            DefaultContext.Emin = -2
            DefaultContext.traps[Inexact] = True
            total = runner.add_decimal_amounts_exact(Decimal("9" * 80), Decimal("0." + "0" * 79 + "1"))
            self.assertEqual(str(total), "9" * 80 + "." + "0" * 79 + "1")
            self.assertEqual(DefaultContext.prec, 2)
            self.assertFalse(any(DefaultContext.flags.values()))
        finally:
            for name in ("prec", "rounding", "Emin", "Emax", "capitals", "clamp", "flags", "traps"):
                setattr(DefaultContext, name, getattr(saved, name))

    def test_ordinary_cli_detects_fine_decimal_excess(self):
        with tempfile.TemporaryDirectory(prefix="vate-amount-cli-") as directory:
            root = Path(directory)
            corpus = root / "corpus"
            (corpus / "cases").mkdir(parents=True)
            admission = read(ROOT / "examples/receipts/admission-attenuate-max-amount.example.json")
            admission.pop("attenuation")
            admission["decision"] = {"outcome": "allow", "reason_codes": ["EVIDENCE_VERIFIED", "POLICY_MATCH"]}
            admission["request"]["constraints"] = {"max_amount": {"currency": "USD", "value": "25.00"}}
            post = read(ROOT / "examples/receipts/post-execution-success.example.json")
            post["admission"].update(decision="allow", digest=runner.digest_descriptor(admission))
            post["execution"]["effective_request_hash"] = admission["request"]["input_hash"]
            post["result"]["policy_violations"] = []
            original_case = read(CORPUS / "cases/post-execution-linkage-success.json")
            original_case["artifact_reference_checks"] = [{"artifact": "admission_receipt", "expect_match": True,
                "reference_paths": [{"artifact": "post_execution_receipt", "path": "admission.digest"}]}]
            original_case["expected"]["admission_decision"] = "allow"
            original_case["expected"]["checks"] = [item for item in original_case["expected"]["checks"]
                                                   if not item["name"].startswith("a2a_metadata.")]
            for check in original_case["linkage_checks"]:
                if check["kind"] == "effective_request_hash":
                    check["admission_path"] = "request.input_hash"
            for name, values in [("at-cap", ["25.00"]), ("ordinary-excess", ["25.00", "0.01"]),
                                 ("fine-excess", ["25.00", "0.000000000000000000000000001"])]:
                post["result"]["side_effects"] = [{"type": "payment_authorization", "amount": {
                    "currency": "USD", "value": value}} for value in values]
                ap, pp = root / (name + "-admission.json"), root / (name + "-post.json")
                write(ap, admission)
                write(pp, post)
                case = copy.deepcopy(original_case)
                case["case_id"] = name
                case["artifacts"] = {"admission_receipt": str(ap), "post_execution_receipt": str(pp)}
                write(corpus / "cases" / (name + ".json"), case)
            report = root / "report.json"
            process = subprocess.run([sys.executable, str(ROOT / "scripts/vate_conformance.py"), "run",
                "--corpus-root", str(corpus), "--report", str(report)], capture_output=True, text=True, timeout=30)
            self.assertEqual(process.returncode, 1, process.stdout + process.stderr)
            output = read(report)
            self.assertEqual(output["summary"], {"total": 3, "passed": 1, "failed": 2, "skipped": 0})
            for case in output["cases"]:
                self.assertEqual(case["pass"], case["case_id"] == "at-cap", case)
                if not case["pass"]:
                    self.assertEqual(case["actual_reason_codes"], ["POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED"])


class ReceiptValueContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="vate-value-contract-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.corpus = self.folder / "corpus"
        (self.corpus / "cases").mkdir(parents=True)
        shutil.copyfile(CORPUS / "conformance-case.schema.json", self.corpus / "conformance-case.schema.json")
        self.admission = read(ROOT / "examples/receipts/admission-attenuate-max-amount.example.json")
        self.admission.pop("attenuation")
        self.admission["decision"] = {"outcome": "allow", "reason_codes": ["EVIDENCE_VERIFIED", "POLICY_MATCH"]}
        self.admission["request"]["constraints"] = {"max_amount": {"currency": "USD", "value": "25.00"}}
        self.admission["x_value"] = False
        self.post = read(ROOT / "examples/receipts/post-execution-success.example.json")
        self.post["admission"].update(decision="allow", digest=runner.digest_descriptor(self.admission))
        self.post["execution"]["effective_request_hash"] = self.admission["request"]["input_hash"]
        self.post["result"]["policy_violations"] = []
        self.post["result"]["side_effects"] = [{"type": "payment_authorization", "amount": {"currency": "USD", "value": 25.0}}]
        self.post["x_value"] = False
        self.case = read(CORPUS / "cases/post-execution-linkage-success.json")
        self.case["case_id"] = "value-contract"
        self.case["artifact_reference_checks"] = [{"artifact": "admission_receipt", "expect_match": True,
            "reference_paths": [{"artifact": "post_execution_receipt", "path": "admission.digest"}]}]
        self.case["expected"]["admission_decision"] = "allow"
        self.case["expected"]["checks"] = [row for row in self.case["expected"]["checks"] if not row["name"].startswith("a2a_metadata.")]
        for check in self.case["linkage_checks"]:
            if check["kind"] == "effective_request_hash":
                check["admission_path"] = "request.input_hash"
        self.case["linkage_checks"].append({"kind": "path_match", "admission_path": "x_value",
            "post_execution_path": "x_value", "expect_match": True, "reason_code": "POST_EXEC_LINKAGE_MISMATCH"})
        self.fixture_a, self.fixture_p = self.folder / "expected-a.json", self.folder / "expected-p.json"
        self.case["artifacts"] = {"admission_receipt": str(self.fixture_a), "post_execution_receipt": str(self.fixture_p)}
        self.save_fixture()

    def save_fixture(self):
        self.post["admission"]["digest"] = runner.digest_descriptor(self.admission)
        write(self.fixture_a, self.admission)
        write(self.fixture_p, self.post)
        write(self.corpus / "cases/value.json", self.case)
        write(self.corpus / "corpus.json", runner.make_corpus_index(self.corpus))

    def command(self, *args, success):
        process = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/vate_conformance.py"), *args],
                                 capture_output=True, text=True, timeout=30)
        self.assertNotIn("Traceback", process.stderr)
        details = process.stdout + process.stderr
        if process.returncode != (0 if success else 1) and "--report" in args:
            path = Path(args[args.index("--report") + 1])
            if path.exists():
                details += path.read_text()
        self.assertEqual(process.returncode, 0 if success else 1, details)

    def ref(self, path, kind):
        return {"uri": str(path), "media_type": "application/vate-" + kind + "+json",
                "digest": {"alg": "sha-256", "value": hashlib.sha256(path.read_bytes()).hexdigest()}}

    def generated(self, post, success, numeric_token=None):
        ap, pp = self.folder / "a.json", self.folder / "p.json"
        post = copy.deepcopy(post)
        post["admission"]["uri"] = ap.name
        write(ap, self.admission)
        if numeric_token is not None:
            post["result"]["side_effects"][0]["amount"]["value"] = "RAW_AMOUNT_TOKEN"
        write(pp, post)
        if numeric_token is not None:
            pp.write_text(pp.read_text().replace('"RAW_AMOUNT_TOKEN"', numeric_token))
        sut = {"version": runner.SUT_RESULTS_VERSION, "profile": runner.PROFILE,
            "generated_at": "2026-11-17T00:00:00Z", "artifact_mode": "generated-receipts",
            "implementation": {"name": "Value contract fixture", "type": "synthetic", "version": "1", "language": "Python", "x_value": False},
            "corpus": {"profile": runner.PROFILE, "digest": runner.corpus_manifest(self.corpus)[1]},
            "results": [{"case_id": self.case["case_id"], "status": "completed", "outcome": "success",
                "should_execute": True, "reason_codes": self.case["expected"]["reason_codes"],
                "checks": [{"name": row["name"], "pass": True} for row in self.case["expected"]["checks"]],
                "artifacts": {"admission_receipt": self.ref(self.fixture_a, "admission-receipt"),
                              "post_execution_receipt": self.ref(self.fixture_p, "post-execution-receipt")},
                "generated_artifacts": {"admission_receipt": {**self.ref(ap, "admission-receipt"), "uri": ap.name},
                                        "post_execution_receipt": {**self.ref(pp, "post-execution-receipt"), "uri": pp.name}}}]}
        write(self.folder / "sut.json", sut)
        report, impl = self.folder / "report.json", self.folder / "implementation.json"
        self.command("compare", "--corpus-root", str(self.corpus), "--sut-results", str(self.folder / "sut.json"),
                     "--report", str(report), "--implementation-report", str(impl),
                     "--conformance-report-uri", str(report), success=success)
        self.bundle(success)
        return read(report)

    def bundle(self, success):
        self.command("verify-bundle", "--corpus-root", str(self.corpus), "--sut-results", str(self.folder / "sut.json"),
            "--conformance-report", str(self.folder / "report.json"), "--implementation-report", str(self.folder / "implementation.json"),
            "--report", str(self.folder / "bundle.json"), success=success)

    def test_raw_number_precision_and_unchanged_fixture_basis(self):
        for token in ["0.1", "25.0", "25.000000000000000000", "2.5e1", "1e-27", "-0.0", "1.2345678901234567"]:
            with self.subTest(token=token):
                parsed = runner.strict_json_loads(token)
                self.assertEqual(Decimal(token), Decimal(str(parsed)))
                self.assertEqual(runner.canonical_bytes(parsed), json.dumps(json.loads(token), separators=(",", ":")).encode())
        for token in ["25.000000000000000001", "9007199254740993.0", "1e-400", "-1e-400", "0.10000000000000001"]:
            with self.subTest(token=token), self.assertRaisesRegex(ValueError, "loses decimal precision"):
                runner.strict_json_loads('{"nested":[' + token + ']}')
        with localcontext() as context:
            context.clear_flags()
            with self.assertRaisesRegex(ValueError, "supported decimal range"):
                runner.strict_json_loads("1e-999999999999999999999999999")
            self.assertFalse(any(context.flags.values()))

    def test_numeric_amount_run_compare_bundle(self):
        for token, success, diagnostic in [
            ("25.0", True, None),
            ("25.000000000000000000", True, None),
            ("25.000000000000000001", False, "loses decimal precision"),
            ("25.01", False, None),
        ]:
            with self.subTest(token=token):
                report = self.generated(self.post, success, numeric_token=token)
                if diagnostic is not None:
                    self.assertIn(diagnostic, str(report["cases"][0]["failures"]))
                # Exercise raw corpus artifact loading as well as external SUT loading.
                self.fixture_p.write_bytes((self.folder / "p.json").read_bytes())
                self.command("run", "--corpus-root", str(self.corpus), "--report", str(self.folder / "run.json"), success=success)
                self.save_fixture()

    def test_path_match_preserves_types_and_numeric_equivalence(self):
        for left, right, success in [(False, False, True), (False, 0, False), (True, 1, False),
                                     ({"nested": [True]}, {"nested": [1]}, False), (1, 1.0, True)]:
            with self.subTest(left=left, right=right):
                self.admission["x_value"] = left
                self.post["x_value"] = left
                self.save_fixture()
                changed = copy.deepcopy(self.post)
                changed["x_value"] = right
                self.generated(changed, success)
                write(self.fixture_p, changed)
                self.command("run", "--corpus-root", str(self.corpus), "--report", str(self.folder / "run.json"), success=success)

    def test_digest_annotations_and_real_mismatch_across_paths(self):
        for mismatch in (False, True):
            with self.subTest(mismatch=mismatch):
                post = copy.deepcopy(self.post)
                post["admission"]["digest"]["x_note"] = {"text": "allowed annotation"}
                if mismatch:
                    post["admission"]["digest"]["value"] = "0" * 64
                self.generated(post, not mismatch)
                write(self.fixture_p, post)
                self.command("run", "--corpus-root", str(self.corpus), "--report", str(self.folder / "run.json"), success=not mismatch)
                self.save_fixture()

    def test_report_metadata_type_difference_with_repaired_digest(self):
        baseline = self.generated(self.post, True)
        for value, success in [(False, True), (0, False), (True, False)]:
            with self.subTest(value=value):
                report = copy.deepcopy(baseline)
                report["sut_results"]["implementation"]["x_value"] = value
                path = self.folder / "report.json"
                write(path, report)
                args = argparse.Namespace(corpus_root=str(self.corpus), conformance_report_uri=str(path), report=str(path))
                write(self.folder / "implementation.json", runner.make_implementation_report(args, report))
                self.bundle(success)
                if not success:
                    failed = [row["name"] for row in read(self.folder / "bundle.json")["checks"] if not row["pass"]]
                    self.assertIn("conformance_report.sut_results.implementation", failed)


if __name__ == "__main__":
    unittest.main()
