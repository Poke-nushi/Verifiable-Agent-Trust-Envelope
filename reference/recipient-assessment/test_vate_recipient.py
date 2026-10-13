"""Wrapper integration regressions; native semantics remain in their own suites."""
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import multiprocessing
import os
from pathlib import Path
import pickle
import py_compile
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
import unicodedata
from unittest.mock import patch

import vate_recipient as api
from run_vectors import run_vectors, verify_result

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RECEIPTS = ROOT / "reference/receipt-linkage-example"
INSTANCE = ROOT / "reference/s3-observation-example/inputs/seaweedfs-4.48/instance"


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def import_api(path):
    spec = importlib.util.spec_from_file_location("_recipient_test_copy", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def copy_tree(root, *, wrapper=False):
    sources = json.loads((HERE / "EVALUATOR-SOURCES.json").read_bytes())["s3_observation"]["source_files"]
    for relative in sources:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    if wrapper:
        destination = root / "reference/recipient-assessment"
        destination.mkdir(parents=True)
        for name in ("vate_recipient.py", "_worker.py", "EVALUATOR-SOURCES.json"):
            shutil.copyfile(HERE / name, destination / name)
    return sources


def synthetic_target_mismatch(folder):
    """Change only the GET target meaning; keep its raw references well formed."""
    shutil.copytree(INSTANCE / "bundles/supported", folder)
    request_path = folder / "get-request.json"
    request = json.loads(request_path.read_bytes())
    request["key"] = "synthetic-other-key"
    raw = encoded(request)
    request_path.write_bytes(raw)
    transport_path = folder / "get-transport.json"
    transport = json.loads(transport_path.read_bytes())
    transport["request_ref"] = {"path": "get-request.json", "byte_length": len(raw),
                                "digest": {"alg": "sha-256", "value": hashlib.sha256(raw).hexdigest()}}
    transport_path.write_bytes(encoded(transport))
    manifest_path = folder / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    for name in ("get-request.json", "get-transport.json"):
        raw = (folder / name).read_bytes()
        manifest["artifacts"][name] = {"byte_length": len(raw),
                                       "digest": {"alg": "sha-256", "value": hashlib.sha256(raw).hexdigest()}}
    manifest_path.write_bytes(encoded(manifest))
    return folder


def replace_bundle_member(folder, name, value):
    """Rebind one synthetic member in a disposable bundle's existing manifest."""
    raw = encoded(value)
    (folder / name).write_bytes(raw)
    manifest_path = folder / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["artifacts"][name] = {"byte_length": len(raw),
                                   "digest": {"alg": "sha-256", "value": hashlib.sha256(raw).hexdigest()}}
    manifest_path.write_bytes(encoded(manifest))


def unknown_check_in_process():
    api.RecipientAssessor(expected_api_contract=api.API_CONTRACT).assess_receipts(
        None, None, requested_checks=["unknown-check"])


class RecipientAssessorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admission = (RECEIPTS / "inputs/R17/admission.json").read_bytes()
        cls.post = (RECEIPTS / "inputs/R17/post.json").read_bytes()
        cls.policy = (INSTANCE / "receiver-policy.json").read_bytes()
        cls.expected_receipt = json.loads((RECEIPTS / "expected-results.json").read_bytes())["examples"][0]["assessment"]
        cls.expected_s3 = json.loads((INSTANCE / "ASSESSMENTS.json").read_bytes())["supported"]

    def setUp(self):
        self.assessor = api.RecipientAssessor(expected_api_contract=api.API_CONTRACT)

    def assert_error(self, code, function, *args, **kwargs):
        with self.assertRaises(api.AssessmentError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        error = caught.exception.as_dict()
        self.assertEqual(error["api_contract"], api.API_CONTRACT)
        self.assertEqual(error["invocation"], {"status": "error"})
        self.assertNotIn("native_result", error)

    def test_shared_vectors_include_eight_complete_native_results(self):
        result = run_vectors()
        self.assertEqual(len(result["vectors"]), 13)
        self.assertTrue(all(v["verification"] == "matched" for v in result["vectors"]), result)

    def test_vector_comparisons_keep_json_types_and_reason_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for expected, actual in ((True, 1), (False, 0), (1, 1.0), (["A", "B"], ["B", "A"])):
                raw = encoded({"value": expected})
                (root / "expected.json").write_bytes(raw)
                reference = {"path": "expected.json", "raw_sha256": hashlib.sha256(raw).hexdigest(),
                             "byte_length": len(raw), "value_path": []}
                for assertion in ({"native_result_ref": reference},
                                  {"native_values": [{"path": ["value"], "value": expected}]}):
                    vector = {"expected": assertion}
                    result = {"native_result": {"value": actual}, "requested_checks": {"unsupported": []}}
                    with self.subTest(expected=expected, actual=actual, assertion=assertion), self.assertRaises(AssertionError):
                        verify_result(root, vector, result)
                    result["native_result"]["value"] = expected
                    verify_result(root, vector, result)

    def test_assessment_error_pickle_roundtrip_preserves_public_fields(self):
        original = api.AssessmentError("UNKNOWN_CHECK", "synthetic check")
        original.context = "synthetic caller metadata"
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=protocol):
                copied = pickle.loads(pickle.dumps(original, protocol=protocol))
                self.assertIs(type(copied), api.AssessmentError)
                self.assertIsNot(copied, original)
                self.assertEqual(copied.args, ("UNKNOWN_CHECK: synthetic check",))
                self.assertEqual(str(copied), str(original))
                self.assertEqual(copied.code, original.code)
                self.assertEqual(copied.detail, original.detail)
                self.assertEqual(copied.as_dict(), original.as_dict())
                self.assertEqual(copied.context, original.context)

    def test_assessment_error_survives_process_pool_transfer(self):
        with ProcessPoolExecutor(max_workers=1, mp_context=multiprocessing.get_context("spawn")) as pool:
            future = pool.submit(unknown_check_in_process)
            self.assert_error("UNKNOWN_CHECK", future.result, timeout=10)

    def test_cli_compact_output_preserves_deep_native_diagnostics(self):
        command = [sys.executable, "-I", "-B", str(HERE / "vate_recipient.py"),
                   "--api-contract", api.API_CONTRACT, "s3",
                   "--receiver-policy", str(INSTANCE / "receiver-policy.json")]
        for depth in (40, 160):
            with self.subTest(depth=depth), tempfile.TemporaryDirectory() as directory:
                bundle = Path(directory) / "bundle"
                shutil.copytree(INSTANCE / "bundles/supported", bundle)
                transport = json.loads((bundle / "get-transport.json").read_bytes())
                nested = json.loads("[" * depth + "]" * depth)
                transport["invocation_error"] = nested
                replace_bundle_member(bundle, "get-transport.json", transport)
                expected = self.assessor.assess_s3(bundle, self.policy)
                self.assertEqual(expected["native_result"]["assessment"], "insufficient")
                detail = next(d["detail"] for d in expected["native_result"]["diagnostics"]
                              if d["code"] == "GET_UNUSABLE_RESPONSE")
                self.assertEqual(encoded(detail["invocation_error"]), encoded(nested))
                cli = subprocess.run(command + ["--bundle", str(bundle)], capture_output=True, timeout=10, check=False)
                self.assertEqual(cli.returncode, 2, cli.stderr)
                self.assertEqual(cli.stderr, b"")
                self.assertEqual(encoded(json.loads(cli.stdout)), encoded(expected))
                # Allow only the platform line ending beyond compact JSON.
                self.assertLessEqual(len(cli.stdout), len(encoded(expected)) + 2)

    def test_cli_encoding_errors_are_structured_without_native_verdict(self):
        result = {"native_result": {"record_linkage": "not_assessed"},
                  "requested_checks": {"unsupported": []}}
        actual_dumps = json.dumps
        for failure in (ValueError("synthetic invalid JSON value"), RecursionError("synthetic encoding depth")):
            def failing_result(value, *args, **kwargs):
                if value is result:
                    raise failure
                return actual_dumps(value, *args, **kwargs)
            with self.subTest(error=type(failure).__name__), patch.object(api.RecipientAssessor, "assess_receipts", return_value=result):
                stdout = io.StringIO()
                with patch.object(api.json, "dumps", side_effect=failing_result), redirect_stdout(stdout):
                    code = api.main(["--api-contract", api.API_CONTRACT, "receipts"])
                self.assertEqual(code, 64)
                error = json.loads(stdout.getvalue())
                self.assertEqual(error["api_contract"], api.API_CONTRACT)
                self.assertEqual(error["invocation"], {"status": "error"})
                self.assertEqual(error["error"]["code"], "WORKER_PROTOCOL_ERROR")
                self.assertNotIn("native_result", error)

    def test_manifest_drift_after_import_precedes_native_checks(self):
        manifest = HERE / "EVALUATOR-SOURCES.json"
        actual_read = Path.read_bytes
        def changed_read(path):
            raw = actual_read(path)
            return raw + b"\n" if path == manifest else raw
        calls = ((self.assessor.capabilities, ()),
                 (self.assessor.assess_receipts, (self.admission, self.post)),
                 (self.assessor.assess_s3, (INSTANCE / "bundles/supported", self.policy)))
        with patch.object(Path, "read_bytes", changed_read), patch.object(api.subprocess, "run") as run:
            for call, args in calls:
                with self.subTest(call=call.__name__):
                    self.assert_error("WRAPPER_SOURCE_CHANGED", call, *args)
            run.assert_not_called()

    def test_manifest_drift_during_invocation_precedes_native_checks(self):
        manifest = HERE / "EVALUATOR-SOURCES.json"
        actual_read = Path.read_bytes
        calls = (("receipt_pair", self.assessor.assess_receipts, (self.admission, self.post), self.expected_receipt),
                 ("s3_observation", self.assessor.assess_s3, (INSTANCE / "bundles/supported", self.policy), self.expected_s3))
        for evaluator, call, args, native in calls:
            response = encoded({"native_result": native, "evaluator": api._native_identity(ROOT, evaluator)})
            error = encoded({"error": {"code": "SOURCE_MANIFEST_ERROR", "detail": "fixed evaluator manifest changed"}})
            replies = (("native_result", 0, response), ("worker_error", 0, error), ("worker_exit", 7, b""))
            for label, returncode, stdout in replies:
                returned = False
                def changed_read(path):
                    raw = actual_read(path)
                    return raw + b"\n" if returned and path == manifest else raw
                def returning_worker(*args, **kwargs):
                    nonlocal returned
                    returned = True
                    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=b"")
                with self.subTest(evaluator=evaluator, reply=label), patch.object(Path, "read_bytes", changed_read):
                    with patch.object(api.subprocess, "run", side_effect=returning_worker) as run:
                        self.assert_error("WRAPPER_SOURCE_CHANGED", call, *args)
                        run.assert_called_once()

    def test_s3_fractional_timestamp_width_preserves_runtime_boundary(self):
        command = [sys.executable, "-I", "-B", str(HERE / "vate_recipient.py"),
                   "--api-contract", api.API_CONTRACT, "s3",
                   "--receiver-policy", str(INSTANCE / "receiver-policy.json")]
        for digits in range(1, 8):
            with self.subTest(digits=digits), tempfile.TemporaryDirectory() as directory:
                bundle = Path(directory) / "bundle"
                shutil.copytree(INSTANCE / "bundles/supported", bundle)
                post = json.loads((bundle / "post.json").read_bytes())
                post["issued_at"] = "2026-10-12T13:12:33." + "9" + "0" * (digits - 1) + "Z"
                replace_bundle_member(bundle, "post.json", post)
                # The pinned native parser remains unchanged: Python 3.10 only
                # accepts 3/6 fractional digits; its regex always rejects 7.
                supported = digits <= 6 and (sys.version_info[:2] != (3, 10) or digits in (3, 6))
                expected_status = "supported_under_local_assumptions" if supported else "insufficient"
                result = self.assessor.assess_s3(bundle, self.policy)
                native = result["native_result"]
                self.assertEqual(native["record_linkage"], "matched" if digits <= 6 else "not_assessed")
                self.assertEqual(native["assessment"], expected_status)
                self.assertEqual(native["post_observation_binding"], "matched" if supported else "not_assessed")
                expected_codes = [] if supported else ["POST_OBSERVATION_NOT_ASSESSED"]
                if digits == 7:
                    expected_codes.insert(0, "RECEIPT_NOT_ASSESSED")
                self.assertEqual([d["code"] for d in native["diagnostics"]],
                                 expected_codes)
                cli = subprocess.run(command + ["--bundle", str(bundle)], capture_output=True, timeout=10, check=False)
                self.assertEqual(cli.returncode, 0 if supported else 2, cli.stderr)
                self.assertEqual(cli.stderr, b"")
                self.assertEqual(encoded(json.loads(cli.stdout)), encoded(result))

    def test_receipt_original_bytes_and_missing_are_not_normalized(self):
        reformatted = b" \n" + self.admission + b"\n "
        result = self.assessor.assess_receipts(reformatted, self.post)
        self.assertEqual(result["native_result"]["record_linkage"], "matched")
        digest = hashlib.sha256(reformatted).hexdigest()
        self.assertEqual(result["inputs"]["admission"]["raw_sha256"], digest)
        self.assertEqual(result["native_result"]["inputs"]["admission"]["raw_file_sha256"], digest)
        self.assertNotEqual(digest, self.expected_receipt["inputs"]["admission"]["raw_file_sha256"])
        missing = self.assessor.assess_receipts(self.admission, None)
        empty = self.assessor.assess_receipts(self.admission, b"")
        self.assertEqual(missing["invocation"]["status"], "returned")
        self.assertEqual(missing["native_result"]["linkage_checks_run"], [])
        self.assertEqual(missing["native_result"]["input_issues"], [{"input": "post", "kind": "not_supplied"}])
        self.assertIsNone(missing["inputs"]["post"]["raw_sha256"])
        self.assertEqual(empty["inputs"]["post"]["raw_sha256"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(empty["native_result"]["input_issues"][0]["kind"], "invalid_input")

    def test_unknown_contract_checks_and_bad_api_inputs_do_not_invoke(self):
        with patch.object(api.subprocess, "run") as run:
            self.assert_error("UNKNOWN_API_CONTRACT", api.RecipientAssessor, expected_api_contract="next-api")
            self.assert_error("UNKNOWN_CHECK", self.assessor.assess_receipts, self.admission, self.post,
                              requested_checks=["receipt_linkgae"])
            self.assert_error("INVALID_CHECK_REQUEST", self.assessor.assess_receipts, self.admission, self.post,
                              requested_checks=["receipt_linkage", "receipt_linkage"])
            self.assert_error("INPUT_TYPE_ERROR", self.assessor.assess_receipts, {}, self.post)
            self.assert_error("INPUT_TYPE_ERROR", self.assessor.assess_receipts, bytearray(self.admission), self.post)
            self.assert_error("INPUT_TYPE_ERROR", self.assessor.assess_s3, INSTANCE, {})
            self.assert_error("INPUT_TYPE_ERROR", self.assessor.assess_s3, None, self.policy)
            self.assert_error("INPUT_SIZE_ERROR", self.assessor.assess_receipts, b"x" * (1024 * 1024 + 1), self.post)
            self.assert_error("INPUT_SIZE_ERROR", self.assessor.assess_s3, INSTANCE, b"x" * (256 * 1024 + 1))
            for timeout in (0, -1, float("inf"), float("nan"), True, "1", 10**400, 10**1000, -(10**1000)):
                self.assert_error("INVALID_CONFIGURATION", api.RecipientAssessor,
                                  expected_api_contract=api.API_CONTRACT, timeout_seconds=timeout)
            run.assert_not_called()

    def test_unsupported_requests_are_not_inferred_as_satisfied(self):
        requested = ["receipt_linkage", "signatures_and_issuer_authority", "operation_population_coverage"]
        result = self.assessor.assess_receipts(self.admission, self.post, requested_checks=requested)
        self.assertEqual(result["native_result"], self.expected_receipt)
        self.assertEqual(result["requested_checks"], {"requested": requested, "supported": ["receipt_linkage"],
                                                    "unsupported": requested[1:]})
        self.assertNotIn("checks_performed", result)
        self.assertNotIn("pass", result)
        caps = self.assessor.capabilities()
        caps["evaluators"]["receipt_pair"]["supported_checks"].clear()
        self.assertEqual(self.assessor.capabilities()["evaluators"]["receipt_pair"]["supported_checks"], ["receipt_linkage"])

    def test_capabilities_report_complete_supported_and_unsupported_tables(self):
        expected = {
            "receipt_pair": {
                "supported_checks": ["receipt_linkage"],
                "unsupported_checks": ["s3_observation_binding", "signatures_and_issuer_authority",
                                       "independent_execution_observation", "operation_population_coverage",
                                       "current_permission_to_execute"],
            },
            "s3_observation": {
                "supported_checks": ["receipt_linkage", "s3_observation_binding"],
                "unsupported_checks": ["signatures_and_issuer_authority", "independent_execution_observation",
                                       "operation_population_coverage", "current_permission_to_execute"],
            },
        }
        self.assertEqual(self.assessor.capabilities()["evaluators"], expected)
        requested = ["receipt_linkage", "s3_observation_binding", "signatures_and_issuer_authority",
                     "independent_execution_observation", "operation_population_coverage", "current_permission_to_execute"]
        receipt = self.assessor.assess_receipts(self.admission, self.post, requested_checks=requested)
        s3 = self.assessor.assess_s3(INSTANCE / "bundles/supported", self.policy, requested_checks=requested)
        for name, result in (("receipt_pair", receipt), ("s3_observation", s3)):
            self.assertEqual(result["requested_checks"], {
                "requested": requested, "supported": expected[name]["supported_checks"],
                "unsupported": expected[name]["unsupported_checks"],
            })
        self.assertEqual(receipt["native_result"], self.expected_receipt)
        self.assertEqual(s3["native_result"], self.expected_s3)

    def test_input_byte_lengths_describe_the_original_bytes(self):
        admission, post, policy = b" \n" + self.admission, self.post + b"\n", self.policy + b" \n"
        result = self.assessor.assess_receipts(admission, post)
        for name, raw in (("admission", admission), ("post", post)):
            self.assertEqual(result["inputs"][name]["byte_length"], len(raw))
        result = self.assessor.assess_s3(INSTANCE / "bundles/supported", policy)
        self.assertEqual(result["inputs"]["receiver_policy"]["byte_length"], len(policy))
        # Invalid evidence still has an exact supplied-byte length. Use non-ASCII
        # JSON to distinguish bytes from decoded character counts, and None from empty.
        unicode_raw = json.dumps({"note": "受領"}, ensure_ascii=False).encode("utf-8")
        self.assertNotEqual(len(unicode_raw), len(unicode_raw.decode("utf-8")))
        for raw in (unicode_raw, b""):
            result = self.assessor.assess_receipts(raw, None)
            self.assertEqual(result["inputs"]["admission"]["byte_length"], len(raw))
            self.assertIsNone(result["inputs"]["post"]["byte_length"])

    def test_subprocess_timeout_overflow_is_configuration_error_for_api_and_cli(self):
        with patch.object(api.subprocess, "run", side_effect=OverflowError("synthetic polling range overflow")):
            self.assert_error("INVALID_CONFIGURATION", self.assessor.assess_receipts, self.admission, self.post)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = api.main(["--api-contract", api.API_CONTRACT, "--timeout", "1e10", "receipts"])
            self.assertEqual(code, 64)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["invocation"], {"status": "error"})
            self.assertEqual(result["error"]["code"], "INVALID_CONFIGURATION")
            self.assertNotIn("native_result", result)

    def test_worker_ignores_caller_pythonpath(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "jsonschema.py").write_text('raise ImportError("synthetic caller PYTHONPATH module")\n')
            with patch.dict(os.environ, {"PYTHONPATH": directory}):
                result = self.assessor.assess_receipts(self.admission, self.post)
            self.assertEqual(result["native_result"], self.expected_receipt)

    def test_missing_python_executable_is_structured_for_api_and_cli(self):
        calls = ((self.assessor.assess_receipts, (self.admission, self.post), ["receipts"]),
                 (self.assessor.assess_s3, (INSTANCE / "bundles/supported", self.policy),
                  ["s3", "--bundle", str(INSTANCE / "bundles/supported"),
                   "--receiver-policy", str(INSTANCE / "receiver-policy.json")]))
        for executable in (None, ""):
            for call, arguments, command in calls:
                with self.subTest(executable=executable, command=command[0]):
                    with patch.object(api.sys, "executable", executable), patch.object(api.subprocess, "run") as run:
                        self.assert_error("WORKER_START_FAILED", call, *arguments)
                        stdout = io.StringIO()
                        with redirect_stdout(stdout):
                            code = api.main(["--api-contract", api.API_CONTRACT, *command])
                        self.assertEqual(code, 64)
                        result = json.loads(stdout.getvalue())
                        self.assertEqual(result["error"]["code"], "WORKER_START_FAILED")
                        self.assertEqual(result["invocation"], {"status": "error"})
                        self.assertNotIn("native_result", result)
                        run.assert_not_called()

    def test_cli_policy_paths_must_resolve_outside_bundle(self):
        command = [sys.executable, "-I", "-B", str(HERE / "vate_recipient.py"), "--api-contract", api.API_CONTRACT, "s3"]
        bundle = INSTANCE / "bundles/supported"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inside = bundle / "permit.json"
            policy_link = root / "policy-link.json"
            policy_link.symlink_to(inside)
            bundle_link = root / "bundle-link"
            bundle_link.symlink_to(bundle, target_is_directory=True)
            for selected_bundle, selected_policy in ((bundle, inside), (bundle, policy_link),
                                                     (bundle_link, inside), (bundle_link, policy_link)):
                result = subprocess.run(command + ["--bundle", str(selected_bundle), "--receiver-policy", str(selected_policy)],
                                        text=True, capture_output=True, check=False)
                self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
                error = json.loads(result.stdout)
                self.assertEqual(error["error"]["code"], "INVALID_CONFIGURATION")
                self.assertNotIn("native_result", error)
            outside_link = root / "outside-policy.json"
            outside_link.symlink_to(INSTANCE / "receiver-policy.json")
            result = subprocess.run(command + ["--bundle", str(bundle), "--receiver-policy", str(outside_link)],
                                    text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)["native_result"], self.expected_s3)
            # Resolving paths for the placement guard must not resolve away the
            # native Bundle no-follow check on the actual selected bundle path.
            result = subprocess.run(command + ["--bundle", str(bundle_link), "--receiver-policy", str(outside_link)],
                                    text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            native = json.loads(result.stdout)["native_result"]
            self.assertEqual(native["assessment"], "insufficient")
            self.assertEqual(native["diagnostics"][0]["code"], "BUNDLE_INVALID")

    def test_cli_policy_filesystem_aliases_are_rejected(self):
        command = [sys.executable, "-I", "-B", str(HERE / "vate_recipient.py"), "--api-contract", api.API_CONTRACT, "s3"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = []
            for name, alias_name in (("Bundle", "bundle"), ("Caf\u00e9", unicodedata.normalize("NFD", "Caf\u00e9"))):
                bundle, alias = root / name, root / alias_name
                (bundle / "nested").mkdir(parents=True)
                inside = bundle / "nested/policy.json"
                inside.write_bytes(self.policy)
                if alias.exists() and alias.samefile(bundle):
                    cases.extend(((bundle, alias / "nested/policy.json"), (alias, inside)))
            if not cases:
                self.skipTest("filesystem does not expose case or Unicode directory aliases")
            for bundle, policy in cases:
                with self.subTest(bundle=bundle, policy=policy):
                    result = subprocess.run(command + ["--bundle", str(bundle), "--receiver-policy", str(policy)],
                                            text=True, capture_output=True, check=False)
                    self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
                    self.assertEqual(result.stderr, "")
                    error = json.loads(result.stdout)
                    self.assertEqual(error["error"]["code"], "INVALID_CONFIGURATION")
                    self.assertNotIn("native_result", error)

    def test_cli_policy_alias_identity_and_stat_errors_stop_before_evaluation(self):
        # Exercise actual-location handling even on case-sensitive CI filesystems.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            bundle, outside = root / "bundle", root / "outside"
            bundle.mkdir()
            outside.mkdir()
            policy = outside / "policy.json"
            policy.write_bytes(self.policy)
            actual_stat, bundle_stat = Path.stat, bundle.stat()
            for failed in (False, True):
                def local_stat(path, *args, **kwargs):
                    if path == outside:
                        if failed:
                            raise PermissionError("synthetic policy location unavailable")
                        return bundle_stat
                    return actual_stat(path, *args, **kwargs)
                with self.subTest(stat_error=failed):
                    with patch.object(api.Path, "stat", local_stat), patch.object(api.subprocess, "run") as run:
                        stdout = io.StringIO()
                        with redirect_stdout(stdout):
                            code = api.main(["--api-contract", api.API_CONTRACT, "s3", "--bundle", str(bundle),
                                             "--receiver-policy", str(policy)])
                        self.assertEqual(code, 64)
                        error = json.loads(stdout.getvalue())
                        self.assertEqual(error["error"]["code"], "INVALID_CONFIGURATION")
                        self.assertNotIn("native_result", error)
                        run.assert_not_called()

    def test_cli_policy_location_check_preserves_missing_and_distinct_paths(self):
        command = [sys.executable, "-I", "-B", str(HERE / "vate_recipient.py"), "--api-contract", api.API_CONTRACT, "s3"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "Bundle"
            shutil.copytree(INSTANCE / "bundles/supported", bundle)
            sibling = root / "Bundle-sibling"
            sibling.mkdir()
            policy = sibling / "policy.json"
            policy.write_bytes(self.policy)
            cases = [(bundle, policy, 0), (root / "missing-bundle", policy, 2),
                     (bundle, root / "missing-parent/policy.json", 64)]
            distinct_case = root / "bundle"
            if not distinct_case.exists():
                distinct_case.mkdir()
                (distinct_case / "policy.json").write_bytes(self.policy)
                cases.append((bundle, distinct_case / "policy.json", 0))
            for selected_bundle, selected_policy, expected in cases:
                with self.subTest(bundle=selected_bundle, policy=selected_policy):
                    result = subprocess.run(command + ["--bundle", str(selected_bundle), "--receiver-policy", str(selected_policy)],
                                            text=True, capture_output=True, check=False)
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    parsed = json.loads(result.stdout)
                    if expected == 64:
                        self.assertEqual(parsed["error"]["code"], "INPUT_FILE_ERROR")
                    else:
                        self.assertEqual(parsed["native_result"]["assessment"],
                                         "supported_under_local_assumptions" if expected == 0 else "insufficient")

    def test_s3_cli_statuses_and_unsupported_request_priority(self):
        command = [sys.executable, "-I", "-B", str(HERE / "vate_recipient.py"), "--api-contract", api.API_CONTRACT, "s3",
                   "--receiver-policy", str(INSTANCE / "receiver-policy.json")]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contradictory = synthetic_target_mismatch(root / "contradictory")
            unsupported = root / "unsupported"
            unsupported.mkdir()
            (unsupported / "manifest.json").write_bytes(encoded({"contract": "future-contract", "artifacts": {}}))
            cases = ((INSTANCE / "bundles/supported", 0, "supported_under_local_assumptions"),
                     (contradictory, 1, "contradictory"),
                     (INSTANCE / "bundles/actual-403", 2, "insufficient"),
                     (unsupported, 3, "unsupported"))
            results = {}
            for bundle, code, verdict in cases:
                result = subprocess.run(command + ["--bundle", str(bundle)], text=True, capture_output=True, check=False)
                self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                parsed = json.loads(result.stdout)
                self.assertEqual(parsed["invocation"], {"status": "returned"})
                self.assertEqual(parsed["native_result"]["assessment"], verdict)
                results[verdict] = parsed["native_result"]
            self.assertEqual(results["supported_under_local_assumptions"], self.expected_s3)
            self.assertEqual(results["insufficient"], json.loads((INSTANCE / "ASSESSMENTS.json").read_bytes())["actual-403"])
            native = results["contradictory"]
            self.assertEqual([d["code"] for d in native["diagnostics"]],
                             ["GET_TARGET_MISMATCH", "PUT_GET_VERSION_TARGET_MISMATCH", "POST_OBSERVATION_NOT_ASSESSED"])
            self.assertEqual(native["record_linkage"], "matched")
            self.assertEqual(native["target_observation"], "mismatch")
            result = subprocess.run(command + ["--bundle", str(contradictory), "--check", "signatures_and_issuer_authority"],
                                    text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
            parsed = json.loads(result.stdout)
            self.assertEqual(parsed["native_result"], native)
            self.assertEqual(parsed["requested_checks"]["unsupported"], ["signatures_and_issuer_authority"])

    def test_policy_decode_failure_is_distinct_from_native_trust_verdict(self):
        for policy in (b"", b"[]", b'{"x":1.0}', b'{"x":1,"x":2}', b'{"x":9007199254740992}'):
            with self.subTest(policy=policy):
                self.assert_error("POLICY_INVALID", self.assessor.assess_s3, INSTANCE / "bundles/supported", policy)
        result = self.assessor.assess_s3(INSTANCE / "bundles/supported", b"{}")
        self.assertEqual(result["invocation"]["status"], "returned")
        self.assertEqual(result["native_result"]["source_trust"], "unverified")
        self.assertEqual(result["native_result"]["assessment"], "insufficient")
        self.assertEqual(result["inputs"]["receiver_policy"]["raw_sha256"], hashlib.sha256(b"{}").hexdigest())

    def test_native_unknown_profile_and_contract_are_preserved(self):
        admission = json.loads(self.admission)
        admission["profile"] = "future-profile"
        result = self.assessor.assess_receipts(encoded(admission), self.post)
        self.assertEqual(result["native_result"]["record_linkage"], "not_assessed")
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "unknown"
            bundle.mkdir()
            (bundle / "manifest.json").write_bytes(encoded({"contract": "future-contract", "artifacts": {}}))
            result = self.assessor.assess_s3(bundle, self.policy)
            self.assertEqual(result["native_result"]["assessment"], "unsupported")
            self.assertEqual(result["native_result"]["diagnostics"][0]["code"], "UNKNOWN_BUNDLE_CONTRACT")
        policy = json.loads(self.policy)
        policy["contract"] = "future-policy"
        result = self.assessor.assess_s3(INSTANCE / "bundles/supported", encoded(policy))
        self.assertEqual(result["native_result"]["assessment"], "unsupported")

    def test_bundle_path_retains_native_no_follow_and_inventory_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "linked-bundle"
            link.symlink_to(INSTANCE / "bundles/supported", target_is_directory=True)
            result = self.assessor.assess_s3(link, self.policy)
            self.assertEqual(result["inputs"]["bundle"], {"selected_path": str(link)})
            self.assertEqual(result["native_result"]["assessment"], "insufficient")
            self.assertEqual(result["native_result"]["diagnostics"][0]["code"], "BUNDLE_INVALID")

    def test_native_symlink_check_os_errors_are_structured_for_api_and_cli(self):
        calls = (
            ("receipts", self.assessor.assess_receipts, (self.admission, self.post),
             ["receipts", "--admission", str(RECEIPTS / "inputs/R17/admission.json"),
              "--post", str(RECEIPTS / "inputs/R17/post.json")]),
            ("s3", self.assessor.assess_s3, (INSTANCE / "bundles/supported", self.policy),
             ["s3", "--bundle", str(INSTANCE / "bundles/supported"),
              "--receiver-policy", str(INSTANCE / "receiver-policy.json")]),
        )
        actual_is_symlink = Path.is_symlink
        for blocked in (RECEIPTS, RECEIPTS / "SOURCE-PINS.json"):
            for failure in (PermissionError, OSError):
                def inaccessible_source(path):
                    if path == blocked:
                        raise failure("synthetic source path access failure")
                    return actual_is_symlink(path)
                for evaluator, call, args, cli_args in calls:
                    with self.subTest(evaluator=evaluator, path=blocked, error=failure.__name__, surface="api"):
                        with patch.object(Path, "is_symlink", inaccessible_source), patch.object(api.subprocess, "run") as run:
                            self.assert_error("SOURCE_UNAVAILABLE", call, *args)
                            run.assert_not_called()
                    with self.subTest(evaluator=evaluator, path=blocked, error=failure.__name__, surface="cli"):
                        stdout = io.StringIO()
                        with patch.object(Path, "is_symlink", inaccessible_source), patch.object(api.subprocess, "run") as run:
                            with redirect_stdout(stdout):
                                code = api.main(["--api-contract", api.API_CONTRACT] + cli_args)
                            run.assert_not_called()
                        self.assertEqual(code, 64)
                        error = json.loads(stdout.getvalue())
                        self.assertEqual(error["api_contract"], api.API_CONTRACT)
                        self.assertEqual(error["invocation"], {"status": "error"})
                        self.assertEqual(error["error"]["code"], "SOURCE_UNAVAILABLE")
                        self.assertNotIn("native_result", error)

    def test_all_fifteen_native_sources_are_pinned_before_invocation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = copy_tree(root)
            assessor = api.RecipientAssessor(expected_api_contract=api.API_CONTRACT, source_root=root)
            self.assertEqual(len(sources), 15)
            with patch.object(api.subprocess, "run") as run:
                for relative in sources:
                    path = root / relative
                    original = path.read_bytes()
                    path.write_bytes(original + b"\n")
                    self.assert_error("SOURCE_MISMATCH", assessor.assess_s3, INSTANCE / "bundles/supported", self.policy)
                    path.write_bytes(original)
                run.assert_not_called()
            relative = "reference/receipt-linkage-example/recipient_example.py"
            path = root / relative
            path.unlink()
            path.symlink_to(ROOT / relative)
            self.assert_error("SOURCE_UNAVAILABLE", assessor.assess_receipts, self.admission, self.post)

    def test_receipt_entry_and_its_pin_file_are_guarded_too(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_tree(root)
            assessor = api.RecipientAssessor(expected_api_contract=api.API_CONTRACT, source_root=root)
            for relative in ("reference/receipt-linkage-example/recipient_example.py", "reference/receipt-linkage-example/SOURCE-PINS.json"):
                path = root / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                self.assert_error("SOURCE_MISMATCH", assessor.assess_receipts, self.admission, self.post)
                path.write_bytes(original)

    def test_source_changed_during_invocation_does_not_get_a_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_tree(root)
            assessor = api.RecipientAssessor(expected_api_contract=api.API_CONTRACT, source_root=root)
            actual_run = subprocess.run
            def changing_run(*args, **kwargs):
                result = actual_run(*args, **kwargs)
                path = root / "reference/receipt-linkage-example/recipient_example.py"
                path.write_bytes(path.read_bytes() + b"\n")
                return result
            with patch.object(api.subprocess, "run", side_effect=changing_run):
                self.assert_error("SOURCE_MISMATCH", assessor.assess_receipts, self.admission, self.post)

    def test_cached_bytecode_cannot_replace_matching_native_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_tree(root)
            paths = ("reference/receipt-linkage-example/recipient_example.py",
                     "reference/vate-verifier-core/vate_verifier_core.py")
            for relative in paths:
                path = root / relative
                raw, original_stat = path.read_bytes(), path.stat()
                poison = b'raise RuntimeError("synthetic stale native bytecode")\n'
                path.write_bytes(poison + b" " * (len(raw) - len(poison)))
                os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
                py_compile.compile(str(path), doraise=True,
                                   invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
                path.write_bytes(raw)
                os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            unguarded = subprocess.run(
                [sys.executable, "-I", "-B", str(root / paths[0]),
                 "--admission", str(RECEIPTS / "inputs/R17/admission.json"),
                 "--post", str(RECEIPTS / "inputs/R17/post.json")],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(unguarded.returncode, 0)
            self.assertIn("synthetic stale native bytecode", unguarded.stderr)
            assessor = api.RecipientAssessor(expected_api_contract=api.API_CONTRACT, source_root=root)
            self.assertEqual(assessor.assess_receipts(self.admission, self.post)["native_result"], self.expected_receipt)

    def test_worker_independently_checks_sources_before_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_tree(root)
            path = root / "reference/receipt-linkage-example/recipient_example.py"
            path.write_bytes(b'raise RuntimeError("must never execute changed source")\n')
            request = {"evaluator": "receipt_pair", "source_root": str(root), "payload": {"admission": None, "post": None}}
            run = subprocess.run([sys.executable, "-I", "-B", str(HERE / "_worker.py")],
                                 input=json.dumps(request), text=True, capture_output=True, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout)["error"]["code"], "SOURCE_MISMATCH")

    def test_long_lived_import_rejects_update_fresh_compatible_import_preserves_native(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_tree(root, wrapper=True)
            path = root / "reference/recipient-assessment/vate_recipient.py"
            old = import_api(path)
            assessor = old.RecipientAssessor(expected_api_contract=api.API_CONTRACT)
            before = assessor.assess_receipts(self.admission, self.post)
            path.write_text(path.read_text().replace('WRAPPER_VERSION = "0.1.0"', 'WRAPPER_VERSION = "0.1.1"') + "\n# compatible local update exercise\n")
            with self.assertRaises(old.AssessmentError) as caught:
                assessor.assess_receipts(self.admission, self.post)
            self.assertEqual(caught.exception.code, "WRAPPER_SOURCE_CHANGED")
            fresh = import_api(path)
            after = fresh.RecipientAssessor(expected_api_contract=api.API_CONTRACT).assess_receipts(self.admission, self.post)
            self.assertEqual(before["api_contract"], after["api_contract"])
            self.assertNotEqual(before["wrapper"], after["wrapper"])
            self.assertEqual(after["wrapper"]["version"], "0.1.1")
            self.assertEqual(before["evaluator"], after["evaluator"])
            self.assertEqual(before["native_result"], after["native_result"])

    def test_cached_api_import_rejects_different_source_even_at_same_version(self):
        consumer = r'''
import json, pathlib, sys
sys.path.insert(0, sys.argv[1])
import vate_recipient as api
try:
    assessor = api.RecipientAssessor(expected_api_contract="vate-recipient-assessment-api-v1")
    receipts = pathlib.Path(sys.argv[2]) / "reference/receipt-linkage-example/inputs/R17"
    result = assessor.assess_receipts((receipts / "admission.json").read_bytes(), (receipts / "post.json").read_bytes())
except api.AssessmentError as exc:
    print(json.dumps(exc.as_dict()))
    raise SystemExit(64)
print(json.dumps(result))
'''
        changes = ((b'WRAPPER_VERSION = "0.1.0"', b'WRAPPER_VERSION = "0.1.1"'),
                   (b'_RECEIPT_LIMIT = 1024 * 1024', b'_RECEIPT_LIMIT = 1023 * 1024'))
        for old, new in changes:
            with self.subTest(change=old), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                copy_tree(root, wrapper=True)
                path = root / "reference/recipient-assessment/vate_recipient.py"
                original, original_stat = path.read_bytes(), path.stat()
                py_compile.compile(str(path), doraise=True, invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
                unchanged = subprocess.run([sys.executable, "-B", "-c", consumer, str(path.parent), str(ROOT)],
                                           cwd=directory, text=True, capture_output=True, check=False)
                self.assertEqual(unchanged.returncode, 0, unchanged.stdout + unchanged.stderr)
                self.assertEqual(json.loads(unchanged.stdout)["native_result"], self.expected_receipt)
                changed = original.replace(old, new)
                self.assertNotEqual(changed, original)
                self.assertEqual(len(changed), len(original))
                path.write_bytes(changed)
                os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
                result = subprocess.run([sys.executable, "-B", "-c", consumer, str(path.parent), str(ROOT)],
                                        cwd=directory, text=True, capture_output=True, check=False)
                self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
                error = json.loads(result.stdout)
                self.assertEqual(error["error"]["code"], "WRAPPER_CODE_MISMATCH")
                self.assertNotIn("native_result", error)

    def test_import_code_identity_respects_python_optimization(self):
        consumer = 'import sys; sys.path.insert(0, sys.argv[1]); import vate_recipient as api; api.RecipientAssessor(expected_api_contract=api.API_CONTRACT).capabilities()'
        for flags in ([], ["-O"], ["-OO"]):
            with self.subTest(flags=flags):
                result = subprocess.run([sys.executable, *flags, "-B", "-c", consumer, str(HERE)],
                                        text=True, capture_output=True, check=False)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_worker_at_import_is_a_structured_api_and_cli_error(self):
        consumer = r'''
import json, sys
sys.path.insert(0, sys.argv[1])
import vate_recipient as api
try:
    api.RecipientAssessor(expected_api_contract="vate-recipient-assessment-api-v1").capabilities()
except api.AssessmentError as exc:
    print(json.dumps(exc.as_dict()))
    raise SystemExit(64)
raise SystemExit("missing worker must not be available")
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_tree(root, wrapper=True)
            here = root / "reference/recipient-assessment"
            (here / "_worker.py").unlink()
            commands = [[sys.executable, "-B", "-c", consumer, str(here)]]
            for name in ("capabilities", "receipts"):
                commands.append([sys.executable, "-I", "-B", str(here / "vate_recipient.py"),
                                 "--api-contract", api.API_CONTRACT, name])
            for command in commands:
                with self.subTest(command=command):
                    result = subprocess.run(command, cwd=directory, text=True, capture_output=True, check=False)
                    self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
                    error = json.loads(result.stdout)
                    self.assertEqual(error["error"]["code"], "WRAPPER_SOURCE_UNAVAILABLE")
                    self.assertNotIn("native_result", error)

    def test_manifest_cannot_silently_repin_native_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_tree(root, wrapper=True)
            path = root / "reference/recipient-assessment/EVALUATOR-SOURCES.json"
            path.write_bytes(path.read_bytes() + b"\n")
            copied = import_api(path.with_name("vate_recipient.py"))
            with self.assertRaises(copied.AssessmentError) as caught:
                copied.RecipientAssessor(expected_api_contract=api.API_CONTRACT).assess_receipts(self.admission, self.post)
            self.assertEqual(caught.exception.code, "SOURCE_MANIFEST_ERROR")

    def test_worker_failures_and_protocol_errors_do_not_invent_verdict(self):
        cases = [
            (subprocess.TimeoutExpired(["python"], 1), "WORKER_TIMEOUT"),
            (OSError("synthetic spawn failure"), "WORKER_START_FAILED"),
            (SimpleNamespace(returncode=7, stdout=b"", stderr=b"synthetic failure"), "WORKER_FAILED"),
            (SimpleNamespace(returncode=0, stdout=b"not-json", stderr=b""), "WORKER_PROTOCOL_ERROR"),
            (SimpleNamespace(returncode=0, stdout=b'[]', stderr=b""), "WORKER_PROTOCOL_ERROR"),
            (SimpleNamespace(returncode=0, stdout=b'{"native_result":{},"evaluator":{}}', stderr=b""), "WORKER_PROTOCOL_ERROR"),
            (SimpleNamespace(returncode=0, stdout=b'{"error":{"code":"EVALUATOR_ERROR","detail":"synthetic native exception"}}', stderr=b""), "EVALUATOR_ERROR"),
        ]
        for value, code in cases:
            mock_args = {"side_effect": value} if isinstance(value, Exception) else {"return_value": value}
            with self.subTest(code=code), patch.object(api.subprocess, "run", **mock_args):
                self.assert_error(code, self.assessor.assess_receipts, self.admission, self.post)
        tiny_timeout = api.RecipientAssessor(expected_api_contract=api.API_CONTRACT, timeout_seconds=0.000001)
        self.assert_error("WORKER_TIMEOUT", tiny_timeout.assess_receipts, self.admission, self.post)

    def test_unrelated_cwd_conflicting_modules_and_concurrent_calls(self):
        code = r'''
import json, pathlib, sys, types
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, sys.argv[1])
import vate_recipient as api
root = pathlib.Path(sys.argv[2])
r = root / "reference/receipt-linkage-example/inputs/R17"
s = root / "reference/s3-observation-example/inputs/seaweedfs-4.48/instance"
sentinel = types.ModuleType("contract")
sentinel.marker = object()
sys.modules["contract"] = sentinel
before_path, before_cwd = sys.path[:], pathlib.Path.cwd()
reviewer = api.RecipientAssessor(expected_api_contract=api.API_CONTRACT)
a, p = (r / "admission.json").read_bytes(), (r / "post.json").read_bytes()
policy = (s / "receiver-policy.json").read_bytes()
def assess(i):
    return reviewer.assess_receipts(a, p) if i % 2 == 0 else reviewer.assess_s3(s / "bundles/supported", policy)
with ThreadPoolExecutor(max_workers=4) as pool:
    results = list(pool.map(assess, range(8)))
assert all(r["native_result"]["record_linkage"] == "matched" for r in results)
assert sys.modules["contract"] is sentinel
assert sys.path == before_path and pathlib.Path.cwd() == before_cwd
assert not any(n.startswith("_vate_fixed_") for n in sys.modules)
print(json.dumps({"calls": len(results), "caller_state": "unchanged"}))
'''
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "contract.py").write_text('raise RuntimeError("caller module collision")\n')
            result = subprocess.run([sys.executable, "-B", "-c", code, str(HERE), str(ROOT)],
                                    cwd=directory, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"calls": 8, "caller_state": "unchanged"})

    def test_returned_data_is_fresh_and_native_result_complete(self):
        first = self.assessor.assess_s3(INSTANCE / "bundles/supported", self.policy)
        self.assertEqual(first["native_result"], self.expected_s3)
        first["native_result"]["receipt_check"]["not_checked"].clear()
        first["evaluator"]["source_files"].clear()
        first["wrapper"]["source_files"].clear()
        second = self.assessor.assess_s3(INSTANCE / "bundles/supported", self.policy)
        self.assertEqual(second["native_result"], self.expected_s3)
        self.assertEqual(len(second["evaluator"]["source_files"]), 15)
        self.assertEqual(second["wrapper"], self.assessor.capabilities()["wrapper"])

    def test_cli_exit_codes_distinguish_native_and_invocation_failures(self):
        command = [sys.executable, "-I", "-B", str(HERE / "vate_recipient.py"), "--api-contract", api.API_CONTRACT]
        receipts = ["receipts", "--admission", str(RECEIPTS / "inputs/R17/admission.json")]
        cases = [
            (receipts + ["--post", str(RECEIPTS / "inputs/R17/post.json")], 0, "returned"),
            (receipts + ["--post", str(RECEIPTS / "inputs/synthetic-runtime-mismatch.json")], 1, "returned"),
            (receipts, 2, "returned"),
            (receipts + ["--post", str(RECEIPTS / "inputs/R17/post.json"), "--check", "operation_population_coverage"], 4, "returned"),
            (receipts + ["--check", "unknown-check"], 64, "error"),
            (receipts + ["--post", str(HERE / "no-such-file")], 64, "error"),
            (["unknown-command"], 64, "error"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / "manifest.json").write_bytes(encoded({"contract": "future", "artifacts": {}}))
            cases.append((["s3", "--bundle", directory, "--receiver-policy", str(INSTANCE / "receiver-policy.json")], 3, "returned"))
            for args, code, invocation in cases:
                result = subprocess.run(command + args, text=True, capture_output=True, check=False, cwd=directory)
                self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                self.assertEqual(json.loads(result.stdout)["invocation"]["status"], invocation)


if __name__ == "__main__":
    unittest.main()
