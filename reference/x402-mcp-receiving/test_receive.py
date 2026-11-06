import copy
import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
import tempfile
import unittest

import receive
from fixture_data import CASE_IDS, fixture

HERE = Path(__file__).resolve().parent


def changed(case_id=CASE_IDS[0], edit_capture=None, edit_selection=None, edit_request=None, repin=True):
    inputs = fixture(case_id)
    selection, request, capture = (json.loads(inputs[name]) for name in ("selection", "request", "capture"))
    if edit_request:
        edit_request(request)
        inputs["request"] = receive.encoded(request)
    if edit_capture:
        edit_capture(capture)
        inputs["capture"] = receive.encoded(capture)
    if repin:
        selection["capture_sha256"] = receive.sha(inputs["capture"])
        selection["request_sha256"] = receive.sha(inputs["request"])
    if edit_selection:
        edit_selection(selection)
    inputs["selection"] = receive.encoded(selection)
    return inputs


class ReceivingTests(unittest.TestCase):
    def assert_no_authorization(self, report):
        self.assertIs(report["is_execution_ticket"], False)
        for key in receive.NOT_ASSESSED:
            self.assertEqual(report["checks"][key]["status"], "not_assessed", key)

    def error(self, inputs, code):
        with self.assertRaises(receive.InputError) as caught:
            receive.assess(**inputs)
        self.assertEqual(caught.exception.code, code)

    def test_all_three_conditions_and_carriers(self):
        for case_id in CASE_IDS:
            with self.subTest(case=case_id):
                report = receive.assess(**fixture(case_id))
                self.assertEqual(report["status"], "inspected")
                self.assert_no_authorization(report)

    def test_unknown_without_receipt_is_not_unexecuted_or_unpaid(self):
        report = receive.assess(**fixture(CASE_IDS[0]))
        observed = report["observations"]
        self.assertEqual(observed["cancellation"]["observation"], "reported_unknown")
        self.assertEqual(observed["receipts"]["views"], [])
        self.assertIs(observed["sdk_payment_made_claim"], True)
        self.assert_no_authorization(report)

    def test_upfront_success_and_unknown_coexist(self):
        report = receive.assess(**fixture(CASE_IDS[1]))
        observed = report["observations"]
        self.assertTrue(observed["claimed_upfront_success_with_unknown_cancellation"])
        self.assertTrue(observed["tool_result"]["raw_is_error"])
        self.assertEqual(observed["receipts"]["distinct_values"], 1)
        self.assertEqual(len(observed["receipts"]["views"]), 2)
        self.assert_no_authorization(report)

    def test_receipt_success_alone_does_not_infer_upfront_phase(self):
        data = changed(CASE_IDS[1], edit_capture=lambda c: c["local_observations"].update(payment_phase="unknown"))
        self.assertFalse(receive.assess(**data)["observations"]["claimed_upfront_success_with_unknown_cancellation"])

    def test_reapproval_denial_preserves_each_carrier(self):
        for case_id, carrier in zip(CASE_IDS[2:], ("return", "exception.result", "exception.mcp_result")):
            report = receive.assess(**fixture(case_id))
            observed = report["observations"]
            self.assertEqual(observed["result_carrier"], carrier)
            self.assertEqual(observed["exporter_claims"]["reapproval"], "denied")
            self.assertIs(observed["exporter_claims"]["client_recovered"], True)
            self.assertIs(observed["result_retained_in_capture"], True)
            self.assert_no_authorization(report)

    def test_recovered_flag_never_becomes_permission(self):
        for value in (True, False, None):
            data = changed(edit_capture=lambda c: c["local_observations"].update(client_recovered=value))
            self.assert_no_authorization(receive.assess(**data))

    def test_native_success_and_no_error_still_not_execution_proof(self):
        def edit(c):
            c["result"]["is_error"] = False
            c["result"]["raw_result"]["is_error"] = False
            c["result"]["content"] = []
            c["result"]["raw_result"]["content"] = []
        report = receive.assess(**changed(CASE_IDS[1], edit_capture=edit))
        self.assertEqual(report["observations"]["cancellation"]["observation"], "not_reported")
        self.assert_no_authorization(report)

    def test_false_payment_made_does_not_prove_no_payment(self):
        self.assert_no_authorization(receive.assess(**changed(edit_capture=lambda c: c["result"].update(payment_made=False))))

    def test_changed_capture_with_old_pin_is_not_inspected(self):
        report = receive.assess(**changed(edit_capture=lambda c: c["result"].update(payment_made=False), repin=False))
        self.assertEqual(report["reason"], "receiver_selected_bytes_mismatch")
        self.assertIsNone(report["observations"])
        self.assert_no_authorization(report)

    def test_changed_request_with_old_pin_is_not_inspected(self):
        report = receive.assess(**changed(edit_request=lambda q: q["arguments"].update(input=2), repin=False))
        self.assertEqual(report["checks"]["receiver_selected_bytes"]["matches"], {"request": False, "capture": True})

    def test_new_request_pin_cannot_rebind_old_capture(self):
        report = receive.assess(**changed(edit_request=lambda q: q["arguments"].update(input=2)))
        self.assertEqual(report["reason"], "request_or_declared_context_mismatch")

    def test_same_args_do_not_merge_operation_or_attempt_or_server(self):
        for key in ("operation_id", "attempt_id", "server_id"):
            for side in ("capture", "selection"):
                with self.subTest(key=key, side=side):
                    change = lambda obj: obj["context"].update({key: "another-context"})
                    data = changed(**{"edit_" + side: change})
                    report = receive.assess(**data)
                    self.assertEqual(report["checks"]["declared_context"]["status"], "mismatched")
                    self.assertIsNone(report["observations"])

    def test_payment_transaction_id_is_not_operation_binding(self):
        def edit(c):
            c["result"]["raw_result"]["meta"][receive.KEY]["transaction"] = c["context"]["operation_id"]
        report = receive.assess(**changed(CASE_IDS[1], edit_capture=edit))
        self.assertEqual(report["observations"]["receipts"]["distinct_values"], 2)
        self.assert_no_authorization(report)

    def test_unknown_source_pin_and_export_are_not_inspected(self):
        edits = (lambda c: c["sdk"].update(version="9.99.0"),
                 lambda c: c["sdk"].update(source_commit="0" * 40),
                 lambda c: c.update(export_profile="unknown"))
        for edit in edits:
            report = receive.assess(**changed(edit_capture=edit))
            self.assertEqual(report["reason"], "unsupported_export_or_sdk_pin")
            self.assertIsNone(report["observations"])

    def test_unknown_selection_profile_is_not_echoed(self):
        data = changed(edit_selection=lambda s: s.update(profile="private-profile-secret"))
        report = receive.assess(**data)
        self.assertEqual(report["reason"], "unsupported_receiver_profile")
        self.assertNotIn(b"private-profile-secret", receive.encoded(report))

    def test_failed_receipt_in_error_body_is_preserved_without_sdk_summary(self):
        def edit(c):
            receipt = {"success": False, "transaction": "", "network": "eip155:84532",
                       "errorReason": "cancellation_failed", "extra": {"depositTransaction": "deposit"}}
            body = {receive.KEY: receipt}
            c["result"]["raw_result"]["structured_content"] = body
            c["result"]["raw_result"]["content"].append({"type": "text", "text": json.dumps(body)})
            c["result"]["content"] = copy.deepcopy(c["result"]["raw_result"]["content"])
        report = receive.assess(**changed(edit_capture=edit))
        receipts = report["observations"]["receipts"]
        self.assertFalse(receipts["sdk_summary_present"])
        self.assertEqual(receipts["distinct_values"], 1)
        self.assertEqual(len(receipts["views"]), 2)
        self.assertTrue(all(v["reported_success"] is False and v["header_subset_location_match"] for v in receipts["views"]))
        self.assert_no_authorization(report)

    def test_success_receipt_in_body_is_not_success_reconciliation_surface(self):
        def edit(c):
            c["result"]["raw_result"]["structured_content"] = {receive.KEY: c["result"]["payment_response"]}
            c["result"]["raw_result"]["meta"] = {}
            c["result"]["payment_response"] = None
        report = receive.assess(**changed(CASE_IDS[1], edit_capture=edit))
        views = report["observations"]["receipts"]["views"]
        self.assertEqual(len(views), 1)
        self.assertIs(views[0]["reported_success"], True)
        self.assertIs(views[0]["header_subset_location_match"], False)

    def test_header_subset_location_is_not_native_acceptance(self):
        receipt = {"success": True, "transaction": "test-only", "network": "test-only"}
        for value, expected in (({**receipt, "extensions": 5}, True), (json.dumps(receipt), False)):
            with self.subTest(receipt=value):
                def edit(c):
                    c["result"]["raw_result"]["meta"][receive.KEY] = value
                report = receive.assess(**changed(edit_capture=edit))
                view = report["observations"]["receipts"]["views"][0]
                self.assertIs(view["header_subset_location_match"], expected)
                self.assertNotIn("native_reconciliation_location", view)
                self.assert_no_authorization(report)

    def test_metadata_and_different_failure_body_are_both_retained(self):
        def edit(c):
            c["result"]["raw_result"]["structured_content"] = {receive.KEY: {
                "success": False, "transaction": "cancel", "network": "eip155:84532"}}
        receipts = receive.assess(**changed(CASE_IDS[1], edit_capture=edit))["observations"]["receipts"]
        self.assertEqual(receipts["distinct_values"], 2)
        self.assertEqual([v["reported_success"] for v in receipts["views"]], [True, True, False])
        self.assertEqual(receipts["selection"], "none_all_views_retained")

    def test_malformed_receipt_remains_unrecognized_not_discarded(self):
        for value in (None, 1, True, "receipt", [], {"success": "true"},
                      {"success": True, "transaction": "tx", "network": "n", "amount": 4}):
            def edit(c):
                c["result"]["raw_result"]["meta"][receive.KEY] = value
            views = receive.assess(**changed(edit_capture=edit))["observations"]["receipts"]["views"]
            self.assertEqual(len(views), 1)
            self.assertEqual(views[0]["shape"], "unrecognized")
            self.assertIsNone(views[0]["reported_success"])

    def test_invalid_embedded_json_is_explicit_diagnostic(self):
        for text in ('{"x402/payment-response":null,"x402/payment-response":{}}', '{"a":NaN}', '{oops'):
            def edit(c):
                c["result"]["raw_result"]["content"].append({"type": "text", "text": text})
            observed = receive.assess(**changed(edit_capture=edit))["observations"]
            self.assertEqual(len(observed["receipts"]["diagnostics"]), 1)
            self.assertEqual(observed["receipts"]["views"], [])

    def test_boolean_number_receipt_disagreement_is_not_equal(self):
        def edit(c):
            c["result"]["payment_response"]["extra"] = {"flag": True}
            c["result"]["raw_result"]["meta"][receive.KEY]["extra"] = {"flag": 1}
        self.assertEqual(receive.assess(**changed(CASE_IDS[1], edit_capture=edit))["observations"]["receipts"]["distinct_values"], 2)

    def test_validation_error_can_keep_raw_success_and_summary_error(self):
        def edit(c):
            c.update(carrier="exception.result", exception_type="PaymentResponseError")
            c["result"]["payment_response"] = None
            c["result"]["raw_result"]["is_error"] = False
        observed = receive.assess(**changed(CASE_IDS[1], edit_capture=edit))["observations"]
        self.assertEqual(observed["tool_result"], {"sdk_is_error": True, "raw_is_error": False, "content_views_equal": True})
        self.assertFalse(observed["receipts"]["sdk_summary_present"])
        self.assertEqual(len(observed["receipts"]["views"]), 1)

    def test_summary_and_raw_content_disagreement_is_visible(self):
        data = changed(edit_capture=lambda c: c["result"].update(content=[]))
        self.assertFalse(receive.assess(**data)["observations"]["tool_result"]["content_views_equal"])

    def test_unknown_text_cannot_prove_cancellation_attempt_or_effect(self):
        data = changed(edit_capture=lambda c: c["result"]["raw_result"].update(content=[
            {"type": "text", "text": "Payment cancellation completed"}]))
        report = receive.assess(**data)
        self.assertEqual(report["observations"]["cancellation"]["observation"], "not_reported")
        self.assert_no_authorization(report)

    def test_no_private_content_or_context_in_report(self):
        def edit(c):
            c["result"]["raw_result"]["content"].append({"type": "text", "text": "SECRET-body-123"})
            c["result"]["raw_result"]["meta"]["remote"] = "https://never-fetch.invalid/SECRET-URL"
        data = changed(edit_capture=edit)
        output = receive.encoded(receive.assess(**data))
        for secret in (b"SECRET", b"synthetic-server", b"synthetic-operation", b"synthetic_paid_tool", b"never-fetch"):
            self.assertNotIn(secret, output)

    def test_invalid_flags_are_not_coerced(self):
        for key in ("payment_made", "is_error"):
            for value in (0, 1, "true", None, {}):
                self.error(changed(edit_capture=lambda c: c["result"].update({key: value})), "result_flags")

    def test_extra_unknown_envelope_fields_rejected(self):
        self.error(changed(edit_capture=lambda c: c.update(retry=True)), "unsupported_object_shape")
        self.error(changed(edit_selection=lambda s: s.update(allow=True)), "unsupported_object_shape")

    def test_missing_result_is_not_empty_success(self):
        self.error(changed(edit_capture=lambda c: c.pop("result")), "unsupported_object_shape")

    def test_wrong_carrier_and_exception_combinations_rejected(self):
        for edit in (lambda c: c.update(carrier="return", exception_type="Error"),
                     lambda c: c.update(carrier="exception.result", exception_type=None),
                     lambda c: c.update(carrier="fallback")):
            with self.assertRaises(receive.InputError):
                receive.assess(**changed(edit_capture=edit))

    def test_non_boolean_recovery_is_rejected(self):
        self.error(changed(edit_capture=lambda c: c["local_observations"].update(client_recovered=1)), "local_observation_shape")

    def test_invalid_context_and_digest_rejected(self):
        for value in (None, True, 12, "space here", "\n", "x" * 257):
            self.error(changed(edit_selection=lambda s: s["context"].update(attempt_id=value)), "invalid_identifier")
        self.error(changed(edit_selection=lambda s: s.update(capture_sha256="sha256:" + "0" * 64)), "invalid_digest")

    def test_duplicate_keys_rejected_in_every_document(self):
        for name in ("selection", "request", "capture"):
            data = fixture(CASE_IDS[0])
            data[name] = b'{"repeated":1,"repeated":2}'
            self.error(data, "duplicate_json_key")

    def test_invalid_json_unicode_constants_and_empty_rejected(self):
        for raw in (b"", b"null", b"[]", b"{", b'{} trailing', b'{"a":NaN}',
                    b'{"a":Infinity}', b'{"a":"\xff"}', b'{"a":"\\ud800"}'):
            data = fixture(CASE_IDS[0])
            data["request"] = raw
            with self.assertRaises(receive.InputError):
                receive.assess(**data)

    def test_size_depth_and_number_limits(self):
        for raw in (b" " * (receive.MAX_BYTES + 1), b'{"a":' + b"[" * 60 + b"0" + b"]" * 60 + b"}",
                    b'{"a":' + b"1" * 129 + b"}"):
            with self.assertRaises(receive.InputError):
                receive.parse(raw, "request")

    def test_opaque_numeric_arguments_are_not_rounded_or_used_as_ids(self):
        data = fixture(CASE_IDS[0])
        data["request"] = b'{"name":"tool","arguments":{"n":9007199254740993,"tiny":1e-999,"d":1.0000000000000001}}'
        capture = json.loads(data["capture"])
        capture["request_sha256"] = receive.sha(data["request"])
        data["capture"] = receive.encoded(capture)
        selection = json.loads(data["selection"])
        selection.update(request_sha256=receive.sha(data["request"]), capture_sha256=receive.sha(data["capture"]))
        data["selection"] = receive.encoded(selection)
        self.assertEqual(receive.assess(**data)["status"], "inspected")
        self.assertEqual(str(receive.parse(data["request"], "request")["arguments"]["n"]), "9007199254740993")


class SourceIdentityTests(unittest.TestCase):
    def run_copy(self, module, output, optimize=0, edit=""):
        script = ("import sys; from pathlib import Path; "
                  "sys.path.insert(0,sys.argv[1]); import reader_copy; " + edit +
                  "raise SystemExit(reader_copy.main(sys.argv[2:]))")
        args = [sys.executable, "-B"]
        if optimize:
            args.append("-" + "O" * optimize)
        args += ["-c", script, str(module.parent), "--out", str(output)]
        for name in ("selection", "request", "capture"):
            args += ["--" + name, str(HERE / "fixtures" / CASE_IDS[0] / (name + ".json"))]
        return subprocess.run(args, capture_output=True, timeout=15, cwd=module.parent)

    def test_stale_bytecode_is_refused_and_fresh_source_assessed(self):
        source = (HERE / "receive.py").read_bytes()
        marker = b'CANCEL_UNKNOWN = "Payment cancellation outcome unknown"'
        self.assertEqual(source.count(marker), 1)
        edited = source.replace(marker, b'CANCEL_UNKNOWN = "Xayment cancellation outcome unknown"')
        self.assertEqual(len(source), len(edited))
        for optimize in (0, 1, 2):
            with self.subTest(optimize=optimize), tempfile.TemporaryDirectory() as temp:
                module = Path(temp) / "reader_copy.py"
                module.write_bytes(source)
                before = module.stat()
                cache = Path(py_compile.compile(str(module), doraise=True, optimize=optimize,
                             invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP))
                module.write_bytes(edited)
                os.utime(module, ns=(before.st_atime_ns, before.st_mtime_ns))
                output = Path(temp) / "result"
                cached = self.run_copy(module, output, optimize)
                self.assertEqual(cached.returncode, 64, cached.stdout + cached.stderr)
                self.assertEqual(json.loads(cached.stdout), {
                    "status": "input_error", "reason": "reader_source_mismatch",
                    "input": "reader", "is_execution_ticket": False})
                self.assertEqual(cached.stderr, b"")
                self.assertFalse(output.exists())
                cache.unlink()
                fresh = self.run_copy(module, output, optimize)
                self.assertEqual(fresh.returncode, 0, fresh.stdout + fresh.stderr)
                report = json.loads(fresh.stdout)
                self.assertEqual(report["reader_sha256"], receive.sha(edited))
                self.assertEqual(report["observations"]["cancellation"]["observation"], "not_reported")
                self.assertFalse(report["is_execution_ticket"])

    def test_source_changed_or_removed_after_import_is_input_error(self):
        for edit in ("p=Path(reader_copy.__file__); p.write_bytes(p.read_bytes()+b'\\n# changed\\n'); ",
                     "Path(reader_copy.__file__).unlink(); "):
            with self.subTest(edit=edit), tempfile.TemporaryDirectory() as temp:
                module = Path(temp) / "reader_copy.py"
                module.write_bytes((HERE / "receive.py").read_bytes())
                output = Path(temp) / "result"
                result = self.run_copy(module, output, edit=edit)
                self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
                self.assertEqual(json.loads(result.stdout)["reason"], "reader_source_changed")
                self.assertEqual(result.stderr, b"")
                self.assertFalse(output.exists())


class FileAndCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.inputs = fixture(CASE_IDS[0])
        self.paths = {}
        for name, raw in self.inputs.items():
            self.paths[name] = self.root / (name + ".json")
            self.paths[name].write_bytes(raw)

    def tearDown(self):
        self.temp.cleanup()

    def cli(self, out="result"):
        args = [sys.executable, str(HERE / "receive.py"), "--out", str(self.root / out)]
        for name, path in self.paths.items():
            args += ["--" + name, str(path)]
        return subprocess.run(args, capture_output=True, timeout=15, cwd=self.root)

    def test_cli_preserves_bytes_and_reassessment(self):
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        originals = {name: (self.root / "result" / (name + ".json")).read_bytes() for name in self.inputs}
        self.assertEqual(originals, self.inputs)
        self.assertEqual(receive.assess(**originals), report)
        self.assertEqual(report, json.loads((self.root / "result/report.json").read_bytes()))
        manifest = json.loads((self.root / "result/MANIFEST.json").read_bytes())
        for name, ref in manifest["files"].items():
            self.assertEqual(receive.raw_ref((self.root / "result" / name).read_bytes()), ref)

    def test_cli_zero_means_report_even_when_pins_mismatch(self):
        self.paths["capture"].write_bytes(self.inputs["capture"] + b" ")
        result = self.cli()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["status"], "not_assessed")

    def test_cli_bad_json_is_64_without_input_leak_or_output_directory(self):
        self.paths["capture"].write_text('{"SECRET-body":')
        result = self.cli()
        self.assertEqual(result.returncode, 64)
        self.assertNotIn(b"SECRET", result.stdout + result.stderr)
        self.assertFalse((self.root / "result").exists())

    def test_cli_existing_output_refused_and_original_preserved(self):
        first = self.cli()
        saved = (self.root / "result/report.json").read_bytes()
        second = self.cli()
        self.assertEqual(first.returncode, 0)
        self.assertEqual(second.returncode, 64)
        self.assertEqual(json.loads(second.stdout)["reason"], "output_exists")
        self.assertEqual((self.root / "result/report.json").read_bytes(), saved)

    def test_missing_file_is_error_not_absence(self):
        self.paths["capture"].unlink()
        self.assertEqual(self.cli().returncode, 64)

    def test_invalid_input_paths_are_input_errors(self):
        for path in ("bad\x00path", "bad\ud800path", None):
            with self.subTest(path=repr(path)), self.assertRaises(receive.InputError) as caught:
                receive.read_file(path, "capture")
            self.assertEqual((caught.exception.code, caught.exception.label), ("invalid_file_path", "capture"))

    def test_invalid_output_paths_are_input_errors(self):
        report = receive.assess(**self.inputs)
        for path in ("bad\x00path", "bad\ud800path", None):
            with self.subTest(path=repr(path)), self.assertRaises(receive.InputError) as caught:
                receive.save_bundle(path, self.inputs, report)
            self.assertEqual((caught.exception.code, caught.exception.label), ("invalid_file_path", "output"))

    def test_programmatic_main_invalid_paths_are_64_without_path_leak(self):
        script = ("import json,sys; sys.path.insert(0,sys.argv[1]); import receive; "
                  "raise SystemExit(receive.main(json.loads(sys.argv[2])))")
        for target, label in (("capture", "capture"), ("out", "output")):
            for invalid in ("SECRET-bad\x00path", "SECRET-bad\ud800path"):
                with self.subTest(target=target, path=repr(invalid)):
                    args = ["--out", str(self.root / "result")]
                    for name, path in self.paths.items():
                        args += ["--" + name, str(path)]
                    args[args.index("--" + target) + 1] = invalid
                    result = subprocess.run([sys.executable, "-B", "-c", script, str(HERE), json.dumps(args)],
                                            capture_output=True, timeout=15, cwd=self.root)
                    self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
                    self.assertEqual(json.loads(result.stdout), {
                        "status": "input_error", "reason": "invalid_file_path",
                        "input": label, "is_execution_ticket": False})
                    self.assertEqual(result.stderr, b"")
                    self.assertNotIn(b"SECRET", result.stdout)
                    self.assertFalse((self.root / "result").exists())

    def test_symlink_and_fifo_refused_without_blocking(self):
        target = self.paths["capture"]
        target.unlink()
        target.symlink_to(self.paths["request"])
        self.assertEqual(self.cli().returncode, 64)
        target.unlink()
        os.mkfifo(target)
        self.assertEqual(self.cli().returncode, 64)

    def test_output_symlink_refused(self):
        (self.root / "result").symlink_to(self.root, target_is_directory=True)
        self.assertEqual(self.cli().returncode, 64)

    def test_private_file_permissions(self):
        self.assertEqual(self.cli().returncode, 0)
        self.assertEqual((self.root / "result").stat().st_mode & 0o777, 0o700)
        for path in (self.root / "result").iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
