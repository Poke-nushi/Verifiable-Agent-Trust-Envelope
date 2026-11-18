"""Failed input must replace a previous success with a usable demo report."""
from __future__ import annotations

import copy
from http.client import IncompleteRead
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import URLError

import trust_envelope_demo as demo


class FailureReportingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="vate-al2-report-")
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        cls.bundle = demo.build_demo_bundle(cls.directory)

    def restore(self):
        demo.write_bundle(self.directory, self.bundle)
        baseline = demo.verify_demo(self.directory, status_mode="stapled")
        self.assertTrue(baseline["ok"], baseline)

    def assert_failed_report(self, report, failed_check):
        self.assertFalse(report["ok"], report)
        self.assertIn(failed_check, {check["name"] for check in report["checks"] if not check["ok"]})
        self.assertEqual(json.loads((self.directory / "verification-report.json").read_bytes()), report)
        self.assertFalse(report["request_binding"]["binding_requirement_met"])

    def cli(self, mode):
        result = subprocess.run([sys.executable, "-B", demo.__file__, "verify-demo",
                                 "--dir", str(self.directory), "--status-mode", mode],
                                capture_output=True, text=True, timeout=30)
        # As before, callers inspect report.ok; the CLI exit status is not admission.
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads((self.directory / "verification-report.json").read_bytes())

    def write_status(self, payload, *, mode="stapled"):
        key = {"kid": "status-key-1", "alg": "ES256",
               "private_key": demo.key_path(self.directory, "status", "private")}
        token = demo.build_compact_jws(payload, key_info=key,
            typ=demo.STATUS_EVENT_TYP if mode == "push" else demo.STATUS_TYP,
            cty=demo.STATUS_EVENT_CONTENT_TYPE if mode == "push" else demo.STATUS_CONTENT_TYPE)
        filename = "push-status-event.jws" if mode == "push" else "stapled-status.jws"
        (self.directory / filename).write_text(token)
        return token

    def test_local_delivery_read_and_decode_failures_replace_success_via_cli(self):
        for mode, filename in (("stapled", "stapled-status.jws"), ("push", "push-status-event.jws")):
            for value, check in ((b"not-a-jws", "status_signature"), (b"\xff", "status_input"), (None, "status_input")):
                with self.subTest(mode=mode, value=value):
                    self.restore()
                    path = self.directory / filename
                    path.unlink() if value is None else path.write_bytes(value)
                    self.assert_failed_report(self.cli(mode), check)

    def test_pull_transport_failures_replace_success(self):
        for error in (URLError("synthetic offline service"), TimeoutError("synthetic timeout"),
                      IncompleteRead(b"partial"),
                      UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid byte")):
            with self.subTest(error=type(error).__name__):
                self.restore()
                with patch.object(demo, "http_get_text", side_effect=error):
                    report = demo.verify_demo(self.directory, status_mode="pull", status_base="http://127.0.0.1")
                self.assert_failed_report(report, "status_pull_fetch")
        self.restore()
        self.assert_failed_report(self.cli("pull"), "status_pull_fetch")

    def test_verification_reads_only_selected_signed_inputs(self):
        for mode in ("stapled", "push", "pull"):
            with self.subTest(mode=mode):
                self.restore()
                for spec in demo.ARTIFACT_SPECS.values():
                    (self.directory / (spec["basename"] + ".json")).unlink()
                (self.directory / "status-store.json").unlink()
                for delivery, filename in (("stapled", "stapled-status.jws"), ("push", "push-status-event.jws")):
                    if delivery != mode:
                        (self.directory / filename).unlink()
                with patch.object(demo, "http_get_text", return_value=self.bundle["status_tokens"]["stapled"]):
                    report = demo.verify_demo(self.directory, status_mode=mode, status_base="http://127.0.0.1")
                self.assertTrue(report["ok"], report)

    def test_status_issuer_only_needs_its_store_and_registered_keypair(self):
        with tempfile.TemporaryDirectory() as directory:
            issuer = Path(directory)
            demo.write_json(issuer / "status-store.json", self.bundle["status_store"])
            demo.write_json(issuer / "trust-bundle.json", self.bundle["trust_bundle"])
            for side in ("private", "public"):
                path = demo.key_path(issuer, "status", side)
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(demo.key_path(self.directory, "status", side).read_bytes())

            for kind in ("bundle", "stapled", "event", "entry"):
                with self.subTest(kind=kind):
                    token = demo.build_status_token(issuer, kind, object_type="permit" if kind == "entry" else None)
                    _, payload, _, _ = demo.decode_compact_jws(token)
                    subjects = set(demo.normalize_status_payload(payload)["entries"])
                    self.assertEqual(subjects, {"permit"} if kind == "entry" else {"passport", "runtime", "permit"})

            wrong_signer = demo.key_path(self.directory, "issuer", "private").read_bytes()
            demo.key_path(issuer, "status", "private").write_bytes(wrong_signer)
            with self.assertRaises(RuntimeError):
                demo.build_status_token(issuer, "bundle")
            saved = dict(self.bundle["status_tokens"])
            bundle = {**self.bundle, "status_tokens": saved.copy()}
            with self.assertRaises(RuntimeError):
                demo.issue_status_tokens(bundle, issuer)
            self.assertEqual(bundle["status_tokens"], saved)

    def test_authenticated_but_unusable_status_replaces_success(self):
        base = demo.build_status_bundle_payload(self.bundle["status_store"], delivery="stapled")
        mutations = (
            ("missing_timestamp", lambda p: p.pop("generated_at")),
            ("invalid_timestamp", lambda p: p.update(next_update_at="not-a-date")),
            ("timestamp_type", lambda p: p.update(generated_at=None)),
            ("naive_timestamp", lambda p: p.update(generated_at="2026-01-01T00:00:00")),
            ("unknown_version", lambda p: p.update(version="unknown")),
            ("entries_type", lambda p: p.update(entries=[])),
            ("missing_entry", lambda p: p["entries"].pop("permit")),
            ("entry_type", lambda p: p["entries"].update(permit=None)),
            ("entry_id_type", lambda p: p["entries"]["permit"].update(id=[])),
            ("missing_reason", lambda p: p["entries"]["permit"].pop("reason")),
            ("entry_state_type", lambda p: p["entries"]["permit"].update(state=[])),
            ("unknown_state", lambda p: p["entries"]["permit"].update(state="unknown")),
            ("effect_type", lambda p: p["entries"]["permit"].update(state="attenuated", effect=True)),
            ("missing_constraints", lambda p: p["entries"]["permit"].update(
                state="attenuated", effect={"mode": "narrow", "require_new_permit": False})),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                self.restore()
                payload = copy.deepcopy(base)
                mutate(payload)
                self.write_status(payload)
                self.assert_failed_report(demo.verify_demo(self.directory, status_mode="stapled"), "status_payload")
        self.restore()
        event = demo.build_status_event_payload(self.bundle["status_store"])
        event.pop("generated_at")
        self.write_status(event, mode="push")
        self.assert_failed_report(self.cli("push"), "status_payload")

    def test_invalid_signature_does_not_interpret_untrusted_status(self):
        self.restore()
        token = demo.tamper_compact_jws_payload(self.bundle["status_tokens"]["stapled"],
                                              lambda p: p.update(entries=None))
        (self.directory / "stapled-status.jws").write_text(token)
        report = demo.verify_demo(self.directory, status_mode="stapled")
        self.assert_failed_report(report, "status_signature")
        self.assertNotIn("status_payload", {check["name"] for check in report["checks"]})

    def test_jws_object_and_kid_shapes_fail_without_field_access_errors(self):
        header, payload, _, _ = demo.decode_compact_jws(self.bundle["status_tokens"]["stapled"])
        for protected, body in ((None, payload), ([], payload), ({**header, "kid": []}, payload),
                                (header, None), (header, [])):
            with self.subTest(header=protected, payload=body):
                self.restore()
                token = ".".join((demo.b64url_encode(demo.canonical(protected)),
                                  demo.b64url_encode(demo.canonical(body)), "AA"))
                (self.directory / "stapled-status.jws").write_text(token)
                self.assert_failed_report(self.cli("stapled"), "status_signature")

    def test_signed_json_reader_accepts_exact_numbers_and_unambiguous_members(self):
        valid = '{"threshold":9007199254740993.0,"ratio":0.125}'
        self.assertEqual(demo.parse_demo_json(valid), {"threshold": 9007199254740993, "ratio": 0.125})
        for raw in ('{"limit":1,"limit":2}', '{"limit":1.00000000000000000001}', '{"limit":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                demo.parse_demo_json(raw)

    def test_artifact_and_trust_input_failures_also_replace_success(self):
        for name, spec in demo.ARTIFACT_SPECS.items():
            with self.subTest(artifact=name):
                self.restore()
                (self.directory / (spec["basename"] + ".jws")).write_text("not-a-jws")
                report = demo.verify_demo(self.directory, status_mode="stapled")
                self.assert_failed_report(report, name + "_signature")
        for filename, value in (("runtime-proof.jws", None), ("trust-bundle.json", b"[]"),
                                ("trust-bundle.json", b"not-json")):
            with self.subTest(filename=filename, value=value):
                self.restore()
                path = self.directory / filename
                path.unlink() if value is None else path.write_bytes(value)
                self.assert_failed_report(self.cli("stapled"), "verification_input")
        self.restore()
        bundle = copy.deepcopy(self.bundle)
        bundle["artifacts"]["runtime_proof"]["payload"]["issued_at"] = None
        demo.resign_artifact(bundle, "runtime_proof", self.directory)
        demo.write_bundle(self.directory, bundle)
        self.assert_failed_report(self.cli("stapled"), "verification_input")

    def test_unexpected_operational_error_cannot_leave_old_success(self):
        self.restore()
        with patch.object(demo, "verify_bytes", side_effect=RuntimeError("synthetic unavailable verifier")):
            with self.assertRaises(RuntimeError):
                demo.verify_demo(self.directory, status_mode="stapled")
        self.assertFalse((self.directory / "verification-report.json").exists())

    def test_negative_suite_publishes_a_mismatch_and_retires_the_summary_on_interruption(self):
        with tempfile.TemporaryDirectory() as work:
            out = Path(work) / "bundle"
            demo.generate_demo(out)
            # An unchanged positive bundle cannot satisfy this negative expectation.
            control = {"name": "positive-control", "description": "unchanged bundle",
                       "mutate": lambda bundle: None, "status_mode": "stapled",
                       "expected_failed_checks": ["permit_signature"]}
            argv = ["demo", "run-negative-tests", "--dir", str(out)]
            with patch.object(demo, "negative_cases", return_value=[control]), patch.object(sys, "argv", argv):
                with self.assertRaises(SystemExit) as stopped:
                    demo.main()
            self.assertNotIn(stopped.exception.code, (0, None))
            summary = out / "negative-test-report.json"
            published = demo.read_json(summary)
            self.assertFalse(published["ok"])
            case_report = out / published["results"][0]["report"]
            self.assertTrue(demo.read_json(case_report)["ok"])
            previous = case_report.read_bytes()
            (out / "trust-bundle.json").unlink()
            with self.assertRaises(FileNotFoundError):
                demo.run_negative_tests(out)
            self.assertFalse(summary.exists())
            self.assertEqual(case_report.read_bytes(), previous)

    def test_new_generation_retires_old_report_and_preserves_the_previous_set_on_publish_error(self):
        with tempfile.TemporaryDirectory() as work:
            out = Path(work) / "bundle"
            demo.generate_demo(out)
            report = demo.verify_demo(out, status_mode="stapled")
            self.assertTrue(report["ok"])
            receipt = out / "execution-receipt.jws"
            old = receipt.read_bytes()
            rename = Path.rename
            interrupted = False

            def fail_on_install(path, target):
                nonlocal interrupted
                if target == out and not interrupted:
                    interrupted = True
                    raise OSError("publication interrupted")
                return rename(path, target)

            with patch.object(Path, "rename", fail_on_install), self.assertRaises(OSError):
                demo.generate_demo(out)
            self.assertEqual(receipt.read_bytes(), old)
            self.assertEqual(demo.read_json(out / "verification-report.json"), report)
            demo.generate_demo(out)
            self.assertNotEqual(receipt.read_bytes(), old)
            self.assertFalse((out / "verification-report.json").exists())
            self.assertTrue(demo.verify_demo(out, status_mode="stapled")["ok"])

    def test_canonical_base64url_segments(self):
        for raw in (b"a", bytes(range(32)), b"\xfb\xff\xef"):
            encoded = demo.b64url_encode(raw)
            self.assertEqual(demo.b64url_decode(encoded), raw)
        for invalid in ("", "YQ==", "Y Q", "YR", "+//v"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                demo.b64url_decode(invalid)

    def test_nonpermit_status_narrowing_and_reissue_are_reported(self):
        for kind in ("passport", "runtime"):
            for reissue in (False, True):
                with self.subTest(kind=kind, reissue=reissue):
                    self.restore()
                    status = demo.build_status_bundle_payload(self.bundle["status_store"], delivery="stapled")
                    status["entries"][kind].update(state="attenuated", effect={
                        "mode": "narrow", "constraints": {}, "require_new_permit": reissue})
                    self.write_status(status)
                    report = demo.verify_demo(self.directory, status_mode="stapled")
                    failures = {row["name"] for row in report["checks"] if not row["ok"]}
                    self.assertFalse(report["ok"])
                    self.assertEqual(failures, {"status_attenuation_scope", "status_attenuation_policy"}
                                     if reissue else {"status_attenuation_scope"})

        self.restore()
        status = demo.build_status_bundle_payload(self.bundle["status_store"], delivery="stapled")
        status["entries"]["permit"]["effect"] = {"mode": "narrow", "constraints": {}, "require_new_permit": True}
        self.write_status(status)
        self.assert_failed_report(demo.verify_demo(self.directory, status_mode="stapled"), "status_attenuation_policy")

    def test_receipt_phase_is_required_for_a_post_execution_result(self):
        for phase in (None, "admission", "post_execution"):
            with self.subTest(phase=phase):
                bundle = copy.deepcopy(self.bundle)
                receipt = bundle["artifacts"]["receipt"]["payload"]
                if phase is None:
                    del receipt["receipt_phase"]
                else:
                    receipt["receipt_phase"] = phase
                demo.resign_artifact(bundle, "receipt", self.directory)
                demo.write_bundle(self.directory, bundle)
                report = demo.verify_demo(self.directory, status_mode="push")
                failures = {check["name"] for check in report["checks"] if not check["ok"]}
                self.assertEqual(failures, set() if phase == "post_execution" else {"receipt_phase"})


if __name__ == "__main__":
    unittest.main()
