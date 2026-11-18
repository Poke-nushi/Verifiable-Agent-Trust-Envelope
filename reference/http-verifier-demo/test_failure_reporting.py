"""The HTTP consumer must persist rejection without using untrusted identities."""
import copy
from datetime import timedelta
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import http_verifier_demo as http


class HttpFailureReportingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="vate-http-report-")
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        http.generate_demo(cls.directory, policy_path=http.DEFAULT_POLICY)
        cls.scenario = cls.directory / "scenarios/allow-active"
        cls.request = json.loads((cls.scenario / "request.json").read_bytes())
        port = http.find_free_port()
        cls.url = "http://127.0.0.1:" + str(port)
        cls.server = subprocess.Popen([sys.executable, "-B", http.__file__, "serve", "--dir", str(cls.scenario),
                                       "--policy", str(http.DEFAULT_POLICY), "--host", "127.0.0.1", "--port", str(port)],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.addClassCleanup(cls.stop_server)
        http.wait_for_health(cls.url + "/healthz")

    @classmethod
    def stop_server(cls):
        cls.server.terminate()
        try:
            cls.server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.server.kill()
            cls.server.wait(timeout=5)

    def baseline(self):
        response = http.http_post_json(self.url + "/execute", self.request)
        self.assertEqual(response["decision"], "allow")
        self.assertTrue(response["verification_report"]["receipt_emitted"])
        for name in ("http-verifier-response.json", "verifier-admission-receipt.json", "verifier-admission-receipt.jws"):
            self.assertTrue((self.scenario / name).is_file())

    def assert_rejected(self, request, failed_check):
        response = http.http_post_json(self.url + "/execute", request)
        self.assertEqual(response["decision"], "deny")
        report = response["verification_report"]
        self.assertEqual(report["decision"], "deny")
        self.assertFalse(report["receipt_emitted"])
        self.assertIn(failed_check, report["failed_checks"])
        self.assertNotIn("admission_receipt", response)
        self.assertNotIn("admission_receipt_jws", response)
        self.assertEqual(json.loads((self.scenario / "http-verifier-response.json").read_bytes()), response)
        self.assertFalse((self.scenario / "verifier-admission-receipt.json").exists())
        self.assertFalse((self.scenario / "verifier-admission-receipt.jws").exists())

    def test_interrupted_save_clears_the_incomplete_receipt(self):
        self.baseline()
        response = http.read_json(self.scenario / "http-verifier-response.json")
        with patch.object(http, "write_text", side_effect=OSError("fixture write failed")), self.assertRaises(OSError):
            http.store_response_artifacts(self.scenario, response)
        for name in ("http-verifier-response.json", "verifier-admission-receipt.json", "verifier-admission-receipt.jws"):
            self.assertFalse((self.scenario / name).exists())

    def test_invalid_signatures_and_missing_kids_have_current_rejection_reports(self):
        for field, check in (("status", "status_signature"), ("passport", "passport_signature"),
                             ("runtime_proof", "runtime_proof_signature"), ("mission_permit", "mission_permit_signature")):
            for mutation in ("missing_kid", "empty_kid", "non_string_kid", "broken_token", "untrusted_payload"):
                with self.subTest(field=field, mutation=mutation):
                    self.baseline()
                    request = copy.deepcopy(self.request)
                    token = request["app_context"][field]["jws"]
                    header, payload, _, signature = http.demo.decode_compact_jws(token)
                    if mutation == "missing_kid":
                        header.pop("kid")
                    elif mutation == "empty_kid":
                        header["kid"] = ""
                    elif mutation == "non_string_kid":
                        header["kid"] = []
                    elif mutation == "untrusted_payload":
                        payload.clear()
                    token = ".".join(http.demo.b64url_encode(raw) for raw in
                                     (http.demo.canonical(header), http.demo.canonical(payload), signature))
                    request["app_context"][field]["jws"] = "not-a-jws" if mutation == "broken_token" else token
                    self.assert_rejected(request, check)

    def test_authenticated_unusable_payloads_are_reported_without_receipts(self):
        for field, name in (("status", None), ("passport", "passport"),
                            ("runtime_proof", "runtime_proof"), ("mission_permit", "permit")):
            with self.subTest(field=field):
                self.baseline()
                request = copy.deepcopy(self.request)
                spec = http.demo.ARTIFACT_SPECS[name] if name else {
                    "role": "status", "typ": http.demo.STATUS_TYP, "cty": http.demo.STATUS_CONTENT_TYPE}
                # A real signature over an empty object distinguishes shape rejection
                # from a broken compact token or a failed cryptographic check.
                request["app_context"][field]["jws"] = http.demo.build_compact_jws({},
                    key_info={"kid": spec["role"] + "-key-1", "alg": "ES256",
                              "private_key": http.demo.key_path(self.scenario, spec["role"], "private")},
                    typ=spec["typ"], cty=spec["cty"])
                self.assert_rejected(request, "verification_input")

    def test_unauthorized_signer_clears_earlier_success_and_receipts(self):
        self.baseline()
        request = copy.deepcopy(self.request)
        header, payload, _, _ = http.demo.decode_compact_jws(request["app_context"]["status"]["jws"])
        request["app_context"]["status"]["jws"] = http.demo.build_compact_jws(payload,
            key_info={"kid": "runtime-key-1", "alg": "ES256",
                      "private_key": http.demo.key_path(self.scenario, "runtime", "private")},
            typ=header["typ"], cty=header["cty"])
        self.assert_rejected(request, "status_signer_role")

    def signed_permit_request(self, change):
        request = copy.deepcopy(self.request)
        header, payload, _, _ = http.demo.decode_compact_jws(request["app_context"]["mission_permit"]["jws"])
        change(payload)
        request["app_context"]["mission_permit"]["jws"] = http.demo.build_compact_jws(payload,
            key_info={"kid": "broker-key-1", "alg": "ES256",
                      "private_key": http.demo.key_path(self.scenario, "broker", "private")},
            typ=header["typ"], cty=header["cty"])
        return request

    def test_unusable_scope_clears_previous_success_without_a_new_receipt(self):
        for change in (lambda p: p.update(actions="other:" + self.request["requested_action"]),
                       lambda p: p.pop("transaction_id")):
            with self.subTest(change=change):
                self.baseline()
                self.assert_rejected(self.signed_permit_request(change), "verification_input")

    def test_valid_scope_denials_replace_the_previous_success_receipt(self):
        for condition, expected_check in (("transaction", "permit_transaction_binding"), ("age", "permit_window")):
            with self.subTest(condition=condition):
                self.baseline()
                request = copy.deepcopy(self.request)
                if condition == "transaction":
                    request["transaction_id"] = "txn:another-operation"
                else:
                    limit = http.load_policy(http.DEFAULT_POLICY)["freshness"]["permit_max_age_seconds"]
                    request = self.signed_permit_request(lambda p: p.update(
                        issued_at=http.demo.iso(http.demo.utc_now() - timedelta(seconds=limit + 60))))
                response = http.http_post_json(self.url + "/execute", request)
                self.assertEqual(response["decision"], "deny")
                self.assertEqual(response["verification_report"]["failed_checks"], [expected_check])
                self.assertTrue(response["verification_report"]["receipt_emitted"])
                receipt = response["admission_receipt"]
                self.assertEqual(receipt["decision"], "deny")
                self.assertEqual(receipt["transaction_id"], request["transaction_id"])
                self.assertEqual(json.loads((self.scenario / "http-verifier-response.json").read_text()), response)
                self.assertEqual(json.loads((self.scenario / "verifier-admission-receipt.json").read_text()), receipt)
                token = (self.scenario / "verifier-admission-receipt.jws").read_text().strip()
                self.assertEqual(token, response["admission_receipt_jws"])
                verified = http.demo.verify_role_bound_jws(out_dir=self.scenario,
                    trust_bundle=http.read_json(self.scenario / "trust-bundle.json"), token=token,
                    expected_typ=http.demo.ARTIFACT_SPECS["receipt"]["typ"],
                    expected_cty=http.demo.ARTIFACT_SPECS["receipt"]["cty"], expected_role="verifier")
                self.assertTrue(verified["ok"])
                self.assertEqual(verified["payload"], receipt)

    def test_bad_envelopes_clear_earlier_response_and_receipts(self):
        for raw in (b"null", b"[]", b"{}", b"not-json"):
            with self.subTest(raw=raw):
                self.baseline()
                request = Request(self.url + "/execute", data=raw,
                                  headers={"Content-Type": "application/json"}, method="POST")
                with self.assertRaises(HTTPError) as caught:
                    urlopen(request, timeout=10)
                self.assertEqual(caught.exception.code, 400)
                caught.exception.close()
                for name in ("http-verifier-response.json", "verifier-admission-receipt.json", "verifier-admission-receipt.jws"):
                    self.assertFalse((self.scenario / name).exists())

    def assert_internal_error(self):
        with self.assertRaises(HTTPError) as caught:
            http.http_post_json(self.url + "/execute", self.request)
        with caught.exception as response:
            self.assertEqual(response.code, 500)
            self.assertNotIn(str(self.scenario).encode(), response.read())
        self.assertFalse((self.scenario / "verifier-admission-receipt.jws").exists())

    def test_verifier_signing_and_output_failures_return_500(self):
        self.baseline()
        key = http.demo.key_path(self.scenario, "verifier", "private")
        saved = key.with_suffix(".saved")
        key.rename(saved)
        try:
            self.assert_internal_error()
        finally:
            saved.rename(key)
        self.baseline()
        output = self.scenario / "http-verifier-response.json"
        output.unlink()
        output.mkdir()
        try:
            self.assert_internal_error()
        finally:
            output.rmdir()

    def test_registered_verification_key_failures_return_500_without_a_denial(self):
        for role, replacement in (("status", None), ("issuer", b"incomplete local key"),
                                  ("runtime", b"incomplete local key")):
            with self.subTest(role=role):
                self.baseline()
                key = http.demo.key_path(self.scenario, role, "public")
                original = key.read_bytes()
                try:
                    if replacement is None:
                        key.unlink()
                    else:
                        key.write_bytes(replacement)
                    self.assert_internal_error()
                    for name in http.RESPONSE_FILES:
                        self.assertFalse((self.scenario / name).exists())
                finally:
                    key.write_bytes(original)

    def test_registered_curve_error_retires_the_receipt_even_without_a_fingerprint(self):
        self.baseline()
        trust_path = self.scenario / "trust-bundle.json"
        self.addCleanup(trust_path.write_bytes, trust_path.read_bytes())
        trust = http.read_json(trust_path)
        entry = next(key for key in trust["keys"].values() if key["owner"] == "status")
        del entry["spki_sha256"]
        http.write_json(trust_path, trust)
        key = self.scenario / entry["public_key"]
        self.addCleanup(key.write_bytes, key.read_bytes())
        openssl = http.demo.ensure_openssl()
        keypair = subprocess.run([openssl, "ecparam", "-name", "secp384r1", "-genkey", "-noout"],
                                 capture_output=True, check=True)
        subprocess.run([openssl, "pkey", "-pubout", "-out", str(key)], input=keypair.stdout,
                       capture_output=True, check=True)
        self.assert_internal_error()
        for name in http.RESPONSE_FILES:
            self.assertFalse((self.scenario / name).exists())

    def test_restored_signing_key_must_match_the_registered_verifier(self):
        self.baseline()
        path = http.demo.key_path(self.scenario, "verifier", "private")
        original = path.read_bytes()
        try:
            path.write_bytes(http.demo.key_path(self.scenario, "issuer", "private").read_bytes())
            self.assert_internal_error()
            self.assertFalse((self.scenario / "http-verifier-response.json").exists())
        finally:
            path.write_bytes(original)
        self.baseline()

    def test_client_transport_failure_cannot_leave_earlier_success(self):
        self.baseline()
        with patch.object(http, "http_post_json", side_effect=URLError("synthetic offline service")):
            with self.assertRaises(URLError):
                http.execute_demo(self.scenario, base_url="http://127.0.0.1")
        for name in ("http-verifier-response.json", "verifier-admission-receipt.json", "verifier-admission-receipt.jws"):
            self.assertFalse((self.scenario / name).exists())


if __name__ == "__main__":
    unittest.main()
