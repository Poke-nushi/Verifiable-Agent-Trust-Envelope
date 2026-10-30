"""OpenSSL-signed controls through Node JCS/JWS and the unchanged policy/API."""
import base64
from copy import deepcopy
import io
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import jcs_recipient_trial as trial
from jcs_trial_fixtures import Fixtures


class JcsTrialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = Fixtures()
        cls.assessor = cls.fixtures.assessor()

    def assess(self, **changes):
        return self.assessor.assess(**{**self.fixtures.arguments(), **changes})

    def policy(self, change):
        policy = deepcopy(self.fixtures.policy)
        change(policy)
        return trial.encoded(policy)

    def post(self, change):
        post = json.loads(self.fixtures.post)
        change(post)
        return trial.encoded(post)

    def assert_post(self, result, signature, authority, reason=None):
        self.assertEqual(result["signatures"]["post_execution"]["status"], signature)
        self.assertEqual(result["issuer_authority"]["post_execution"]["status"], authority)
        if reason is not None:
            self.assertEqual(result["issuer_authority"]["post_execution"]["reason"], reason)

    def assert_error(self, code, function, **arguments):
        with self.assertRaises(trial.TrialError) as caught:
            function(**arguments)
        self.assertEqual(caught.exception.code, code)

    def test_openssl_signatures_verify_in_node_with_separate_results(self):
        result = self.assess()
        for kind in trial.KINDS:
            self.assertEqual(result["signatures"][kind]["status"], "verified")
            self.assertEqual(result["issuer_authority"][kind]["status"], "authorized_under_policy")
        native = self.assessor.assessor.assess_receipts(self.fixtures.admission, self.fixtures.post,
                     requested_checks=["receipt_linkage", "signatures_and_issuer_authority"])
        self.assertEqual(result["receipt_assessment"], native)
        self.assertEqual(native["native_result"]["record_linkage"], "matched")
        self.assertEqual(native["requested_checks"]["unsupported"], ["signatures_and_issuer_authority"])
        self.assertNotIn("overall", result)
        self.assertEqual(result["verifier"]["authority_source"][trial.LEGACY_PATH], trial.LEGACY_SHA)
        self.assertEqual(result["inputs"]["post"]["raw_sha256"], trial.sha(self.fixtures.post))

    def test_reformatting_verifies_and_retains_original_identity(self):
        post = json.dumps(json.loads(self.fixtures.post), indent=2).encode() + b"\n"
        result = self.assess(post=post)
        self.assert_post(result, "verified", "authorized_under_policy")
        self.assertEqual(result["signatures"]["post_execution"]["source_sha256"], trial.sha(post))
        self.assertEqual(result["receipt_assessment"]["native_result"]["record_linkage"], "matched")

    def test_tampering_not_authorized(self):
        post = self.post(lambda p: p["issuer"].update(id="urn:other"))
        self.assert_post(self.assess(post=post), "invalid", "not_assessed", "SIGNATURE_NOT_VERIFIED")

    def test_invalid_utf8_and_duplicate_json_are_invalid_inputs_not_bridge_failures(self):
        for post, reason in ((b"\xff", "JCS_INVALID_UTF8"), (b'{"a":1,"a":2}', "JCS_DUPLICATE_KEY")):
            result = self.assess(post=post)
            self.assert_post(result, "invalid", "not_assessed", "SIGNATURE_NOT_VERIFIED")
            self.assertEqual(result["signatures"]["post_execution"]["reason"], reason)

    def test_header_shape_errors_stay_invalid_through_bridge_and_authority(self):
        parts = self.fixtures.post_proof.split(b".")
        header = json.loads(base64.urlsafe_b64decode(parts[0] + b"=" * (-len(parts[0]) % 4)))
        cases = [
            (None, "invalid", "INVALID_DETACHED_JWS"),
            (["ES256"], "invalid", "INVALID_DETACHED_JWS"),
            ({key: value for key, value in header.items() if key != "typ"}, "invalid", "INVALID_DETACHED_JWS"),
            ({**header, "alg": None, "extra": True}, "invalid", "INVALID_DETACHED_JWS"),
            ({**header, "alg": "RS256"}, "not_assessed", "UNSUPPORTED_ALGORITHM"),
            ({**header, "extra": True}, "not_assessed", "UNSUPPORTED_PROTECTED_HEADER"),
        ]
        for protected, status, reason in cases:
            with self.subTest(protected=protected):
                proof = base64.urlsafe_b64encode(trial.encoded(protected)).rstrip(b"=") + b".." + parts[2]
                result = self.assess(post_proof=proof)
                self.assert_post(result, status, "not_assessed", "SIGNATURE_NOT_VERIFIED")
                self.assertEqual(result["signatures"]["post_execution"]["reason"], reason)
                self.assertIsNone(result["signatures"]["post_execution"]["canonical_sha256"])
                self.assertEqual(result["receipt_assessment"]["native_result"]["record_linkage"], "matched")

    def test_valid_signature_ungranted_issuer_role_or_key_denied(self):
        for change in (lambda p: p["issuer"].update(id="urn:other"), lambda p: p["issuer"].update(role="runtime")):
            post = self.post(change)
            self.assert_post(self.assess(post=post, post_proof=self.fixtures.sign("post_execution", post, 1)),
                             "verified", "denied", "AUTHORITY_NOT_GRANTED")
        self.assert_post(self.assess(post_proof=self.fixtures.sign("post_execution", self.fixtures.post, 2)),
                         "verified", "denied", "AUTHORITY_NOT_GRANTED")
        self.assert_post(self.assess(receiver_policy=self.policy(lambda p: p.update(grants=[]))),
                         "verified", "denied", "AUTHORITY_NOT_GRANTED")

    def test_signed_noncharacters_cannot_reach_issuer_authority(self):
        for point in (0xFDD0, 0xFDEF, 0xFFFE, 0xFFFF, 0x1FFFE, 0x10FFFF):
            post = json.loads(self.fixtures.post)
            post["annotation"] = chr(point)
            # Fixed UTF-8 signing bytes, independent of the JCS parser under test.
            canonical = json.dumps(post, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            proof = self.fixtures.sign("post_execution", canonical, 1, canonical=canonical)
            for raw in (canonical, trial.encoded(post)):
                with self.subTest(point=hex(point), escaped=raw != canonical):
                    result = self.assess(post=raw, post_proof=proof)
                    self.assert_post(result, "invalid", "not_assessed", "SIGNATURE_NOT_VERIFIED")
                    self.assertEqual(result["signatures"]["post_execution"]["reason"], "JCS_INVALID_UNICODE")
                    self.assertIsNone(result["signatures"]["post_execution"]["canonical_sha256"])
                    self.assertEqual(result["receipt_assessment"]["native_result"]["record_linkage"], "matched")

    def test_scope_mismatch_transaction_runtime_and_action(self):
        for field, value in (("transaction_id", "different-transaction"), ("runtime", "urn:other"),
                             ("action_binding", {**self.fixtures.policy["grants"][1]["action_binding"], "digest": {"alg": "sha-256", "value": "0" * 64}})):
            with self.subTest(field=field):
                self.assert_post(self.assess(receiver_policy=self.policy(lambda p: p["grants"][1].update({field: value}))),
                                 "verified", "denied", "AUTHORITY_SCOPE_MISMATCH")

    def test_expiry_future_issue_and_half_open_interval(self):
        for time, reason in (("2026-10-15T00:00:00Z", "AUTHORITY_TIME_MISMATCH"),
                             ("2026-10-12T00:00:00Z", "ISSUED_AFTER_EVALUATION_TIME")):
            self.assert_post(self.assess(receiver_policy=self.policy(lambda p: p.update(evaluation_time=time))), "verified", "denied", reason)
        instant = "2026-10-14T00:00:00.123456Z"
        post = self.post(lambda p: p.update(issued_at=instant))
        proof = self.fixtures.sign("post_execution", post, 1)
        for evaluated, expected in ((instant, "authorized_under_policy"), ("2026-10-14T00:00:00.123457Z", "denied")):
            policy = deepcopy(self.fixtures.policy)
            policy["evaluation_time"] = evaluated
            policy["grants"][1].update(valid_from=instant, valid_until="2026-10-14T00:00:00.123457Z")
            self.assert_post(self.assess(post=post, post_proof=proof, receiver_policy=trial.encoded(policy)), "verified", expected)

    def test_receiver_key_rotation(self):
        policy = self.policy(lambda p: p["grants"][1].update(key_sha256=self.fixtures.base.keys[2]["key_sha256"]))
        self.assert_post(self.assess(receiver_policy=policy), "verified", "denied")
        self.assert_post(self.assess(receiver_policy=policy, post_proof=self.fixtures.sign("post_execution", self.fixtures.post, 2)),
                         "verified", "authorized_under_policy")

    def test_unknown_key_and_missing_inputs_remain_not_assessed(self):
        policy = self.policy(lambda p: p.update(verification_keys=p["verification_keys"][:2]))
        result = self.assess(receiver_policy=policy, post_proof=self.fixtures.sign("post_execution", self.fixtures.post, 2))
        self.assert_post(result, "not_assessed", "not_assessed")
        self.assertEqual(result["signatures"]["post_execution"]["reason"], "UNKNOWN_KEY")
        for field in ("post", "post_proof"):
            self.assert_post(self.assess(**{field: None}), "not_assessed", "not_assessed")

    def test_record_kind_is_signed(self):
        proof = self.fixtures.sign("admission", self.fixtures.post, 1)
        self.assert_post(self.assess(post_proof=proof), "invalid", "not_assessed")

    def test_old_raw_proof_not_reinterpreted_as_jws(self):
        self.assert_post(self.assess(post_proof=self.fixtures.base.post_proof), "invalid", "not_assessed")

    def test_linkage_mismatch_not_hidden_by_valid_signature_and_grant(self):
        post = self.post(lambda p: p["admission"]["digest"].update(value="0" * 64))
        result = self.assess(post=post, post_proof=self.fixtures.sign("post_execution", post, 1))
        self.assert_post(result, "verified", "authorized_under_policy")
        self.assertEqual(result["receipt_assessment"]["native_result"]["record_linkage"], "mismatch")

    def test_generic_json_signature_does_not_create_supported_receipt_context(self):
        for post in (b"null", b"{}"):
            self.assert_post(self.assess(post=post, post_proof=self.fixtures.sign("post_execution", post, 1)),
                             "verified", "not_assessed", "UNSUPPORTED_RECEIPT_CONTEXT")
        post = self.post(lambda p: p.update(profile="other-profile"))
        self.assert_post(self.assess(post=post, post_proof=self.fixtures.sign("post_execution", post, 1)),
                         "verified", "not_assessed", "UNSUPPORTED_RECEIPT_CONTEXT")

    def test_jcs_valid_fractional_number_not_supported_by_authority_context(self):
        post = self.post(lambda p: p.update(annotation=1.5))
        proof = self.fixtures.sign("post_execution", post, 1, canonical=post)
        self.assert_post(self.assess(post=post, post_proof=proof), "verified", "not_assessed", "UNSUPPORTED_RECEIPT_CONTEXT")

    def test_rounded_integer_cannot_gain_authority_through_parser_difference(self):
        for value in (9007199254740992, 9007199254740993):
            post = self.post(lambda p: p.update(annotation=value))
            canonical = post.replace(str(value).encode(), b"9007199254740992")
            proof = self.fixtures.sign("post_execution", post, 1, canonical=canonical)
            self.assert_post(self.assess(post=post, post_proof=proof), "verified", "not_assessed", "UNSUPPORTED_RECEIPT_CONTEXT")

    def test_invalid_policy_and_invalid_unused_public_key_fail_closed(self):
        for policy in (b"{}", self.policy(lambda p: p.update(contract="other")), self.policy(lambda p: p.update(verification_keys=[]))):
            self.assert_error("INVALID_POLICY", self.assess, receiver_policy=policy)
        policy = deepcopy(self.fixtures.policy)
        der = base64.b64decode(policy["verification_keys"][2]["spki_der_base64"])
        der = der[:-64] + bytes(64)
        policy["verification_keys"][2] = {"key_sha256": trial.sha(der), "spki_der_base64": base64.b64encode(der).decode()}
        self.assert_error("KEY_VALIDATION_FAILED", self.assess, receiver_policy=trial.encoded(policy))

    def test_bounds_and_byte_types(self):
        for field, raw, code in (("post", b" " * (trial.LIMIT + 1), "INPUT_SIZE_ERROR"),
                                 ("post_proof", b"x" * (trial.PROOF_LIMIT + 1), "INPUT_SIZE_ERROR"),
                                 ("post", "{}", "INPUT_TYPE_ERROR"), ("receiver_policy", b"x" * (trial.POLICY_LIMIT + 1), "INPUT_SIZE_ERROR")):
            self.assert_error(code, self.assess, **{field: raw})

    def test_explicit_contract_and_runtime_pin(self):
        self.assert_error("UNKNOWN_CONTRACT", self.fixtures.assessor, expected_contract="other")
        self.assert_error("VERIFIER_CHANGED", self.fixtures.assessor, node_sha256="0" * 64)
        for timeout in (0, -1, True, math.nan, math.inf, 61):
            self.assert_error("INVALID_CONFIGURATION", self.fixtures.assessor, timeout_seconds=timeout)
        self.assert_error("INVALID_CONFIGURATION", self.fixtures.assessor, node="node")
        with patch.object(trial, "file_sha", side_effect=OSError("unreadable runtime")):
            self.assert_error("VERIFIER_UNAVAILABLE", self.assessor._check_runtime)

    def test_source_change_after_initialization_rejected(self):
        assessor = self.fixtures.assessor()
        assessor.sources[trial.BRIDGE_PATH] = "0" * 64
        self.assert_error("BRIDGE_SOURCE_CHANGED", assessor.assess, **self.fixtures.arguments())

    def test_verifier_timeout_and_error_are_not_bad_signatures(self):
        with patch.object(trial.subprocess, "run", side_effect=subprocess.TimeoutExpired("node", 10)):
            self.assert_error("VERIFIER_TIMEOUT", self.assess)
        with patch.object(trial.subprocess, "run", return_value=subprocess.CompletedProcess([], 64, b'{"error":"BRIDGE_ERROR"}', b"")):
            self.assert_error("VERIFIER_ERROR", self.assess)

    def test_corrupt_partial_or_misbound_bridge_response_rejected(self):
        real_run = subprocess.run
        mutations = [lambda r: r.update(request_sha256="0" * 64), lambda r: r["signatures"].pop("admission"),
                     lambda r: r["signatures"]["post_execution"].update(source_sha256="0" * 64),
                     lambda r: r["signatures"]["post_execution"].update(signing_input_sha256=None),
                     lambda r: r["signatures"]["post_execution"].update(key_sha256="0" * 64),
                     lambda r: r.update(validated_keys=[])]
        for change in mutations:
            def corrupt(*args, **kwargs):
                completed = real_run(*args, **kwargs)
                result = json.loads(completed.stdout)
                change(result)
                return subprocess.CompletedProcess(completed.args, completed.returncode, trial.encoded(result), completed.stderr)
            with patch.object(trial.subprocess, "run", side_effect=corrupt):
                self.assert_error("INVALID_VERIFIER_RESPONSE", self.assess)

    def test_cli_round_trip_and_regular_file_boundaries(self):
        with tempfile.TemporaryDirectory(prefix="vate-jcs-cli-test-") as directory:
            folder = Path(directory) / "inputs"
            self.fixtures.save(folder)
            command = [sys.executable, "-B", str(Path(trial.__file__)), "--trial-contract", trial.CONTRACT,
                       "--node", str(self.fixtures.node), "--node-sha256", self.fixtures.node_sha,
                       "--admission", str(folder / "admission.json"), "--post", str(folder / "post.json"),
                       "--admission-proof", str(folder / "admission.jws"), "--post-proof", str(folder / "post.jws"),
                       "--receiver-policy", str(folder / "receiver-policy.json")]
            completed = subprocess.run(command, capture_output=True, check=True, timeout=30)
            self.assertEqual(completed.stderr, b"")
            self.assert_post(json.loads(completed.stdout), "verified", "authorized_under_policy")
            (folder / "post.jws").write_bytes(self.fixtures.base.post_proof)
            completed = subprocess.run(command, capture_output=True, check=True, timeout=30)
            self.assert_post(json.loads(completed.stdout), "invalid", "not_assessed")
            fifo = Path(directory) / "fifo"
            os.mkfifo(fifo)
            self.assert_error("INPUT_FILE_ERROR", trial.read_file, path=fifo, limit=10)


class FileHashTests(unittest.TestCase):
    def test_file_hash_uses_bounded_reads_and_preserves_complete_bytes(self):
        raw = bytes(range(256)) * 9001
        case = self

        class BoundedReader(io.BytesIO):
            def read(self, size=-1):
                case.assertGreater(size, 0)
                case.assertLessEqual(size, 1024 * 1024)
                return super().read(size)

        reader = BoundedReader(raw)
        with patch.object(Path, "open", return_value=reader):
            self.assertEqual(trial.file_sha(Path("test-runtime")), trial.sha(raw))
        self.assertTrue(reader.closed)

    def test_empty_and_short_files_match_byte_digest(self):
        with tempfile.TemporaryDirectory(prefix="vate-jcs-runtime-hash-") as directory:
            path = Path(directory) / "runtime"
            for raw in (b"", b"public test runtime\x00\xff"):
                path.write_bytes(raw)
                self.assertEqual(trial.file_sha(path), trial.sha(raw))


if __name__ == "__main__":
    unittest.main()
