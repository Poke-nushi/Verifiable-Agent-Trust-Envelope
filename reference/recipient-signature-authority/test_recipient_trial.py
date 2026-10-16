"""Actual OpenSSL checks plus failure controls and unchanged native results."""
from copy import deepcopy
import base64
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import recipient_trial as trial
import run_trial
from trial_fixtures import Fixtures
sys.path.insert(0, str(trial.ROOT / "reference/runtime-support"))
from historical import historical_api, historical_root


class TrialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = Fixtures()
        cls.assessor = cls.fixtures.assessor()

    def assess(self, **changes):
        arguments = self.fixtures.arguments()
        arguments.update(changes)
        return self.assessor.assess(**arguments)

    def policy(self, change):
        policy = deepcopy(self.fixtures.policy)
        change(policy)
        return trial.encoded(policy)

    def post(self, change):
        post = json.loads(self.fixtures.post)
        change(post)
        return trial.encoded(post)

    def assert_error(self, code, function, *args, **kwargs):
        with self.assertRaises(trial.TrialError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def assert_post(self, result, signature, authority, reason=None):
        self.assertEqual(result["signatures"]["post_execution"]["status"], signature)
        self.assertEqual(result["issuer_authority"]["post_execution"]["status"], authority)
        if reason:
            self.assertEqual(result["issuer_authority"]["post_execution"]["reason"], reason)

    def test_success_has_three_separate_results_and_original_v1_unsupported(self):
        result = self.assess()
        for kind in trial.KINDS:
            self.assertEqual(result["signatures"][kind]["status"], "verified")
            self.assertEqual(result["issuer_authority"][kind]["status"], "authorized_under_policy")
            self.assertEqual(result["signatures"][kind]["native"]["returncode"], 0)
        self.assertEqual(result["receipt_assessment"]["native_result"]["record_linkage"], "matched")
        self.assertEqual(result["receipt_assessment"]["requested_checks"]["unsupported"], ["signatures_and_issuer_authority"])
        before = json.loads((trial.HERE / "BASELINE.json").read_bytes())["receipt_pair"]
        historical, frozen = historical_api(trial.ROOT)
        replay = historical.RecipientAssessor(expected_api_contract=historical.API_CONTRACT, source_root=frozen).assess_receipts(
            self.fixtures.admission, self.fixtures.post, requested_checks=["receipt_linkage", "signatures_and_issuer_authority"])
        self.assertEqual(replay, before)
        current = deepcopy(result["receipt_assessment"])
        for field in ("wrapper", "evaluator", "native_result"):
            observed_sources = current[field].pop("source_files")
            self.assertEqual(set(observed_sources), set(before[field]["source_files"]))
            self.assertEqual(observed_sources, {name: trial.sha((trial.ROOT / name).read_bytes()) for name in observed_sources})
            before[field].pop("source_files")
        self.assertEqual(trial.encoded(current), trial.encoded(before))
        self.assertNotIn("overall", result)

    def test_all_protected_sources_unchanged(self):
        before = json.loads((trial.HERE / "BASELINE.json").read_bytes())
        for relative, expected in before["protected_files"].items():
            with self.subTest(path=relative):
                self.assertEqual(trial.sha((historical_root(trial.ROOT) / relative).read_bytes()), expected)

    def test_trial_comparison_refuses_forged_or_partial_current_source_identity(self):
        current = self.assess()["receipt_assessment"]
        baseline = json.loads((trial.HERE / "BASELINE.json").read_bytes())["receipt_pair"]
        run_trial.check_current_response(current, baseline)
        for field in ("wrapper", "evaluator", "native_result"):
            for remove in (False, True):
                changed = deepcopy(current)
                name = next(iter(changed[field]["source_files"]))
                if remove:
                    del changed[field]["source_files"][name]
                else:
                    changed[field]["source_files"][name] = "0" * 64
                with self.subTest(field=field, remove=remove), self.assertRaisesRegex(AssertionError, "current source"):
                    run_trial.check_current_response(changed, baseline)

    def test_trial_comparison_refuses_semantic_change_even_with_correct_current_sources(self):
        current = self.assess()["receipt_assessment"]
        baseline = json.loads((trial.HERE / "BASELINE.json").read_bytes())["receipt_pair"]
        current["native_result"]["record_linkage"] = "mismatch"
        with self.assertRaisesRegex(AssertionError, "changed beyond verified source identities"):
            run_trial.check_current_response(current, baseline)

    def test_shipped_policy_matches_generated_fixture_policy(self):
        shipped = (trial.HERE / "receiver-policy.example.json").read_bytes()
        self.assertEqual(trial.strict_json(shipped), self.fixtures.policy)

    def test_raw_whitespace_tamper_invalid_signature_even_with_matched_linkage(self):
        result = self.assess(post=self.fixtures.post + b"\n")
        self.assert_post(result, "invalid", "not_assessed", "SIGNATURE_NOT_VERIFIED")
        self.assertEqual(result["receipt_assessment"]["native_result"]["record_linkage"], "matched")

    def test_changed_signed_content_with_old_signature(self):
        post = self.post(lambda p: p["issuer"].update(id="urn:test:someone-else"))
        self.assert_post(self.assess(post=post), "invalid", "not_assessed")

    def test_signature_with_wrong_known_key(self):
        proof = json.loads(self.fixtures.post_proof)
        proof["key_sha256"] = self.fixtures.keys[0]["key_sha256"]
        self.assert_post(self.assess(post_proof=trial.encoded(proof)), "invalid", "not_assessed")

    def test_valid_signature_unauthorized_issuer(self):
        post = self.post(lambda p: p["issuer"].update(id="urn:test:someone-else"))
        result = self.assess(post=post, post_proof=self.fixtures.sign("post_execution", post, 1))
        self.assert_post(result, "verified", "denied", "AUTHORITY_NOT_GRANTED")
        self.assertEqual(result["receipt_assessment"]["native_result"]["record_linkage"], "matched")

    def test_valid_signature_ungranted_known_key(self):
        proof = self.fixtures.sign("post_execution", self.fixtures.post, 2)
        self.assert_post(self.assess(post_proof=proof), "verified", "denied", "AUTHORITY_NOT_GRANTED")

    def test_empty_grants_denies_with_valid_signature(self):
        result = self.assess(receiver_policy=self.policy(lambda p: p.update(grants=[])))
        self.assert_post(result, "verified", "denied", "AUTHORITY_NOT_GRANTED")

    def test_policy_scope_mismatch_transaction_runtime_and_action(self):
        for field, value in (("transaction_id", "another-transaction"), ("runtime", "urn:other:runtime"),
                             ("action_binding", {**self.fixtures.policy["grants"][1]["action_binding"],
                              "digest": {"alg": "sha-256", "value": "0" * 64}})):
            with self.subTest(field=field):
                policy = self.policy(lambda p: p["grants"][1].update({field: value}))
                self.assert_post(self.assess(receiver_policy=policy), "verified", "denied", "AUTHORITY_SCOPE_MISMATCH")

    def test_valid_signatures_and_authority_do_not_mask_linkage_mismatch(self):
        post = self.post(lambda p: p["admission"]["digest"].update(value="0" * 64))
        result = self.assess(post=post, post_proof=self.fixtures.sign("post_execution", post, 1))
        self.assert_post(result, "verified", "authorized_under_policy")
        self.assertEqual(result["receipt_assessment"]["native_result"]["record_linkage"], "mismatch")

    def test_issuer_role_is_bound(self):
        post = self.post(lambda p: p["issuer"].update(role="runtime"))
        self.assert_post(self.assess(post=post, post_proof=self.fixtures.sign("post_execution", post, 1)),
                         "verified", "denied", "AUTHORITY_NOT_GRANTED")

    def test_grant_must_cover_evaluation_time_and_signed_issued_time(self):
        changes = [{"valid_until": "2026-10-13T00:00:00Z"}, {"valid_from": "2026-10-13T00:00:00Z"},
                   {"valid_from": "2026-10-14T01:00:00Z"}, {"valid_until": "2026-10-14T00:00:00Z"}]
        for change in changes:
            with self.subTest(change=change):
                self.assert_post(self.assess(receiver_policy=self.policy(lambda p: p["grants"][1].update(change))),
                                 "verified", "denied", "AUTHORITY_TIME_MISMATCH")

    def test_time_before_issuance_denied(self):
        policy = self.policy(lambda p: p.update(evaluation_time="2026-10-12T00:00:00Z"))
        self.assert_post(self.assess(receiver_policy=policy), "verified", "denied", "ISSUED_AFTER_EVALUATION_TIME")

    def test_authority_time_is_microsecond_precise_and_half_open(self):
        instant = "2026-10-14T00:00:00.123456Z"
        post = self.post(lambda p: p.update(issued_at=instant))
        proof = self.fixtures.sign("post_execution", post, 1)
        for start, end, evaluated, expected in (
            (instant, "2026-10-14T00:00:00.123457Z", instant, "authorized_under_policy"),
            (instant, "2026-10-14T00:00:00.123457Z", "2026-10-14T00:00:00.123457Z", "denied"),
            ("2026-10-14T00:00:00.123457Z", "2026-10-15T00:00:00Z", "2026-10-14T00:00:00.123457Z", "denied"),
            ("2026-10-14T00:00:00.123455Z", instant, instant, "denied"),
        ):
            policy = deepcopy(self.fixtures.policy)
            policy["evaluation_time"] = evaluated
            policy["grants"][1].update(valid_from=start, valid_until=end)
            with self.subTest(start=start, end=end, evaluated=evaluated):
                self.assert_post(self.assess(post=post, post_proof=proof, receiver_policy=trial.encoded(policy)),
                                 "verified", expected)

    def test_authority_accepts_one_to_six_fractional_digits_without_rounding(self):
        for digits, micros in (("1", 100000), ("12", 120000), ("123", 123000),
                               ("1234", 123400), ("12345", 123450), ("123456", 123456)):
            instant = "2026-10-14T00:00:00." + digits + "Z"
            post = self.post(lambda p: p.update(issued_at=instant))
            policy = deepcopy(self.fixtures.policy)
            policy["evaluation_time"] = instant
            policy["grants"][1].update(valid_from=instant)
            with self.subTest(digits=digits):
                self.assertEqual(trial.timestamp(instant).microsecond, micros)
                self.assert_post(self.assess(post=post, post_proof=self.fixtures.sign("post_execution", post, 1),
                                            receiver_policy=trial.encoded(policy)),
                                 "verified", "authorized_under_policy")

    def test_receiver_policy_rotation_and_revocation_are_separate_from_signature(self):
        policy = self.policy(lambda p: p["grants"][1].update(key_sha256=self.fixtures.keys[2]["key_sha256"]))
        self.assert_post(self.assess(receiver_policy=policy), "verified", "denied", "AUTHORITY_NOT_GRANTED")
        result = self.assess(receiver_policy=policy, post_proof=self.fixtures.sign("post_execution", self.fixtures.post, 2))
        self.assert_post(result, "verified", "authorized_under_policy")

    def test_unknown_key_not_fetched_or_treated_as_bad_signature(self):
        proof = json.loads(self.fixtures.post_proof)
        proof["key_sha256"] = "0" * 64
        result = self.assess(post_proof=trial.encoded(proof))
        self.assert_post(result, "not_assessed", "not_assessed")
        self.assertEqual(result["signatures"]["post_execution"]["reason"], "KEY_NOT_IN_RECEIVER_KEYRING")
        self.assertIsNone(result["signatures"]["post_execution"]["native"])

    def test_missing_receipt_remains_not_assessed(self):
        result = self.assess(post=None)
        self.assert_post(result, "not_assessed", "not_assessed")
        self.assertEqual(result["receipt_assessment"]["native_result"]["record_linkage"], "not_assessed")
        self.assertFalse(result["inputs"]["post"]["supplied"])

    def test_missing_proof_leaves_linkage_result(self):
        result = self.assess(post_proof=None)
        self.assert_post(result, "not_assessed", "not_assessed")
        self.assertEqual(result["receipt_assessment"]["native_result"]["record_linkage"], "matched")

    def test_domain_separates_receipt_kinds(self):
        proof = self.fixtures.sign("admission", self.fixtures.post, 1)
        self.assert_post(self.assess(post_proof=proof), "invalid", "not_assessed")

    def test_unsigned_or_embedded_key_or_algorithm_override_not_supported(self):
        original = json.loads(self.fixtures.post_proof)
        for change in ({"contract": "JWS"}, {"alg": "none"}, {"public_key_url": "https://invalid.example/key"},
                       {"signature_base64": ""}, {"signature_base64": original["signature_base64"] + "\n"}):
            with self.subTest(change=change):
                result = self.assess(post_proof=trial.encoded({**original, **change}))
                self.assert_post(result, "not_assessed", "not_assessed")
                self.assertEqual(result["signatures"]["post_execution"]["reason"], "INVALID_PROOF")

    def test_signed_malformed_json_has_no_authority(self):
        for raw in (b"{", b'{"receipt_type":"post_execution","receipt_type":"admission"}', b"{}", b"null"):
            with self.subTest(raw=raw):
                result = self.assess(post=raw, post_proof=self.fixtures.sign("post_execution", raw, 1))
                self.assert_post(result, "verified", "not_assessed", "UNSUPPORTED_RECEIPT_CONTEXT")
                self.assertNotEqual(result["receipt_assessment"]["native_result"]["record_linkage"], "matched")

    def test_wrong_receipt_kind_or_proof_format_not_silently_reinterpreted(self):
        for change in ({"receipt_type": "admission"}, {"proof": {"format": "jws"}}, {"profile": "other-profile"}):
            with self.subTest(change=change):
                raw = self.post(lambda p: p.update(change))
                self.assert_post(self.assess(post=raw, post_proof=self.fixtures.sign("post_execution", raw, 1)),
                                 "verified", "not_assessed", "UNSUPPORTED_RECEIPT_CONTEXT")

    def test_invalid_binding_context_not_used_for_authority(self):
        raw = self.post(lambda p: p["execution"].update(effective_request_hash="sha-256:" + "0" * 64))
        self.assert_post(self.assess(post=raw, post_proof=self.fixtures.sign("post_execution", raw, 1)),
                         "verified", "not_assessed", "UNSUPPORTED_RECEIPT_CONTEXT")

    def test_invalid_policy_fails_before_receipt_assessment(self):
        mutations = [lambda p: p.update(contract="other"), lambda p: p.update(evaluation_time="yesterday"),
                     lambda p: p.update(verification_keys=[]), lambda p: p.update(grants=True),
                     lambda p: p["verification_keys"].append(p["verification_keys"][0]),
                     lambda p: p["verification_keys"][0].update(key_sha256="0" * 64),
                     lambda p: p["grants"][0].update(runtime=True),
                     lambda p: p["grants"][0].update(valid_until=p["grants"][0]["valid_from"]),
                     lambda p: p["verification_keys"][0].update(spki_der_base64=base64.b64encode(b"x" * 44).decode())]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_error("INVALID_POLICY", self.assess, receiver_policy=self.policy(mutation))
        self.assert_error("INVALID_POLICY", self.assess, receiver_policy=b'{"contract":1,"contract":2}')
        self.assert_error("INVALID_POLICY", self.assess, receiver_policy=b'{"n":1.0}')

    def test_input_bounds_and_types(self):
        for field, value, code in (("post", "{}", "INPUT_TYPE_ERROR"), ("post", b"x" * (trial.LIMIT + 1), "INPUT_SIZE_ERROR"),
                                   ("post_proof", b"x" * (trial.PROOF_LIMIT + 1), "INPUT_SIZE_ERROR"),
                                   ("receiver_policy", b"x" * (trial.POLICY_LIMIT + 1), "INPUT_SIZE_ERROR")):
            with self.subTest(field=field):
                self.assert_error(code, self.assess, **{field: value})

    def test_backend_failure_is_not_signature_invalid(self):
        actual = self.assessor._process
        for code, stdout, stderr in ((1, b"", b"could not open key"), (0, b"unexpected", b""),
                                     (-9, b"", b""), (1, b"Signature Verification Failure\n", b"provider error")):
            def selected(arguments):
                return subprocess.CompletedProcess([], code, stdout, stderr) if arguments[0] == "pkeyutl" else actual(arguments)
            with self.subTest(code=code, stderr=stderr), patch.object(self.assessor, "_process", side_effect=selected):
                result = self.assess()
                self.assert_post(result, "error", "not_assessed")
                self.assertEqual(result["signatures"]["post_execution"]["reason"], "VERIFIER_EXECUTION_ERROR")

    def test_observed_openssl_mismatch_diagnostics_preserve_error_boundary(self):
        # Captured from OpenSSL 3.5.5 on Linux; the source path differs from
        # the OpenSSL builds used by the Mac controls.
        diagnostic = (b"40A7B4B7897A0000:error:030000EA:digital envelope routines:EVP_DigestVerifyFinal:"
                      b"provider signature failure:../crypto/evp/m_sigver.c:701:ECDSA digest_verify_final:\n")
        failure = b"Signature Verification Failure\n"
        controls = [
            (1, failure, b"", "invalid"),
            (1, failure, diagnostic, "invalid"),
            (1, failure, diagnostic.replace(b"../crypto/", b"crypto/"), "invalid"),
            (1, failure, diagnostic + b"other provider failure\n", "error"),
            (1, failure, diagnostic.replace(b"030000EA", b"03000086"), "error"),
            (1, failure, diagnostic.replace(b"EVP_DigestVerifyFinal", b"EVP_DigestVerifyInit"), "error"),
            (1, failure, diagnostic.replace(b"ECDSA", b"RSA"), "error"),
            (1, failure, diagnostic.replace(b"../crypto/", b"unknown/crypto/"), "error"),
            (1, failure, diagnostic.replace(b"m_sigver.c", b"m_sigverXc"), "error"),
            (2, failure, diagnostic, "error"),
            (1, b"Signature Verified Successfully\n", diagnostic, "error"),
        ]
        policy, keys, evaluation = trial.policy_from(trial.encoded(self.fixtures.policy))
        for code, stdout, stderr, expected in controls:
            with self.subTest(code=code, stderr=stderr, stdout=stdout), patch.object(
                    self.assessor, "_process", return_value=subprocess.CompletedProcess([], code, stdout, stderr)):
                result = self.assessor._signature("post_execution", self.fixtures.post, self.fixtures.post_proof, keys)
                self.assertEqual(result["status"], expected)
                self.assertEqual(base64.b64decode(result["native"]["stdout_base64"]), stdout)
                self.assertEqual(base64.b64decode(result["native"]["stderr_base64"]), stderr)
                authority = trial.assess_authority("post_execution", self.fixtures.post, result, policy, evaluation)
                self.assertEqual(authority["status"], "not_assessed")

    def test_openssl_timeout_leaves_receipt_worker_timeout_separate(self):
        actual = trial.subprocess.run
        openssl_timeouts, worker_timeouts = [], []
        worker = str(trial.ROOT / "reference/recipient-assessment/_worker.py")

        def observe_timeout(command, **kwargs):
            if command[0] == str(self.fixtures.openssl):
                openssl_timeouts.append((command[1], kwargs["timeout"]))
            elif command[-1] == worker:
                worker_timeouts.append(kwargs["timeout"])
            return actual(command, **kwargs)

        with patch.object(trial.subprocess, "run", side_effect=observe_timeout):
            assessor = trial.RecipientTrial(expected_contract=trial.CONTRACT,
                openssl=self.fixtures.openssl, openssl_sha256=self.fixtures.binary_sha256,
                timeout_seconds=5.0)
            result = assessor.assess(**self.fixtures.arguments())
        self.assertEqual({name for name, _ in openssl_timeouts}, {"version", "pkey", "pkeyutl"})
        self.assertTrue(all(timeout == 5.0 for _, timeout in openssl_timeouts))
        self.assertEqual(worker_timeouts, [30.0])
        self.assertEqual(trial.encoded(result), trial.encoded(self.assess()))

    def test_backend_timeout_is_not_signature_invalid(self):
        actual = trial.subprocess.run
        def timeout_for_openssl(command, **kwargs):
            if command[0] == str(self.fixtures.openssl) and command[1] == "pkeyutl":
                raise subprocess.TimeoutExpired(command, 10, output=b"partial stdout\xff", stderr=b"partial stderr\xfe")
            return actual(command, **kwargs)
        with patch.object(trial.subprocess, "run", side_effect=timeout_for_openssl):
            result = self.assess()
            self.assert_post(result, "error", "not_assessed")
            self.assertEqual(result["signatures"]["post_execution"]["reason"], "VERIFIER_TIMEOUT")
            native = result["signatures"]["post_execution"]["native"]
            self.assertFalse(native["complete"])
            self.assertIsNone(native["returncode"])
            self.assertEqual(base64.b64decode(native["stdout_base64"]), b"partial stdout\xff")
            self.assertEqual(base64.b64decode(native["stderr_base64"]), b"partial stderr\xfe")

    def test_curve_oid_and_ed25519_identity_key_rejected(self):
        valid = base64.b64decode(self.fixtures.keys[1]["spki_der_base64"])
        for der in (bytes.fromhex("302a300506032b6570032100") + bytes([1]) + bytes(31),
                    valid[:22] + bytes([8]) + valid[23:], valid[:-1], valid + b"\x00"):
            policy = deepcopy(self.fixtures.policy)
            old = policy["verification_keys"][1]["key_sha256"]
            key = trial.sha(der)
            policy["verification_keys"][1] = {"key_sha256": key, "spki_der_base64": base64.b64encode(der).decode()}
            policy["grants"][1]["key_sha256"] = key
            with self.subTest(length=len(der)):
                self.assert_error("INVALID_POLICY", self.assess, receiver_policy=trial.encoded(policy))

    def test_off_curve_point_rejected_by_openssl_before_authority(self):
        for point in (bytes(64), b"\xff" * 64):
            der = trial.SPKI_PREFIX + point
            key = trial.sha(der)
            policy = deepcopy(self.fixtures.policy)
            policy["verification_keys"][1] = {"key_sha256": key, "spki_der_base64": base64.b64encode(der).decode()}
            policy["grants"][1]["key_sha256"] = key
            with self.subTest(point=point[:1]), self.assertRaises(trial.TrialError) as caught:
                self.assess(receiver_policy=trial.encoded(policy))
            self.assertEqual(caught.exception.code, "KEY_VALIDATION_FAILED")
            self.assertNotEqual(caught.exception.native["returncode"], 0)

    def test_key_validation_error_or_timeout_never_returns_authority(self):
        for failure in (subprocess.CompletedProcess([], 1, b"", b"backend failure"),
                        subprocess.CompletedProcess([], 0, b"unexpected", b"")):
            with patch.object(self.assessor, "_process", return_value=failure):
                self.assert_error("KEY_VALIDATION_FAILED", self.assess)
        with patch.object(self.assessor, "_process", side_effect=trial.TrialError("VERIFIER_TIMEOUT", "key check timeout")):
            self.assert_error("VERIFIER_TIMEOUT", self.assess)

    def test_signature_der_parse_failure_never_authorizes(self):
        proof = json.loads(self.fixtures.post_proof)
        proof["signature_base64"] = base64.b64encode(b"x" * 70).decode()
        result = self.assess(post_proof=trial.encoded(proof))
        self.assertNotEqual(result["signatures"]["post_execution"]["status"], "verified")
        self.assertEqual(result["issuer_authority"]["post_execution"]["status"], "not_assessed")

    def test_actual_timeout_keeps_partial_bytes(self):
        # Allow normal interpreter startup; the deliberate delay must exceed it.
        # A pinned fake executable exercises process failure, not cryptography.
        with tempfile.TemporaryDirectory() as directory:
            backend = Path(directory) / "timeout-backend"
            backend.write_text("#!" + sys.executable + "\n" +
                "import sys,time\n" +
                "if sys.argv[1]=='version': print('OpenSSL 4.0.3 synthetic failure control')\n" +
                "elif sys.argv[1]=='pkey': print('Key is valid')\n" +
                "else:\n sys.stdout.buffer.write(b'partial-out\\xff');sys.stdout.flush()\n" +
                " sys.stderr.buffer.write(b'partial-err\\xfe');sys.stderr.flush()\n time.sleep(10)\n")
            backend.chmod(0o700)
            assessor = trial.RecipientTrial(expected_contract=trial.CONTRACT, openssl=backend,
                         openssl_sha256=trial.sha(backend.read_bytes()), timeout_seconds=2)
            result = assessor.assess(**self.fixtures.arguments())
            for signature in result["signatures"].values():
                self.assertEqual(signature["reason"], "VERIFIER_TIMEOUT")
                self.assertFalse(signature["native"]["complete"])
                self.assertEqual(base64.b64decode(signature["native"]["stdout_base64"]), b"partial-out\xff")
                self.assertEqual(base64.b64decode(signature["native"]["stderr_base64"]), b"partial-err\xfe")

    def test_postflight_binary_change_keeps_process_output(self):
        with patch.object(self.assessor, "_binary_check", side_effect=[None, trial.TrialError("VERIFIER_CHANGED", "synthetic change")]):
            with self.assertRaises(trial.TrialError) as caught:
                self.assessor._process(["version"])
        self.assertEqual(caught.exception.code, "VERIFIER_CHANGED")
        self.assertEqual(caught.exception.native["returncode"], 0)
        self.assertTrue(caught.exception.native["complete"])
        self.assertTrue(caught.exception.native["stdout"].startswith("OpenSSL "))

    def test_source_pin_drift_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "reference/recipient-assessment"
            folder.mkdir(parents=True)
            for name in trial.API_PINS:
                raw = (trial.ROOT / "reference/recipient-assessment" / name).read_bytes()
                (folder / name).write_bytes(raw + (b"\n" if name == "vate_recipient.py" else b""))
            self.assert_error("API_SOURCE_MISMATCH", trial.RecipientTrial, expected_contract=trial.CONTRACT,
                openssl=self.fixtures.openssl, openssl_sha256=self.fixtures.binary_sha256, source_root=root)

    def test_binary_pin_required_before_execution(self):
        self.assert_error("VERIFIER_CHANGED", trial.RecipientTrial, expected_contract=trial.CONTRACT,
                          openssl=self.fixtures.openssl, openssl_sha256="0" * 64)

    def test_unknown_contract_and_invalid_timeout(self):
        arguments = {"expected_contract": trial.CONTRACT, "openssl": self.fixtures.openssl,
                     "openssl_sha256": self.fixtures.binary_sha256}
        self.assert_error("UNKNOWN_CONTRACT", trial.RecipientTrial, **{**arguments, "expected_contract": "new"})
        for timeout in (True, 0, -1, float("nan"), float("inf"), 61, 10 ** 10000):
            with self.subTest(type=type(timeout)):
                self.assert_error("INVALID_CONFIGURATION", trial.RecipientTrial, **arguments, timeout_seconds=timeout)

    def test_cli_roundtrip_and_exit_zero_only_means_report_returned(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory) / "fixtures"
            self.fixtures.save(folder)
            command = [sys.executable, "-I", "-B", str(trial.HERE / "recipient_trial.py"),
                       "--trial-contract=" + trial.CONTRACT, "--openssl=" + str(self.fixtures.openssl),
                       "--openssl-sha256=" + self.fixtures.binary_sha256]
            policy_path = trial.HERE / "receiver-policy.example.json"
            command.append("--receiver-policy=" + str(policy_path))
            for name in ("admission", "post", "admission-proof", "post-proof"):
                command.append("--" + name + "=" + str(folder / (name + ".json")))
            result = subprocess.run(command, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            expected = self.assess(receiver_policy=policy_path.read_bytes())
            self.assertEqual(trial.encoded(json.loads(result.stdout)), trial.encoded(expected))
            (folder / "post.json").write_bytes(self.fixtures.post + b"\n")
            changed = subprocess.run(command, capture_output=True, timeout=30)
            self.assertEqual(changed.returncode, 0)
            self.assert_post(json.loads(changed.stdout), "invalid", "not_assessed")

    def test_cli_errors_are_structured(self):
        command = [sys.executable, "-I", "-B", str(trial.HERE / "recipient_trial.py")]
        result = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 64)
        self.assertEqual(json.loads(result.stdout)["error"]["code"], "CLI_USAGE_ERROR")
        self.assertEqual(result.stderr, b"")


if __name__ == "__main__":
    unittest.main()
