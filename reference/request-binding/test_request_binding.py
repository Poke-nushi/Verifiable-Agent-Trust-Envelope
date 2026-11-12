"""Adversarial preimage tests; digest-consistent mutations must still fail."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import example
import request_binding as binding
from request_binding import (
    CONTRACT, Invalid, admit_bound, assess_request_binding, core, decode, digest,
    encode, object_hash, reference,
)


class RequestBindingTests(unittest.TestCase):
    def setUp(self):
        self.original, self.request, self.policy = example.inputs()
        self.verifier = core.VateVerifier(verifier_id="did:web:verifier.example", policy=self.policy)
        self.bound = admit_bound(self.verifier, encode(self.request), encode(self.original),
                                 now=core.parse_time(example.EVALUATED_AT))
        self.receipt = decode(self.bound.receipt)
        self.effective = decode(self.bound.effective)

    def assess(self, *, rehash_effective=False):
        # Update every raw reference (and optionally the effective object hash),
        # so semantic failures are not incidental broken outer checksums.
        objects = {"original_ref": self.original, "admission_request_ref": self.request,
                   "effective_ref": self.effective}
        artifacts = {}
        for key, value in objects.items():
            raw = encode(value)
            ref = reference(raw)
            self.receipt["request_binding"][key] = ref
            artifacts[ref["uri"]] = raw
        if rehash_effective:
            self.receipt["attenuation"]["effective_request_hash"] = object_hash(self.effective)
            self.receipt["request"]["action_binding"] = binding.action_binding(self.effective)
        return assess_request_binding(encode(self.receipt), artifacts,
                                      expected_admission_request_ref=reference(encode(self.request)))

    def expect_failure(self, cause, *, rehash_effective=False):
        report = self.assess(rehash_effective=rehash_effective)
        self.assertFalse(report["pass"])
        self.assertFalse(report["binding_requirement_met"])
        self.assertFalse(report["decision_allows_immediate_execution"])
        self.assertIn(cause, [check.get("cause") for check in report["checks"]])

    def issue(self, *, cap="120.00", purchase="24.50", now=example.EVALUATED_AT, require_new_permit=False, policy=None):
        original, request, default_policy = example.inputs(cap=cap, purchase=purchase)
        selected_policy = policy if policy is not None else default_policy
        request["evidence_refs"][0].update(uri=selected_policy.get("policy_ref", "local"),
                                             digest=digest(encode(selected_policy)))
        verifier = core.VateVerifier(verifier_id="did:web:verifier.example", policy=selected_policy)
        return admit_bound(verifier, encode(request), encode(original), now=core.parse_time(now),
                           require_new_permit=require_new_permit)

    def test_attenuate_retains_original_summary(self):
        self.assertEqual(self.receipt["request"]["constraints"]["max_amount"]["value"], "120.00")
        self.assertEqual(self.effective["constraints"]["max_amount"]["value"], "25.00")
        self.assertEqual(self.effective["payload"]["amount"]["value"], "24.50")
        self.assertEqual(self.receipt["request"]["input_hash"], self.receipt["attenuation"]["original_request_hash"])
        self.assertNotEqual(self.receipt["attenuation"]["original_request_hash"], self.receipt["attenuation"]["effective_request_hash"])
        self.assertTrue(self.assess()["binding_requirement_met"])

    def test_allow(self):
        result = self.issue(cap="25.00")
        self.assertEqual(decode(result.receipt)["decision"]["outcome"], "allow")
        self.assertEqual(decode(result.original), decode(result.effective))
        self.assertTrue(decode(result.assessment)["binding_requirement_met"])

    def test_exact_cap_is_allowed(self):
        result = self.issue(purchase="25.00")
        self.assertTrue(decode(result.assessment)["decision_allows_immediate_execution"])

    def test_payload_above_effective_cap_is_denied(self):
        for purchase in ("25.01", "120.00"):
            with self.subTest(purchase=purchase):
                result = self.issue(purchase=purchase)
                self.assertEqual(decode(result.receipt)["decision"]["outcome"], "deny")
                self.assertIsNone(result.effective)
                self.assertTrue(decode(result.assessment)["binding_requirement_met"])
                self.assertFalse(decode(result.assessment)["decision_allows_immediate_execution"])

    def test_expired_denial_does_not_require_effective(self):
        result = self.issue(now="2026-11-12T01:00:00Z")
        self.assertEqual(decode(result.receipt)["decision"]["reason_codes"][0], "PERMIT_EXPIRED")
        self.assertNotIn("effective_ref", decode(result.receipt)["request_binding"])
        self.assertTrue(decode(result.assessment)["pass"])

    def test_new_permit_blocks_immediate_execution(self):
        result = self.issue(require_new_permit=True)
        report = decode(result.assessment)
        self.assertTrue(report["pass"])
        self.assertFalse(report["decision_allows_immediate_execution"])
        receipt = decode(result.receipt)
        linked = self.verifier.validate_post_execution_linkage(receipt, example.synthetic_post(receipt))
        self.assertIn("POST_EXEC_ADMISSION_DENIED", linked["reason_codes"])

    def test_core_validation_and_replay_run_once(self):
        class Counted(core.VateVerifier):
            calls = 0
            def _validate_admission_request(self, request, *, now):
                self.calls += 1
                return super()._validate_admission_request(request, now=now)
        verifier = Counted(verifier_id="urn:verifier", policy=self.policy)
        first = admit_bound(verifier, encode(self.request), encode(self.original), now=core.parse_time(example.EVALUATED_AT))
        self.assertEqual(verifier.calls, 1)
        self.assertEqual(decode(first.receipt)["decision"]["outcome"], "attenuate")
        second = admit_bound(verifier, encode(self.request), encode(self.original), now=core.parse_time(example.EVALUATED_AT))
        self.assertEqual(verifier.calls, 2)
        self.assertIn("REPLAY_DETECTED", decode(second.receipt)["decision"]["reason_codes"])

    def test_bad_original_does_not_consume_replay_state(self):
        request = copy.deepcopy(self.request)
        request["input_hash"] = "sha-256:" + "0" * 64
        verifier = core.VateVerifier(verifier_id="urn:verifier", policy=self.policy)
        with self.assertRaisesRegex(Invalid, "INPUT_HASH_MISMATCH"):
            admit_bound(verifier, encode(request), encode(self.original), now=core.parse_time(example.EVALUATED_AT))
        self.assertEqual(verifier._seen_request_ids, set())

    def test_unknown_policy_is_rejected(self):
        policy = {**self.policy, "undeclared_privilege": True}
        with self.assertRaisesRegex(Invalid, "SCHEMA_INVALID"):
            self.issue(policy=policy)

    def test_legacy_api_preserved_and_binding_not_checked(self):
        receipt = decode(self.bound.core_result)["admission_receipt"]
        effective_wrapper = core.set_amount(self.request, "USD", binding.Decimal("25.00"))
        self.assertEqual(receipt["attenuation"]["original_request_hash"], core.canonical_hash(self.request))
        self.assertEqual(receipt["attenuation"]["effective_request_hash"], core.canonical_hash(effective_wrapper))
        report = assess_request_binding(encode(receipt), {}, expected_admission_request_ref=reference(self.bound.request))
        self.assertIsNone(report["pass"])
        self.assertFalse(report["binding_requirement_met"])

    def test_stripping_binding_cannot_downgrade(self):
        del self.receipt["request_binding"]
        report = assess_request_binding(encode(self.receipt), {}, required_contract=CONTRACT)
        self.assertIsNone(report["pass"])
        self.assertFalse(report["binding_requirement_met"])
        self.assertIn("BINDING_NOT_DECLARED", [c.get("cause") for c in report["checks"]])

    def test_unknown_profiles_are_not_checked(self):
        for key in ("contract", "preimage_profile", "canonicalization", "transformation_profile"):
            with self.subTest(key=key):
                receipt = decode(self.bound.receipt)
                receipt["request_binding"][key] = "unknown"
                report = assess_request_binding(encode(receipt), {})
                self.assertIsNone(report["pass"])
                self.assertFalse(report["binding_requirement_met"])
        self.assertFalse(assess_request_binding(self.bound.receipt, {}, required_contract="future")["binding_requirement_met"])

    def test_receiver_pin_is_required(self):
        report = assess_request_binding(self.bound.receipt, {})
        self.assertIsNone(report["pass"])
        self.assertFalse(report["binding_requirement_met"])
        report = assess_request_binding(self.bound.receipt, {}, expected_admission_request_ref=reference(b"{}"))
        self.assertIs(report["pass"], False)
        self.assertIn("ADMISSION_REFERENCE_MISMATCH", [c.get("cause") for c in report["checks"]])

    def test_invalid_api_arguments_are_rejected(self):
        for requirement in ("", None, [], 1):
            with self.subTest(requirement=requirement):
                with self.assertRaisesRegex(Invalid, "SCHEMA_INVALID"):
                    assess_request_binding(self.bound.receipt, {}, required_contract=requirement)
        with self.assertRaisesRegex(Invalid, "SCHEMA_INVALID"):
            assess_request_binding("{}", {})
        with self.assertRaisesRegex(Invalid, "SCHEMA_INVALID"):
            assess_request_binding(b"{}", [])

    def test_missing_artifact_is_not_checked(self):
        report = assess_request_binding(self.bound.receipt, {}, expected_admission_request_ref=reference(self.bound.request))
        self.assertIsNone(report["pass"])
        self.assertIn("ARTIFACT_NOT_SUPPLIED", [c.get("cause") for c in report["checks"]])

    def test_changed_raw_bytes_fail_digest(self):
        original_ref = reference(self.bound.original)
        report = assess_request_binding(self.bound.receipt, {original_ref["uri"]: self.bound.original + b" "},
                                         expected_admission_request_ref=reference(self.bound.request))
        self.assertIs(report["pass"], False)
        self.assertIn("DIGEST_MISMATCH", [c.get("cause") for c in report["checks"]])

    def test_json_whitespace_and_key_order(self):
        original = json.dumps(self.original, ensure_ascii=False, indent=2).encode()
        self.assertEqual(object_hash(decode(original)), object_hash(self.original))
        self.assertNotEqual(digest(original), digest(self.bound.original))
        verifier = core.VateVerifier(verifier_id="urn:verifier", policy=self.policy)
        result = admit_bound(verifier, self.bound.request, original, now=core.parse_time(example.EVALUATED_AT))
        self.assertTrue(decode(result.assessment)["pass"])

    def test_existing_canonical_bytes_with_nonascii(self):
        value = {"z": "é", "a": "購入"}
        fixed = b'{"a":"\\u8cfc\\u5165","z":"\\u00e9"}'
        self.assertEqual(encode(value), fixed)
        self.assertEqual(object_hash(value), "sha-256:" + hashlib.sha256(fixed).hexdigest())
        self.assertEqual(encode(value), core.canonical_bytes(value))

    def test_fixed_operation_hashes(self):
        self.assertEqual(object_hash(self.original),
                         "sha-256:c1a39c783270b8ef7dd21dbb9bf436e125f62a5b3adf6f53ae4dc07ed46d027b")
        self.assertEqual(object_hash(self.effective),
                         "sha-256:702626db18f74a4e128e3abe56be3f9bda42affaa7c23a8cfa25177ff568d1e4")

    def test_malformed_evidence_types_return_assessment(self):
        for bad in ([], {}, True, None, 23):
            with self.subTest(evidence_type=bad):
                self.request = decode(self.bound.request)
                self.request["evidence_refs"][0]["type"] = bad
                self.expect_failure("SCHEMA_INVALID")
                verifier = core.VateVerifier(verifier_id="urn:verifier", policy=self.policy)
                with self.assertRaisesRegex(Invalid, "SCHEMA_INVALID"):
                    admit_bound(verifier, encode(self.request), self.bound.original,
                                now=core.parse_time(example.EVALUATED_AT))
                self.assertEqual(verifier._seen_request_ids, set())

    def test_naive_evaluation_time_is_rejected(self):
        with self.assertRaisesRegex(Invalid, "INVALID_EVALUATION_TIME"):
            admit_bound(self.verifier, self.bound.request, self.bound.original,
                        now=core.parse_time(example.EVALUATED_AT).replace(tzinfo=None))

    def test_strict_json_rejections(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":1.0}', b'{"a":NaN}', b'{"a":Infinity}',
                    b'{"a":9007199254740992}', b'{"a":"\\ud800"}', b'\xff', b'[]' * 20,
                    b'[' * 70 + b'0' + b']' * 70, b' ' * (binding.MAX_BYTES + 1)):
            with self.subTest(raw=raw[:60]):
                with self.assertRaises(Invalid):
                    decode(raw)

    def test_amount_types_and_unknown_constraints(self):
        for bad in (True, 25, "-1", "NaN", "1e2", "01", "0.000000001"):
            with self.subTest(amount=bad):
                self.effective = decode(self.bound.effective)
                self.effective["constraints"]["max_amount"]["value"] = bad
                self.expect_failure("INVALID_DECIMAL_AMOUNT")
        self.effective = decode(self.bound.effective)
        self.effective["constraints"]["new_privilege"] = True
        self.expect_failure("SCHEMA_INVALID")

    def test_original_hash_mismatch(self):
        self.receipt["attenuation"]["original_request_hash"] = "sha-256:" + "0" * 64
        self.expect_failure("ORIGINAL_HASH_MISMATCH")

    def test_effective_hash_mismatch(self):
        self.receipt["attenuation"]["effective_request_hash"] = "sha-256:" + "0" * 64
        self.expect_failure("EFFECTIVE_HASH_MISMATCH")

    def test_input_hash_mismatch(self):
        self.request["input_hash"] = "sha-256:" + "0" * 64
        self.expect_failure("INPUT_HASH_MISMATCH")

    def test_receipt_input_hash_mismatch(self):
        self.receipt["request"]["input_hash"] = "sha-256:" + "0" * 64
        self.expect_failure("RECEIPT_REQUEST_MISMATCH")

    def test_from_mismatch(self):
        for bad in ("119.00", 120, True):
            with self.subTest(value=bad):
                self.receipt["attenuation"]["changes"][0]["from"] = bad
                self.expect_failure("ATTENUATION_FROM_MISMATCH")

    def test_noop_and_widening_rejected_with_consistent_hashes(self):
        for value in ("120.00", "121.00"):
            with self.subTest(value=value):
                self.effective["constraints"]["max_amount"]["value"] = value
                self.receipt["attenuation"]["changes"][0]["to"] = value
                self.receipt["attenuation"]["effective_constraints"] = copy.deepcopy(self.effective["constraints"])
                self.expect_failure("CONSTRAINT_NOT_NARROWED", rehash_effective=True)

    def test_other_fields_cannot_change_with_consistent_hashes(self):
        for key in ("currency", "target", "payload", "tool_allowlist", "operation_id"):
            with self.subTest(key=key):
                self.effective = decode(self.bound.effective)
                if key == "currency":
                    self.effective["constraints"]["max_amount"]["currency"] = "EUR"
                elif key == "target":
                    self.effective["target"]["resource"] = "https://other.example/checkout"
                elif key == "payload":
                    self.effective["payload"]["amount"]["value"] = "20.00"
                elif key == "operation_id":
                    self.effective["operation_id"] = "other-operation"
                else:
                    self.effective["constraints"]["tool_allowlist"].append("merchant.cancel")
                self.expect_failure("EFFECTIVE_RECONSTRUCTION_MISMATCH", rehash_effective=True)

    def test_effective_constraints_must_match(self):
        self.receipt["attenuation"]["effective_constraints"]["max_amount"]["value"] = "1000.00"
        self.expect_failure("EFFECTIVE_CONSTRAINTS_MISMATCH")

    def test_payload_over_cap_with_all_hashes_recomputed(self):
        self.original["payload"]["amount"]["value"] = "120.00"
        self.effective["payload"]["amount"]["value"] = "120.00"
        self.request["input_hash"] = object_hash(self.original)
        self.receipt["request"]["input_hash"] = object_hash(self.original)
        self.receipt["attenuation"]["original_request_hash"] = object_hash(self.original)
        self.expect_failure("PAYLOAD_EXCEEDS_CONSTRAINTS", rehash_effective=True)

    def test_unlisted_tool_fails(self):
        self.original["payload"]["tool"] = "other.tool"
        self.effective["payload"]["tool"] = "other.tool"
        self.request["input_hash"] = object_hash(self.original)
        self.receipt["request"]["input_hash"] = object_hash(self.original)
        self.receipt["attenuation"]["original_request_hash"] = object_hash(self.original)
        self.expect_failure("PAYLOAD_EXCEEDS_CONSTRAINTS", rehash_effective=True)

    def test_unsupported_transformations(self):
        for op, path in (("add", "/constraints/max_amount/value"), ("remove", "/constraints/max_amount/value"),
                         ("replace", "/runtime")):
            with self.subTest(op=op, path=path):
                self.receipt["attenuation"]["changes"][0].update(op=op, path=path)
                self.expect_failure("UNSUPPORTED_TRANSFORMATION")
        self.receipt = decode(self.bound.receipt)
        self.receipt["attenuation"]["changes"] *= 2
        self.expect_failure("UNSUPPORTED_TRANSFORMATION")

    def test_reason_code_is_bound(self):
        self.receipt["decision"]["reason_codes"] = ["POLICY_MATCH"]
        self.expect_failure("ATTENUATION_REASON_MISMATCH")

    def test_admission_context_mismatches(self):
        for key in ("target", "transaction_id", "action", "audience", "constraints"):
            with self.subTest(key=key):
                self.request = decode(self.bound.request)
                self.request[key] = "wrong"
                self.expect_failure("ADMISSION_REQUEST_MISMATCH")

    def test_receipt_subject_and_summary_mismatches(self):
        for key in ("actor", "principal", "runtime"):
            with self.subTest(key=key):
                self.receipt = decode(self.bound.receipt)
                self.receipt["subject"][key] = "wrong"
                self.expect_failure("RECEIPT_SUBJECT_MISMATCH")
        for key in ("request_id", "transaction_id", "action", "constraints"):
            with self.subTest(key=key):
                self.receipt = decode(self.bound.receipt)
                self.receipt["request"][key] = "wrong"
                self.expect_failure("RECEIPT_REQUEST_MISMATCH")

    def test_receipt_window_cannot_expand(self):
        self.receipt["expires_at"] = "2026-11-12T00:06:00Z"
        self.expect_failure("RECEIPT_WINDOW_EXCEEDS_REQUEST")
        self.receipt = decode(self.bound.receipt)
        self.receipt["issued_at"] = "2026-11-11T23:59:59Z"
        self.expect_failure("RECEIPT_WINDOW_EXCEEDS_REQUEST")

    def test_allow_cannot_change_operation(self):
        self.receipt["decision"]["outcome"] = "allow"
        del self.receipt["attenuation"]
        self.expect_failure("ALLOW_REQUEST_CHANGED")

    def test_action_binding_must_identify_effective(self):
        self.receipt["request"]["action_binding"] = binding.action_binding(self.original)
        self.expect_failure("ACTION_BINDING_MISMATCH")

    def test_malformed_receipt_does_not_crash(self):
        for bad in ([], None, {"request_binding": None}, {"request_binding": {}}):
            with self.subTest(bad=bad):
                report = assess_request_binding(encode(bad), {})
                self.assertIs(report["pass"], False)

    def test_explicit_null_protocol_hint_is_rejected(self):
        self.request["evidence_refs"][0]["protocol_hint"] = None
        self.expect_failure("SCHEMA_INVALID")

    def test_json_diagnostics_follow_token_order_with_platform_independent_limits(self):
        for content, cause in (
            (b'{"x":9007199254740992,"x":0}', "UNSAFE_JSON_INTEGER"),
            (b'{"x":1,"x":2,}', "DUPLICATE_JSON_KEY"),
            (b'9' * 5000, "UNSAFE_JSON_INTEGER"),
            (b'[' * 20000 + b'0' + b']' * 20000, "JSON_DEPTH_EXCEEDED"),
            (b'{"10":"\\ud800","2":1.0}', "INVALID_UNICODE"),
            (b'{"10":1.0,"2":"\\ud800"}', "UNSUPPORTED_JSON_NUMBER"),
        ):
            with self.subTest(cause=cause, prefix=content[:40]):
                with self.assertRaisesRegex(Invalid, "^" + cause + "$"):
                    decode(content)

    def test_json_token_reader_preserves_supported_values(self):
        values = [None, True, False, {}, [], [0, -1, 9007199254740991, -9007199254740991],
                  {"quoted\"key": "backslash\\ / \b\f\n\r\t 😀", "items": [None, {"a": True}]},
                  {"2": 0, "10": 1, "__proto__": {"constructor": 2}}]
        for value in values:
            with self.subTest(value=value):
                for ascii_only in (True, False):
                    raw = json.dumps(value, ensure_ascii=ascii_only, indent=2).encode()
                    self.assertEqual(decode(raw), value)
                    self.assertEqual(object_hash(decode(raw)), object_hash(value))

    def test_assessment_does_not_mutate_inputs(self):
        artifacts = {reference(raw)["uri"]: raw for raw in (self.bound.request, self.bound.original, self.bound.effective)}
        original = copy.deepcopy(artifacts)
        report = assess_request_binding(self.bound.receipt, artifacts, expected_admission_request_ref=reference(self.bound.request))
        self.assertTrue(report["pass"])
        self.assertEqual(artifacts, original)
        self.assertIsNone(report["checks"][-1]["pass"])
        self.assertEqual(report["checks"][-1]["name"], "execution.actual_input")

    def test_post_links_effective_hash(self):
        post = example.synthetic_post(self.receipt)
        self.assertEqual(self.verifier.validate_post_execution_linkage(self.receipt, post)["outcome"], "success")
        post["execution"]["effective_request_hash"] = object_hash(self.original)
        self.assertIn("POST_EXEC_EFFECTIVE_REQUEST_HASH_MISMATCH",
                      self.verifier.validate_post_execution_linkage(self.receipt, post)["reason_codes"])

    def test_post_receipt_digest(self):
        post = example.synthetic_post(self.receipt)
        post["admission"]["digest"]["value"] = "0" * 64
        self.assertIn("POST_EXEC_ADMISSION_DIGEST_MISMATCH",
                      self.verifier.validate_post_execution_linkage(self.receipt, post)["reason_codes"])

    def test_post_aggregate_amount(self):
        post = example.synthetic_post(self.receipt)
        effect = post["result"]["side_effects"][0]
        effect["amount"]["value"] = "15.00"
        post["result"]["side_effects"].append(copy.deepcopy(effect))
        self.assertIn("POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED",
                      self.verifier.validate_post_execution_linkage(self.receipt, post)["reason_codes"])
        post["result"]["side_effects"][1]["amount"]["value"] = "10.00"
        self.assertEqual(self.verifier.validate_post_execution_linkage(self.receipt, post)["outcome"], "success")

    def test_reproducible_bundle_and_manifest_rehash_attack(self):
        files = example.generate()
        self.assertEqual(files, example.generate())
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name, raw in files.items():
                (root / name).write_bytes(raw)
            result = example.verify_example(root, files["admission-request.json"])
            self.assertTrue(result["generation_reproduced"])
            receipt = decode(files["admission-receipt.json"])
            receipt["attenuation"]["changes"][0]["from"] = "999.00"
            raw = encode(receipt)
            (root / "admission-receipt.json").write_bytes(raw)
            manifest = decode(files["manifest.json"])
            manifest["artifacts"]["admission-receipt.json"] = digest(raw)
            (root / "manifest.json").write_bytes(encode(manifest))
            with self.assertRaisesRegex(Invalid, "ATTENUATION_FROM_MISMATCH"):
                example.verify_example(root, files["admission-request.json"])

    def test_committed_example_matches_generator(self):
        directory = example.HERE / "examples/purchase-cap"
        for name, raw in example.generate().items():
            self.assertEqual((directory / name).read_bytes(), raw, name)

    def test_cli_and_safe_file_reads(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            output = root / "generated"
            command = [sys.executable, str(example.HERE / "example.py")]
            generated = subprocess.run(command + ["generate", "--output", str(output)], capture_output=True, text=True)
            self.assertEqual(generated.returncode, 0, generated.stderr)
            checked = subprocess.run(command + ["check", "--bundle", str(output), "--expected-admission-request",
                                                 str(output / "admission-request.json")], capture_output=True, text=True)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertFalse(json.loads(checked.stdout)["execution_observed"])
            again = subprocess.run(command + ["generate", "--output", str(output)], capture_output=True, text=True)
            self.assertNotEqual(again.returncode, 0)
            (root / "link.json").symlink_to(output / "original.json")
            with self.assertRaises(OSError):
                example.read_file(root / "link.json")


if __name__ == "__main__":
    unittest.main()
