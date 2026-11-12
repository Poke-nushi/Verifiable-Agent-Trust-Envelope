"""Current public admission entries require request preimages by default."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

import example
import request_binding as b

spec = importlib.util.spec_from_file_location(
    "binding_default_a2a", b.ROOT / "reference/a2a-metadata-adapter-demo/a2a_metadata_adapter_demo.py")
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


class DefaultAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.original, self.request, self.policy = example.inputs()
        self.now = b.core.parse_time(example.EVALUATED_AT)
        self.verifier = b.core.VateVerifier(verifier_id="did:web:verifier.example", policy=self.policy)

    def admit(self, original=None):
        return self.verifier.admit(b.encode(self.request),
                                   original=b.encode(self.original if original is None else original), now=self.now)

    def test_legacy_call_cannot_issue_a_receipt(self):
        with self.assertRaises(TypeError):
            self.verifier.admit(self.request, now=self.now)
        with self.assertRaises(ValueError):
            self.verifier.admit(self.request, original=b.encode(self.original), now=self.now)
        with self.assertRaises(ValueError):
            self.verifier.admit(b.encode(self.request), original=None, now=self.now)
        # Rejected preimages do not consume the request's replay slot.
        self.assertEqual(b.decode(self.admit().receipt)["decision"]["outcome"], "attenuate")

    def test_changed_or_unsupported_preimage_cannot_issue_a_receipt(self):
        for mutate in (
            lambda o: o["payload"].update(order_id="other-order"),
            lambda o: o.update(preimage_profile="unknown-profile"),
            lambda o: o.update(operation_id="other-operation"),
        ):
            with self.subTest(mutation=mutate):
                original = copy.deepcopy(self.original)
                mutate(original)
                with self.assertRaises(ValueError):
                    self.admit(original)
        self.assertTrue(b.decode(self.admit().assessment)["binding_requirement_met"])

    def test_public_entry_retains_raw_bytes_and_reassesses(self):
        request_raw = json.dumps(self.request, indent=2).encode() + b"\n"
        original_raw = json.dumps(self.original, indent=2).encode() + b"\n"
        result = self.verifier.admit(request_raw, original=original_raw, now=self.now)
        self.assertIsInstance(result, b.BoundAdmission)
        self.assertEqual((result.request, result.original), (request_raw, original_raw))
        receipt = b.decode(result.receipt)
        self.assertEqual(receipt["request"]["input_hash"], receipt["attenuation"]["original_request_hash"])
        artifacts = {b.reference(raw)["uri"]: raw for raw in (result.request, result.original, result.effective)}
        checked = b.assess_request_binding(result.receipt, artifacts,
                                           expected_admission_request_ref=b.reference(request_raw))
        self.assertEqual(checked, b.decode(result.assessment))
        self.assertTrue(checked["binding_requirement_met"])

    def test_public_entry_uses_the_published_validation_exception(self):
        with self.assertRaises(b.Invalid):
            self.verifier.admit(b.encode(self.request), original=b"{}", now=self.now)

    def test_public_entry_preserves_decision_and_new_permit_rules(self):
        for options, new_permit, outcome, executable in (
            ({"cap": "25.00"}, False, "allow", True),
            ({}, False, "attenuate", True),
            ({}, True, "attenuate", False),
            ({"purchase": "120.00"}, False, "deny", False),
        ):
            with self.subTest(options=options, new_permit=new_permit):
                original, request, policy = example.inputs(**options)
                verifier = b.core.VateVerifier(verifier_id="did:web:verifier.example", policy=policy)
                result = verifier.admit(b.encode(request), original=b.encode(original), now=self.now,
                                         require_new_permit=new_permit)
                self.assertEqual(b.decode(result.receipt)["decision"]["outcome"], outcome)
                self.assertTrue(b.decode(result.assessment)["binding_requirement_met"])
                self.assertIs(b.decode(result.assessment)["decision_allows_immediate_execution"], executable)


class A2ABindingTests(unittest.TestCase):
    def setUp(self):
        self.task = json.loads(adapter.TASK_MESSAGE.read_bytes())
        self.temp = tempfile.TemporaryDirectory(prefix=".tmp-a2a-binding-", dir=b.ROOT)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def assert_denied(self, task):
        response = adapter.adapt_task_message(task)
        self.assertEqual(response["vate_decision"]["outcome"], "deny", response)
        self.assertEqual(response["status"]["state"], "rejected")
        self.assertNotIn("post_execution_metadata_example", response)
        self.assertNotIn("request_binding_assessment", response)

    def test_normal_task_uses_bound_default_admission(self):
        response = adapter.adapt_task_message(self.task)
        self.assertEqual(response["vate_decision"]["outcome"], "attenuate")
        assessment = response["request_binding_assessment"]
        self.assertTrue(assessment["binding_requirement_met"])
        receipt_ref = response["metadata"][adapter.EXTENSION_URI]["admission_receipt"]
        self.assertEqual(assessment["receipt_digest"], receipt_ref["digest"])
        self.assertIn({"name": "execution.actual_input", "status": "not_checked", "pass": None,
                       "cause": "EXECUTION_OBSERVATION_NOT_SUPPLIED"}, assessment["checks"])

    def test_missing_or_unknown_original_contract_is_rejected(self):
        task = copy.deepcopy(self.task)
        del task["demo_request_binding"]
        self.assert_denied(task)
        for invalid in (None, {}, {"contract": "unknown", "original_ref": self.task["demo_request_binding"]["original_ref"]}):
            task = copy.deepcopy(self.task)
            task["demo_request_binding"] = invalid
            self.assert_denied(task)

    def test_changed_original_is_rejected_even_with_matching_raw_digest(self):
        ref = self.task["demo_request_binding"]["original_ref"]
        original = b.decode(adapter.read_raw(adapter.resolve_local_uri(ref["uri"])))
        original["payload"]["order_id"] = "a-different-order"
        raw = b.encode(original)
        path = self.directory / "changed.json"
        path.write_bytes(raw)
        ref.update(uri="local:" + str(path.relative_to(b.ROOT)), digest=b.digest(raw))
        self.assert_denied(self.task)

    def test_wrong_outer_transaction_and_raw_digest_are_rejected(self):
        task = copy.deepcopy(self.task)
        task["metadata"][adapter.EXTENSION_URI]["transaction_id"] = "different-transaction"
        self.assert_denied(task)
        task = copy.deepcopy(self.task)
        task["demo_request_binding"]["original_ref"]["digest"]["value"] = "0" * 64
        self.assert_denied(task)

    def test_duplicate_json_and_symlink_preimages_are_rejected(self):
        path = self.directory / "input.json"
        raw = b'{"preimage_profile":"x","preimage_profile":"x"}'
        path.write_bytes(raw)
        ref = self.task["demo_request_binding"]["original_ref"]
        ref.update(uri="local:" + str(path.relative_to(b.ROOT)), digest=b.digest(raw))
        self.assert_denied(self.task)
        path.unlink()
        target = b.ROOT / "reference/a2a-metadata-adapter-demo/original-request.example.json"
        path.symlink_to(target)
        ref["digest"] = b.digest(target.read_bytes())
        self.assert_denied(self.task)
        path.unlink()
        path.symlink_to(target.parent, target_is_directory=True)
        ref["uri"] = "local:" + str((path / target.name).relative_to(b.ROOT))
        self.assert_denied(self.task)


if __name__ == "__main__":
    unittest.main()
