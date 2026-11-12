"""A failed bound issuance must not consume a new replay ID."""

import copy
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from unittest.mock import patch

import example
import request_binding as b


class AdmissionTransactionTests(unittest.TestCase):
    def setUp(self):
        self.original, self.request, self.policy = example.inputs()
        self.now = b.core.parse_time(example.EVALUATED_AT)
        self.verifier = b.core.VateVerifier(verifier_id="urn:verifier", policy=self.policy)

    def admit(self, request=None, **options):
        request = self.request if request is None else request
        raw = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode()
        self.assertLessEqual(len(raw), b.MAX_BYTES)
        return self.verifier.admit(raw, original=b.encode(self.original), now=self.now, **options)

    def test_output_size_failure_allows_retry_and_preserves_other_ids(self):
        for actor in ("x" * (b.MAX_BYTES - 1500), "あ" * 400000):
            with self.subTest(actor_bytes=len(actor.encode())):
                self.verifier = b.core.VateVerifier(verifier_id="urn:verifier", policy=self.policy)
                other = {**self.request, "request_id": "previous-success"}
                self.admit(other)
                with self.assertRaisesRegex(b.Invalid, "ARTIFACT_TOO_LARGE"):
                    self.admit({**self.request, "actor": actor})
                self.assertEqual(self.verifier._seen_request_ids, {"previous-success"})
                with patch.object(self.verifier, "_evaluate_policy", wraps=self.verifier._evaluate_policy) as evaluate:
                    result = self.admit()
                    self.assertEqual(evaluate.call_count, 1)
                self.assertEqual(b.decode(result.receipt)["decision"]["outcome"], "attenuate")
                self.assertIn("REPLAY_DETECTED", b.decode(self.admit().receipt)["decision"]["reason_codes"])

    def test_generation_failure_does_not_erase_existing_replay_id(self):
        self.admit()
        with self.assertRaisesRegex(b.Invalid, "ARTIFACT_TOO_LARGE"):
            self.admit({**self.request, "actor": "あ" * 400000})
        self.assertEqual(self.verifier._seen_request_ids, {self.request["request_id"]})
        self.assertIn("REPLAY_DETECTED", b.decode(self.admit().receipt)["decision"]["reason_codes"])

    def test_failure_does_not_erase_id_committed_by_nested_admission(self):
        class Nested(b.core.VateVerifier):
            before_validation = None

            def _validate_admission_request(self, request, *, now):
                callback, self.before_validation = self.before_validation, None
                if callback is not None:
                    callback()
                return super()._validate_admission_request(request, now=now)

        self.verifier = Nested(verifier_id="urn:verifier", policy=self.policy)
        completed = []
        self.verifier.before_validation = lambda: completed.append(self.admit())
        with self.assertRaisesRegex(b.Invalid, "ARTIFACT_TOO_LARGE"):
            self.admit({**self.request, "actor": "あ" * 400000})
        self.assertEqual(b.decode(completed[0].receipt)["decision"]["outcome"], "attenuate")
        self.assertEqual(self.verifier._seen_request_ids, {self.request["request_id"]})
        self.assertIn("REPLAY_DETECTED", b.decode(self.admit().receipt)["decision"]["reason_codes"])

    def test_all_returned_bytes_are_validated_before_replay_commit(self):
        original_encode = b.encode
        for output in ("assessment", "core_result"):
            with self.subTest(output=output):
                self.verifier = b.core.VateVerifier(verifier_id="urn:verifier", policy=self.policy)

                def unavailable(value):
                    if isinstance(value, dict) and (
                            output == "assessment" and value.get("contract") == b.ASSESSMENT
                            or output == "core_result" and "admission_receipt" in value):
                        raise b.Invalid("ARTIFACT_TOO_LARGE")
                    return original_encode(value)

                with patch.object(b, "encode", side_effect=unavailable):
                    with self.assertRaisesRegex(b.Invalid, "ARTIFACT_TOO_LARGE"):
                        self.admit()
                self.assertEqual(self.verifier._seen_request_ids, set())
                self.assertEqual(b.decode(self.admit().receipt)["decision"]["outcome"], "attenuate")

    def test_failed_generated_binding_does_not_consume_id(self):
        with patch.object(b, "assess_request_binding", return_value={"binding_requirement_met": False}):
            with self.assertRaisesRegex(b.Invalid, "GENERATED_BINDING_FAILED"):
                self.admit()
        self.assertEqual(self.verifier._seen_request_ids, set())
        self.assertTrue(b.decode(self.admit().assessment)["binding_requirement_met"])

    def test_returned_denial_and_new_permit_keep_replay_protection(self):
        for purchase, options in (("30.00", {}), ("24.50", {"require_new_permit": True})):
            with self.subTest(purchase=purchase):
                self.original, self.request, self.policy = example.inputs(purchase=purchase)
                self.verifier = b.core.VateVerifier(verifier_id="urn:verifier", policy=self.policy)
                result = self.admit(**options)
                self.assertFalse(b.decode(result.assessment)["decision_allows_immediate_execution"])
                self.assertEqual(self.verifier._seen_request_ids, {self.request["request_id"]})
                self.assertIn("REPLAY_DETECTED", b.decode(self.admit().receipt)["decision"]["reason_codes"])

    def test_overlapping_calls_observe_only_completed_issuance(self):
        original_encode = b.encode
        for fails in (True, False):
            for private_second in (False, True):
                with self.subTest(fails=fails, private_second=private_second):
                    self.verifier = b.core.VateVerifier(verifier_id="urn:verifier", policy=self.policy)
                    at_receipt, release, second_started = threading.Event(), threading.Event(), threading.Event()
                    first_thread = []

                    def pause_receipt(value):
                        if (isinstance(value, dict) and value.get("receipt_type") == "admission"
                                and first_thread and threading.get_ident() == first_thread[0]):
                            at_receipt.set()
                            if not release.wait(5):
                                raise RuntimeError("test release timed out")
                        return original_encode(value)

                    def first_call():
                        first_thread.append(threading.get_ident())
                        request = {**self.request, "actor": "あ" * 400000} if fails else self.request
                        return self.admit(request)

                    def second_call():
                        second_started.set()
                        if private_second:
                            return self.verifier._evaluate_policy(copy.deepcopy(self.request), now=self.now)["admission_receipt"]
                        return b.decode(self.admit().receipt)

                    with patch.object(b, "encode", side_effect=pause_receipt), ThreadPoolExecutor(max_workers=2) as pool:
                        first = pool.submit(first_call)
                        try:
                            self.assertTrue(at_receipt.wait(5))
                            second = pool.submit(second_call)
                            self.assertTrue(second_started.wait(5))
                            with self.assertRaises(TimeoutError):
                                second.result(timeout=0.1)
                        finally:
                            release.set()
                        if fails:
                            with self.assertRaisesRegex(b.Invalid, "ARTIFACT_TOO_LARGE"):
                                first.result(timeout=5)
                        else:
                            self.assertTrue(b.decode(first.result(timeout=5).assessment)["binding_requirement_met"])
                        decision = second.result(timeout=5)["decision"]
                    self.assertEqual(decision["outcome"], "attenuate" if fails else "deny")
                    if not fails:
                        self.assertIn("REPLAY_DETECTED", decision["reason_codes"])
                    self.assertEqual(self.verifier._seen_request_ids, {self.request["request_id"]})


if __name__ == "__main__":
    unittest.main()
