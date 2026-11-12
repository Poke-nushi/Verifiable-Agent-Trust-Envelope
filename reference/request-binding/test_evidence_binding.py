"""Evidence references stay attached to the receiver-selected admission."""

import copy
import json
import unittest

import example
import request_binding as b


class EvidenceBindingTests(unittest.TestCase):
    def setUp(self):
        self.files = example.generate()
        self.request = b.decode(self.files["admission-request.json"])
        self.receipt = b.decode(self.files["admission-receipt.json"])
        self.policy = b.decode(self.files["policy.json"])

    def assess(self, *, raw_utf8=False):
        serialize = (lambda value: json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()) if raw_utf8 else b.encode
        request_raw = serialize(self.request)
        self.receipt["request_binding"]["admission_request_ref"] = b.reference(request_raw)
        artifacts = {b.reference(raw)["uri"]: raw for raw in self.files.values()}
        artifacts[b.reference(request_raw)["uri"]] = request_raw
        return b.assess_request_binding(serialize(self.receipt), artifacts,
                                        expected_admission_request_ref=b.reference(request_raw))

    def test_unicode_annotations_compare_without_canonical_artifact_limit(self):
        for name, annotation in (("japanese", "あ" * 350000), ("accent", "é" * 400000),
                                 ("astral", "😀" * 180000)):
            with self.subTest(name=name):
                note = {"text": annotation, "values": [True, 1, None]}
                self.request["evidence_refs"][0]["digest"]["annotation"] = note
                self.receipt["evidence"][0]["digest"]["annotation"] = copy.deepcopy(note)
                for value in (self.request, self.receipt):
                    self.assertLess(len(json.dumps(value, ensure_ascii=False).encode()), b.MAX_BYTES)
                self.assertTrue(self.assess(raw_utf8=True)["binding_requirement_met"])
                self.receipt["evidence"][0]["digest"]["annotation"]["text"] += "x"
                result = self.assess(raw_utf8=True)
                self.assertFalse(result["binding_requirement_met"])
                self.assertIn("RECEIPT_EVIDENCE_MISMATCH", [x.get("cause") for x in result["checks"]])

    def test_annotation_comparison_preserves_nested_json_types(self):
        for left, right in ((True, 1), (False, 0), ([True], [1]),
                            ({"nested": [False]}, {"nested": [0]})):
            with self.subTest(left=left, right=right):
                self.request["evidence_refs"][0]["digest"]["annotation"] = left
                self.receipt["evidence"][0]["digest"]["annotation"] = right
                result = self.assess()
                self.assertFalse(result["binding_requirement_met"])
                self.assertIn("RECEIPT_EVIDENCE_MISMATCH", [x.get("cause") for x in result["checks"]])

    def test_raw_artifact_limit_still_applies_to_annotations(self):
        self.request["evidence_refs"][0]["digest"]["annotation"] = "x" * b.MAX_BYTES
        self.receipt["evidence"][0]["digest"]["annotation"] = "x" * b.MAX_BYTES
        result = self.assess(raw_utf8=True)
        self.assertFalse(result["binding_requirement_met"])
        self.assertEqual(result["checks"][0]["cause"], "ARTIFACT_TOO_LARGE")

    def test_receipt_cannot_replace_requested_evidence(self):
        for field, value in (("digest", {"alg": "sha-256", "value": "0" * 64}),
                             ("uri", "urn:other-policy"), ("type", "runtime_attestation"),
                             ("protocol_hint", "spiffe"), ("media_type", "text/plain")):
            with self.subTest(field=field):
                self.receipt = b.decode(self.files["admission-receipt.json"])
                self.receipt["evidence"][0][field] = value
                result = self.assess()
                self.assertIs(result["binding_requirement_met"], False)
                self.assertIs(result["decision_allows_immediate_execution"], False)
                self.assertIn("RECEIPT_EVIDENCE_MISMATCH", [x.get("cause") for x in result["checks"]])

    def test_receipt_cannot_omit_add_or_duplicate_evidence(self):
        item = self.receipt["evidence"][0]
        other = {**item, "uri": "urn:other-policy"}
        for value in (None, [], {}, [item, other], [item, copy.deepcopy(item)]):
            with self.subTest(value=value):
                self.receipt["evidence"] = value
                self.assertIs(self.assess()["binding_requirement_met"], False)

    def test_request_cannot_duplicate_logical_reference(self):
        self.request["evidence_refs"].append(copy.deepcopy(self.request["evidence_refs"][0]))
        self.assertIs(self.assess()["binding_requirement_met"], False)

    def test_matching_reference_order_and_annotations_are_preserved(self):
        second = {**self.request["evidence_refs"][0], "uri": "urn:second-policy"}
        self.request["evidence_refs"].append(second)
        self.receipt["evidence"].insert(0, {**self.receipt["evidence"][0], "uri": second["uri"]})
        self.receipt["evidence"][0]["annotation"] = {"note": "retained"}
        self.receipt["evidence"][1]["media_type"] = "application/json"
        self.assertIs(self.assess()["binding_requirement_met"], True)

    def test_success_does_not_report_evidence_authentication(self):
        result = self.assess()
        self.assertIn({"name": "evidence.authentication", "status": "not_checked", "pass": None,
                       "cause": "EVIDENCE_AUTHENTICATION_NOT_PERFORMED"}, result["checks"])

    def test_default_api_rejects_unmatched_local_policy_before_replay(self):
        for field, value in (("digest", {"alg": "sha-256", "value": "0" * 64}),
                             ("uri", "urn:other-policy"), ("media_type", "text/plain")):
            with self.subTest(field=field):
                request = copy.deepcopy(self.request)
                request["evidence_refs"][0][field] = value
                verifier = b.core.VateVerifier(verifier_id="urn:verifier", policy=self.policy)
                with self.assertRaisesRegex(b.Invalid, "LOCAL_POLICY_REFERENCE_MISMATCH"):
                    verifier.admit(b.encode(request), original=self.files["original.json"],
                                   now=b.core.parse_time(example.EVALUATED_AT))
                self.assertEqual(verifier._seen_request_ids, set())
                self.assertTrue(b.decode(verifier.admit(self.files["admission-request.json"],
                    original=self.files["original.json"], now=b.core.parse_time(example.EVALUATED_AT)).assessment)["pass"])

    def test_default_api_rejects_unimplemented_evidence_types(self):
        for kind in sorted(b.core.EVIDENCE_TYPES - {"local_policy"}):
            with self.subTest(kind=kind):
                request = copy.deepcopy(self.request)
                request["evidence_refs"][0]["type"] = kind
                verifier = b.core.VateVerifier(verifier_id="urn:verifier", policy=self.policy)
                with self.assertRaisesRegex(b.Invalid, "UNSUPPORTED_ADMISSION_EVIDENCE"):
                    verifier.admit(b.encode(request), original=self.files["original.json"],
                                   now=b.core.parse_time(example.EVALUATED_AT))
                self.assertEqual(verifier._seen_request_ids, set())

    def test_policy_change_requires_its_own_reference(self):
        policy = {**self.policy, "max_amount": {"currency": "USD", "value": "20.00"}}
        verifier = b.core.VateVerifier(verifier_id="urn:verifier", policy=policy)
        with self.assertRaisesRegex(b.Invalid, "LOCAL_POLICY_REFERENCE_MISMATCH"):
            verifier.admit(b.encode(self.request), original=self.files["original.json"],
                           now=b.core.parse_time(example.EVALUATED_AT))
        self.request["evidence_refs"][0]["digest"] = b.digest(b.encode(policy))
        result = verifier.admit(b.encode(self.request), original=self.files["original.json"],
                                now=b.core.parse_time(example.EVALUATED_AT))
        receipt = b.decode(result.receipt)
        self.assertEqual(receipt["decision"]["outcome"], "deny")
        verification = receipt["evidence"][0]["verification"]
        self.assertEqual(verification["result"], "verified")
        self.assertEqual(verification["method"], "vate-local-policy-content-v1")


if __name__ == "__main__":
    unittest.main()
