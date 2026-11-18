"""Digest annotations are accepted only where the public contract permits them."""
import copy
import unittest

import example
import request_binding as binding
import runner_binding


class DigestContractTests(unittest.TestCase):
    def test_raw_digest_identity_is_shared_by_admission_and_runner(self):
        raw = b'{"value":1}'
        descriptor = binding.digest(raw)
        for candidate, valid in ((descriptor, True), ({**descriptor, "note": [True, 1]}, True),
                                 ({**descriptor, "value": "0" * 64}, False),
                                 ({**descriptor, "alg": "sha-512"}, False),
                                 ({**descriptor, "value": descriptor["value"] + "\n"}, False),
                                 ({**descriptor, "value": True}, False), (None, False)):
            with self.subTest(candidate=candidate):
                self.assertEqual(binding.matches_digest(raw, candidate), valid)
                self.assertEqual(runner_binding.matches_digest(raw, candidate), valid)

    def test_public_admit_preserves_open_policy_digest_annotations(self):
        for cap, decision in (("25.00", "allow"), ("120.00", "attenuate")):
            with self.subTest(decision=decision):
                original, request, policy = example.inputs(cap=cap)
                request["evidence_refs"][0]["digest"]["note"] = {"reviewed": False, "revision": 1}
                verifier = binding.core.VateVerifier(verifier_id="urn:digest-contract", policy=policy)
                result = verifier.admit(binding.encode(request), original=binding.encode(original),
                                        now=binding.core.parse_time(example.EVALUATED_AT))
                receipt = binding.decode(result.receipt)
                self.assertEqual(receipt["decision"]["outcome"], decision)
                self.assertTrue(binding.decode(result.assessment)["pass"])
                self.assertEqual(receipt["evidence"][0]["digest"], request["evidence_refs"][0]["digest"])
                # Complete evidence correspondence still includes annotation
                # metadata, even though policy content identity uses alg/value.
                changed = copy.deepcopy(receipt)
                changed["evidence"][0]["digest"]["note"]["reviewed"] = 0
                with self.assertRaises(binding.Invalid) as caught:
                    binding._receipt_evidence_references(changed, request)
                self.assertEqual(caught.exception.cause, "RECEIPT_EVIDENCE_MISMATCH")

    def test_false_policy_identity_is_rejected_before_replay_consumption(self):
        for mutation, cause in (({"value": "0" * 64}, "LOCAL_POLICY_REFERENCE_MISMATCH"),
                                ({"alg": "sha-512"}, "SCHEMA_INVALID"),
                                ({"value": True}, "SCHEMA_INVALID"),
                                ({"value": "0" * 64 + "\n"}, "SCHEMA_INVALID")):
            with self.subTest(mutation=mutation):
                original, request, policy = example.inputs()
                bad = copy.deepcopy(request)
                bad["evidence_refs"][0]["digest"].update(mutation)
                verifier = binding.core.VateVerifier(verifier_id="urn:digest-contract", policy=policy)
                with self.assertRaises(binding.Invalid) as caught:
                    verifier.admit(binding.encode(bad), original=binding.encode(original),
                                   now=binding.core.parse_time(example.EVALUATED_AT))
                self.assertEqual(caught.exception.cause, cause)
                self.assertFalse(verifier._seen_request_ids)
                result = verifier.admit(binding.encode(request), original=binding.encode(original),
                                        now=binding.core.parse_time(example.EVALUATED_AT))
                self.assertTrue(binding.decode(result.assessment)["pass"])

    def test_closed_request_binding_reference_still_rejects_annotations(self):
        raw = b'{"value":1}'
        ref = binding.reference(raw)
        self.assertEqual(binding.resolve(ref, {ref["uri"]: raw}), {"value": 1})
        annotated = copy.deepcopy(ref)
        annotated["digest"]["note"] = "not allowed here"
        with self.assertRaises(binding.Invalid) as caught:
            binding.resolve(annotated, {ref["uri"]: raw})
        self.assertEqual(caught.exception.cause, "SCHEMA_INVALID")


if __name__ == "__main__":
    unittest.main()
