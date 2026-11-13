"""Runtime verifier integration; the HMAC adapter is a test fixture only.

The fixture authenticates bytes with a private per-test key. It is not a
production evidence format, JOSE implementation, or SPIFFE adapter.
"""

import copy
import dataclasses
import hashlib
import hmac
import json
import secrets
import unittest
from datetime import timedelta
from unittest.mock import patch

import example
import request_binding as b


class RuntimeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.original, self.request, self.policy = example.inputs()
        self.now = b.core.parse_time(example.EVALUATED_AT)
        self.key = secrets.token_bytes(32)
        self.calls = []
        self.adapter = b.RuntimeEvidenceVerifier(
            method="test-only-hmac-runtime-v1", media_type="application/json",
            max_age_seconds=60, verify=self.verify)
        self.claims = {
            "issuer": "urn:test:runtime-issuer", "runtime": self.request["runtime"],
            "audience": self.request["audience"],
            "context_hash": b.runtime_context_hash(b.encode(self.request), b.encode(self.original)),
            "issued_at": b.core.iso(self.now - timedelta(seconds=10)),
            "not_before": b.core.iso(self.now - timedelta(seconds=10)),
            "valid_until": b.core.iso(self.now + timedelta(seconds=100)),
        }
        self.attach()
        self.verifier = self.new_verifier()

    def new_verifier(self, adapter=None):
        return b.core.VateVerifier(verifier_id="urn:test:verifier", policy=self.policy,
                                  runtime_evidence_verifier=self.adapter if adapter is None else adapter)

    def sign(self):
        return b.encode({"claims": self.claims,
                         "mac": hmac.digest(self.key, b.encode(self.claims), "sha256").hex()})

    def attach(self, raw=None):
        self.raw = self.sign() if raw is None else raw
        self.request["evidence_refs"] = [ref for ref in self.request["evidence_refs"]
                                          if ref["type"] != "runtime_attestation"]
        self.request["evidence_refs"].append({"type": "runtime_attestation", "uri": "urn:test:runtime-proof",
            "media_type": "application/json", "digest": b.digest(self.raw)})

    def verify(self, raw, context):
        self.calls.append(context)
        proof = b.decode(raw)
        expected = hmac.digest(self.key, b.encode(proof["claims"]), "sha256").hex()
        if not hmac.compare_digest(expected, proof["mac"]):
            raise ValueError("fixture authentication failed")
        claims = proof["claims"]
        if claims["issuer"] != "urn:test:runtime-issuer":
            raise ValueError("fixture issuer not authorized")
        return b.AuthenticatedRuntimeClaims(artifact_sha256=hashlib.sha256(raw).hexdigest(), **claims)

    def admit(self, **options):
        options.setdefault("now", self.now)
        options.setdefault("evidence_artifacts", {"urn:test:runtime-proof": self.raw})
        return self.verifier.admit(b.encode(self.request), original=b.encode(self.original), **options)

    def reject(self, cause, **options):
        with patch.object(self.verifier, "_evaluate_policy", wraps=self.verifier._evaluate_policy) as policy:
            with self.assertRaisesRegex(b.Invalid, cause):
                self.admit(**options)
            policy.assert_not_called()
        self.assertEqual(self.verifier._seen_request_ids, set())

    def test_authenticated_evidence_is_retained_with_request_and_receipt(self):
        result = self.admit()
        receipt, assessment = b.decode(result.receipt), b.decode(result.assessment)
        verified = b.decode(result.runtime_verification)
        self.assertEqual(receipt["decision"]["outcome"], "attenuate")
        self.assertEqual(result.runtime_evidence, self.raw)
        self.assertEqual(verified["admission_request_ref"], b.reference(result.request))
        self.assertEqual(verified["original_ref"], b.reference(result.original))
        self.assertEqual(verified["evidence_ref"], self.request["evidence_refs"][1])
        self.assertEqual(verified["issuer"], self.claims["issuer"])
        self.assertEqual(receipt["evidence"][1]["verification"], verified["verification"])
        self.assertEqual(receipt["evidence"][0]["verification"]["method"], "vate-local-policy-content-v1")
        self.assertTrue(assessment["binding_requirement_met"])
        self.assertIn({"name": "evidence.authentication", "status": "not_checked", "pass": None,
                       "cause": "EVIDENCE_AUTHENTICATION_NOT_PERFORMED"}, assessment["checks"])
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.runtime_evidence = b"replaced"

    def test_adapter_receives_immutable_expected_context(self):
        self.admit()
        context, = self.calls
        self.assertEqual(context.admission_request, b.encode(self.request))
        self.assertEqual(context.original, b.encode(self.original))
        self.assertEqual(context.evidence_reference, b.encode(self.request["evidence_refs"][1]))
        self.assertEqual(context.context_hash, self.claims["context_hash"])
        self.assertEqual(context.now, self.now)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            context.runtime = "different"

    def test_missing_runtime_proof_cannot_downgrade_configured_verifier(self):
        self.request["evidence_refs"].pop()
        self.reject("RUNTIME_EVIDENCE_REQUIRED", evidence_artifacts={})
        self.assertEqual(self.calls, [])

    def test_runtime_proof_requires_application_selected_verifier(self):
        self.verifier = b.core.VateVerifier(verifier_id="urn:test:verifier", policy=self.policy)
        self.reject("UNSUPPORTED_ADMISSION_EVIDENCE")

    def test_runtime_policy_and_artifact_sets_are_exact(self):
        for refs in ([self.request["evidence_refs"][1]],
                     self.request["evidence_refs"] + [{**self.request["evidence_refs"][1], "uri": "urn:other"}],
                     self.request["evidence_refs"] + [{**self.request["evidence_refs"][0], "type": "status_bundle"}]):
            with self.subTest(refs=refs):
                saved = self.request["evidence_refs"]
                self.request["evidence_refs"] = refs
                self.reject("RUNTIME_EVIDENCE_REQUIRED")
                self.request["evidence_refs"] = saved
        for artifacts in (None, {}, {"urn:test:runtime-proof": self.raw, "urn:extra": b"x"}):
            with self.subTest(artifacts=list(artifacts or {})):
                self.reject("EVIDENCE_ARTIFACT_SET_MISMATCH", evidence_artifacts=artifacts)
        for artifacts in ([], True, self.raw):
            with self.subTest(type=type(artifacts)):
                self.reject("INVALID_EVIDENCE_ARTIFACTS", evidence_artifacts=artifacts)

    def test_local_policy_is_checked_before_runtime_adapter(self):
        self.request["evidence_refs"][0]["digest"]["value"] = "0" * 64
        self.reject("LOCAL_POLICY_REFERENCE_MISMATCH")
        self.assertEqual(self.calls, [])

    def test_raw_digest_precedes_adapter_and_covers_whitespace(self):
        self.raw += b" "
        self.reject("RUNTIME_EVIDENCE_DIGEST_MISMATCH")
        self.assertEqual(self.calls, [])
        self.attach(self.raw)
        self.assertTrue(b.decode(self.admit().assessment)["pass"])

    def test_resigned_outer_digest_does_not_authenticate_changed_body(self):
        proof = b.decode(self.raw)
        proof["claims"]["runtime"] = "urn:changed-runtime"
        self.attach(b.encode(proof))
        self.reject("RUNTIME_EVIDENCE_VERIFICATION_FAILED")
        self.assertEqual(len(self.calls), 1)

    def test_untrusted_verified_annotation_cannot_replace_verification(self):
        self.attach(b.encode({"verification": {"result": "verified"}, "claims": self.claims, "mac": "00"}))
        self.reject("RUNTIME_EVIDENCE_VERIFICATION_FAILED")

    def test_new_request_or_subject_cannot_reuse_authenticated_context(self):
        original_request = copy.deepcopy(self.request)
        for field in ("request_id", "actor", "principal"):
            with self.subTest(field=field):
                self.request = {**original_request, field: "urn:another"}
                self.reject("RUNTIME_VERIFICATION_CONTEXT_MISMATCH")
        self.request = original_request
        self.request["expires_at"] = b.core.iso(b.core.parse_time(self.request["expires_at"]) + timedelta(seconds=1))
        self.reject("RUNTIME_VERIFICATION_CONTEXT_MISMATCH")

    def test_new_operation_cannot_reuse_authenticated_context(self):
        self.original["payload"]["order_id"] = "another-order"
        self.request["input_hash"] = b.object_hash(self.original)
        self.reject("RUNTIME_VERIFICATION_CONTEXT_MISMATCH")

    def test_policy_reference_is_inside_authenticated_context(self):
        self.policy["policy_version"] = "different-policy-version"
        self.request["evidence_refs"][0]["digest"] = b.digest(b.encode(self.policy))
        self.reject("RUNTIME_VERIFICATION_CONTEXT_MISMATCH")

    def test_runtime_reference_exclusion_avoids_self_digest(self):
        expected = self.claims["context_hash"]
        request = copy.deepcopy(self.request)
        request["evidence_refs"][1]["digest"]["value"] = "0" * 64
        self.assertEqual(b.runtime_context_hash(b.encode(request), b.encode(self.original)), expected)
        result = self.admit()
        self.assertEqual(b.decode(result.receipt)["request_binding"]["admission_request_ref"], b.reference(result.request))

    def test_verified_claims_must_match_runtime_audience_and_raw_bytes(self):
        for field, value, code in (
                ("runtime", "urn:other", "SUBJECT"), ("audience", "urn:other", "AUDIENCE"),
                ("context_hash", "sha-256:" + "0" * 64, "CONTEXT")):
            with self.subTest(field=field):
                old = self.claims[field]
                self.claims[field] = value
                self.attach()
                self.reject("RUNTIME_VERIFICATION_" + code + "_MISMATCH")
                self.claims[field] = old
        self.attach()
        adapter = dataclasses.replace(self.adapter, verify=lambda raw, context:
            dataclasses.replace(self.verify(raw, context), artifact_sha256="0" * 64))
        self.verifier = self.new_verifier(adapter)
        self.reject("RUNTIME_VERIFICATION_ARTIFACT_MISMATCH")

    def test_adapter_rejects_untrusted_issuer(self):
        self.claims["issuer"] = "urn:untrusted-issuer"
        self.attach()
        self.reject("RUNTIME_EVIDENCE_VERIFICATION_FAILED")

    def test_booleans_dicts_and_incomplete_claims_are_not_results(self):
        valid = self.verify(self.raw, None)
        for result in (True, False, None, dataclasses.asdict(valid),
                       dataclasses.replace(valid, issuer=""), dataclasses.replace(valid, runtime=1)):
            with self.subTest(type=type(result)):
                self.verifier = self.new_verifier(dataclasses.replace(self.adapter, verify=lambda *_: result))
                self.reject("INVALID_RUNTIME_VERIFICATION_RESULT")

    def test_adapter_exception_is_fail_closed_and_diagnostics_are_not_exposed(self):
        def broken(*_):
            raise RuntimeError("private diagnostic value")
        self.verifier = self.new_verifier(dataclasses.replace(self.adapter, verify=broken))
        self.reject("^RUNTIME_EVIDENCE_VERIFICATION_FAILED$")
        self.verifier.runtime_evidence_verifier = self.adapter
        self.assertTrue(b.decode(self.admit().assessment)["pass"])

    def test_policy_fail_closed_flag_does_not_bypass_runtime_validation(self):
        self.verifier.fail_closed = False
        self.claims["runtime"] = "urn:wrong-runtime"
        self.attach()
        self.reject("RUNTIME_VERIFICATION_SUBJECT_MISMATCH")

    def test_adapter_cannot_change_configuration_before_policy_evaluation(self):
        for field in ("policy", "runtime_evidence_verifier"):
            with self.subTest(field=field):
                def changes_config(raw, context):
                    claims = self.verify(raw, context)
                    if field == "policy":
                        self.verifier.policy = {**self.policy, "max_amount": {"currency": "USD", "value": "120.00"}}
                    else:
                        self.verifier.runtime_evidence_verifier = None
                    return claims
                self.verifier = self.new_verifier(dataclasses.replace(self.adapter, verify=changes_config))
                self.reject("ADMISSION_CONFIGURATION_CHANGED")

    def test_config_and_format_are_selected_by_application(self):
        for adapter in (True, {}, dataclasses.replace(self.adapter, max_age_seconds=True),
                        dataclasses.replace(self.adapter, max_age_seconds=0),
                        dataclasses.replace(self.adapter, max_age_seconds=10**100),
                        dataclasses.replace(self.adapter, method=""),
                        dataclasses.replace(self.adapter, verify=None),
                        dataclasses.replace(self.adapter, protocol_hint="unknown")):
            with self.subTest(adapter=str(type(adapter))):
                self.verifier = self.new_verifier(adapter)
                self.reject("INVALID_RUNTIME_VERIFIER")
        self.verifier = self.new_verifier()
        for field, value in (("media_type", "application/jwt"), ("protocol_hint", "spiffe")):
            with self.subTest(field=field):
                self.request["evidence_refs"][1][field] = value
                self.reject("UNSUPPORTED_RUNTIME_EVIDENCE_FORMAT")
                self.attach()

    def test_adapter_protocol_hint_must_be_explicitly_selected(self):
        self.request["evidence_refs"][1]["protocol_hint"] = "spiffe"
        self.verifier = self.new_verifier(dataclasses.replace(self.adapter, protocol_hint="spiffe"))
        result = self.admit()
        self.assertEqual(b.decode(result.receipt)["evidence"][1]["protocol_hint"], "spiffe")
        # A test-only format with a hint does not implement the SPIFFE standard.

    def test_evidence_bytes_are_bounded_and_immutable(self):
        for raw in (b"", bytearray(self.raw), "not bytes", b"x" * (b.MAX_BYTES + 1)):
            with self.subTest(type=type(raw), size=len(raw)):
                self.reject("INVALID_RUNTIME_EVIDENCE_BYTES", evidence_artifacts={"urn:test:runtime-proof": raw})
        self.assertEqual(self.calls, [])

    def test_windows_and_freshness_reject_future_expired_and_stale_proofs(self):
        for field, value, cause in (
                ("issued_at", b.core.iso(self.now + timedelta(microseconds=1)), "OUTSIDE_WINDOW"),
                ("not_before", b.core.iso(self.now + timedelta(microseconds=1)), "OUTSIDE_WINDOW"),
                ("valid_until", b.core.iso(self.now - timedelta(microseconds=1)), "OUTSIDE_WINDOW"),
                ("issued_at", b.core.iso(self.now - timedelta(seconds=60, microseconds=1)), "STALE")):
            with self.subTest(field=field, cause=cause):
                old = self.claims[field]
                self.claims[field] = value
                self.attach()
                self.reject("RUNTIME_EVIDENCE_" + cause)
                self.claims[field] = old

    def test_invalid_timestamp_and_inverted_window_are_rejected(self):
        for value in ("2026-01-01", "2026-09-01T00:00:00.1234567Z", "not-a-time"):
            self.claims["valid_until"] = value
            self.attach()
            self.reject("INVALID_RUNTIME_EVIDENCE_WINDOW")
        self.claims["valid_until"] = b.core.iso(self.now - timedelta(seconds=20))
        self.attach()
        self.reject("INVALID_RUNTIME_EVIDENCE_WINDOW")

    def test_freshness_and_validity_boundaries_are_inclusive(self):
        for field, value in (("issued_at", b.core.iso(self.now - timedelta(seconds=60))),
                             ("valid_until", b.core.iso(self.now)), ("not_before", b.core.iso(self.now))):
            with self.subTest(field=field):
                self.verifier = self.new_verifier()
                old = self.claims[field]
                self.claims[field] = value
                self.attach()
                self.assertTrue(b.decode(self.admit().assessment)["pass"])
                self.claims[field] = old

    def test_receipt_expiry_is_limited_by_proof_and_freshness(self):
        for valid_until, max_age, expected in ((100, 60, 50), (5, 60, 5), (100, 10, 0)):
            with self.subTest(valid_until=valid_until, max_age=max_age):
                self.claims["valid_until"] = b.core.iso(self.now + timedelta(seconds=valid_until))
                self.attach()
                self.verifier = self.new_verifier(dataclasses.replace(self.adapter, max_age_seconds=max_age))
                result = self.admit(require_new_permit=True)
                self.assertEqual(b.decode(result.receipt)["expires_at"], b.core.iso(self.now + timedelta(seconds=expected)))
                self.assertEqual(result.request, b.encode(self.request))
                self.assertFalse(b.decode(result.assessment)["decision_allows_immediate_execution"])

    def test_shorter_request_window_is_preserved(self):
        self.request["expires_at"] = b.core.iso(self.now + timedelta(seconds=1))
        self.claims["context_hash"] = b.runtime_context_hash(b.encode(self.request), b.encode(self.original))
        self.attach()
        self.assertEqual(b.decode(self.admit().receipt)["expires_at"], self.request["expires_at"])

    def test_offset_timestamp_and_microseconds_are_not_truncated(self):
        self.claims["valid_until"] = b.core.iso(self.now + timedelta(microseconds=1)).replace("Z", "+00:00")
        self.attach()
        self.assertEqual(b.decode(self.admit().receipt)["expires_at"], b.core.iso(self.now + timedelta(microseconds=1)))

    def test_allow_and_policy_denial_retain_successful_evidence_checks(self):
        for purchase, cap, outcome in (("24.50", "120.00", "allow"), ("30.00", "25.00", "deny")):
            with self.subTest(outcome=outcome):
                self.setUp()
                self.original["payload"]["amount"]["value"] = purchase
                self.policy["max_amount"]["value"] = cap
                self.request["input_hash"] = b.object_hash(self.original)
                self.request["evidence_refs"][0]["digest"] = b.digest(b.encode(self.policy))
                self.claims["context_hash"] = b.runtime_context_hash(b.encode(self.request), b.encode(self.original))
                self.attach()
                receipt = b.decode(self.admit().receipt)
                self.assertEqual(receipt["decision"]["outcome"], outcome)
                self.assertTrue(all(item["verification"]["result"] == "verified" for item in receipt["evidence"]))

    def test_reference_order_does_not_select_the_verification_method(self):
        self.request["evidence_refs"].reverse()
        receipt = b.decode(self.admit().receipt)
        self.assertEqual(receipt["evidence"][0]["verification"]["method"], self.adapter.method)
        self.assertEqual(receipt["evidence"][1]["verification"]["method"], "vate-local-policy-content-v1")

    def test_replay_is_consumed_only_after_complete_returned_artifacts(self):
        original_encode = b.encode
        def fail_record(value):
            if isinstance(value, dict) and value.get("contract") == b.RUNTIME_VERIFICATION:
                raise b.Invalid("RECORD_SERIALIZATION_FAILED")
            return original_encode(value)
        with patch.object(b, "encode", side_effect=fail_record):
            with self.assertRaisesRegex(b.Invalid, "RECORD_SERIALIZATION_FAILED"):
                self.admit()
        self.assertEqual(self.verifier._seen_request_ids, set())
        self.admit()
        receipt = b.decode(self.admit().receipt)
        self.assertEqual(receipt["decision"]["outcome"], "deny")
        self.assertIn("REPLAY_DETECTED", receipt["decision"]["reason_codes"])
        self.assertEqual(receipt["evidence"][1]["verification"]["result"], "verified")

    def test_runtime_report_and_receipt_satisfy_schemas(self):
        try:
            from jsonschema import Draft202012Validator, FormatChecker
        except ImportError:
            self.skipTest("schema validation runs in the existing jsonschema environment")
        record_schema = json.loads((b.ROOT / "reference/request-binding/schemas/runtime-verification.schema.json").read_text())
        receipt_schema = json.loads((b.ROOT / "schemas/admission-receipt.schema.json").read_text())
        Draft202012Validator.check_schema(record_schema)
        result = self.admit()
        record = b.decode(result.runtime_verification)
        formats = FormatChecker()
        # jsonschema's optional RFC3339 package is not required by this repo.
        # Use the same explicitly enabled timestamp check as the core/strict CI.
        formats.checks("date-time")(lambda value: b.core.safe_parse_time(value) is not None)
        validator = Draft202012Validator(record_schema, format_checker=formats)
        validator.validate(record)
        Draft202012Validator(receipt_schema, format_checker=formats).validate(b.decode(result.receipt))
        for field, value in (("max_age_seconds", True), ("context_hash", record["context_hash"] + "\n"),
                             ("valid_until", "invalid"), ("runtime", ""),
                             ("verification", {**record["verification"], "result": "not_checked"})):
            with self.subTest(field=field):
                self.assertFalse(validator.is_valid({**record, field: value}))


if __name__ == "__main__":
    unittest.main()
