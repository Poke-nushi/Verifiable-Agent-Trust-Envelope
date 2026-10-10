import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import recipient_example as example
from run_examples import run_examples


def encode(value):
    return json.dumps(value).encode()


class RecipientExampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reader = example.RecipientExample()
        cls.admission = (example.HERE / "inputs/R17/admission.json").read_bytes()
        cls.post = (example.HERE / "inputs/R17/post.json").read_bytes()

    def linked_post(self, admission):
        post = json.loads(self.post)
        post["admission"].update({"receipt_id": admission["receipt_id"],
                                  "digest": self.reader.runner.digest_descriptor(admission),
                                  "decision": admission["decision"]["outcome"]})
        post["execution"].update({"transaction_id": admission["request"]["transaction_id"],
                                  "runtime": admission["subject"]["runtime"],
                                  "effective_request_hash": self.reader.runner.admitted_effective_request_hash(admission),
                                  "started_at": admission["issued_at"], "finished_at": admission["expires_at"]})
        post["issued_at"] = admission["expires_at"]
        post["result"]["side_effects"] = []
        post["result"]["policy_violations"] = []
        return post

    def fixture(self, name):
        return json.loads((example.ROOT / f"examples/receipts/admission-{name}.example.json").read_text())

    def cli(self, *args):
        return subprocess.run([sys.executable, "-B", str(example.HERE / "recipient_example.py"), *map(str, args)],
                              text=True, capture_output=True, check=False)

    def test_saved_current_results_match_full_regeneration(self):
        expected = (example.HERE / "expected-results.json").read_bytes()
        actual = run_examples()
        self.assertEqual(actual, json.loads(expected))
        self.assertEqual((json.dumps(actual, ensure_ascii=False, indent=2) + "\n").encode(), expected)

    def test_fixed_examples_and_input_preservation(self):
        before = {p: p.read_bytes() for p in (example.HERE / "inputs").rglob("*.json")}
        report = run_examples()
        self.assertTrue(report["all_expected_assessments_observed"])
        self.assertEqual([r["assessment"]["record_linkage"] for r in report["examples"]],
                         ["matched", "matched", "not_assessed", "mismatch"])
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        for item in report["examples"]:
            self.assertIn("actual_or_independently_observed_execution", item["assessment"]["not_checked"])
            self.assertIn("signatures_and_issuer_authority", item["assessment"]["not_checked"])

    def test_missing_post_has_no_linkage_verdict(self):
        result = self.reader.assess(self.admission, None)
        self.assertEqual(result["record_linkage"], "not_assessed")
        self.assertEqual(result["input_issues"], [{"input": "post", "kind": "not_supplied"}])
        self.assertIsNone(result["core_result"])
        self.assertEqual(result["linkage_checks_run"], [])

    def test_missing_admission_and_both_missing(self):
        for admission, post in ((None, self.post), (None, None)):
            with self.subTest(admission=admission is None, post=post is None):
                result = self.reader.assess(admission, post)
                self.assertEqual(result["record_linkage"], "not_assessed")
                self.assertIsNone(result["core_result"])

    def test_mismatched_runtime_specific_reason(self):
        post = json.loads(self.post)
        post["execution"]["runtime"] = "urn:example:different-runtime"
        result = self.reader.assess(self.admission, encode(post))
        self.assertEqual(result["record_linkage"], "mismatch")
        self.assertEqual(result["core_result"]["reason_codes"], ["POST_EXEC_RUNTIME_MISMATCH"])

    def test_receipts_from_different_operations(self):
        result = self.reader.assess(self.admission, (example.HERE / "inputs/R86/post.json").read_bytes())
        self.assertEqual(result["record_linkage"], "mismatch")
        self.assertIn("POST_EXEC_TRANSACTION_MISMATCH", result["core_result"]["reason_codes"])

    def test_fresh_permit_required_rejected_with_matching_digest(self):
        admission = self.fixture("attenuate-requires-new-permit")
        result = self.reader.assess(encode(admission), encode(self.linked_post(admission)))
        self.assertEqual(result["core_result"], {"outcome": "failed", "reason_codes": ["POST_EXEC_ADMISSION_DENIED"]})

    def test_executable_attenuation(self):
        admission = self.fixture("attenuate-max-amount")
        result = self.reader.assess(encode(admission), encode(self.linked_post(admission)))
        self.assertEqual(result["record_linkage"], "matched")

    def test_semantically_inconsistent_attenuation_is_not_assessed(self):
        admission = self.fixture("attenuate-requires-new-permit")
        admission["attenuation"]["require_new_permit"] = False
        result = self.reader.assess(encode(admission), encode(self.linked_post(admission)))
        self.assertEqual(result["record_linkage"], "not_assessed")
        self.assertTrue(any(i["kind"] == "semantic_input_invalid" for i in result["input_issues"]))
        self.assertIsNone(result["core_result"])

    def test_invalid_json_and_schema(self):
        for raw in (b"{", b"[]", b"{}", b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}'):
            with self.subTest(raw=raw):
                result = self.reader.assess(raw, self.post)
                self.assertEqual(result["record_linkage"], "not_assessed")
                self.assertIsNone(result["core_result"])

    def test_duplicate_key_in_otherwise_valid_receipt_is_rejected(self):
        raw = b'{"receipt_id":"discarded-value",' + self.admission.lstrip()[1:]
        result = self.reader.assess(raw, self.post)
        self.assertEqual(result["record_linkage"], "not_assessed")
        self.assertIsNone(result["core_result"])
        self.assertEqual([(i["input"], i["kind"]) for i in result["input_issues"]],
                         [("admission", "invalid_input")])

    def test_nonfinite_number_in_otherwise_valid_receipt_is_rejected(self):
        post = json.loads(self.post)
        post["demo_evidence"]["local_numeric_annotation"] = "NUMBER_PLACEHOLDER"
        template = encode(post)
        for number in (b"NaN", b"Infinity", b"-Infinity", b"1e999"):
            with self.subTest(number=number):
                raw = template.replace(b'"NUMBER_PLACEHOLDER"', number)
                result = self.reader.assess(self.admission, raw)
                self.assertEqual(result["record_linkage"], "not_assessed")
                self.assertIsNone(result["core_result"])
                self.assertEqual([(i["input"], i["kind"]) for i in result["input_issues"]],
                                 [("post", "invalid_input")])
        finite = template.replace(b'"NUMBER_PLACEHOLDER"', b"1.25")
        self.assertEqual(self.reader.assess(self.admission, finite)["record_linkage"], "matched")

    def test_generated_receipt_retains_admission_clock_precision(self):
        core = self.reader.core
        for now_text, issued_at in (
            ("2026-07-01T00:01:00Z", "2026-07-01T00:01:00Z"),
            ("2026-07-01T00:01:00.800000Z", "2026-07-01T00:01:00.800000Z"),
            ("2026-07-01T01:01:00.000001+01:00", "2026-07-01T00:01:00.000001Z"),
        ):
            with self.subTest(now=now_text):
                result = core.VateVerifier(verifier_id="did:web:verifier.example").admit(
                    core.sample_request(), now=core.parse_time(now_text))
                receipt = result["admission_receipt"]
                self.assertEqual(result["decision"], "allow")
                self.assertEqual(receipt["issued_at"], issued_at)
                self.assertTrue(all(e["verification"]["checked_at"] == issued_at for e in receipt["evidence"]))
                self.assertEqual(list(self.reader.validators["admission"].iter_errors(receipt)), [])

    def test_generated_window_excludes_start_before_admission_clock(self):
        core = self.reader.core
        request = core.sample_request()
        request["issued_at"] = "2026-07-01T00:01:00.700000Z"
        original = encode(request)
        now = core.parse_time("2026-07-01T00:01:00.800000Z")
        admission = core.VateVerifier(verifier_id="did:web:verifier.example").admit(
            request, now=now)["admission_receipt"]
        for start, expected in (("2026-07-01T00:01:00.100000Z", "mismatch"),
                                ("2026-07-01T00:01:00.799999Z", "mismatch"),
                                ("2026-07-01T00:01:00.800000Z", "matched")):
            with self.subTest(start=start):
                post = self.linked_post(admission)
                post["execution"].update(started_at=start, finished_at="2026-07-01T00:01:01Z")
                result = self.reader.assess(encode(admission), encode(post))
                self.assertEqual(result["record_linkage"], expected)
                self.assertEqual(result["input_issues"], [])
                if expected == "mismatch":
                    self.assertEqual(result["core_result"]["reason_codes"], ["POST_EXEC_ADMISSION_EXPIRED"])
        self.assertEqual(encode(request), original)

    def test_expired_denial_has_ordered_nonexecutable_receipt_window(self):
        core = self.reader.core
        for now_text in ("2026-07-01T00:20:00Z", "2026-07-01T00:10:00.000001Z",
                         "2026-07-01T01:20:00.800000+01:00"):
            with self.subTest(now=now_text):
                request = core.sample_request()
                original = encode(request)
                now = core.parse_time(now_text)
                result = core.VateVerifier(verifier_id="did:web:verifier.example").admit(request, now=now)
                receipt = result["admission_receipt"]
                self.assertEqual(result["decision"], "deny")
                self.assertEqual(result["reason_codes"], ["PERMIT_EXPIRED", "FAIL_CLOSED"])
                self.assertEqual(core.parse_time(receipt["issued_at"]), now)
                self.assertEqual(receipt["expires_at"], receipt["issued_at"])
                self.assertEqual(list(self.reader.validators["admission"].iter_errors(receipt)), [])
                self.assertEqual(self.reader.runner.generated_receipt_identity_failures(receipt, "test", "admission"), [])
                linkage = self.reader.verifier.validate_post_execution_linkage(receipt, self.linked_post(receipt))
                self.assertEqual(linkage, {"outcome": "failed", "reason_codes": ["POST_EXEC_ADMISSION_DENIED"]})
                self.assertEqual(encode(request), original)

    def test_unexpired_receipt_keeps_original_expiry_and_decision(self):
        core = self.reader.core
        for issued_at, now_text, decision in (
            ("2026-07-01T00:00:00Z", "2026-07-01T00:09:59.999999Z", "allow"),
            ("2026-07-01T00:00:00Z", "2026-07-01T00:10:00Z", "allow"),
            ("2026-07-01T00:02:00Z", "2026-07-01T00:01:00.800000Z", "deny"),
        ):
            with self.subTest(issued_at=issued_at, now=now_text):
                request = core.sample_request()
                request.update(issued_at=issued_at, expires_at="2026-07-01T01:10:00+01:00")
                result = core.VateVerifier(verifier_id="did:web:verifier.example").admit(
                    request, now=core.parse_time(now_text))
                receipt = result["admission_receipt"]
                self.assertEqual(result["decision"], decision)
                self.assertEqual(receipt["expires_at"], request["expires_at"])
                self.assertEqual(self.reader.runner.generated_receipt_identity_failures(receipt, "test", "admission"), [])

    def test_unknown_profile_and_invalid_date(self):
        for field, value in (("profile", "unsupported-profile"), ("issued_at", "not-a-date")):
            with self.subTest(field=field):
                admission = json.loads(self.admission)
                admission[field] = value
                self.assertEqual(self.reader.assess(encode(admission), self.post)["record_linkage"], "not_assessed")

    def test_nested_schema_dates_use_explicit_format_validation(self):
        for timestamp, expected in (("not-a-date", "not_assessed"),
                                    ("2026-02-30T00:00:00Z", "not_assessed"),
                                    ("2026-09-15T06:25:00.0000001Z", "not_assessed"),
                                    ("2026-09-15t06:25:00.000001z", "matched")):
            with self.subTest(timestamp=timestamp):
                admission = json.loads(self.admission)
                admission["evidence"][0]["verification"]["checked_at"] = timestamp
                result = self.reader.assess(encode(admission), encode(self.linked_post(admission)))
                self.assertEqual(result["record_linkage"], expected)
                if expected == "not_assessed":
                    self.assertIsNone(result["core_result"])
                    self.assertTrue(any(i.get("path") == ["evidence", 0, "verification", "checked_at"]
                                        for i in result["input_issues"]))
        admission = self.fixture("attenuate-max-amount")
        admission["attenuation"]["effective_constraints"]["expires_at"] = "not-a-date"
        result = self.reader.assess(encode(admission), encode(self.linked_post(admission)))
        self.assertEqual(result["record_linkage"], "not_assessed")
        self.assertIsNone(result["core_result"])

    def test_failed_operation_can_have_matched_receipts(self):
        post = json.loads(self.post)
        post["result"]["outcome"] = "failed"
        self.assertEqual(self.reader.assess(self.admission, encode(post))["record_linkage"], "matched")

    def test_reformatted_json_retains_object_linkage(self):
        reformatted = json.dumps(json.loads(self.admission), indent=4).encode()
        result = self.reader.assess(reformatted, self.post)
        self.assertEqual(result["record_linkage"], "matched")
        self.assertNotEqual(example.digest(reformatted), example.digest(self.admission))
        self.assertEqual(result["inputs"]["admission"]["raw_file_sha256"], example.digest(reformatted))

    def test_constraint_and_time_failures(self):
        admission = self.fixture("attenuate-max-amount")
        post = self.linked_post(admission)
        amount = admission["attenuation"]["effective_constraints"]["max_amount"]
        post["result"]["side_effects"] = [{"amount": {"currency": amount["currency"], "value": "9999.00"}}]
        result = self.reader.assess(encode(admission), encode(post))
        self.assertIn("POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED", result["core_result"]["reason_codes"])
        post = self.linked_post(admission)
        post["execution"]["finished_at"] = "2099-01-01T00:00:00Z"
        result = self.reader.assess(encode(admission), encode(post))
        self.assertIn("POST_EXEC_ADMISSION_EXPIRED", result["core_result"]["reason_codes"])

    def test_malformed_reported_amount_is_not_assessed(self):
        admission = self.fixture("attenuate-max-amount")
        for amount in (None, "10.00", [], {}, {"currency": "USD", "value": None}):
            with self.subTest(amount=amount):
                post = self.linked_post(admission)
                post["result"]["side_effects"] = [{"amount": amount}]
                result = self.reader.assess(encode(admission), encode(post))
                self.assertEqual(result["record_linkage"], "not_assessed")
                self.assertTrue(any(i["input"] == "post" and i["kind"] == "semantic_input_invalid"
                                    for i in result["input_issues"]))
                self.assertIsNone(result["core_result"])

    def test_time_precision_and_supported_spellings(self):
        for start, finish, expected in (
            ("2026-09-15T06:35:05.0000001Z", "2026-09-15T06:35:05.0000002Z", "not_assessed"),
            ("2026-09-15T06:25:06.0000009Z", "2026-09-15T06:25:06.0000001Z", "not_assessed"),
            ("2026-09-15T06:25:06.000009Z", "2026-09-15T06:25:06.000001Z", "mismatch"),
            ("2026-09-15T06:35:05.000001Z", "2026-09-15T06:35:05.000002Z", "mismatch"),
            ("2026-09-15t06:25:06.000001z", "2026-09-15T06:25:06.000009+00:00", "matched"),
            ("2026-09-15T07:25:06+01:00", "2026-09-15T06:25:07Z", "matched"),
            ("2026-09-15T06:35:05Z", "2026-09-15T06:35:05Z", "matched"),
        ):
            with self.subTest(start=start, finish=finish):
                post = json.loads(self.post)
                post["execution"].update(started_at=start, finished_at=finish)
                post["issued_at"] = "2026-09-15T06:35:06Z"
                result = self.reader.assess(self.admission, encode(post))
                self.assertEqual(result["record_linkage"], expected)
                if expected == "not_assessed":
                    self.assertIsNone(result["core_result"])
                elif expected == "mismatch":
                    self.assertIn("POST_EXEC_ADMISSION_EXPIRED", result["core_result"]["reason_codes"])

    def test_all_supported_fraction_lengths_preserve_the_instant_and_input(self):
        for fraction in ("1", "12", "123", "1234", "12345", "123456"):
            expected = datetime(2026, 9, 15, 6, 25, 5, int(fraction.ljust(6, "0")), tzinfo=timezone.utc)
            for clock, zone in (("06:25:05", "Z"), ("06:25:05", "z"),
                                ("07:25:05", "+01:00"), ("05:55:05", "-00:30")):
                timestamp = f"2026-09-15t{clock}.{fraction}{zone}"
                with self.subTest(timestamp=timestamp):
                    self.assertEqual(self.reader.core.parse_time(timestamp), expected)
                    self.assertEqual(self.reader.runner.try_parse_time(timestamp), expected)
                    post = json.loads(self.post)
                    post["execution"]["started_at"] = timestamp
                    raw = encode(post)
                    result = self.reader.assess(self.admission, raw)
                    self.assertEqual(result["record_linkage"], "matched")
                    self.assertEqual(result["inputs"]["post"]["raw_file_sha256"], example.digest(raw))
                    self.assertEqual(post["execution"]["started_at"], timestamp)

    def test_reported_amount_scope_depends_on_effective_cap(self):
        for capped in (False, True):
            admission = json.loads(self.admission)
            admission["request"]["constraints"] = (
                {"max_amount": {"currency": "USD", "value": "100.00"}} if capped else {})
            for amount, capped_result in (
                (None, "not_assessed"),
                ({"currency": "USD", "value": "-1.00"}, "not_assessed"),
                ({"currency": "USD", "value": "0.000000001"}, "not_assessed"),
                ({"currency": "USD\n", "value": "1.00"}, "not_assessed"),
                ({"currency": "USD", "value": "1.00"}, "matched"),
                ({"currency": "USD", "value": "101.00"}, "mismatch"),
            ):
                with self.subTest(capped=capped, amount=amount):
                    post = self.linked_post(admission)
                    post["result"]["side_effects"] = [{"amount": amount}]
                    result = self.reader.assess(encode(admission), encode(post))
                    self.assertEqual(result["record_linkage"], capped_result if capped else "matched")
                    if not capped:
                        self.assertNotIn("runner_reported_amount_validation", result["linkage_checks_run"])
                        self.assertIn("reported_amounts_without_max_amount_constraint", result["not_checked"])
                    elif capped_result == "not_assessed":
                        self.assertEqual(result["linkage_checks_run"], [])
                    else:
                        self.assertIn("runner_reported_amount_validation", result["linkage_checks_run"])
                        self.assertNotIn("reported_amounts_without_max_amount_constraint", result["not_checked"])

    def test_tools_without_allowlist_are_reported_as_unchecked(self):
        admission = json.loads(self.admission)
        admission["request"]["constraints"] = {}
        post = self.linked_post(admission)
        post["result"]["side_effects"] = [{"tool": None}]
        result = self.reader.assess(encode(admission), encode(post))
        self.assertEqual(result["record_linkage"], "matched")
        self.assertIn("reported_tools_without_tool_allowlist_constraint", result["not_checked"])
        admission["request"]["constraints"] = {"tool_allowlist": ["files/write"]}
        post = self.linked_post(admission)
        post["result"]["side_effects"] = [{"tool": "files/write"}]
        result = self.reader.assess(encode(admission), encode(post))
        self.assertEqual(result["record_linkage"], "matched")
        self.assertNotIn("reported_tools_without_tool_allowlist_constraint", result["not_checked"])

    def test_numeric_precision_loss_is_not_assessed_before_linkage(self):
        for role in ("admission", "post"):
            for literal in ("1000000000.00000001", "1.00000000000000001e9", "1e-999"):
                with self.subTest(role=role, literal=literal):
                    admission = json.loads(self.admission)
                    admission["request"]["constraints"] = {"max_amount": {"currency": "USD", "value": "1000000000.00"}}
                    post = self.linked_post(admission)
                    post["result"]["side_effects"] = [{"amount": {"currency": "USD", "value": "1.00"}}]
                    target = (admission["request"]["constraints"]["max_amount"] if role == "admission" else
                              post["result"]["side_effects"][0]["amount"])
                    target["value"] = "RAW_NUMBER"
                    raws = {"admission": encode(admission), "post": encode(post)}
                    raws[role] = raws[role].replace(b'"RAW_NUMBER"', literal.encode())
                    result = self.reader.assess(raws["admission"], raws["post"])
                    self.assertEqual(result["record_linkage"], "not_assessed")
                    self.assertIsNone(result["core_result"])
                    self.assertTrue(any(i["input"] == role and "precision" in i.get("detail", "")
                                        for i in result["input_issues"]))

    def test_supported_numeric_and_string_amounts_preserve_comparison(self):
        admission = json.loads(self.admission)
        admission["request"]["constraints"] = {"max_amount": {"currency": "USD", "value": "1000000000.00"}}
        for amount, expected in ((0.1, "matched"), (1e-8, "matched"), (1000000000, "matched"),
                                 (1000000000.0, "matched"), (1000000001.0, "mismatch"),
                                 ("1000000000.00000001", "mismatch")):
            with self.subTest(amount=amount):
                post = self.linked_post(admission)
                post["result"]["side_effects"] = [{"amount": {"currency": "USD", "value": amount}}]
                result = self.reader.assess(encode(admission), encode(post))
                self.assertEqual(result["record_linkage"], expected)
                self.assertEqual(result["input_issues"], [])

    def test_amount_outside_core_bounds_is_not_a_violation_verdict(self):
        for role in ("admission", "post"):
            for amount in ("0.000000001", 1e-9, "1000000000000000000", "1." + "0" * 63):
                with self.subTest(role=role, amount=amount):
                    admission = json.loads(self.admission)
                    admission["request"]["constraints"] = {"max_amount": {"currency": "USD", "value": "1.00"}}
                    if role == "admission":
                        admission["request"]["constraints"]["max_amount"]["value"] = amount
                    post = self.linked_post(admission)
                    post["result"]["side_effects"] = [{"amount": {"currency": "USD", "value": amount if role == "post" else "0.00"}}]
                    result = self.reader.assess(encode(admission), encode(post))
                    self.assertEqual(result["record_linkage"], "not_assessed")
                    self.assertIsNone(result["core_result"])

    def test_decision_reason_and_evidence_combinations(self):
        for kind in ("reason", "evidence"):
            admission = json.loads(self.admission)
            if kind == "reason":
                admission["decision"]["reason_codes"] = ["FAIL_CLOSED"]
            else:
                admission["evidence"][0]["protocol_hint"] = "ap2"
            result = self.reader.assess(encode(admission), encode(self.linked_post(admission)))
            self.assertEqual(result["record_linkage"], "not_assessed")
            self.assertIsNone(result["core_result"])
        admission = json.loads(self.admission)
        admission["evidence"][0]["type"] = "payment_mandate"
        admission["evidence"][0]["protocol_hint"] = "ap2"
        self.assertEqual(self.reader.assess(encode(admission), encode(self.linked_post(admission)))["record_linkage"], "matched")

    def test_declared_hashes_and_digests_reject_terminal_newlines(self):
        for role, path in (
            ("admission", ["request", "input_hash"]),
            ("admission", ["evidence", 0, "digest", "value"]),
            ("post", ["admission", "digest", "value"]),
            ("post", ["execution", "effective_request_hash"]),
            ("post", ["result", "output_hash"]),
        ):
            with self.subTest(role=role, path=path):
                admission, post = json.loads(self.admission), json.loads(self.post)
                target = admission if role == "admission" else post
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] += "\n"
                if role == "admission":
                    post["admission"]["digest"] = self.reader.runner.digest_descriptor(admission)
                result = self.reader.assess(encode(admission), encode(post))
                self.assertEqual(result["record_linkage"], "not_assessed")
                self.assertIsNone(result["core_result"])

    def test_malformed_allow_constraint_is_not_assessed(self):
        for field, values in (("max_amount", (None, "10.00", [], {})),
                              ("tool_allowlist", (None, "files/write", [42], [""]))):
            for value in values:
                with self.subTest(field=field, value=value):
                    admission = json.loads(self.admission)
                    admission["request"]["constraints"] = {field: value}
                    result = self.reader.assess(encode(admission), encode(self.linked_post(admission)))
                    self.assertEqual(result["record_linkage"], "not_assessed")
                    self.assertTrue(any(i["input"] == "admission" for i in result["input_issues"]))
                    self.assertIsNone(result["core_result"])

    def test_legacy_effective_constraint_names_are_not_assessed(self):
        for field, value in (("max_amount_usd", "100.00"), ("max_amount_usd", None),
                             ("resource", "deploy:production"),
                             ("approval", "human_required"), ("approval", "")):
            for with_canonical_cap in (False, True):
                with self.subTest(field=field, value=value, canonical=with_canonical_cap):
                    admission = json.loads(self.admission)
                    constraints = {field: value}
                    if with_canonical_cap:
                        constraints["max_amount"] = {"currency": "USD", "value": "200.00"}
                    admission["request"]["constraints"] = constraints
                    post = self.linked_post(admission)
                    post["result"]["side_effects"] = [{"amount": {"currency": "USD", "value": "120.00"}}]
                    a_raw, p_raw = encode(admission), encode(post)
                    result = self.reader.assess(a_raw, p_raw)
                    self.assertEqual(result["record_linkage"], "not_assessed")
                    self.assertIsNone(result["core_result"])
                    self.assertEqual(result["linkage_checks_run"], [])
                    self.assertTrue(any(i["input"] == "admission" and
                                        i["kind"] == "semantic_input_invalid" and
                                        i.get("path") == ["request", "constraints", field]
                                        for i in result["input_issues"]))
                    self.assertEqual(result["inputs"]["admission"]["raw_file_sha256"], example.digest(a_raw))
                    self.assertEqual((a_raw, p_raw), (encode(admission), encode(post)))

    def test_canonical_constraints_and_nested_alias_annotations_remain_supported(self):
        admission = json.loads(self.admission)
        admission["request"]["constraints"] = {
            "max_amount": {"currency": "USD", "value": "100.00"},
            "target_resource": "deploy:production",
            "approval": {"mode": "human_required"},
            "vendor_annotation": {"max_amount_usd": "1.00", "resource": "note", "approval": "note"},
        }
        for amount, expected in (("100.00", "matched"), ("120.00", "mismatch")):
            with self.subTest(amount=amount):
                post = self.linked_post(admission)
                post["result"]["side_effects"] = [{"amount": {"currency": "USD", "value": amount}}]
                result = self.reader.assess(encode(admission), encode(post))
                self.assertEqual(result["record_linkage"], expected)
                self.assertEqual(result["input_issues"], [])
                if expected == "mismatch":
                    self.assertIn("POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED", result["core_result"]["reason_codes"])

    def test_noncanonical_amount_and_currency_is_not_assessed(self):
        for role in ("admission", "post"):
            for field, value in (("value", "10.00\n"), ("currency", "USD\n")):
                with self.subTest(role=role, field=field):
                    admission = json.loads(self.admission)
                    admission["request"]["constraints"] = {"max_amount": {"currency": "USD", "value": "100.00"}}
                    if role == "admission":
                        admission["request"]["constraints"]["max_amount"][field] = value
                    post = self.linked_post(admission)
                    post["result"]["side_effects"] = [{"amount": {"currency": "USD", "value": "10.00"}}]
                    if role == "post":
                        post["result"]["side_effects"][0]["amount"][field] = value
                    result = self.reader.assess(encode(admission), encode(post))
                    self.assertEqual(result["record_linkage"], "not_assessed")
                    self.assertTrue(any(i["input"] == role for i in result["input_issues"]))
                    self.assertIsNone(result["core_result"])

    def test_amount_currency_and_aggregate_mismatches_remain_assessed(self):
        admission = json.loads(self.admission)
        admission["request"]["constraints"] = {"max_amount": {"currency": "USD", "value": "100.00"}}
        for amounts in (({"currency": "EUR", "value": "1.00"},),
                        ({"currency": "USD", "value": "60.00"}, {"currency": "USD", "value": "60.00"})):
            with self.subTest(amounts=amounts):
                post = self.linked_post(admission)
                post["result"]["side_effects"] = [{"amount": amount} for amount in amounts]
                result = self.reader.assess(encode(admission), encode(post))
                self.assertEqual(result["record_linkage"], "mismatch")
                self.assertEqual(result["input_issues"], [])
                self.assertIn("POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED", result["core_result"]["reason_codes"])
                self.assertTrue(result["side_effect_check_failures"])

    def test_reported_tool_allowlist_and_core_aliases(self):
        admission = json.loads(self.admission)
        admission["request"]["constraints"] = {"tool_allowlist": ["files/write"]}
        for alias in ("tool", "tool_id", "name"):
            for tool, expected in (("files/write", "matched"), ("files/delete", "mismatch")):
                with self.subTest(alias=alias, tool=tool):
                    post = self.linked_post(admission)
                    post["result"]["side_effects"] = [{alias: tool}]
                    result = self.reader.assess(encode(admission), encode(post))
                    self.assertEqual(result["record_linkage"], expected)
                    self.assertEqual(result["input_issues"], [])
                    if expected == "mismatch":
                        self.assertIn("POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED", result["core_result"]["reason_codes"])

    def test_malformed_reported_tool_is_not_assessed(self):
        admission = json.loads(self.admission)
        admission["request"]["constraints"] = {"tool_allowlist": ["files/write"]}
        for tool in (None, "", [], {}, 0, False):
            with self.subTest(tool=tool):
                post = self.linked_post(admission)
                post["result"]["side_effects"] = [{"tool": tool}]
                result = self.reader.assess(encode(admission), encode(post))
                self.assertEqual(result["record_linkage"], "not_assessed")
                self.assertIsNone(result["core_result"])
        post["result"]["side_effects"] = [{"tool": None, "tool_id": "files/write"}]
        self.assertEqual(self.reader.assess(encode(admission), encode(post))["record_linkage"], "matched")

    def test_tool_alias_precedence_and_filename_fallback(self):
        admission = json.loads(self.admission)
        admission["request"]["constraints"] = {"tool_allowlist": ["files/write"]}
        for effect, expected in (
            ({"tool": "files/write", "name": "summary.txt"}, "matched"),
            ({"tool": "files/write", "tool_id": "files/delete"}, "matched"),
            ({"tool_id": "files/write", "name": "summary.txt"}, "matched"),
            ({"name": "summary.txt"}, "mismatch"),
        ):
            with self.subTest(effect=effect):
                post = self.linked_post(admission)
                post["result"]["side_effects"] = [effect]
                result = self.reader.assess(encode(admission), encode(post))
                self.assertEqual(result["record_linkage"], expected)
                self.assertEqual(result["input_issues"], [])

    def test_missing_effect_fields_do_not_establish_completeness(self):
        admission = json.loads(self.admission)
        admission["request"]["constraints"] = {
            "max_amount": {"currency": "USD", "value": "100.00"}, "tool_allowlist": ["files/write"]}
        post = self.linked_post(admission)
        post["result"]["side_effects"] = [{"local_note": "no reported amount or tool"}]
        result = self.reader.assess(encode(admission), encode(post))
        self.assertEqual(result["record_linkage"], "matched")
        self.assertIn("completeness_of_reported_side_effects", result["not_checked"])

    def test_cli_all_three_exit_codes(self):
        for post_path, expected_exit, expected_state in (
            ("inputs/R17/post.json", 0, "matched"),
            ("inputs/synthetic-runtime-mismatch.json", 1, "mismatch"),
            (None, 2, "not_assessed"),
        ):
            with self.subTest(post_path=post_path):
                args = ["--admission", example.HERE / "inputs/R17/admission.json"]
                if post_path:
                    args += ["--post", example.HERE / post_path]
                result = self.cli(*args)
                self.assertEqual(result.returncode, expected_exit, result.stderr)
                output = json.loads(result.stdout)
                self.assertEqual(output["record_linkage"], expected_state)
                self.assertEqual(output["inputs"]["admission"]["file_status"], "read")
                self.assertEqual(output["inputs"]["post"]["file_status"], "read" if post_path else "not_specified")

    def test_cli_file_errors_and_size_bound_do_not_hash_partial_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "receipt.json"
            for state in ("missing", "directory", "oversize"):
                with self.subTest(state=state):
                    if state == "directory":
                        p.mkdir()
                    elif state == "oversize":
                        p.rmdir()
                        p.write_bytes(b" " * (example.MAX_INPUT_BYTES + 1))
                    result = self.cli("--admission", p, "--post", example.HERE / "inputs/R17/post.json")
                    output = json.loads(result.stdout)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(output["record_linkage"], "not_assessed")
                    self.assertIsNone(output["inputs"]["admission"]["raw_file_sha256"])
                    self.assertFalse(output["inputs"]["admission"]["supplied"])
                    self.assertEqual(output["inputs"]["admission"]["file_status"],
                                     "too_large" if state == "oversize" else "unreadable")
                    self.assertEqual(output["inputs"]["post"]["file_status"], "read")
                    self.assertTrue(any(i["kind"] in {"unreadable_file", "input_too_large"} for i in output["input_issues"]))


if __name__ == "__main__":
    unittest.main()
