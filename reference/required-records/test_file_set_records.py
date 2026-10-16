"""Operation-level coverage over fresh, unmodified file-set demo receipts."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

from fixture_inputs import Inputs, ROOT
from required_records import Reviewer, encode

sys.path.insert(0, str(ROOT / "reference/runtime-support"))
from file_set_fixture import capture_cases, operation_context, receipt_pair, tree_hashes


class FileSetRecordsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="vate-file-set-records-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.captures = Path(cls.temp.name) / "captures"
        cls.native_reports = capture_cases(ROOT, cls.captures)
        cls.originals = tree_hashes(cls.captures)

    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="vate-file-set-review-")
        self.addCleanup(self.work.cleanup)
        self.f = Inputs(self.work.name)
        self.f.basis = self.f.store(b"Test-only finite receiver selection and arrival assertions.\n")
        self.f.review["population_basis_refs"] = [self.f.basis]
        self.f.snapshot["collection_basis_ref"] = self.f.basis
        self.f.selection["selection_basis_ref"] = self.f.basis
        self.f.selection["native_policy_refs"] = {"s3": None, "signature": None}
        self.addCleanup(lambda: self.assertEqual(tree_hashes(self.captures), self.originals))

    def setup_pair(self, scenario="allow", *, record="post_execution"):
        admission, post = receipt_pair(self.captures / scenario)
        row = self.f.row(context=operation_context(admission), record=record)
        entry = self.f.pair(admission=admission, post=post)
        if post is None:
            entry["originals"]["post"] = None
        return row, entry

    def assess(self, *, invalid=False):
        result = Reviewer(path_bases=self.f.roots(), source_root=ROOT).assess(self.f.seal())
        self.assertIs(result["invocation_errors"], invalid)
        return result

    def linkage(self, result):
        return result["native_calls"][0]["result"]["native_result"]["record_linkage"]

    def test_both_original_records_bind_for_each_terminal_scenario(self):
        for scenario in ("allow", "attenuate", "response-loss-reconciled"):
            with self.subTest(scenario=scenario):
                self.f.review["requirements"] = []
                self.f.snapshot["entries"] = []
                row, _ = self.setup_pair(scenario)
                self.f.row("admission", context=row["subject"]["native_context"], record="admission", operation="A")
                result = self.assess()
                self.assertEqual([r["record_coverage"] for r in result["requirements"]], ["present", "present"])
                self.assertEqual(self.linkage(result), "matched")

    def test_attenuated_context_matches_retained_effective_input(self):
        for scenario in ("attenuate", "require-new-permit"):
            with self.subTest(scenario=scenario):
                case = self.captures / scenario
                admission = json.loads(receipt_pair(case)[0])
                effective = (case / "admission-1/effective-operation.json").read_bytes()
                expected = "sha-256:" + hashlib.sha256(effective).hexdigest()
                self.assertNotEqual(admission["request"]["input_hash"], expected)
                self.assertEqual(admission["attenuation"]["effective_request_hash"], expected)
                self.assertEqual(operation_context(receipt_pair(case)[0])["effective_request_hash"], expected)

    def test_new_permit_admission_presence_does_not_assert_execution(self):
        row, _ = self.setup_pair("require-new-permit", record="admission")
        self.f.row("post", context=row["subject"]["native_context"], operation="A")
        result = self.assess()
        self.assertEqual([r["record_coverage"] for r in result["requirements"]], ["present", "missing"])
        self.assertEqual(self.linkage(result), "not_assessed")
        self.assertEqual(self.native_reports["require-new-permit"]["provider_execution_count"], 0)
        self.assertIn("current_permission_to_execute", result["not_checked"])

    def test_unrelated_attenuated_admission_does_not_obscure_selected_record(self):
        self.setup_pair(record="admission")
        admission, post = receipt_pair(self.captures / "attenuate")
        self.f.pair("other", admission=admission, post=post)
        result = self.assess()
        self.assertEqual(result["requirements"][0]["record_coverage"], "present")
        self.assertEqual([c["reason"] for c in result["requirements"][0]["candidates"]],
                         ["CONTEXT_MATCHED", "CONTEXT_MISMATCH"])

    def test_unusable_file_set_hash_selection_stays_unresolved(self):
        _, entry = self.setup_pair("attenuate", record="admission")
        original = json.loads(receipt_pair(self.captures / "attenuate")[0])
        variants = []
        for field in ("decision", "attenuation"):
            changed = deepcopy(original); del changed[field]; variants.append(changed)
            for value in (None, [], {}, "invalid"):
                changed = deepcopy(original); changed[field] = value; variants.append(changed)
        for value in (None, [], {}, "unknown"):
            changed = deepcopy(original); changed["decision"]["outcome"] = value; variants.append(changed)
        for value in (None, [], {}, original["request"]["input_hash"]):
            changed = deepcopy(original); changed["attenuation"]["effective_request_hash"] = value
            variants.append(changed)
        for index, changed in enumerate(variants):
            with self.subTest(variant=index):
                entry["originals"]["admission"] = self.f.event(encode(changed))
                result = self.assess()
                self.assertEqual(result["requirements"][0]["record_coverage"], "unresolved")
                self.assertEqual(result["requirements"][0]["candidates"][0]["reason"], "UNSUPPORTED_CONTEXT")

    def test_missing_post_does_not_mean_no_provider_execution(self):
        self.setup_pair("response-loss")
        result = self.assess()
        self.assertEqual(result["requirements"][0]["record_coverage"], "missing")
        self.assertEqual(self.linkage(result), "not_assessed")
        self.assertEqual(self.native_reports["response-loss"]["provider_execution_count"], 1)
        self.assertIn("actual_execution", result["not_checked"])
        self.assertIn("current_permission_to_execute", result["not_checked"])

    def test_s3_and_file_set_operations_share_one_finite_review(self):
        self.setup_pair()
        self.f.row("S3", context=self.f.context)
        self.f.pair("S3")
        result = self.assess()
        self.assertEqual([r["record_coverage"] for r in result["requirements"]], ["present", "present"])
        for row in result["requirements"]:
            self.assertEqual(sorted(c["reason"] for c in row["candidates"]), ["CONTEXT_MATCHED", "CONTEXT_MISMATCH"])
        self.assertEqual([c["result"]["native_result"]["record_linkage"] for c in result["native_calls"]],
                         ["matched", "matched"])

    def test_other_operations_original_post_does_not_fill_selected_requirement(self):
        _, entry = self.setup_pair()
        entry["originals"]["post"] = self.f.event(receipt_pair(self.captures / "response-loss-reconciled")[1])
        result = self.assess()
        self.assertEqual(result["requirements"][0]["record_coverage"], "missing")
        self.assertEqual(result["requirements"][0]["candidates"][0]["reason"], "CONTEXT_MISMATCH")
        self.assertEqual(self.linkage(result), "mismatch")

    def test_runtime_and_hash_are_not_replaced_by_operation_labels(self):
        _, entry = self.setup_pair()
        original = json.loads(receipt_pair(self.captures / "allow")[1])
        for field in ("runtime", "hash"):
            with self.subTest(field=field):
                post = deepcopy(original)
                if field == "runtime":
                    post["execution"]["runtime"] = "urn:example:other-runtime"
                else:
                    post["execution"]["effective_request_hash"] = "sha-256:" + "0" * 64
                    post["execution"]["action_binding"]["digest"]["value"] = "0" * 64
                entry["originals"]["post"] = self.f.event(encode(post))
                result = self.assess()
                self.assertEqual(result["requirements"][0]["record_coverage"], "missing")
                self.assertEqual(self.linkage(result), "mismatch")

    def test_unknown_or_malformed_context_stays_unresolved(self):
        _, entry = self.setup_pair()
        original = json.loads(receipt_pair(self.captures / "allow")[1])
        variants = [("preimage_profile", "unknown-profile"), ("preimage_profile", []),
                    ("preimage_profile", {}), ("canonicalization", "other-json")]
        for field, value in variants:
            with self.subTest(field=field, value=value):
                post = deepcopy(original)
                post["execution"]["action_binding"][field] = value
                entry["originals"]["post"] = self.f.event(encode(post))
                result = self.assess()
                self.assertEqual(result["requirements"][0]["record_coverage"], "unresolved")
                self.assertEqual(result["requirements"][0]["candidates"][0]["reason"], "UNSUPPORTED_CONTEXT")

    def test_malformed_selected_profile_is_invalid_not_an_uncaught_type_error(self):
        row, _ = self.setup_pair()
        for value in ([], {}, "unknown-profile"):
            with self.subTest(value=value):
                row["subject"]["native_context"]["action_binding"]["preimage_profile"] = value
                result = self.assess(invalid=True)
                self.assertEqual(result["review_set_status"], "invalid")
                self.assertEqual(result["requirements"], [])

    def test_admission_action_must_match_its_own_profile(self):
        for admission, wrong_action in ((receipt_pair(self.captures / "allow")[0], "s3.put_object"),
                                        (self.f.admission, "demo.create_file_set")):
            with self.subTest(action=wrong_action):
                self.f.review["requirements"] = []
                self.f.snapshot["entries"] = []
                self.f.row(context=operation_context(admission), record="admission")
                changed = json.loads(admission)
                changed["request"]["action"] = wrong_action
                entry = self.f.pair(admission=encode(changed))
                entry["originals"]["post"] = None
                result = self.assess()
                self.assertEqual(result["requirements"][0]["record_coverage"], "unresolved")
                self.assertEqual(result["requirements"][0]["candidates"][0]["reason"], "UNSUPPORTED_CONTEXT")

    def test_file_set_attempt_is_not_accepted_as_s3_attempt(self):
        row, _ = self.setup_pair()
        row["subject"].update(kind="attempt", attempt_id="attempt-label")
        row["binding_profile"] = "vate_s3_attempt_context"
        result = self.assess(invalid=True)
        self.assertEqual(result["review_set_status"], "invalid")
        self.assertEqual(result["requirements"], [])

    def test_presence_and_failed_receipt_linkage_remain_separate(self):
        _, entry = self.setup_pair()
        changed = json.loads(receipt_pair(self.captures / "allow")[1])
        changed["admission"]["digest"]["value"] = "0" * 64
        entry["originals"]["post"] = self.f.event(encode(changed))
        result = self.assess()
        self.assertEqual(result["requirements"][0]["record_coverage"], "present")
        self.assertEqual(self.linkage(result), "mismatch")


if __name__ == "__main__":
    unittest.main()
