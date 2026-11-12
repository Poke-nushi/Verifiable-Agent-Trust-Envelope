"""AL2 context facts must correspond to the selected admission records."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import vate_conformance as runner


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "conformance/al2-vate-v0.3"


def read(path):
    return json.loads(path.read_bytes())


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


class ContextCorrespondenceTests(unittest.TestCase):
    def select(self, name):
        self.case = read(CORPUS / "cases" / (name + ".json"))
        self.artifacts = {key: read(ROOT / path) for key, path in self.case["artifacts"].items()}
        self.context_key = self.case["al2_context_checks"][0]["artifact"]
        self.context = self.artifacts[self.context_key]
        self.receipt = self.artifacts["admission_receipt"]

    def evaluate(self):
        def load(case, key):
            value = self.artifacts.get(key)
            return (copy.deepcopy(value), None) if isinstance(value, dict) else (None, "artifact missing")
        with patch.object(runner, "read_case_artifact", side_effect=load):
            return runner.evaluate_al2_context_checks(self.case)

    def assert_rejected(self, fragment):
        failures = self.evaluate()
        self.assertTrue(failures, "inconsistent records passed")
        self.assertIn(fragment, "\n".join(failures))

    def select_runtime_checks(self, *, matched=True, fresh=False):
        self.select("deny-runtime-proof-stale")
        self.context["source_issued_at"] = (self.context["checked_at"] if fresh
                                              else "2026-07-01T00:00:00Z")
        self.context["failure_reason"] = None if fresh else "RUNTIME_PROOF_STALE"
        freshness = self.case["al2_context_checks"][0]
        freshness["expect_fresh"] = fresh
        if fresh:
            freshness.pop("expected_failure_reason")
        runtime = self.receipt["subject"]["runtime"]
        self.artifacts["runtime_binding"] = {
            "binding": "runtime", "actual": runtime,
            "expected": runtime if matched else "urn:other-permitted-runtime",
            "failure_reason": None if matched else "RUNTIME_MISMATCH",
        }
        self.case["artifacts"]["runtime_binding"] = "runtime-binding.json"
        binding = {"kind": "binding", "artifact": "runtime_binding", "expect_match": matched}
        if not matched:
            binding["expected_failure_reason"] = "RUNTIME_MISMATCH"
        self.case["al2_context_checks"].append(binding)
        self.runtime_evidence = next(e for e in self.receipt["evidence"] if e["type"] == "runtime_attestation")
        result = "failed" if not matched else ("verified" if fresh else "stale")
        self.runtime_evidence["verification"]["result"] = result
        self.receipt["decision"]["outcome"] = "allow" if result == "verified" else "deny"
        return result

    def test_runtime_combination_result_and_order(self):
        for matched in (True, False):
            for fresh in (True, False):
                for reverse in (True, False):
                    for result in ("verified", "stale", "failed", "unavailable", None, {}, [], 1):
                        with self.subTest(matched=matched, fresh=fresh, reverse=reverse, result=result):
                            expected = self.select_runtime_checks(matched=matched, fresh=fresh)
                            if reverse:
                                self.case["al2_context_checks"].reverse()
                            self.runtime_evidence["verification"]["result"] = result
                            if result == expected:
                                self.assertEqual(self.evaluate(), [])
                            else:
                                self.assert_rejected("verification.result")

    def test_standalone_runtime_checks_still_require_their_own_result(self):
        for retained_kind, matched, fresh, expected in (
            ("binding", True, False, "verified"), ("binding", False, False, "failed"),
            ("freshness", False, True, "verified"), ("freshness", False, False, "stale"),
        ):
            for result in ("verified", "stale", "failed", "unavailable"):
                with self.subTest(kind=retained_kind, result=result):
                    self.select_runtime_checks(matched=matched, fresh=fresh)
                    self.case["al2_context_checks"] = [c for c in self.case["al2_context_checks"]
                                                       if c["kind"] == retained_kind]
                    # An unselected context artifact cannot justify another result.
                    self.runtime_evidence["verification"]["result"] = result
                    if result == expected:
                        self.assertEqual(self.evaluate(), [])
                    else:
                        self.assert_rejected("verification.result")

    def test_runtime_context_conflicts_cannot_be_hidden_by_another_failure(self):
        for kind in ("binding", "freshness"):
            for reverse in (True, False):
                for result in ("verified", "stale", "failed"):
                    with self.subTest(kind=kind, reverse=reverse, result=result):
                        self.select_runtime_checks()
                        key = "runtime_binding" if kind == "binding" else "runtime_context"
                        other = copy.deepcopy(self.artifacts[key])
                        check = copy.deepcopy(next(c for c in self.case["al2_context_checks"] if c["kind"] == kind))
                        check["artifact"] = "conflicting_context"
                        if kind == "binding":
                            other.update(expected="urn:other-permitted-runtime", failure_reason="RUNTIME_MISMATCH")
                            check.update(expect_match=False, expected_failure_reason="RUNTIME_MISMATCH")
                        else:
                            other.update(source_issued_at=other["checked_at"], failure_reason=None)
                            check.update(expect_fresh=True)
                            check.pop("expected_failure_reason")
                        self.artifacts["conflicting_context"] = other
                        self.case["artifacts"]["conflicting_context"] = "conflicting-context.json"
                        self.case["al2_context_checks"].append(check)
                        if reverse:
                            self.case["al2_context_checks"].reverse()
                        self.runtime_evidence["verification"]["result"] = result
                        self.assert_rejected(f"conflicting {kind}")

    def test_runtime_combination_preserves_context_correspondence_and_deny(self):
        for change in ("missing", "invalid-time", "different-time", "invalid-age", "wrong-source", "wrong-runtime"):
            with self.subTest(change=change):
                self.select_runtime_checks()
                if change == "missing":
                    del self.artifacts["runtime_context"]
                elif change == "invalid-time":
                    self.context["checked_at"] = []
                elif change == "different-time":
                    self.context["checked_at"] = "2026-07-01T00:12:06Z"
                elif change == "invalid-age":
                    self.context["max_age_seconds"] = True
                elif change == "wrong-source":
                    self.context["source"] = "other"
                else:
                    self.artifacts["runtime_binding"].update(actual="urn:other", expected="urn:other")
                self.assertTrue(self.evaluate())
        for matched, fresh in ((True, False), (False, True), (False, False)):
            for decision in ("allow", "attenuate"):
                with self.subTest(matched=matched, fresh=fresh, decision=decision):
                    self.select_runtime_checks(matched=matched, fresh=fresh)
                    self.receipt["decision"]["outcome"] = decision
                    self.assert_rejected("decision.outcome")

    def test_runtime_result_is_not_combined_with_other_evidence(self):
        self.select_runtime_checks()
        status_case = read(CORPUS / "cases/allow-valid-with-status-fresh.json")
        other = {k: read(ROOT / path) for k, path in status_case["artifacts"].items()}
        status_check = copy.deepcopy(status_case["al2_context_checks"][0])
        context = other[status_check["artifact"]]
        context.update(checked_at=self.context["checked_at"], source_issued_at=self.context["checked_at"])
        evidence = copy.deepcopy(next(e for e in other["admission_receipt"]["evidence"] if e["type"] == "status_bundle"))
        evidence["verification"]["checked_at"] = context["checked_at"]
        self.artifacts[status_check["artifact"]] = context
        self.case["artifacts"][status_check["artifact"]] = "status-context.json"
        self.case["al2_context_checks"].append(status_check)
        self.receipt["evidence"].append(evidence)
        self.assertEqual(self.evaluate(), [])
        evidence["verification"]["result"] = "stale"
        self.assert_rejected("must be verified")

    def test_combined_runtime_rejection_record_passes_run_compare_and_bundle(self):
        self.select_runtime_checks()
        # Keep both copied inputs schema-valid; the historical request uses a
        # placeholder digest, which is unrelated to the combination regression.
        self.artifacts["admission_request"]["evidence_refs"][0]["digest"] = copy.deepcopy(self.runtime_evidence["digest"])
        with tempfile.TemporaryDirectory(prefix="vate-combined-context-") as directory:
            root = Path(directory)
            corpus = root / "corpus"
            for key, value in self.artifacts.items():
                path = root / (key + ".json")
                write(path, value)
                self.case["artifacts"][key] = str(path)
            write(corpus / "cases/combined.json", self.case)
            write(corpus / "corpus.json", runner.make_corpus_index(corpus))
            sut = read(ROOT / "examples/conformance/sut-results-pass.example.json")
            result = copy.deepcopy(next(r for r in sut["results"] if r["case_id"] == self.case["case_id"]))
            result["artifacts"]["admission_receipt"].update(
                uri=self.case["artifacts"]["admission_receipt"],
                digest={"alg": "sha-256", "value": runner.case_artifact_sha256(self.case, "admission_receipt")})
            result["artifacts"]["verification_context"] = [
                {"kind": check["kind"], "case_artifact": check["artifact"],
                 "uri": self.case["artifacts"][check["artifact"]], "media_type": "application/json",
                 "digest": {"alg": "sha-256", "value": runner.case_artifact_sha256(self.case, check["artifact"])},
                 "context_bindings": runner.required_context_bindings(self.case, check)}
                for check in self.case["al2_context_checks"]]
            sut["results"] = [result]
            sut["corpus"]["digest"] = runner.corpus_manifest(corpus)[1]
            reports = [("run", runner.run_corpus(corpus), None)]
            for mode in (runner.SUT_ARTIFACT_MODE_CORPUS, runner.SUT_ARTIFACT_MODE_GENERATED):
                sut["artifact_mode"] = mode
                if mode == runner.SUT_ARTIFACT_MODE_GENERATED:
                    write(root / "generated/receipt.json", self.receipt)
                    ref = copy.deepcopy(result["artifacts"]["admission_receipt"])
                    ref.update(uri="generated/receipt.json", local_path="generated/receipt.json")
                    result["generated_artifacts"] = {"admission_receipt": ref}
                path = root / (mode + ".json")
                write(path, sut)
                reports.append((mode, runner.compare_sut_results(corpus, path), path))
            for mode, report, sut_path in reports:
                with self.subTest(mode=mode):
                    self.assertEqual(report["summary"]["failed"], 0, report)
                    report_path = root / (mode + "-report.json")
                    implementation = root / (mode + "-implementation.json")
                    write(report_path, report)
                    args = argparse.Namespace(corpus_root=str(corpus), conformance_report_uri=str(report_path), report=str(report_path))
                    write(implementation, runner.make_implementation_report(args, report))
                    bundle = runner.verify_report_bundle(corpus, report_path, implementation, sut_path)
                    self.assertEqual(bundle["status"], "pass", bundle)

    def test_existing_context_cases_retain_their_expected_results(self):
        names = [path.stem for path in sorted((CORPUS / "cases").glob("*.json"))
                 if read(path).get("al2_context_checks")]
        self.assertEqual(len(names), 13)
        for name in names:
            with self.subTest(case=name):
                self.select(name)
                self.assertEqual(self.evaluate(), [])

    def test_runtime_pair_cannot_move_together_to_another_runtime(self):
        self.select("allow-valid-admission")
        self.context.update(expected="urn:other-runtime", actual="urn:other-runtime")
        self.assert_rejected("subject.runtime")

    def test_runtime_negative_case_binds_actual_not_expected(self):
        self.select("deny-runtime-mismatch")
        self.assertEqual(self.context["actual"], self.receipt["subject"]["runtime"])
        self.assertNotEqual(self.context["expected"], self.receipt["subject"]["runtime"])
        self.assertEqual(self.evaluate(), [])
        self.context["actual"] = "urn:another-mismatching-runtime"
        self.assert_rejected("subject.runtime")

    def test_missing_or_ambiguous_evidence_cannot_select_a_convenient_entry(self):
        for operation in ("remove", "duplicate", "substitute", "missing-verification", "wrong-result"):
            with self.subTest(operation=operation):
                self.select("allow-valid-admission")
                entry = self.receipt["evidence"][1]
                if operation == "remove":
                    self.receipt["evidence"].pop()
                elif operation == "duplicate":
                    self.receipt["evidence"].append(copy.deepcopy(entry))
                elif operation == "substitute":
                    entry["type"] = "local_policy"
                elif operation == "missing-verification":
                    entry.pop("verification")
                else:
                    entry["verification"]["result"] = "failed"
                self.assert_rejected("evidence")

    def test_unknown_context_sources_and_runtime_subjects_fail(self):
        for name, field in (("allow-valid-admission", "binding"),
                            ("allow-valid-with-status-fresh", "source")):
            for value in (None, [], {}, True, 1, "unsupported"):
                with self.subTest(case=name, field=field, value=value):
                    self.select(name)
                    self.context[field] = value
                    self.assert_rejected("context")

    def test_context_time_must_match_receipt_verification_time(self):
        for name in ("allow-valid-with-status-fresh", "allow-replay-state-unused", "deny-runtime-proof-stale"):
            with self.subTest(case=name):
                self.select(name)
                old = self.context["checked_at"]
                self.context["checked_at"] = old.replace("05Z", "06Z")
                self.assert_rejected("checked_at")

    def test_equal_timestamp_instants_and_receipt_order(self):
        self.select("allow-valid-with-status-fresh")
        self.context["checked_at"] = "2026-07-01T09:00:05+09:00"
        self.assertEqual(self.evaluate(), [])
        self.receipt["issued_at"] = "2026-07-01T00:00:04Z"
        self.assert_rejected("issued_at")

    def test_receipt_cannot_claim_success_for_failed_context(self):
        for name in ("deny-runtime-mismatch", "deny-runtime-proof-stale", "deny-status-revoked",
                     "deny-status-unavailable-fail-closed", "deny-status-stale-fail-closed", "deny-replay-detected"):
            with self.subTest(case=name):
                self.select(name)
                selected = self.receipt["evidence"][0]
                selected["verification"]["result"] = "verified"
                self.assert_rejected("verification.result")
                self.select(name)
                self.receipt["decision"]["outcome"] = "allow"
                self.assert_rejected("decision.outcome")

    def test_status_and_replay_annotations_cannot_contradict_context(self):
        for name in ("allow-valid-with-status-fresh", "allow-replay-state-unused", "deny-status-revoked",
                     "deny-status-unavailable-fail-closed"):
            with self.subTest(case=name):
                self.select(name)
                self.receipt["evidence"][0]["verification"]["status_result"] = "other"
                self.assert_rejected("status_result")
        self.select("deny-status-unavailable-fail-closed")
        self.receipt["evidence"][0]["verification"]["status_result"] = "unavailable"
        self.assertEqual(self.evaluate(), [])

    def test_optional_unavailable_status_preserves_existing_nonblocking_rule(self):
        self.select("deny-status-unavailable-fail-closed")
        self.context["required"] = False
        check = self.case["al2_context_checks"][0]
        check["expect_required"] = False
        check.pop("expected_failure_reason")
        for outcome in ("allow", "attenuate", "deny"):
            with self.subTest(outcome=outcome):
                self.receipt["decision"]["outcome"] = outcome
                self.assertEqual(self.evaluate(), [])
        # Optional does not mean authenticated or successfully observed.
        self.receipt["evidence"][0]["verification"]["result"] = "verified"
        self.assert_rejected("verification.result")

    def test_replay_key_binds_request_and_nonce(self):
        for name in ("allow-replay-state-unused", "deny-replay-detected", "deny-replay-state-replayed"):
            for field, value in (("replay_key", "other-request:nonce-001"), ("nonce", "other-nonce")):
                with self.subTest(case=name, field=field):
                    self.select(name)
                    self.context[field] = value
                    self.assert_rejected("replay_key")

    def test_replay_observation_order(self):
        for value in (None, "bad-time", "2026-07-01T00:11:06Z", [], True):
            with self.subTest(value=value):
                self.select("deny-replay-detected")
                self.context["first_seen_at"] = value
                self.assert_rejected("first_seen_at")

    def test_ap2_consume_key_recomputes_authority_content(self):
        for field in ("digest", "artifact", "canonicalization", "replay_key", "body", "evidence"):
            with self.subTest(field=field):
                self.select("deny-ap2-hnp-replay")
                basis = self.context["consume_key_basis"]
                if field == "digest":
                    basis["digest"]["value"] = "0" * 64
                    self.context["replay_key"] = "vate-fixture-json-sha256:" + "0" * 64
                elif field in ("artifact", "canonicalization"):
                    basis[field] = "unsupported"
                elif field == "replay_key":
                    self.context["replay_key"] = "other-key"
                elif field == "body":
                    self.artifacts["ap2_mandate"]["id"] = "other-authority"
                else:
                    self.receipt["evidence"][0]["digest"]["value"] = "0" * 64
                self.assert_rejected("consume_key")

    def test_available_admission_identity_must_match_receipt(self):
        for field in ("request_id", "transaction_id", "action", "input_hash", "principal", "actor", "runtime"):
            with self.subTest(field=field):
                self.select("deny-runtime-proof-stale")
                self.artifacts["admission_request"][field] = "other"
                self.assert_rejected(field)

    def test_authority_basis_cannot_be_removed_and_annotations_remain_allowed(self):
        self.select("deny-ap2-hnp-replay")
        del self.context["consume_key_basis"]
        self.assert_rejected("consume_key_basis")
        self.select("deny-ap2-hnp-replay")
        for descriptor in (self.context["consume_key_basis"]["digest"], self.receipt["evidence"][0]["digest"],
                           self.artifacts["admission_request"]["evidence_refs"][0]["digest"]):
            descriptor["annotation"] = {"retained": True}
        self.assertEqual(self.evaluate(), [])

    def test_authority_observation_nonce_is_separate_and_request_reference_matches(self):
        for change in ("key-as-nonce", "authority-nonce", "reference-digest", "reference-uri", "duplicate-ref"):
            with self.subTest(change=change):
                self.select("deny-ap2-hnp-replay")
                refs = self.artifacts["admission_request"]["evidence_refs"]
                if change == "key-as-nonce":
                    self.context["nonce"] = self.context["replay_key"]
                elif change == "authority-nonce":
                    self.context["nonce"] = self.artifacts["ap2_mandate"]["constraints"]["replay_nonce"]
                elif change == "reference-digest":
                    refs[0]["digest"]["value"] = "0" * 64
                elif change == "reference-uri":
                    refs[0]["uri"] = "urn:other"
                else:
                    refs.append(copy.deepcopy(refs[0]))
                self.assert_rejected("consume_key")

    def test_missing_records_and_malformed_receipt_sections_fail_closed(self):
        for section in ("request", "subject", "evidence", "decision"):
            for value in (None, [], True, "bad", {}):
                with self.subTest(section=section, value=value):
                    self.select("allow-valid-admission")
                    self.receipt[section] = value
                    self.assert_rejected(section)
        self.select("allow-valid-admission")
        del self.artifacts["admission_receipt"]
        self.assert_rejected("admission_receipt")
        self.select("deny-runtime-proof-stale")
        del self.artifacts["admission_request"]
        self.assert_rejected("admission_request")

    def test_run_compare_and_bundle_reject_digest_consistent_context_mismatch(self):
        self.select("allow-valid-admission")
        with tempfile.TemporaryDirectory(prefix="vate-context-binding-") as directory:
            root = Path(directory)
            corpus = root / "corpus"
            for key, value in self.artifacts.items():
                path = root / (key + ".json")
                write(path, value)
                self.case["artifacts"][key] = str(path)
            case_path = corpus / "cases" / "allow.json"
            write(case_path, self.case)
            write(corpus / "corpus.json", runner.make_corpus_index(corpus))

            def fixture_result():
                sut = read(ROOT / "examples/conformance/sut-results-pass.example.json")
                result = copy.deepcopy(next(item for item in sut["results"] if item["case_id"] == self.case["case_id"]))
                result["artifacts"]["admission_receipt"]["digest"]["value"] = runner.case_artifact_sha256(self.case, "admission_receipt")
                for context in result["artifacts"]["verification_context"]:
                    context["digest"]["value"] = runner.case_artifact_sha256(self.case, context["case_artifact"])
                    check = next(c for c in self.case["al2_context_checks"] if c["artifact"] == context["case_artifact"])
                    context["context_bindings"] = runner.required_context_bindings(self.case, check)
                sut["results"] = [result]
                sut["corpus"]["digest"] = runner.corpus_manifest(corpus)[1]
                path = root / "sut.json"
                write(path, sut)
                return path

            sut_path = fixture_result()
            self.assertTrue(runner.run_corpus(corpus)["cases"][0]["pass"])
            self.assertTrue(runner.compare_sut_results(corpus, sut_path)["cases"][0]["pass"])
            self.context.update(expected="urn:unrelated", actual="urn:unrelated")
            write(Path(self.case["artifacts"][self.context_key]), self.context)
            write(corpus / "corpus.json", runner.make_corpus_index(corpus))
            sut_path = fixture_result()
            run_report = runner.run_corpus(corpus)
            compared = runner.compare_sut_results(corpus, sut_path)
            for mode, report in (("run", run_report), ("compare", compared)):
                with self.subTest(mode=mode):
                    self.assertFalse(report["cases"][0]["pass"])
                    self.assertNotIn("fatal_errors", report)
                    self.assertIn("subject.runtime", " ".join(report["cases"][0]["failures"]))

            # Even a saved success with matching outer digests needs the live
            # context/receipt correspondence check during bundle verification.
            compared["cases"][0]["pass"] = True
            compared["cases"][0]["failures"] = []
            compared["summary"].update(passed=1, failed=0)
            report_path, implementation_path = root / "report.json", root / "implementation.json"
            write(report_path, compared)
            args = argparse.Namespace(corpus_root=str(corpus), conformance_report_uri=str(report_path), report=str(report_path))
            write(implementation_path, runner.make_implementation_report(args, compared))
            bundle = runner.verify_report_bundle(corpus, report_path, implementation_path, sut_path)
            with self.subTest(mode="verify-bundle"):
                self.assertEqual(bundle["status"], "fail")
                self.assertTrue(any(c["name"].startswith("al2_context.") and c["pass"] is False for c in bundle["checks"]))


if __name__ == "__main__":
    unittest.main()
