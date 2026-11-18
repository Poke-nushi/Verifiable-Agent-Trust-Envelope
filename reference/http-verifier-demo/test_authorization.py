"""The HTTP admission decision must preserve issuer and narrowing boundaries."""
import copy
from datetime import timedelta
import json
import math
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import http_verifier_demo as http


AGE_FIELDS = ("status_max_age_seconds", "runtime_max_age_seconds", "permit_max_age_seconds")
INVALID_AGE_LIMITS = (None, True, False, "600", [], {}, -1, 0, 0.5, 1.5, float("inf"), float("nan"))


class AuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="vate-http-authorization-")
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name) / "demo"
        http.generate_demo(cls.directory, policy_path=http.DEFAULT_POLICY)
        cls.scenario = cls.directory / "scenarios/allow-active"
        cls.original = json.loads((cls.scenario / "request.json").read_bytes())
        cls.policy = http.load_policy(http.DEFAULT_POLICY)

    def setUp(self):
        self.request = copy.deepcopy(self.original)

    def payload(self, field):
        return http.demo.decode_compact_jws(self.request["app_context"][field]["jws"])[1]

    def sign(self, field, payload, role):
        header = http.demo.decode_compact_jws(self.original["app_context"][field]["jws"])[0]
        self.request["app_context"][field]["jws"] = http.demo.build_compact_jws(payload,
            key_info={"kid": role + "-key-1", "alg": "ES256",
                      "private_key": http.demo.key_path(self.scenario, role, "private")},
            typ=header["typ"], cty=header["cty"])

    def effect(self, constraints):
        status = self.payload("status")
        status["entries"]["permit"].update({"state": "attenuated", "reason": "test-narrowing",
            "effect": {"mode": "narrow", "require_new_permit": False, "constraints": constraints}})
        self.sign("status", status, "status")

    def evaluate(self, expected, *, policy=None):
        response = http.verify_execute_request(verifier_dir=self.scenario, request=self.request,
                                              policy=self.policy if policy is None else policy)
        self.assertEqual(response["decision"], expected, response["verification_report"]["failed_checks"])
        return response

    def assert_unusable_permit(self):
        response = self.evaluate("deny")
        report = response["verification_report"]
        self.assertIn("mission_permit_signature", report["passed_checks"])
        self.assertIn("mission_permit_signer_role", report["passed_checks"])
        self.assertIn("verification_input", report["failed_checks"])
        self.assertFalse(report["receipt_emitted"])
        self.assertNotIn("admission_receipt", response)
        self.assertNotIn("admission_receipt_jws", response)

    def test_policy_uses_exact_names_and_the_passport_uses_known_levels(self):
        action = self.request["requested_action"]
        for names, decision in (([action, action], "allow"), (["other:" + action], "deny"), ([], "deny")):
            response = self.evaluate(decision, policy={**self.policy, "allowed_actions": names})
            self.assertTrue(response["verification_report"]["receipt_emitted"])
            if decision == "deny":
                self.assertIn("policy_action_allowed", response["verification_report"]["failed_checks"])
        passport = self.payload("passport")
        for level, decision, check in (("AL1", "deny", "passport_assurance_level"),
                                       ("AL4", "allow", None), ("AL5", "deny", "verification_input")):
            passport["assurance_level"] = level
            self.sign("passport", passport, "issuer")
            report = self.evaluate(decision)["verification_report"]
            if check:
                self.assertIn(check, report["failed_checks"])
            self.assertEqual(report["receipt_emitted"], check != "verification_input")

    def test_receipt_omits_absent_principal_and_requires_usable_identity(self):
        permit = self.payload("mission_permit")
        permit.pop("principal")
        self.sign("mission_permit", permit, "broker")
        response = self.evaluate("allow")
        receipt = response["admission_receipt"]
        self.assertNotIn("principal", receipt)
        self.assertEqual(http.demo.decode_compact_jws(response["admission_receipt_jws"])[1], receipt)
        for changed in ({"principal": None}, {"actor": ""}, {"permit_id": []}):
            self.sign("mission_permit", {**permit, **changed}, "broker")
            self.assert_unusable_permit()

    def test_required_numeric_limits_apply_to_active_and_attenuated_permits(self):
        for state in ("active", "attenuated"):
            with self.subTest(state=state):
                self.setUp()
                if state == "attenuated":
                    self.effect({"tool_allowlist": ["summarize"]})
                original = self.payload("mission_permit")
                for field, value in (("max_amount_usd", None), ("max_amount_usd", True),
                                     ("max_redelegation_depth", 0.5)):
                    permit = copy.deepcopy(original)
                    if value is None:
                        del permit["constraints"][field]
                    else:
                        permit["constraints"][field] = value
                    self.sign("mission_permit", permit, "broker")
                    self.assert_unusable_permit()

    def test_signed_runtime_binding_refers_to_the_registered_key_and_subject(self):
        passport = self.payload("passport")
        runtime = self.payload("runtime_proof")
        del passport["subject"]["root_id"]
        del runtime["subject_id"]
        self.sign("passport", passport, "issuer")
        self.sign("runtime_proof", runtime, "attestor")
        missing = self.evaluate("deny")["verification_report"]
        self.assertIn("verification_input", missing["failed_checks"])
        self.assertFalse(missing["receipt_emitted"])
        self.setUp()
        runtime = self.payload("runtime_proof")
        permit = self.payload("mission_permit")
        other = http.read_json(self.scenario / "trust-bundle.json")["keys"]["issuer-key-1"]["spki_sha256"]
        runtime["presented_key"]["spki_sha256"] = other
        permit["proof_binding"]["spki_sha256"] = other
        self.sign("runtime_proof", runtime, "attestor")
        self.sign("mission_permit", permit, "broker")
        self.assertIn("permit_proof_binding", self.evaluate("deny")["verification_report"]["failed_checks"])
        del runtime["presented_key"]["spki_sha256"]
        del permit["proof_binding"]["spki_sha256"]
        self.sign("runtime_proof", runtime, "attestor")
        self.sign("mission_permit", permit, "broker")
        self.evaluate("allow")

    def test_nested_approval_annotations_retain_json_types(self):
        permit = self.payload("mission_permit")
        permit["approval"]["review"] = {"conditions": [True, 2]}
        self.sign("mission_permit", permit, "broker")
        for value, decision in (([True, 2.0], "attenuate"), ([1, 2], "deny")):
            self.effect({"approval": {"mode": "policy_auto", "review": {"conditions": value}}})
            response = self.evaluate(decision)
            if decision == "deny":
                self.assertIn("policy_attenuation_effect_valid", response["verification_report"]["failed_checks"])

    def test_actions_require_a_list_and_exact_membership(self):
        action = self.request["requested_action"]
        permit = self.payload("mission_permit")
        for actions, decision in (([action], "allow"), (["other:" + action, action], "allow"),
                                  ([action, action], "allow"), (["other:" + action], "deny")):
            with self.subTest(actions=actions):
                permit["actions"] = actions
                self.sign("mission_permit", permit, "broker")
                response = self.evaluate(decision)
                self.assertTrue(response["verification_report"]["receipt_emitted"])
                if decision == "deny":
                    self.assertEqual(response["verification_report"]["failed_checks"], ["permit_action_scope"])
        for actions in (action, "other:" + action, {action: False}, None, True, [], [""], [action, 1]):
            with self.subTest(actions=actions):
                permit["actions"] = actions
                self.sign("mission_permit", permit, "broker")
                self.assert_unusable_permit()
        permit.pop("actions")
        self.sign("mission_permit", permit, "broker")
        self.assert_unusable_permit()

    def test_permit_transaction_is_valid_and_matches_the_request(self):
        permit = self.payload("mission_permit")
        self.request["transaction_id"] = "txn:別の取引"
        response = self.evaluate("deny")
        self.assertEqual(response["verification_report"]["failed_checks"], ["permit_transaction_binding"])
        self.assertEqual(response["admission_receipt"]["decision"], "deny")
        self.assertEqual(response["admission_receipt"]["transaction_id"], self.request["transaction_id"])
        permit["transaction_id"] = self.request["transaction_id"]
        self.sign("mission_permit", permit, "broker")
        self.evaluate("allow")
        for transaction in (None, "", True, 1, [], {}):
            with self.subTest(transaction=transaction):
                permit["transaction_id"] = transaction
                self.sign("mission_permit", permit, "broker")
                self.assert_unusable_permit()
        permit.pop("transaction_id")
        self.sign("mission_permit", permit, "broker")
        self.assert_unusable_permit()

    def test_permit_freshness_uses_the_configured_inclusive_limit(self):
        permit = self.payload("mission_permit")
        now = http.demo.utc_now()
        limit = self.policy["freshness"]["permit_max_age_seconds"]
        cases = ((limit - 1, 60, limit, "allow"), (limit, 60, limit, "allow"),
                 (limit + 0.001, 60, limit, "deny"), (-1, 60, limit, "deny"),
                 (1, 0, limit, "allow"), (1, -1, limit, "deny"),
                 (1, 60, 1, "allow"), (1.001, 60, 1, "deny"), (1, 60, 1.0, "allow"))
        # Same permit age, different policy: the boundary must not be a constant.
        cases += tuple((limit / 2, 60, bound, decision) for bound, decision in
                       ((limit / 2 - 1, "deny"), (limit / 2, "allow"), (limit / 2 + 1, "allow")))
        with patch.object(http.demo, "utc_now", return_value=now):
            for age, expiry, bound, decision in cases:
                with self.subTest(age=age, expiry=expiry, bound=bound):
                    permit["issued_at"] = http.demo.iso(now - timedelta(seconds=age))
                    permit["constraints"]["expires_at"] = http.demo.iso(now + timedelta(seconds=expiry))
                    self.sign("mission_permit", permit, "broker")
                    policy = copy.deepcopy(self.policy)
                    policy["freshness"]["permit_max_age_seconds"] = bound
                    response = self.evaluate(decision, policy=policy)
                    self.assertEqual(response["verification_report"]["failed_checks"],
                                     ["permit_window"] if decision == "deny" else [])
                    self.assertTrue(response["verification_report"]["receipt_emitted"])

    def test_all_freshness_limits_reject_invalid_configuration(self):
        for field in AGE_FIELDS:
            for value in INVALID_AGE_LIMITS:
                with self.subTest(field=field, value=value):
                    policy = copy.deepcopy(self.policy)
                    policy["freshness"][field] = value
                    response = self.evaluate("deny", policy=policy)
                    self.assertIn("verification_input", response["verification_report"]["failed_checks"])
                    self.assertFalse(response["verification_report"]["receipt_emitted"])
                    self.assertNotIn("admission_receipt", response)
            policy = copy.deepcopy(self.policy)
            policy["freshness"].pop(field)
            response = self.evaluate("deny", policy=policy)
            self.assertIn("verification_input", response["verification_report"]["failed_checks"])
            self.assertFalse(response["verification_report"]["receipt_emitted"])

    def test_policy_schema_requires_the_same_age_limits(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is not installed")
        schema = http.read_json(http.ROOT / "schemas/verifier-policy.schema.json")
        validator = jsonschema.Draft202012Validator(schema)
        for field in AGE_FIELDS:
            for value in (*INVALID_AGE_LIMITS, 1, 1.0, 42, 9876):
                with self.subTest(field=field, value=value):
                    policy = copy.deepcopy(self.policy)
                    policy["freshness"][field] = value
                    # Infinity and NaN are not JSON numbers. The runtime rejects
                    # them even for direct Python callers; the schema sees JSON.
                    if isinstance(value, float) and not math.isfinite(value):
                        continue
                    errors = list(validator.iter_errors(policy))
                    if errors:
                        with self.assertRaises(ValueError):
                            http.freshness_limit(policy, field)
                    else:
                        self.assertEqual(http.freshness_limit(policy, field), value)
            policy = copy.deepcopy(self.policy)
            policy["freshness"].pop(field)
            self.assertFalse(validator.is_valid(policy))

    def test_attenuation_still_requires_valid_scope_and_freshness(self):
        for mutation, decision, failure in ((None, "attenuate", None), ("actions", "deny", "verification_input"),
                                            ("transaction", "deny", "permit_transaction_binding"),
                                            ("age", "deny", "permit_window")):
            with self.subTest(mutation=mutation):
                self.request = copy.deepcopy(self.original)
                self.effect({"tool_allowlist": [self.request["requested_tool"]]})
                permit = self.payload("mission_permit")
                if mutation == "actions":
                    permit["actions"] = "other:" + self.request["requested_action"]
                elif mutation == "transaction":
                    self.request["transaction_id"] = "txn:other"
                elif mutation == "age":
                    permit["issued_at"] = http.demo.iso(http.demo.utc_now() - timedelta(
                        seconds=self.policy["freshness"]["permit_max_age_seconds"] + 60))
                self.sign("mission_permit", permit, "broker")
                response = self.evaluate(decision)
                self.assertEqual(response["verification_report"]["failed_checks"], [failure] if failure else [])

    def test_tool_intersection_including_empty_sets(self):
        for tools, decision in (([], "deny"), (["other_tool"], "deny"),
                                (["read_file"], "deny"), (["summarize"], "attenuate")):
            with self.subTest(tools=tools):
                self.setUp()
                self.effect({"tool_allowlist": tools})
                response = self.evaluate(decision)
                if decision == "deny":
                    self.assertIn("policy_request_within_effective_constraints", response["verification_report"]["failed_checks"])
                else:
                    self.assertEqual(response["verification_report"]["effective_constraints"]["tool_allowlist"], tools)

    def test_tool_constraints_are_lists_of_names(self):
        for value in ("summarize", None, True, [1]):
            for location in ("permit", "effect"):
                with self.subTest(value=value, location=location):
                    self.setUp()
                    if location == "permit":
                        permit = self.payload("mission_permit")
                        permit["constraints"]["tool_allowlist"] = value
                        self.sign("mission_permit", permit, "broker")
                    else:
                        self.effect({"tool_allowlist": value})
                    self.evaluate("deny")

    def test_approval_transitions_preserve_the_original_obligation(self):
        cases = [("policy_auto", "policy_auto", None, "attenuate"),
                 ("policy_auto", "human_required", None, "deny"),
                 ("policy_auto", "human_required", "approval:local", "attenuate"),
                 ("human_required", "human_required", None, "deny"),
                 ("human_required", "human_required", "approval:local", "attenuate"),
                 ("human_required", "policy_auto", None, "deny"),
                 ("human_required", "policy_auto", "approval:local", "deny")]
        for original, applied, reference, decision in cases:
            with self.subTest(original=original, applied=applied, reference=reference):
                self.setUp()
                permit = self.payload("mission_permit")
                permit["approval"]["mode"] = original
                self.sign("mission_permit", permit, "broker")
                self.effect({"approval": {"mode": applied}})
                if reference is not None:
                    self.request["approval_ref"] = reference
                response = self.evaluate(decision)
                if decision == "attenuate":
                    actual = response["verification_report"]["effective_constraints"]["approval"]
                    self.assertEqual(actual, {**permit["approval"], "mode": applied})
                if original == "human_required" and applied == "policy_auto":
                    self.assertIn("policy_attenuation_effect_valid", response["verification_report"]["failed_checks"])

    def test_unknown_approval_modes_are_rejected_at_both_sources(self):
        for approval in ({"mode": "unknown"}, {"mode": []}, {}, None):
            for location in ("permit", "effect"):
                with self.subTest(approval=approval, location=location):
                    self.setUp()
                    if location == "permit":
                        permit = self.payload("mission_permit")
                        permit["approval"] = approval
                        self.sign("mission_permit", permit, "broker")
                    else:
                        self.effect({"approval": approval})
                    self.evaluate("deny")

    def test_nested_approval_and_policy_references_cannot_erase_obligations(self):
        for change in ("nested_weaker", "nested_stronger", "different_policy", "effect_different_policy"):
            with self.subTest(change=change):
                self.setUp()
                permit = self.payload("mission_permit")
                if change == "nested_weaker":
                    permit["approval"]["mode"] = "human_required"
                    permit["constraints"]["approval"] = {"mode": "policy_auto"}
                elif change == "nested_stronger":
                    permit["constraints"]["approval"] = {"mode": "human_required"}
                elif change == "different_policy":
                    permit["constraints"]["approval"] = {"mode": "policy_auto", "policy_ref": "policy:other"}
                else:
                    self.effect({"approval": {"mode": "policy_auto", "policy_ref": "policy:other"}})
                self.sign("mission_permit", permit, "broker")
                self.evaluate("deny")
                if change == "nested_stronger":
                    self.request["approval_ref"] = "approval:local"
                    self.evaluate("allow")

    def test_human_approval_requires_a_nonempty_reference_string(self):
        permit = self.payload("mission_permit")
        permit["approval"]["mode"] = "human_required"
        self.sign("mission_permit", permit, "broker")
        for reference in (None, "", " ", True, [], {}, ["approval:local"]):
            with self.subTest(reference=reference):
                self.request["approval_ref"] = reference
                self.evaluate("deny")
        self.request["approval_ref"] = "approval:local"
        self.evaluate("allow")

    def test_malformed_effects_and_incompatible_handlers_cannot_authorize(self):
        for constraints in (None, [], {"max_amount_usd": True},
                            {"max_redelegation_depth": 0.5}, {"resource": "other-resource"}):
            with self.subTest(constraints=constraints):
                self.setUp()
                self.effect(constraints)
                response = self.evaluate("deny")
                self.assertIn("policy_attenuation_effect_valid", response["verification_report"]["failed_checks"])
        self.setUp()
        self.effect({"tool_allowlist": ["summarize"]})
        policy = copy.deepcopy(self.policy)
        policy["attenuation_handlers"]["tool_allowlist"] = "replace"
        response = http.verify_execute_request(verifier_dir=self.scenario, request=self.request, policy=policy)
        self.assertEqual(response["decision"], "deny")
        self.assertIn("verification_input", response["verification_report"]["failed_checks"])
        self.assertFalse(response["verification_report"]["receipt_emitted"])

    def test_numeric_narrowing_retains_original_limits(self):
        permit = self.payload("mission_permit")
        self.effect({"max_amount_usd": 1000, "max_redelegation_depth": 0.0})
        response = self.evaluate("attenuate")
        effective = response["verification_report"]["effective_constraints"]
        for key in ("max_amount_usd", "max_redelegation_depth"):
            self.assertEqual(effective[key], permit["constraints"][key])

    def test_reissue_requirement_must_be_explicitly_false(self):
        for requirement in (None, 0, "", True):
            with self.subTest(requirement=requirement):
                self.setUp()
                self.effect({"tool_allowlist": ["summarize"]})
                status = self.payload("status")
                status["entries"]["permit"]["effect"]["require_new_permit"] = requirement
                self.sign("status", status, "status")
                response = self.evaluate("deny")
                report = response["verification_report"]
                self.assertIn("policy_attenuation_reissue", report["failed_checks"])
                if requirement is not True:
                    self.assertFalse(report["receipt_emitted"])

    def test_accepted_state_does_not_grant_support_for_other_narrowing_subjects(self):
        for kind in ("passport", "runtime"):
            policy = copy.deepcopy(self.policy)
            policy["accepted_states"][kind].append("attenuated")
            for reissue in (False, True):
                with self.subTest(kind=kind, reissue=reissue):
                    self.setUp()
                    self.effect({"tool_allowlist": [self.request["requested_tool"]]})
                    status = self.payload("status")
                    status["entries"][kind].update(state="attenuated", effect={
                        "mode": "narrow", "constraints": {}, "require_new_permit": reissue})
                    self.sign("status", status, "status")
                    response = self.evaluate("deny", policy=policy)
                    failed = response["verification_report"]["failed_checks"]
                    self.assertIn("status_attenuation_scope", failed)
                    self.assertEqual("policy_attenuation_reissue" in failed, reissue)
                    self.assertEqual(response["admission_receipt"]["decision"], "deny")

    def test_active_entries_preserve_explicit_effects(self):
        for kind, constraints, reissue, expected, failed in (
                ("passport", {}, True, "deny", ["policy_attenuation_reissue"]),
                ("permit", {"tool_allowlist": []}, False, "deny", ["status_attenuation_scope"]),
                ("runtime", {}, False, "allow", [])):
            with self.subTest(kind=kind):
                self.setUp()
                status = self.payload("status")
                status["entries"][kind]["effect"] = {"mode": "narrow", "constraints": constraints,
                                                     "require_new_permit": reissue}
                self.sign("status", status, "status")
                response = self.evaluate(expected)
                self.assertEqual(response["verification_report"]["failed_checks"], failed)

    def test_signed_interval_spans_evaluation_and_uses_freshness_at_the_decision(self):
        permit = self.payload("mission_permit")
        start = http.demo.utc_now()
        deadline = start + timedelta(seconds=2, microseconds=371)
        permit["constraints"]["expires_at"] = http.demo.iso(deadline)
        self.sign("mission_permit", permit, "broker")
        verify_status = http.verify_status
        for finish, decision in ((deadline, "allow"), (deadline + timedelta(microseconds=1), "deny")):
            now = start

            def check_status(**kwargs):
                nonlocal now
                result = verify_status(**kwargs)
                now = finish
                return result

            with self.subTest(finish=finish), patch.object(http.demo, "utc_now", side_effect=lambda: now), \
                    patch.object(http, "verify_status", side_effect=check_status):
                response = self.evaluate(decision)
            receipt = http.demo.decode_compact_jws(response["admission_receipt_jws"])[1]
            report = response["verification_report"]
            self.assertEqual(http.demo.parse_time(receipt["started_at"]), start)
            self.assertEqual(http.demo.parse_time(receipt["finished_at"]), finish)
            self.assertEqual(receipt["finished_at"], report["checked_at"])
            self.assertEqual(report["failed_checks"], [] if decision == "allow" else ["permit_window"])

    def test_attenuation_requires_an_explicit_constraints_object(self):
        self.effect({})
        response = self.evaluate("attenuate")
        self.assertEqual(response["verification_report"]["effective_constraints"],
                         http.effective_permit_constraints(self.payload("mission_permit")))
        status = self.payload("status")
        del status["entries"]["permit"]["effect"]["constraints"]
        self.sign("status", status, "status")
        report = self.evaluate("deny")["verification_report"]
        self.assertIn("policy_attenuation_effect_valid", report["failed_checks"])
        self.assertFalse(report["receipt_emitted"])

    def test_signer_roles_are_required_before_using_payloads(self):
        for field in ("status", "passport", "runtime_proof", "mission_permit"):
            for usable_payload in (True, False):
                with self.subTest(field=field, usable_payload=usable_payload):
                    self.setUp()
                    self.sign(field, self.payload(field) if usable_payload else {}, "runtime")
                    response = self.evaluate("deny")
                    report = response["verification_report"]
                    self.assertIn(field + "_signature", report["passed_checks"])
                    self.assertIn(field + "_signer_role", report["failed_checks"])
                    self.assertNotIn("verification_input", report["failed_checks"])
                    self.assertFalse(report["receipt_emitted"])
                    self.assertNotIn("admission_receipt", response)
                    self.assertNotIn("admission_receipt_jws", response)


if __name__ == "__main__":
    unittest.main()
