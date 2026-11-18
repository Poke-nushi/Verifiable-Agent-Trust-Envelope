"""Direct linkage API controls using digest-consistent, local receipt pairs."""

from copy import deepcopy
from decimal import DefaultContext, Inexact, Overflow, ROUND_DOWN, Rounded, localcontext
import sys
import unittest
from unittest import mock

import example
from request_binding import core, decode, encode


class PostExecutionLinkageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.verifier = core.VateVerifier(verifier_id="urn:vate:linkage-input-tests")
        cls.pairs = {}
        for decision, cap in (("allow", "25.00"), ("attenuate", "120.00")):
            original, request, policy = example.inputs(cap=cap)
            issuer = core.VateVerifier(verifier_id="urn:vate:linkage-input-tests", policy=policy)
            bound = issuer.admit(encode(request), original=encode(original),
                                 now=core.parse_time(example.EVALUATED_AT))
            receipt = decode(bound.receipt)
            assert receipt["decision"]["outcome"] == decision
            cls.pairs[decision] = receipt, example.synthetic_post(receipt)

    def pair(self, decision="attenuate"):
        return deepcopy(self.pairs[decision])

    def check(self, receipt, post, *, rebind=True):
        if rebind:
            post["admission"]["digest"] = {"alg": "sha-256", "value": core.digest_value(receipt)}
        return self.verifier.validate_post_execution_linkage(receipt, post)

    def assert_failed(self, receipt, post, reason=None, *, rebind=True):
        result = self.check(receipt, post, rebind=rebind)
        self.assertEqual(result["outcome"], "failed")
        self.assertTrue(result["reason_codes"])
        self.assertEqual(len(result["reason_codes"]), len(set(result["reason_codes"])))
        if reason:
            self.assertIn(reason, result["reason_codes"])

    def test_valid_allow_and_attenuate_keep_success_result(self):
        for decision in self.pairs:
            with self.subTest(decision=decision):
                receipt, post = self.pair(decision)
                self.assertEqual(self.check(receipt, post), {
                    "outcome": "success", "reason_codes": [
                        "ADMISSION_RECEIPT_LINKED", "ADMISSION_DIGEST_MATCH",
                        "ADMISSION_DECISION_EXECUTABLE", "TRANSACTION_MATCH", "RUNTIME_MATCH",
                        "ADMISSION_WINDOW_VALID", "EFFECTIVE_REQUEST_HASH_MATCH",
                        "EFFECTIVE_CONSTRAINTS_OBSERVED", "NO_POLICY_VIOLATIONS",
                    ],
                })

    def test_allow_rejects_contradictory_attenuation(self):
        for value in (None, [], {}, {"effective_constraints": {"max_amount": {"currency": "USD", "value": "999"}}}):
            with self.subTest(value=value):
                receipt, post = self.pair("allow")
                receipt["attenuation"] = value
                self.assert_failed(receipt, post, "POST_EXEC_LINKAGE_MISMATCH")

    def test_attenuation_must_be_an_object(self):
        for value in (None, [], True, 0, "narrow"):
            with self.subTest(value=value):
                receipt, post = self.pair()
                receipt["attenuation"] = value
                self.assert_failed(receipt, post, "POST_EXEC_LINKAGE_MISMATCH")

    def test_effective_constraints_never_fall_back_to_original(self):
        for value in (None, [], True, "", {}, "missing"):
            with self.subTest(value=value):
                receipt, post = self.pair()
                if value == "missing":
                    del receipt["attenuation"]["effective_constraints"]
                else:
                    receipt["attenuation"]["effective_constraints"] = value
                self.assert_failed(receipt, post, "POST_EXEC_LINKAGE_MISMATCH")

    def test_new_permit_flag_is_required_and_boolean(self):
        for value in (None, 0, 1, "false", [], {}, "missing"):
            with self.subTest(value=value):
                receipt, post = self.pair()
                if value == "missing":
                    del receipt["attenuation"]["require_new_permit"]
                else:
                    receipt["attenuation"]["require_new_permit"] = value
                self.assert_failed(receipt, post, "POST_EXEC_LINKAGE_MISMATCH")

    def test_new_permit_flag_and_mode_cannot_authorize_linkage(self):
        for mode, required in (("narrow", True), ("require_new_permit", True), ("require_new_permit", False)):
            with self.subTest(mode=mode, required=required):
                receipt, post = self.pair()
                receipt["attenuation"].update(mode=mode, require_new_permit=required)
                self.assert_failed(receipt, post, "POST_EXEC_ADMISSION_DENIED")

    def test_deny_if_not_accepted_mode_can_link_an_executable_receipt(self):
        receipt, post = self.pair()
        receipt["attenuation"].update(mode="deny_if_not_accepted", require_new_permit=False)
        self.assertEqual(self.check(receipt, post)["outcome"], "success")

    def test_invalid_attenuation_mode_fails(self):
        for mode in (None, [], "unknown", "", True):
            with self.subTest(mode=mode):
                receipt, post = self.pair()
                receipt["attenuation"]["mode"] = mode
                self.assert_failed(receipt, post, "POST_EXEC_LINKAGE_MISMATCH")

    def test_deny_cannot_link(self):
        receipt, post = self.pair("allow")
        receipt["decision"]["outcome"] = "deny"
        self.assert_failed(receipt, post, "POST_EXEC_ADMISSION_DENIED")

    def test_nested_blocks_have_controlled_failures(self):
        for role, names in ((0, ("decision", "request", "subject")), (1, ("admission", "execution", "result"))):
            for name in names:
                for value in (None, [], True, 0, "bad"):
                    with self.subTest(role=role, name=name, value=value):
                        pair = self.pair()
                        pair[role][name] = value
                        self.assert_failed(*pair, "POST_EXEC_LINKAGE_MISMATCH", rebind=False)

    def test_top_level_values_have_controlled_failures(self):
        for role in (0, 1):
            for value in (None, [], True, 0, "bad"):
                with self.subTest(role=role, value=value):
                    pair = list(self.pair())
                    pair[role] = value
                    self.assert_failed(*pair, "POST_EXEC_LINKAGE_MISMATCH", rebind=False)

    def test_decision_values_have_controlled_failures(self):
        for role in (0, 1):
            for value in (None, [], {}, True, 1, "", "unknown"):
                with self.subTest(role=role, value=value):
                    receipt, post = self.pair()
                    if role == 0:
                        receipt["decision"]["outcome"] = value
                    else:
                        post["admission"]["decision"] = value
                    self.assert_failed(receipt, post)

    def test_absent_or_non_string_identities_never_match_each_other(self):
        paths = ((None, "receipt_id", "admission", "receipt_id", "POST_EXEC_LINKAGE_MISMATCH"),
                 ("request", "transaction_id", "execution", "transaction_id", "POST_EXEC_TRANSACTION_MISMATCH"),
                 ("subject", "runtime", "execution", "runtime", "POST_EXEC_RUNTIME_MISMATCH"))
        for block, field, post_block, post_field, reason in paths:
            for value in (None, "", [], {}, True, 1, "missing"):
                with self.subTest(field=field, value=value):
                    receipt, post = self.pair()
                    selected = receipt if block is None else receipt[block]
                    if value == "missing":
                        selected.pop(field)
                        post[post_block].pop(post_field)
                    else:
                        selected[field] = value
                        post[post_block][post_field] = value
                    self.assert_failed(receipt, post, reason)

    def test_allow_constraints_may_be_absent_but_not_malformed(self):
        for value in (None, [], True, "bad"):
            with self.subTest(value=value):
                receipt, post = self.pair("allow")
                receipt["request"]["constraints"] = value
                self.assert_failed(receipt, post, "POST_EXEC_LINKAGE_MISMATCH")
        for present in (True, False):
            receipt, post = self.pair("allow")
            if present:
                receipt["request"]["constraints"] = {}
            else:
                del receipt["request"]["constraints"]
            self.assertEqual(self.check(receipt, post)["outcome"], "success")

    def test_malformed_configured_amount_does_not_disable_limit(self):
        values = (None, [], True, 25, "25", {}, {"currency": "USD"}, {"value": "25"},
                  {"currency": "usd", "value": "25"}, {"currency": "USD\n", "value": "25"},
                  {"currency": "USD", "value": False}, {"currency": "USD", "value": "NaN"})
        for decision in self.pairs:
            for value in values:
                with self.subTest(decision=decision, value=value):
                    receipt, post = self.pair(decision)
                    constraints = receipt["request"]["constraints"] if decision == "allow" else receipt["attenuation"]["effective_constraints"]
                    constraints["max_amount"] = value
                    self.assert_failed(receipt, post, "POST_EXEC_LINKAGE_MISMATCH")

    def test_malformed_reported_amount_does_not_disappear(self):
        for value in (None, [], True, 1, "1", {}, {"currency": "USD", "value": "bad"}):
            with self.subTest(value=value):
                receipt, post = self.pair()
                post["result"]["side_effects"][0]["amount"] = value
                self.assert_failed(receipt, post, "POST_EXEC_LINKAGE_MISMATCH")

    def test_money_strings_require_canonical_ascii_decimal_syntax(self):
        invalid = ("1e2", " 25 ", "1_000", "+25", "25.", ".5", "２５", "-0",
                   "01", "01.0", "25\n", "25\r", "25\t", "25.٥", "")
        for decision in self.pairs:
            for role in ("limit", "observation"):
                for value in invalid:
                    with self.subTest(decision=decision, role=role, value=value):
                        receipt, post = self.pair(decision)
                        constraints = core.admitted_effective_constraints(receipt)
                        amount = (constraints["max_amount"] if role == "limit"
                                  else post["result"]["side_effects"][0]["amount"])
                        amount["value"] = value
                        self.assert_failed(receipt, post, "POST_EXEC_LINKAGE_MISMATCH")

    def test_canonical_money_strings_and_compatible_numbers_keep_success(self):
        for decision in self.pairs:
            for value in ("0", "0.00", "25", "25.00", "0.5", "999999999999999999.99999999",
                          0, 25, 25.0, 0.5, 1e2):
                with self.subTest(decision=decision, value=value):
                    receipt, post = self.pair(decision)
                    core.admitted_effective_constraints(receipt)["max_amount"]["value"] = value
                    post["result"]["side_effects"][0]["amount"]["value"] = value
                    self.assertEqual(self.check(receipt, post)["outcome"], "success")

    def test_unconfigured_amount_observation_remains_uninterpreted(self):
        receipt, post = self.pair()
        del receipt["attenuation"]["effective_constraints"]["max_amount"]
        post["result"]["side_effects"][0]["amount"]["value"] = "1e2"
        self.assertEqual(self.check(receipt, post)["outcome"], "success")

    def test_invalid_or_unsupported_amounts_have_the_linkage_input_reason(self):
        for decision in self.pairs:
            for role in ("limit", "observation"):
                for value in ("bad", "0.123456789", "1000000000000000000"):
                    with self.subTest(decision=decision, role=role, value=value):
                        receipt, post = self.pair(decision)
                        amount = (core.admitted_effective_constraints(receipt)["max_amount"]
                                  if role == "limit" else post["result"]["side_effects"][0]["amount"])
                        amount["value"] = value
                        self.assertEqual(self.check(receipt, post), {
                            "outcome": "failed", "reason_codes": ["POST_EXEC_LINKAGE_MISMATCH"]})

    def test_currency_mismatch_has_the_constraint_excess_reason(self):
        for decision in self.pairs:
            with self.subTest(decision=decision):
                receipt, post = self.pair(decision)
                post["result"]["side_effects"][0]["amount"]["currency"] = "EUR"
                self.assertEqual(self.check(receipt, post), {
                    "outcome": "failed", "reason_codes": ["POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED"]})

    def test_legacy_constraint_names_are_rejected_even_with_canonical_names(self):
        for decision in self.pairs:
            for name in ("max_amount_usd", "resource"):
                for retain_canonical in (True, False):
                    for value in (None, "25", {}):
                        with self.subTest(decision=decision, name=name, retain=retain_canonical, value=value):
                            receipt, post = self.pair(decision)
                            constraints = core.admitted_effective_constraints(receipt)
                            if not retain_canonical:
                                constraints.clear()
                            constraints[name] = value
                            self.assertEqual(self.check(receipt, post), {
                                "outcome": "failed", "reason_codes": ["POST_EXEC_LINKAGE_MISMATCH"]})

    def test_target_and_constraint_expiry_are_not_receipt_linkage_guarantees(self):
        for decision in self.pairs:
            with self.subTest(decision=decision):
                receipt, post = self.pair(decision)
                constraints = core.admitted_effective_constraints(receipt)
                constraints.clear()
                constraints.update(target_resource="urn:example:unobserved-target", expires_at="2026-01-01T00:00:00Z")
                result = self.check(receipt, post)
                self.assertEqual(result["outcome"], "success")
                self.assertIn("ADMISSION_WINDOW_VALID", result["reason_codes"])
                self.assertIn("EFFECTIVE_CONSTRAINTS_OBSERVED", result["reason_codes"])

    def test_tool_allowlist_and_selected_alias_are_not_coerced(self):
        for value in (None, "merchant.checkout.confirm", {}, True, [1], [None], [""]):
            with self.subTest(allowlist=value):
                receipt, post = self.pair()
                receipt["attenuation"]["effective_constraints"]["tool_allowlist"] = value
                self.assert_failed(receipt, post, "POST_EXEC_LINKAGE_MISMATCH")
        for value in (None, [], {}, True, 1, ""):
            with self.subTest(tool=value):
                receipt, post = self.pair()
                post["result"]["side_effects"][0]["tool"] = value
                self.assert_failed(receipt, post, "POST_EXEC_LINKAGE_MISMATCH")

    def test_tool_alias_precedence_is_preserved(self):
        receipt, post = self.pair()
        effect = post["result"]["side_effects"][0]
        effect.update(tool=None, tool_id="merchant.checkout.confirm", name="a filename")
        self.assertEqual(self.check(receipt, post)["outcome"], "success")
        effect.update(tool="other")
        self.assert_failed(receipt, post, "POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED")

    def test_every_present_tool_alias_requires_string_or_null(self):
        for alias in ("tool", "tool_id", "name"):
            for value in (0, False, [], {}, 1, True, ["x"], 0.0):
                with self.subTest(alias=alias, value=value):
                    receipt, post = self.pair()
                    effect = post["result"]["side_effects"][0]
                    effect.update(tool="merchant.checkout.confirm", tool_id="merchant.checkout.confirm",
                                  name="merchant.checkout.confirm")
                    effect[alias] = value
                    self.assert_failed(receipt, post, "POST_EXEC_LINKAGE_MISMATCH")

    def test_null_and_empty_tool_aliases_skip_to_first_nonempty_string(self):
        for selected in ("tool", "tool_id", "name"):
            for empty in (None, ""):
                with self.subTest(selected=selected, empty=empty):
                    receipt, post = self.pair()
                    effect = post["result"]["side_effects"][0]
                    effect.update(tool=empty, tool_id=empty, name=empty)
                    effect[selected] = "merchant.checkout.confirm"
                    self.assertEqual(self.check(receipt, post)["outcome"], "success")
        receipt, post = self.pair()
        post["result"]["side_effects"][0].update(tool="", tool_id=None, name="")
        self.assert_failed(receipt, post, "POST_EXEC_LINKAGE_MISMATCH")

    def test_unconfigured_tool_aliases_remain_uninterpreted(self):
        receipt, post = self.pair()
        del receipt["attenuation"]["effective_constraints"]["tool_allowlist"]
        post["result"]["side_effects"][0].update(tool=False, tool_id=[], name={})
        self.assertEqual(self.check(receipt, post)["outcome"], "success")

    def test_empty_allowlist_denies_reported_tool(self):
        receipt, post = self.pair()
        receipt["attenuation"]["effective_constraints"]["tool_allowlist"] = []
        self.assert_failed(receipt, post, "POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED")

    def test_absent_observations_do_not_assert_completeness(self):
        receipt, post = self.pair()
        post["result"]["side_effects"] = [{"type": "unobserved-details"}]
        self.assertEqual(self.check(receipt, post)["outcome"], "success")

    def test_non_json_values_are_failed_results(self):
        for role in (0, 1):
            for value in (b"bytes", (1,), {1}, object(), float("nan"), float("inf"), {1: "non-string-key"}):
                with self.subTest(role=role, kind=type(value).__name__):
                    pair = self.pair()
                    pair[role]["annotation"] = value
                    self.assert_failed(*pair, "POST_EXEC_LINKAGE_MISMATCH", rebind=False)

    def test_cyclic_values_are_failed_results(self):
        for role in (0, 1):
            pair = self.pair()
            pair[role]["annotation"] = pair[role]
            self.assert_failed(*pair, "POST_EXEC_LINKAGE_MISMATCH", rebind=False)

    def test_shared_containers_and_annotations_remain_valid(self):
        receipt, post = self.pair()
        shared = {"enabled": True, "note": [None, "example", 1, 1.5]}
        receipt.update(annotation=shared, another_annotation=shared)
        post["admission"]["digest"] = {"alg": "sha-256", "value": core.digest_value(receipt), "annotation": "retained"}
        self.assertEqual(self.check(receipt, post, rebind=False)["outcome"], "success")

    def test_digest_api_rejects_non_json_or_unserializable_objects(self):
        for artifact in ({"a": object()}, {"a": float("nan")}, {1: "a", "1": "b"}):
            self.assertFalse(self.verifier.validate_digest(artifact, {"alg": "sha-256", "value": "0" * 64}))
        cyclic = {}; cyclic["self"] = cyclic
        self.assertFalse(self.verifier.validate_digest(cyclic, {"alg": "sha-256", "value": "0" * 64}))

    def test_digest_api_preserves_json_roots_without_asserting_receipt_shape(self):
        for artifact in ({"receipt": "example"}, ["not", "a", "receipt"], "text", 3, 1.5, True, None):
            with self.subTest(kind=type(artifact).__name__):
                digest = {"alg": "sha-256", "value": core.digest_value(artifact)}
                self.assertTrue(self.verifier.validate_digest(artifact, digest))
                receipt, post = self.pair()
                if type(artifact) is not dict:
                    self.assert_failed(artifact, post, "POST_EXEC_LINKAGE_MISMATCH", rebind=False)

    def test_amount_sum_is_independent_of_caller_decimal_precision(self):
        receipt, post = self.pair()
        receipt["attenuation"]["effective_constraints"]["max_amount"]["value"] = "2.0001"
        post["result"]["side_effects"] = [{"amount": {"currency": "USD", "value": "1.0001"}}] * 2
        with localcontext() as context:
            context.prec = 3
            context.traps[Inexact] = False
            context.traps[Rounded] = False
            self.assert_failed(receipt, post, "POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED")

    def test_amount_sum_is_independent_of_process_decimal_defaults(self):
        saved = DefaultContext.copy()
        try:
            DefaultContext.prec = 1
            DefaultContext.Emin = 0
            DefaultContext.Emax = 0
            DefaultContext.rounding = ROUND_DOWN
            DefaultContext.capitals = 0
            DefaultContext.clamp = 1
            DefaultContext.flags[Inexact] = True
            for trapped in (False, True):
                with self.subTest(overflow_trapped=trapped):
                    DefaultContext.traps[Overflow] = trapped
                    receipt, post = self.pair()
                    self.assertEqual(self.check(receipt, post)["outcome"], "success")
                    post["result"]["side_effects"][0]["amount"]["value"] = "25.01"
                    self.assert_failed(receipt, post, "POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED")
        finally:
            for attribute in ("prec", "Emin", "Emax", "rounding", "capitals", "clamp", "flags", "traps"):
                setattr(DefaultContext, attribute, getattr(saved, attribute))

    def test_input_objects_are_unchanged(self):
        receipt, post = self.pair()
        original = deepcopy((receipt, post))
        self.check(receipt, post, rebind=False)
        self.assertEqual((receipt, post), original)

    def test_large_integer_amount_fails_with_a_fresh_matching_digest(self):
        receipt, post = self.pair()
        # Serializable on supported Python versions, but beyond the money bound.
        receipt["attenuation"]["effective_constraints"]["max_amount"]["value"] = 10 ** 100
        self.assertEqual(self.check(receipt, post), {
            "outcome": "failed", "reason_codes": ["POST_EXEC_LINKAGE_MISMATCH"]})

    def test_unserializable_depth_is_a_failed_result(self):
        receipt, post = self.pair()
        nested = []
        receipt["annotation"] = nested
        for _ in range(2000):
            child = []
            nested.append(child)
            nested = child
        original_limit = sys.getrecursionlimit()
        serialize = core.canonical_bytes
        # Some standard-library encoders can serialize this depth. In that
        # case a matching digest must succeed before testing the error path.
        try:
            serialize(receipt)
        except RecursionError:
            self.assertEqual(self.check(receipt, post, rebind=False), {
                "outcome": "failed", "reason_codes": ["POST_EXEC_ADMISSION_DIGEST_MISMATCH"]})
        else:
            self.assertEqual(self.check(receipt, post)["outcome"], "success")
        try:
            sys.setrecursionlimit(1000)
            # Select the stdlib's recursive encoder to exercise a real depth
            # failure even when the host's C encoder can serialize this input.
            with mock.patch.object(core.json.encoder, "c_make_encoder", None):
                with self.assertRaises(RecursionError):
                    serialize(receipt)
                with mock.patch.object(core, "canonical_bytes", wraps=serialize) as observed:
                    self.assertEqual(self.check(receipt, post, rebind=False), {
                        "outcome": "failed", "reason_codes": ["POST_EXEC_ADMISSION_DIGEST_MISMATCH"]})
                    observed.assert_called_once_with(receipt)
        finally:
            sys.setrecursionlimit(original_limit)

    def test_serializer_data_errors_have_a_specific_controlled_result(self):
        for error in (TypeError, ValueError, RecursionError):
            with self.subTest(error=error.__name__):
                receipt, post = self.pair()
                self.assertEqual(self.check(receipt, post)["outcome"], "success")
                with mock.patch.object(core, "canonical_bytes", side_effect=error("local serializer failure")) as observed:
                    self.assertEqual(self.check(receipt, post, rebind=False), {
                        "outcome": "failed", "reason_codes": ["POST_EXEC_ADMISSION_DIGEST_MISMATCH"]})
                    observed.assert_called_once_with(receipt)

    def test_reported_constraint_excess_and_policy_violation_still_fail(self):
        receipt, post = self.pair()
        post["result"]["side_effects"][0]["amount"]["value"] = "25.01"
        self.assert_failed(receipt, post, "POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED")
        receipt, post = self.pair()
        post["result"]["policy_violations"] = ["scope_exceeded"]
        self.assert_failed(receipt, post, "POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED")


if __name__ == "__main__":
    unittest.main()
