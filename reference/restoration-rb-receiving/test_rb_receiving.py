"""Behavior and negative coverage for the bounded, offline RB receiving example."""
from copy import deepcopy
from itertools import combinations, product
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from example_inputs import inputs, timestamp
import rb_receiving as rb

HERE = Path(__file__).resolve().parent


class ReceivingTests(unittest.TestCase):
    def setUp(self):
        self.data = inputs("commit_observed")

    def statement(self, mutate, *, data=None, rebind=True):
        data = deepcopy(data or self.data)
        value = json.loads(data["statement"])
        mutate(value)
        data["statement"] = rb.encode(value)
        if rebind:
            o = json.loads(data["observation"])
            o["statement_sha256"] = rb.digest(data["statement"])
            # Preserve the independent selected context, except tests that
            # intentionally build their own valid context mutation.
            data["observation"] = rb.encode(o)
        return data

    def observation(self, mutate, *, data=None):
        data = deepcopy(data or self.data)
        value = json.loads(data["observation"])
        mutate(value)
        data["observation"] = rb.encode(value)
        return data

    def test_three_results_are_separate_from_permission(self):
        for scenario, status in (("no_commit", "consistent_under_local_assumptions"),
                                 ("commit_observed", "consistent_under_local_assumptions"),
                                 ("not_established", "not_established")):
            with self.subTest(scenario=scenario):
                report = rb.assess(**inputs(scenario))
                self.assertEqual(report["record_check"], {"status": "passed", "reason": "boundary-recorded"})
                self.assertEqual(report["receiver_binding"]["status"], "matched")
                self.assertEqual(report["test_plan_binding"]["status"], "matched_under_local_profile")
                self.assertEqual(report["observation_check"]["status"], status)
                for key in ("signature_verification", "issuer_authority", "evidence_sufficiency", "permission_to_resume"):
                    self.assertEqual(report[key]["status"], "not_assessed")

    def test_ordered_rule_failures(self):
        cases = [
            (lambda s: s.update(_type="other"), "statement-malformed"),
            (lambda s: s["predicate"].update(note="unknown"), "predicate-malformed"),
            (lambda s: s["predicate"]["counts"].update(attempts=-1), "predicate-malformed"),
            (lambda s: s["predicate"]["window"].update(end=timestamp(0)), "revocation-outside-window"),
            (lambda s: s["predicate"]["counts"].update(inFlightAtRevocation=2), "counts-inconsistent"),
            (lambda s: s["predicate"]["counts"].update(postRevocationCommits=2), "counts-inconsistent"),
            (lambda s: s["predicate"]["counts"].update(replaysCommitted=1), "counts-inconsistent"),
            (lambda s: s["predicate"].update(result=rb.NO_COMMIT), "result-contradicts-counts"),
        ]
        for mutation, reason in cases:
            with self.subTest(reason=reason):
                report = rb.assess(**self.statement(mutation))
                self.assertEqual(report["record_check"], {"status": "failed", "reason": reason})
                self.assertEqual(report["observation_check"]["status"], "not_assessed")

    def test_first_failure_not_last_failure(self):
        def bad(s):
            s["predicate"]["window"]["end"] = timestamp(0)
            s["predicate"]["counts"]["postRevocationCommits"] = 9
            s["predicate"]["result"] = rb.NO_COMMIT
        self.assertEqual(rb.assess(**self.statement(bad))["record_check"]["reason"], "revocation-outside-window")

    def test_document_closed_values(self):
        for field, key, value in (("sink", "kind", "network"), ("observer", "vantage", "trusted"),
                                  ("counts", "attempts", True), ("counts", "attempts", None)):
            with self.subTest(field=field, key=key):
                data = self.statement(lambda s: s["predicate"][field].update({key: value}))
                self.assertEqual(rb.assess(**data)["record_check"]["reason"], "predicate-malformed")

    def test_sink_observation_required_for_negative_result(self):
        data = self.statement(lambda s: s["predicate"]["observer"].update(vantage="agent_side"), data=inputs("no_commit"))
        self.assertEqual(rb.assess(**data)["record_check"]["reason"], "observer-not-at-sink")

    def test_unknown_result_does_not_assert_no_commit(self):
        report = rb.assess(**inputs("not_established"))
        self.assertEqual(report["declared"]["counts"]["postRevocationCommits"], 1)
        self.assertIsNone(report["observation_check"]["derived_counts"])
        self.assertEqual(report["observation_check"]["derived_result"], rb.UNKNOWN)

    def test_replay_alone_is_a_positive_result(self):
        report = rb.assess(**inputs("replay_only"))
        observation = report["observation_check"]
        self.assertEqual(observation["status"], "consistent_under_local_assumptions")
        self.assertEqual(observation["derived_counts"]["postRevocationCommits"], 0)
        self.assertEqual(observation["derived_counts"]["replaysCommitted"], 1)
        self.assertEqual(observation["derived_result"], rb.COMMIT)

    def test_same_second_is_unestablished(self):
        report = rb.assess(**inputs("time_tie"))
        self.assertEqual(report["observation_check"]["status"], "not_established")
        self.assertIn("REVOCATION_TIME_TIE", report["observation_check"]["gaps"])
        self.assertIsNone(report["observation_check"]["derived_counts"])

    def test_positive_observation_is_retained_in_partial_collection(self):
        report = rb.assess(**self.observation(lambda o: o.update(collection="partial")))
        self.assertEqual(report["observation_check"]["status"], "not_established")
        self.assertTrue(report["observation_check"]["observed_positive"])
        self.assertEqual(report["observation_check"]["derived_result"], rb.COMMIT)
        self.assertIsNone(report["observation_check"]["derived_counts"])

    def test_partial_positive_witness_refutes_a_zero_declaration(self):
        def zero(s):
            s["predicate"]["counts"]["postRevocationCommits"] = 0
            s["predicate"]["result"] = rb.NO_COMMIT
        data = self.statement(zero)
        observation = json.loads(data["observation"])
        observation["collection"] = "partial"
        data["observation"] = rb.encode(observation)
        report = rb.assess(**data)
        self.assertEqual(report["record_check"]["status"], "passed")
        self.assertEqual(report["observation_check"]["status"], "contradiction")
        self.assertIsNone(report["observation_check"]["derived_counts"])
        self.assertTrue(report["observation_check"]["observed_positive"])

    def test_known_count_lower_bounds_survive_incomplete_observation(self):
        for collection in ("partial", "closed"):
            for field in ("attempts", "inFlightAtRevocation", "replaysAttempted"):
                with self.subTest(collection=collection, field=field):
                    data = self.statement(lambda s: s["predicate"].update(result=rb.UNKNOWN),
                                          data=inputs("no_commit"))
                    if field == "inFlightAtRevocation":
                        data = self.statement(lambda s: s["predicate"]["counts"].update(attempts=2), data=data)
                    o = json.loads(data["observation"])
                    o["collection"] = collection
                    a = o["attempts"][0]
                    extra = {**a, "id": "another"}
                    if field == "attempts":
                        extra["finished_at"] = timestamp(0)
                    if field == "replaysAttempted":
                        extra.update(kind="replay", replay_of=a["id"], started_at=timestamp(2))
                    o["attempts"].append(extra)
                    if collection == "closed":
                        a.update(commit_state="unknown", committed_at=None)
                    data["observation"] = rb.encode(o)
                    report = rb.assess(**data)
                    self.assertEqual(report["record_check"]["status"], "passed")
                    result = report["observation_check"]
                    self.assertEqual(result["status"], "contradiction")
                    self.assertIn(field, result["different_fields"])
                    self.assertIsNone(result["derived_counts"])
                    self.assertEqual(result["derived_result"], rb.UNKNOWN)

    def test_closed_attempt_total_is_exact_even_when_effect_is_unknown(self):
        data = self.statement(lambda s: s["predicate"]["counts"].update(attempts=2),
                              data=inputs("not_established"))
        data = self.observation(lambda o: o.update(collection="closed"), data=data)
        result = rb.assess(**data)["observation_check"]
        self.assertEqual(result["status"], "contradiction")
        self.assertIn("attempts", result["different_fields"])
        self.assertIsNone(result["derived_counts"])

    def test_partial_collection_has_no_total_upper_bound(self):
        data = self.statement(lambda s: s["predicate"]["counts"].update(
            attempts=2, inFlightAtRevocation=2, postRevocationCommits=2), data=inputs("not_established"))
        result = rb.assess(**data)["observation_check"]
        self.assertEqual(result["status"], "not_established")
        self.assertIsNone(result["derived_counts"])

    def test_empty_partial_replays_require_initial_capacity(self):
        for replays in (1, 3, rb.MAX_INTEGER):
            for committed in (0, replays):
                with self.subTest(replays=replays, committed=committed):
                    def declare(s):
                        s["predicate"]["counts"].update(attempts=0, inFlightAtRevocation=0,
                            postRevocationCommits=0, replaysAttempted=replays, replaysCommitted=committed)
                        s["predicate"]["result"] = rb.UNKNOWN
                    data = self.statement(declare)
                    data = self.observation(lambda o: o.update(collection="partial", attempts=[]), data=data)
                    report = rb.assess(**data)
                    self.assertEqual(report["record_check"]["status"], "passed")
                    self.assertEqual(report["receiver_binding"]["status"], "matched")
                    self.assertEqual(report["test_plan_binding"]["status"], "matched_under_local_profile")
                    result = report["observation_check"]
                    self.assertEqual(result["status"], "contradiction")
                    self.assertEqual(result["reason"], "OBSERVATION_DISAGREES_WITH_RECORD")
                    self.assertEqual(result["different_fields"], ["attempts", "replaysAttempted"])
                    self.assertIsNone(result["derived_counts"])
                    self.assertEqual(result["derived_result"], rb.UNKNOWN)
                    self.assertFalse(result["observed_positive"])

    def test_empty_partial_replays_can_share_an_initial(self):
        for initial, replays, committed in ((0, 0, 0), (1, 1, 1), (1, 3, 3),
                                           (2, 1, 0), (1, rb.MAX_INTEGER, rb.MAX_INTEGER)):
            with self.subTest(initial=initial, replays=replays, committed=committed):
                def declare(s):
                    s["predicate"]["counts"].update(attempts=initial, inFlightAtRevocation=0,
                        postRevocationCommits=0, replaysAttempted=replays, replaysCommitted=committed)
                    s["predicate"]["result"] = rb.UNKNOWN
                data = self.statement(declare)
                data = self.observation(lambda o: o.update(collection="partial", attempts=[]), data=data)
                report = rb.assess(**data)
                self.assertEqual(report["record_check"]["status"], "passed")
                result = report["observation_check"]
                self.assertEqual(result["status"], "not_established")
                self.assertIsNone(result["derived_counts"])
                self.assertEqual(result["derived_result"], rb.UNKNOWN)
                self.assertFalse(result["observed_positive"])

    def test_replay_capacity_rule_requires_valid_bound_observation(self):
        def declare(s):
            s["predicate"]["counts"].update(attempts=0, inFlightAtRevocation=0,
                postRevocationCommits=0, replaysAttempted=1, replaysCommitted=1)
            s["predicate"]["result"] = rb.UNKNOWN
        data = self.statement(declare)
        data = self.observation(lambda o: o.update(collection="partial", attempts=[]), data=data)
        wrong_hash = json.loads(data["observation"])
        wrong_hash["statement_sha256"] = "0" * 64
        wrong_context = json.loads(data["observation"])
        wrong_context["context"]["sink"]["id"] += "-another"
        cases = ((None, "not_assessed", "OBSERVATION_ABSENT"),
                 (b"{}", "not_assessed", "INVALID_OBSERVATION"),
                 (rb.encode(wrong_hash), "mismatch", "OBSERVATION_BINDING_MISMATCH"),
                 (rb.encode(wrong_context), "mismatch", "OBSERVATION_BINDING_MISMATCH"))
        for raw, status, reason in cases:
            with self.subTest(reason=reason, raw=raw):
                report = rb.assess(**{**data, "observation": raw})
                self.assertEqual(report["record_check"]["status"], "passed")
                result = report["observation_check"]
                self.assertEqual((result["status"], result["reason"]), (status, reason))
                self.assertIsNone(result["derived_counts"])
                self.assertIsNone(result["observed_positive"])

    def test_unknown_finish_does_not_prove_in_flight(self):
        data = self.statement(lambda s: s["predicate"]["counts"].update(
            inFlightAtRevocation=0, postRevocationCommits=0), data=inputs("not_established"))
        for collection in ("partial", "closed"):
            with self.subTest(collection=collection):
                o = json.loads(data["observation"])
                o.update(collection=collection)
                o["attempts"][0]["finished_at"] = None
                result = rb.assess(**{**data, "observation": rb.encode(o)})["observation_check"]
                self.assertEqual(result["status"], "not_established")
                self.assertIsNone(result["derived_counts"])
                self.assertFalse(result["observed_positive"])

    def test_closed_unknown_commit_has_a_finite_upper_bound(self):
        data = self.statement(lambda s: s["predicate"]["counts"].update(
            attempts=2, inFlightAtRevocation=2, postRevocationCommits=2), data=inputs("not_established"))
        o = json.loads(data["observation"])
        o["collection"] = "closed"
        o["attempts"].append({**o["attempts"][0], "id": "another", "commit_state": "not_committed"})
        result = rb.assess(**{**data, "observation": rb.encode(o)})["observation_check"]
        self.assertEqual(result["status"], "contradiction")
        self.assertIn("postRevocationCommits", result["different_fields"])
        self.assertIsNone(result["derived_counts"])

    def test_partial_initial_counts_must_fit_together(self):
        for attempts, in_flight, expected in ((1, 1, "contradiction"),
                                              (2, 1, "contradiction"),
                                              (2, 2, "not_established")):
            with self.subTest(attempts=attempts, in_flight=in_flight):
                data = self.statement(lambda s: s["predicate"]["counts"].update(
                    attempts=attempts, inFlightAtRevocation=in_flight))
                o = json.loads(data["observation"])
                o["collection"] = "partial"
                o["attempts"][0].update(commit_state="not_committed", committed_at=None)
                report = rb.assess(**{**data, "observation": rb.encode(o)})
                self.assertEqual(report["record_check"]["status"], "passed")
                self.assertEqual(report["receiver_binding"]["status"], "matched")
                result = report["observation_check"]
                self.assertEqual(result["status"], expected)
                self.assertIsNone(result["derived_counts"])
                self.assertEqual(result["derived_result"], rb.UNKNOWN)
                self.assertFalse(result["observed_positive"])
                if expected == "contradiction":
                    self.assertEqual(result["different_fields"], list(rb.COUNTS[:3]))

    def test_closed_initial_counts_must_fit_together_with_unknown_finish(self):
        for in_flight, expected in ((1, "contradiction"), (2, "not_established")):
            for reverse in (False, True):
                with self.subTest(in_flight=in_flight, reverse=reverse):
                    data = self.statement(lambda s: s["predicate"]["counts"].update(
                        attempts=2, inFlightAtRevocation=in_flight))
                    o = json.loads(data["observation"])
                    a = o["attempts"][0]
                    a.update(commit_state="not_committed", committed_at=None)
                    o["attempts"].append({**a, "id": "task-2", "finished_at": None, "commit_state": "unknown"})
                    if reverse:
                        o["attempts"].reverse()
                    report = rb.assess(**{**data, "observation": rb.encode(o)})
                    self.assertEqual(report["record_check"]["status"], "passed")
                    result = report["observation_check"]
                    self.assertEqual(result["status"], expected)
                    self.assertIsNone(result["derived_counts"])
                    self.assertFalse(result["observed_positive"])
                    self.assertIn("COMMIT_OBSERVATION_UNKNOWN", result["gaps"])

    def test_partial_replay_counts_must_fit_together(self):
        for attempts, expected in ((1, "contradiction"), (2, "not_established")):
            with self.subTest(attempts=attempts):
                data = self.statement(lambda s: s["predicate"]["counts"].update(
                    replaysAttempted=attempts), data=inputs("replay_only"))
                o = json.loads(data["observation"])
                o["collection"] = "partial"
                o["attempts"][1].update(commit_state="not_committed", committed_at=None)
                report = rb.assess(**{**data, "observation": rb.encode(o)})
                self.assertEqual(report["record_check"]["status"], "passed")
                result = report["observation_check"]
                self.assertEqual(result["status"], expected)
                self.assertIsNone(result["derived_counts"])
                self.assertEqual(result["derived_result"], rb.UNKNOWN)
                if expected == "contradiction":
                    self.assertEqual(result["different_fields"], list(rb.COUNTS[3:]))

    def test_count_groups_report_independent_conflicts(self):
        cases = (
            ((2, 0, 0, 1, 1), False, ["inFlightAtRevocation", "replaysAttempted", "replaysCommitted"]),
            ((1, 1, 1, 1, 0), True, [*rb.COUNTS[:3], "replaysCommitted"]),
            ((2, 0, 0, 0, 0), False, ["inFlightAtRevocation", "replaysAttempted"]),
            ((1, 1, 1, 1, 1), False, list(rb.COUNTS)),
        )
        for counts, positive_replay, fields in cases:
            for reverse in (False, True):
                with self.subTest(counts=counts, positive_replay=positive_replay, reverse=reverse):
                    def declare(s):
                        s["predicate"]["counts"] = dict(zip(rb.COUNTS, counts))
                        s["predicate"]["result"] = rb.UNKNOWN
                    data = self.statement(declare, data=inputs("replay_only"))
                    o = json.loads(data["observation"])
                    o["collection"] = "partial"
                    o["attempts"][0].update(commit_state="not_committed", committed_at=None)
                    if not positive_replay:
                        o["attempts"][1].update(commit_state="not_committed", committed_at=None)
                    if reverse:
                        o["attempts"].reverse()
                    result = rb.assess(**{**data, "observation": rb.encode(o)})["observation_check"]
                    self.assertEqual(result["status"], "contradiction")
                    self.assertEqual(result["different_fields"], fields)
                    self.assertIsNone(result["derived_counts"])
                    self.assertIs(result["observed_positive"], positive_replay)
                    self.assertEqual(result["derived_result"], rb.COMMIT if positive_replay else rb.UNKNOWN)

    def test_start_time_tie_preserves_only_possible_joint_counts(self):
        for in_flight, commits, expected in ((0, 0, "not_established"),
                                             (1, 0, "contradiction"),
                                             (1, 1, "not_established")):
            with self.subTest(in_flight=in_flight, commits=commits):
                def declare(s):
                    s["predicate"]["counts"].update(inFlightAtRevocation=in_flight, postRevocationCommits=commits)
                    s["predicate"]["result"] = rb.UNKNOWN
                data = self.statement(declare)
                data = self.observation(lambda o: o["attempts"][0].update(started_at=timestamp(1)), data=data)
                result = rb.assess(**data)["observation_check"]
                self.assertEqual(result["status"], expected)
                self.assertIsNone(result["derived_counts"])
                self.assertFalse(result["observed_positive"])
                self.assertIn("REVOCATION_TIME_TIE", result["gaps"])

    def test_partition_check_matches_exhaustive_assignments(self):
        # Independent oracle: actually assign up to three attempts, then count
        # each category. This also checks partial collections with spare slots.
        for size in (2, 3):
            choices = [set(group) for n in range(1, size + 1)
                       for group in combinations(range(size), n)]
            for row_count in range(4):
                for options in product(choices, repeat=row_count):
                    loads = {tuple(assignment.count(i) for i in range(size))
                             for assignment in product(*options)}
                    for capacities in product(range(4), repeat=size):
                        expected = any(all(n <= cap for n, cap in zip(load, capacities)) for load in loads)
                        self.assertEqual(rb._partition_fits(options, capacities), expected,
                                         (options, capacities))
        self.assertTrue(rb._partition_fits([{0, 1, 2}] * rb.MAX_ITEMS, (rb.MAX_INTEGER, 0, 0)))

    def test_replay_before_referenced_initial_is_not_evidence(self):
        data = inputs("replay_only")
        for reverse in (False, True):
            o = json.loads(data["observation"])
            o["attempts"][0].update(started_at=timestamp(3), finished_at=timestamp(4))
            o["attempts"][1].update(started_at=timestamp(1), committed_at=timestamp(2), finished_at=timestamp(2))
            if reverse:
                o["attempts"].reverse()
            result = rb.assess(**{**data, "observation": rb.encode(o)})["observation_check"]
            self.assertEqual(result["status"], "not_assessed")
            self.assertEqual(result["reason"], "REPLAY_BEFORE_INITIAL")
            self.assertIsNone(result["observed_positive"])

    def test_concurrent_replay_can_precede_original_finish_and_row(self):
        data = inputs("replay_only")
        o = json.loads(data["observation"])
        self.assertLess(o["attempts"][1]["started_at"], o["attempts"][0]["finished_at"])
        o["attempts"].reverse()
        result = rb.assess(**{**data, "observation": rb.encode(o)})["observation_check"]
        self.assertEqual(result["status"], "consistent_under_local_assumptions")
        self.assertTrue(result["observed_positive"])

    def test_https_uses_pinned_ecmascript_whitespace_set(self):
        for char, allowed in (("\ufeff", False), ("\u0085", True), ("\u001c", True),
                              ("\u001d", True), ("\u001e", True), ("\u001f", True), (" ", False)):
            for location in ("producer", "incident", "related"):
                with self.subTest(codepoint=ord(char), location=location):
                    def mutate(s):
                        url = "https://example.org/" + char
                        if location == "producer":
                            s["predicate"]["producer"]["id"] = url
                        elif location == "incident":
                            s["predicate"]["incident"]["issuer"] = url
                        else:
                            s["predicate"]["incident"]["related"] = [{"issuer": url, "id": "related-1"}]
                    data = self.statement(mutate)
                    self.assertEqual(rb.assess(**data)["record_check"]["status"], "passed" if allowed else "failed")
                    if location != "related":
                        selection = json.loads(data["selection"])
                        key = "id" if location == "producer" else "issuer"
                        selection["expected"][location][key] = "https://example.org/" + char
                        if allowed:
                            rb.selection_check(rb.encode(selection))
                        else:
                            with self.assertRaises(rb.InputError):
                                rb.selection_check(rb.encode(selection))

    def test_claim_values_are_not_receiver_choices(self):
        for field in ("sink", "producer", "observer", "incident", "revocation", "window", "test_plan_sha256", "registry_sha256"):
            with self.subTest(field=field):
                s = json.loads(self.data["statement"])
                if field == "test_plan_sha256":
                    s["subject"][0]["digest"]["sha256"] = "0" * 64
                elif field == "registry_sha256":
                    s["predicate"]["registryDigest"]["sha256"] = "0" * 64
                elif field == "revocation":
                    s["predicate"][field]["credential"] += "-different"
                elif field == "window":
                    s["predicate"][field]["end"] = timestamp(7)
                else:
                    s["predicate"][field]["id"] += "-different"
                data = {**self.data, "statement": rb.encode(s)}
                report = rb.assess(**data)
                self.assertEqual(report["record_check"]["status"], "passed")
                self.assertEqual(report["receiver_binding"]["status"], "mismatch")
                self.assertIn(field, report["receiver_binding"]["different_fields"])
                self.assertEqual(report["observation_check"]["status"], "mismatch")

    def test_missing_inputs_are_not_success(self):
        self.assertEqual(rb.assess(None)["record_check"]["status"], "not_assessed")
        for raw in (None, b"[]", b"not json"):
            report = rb.assess(raw, self.data["selection"])
            self.assertEqual(report["receiver_binding"],
                             {"status": "not_assessed", "reason": "RECORD_NOT_CHECKED"})
        report = rb.assess(self.data["statement"])
        self.assertEqual(report["receiver_binding"]["status"], "not_assessed")
        self.assertEqual(report["receiver_binding"]["reason"], "SELECTION_ABSENT")
        self.assertEqual(report["test_plan_binding"]["status"], "not_assessed")
        self.assertEqual(report["observation_check"]["status"], "not_assessed")

    def test_subject_and_predecessor_shapes(self):
        for mutation, reason in (
            (lambda s: s["subject"].append(deepcopy(s["subject"][0])), "statement-malformed"),
            (lambda s: s["predicate"].update(predecessors=[]), "predicate-malformed"),
            (lambda s: s["predicate"].update(predecessors=[{"predicateType": "other", "digest": {"sha256": "0" * 64}}]), "predicate-malformed"),
        ):
            self.assertEqual(rb.assess(**self.statement(mutation))["record_check"]["reason"], reason)

    def test_bounded_parsing_and_exact_numbers(self):
        bad = [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e0}', b'{"x":9007199254740992}',
               b'{"x":"\\ud800"}', b'{"x":'+b'['*80+b'0'+b']'*80+b'}', b'\xff']
        for raw in bad:
            with self.subTest(raw=raw[:24]):
                report = rb.assess(raw, self.data["selection"])
                self.assertEqual(report["record_check"]["status"], "not_assessed")
        self.assertEqual(rb.decode(b'{"x":9007199254740991}', "test")["x"], rb.MAX_INTEGER)
        with self.assertRaises(rb.InputError):
            rb.assess(b"x" * (rb.MAX_BYTES + 1))

    def test_invalid_selection_raises_instead_of_adopting_producer(self):
        for raw in (b"{}", b"null", b'{"profile":true}', b"[]"):
            with self.assertRaises(rb.InputError):
                rb.assess(self.data["statement"], raw)

    def test_raw_plan_hash_and_context_both_required(self):
        report = rb.assess(**{**self.data, "test_plan": self.data["test_plan"] + b"\n"})
        self.assertEqual(report["test_plan_binding"]["reason"], "TEST_PLAN_DIGEST_MISMATCH")
        plan = rb.encode({"sink": {}, "window": {}})
        data = self.statement(lambda s: s["subject"][0]["digest"].update(sha256=rb.digest(plan)))
        report = rb.assess(**{**data, "test_plan": plan})
        self.assertEqual(report["test_plan_binding"]["reason"], "TEST_PLAN_CONTEXT_MISMATCH")

    def test_observation_references_exact_original(self):
        report = rb.assess(**{**self.data, "statement": self.data["statement"] + b"\n"})
        self.assertEqual(report["record_check"]["status"], "passed")
        self.assertEqual(report["observation_check"]["reason"], "OBSERVATION_BINDING_MISMATCH")

    def test_observation_count_contradiction(self):
        data = self.observation(lambda o: o["attempts"][0].update(commit_state="not_committed", committed_at=None))
        result = rb.assess(**data)["observation_check"]
        self.assertEqual(result["status"], "contradiction")
        self.assertEqual(result["derived_counts"]["postRevocationCommits"], 0)

    def test_exclusions_are_compared(self):
        data = self.observation(lambda o: o.update(exclusions=[{"count": 1, "reason": "withdrawn"}]))
        self.assertEqual(rb.assess(**data)["observation_check"]["status"], "contradiction")

    def test_bad_attempt_shapes_and_times(self):
        mutations = [lambda o: o["attempts"].append(deepcopy(o["attempts"][0])),
                     lambda o: o["attempts"][0].update(committed_at=timestamp(4)),
                     lambda o: o["attempts"][0].update(finished_at=None),
                     lambda o: o["attempts"][0].update(started_at=timestamp(4)),
                     lambda o: o["attempts"][0].update(commit_state="unknown"),
                     lambda o: o["attempts"][0].update(kind="replay", replay_of="missing", started_at=timestamp(1)),
                     lambda o: o["attempts"][0].update(replay_of="other")]
        for mutation in mutations:
            self.assertEqual(rb.assess(**self.observation(mutation))["observation_check"]["status"], "not_assessed")

    def test_initial_after_revocation_is_not_a_zero_claim(self):
        data = self.observation(lambda o: o["attempts"][0].update(started_at=timestamp(2)))
        report = rb.assess(**data)["observation_check"]
        # A closed inventory already contradicts the declared in-flight count.
        self.assertEqual(report["status"], "contradiction")
        self.assertIn("inFlightAtRevocation", report["different_fields"])
        # With compatible declared counts, the initial-start gap still prevents
        # a zero-commit conclusion under this local profile.
        data = self.statement(lambda s: s["predicate"].update(result=rb.UNKNOWN), data=data)
        data = self.statement(lambda s: s["predicate"]["counts"].update(
            inFlightAtRevocation=0, postRevocationCommits=0), data=data)
        report = rb.assess(**data)["observation_check"]
        self.assertEqual(report["status"], "not_established")
        self.assertIsNone(report["derived_counts"])
        self.assertEqual(report["derived_result"], rb.UNKNOWN)

    def test_same_second_initial_start_is_not_a_definite_positive(self):
        data = self.observation(lambda o: o["attempts"][0].update(started_at=timestamp(1)))
        result = rb.assess(**data)["observation_check"]
        self.assertEqual(result["status"], "not_established")
        self.assertFalse(result["observed_positive"])
        self.assertIsNone(result["derived_counts"])

    def test_same_second_replay_and_initial_start_are_not_rejected(self):
        data = inputs("replay_only")
        o = json.loads(data["observation"])
        for attempt in o["attempts"]:
            attempt["started_at"] = timestamp(1)
        result = rb.assess(**{**data, "observation": rb.encode(o)})["observation_check"]
        self.assertEqual(result["status"], "not_established")
        self.assertTrue(result["observed_positive"])

    def test_datetime_validation_and_whole_seconds(self):
        for timestamp_value in ("2026-02-30T00:00:00Z", "2026-10-23T00:00:00.1Z", "2026-10-23T00:00:00+00:00"):
            data = self.statement(lambda s: s["predicate"].update(issuedAt=timestamp_value))
            self.assertEqual(rb.assess(**data)["record_check"]["reason"], "predicate-malformed")

    def test_output_preserves_original_bytes_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "reading"
            report = rb.receive(out, **self.data)
            manifest = json.loads((out / "MANIFEST.json").read_bytes())["files"]
            for key, raw in self.data.items():
                self.assertEqual((out / (key + ".json")).read_bytes(), raw)
            for name, ref in manifest.items():
                self.assertEqual(rb.identity((out / name).read_bytes()), ref)
            self.assertEqual(json.loads((out / "report.json").read_bytes()), report)
            with self.assertRaises(FileExistsError):
                rb.receive(out, **self.data)

    def test_unrecognized_statement_does_not_crash(self):
        for value in (None, [], True, 1, "str", {"_type": []}):
            self.assertEqual(rb.assess(rb.encode(value))["record_check"]["reason"], "statement-malformed")

    def test_cli_and_optimized_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, raw in self.data.items():
                (root / (name + ".json")).write_bytes(raw)
            base = [str(HERE / "rb_receiving.py"), "--statement", str(root / "statement.json"),
                    "--selection", str(root / "selection.json"), "--test-plan", str(root / "test_plan.json"),
                    "--observation", str(root / "observation.json")]
            outputs = []
            for label, opts in (("normal", []), ("optimized", ["-O"])):
                p = subprocess.run([sys.executable, "-B", *opts, *base, "--out", str(root / label)],
                                   capture_output=True, timeout=20)
                self.assertEqual(p.returncode, 0, p.stderr)
                outputs.append(p.stdout)
            self.assertEqual(*outputs)

    def test_cli_failures_leave_no_success_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "s.json").write_bytes(self.data["statement"])
            (root / "bad.json").write_bytes(b"{}")
            out = root / "out"
            p = subprocess.run([sys.executable, "-B", str(HERE / "rb_receiving.py"), "--statement", str(root / "s.json"),
                "--selection", str(root / "bad.json"), "--out", str(out)], capture_output=True, timeout=20)
            self.assertEqual(p.returncode, 64)
            self.assertEqual(p.stdout, b"")
            self.assertFalse(out.exists())

    def test_reader_refuses_nonregular_and_symlink_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "file").write_bytes(b"{}")
            (root / "link").symlink_to(root / "file")
            with self.assertRaises((OSError, rb.InputError)):
                rb.read_file(root / "link")
            with self.assertRaises((OSError, rb.InputError)):
                rb.read_file(root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
