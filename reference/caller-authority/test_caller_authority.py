"""Local signed instructions and durable recording callbacks; no service calls."""
from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import caller_jwt as c
from fixture_support import sign_fixture
import test_runtime_jwt as runtime_fixtures

b, a = c.b, c.a
s = b.durable_state_module()


class CallerAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime_fixtures.RuntimeJwtTests.setUpClass()

    def setUp(self):
        self.f = runtime_fixtures.RuntimeJwtTests()
        self.f.setUp()
        self.now = self.f.now
        self.header = {"alg": "ES256", "typ": c.TOKEN_TYPE, "kid": "actor-key"}
        self.claims = {"iss": self.f.request["actor"], "sub": self.f.request["actor"],
            "aud": self.f.request["audience"], "iat": self.f.second - 1, "nbf": self.f.second - 1,
            "exp": self.f.second + 60, "grant_id": "grant-purchase",
            "request_sha256": b.digest(b.encode(self.f.request))["value"],
            "original_sha256": b.digest(b.encode(self.f.original))["value"]}
        self.proof, key = sign_fixture(self.f.node, b.encode(self.header), b.encode(self.claims))
        self.grant = c.DelegationGrant("grant-purchase", self.f.request["principal"], self.f.request["actor"],
            "actor-key", key, self.f.request["runtime"], self.f.request["audience"],
            self.f.request["target"]["resource"], self.f.request["action"], "USD", "150.00",
            tuple(self.f.original["constraints"]["tool_allowlist"]), self.f.second - 10, self.f.second + 80)
        self.policy = c.AuthorityPolicy(self.f.second - 2, self.f.second + 80, (self.grant,))
        self.authorizer = self.new_authorizer()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = s.DurableStateStore.create(Path(self.tmp.name) / "state", scope="caller fixture",
                                                 verifier_id=self.f.verifier.verifier_id)
        self.calls = []
        self.configure(self.f.verifier, self.store)

    def new_authorizer(self, **changes):
        options = dict(expected_profile=c.PROFILE, authority_id="urn:example:merchant-authority",
            node=self.f.node, node_sha256=self.f.node_sha, authority_policy_provider=lambda: self.policy,
            max_token_age_seconds=40, max_policy_age_seconds=30)
        options.update(changes)
        return c.CallerJwtAuthorizer(**options)

    def configure(self, verifier, store):
        verifier.state_store = store
        verifier.caller_authorizer = self.authorizer.as_caller_authorizer()
        verifier.dispatch_boundary = b.DispatchBoundary(execute=lambda *args: self.calls.append(args), clock=lambda: self.now)
        return verifier

    def reopen(self):
        verifier = b.core.VateVerifier(verifier_id=self.f.verifier.verifier_id, policy=self.f.policy,
                                       runtime_evidence_verifier=self.f.adapter.as_runtime_verifier())
        return self.configure(verifier, s.DurableStateStore(self.store.directory, expected_anchor=self.store.anchor))

    def admit(self, **options):
        options.setdefault("caller_proof", self.proof)
        return self.f.admit(**options)

    def context(self):
        return a.CallerAuthorityContext(b.encode(self.f.request), b.encode(self.f.original), self.now)

    def resign(self, header_raw=None, claims_raw=None):
        self.proof, key = sign_fixture(self.f.node,
            b.encode(self.header) if header_raw is None else header_raw,
            b.encode(self.claims) if claims_raw is None else claims_raw)
        self.grant = replace(self.grant, public_key_spki=key)
        self.policy = replace(self.policy, grants=(self.grant,))

    def reject(self, **options):
        with patch.object(self.f.verifier, "_evaluate_policy", wraps=self.f.verifier._evaluate_policy) as evaluate:
            with self.assertRaises(b.Invalid):
                self.admit(**options)
            evaluate.assert_not_called()
        self.assertEqual(self.f.verifier._seen_request_ids, set())
        self.assertEqual(self.calls, [])

    def test_valid_signed_instruction_dispatch_and_schema(self):
        bound = self.admit()
        self.assertEqual(b.decode(bound.receipt)["expires_at"], b.core.iso(self.now + timedelta(seconds=28)))
        self.assertEqual(b.decode(bound.receipt)["decision"]["outcome"], "attenuate")
        result = self.f.verifier.dispatch(bound, caller_proof=self.proof)
        checkpoint = b.decode(result.checkpoint)
        record = checkpoint["caller_authorization"]
        self.assertEqual(record["proof_ref"]["digest"], b.digest(self.proof))
        self.assertEqual(record["principal"], self.f.request["principal"])
        self.assertEqual(record["authority_id"], self.authorizer.authority_id)
        self.assertEqual(self.calls, [(bound.effective, result.checkpoint)])
        checks = {row["name"]: row["status"] for row in b.decode(bound.assessment)["checks"]}
        self.assertEqual(checks["evidence.authentication"], "not_checked")
        self.assertEqual(checks["execution.actual_input"], "not_checked")
        try:
            import jsonschema
            from referencing import Registry, Resource
        except ImportError:
            self.skipTest("jsonschema unavailable; core behavior checked")
        schemas = [json.loads(path.read_text()) for path in (c.ROOT / "reference/request-binding/schemas").glob("*.json")]
        registry = Registry().with_resources((schema["$id"], Resource.from_contents(schema)) for schema in schemas)
        schema = next(schema for schema in schemas if schema["$id"].endswith(":pre-dispatch:v1"))
        jsonschema.Draft202012Validator(schema, registry=registry, format_checker=jsonschema.FormatChecker()).validate(checkpoint)

    def test_proof_not_persisted_in_bound_checkpoint_or_database(self):
        bound = self.admit()
        result = self.f.verifier.dispatch(bound, caller_proof=self.proof)
        values = [value for value in b._bound_values(bound) if value is not None]
        values += [result.checkpoint] + [p.read_bytes() for p in self.store.directory.iterdir() if p.is_file()]
        self.assertTrue(all(self.proof not in raw for raw in values))

    def test_missing_proof_prevents_admission(self):
        self.reject(caller_proof=None)

    def test_unreadable_source_keeps_caller_identity_error_typed(self):
        file_sha = c.jwt.file_sha
        sources = {Path(c.__file__), Path(c.jwt.__file__)}
        def unreadable(path):
            if path in sources:
                raise PermissionError("fixture caller source")
            return file_sha(path)
        with patch.object(c.jwt, "file_sha", side_effect=unreadable):
            for entry in (self.new_authorizer, self.authorizer.as_caller_authorizer,
                          lambda: self.authorizer.verify(self.proof, self.context())):
                with self.subTest(entry=entry), self.assertRaisesRegex(c.jwt.RuntimeJwtError, "CALLER_IMPLEMENTATION_CHANGED"):
                    entry()
            self.reject()
        self.admit()
        self.assertEqual(self.calls, [])

    def test_disabled_adapter_does_not_ignore_proof(self):
        self.f.verifier.caller_authorizer = None
        self.reject()

    def test_durable_store_required(self):
        self.f.verifier.state_store = None
        self.reject()

    def test_boundary_required(self):
        self.f.verifier.dispatch_boundary = None
        self.reject()

    def test_runtime_adapter_required(self):
        self.f.verifier.runtime_evidence_verifier = None
        self.reject()

    def test_signature_wrong_key(self):
        _, key = sign_fixture(self.f.node, b.encode(self.header), b.encode(self.claims))
        self.policy = replace(self.policy, grants=(replace(self.grant, public_key_spki=key),))
        self.reject()

    def test_wrong_grant_scope(self):
        for field, value in (("principal", "different"), ("actor", "different"), ("kid", "different"),
                ("runtime", "different"), ("audience", "different"), ("resource", "different"),
                ("action", "different"), ("currency", "EUR"), ("max_amount", "100.00"),
                ("tool_allowlist", ("different",)), ("revoked", True)):
            with self.subTest(field=field):
                self.policy = replace(self.policy, grants=(replace(self.grant, **{field: value}),))
                self.reject()

    def test_wrong_signed_claims(self):
        for field in ("iss", "sub", "aud", "grant_id", "request_sha256", "original_sha256"):
            original = self.claims[field]
            with self.subTest(field=field):
                self.claims[field] = "0" * 64
                self.resign()
                self.reject()
            self.claims[field] = original

    def test_proof_bound_to_exact_admission_bytes(self):
        raw = json.dumps(self.f.request, indent=2).encode()
        with self.assertRaises(b.Invalid):
            self.f.verifier.admit(raw, original=b.encode(self.f.original), now=self.now,
                evidence_artifacts={"urn:example:jwt": self.f.raw}, caller_proof=self.proof)

    def test_proof_bound_to_exact_original_bytes(self):
        with self.assertRaises(b.Invalid):
            self.f.verifier.admit(b.encode(self.f.request), original=json.dumps(self.f.original, indent=2).encode(),
                now=self.now, evidence_artifacts={"urn:example:jwt": self.f.raw}, caller_proof=self.proof)

    def test_header_type_algorithm_and_extra_fields(self):
        for changes in ({"typ": c.jwt.TOKEN_TYPE}, {"alg": "HS256"}, {"jku": "https://invalid.example"}, {"kid": ""}):
            original = dict(self.header)
            with self.subTest(changes=changes):
                self.header.update(changes)
                self.resign()
                self.reject()
            self.header = original

    def test_duplicate_claims_rejected(self):
        self.resign(claims_raw=b'{"sub":"other",' + b.encode(self.claims)[1:])
        self.reject()

    def test_noncanonical_and_oversized_tokens_rejected(self):
        for raw in (b"", self.proof + b"\n", self.proof + b"=", b"x" * (65536 + 1), self.proof.decode()):
            with self.subTest(length=len(raw)):
                self.reject(caller_proof=raw)

    def test_invalid_and_stale_token_times(self):
        for changes in ({"exp": self.f.second}, {"nbf": self.f.second + 1}, {"iat": self.f.second + 1},
                        {"iat": self.f.second - 41}, {"iat": True}, {"exp": 253402300800}):
            original = dict(self.claims)
            with self.subTest(changes=changes):
                self.claims.update(changes)
                self.resign()
                self.reject()
            self.claims = original

    def test_grant_times_and_policy_freshness(self):
        original = self.policy
        for policy in (replace(original, issued_at=self.f.second - 31),
                replace(original, issued_at=self.f.second + 1), replace(original, expires_at=self.f.second),
                replace(original, grants=()), replace(original, grants=(self.grant, self.grant)),
                replace(original, grants=(replace(self.grant, not_before=self.f.second),)),
                replace(original, grants=(replace(self.grant, expires_at=self.f.second),))):
            with self.subTest(policy=policy.issued_at):
                self.policy = policy
                self.reject()

    def test_ambiguous_keys_rejected(self):
        _, key = sign_fixture(self.f.node, b.encode(self.header), b.encode(self.claims))
        other = replace(self.grant, grant_id="other", public_key_spki=key)
        self.policy = replace(self.policy, grants=(self.grant, other))
        self.reject()

    def test_provider_failure_sanitized(self):
        self.authorizer.authority_policy_provider = lambda: (_ for _ in ()).throw(ValueError("private-provider-detail"))
        with self.assertRaisesRegex(b.Invalid, "^CALLER_AUTHORIZATION_FAILED$"):
            self.admit()

    def test_policy_change_during_signature_rejected(self):
        signature = self.authorizer.backend._signature
        def change(*args):
            signature(*args)
            self.policy = replace(self.policy, grants=(replace(self.grant, revoked=True),))
        with patch.object(self.authorizer.backend, "_signature", side_effect=change):
            self.reject()

    def test_configuration_change_during_authorization_rolls_back_admission(self):
        verify = self.authorizer.verify
        def change(*args):
            result = verify(*args)
            self.f.verifier.caller_authorizer = None
            return result
        self.f.verifier.caller_authorizer = replace(self.authorizer.as_caller_authorizer(), verify=change)
        self.reject()

    def test_declared_extra_tool_fails_even_when_actual_tool_is_authorized(self):
        self.f.original["constraints"]["tool_allowlist"].append("merchant.refund")
        self.f.request["constraints"] = self.f.original["constraints"]
        self.f.request["input_hash"] = b.object_hash(self.f.original)
        self.f.claims["vate_context_hash"] = b.runtime_context_hash(b.encode(self.f.request), b.encode(self.f.original))
        self.f.resign()
        self.claims["request_sha256"] = b.digest(b.encode(self.f.request))["value"]
        self.claims["original_sha256"] = b.digest(b.encode(self.f.original))["value"]
        self.resign()
        self.reject()

    def test_runtime_deadline_is_rechecked_after_slow_caller_authentication(self):
        self.f.trust = replace(self.f.trust, expires_at=self.f.second + 5)
        bound = self.admit()
        signature = self.authorizer.backend._signature
        def delayed(*args):
            signature(*args)
            self.now += timedelta(seconds=5)
        with patch.object(self.authorizer.backend, "_signature", side_effect=delayed):
            with self.assertRaisesRegex(b.Invalid, "DISPATCH_OUTSIDE_WINDOW"):
                self.f.verifier.dispatch(bound, caller_proof=self.proof)
        self.assertEqual(self.calls, [])

    def test_caller_expiry_prevents_callback_after_store_commit_delay(self):
        bound = self.admit()
        commit = self.store._commit
        def delayed(connection):
            claimed = connection.execute("SELECT count(*) FROM operations").fetchone()[0]
            commit(connection)
            if claimed:
                self.now += timedelta(seconds=29)
        with patch.object(self.store, "_commit", side_effect=delayed):
            with self.assertRaises(b.DispatchAttemptError):
                self.f.verifier.dispatch(bound, caller_proof=self.proof)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.f.verifier.dispatch_status(self.f.request["request_id"]).state, "outcome_unknown")

    def test_adapter_cannot_return_dict_or_boolean(self):
        for claims in ({"verified": True}, True):
            self.f.verifier.caller_authorizer = replace(self.authorizer.as_caller_authorizer(), verify=lambda *args: claims)
            self.reject()

    def test_core_rechecks_claims_from_adapter(self):
        claims = self.authorizer.verify(self.proof, self.context())
        for key, value in (("proof_sha256", "0" * 64), ("request_sha256", "0" * 64),
                ("original_sha256", "0" * 64), ("principal", "other"), ("actor", "other"),
                ("runtime", "other"), ("audience", "other"), ("valid_until", "bad"),
                ("issued_at", b.core.iso(self.now - timedelta(seconds=41)))):
            with self.subTest(key=key):
                result = replace(claims, **{key: value})
                self.f.verifier.caller_authorizer = replace(self.authorizer.as_caller_authorizer(), verify=lambda *args: result)
                self.reject()

    def test_missing_dispatch_proof_keeps_operation_ready(self):
        bound = self.admit()
        with self.assertRaisesRegex(b.Invalid, "CALLER_PROOF_REQUIRED"):
            self.f.verifier.dispatch(bound)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.f.verifier.dispatch_status(self.f.request["request_id"]).state, "ready")
        self.f.verifier.dispatch(bound, caller_proof=self.proof)
        self.assertEqual(len(self.calls), 1)

    def test_revocation_after_admission_prevents_callback(self):
        bound = self.admit()
        with self.f.verifier.dispatch_boundary.update():
            self.policy = replace(self.policy, grants=(replace(self.grant, revoked=True),))
        with self.assertRaisesRegex(b.Invalid, "CALLER_AUTHORIZATION_FAILED"):
            self.f.verifier.dispatch(bound, caller_proof=self.proof)
        self.assertEqual(self.calls, [])

    def test_delay_during_caller_check_prevents_callback(self):
        bound = self.admit()
        signature = self.authorizer.backend._signature
        def delayed(*args):
            signature(*args)
            self.now += timedelta(seconds=29)
        with patch.object(self.authorizer.backend, "_signature", side_effect=delayed):
            with self.assertRaisesRegex(b.Invalid, "DISPATCH_OUTSIDE_WINDOW"):
                self.f.verifier.dispatch(bound, caller_proof=self.proof)
        self.assertEqual(self.calls, [])

    def test_restart_requires_proof_and_reauthenticates(self):
        bound = self.admit()
        verifier = self.reopen()
        restored = verifier.restore_admission(self.f.request["request_id"])
        with self.assertRaisesRegex(b.Invalid, "CALLER_PROOF_REQUIRED"):
            verifier.dispatch(restored)
        with patch.object(self.authorizer.backend, "_signature", wraps=self.authorizer.backend._signature) as signature:
            verifier.dispatch(restored, caller_proof=self.proof)
            self.assertEqual(signature.call_count, 1)
        self.assertEqual(self.calls[0][0], bound.effective)
        with self.assertRaisesRegex(b.Invalid, "DURABLE_OPERATION_ALREADY_ATTEMPTED"):
            self.reopen().restore_admission(self.f.request["request_id"])

    def test_restart_observes_revocation(self):
        self.admit()
        self.policy = replace(self.policy, grants=(replace(self.grant, revoked=True),))
        verifier = self.reopen()
        with self.assertRaisesRegex(b.Invalid, "CALLER_AUTHORIZATION_FAILED"):
            verifier.dispatch(verifier.restore_admission(self.f.request["request_id"]), caller_proof=self.proof)
        self.assertEqual(self.calls, [])

    def test_mode_downgrade_or_replacement_cannot_dispatch_or_restore(self):
        bound = self.admit()
        for caller in (None, replace(self.f.verifier.caller_authorizer, configuration_id="different")):
            verifier = self.reopen()
            verifier.caller_authorizer = caller
            with self.assertRaisesRegex(b.Invalid, "STATE_CONFIGURATION_CHANGED"):
                verifier.restore_admission(self.f.request["request_id"])
        self.f.verifier.caller_authorizer = None
        with self.assertRaisesRegex(b.Invalid, "DISPATCH_CONFIGURATION_CHANGED"):
            self.f.verifier.dispatch(bound, caller_proof=self.proof)
        self.assertEqual(self.calls, [])

    def test_changed_adapter_configuration_rejected(self):
        self.authorizer.max_policy_age_seconds += 1
        self.reject()

    def test_request_replay_after_restart(self):
        self.admit()
        self.f.verifier = self.reopen()
        with self.assertRaises(b.Invalid):
            self.admit()

    def test_fresh_proof_cannot_extend_receipt(self):
        self.admit()
        self.now += timedelta(seconds=29)
        self.policy = replace(self.policy, issued_at=self.f.second + 29, expires_at=self.f.second + 100)
        self.claims["iat"] = self.f.second + 29
        self.resign()
        verifier = self.reopen()
        with self.assertRaisesRegex(b.Invalid, "DISPATCH_OUTSIDE_WINDOW"):
            verifier.dispatch(verifier.restore_admission(self.f.request["request_id"]), caller_proof=self.proof)
        self.assertEqual(self.calls, [])

    def test_new_current_grant_may_authorize_same_pending_instruction(self):
        bound = self.admit()
        old = self.grant
        self.grant = replace(old, grant_id="new-grant", kid="new-key")
        self.header["kid"] = "new-key"
        self.claims["grant_id"] = "new-grant"
        self.resign()
        self.policy = replace(self.policy, grants=(replace(old, revoked=True), self.grant))
        verifier = self.reopen()
        restored = verifier.restore_admission(self.f.request["request_id"])
        result = verifier.dispatch(restored, caller_proof=self.proof)
        self.assertEqual(restored.receipt, bound.receipt)
        self.assertEqual(b.decode(result.checkpoint)["caller_authorization"]["grant_id"], "new-grant")

    def test_store_does_not_impose_authority_mode_on_other_admissions(self):
        # Operator configuration is trusted. Row pinning is not a store-wide
        # mandatory authentication policy; the application must enforce that.
        self.admit()
        self.f.verifier = self.reopen()
        self.f.verifier.caller_authorizer = None
        self.f.request["request_id"] += "-new"
        self.f.claims["vate_context_hash"] = b.runtime_context_hash(b.encode(self.f.request), b.encode(self.f.original))
        self.f.resign()
        other = self.f.admit()
        self.assertTrue(b.decode(other.assessment)["decision_allows_immediate_execution"])
        self.assertEqual(self.calls, [])

    def test_shared_operation_allows_pending_admissions_but_only_one_attempt(self):
        first = self.admit()
        self.f.request["request_id"] += "-second"
        self.f.claims["vate_context_hash"] = b.runtime_context_hash(b.encode(self.f.request), b.encode(self.f.original))
        self.f.resign()
        self.claims["request_sha256"] = b.digest(b.encode(self.f.request))["value"]
        self.resign()
        second = self.admit()
        self.f.verifier.dispatch(second, caller_proof=self.proof)
        verifier = self.reopen()
        with self.assertRaisesRegex(b.Invalid, "DURABLE_OPERATION_ALREADY_ATTEMPTED"):
            verifier.restore_admission(b.decode(first.request)["request_id"])
        self.assertEqual(len(self.calls), 1)

    def test_local_example(self):
        import importlib.util
        path = Path(__file__).with_name("run_example.py")
        spec = importlib.util.spec_from_file_location("caller_example_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        files = module.run(self.f.node, self.f.node_sha)
        self.assertEqual(b.decode(files["RUN.json"])["observations"]["restored_callback_calls"], 1)


if __name__ == "__main__":
    unittest.main()
