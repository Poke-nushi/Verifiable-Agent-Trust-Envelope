"""Issuer behavior with real signatures and persistent state; simulated services."""
import copy
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import shutil
import tempfile
import threading
import unittest

from authority_issuer import AuthorityIssuer, Registration, MODEL, model_identity, selected_scope, s, b, c, jwt
from authority_store import AuthorityStore
from fixture_signer import FixtureSigner


class Service:
    def __init__(self, response, base):
        self.response, self.base, self.calls = response, base, []
        self.hook = lambda: None

    def descriptor(self):
        return {"base_url": self.base, "development_loopback": False}

    def request(self, path, **options):
        self.calls.append((path, copy.deepcopy(options)))
        self.hook()
        if path.endswith("/model"):
            return {"authorization_model": {"id": "model", **copy.deepcopy(MODEL)}}
        return copy.deepcopy(self.response)


class IssuerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = Path(shutil.which("node")).resolve()
        cls.node_sha = jwt.file_sha(cls.node)

    def setUp(self):
        self.now = b.core.parse_time("2026-11-13T12:00:00.500Z")
        self.second = int((self.now - jwt.EPOCH).total_seconds())
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.signer = FixtureSigner(self.node, self.node_sha); self.addCleanup(self.signer.close)
        self.auth = {"active": True, "iss": "https://auth.example/", "sub": "alice", "client_id": "agent",
            "token_use": "access_token", "aud": ["purchase-api"], "iat": self.second - 10,
            "exp": self.second + 120, "scope": "purchase.execute"}
        self.oauth = Service(self.auth, "https://auth-admin.example")
        self.pdp = Service({"allowed": True}, "https://pdp.example")
        runtime = jwt.RuntimeIssuerGrant("runtime-issuer", "runtime-key", self.signer.public_key,
            "runtime", "vate-audience", self.second - 60, self.second + 300)
        grant = c.DelegationGrant("grant", "principal", "actor", "actor-key", self.signer.public_key,
            "runtime", "vate-audience", "resource", "commerce.purchase", "USD", "120.00", ("checkout",),
            self.second - 60, self.second + 300)
        self.registration = Registration("https://auth.example/", "purchase-api", "alice", "agent",
            "store", "model", "user:alice", "purchase:order", runtime, grant)
        self.selection = s.AuthoritySelection("authority", "verifier", selected_scope(self.registration,
            self.oauth, self.pdp, 30), "epoch1", "issuer-key", self.signer.public_key, 1, 30)
        self.verifier = s.SnapshotVerifier(expected_profile=s.PROFILE, selection=self.selection,
            node=self.node, node_sha256=self.node_sha)
        self.state = AuthorityStore.create(Path(self.temp.name) / "issuer", verifier=self.verifier, clock=lambda: self.now)
        self.issuer = self.make_issuer()

    def make_issuer(self, **options):
        defaults = dict(registration=self.registration, oauth=self.oauth, pdp=self.pdp, state=self.state,
                        token_provider=lambda: "selected-token", signer=self.signer, ttl_seconds=30)
        defaults.update(options)
        return AuthorityIssuer(**defaults)

    def claims(self, raw):
        return b.decode(jwt.decode_segment(raw.split(b".")[1], jwt.MAX_TOKEN_BYTES))

    def failed(self):
        prior = self.state.status()["revision"]
        with self.assertRaisesRegex(s.AuthorityError, "^ISSUER_PUBLICATION_FAILED$"):
            self.issuer.publish()
        self.assertTrue(self.state.status()["unavailable"])
        self.assertEqual(self.state.status()["revision"], prior)
        with self.assertRaises(s.AuthorityError), self.state.lease():
            pass

    def test_permit_is_bounded_and_checks_selected_model_and_intersection(self):
        claims = self.claims(self.issuer.publish())
        self.assertEqual((claims["iat"], claims["exp"], claims["revision"]), (self.second, self.second + 30, 1))
        self.assertEqual(claims["delegation_grants"][0]["max_amount"], "120.00")
        self.assertEqual(claims["delegation_grants"][0]["not_before"], self.auth["iat"])
        self.assertEqual(self.oauth.calls, [("/admin/oauth2/introspect", {"form": {"token": "selected-token"}})])
        self.assertEqual(self.pdp.calls[-1][1]["body"], {"authorization_model_id": "model",
            "consistency": "HIGHER_CONSISTENCY", "tuple_key": {"user": "user:alice",
            "relation": "can_execute", "object": "purchase:order"}})

    def test_inactive_produces_empty_delegation_without_pdp(self):
        self.oauth.response = {"active": False}
        claims = self.claims(self.issuer.publish())
        self.assertEqual(claims["delegation_grants"], [])
        self.assertEqual(len(claims["runtime_grants"]), 1)
        self.assertEqual(self.pdp.calls, [])

    def test_scope_alone_cannot_override_policy_denial(self):
        self.pdp.response = {"allowed": False}
        self.assertEqual(self.claims(self.issuer.publish())["delegation_grants"], [])

    def test_context_and_types_fail_closed(self):
        cases = [(key, value) for key, value in (("active", 1), ("active", "true"), ("active", None),
            ("iss", "https://wrong.example/"), ("sub", "bob"), ("client_id", "another"),
            ("token_use", "refresh_token"), ("aud", "purchase-api"), ("aud", ["purchase-api", "extra"]),
            ("iat", True), ("iat", self.second + 1), ("exp", self.second), ("exp", 1.5),
            ("nbf", self.second + 1), ("nbf", "now"))]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                self.oauth.response = {**self.auth, key: value}
                self.failed()
        self.assertEqual(self.pdp.calls, [])

    def test_missing_token_times_fail(self):
        for field in ("iat", "exp"):
            self.oauth.response = {k: v for k, v in self.auth.items() if k != field}
            self.failed()

    def test_policy_decision_boolean_is_not_coerced(self):
        for result in ({}, {"allowed": 1}, {"allowed": "true"}, {"allowed": True, "unselected": True}):
            with self.subTest(result=result):
                self.pdp.response = result
                self.failed()

    def test_model_change_cannot_relabel_policy_decision(self):
        original = self.pdp.request
        for change in ("id", "semantics", "extra"):
            def request(path, **options):
                response = original(path, **options)
                if path.endswith("/model"):
                    if change == "id": response["authorization_model"]["id"] = "different"
                    if change == "semantics": response["authorization_model"]["type_definitions"].pop()
                    if change == "extra": response["authorization_model"]["unselected"] = True
                return response
            self.pdp.request = request
            self.failed()

    def test_snapshot_expiry_never_exceeds_token_expiry(self):
        self.auth["exp"] = self.second + 5
        claims = self.claims(self.issuer.publish())
        self.assertEqual(claims["exp"], self.second + 5)
        self.assertEqual(claims["delegation_grants"][0]["expires_at"], self.second + 5)

    def test_waiting_on_backend_does_not_extend_validity(self):
        self.pdp.hook = lambda: setattr(self, "now", self.now + timedelta(seconds=16))
        self.failed()

    def test_waiting_on_signer_does_not_extend_validity(self):
        def delayed(header, claims):
            self.now += timedelta(seconds=30)
            return self.signer(header, claims)
        self.issuer.signer = delayed
        self.failed()

    def test_subsecond_expiry_boundary_fails(self):
        self.auth["exp"] = self.second + 1
        self.pdp.hook = lambda: setattr(self, "now", self.now + timedelta(milliseconds=300))
        self.failed()

    def test_source_failure_sanitizes_secrets_and_recovery_increments(self):
        self.issuer.publish()
        def unavailable(): raise RuntimeError("selected-token secret credential")
        self.oauth.hook = unavailable
        self.failed()
        self.oauth.hook = lambda: None
        self.assertEqual(self.claims(self.issuer.publish())["revision"], 2)

    def test_wrong_signer_key_and_modified_claims_fail(self):
        with FixtureSigner(self.node, self.node_sha) as other:
            self.issuer.signer = other
            self.failed()
        self.issuer.signer = lambda header, claims: self.signer(header, {**claims, "revision": 99})
        self.failed()

    def test_signer_cannot_mutate_the_expected_payload_in_place(self):
        def mutated(header, claims):
            claims["delegation_grants"][0]["max_amount"] = "90000.00"
            return self.signer(header, claims)
        self.issuer.signer = mutated
        self.failed()

    def test_configuration_change_during_poll_cannot_relabel_source(self):
        self.pdp.hook = lambda: setattr(self.oauth, "base", "https://other.example")
        self.failed()

    def test_native_model_defaults_are_equivalent_but_conditions_are_not(self):
        model = copy.deepcopy(MODEL)
        model["conditions"] = {}
        model["type_definitions"][0].update(relations={}, metadata=None)
        definition = model["type_definitions"][1]
        definition["metadata"].update(module="", source_info=None)
        relation = definition["metadata"]["relations"]["delegation"]
        relation.update(module="", source_info=None)
        relation["directly_related_user_types"][0]["condition"] = ""
        computed = model["type_definitions"][1]["relations"]["can_execute"]["intersection"]["child"][0]
        computed["computedUserset"]["object"] = ""
        self.assertEqual(model_identity(model), model_identity(MODEL))
        relation["directly_related_user_types"][0]["condition"] = "unselected-condition"
        self.assertNotEqual(model_identity(model), model_identity(MODEL))

    def test_restart_continues_revision_and_rejects_old_snapshot(self):
        old = self.issuer.publish()
        self.issuer.publish()
        self.state = AuthorityStore(self.state.directory, verifier=self.verifier,
            expected_anchor=self.state.anchor, clock=lambda: self.now)
        self.issuer = self.make_issuer()
        self.assertEqual(self.claims(self.issuer.publish())["revision"], 3)
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_ROLLBACK"):
            self.state.accept(old)

    def test_persisted_clock_rollback_prevents_new_publication(self):
        self.issuer.publish()
        self.now -= timedelta(seconds=1)
        with self.assertRaisesRegex(s.AuthorityError, "ISSUER_PUBLICATION_FAILED"):
            self.issuer.publish()
        self.assertEqual(self.state.status()["revision"], 1)
        with self.assertRaises(s.AuthorityError), self.state.lease(): pass

    def test_registration_changes_require_explicit_scope_reselection(self):
        for change in (replace(self.registration, oauth_subject="bob"),
                       replace(self.registration, fga_object="purchase:other"),
                       replace(self.registration, delegation_grant=replace(self.registration.delegation_grant,
                                                                         max_amount="500.00"))):
            with self.assertRaisesRegex(s.AuthorityError, "ISSUER_REGISTRATION_MISMATCH"):
                self.make_issuer(registration=change)
        self.oauth.base = "https://other.example"
        self.failed()

    def test_renewed_token_does_not_extend_registered_grant_window(self):
        self.auth.update(iat=self.second, exp=self.second + 600)
        grant = self.claims(self.issuer.publish())["delegation_grants"][0]
        self.assertEqual(grant["not_before"], self.second)
        self.assertEqual(grant["expires_at"], self.registration.delegation_grant.expires_at)

    def test_expired_registered_grant_cannot_be_renewed_by_active_token(self):
        self.now += timedelta(seconds=301)
        self.auth.update(iat=self.second + 300, exp=self.second + 600)
        self.assertEqual(self.claims(self.issuer.publish())["delegation_grants"], [])

    def test_one_publisher_rejects_concurrent_poll(self):
        entered, release = threading.Event(), threading.Event()
        self.oauth.hook = lambda: (entered.set(), release.wait(5))
        result = []
        worker = threading.Thread(target=lambda: result.append(self.issuer.publish()))
        worker.start()
        try:
            self.assertTrue(entered.wait(5))
            with self.assertRaisesRegex(s.AuthorityError, "ISSUER_BUSY"):
                self.issuer.publish()
        finally:
            release.set(); worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(result), 1)


if __name__ == "__main__":
    unittest.main()
