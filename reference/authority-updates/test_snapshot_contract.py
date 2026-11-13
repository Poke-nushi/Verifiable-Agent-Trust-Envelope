"""Wire and local example checks for the optional authority snapshot contract."""
import copy
from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch

import test_authority_updates as fixtures
import authority_store
from fixture_support import sign_fixture

s, b = fixtures.s, fixtures.b


class SnapshotContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.AuthorityUpdateTests.setUpClass()

    def setUp(self):
        self.f = fixtures.AuthorityUpdateTests(); self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def test_schema_shape_and_ordinary_verifier_agree_on_example(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is an optional repository development dependency")
        schema = json.loads(Path(__file__).with_name("snapshot-claims.schema.json").read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(schema)
        validator.validate(self.f.claims)
        raw, = self.f.setup_source(); self.f.source.accept(raw)
        mutations = [lambda x: x.update(revision=True), lambda x: x.update(extension=True),
            lambda x: x["delegation_grants"][0].update(tool_allowlist=["a", "a"]),
            lambda x: x["runtime_grants"][0].update(public_key_spki_base64="invalid"),
            lambda x: x["delegation_grants"][0].update(currency="USD\n")]
        for mutation in mutations:
            changed = copy.deepcopy(self.f.claims); mutation(changed)
            self.assertFalse(validator.is_valid(changed))

    def test_malformed_and_ambiguous_grants_reject_entire_signed_snapshot(self):
        variants = []
        for mutate in (lambda x: x["runtime_grants"][0].update(revoked=1),
                       lambda x: x["delegation_grants"][0].update(extra=True),
                       lambda x: x["delegation_grants"].append(copy.deepcopy(x["delegation_grants"][0])),
                       lambda x: x["runtime_grants"].append(copy.deepcopy(x["runtime_grants"][0]))):
            item = copy.deepcopy(self.f.claims); mutate(item); variants.append(item)
        tokens = self.f.setup_source(variants)
        for raw in tokens:
            with self.assertRaises(s.AuthorityError): self.f.source.accept(raw)
        self.assertEqual(self.f.source.status()["revision"], 0)

    def test_duplicate_json_claim_is_rejected_even_with_selected_signature(self):
        self.f.setup_source()
        claims = b.encode(self.f.claims)
        malformed = claims[:-1] + b',"revision":1}'
        raw, key = sign_fixture(self.f.f.f.node,
            b.encode({"alg": "ES256", "typ": s.TOKEN_TYPE, "kid": "authority-key"}), malformed)
        verifier = s.SnapshotVerifier(expected_profile=s.PROFILE,
            selection=replace(self.f.selection, public_key_spki=key),
            node=self.f.f.f.node, node_sha256=self.f.f.f.node_sha)
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_VERIFICATION_FAILED"):
            verifier.verify(raw, self.f.now)

    def test_future_and_exclusive_expiry(self):
        now = self.f.f.f.second
        variants = [{**self.f.claims, "iat": now + 1}, {**self.f.claims, "nbf": now + 1},
                    {**self.f.claims, "exp": now}]
        for raw in self.f.setup_source(variants):
            with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_OUTSIDE_WINDOW"):
                self.f.source.accept(raw)

    def test_missing_store_is_not_recreated(self):
        raw, = self.f.setup_source(); self.f.source.accept(raw)
        path = self.f.directory / "authority.sqlite3"; path.unlink()
        with self.assertRaises(s.AuthorityError): self.f.source.accept(raw)
        self.assertFalse(path.exists())

    def test_failed_update_commit_keeps_prior_revision_and_can_retry(self):
        first, second = self.f.setup_source([self.f.claims, {**self.f.claims, "revision": 2}])
        self.f.source.accept(first)
        real_connect = sqlite3.connect
        class FailedCommit(sqlite3.Connection):
            updates_policy = False
            def execute(self, sql, *args, **kwargs):
                if sql.startswith("UPDATE state SET revision="): self.updates_policy = True
                return super().execute(sql, *args, **kwargs)
            def commit(self):
                if self.updates_policy: raise sqlite3.OperationalError("local fixture commit failure")
                return super().commit()
        def connect(*args, **kwargs):
            return real_connect(*args, **kwargs, factory=FailedCommit)
        with patch.object(authority_store.sqlite3, "connect", connect):
            with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_STORE_UNAVAILABLE"):
                self.f.source.accept(second)
        self.assertEqual(self.f.source.status()["revision"], 1)
        self.f.source.accept(second)
        self.assertEqual(self.f.source.status()["revision"], 2)

    def test_local_example_records_revocation_restart_and_recovery(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("authority_cli_fixture", Path(__file__).with_name("run_example.py"))
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        files = module.run(self.f.f.f.node, self.f.f.f.node_sha)
        run = b.decode(files["RUN.json"])
        self.assertEqual(run["observations"]["callback_calls"], 1)
        self.assertEqual(run["observations"]["revoked_callback_calls"], 0)
        self.assertEqual(run["observations"]["old_snapshot"], "AUTHORITY_ROLLBACK")
        for name, digest in run["artifacts"].items():
            self.assertEqual(b.digest(files[name]), digest)
        for name, digest in run["sources"].items():
            self.assertEqual(b.digest((s.ROOT / name).read_bytes()), digest)


if __name__ == "__main__":
    unittest.main()
