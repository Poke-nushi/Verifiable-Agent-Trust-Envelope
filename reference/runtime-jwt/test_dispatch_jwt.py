"""Real ES256 proof revalidation and changing local trust at dispatch."""
from dataclasses import replace
from datetime import timedelta
import unittest
from unittest.mock import patch

import runtime_jwt as jwt
import test_runtime_jwt as fixtures
import run_dispatch_example

b = jwt.binding


class RuntimeJwtDispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.RuntimeJwtTests.setUpClass()

    def setUp(self):
        self.fixture = fixtures.RuntimeJwtTests()
        self.fixture.setUp()
        self.now = self.fixture.now
        self.calls = []
        self.boundary = b.DispatchBoundary(execute=lambda *args: self.calls.append(args), clock=lambda: self.now)
        self.fixture.verifier.dispatch_boundary = self.boundary
        self.bound = self.fixture.admit()

    def reject(self, cause="RUNTIME_EVIDENCE_VERIFICATION_FAILED"):
        with self.assertRaisesRegex(b.Invalid, "^" + cause + "$"):
            self.fixture.verifier.dispatch(self.bound)
        self.assertEqual(self.calls, [])

    def test_real_signature_checked_again_at_dispatch(self):
        self.now += timedelta(seconds=3)
        with patch.object(self.fixture.adapter, "_signature", wraps=self.fixture.adapter._signature) as verify:
            dispatched = self.fixture.verifier.dispatch(self.bound)
            self.assertEqual(verify.call_count, 1)
        self.assertEqual(self.calls, [(self.bound.effective, dispatched.checkpoint)])
        record = b.decode(dispatched.checkpoint)
        self.assertEqual(record["runtime_verification"]["verification"]["checked_at"], b.core.iso(self.now))

    def test_revocation_delivered_after_admission_prevents_callback(self):
        with self.boundary.update():
            self.fixture.trust = replace(self.fixture.trust,
                grants=(replace(self.fixture.grant, revoked=True),))
        self.reject()

    def test_removed_issuer_grant_prevents_callback(self):
        with self.boundary.update():
            self.fixture.trust = replace(self.fixture.trust, grants=())
        self.reject()

    def test_replaced_public_key_prevents_callback(self):
        with self.boundary.update():
            self.fixture.trust = replace(self.fixture.trust,
                grants=(replace(self.fixture.grant, public_key_spki=b"x" * 91),))
        self.reject()

    def test_unavailable_current_trust_prevents_callback(self):
        def unavailable():
            raise RuntimeError("local source unavailable")
        with self.boundary.update():
            self.fixture.adapter.trust_policy_provider = unavailable
        self.reject()

    def test_expired_current_policy_prevents_callback(self):
        with self.boundary.update():
            self.fixture.trust = replace(self.fixture.trust, expires_at=self.fixture.second)
        self.reject()

    def test_refresh_cannot_extend_old_receipt(self):
        with self.boundary.update():
            self.fixture.trust = replace(self.fixture.trust, issued_at=self.fixture.second + 40,
                                         expires_at=self.fixture.second + 300)
        self.now += timedelta(seconds=49)
        self.reject("DISPATCH_OUTSIDE_WINDOW")

    def test_policy_change_observed_during_crypto_prevents_callback(self):
        signature = self.fixture.adapter._signature
        def changed(*args):
            signature(*args)
            # Non-cooperating writer: the adapter's second snapshot also
            # detects changes that happen to be visible during verification.
            self.fixture.trust = replace(self.fixture.trust,
                grants=(replace(self.fixture.grant, revoked=True),))
        with patch.object(self.fixture.adapter, "_signature", side_effect=changed):
            self.reject()

    def test_slow_crypto_cannot_outlive_issuer_grant(self):
        with self.boundary.update():
            self.fixture.trust = replace(self.fixture.trust,
                grants=(replace(self.fixture.grant, expires_at=self.fixture.second + 2),))
        signature = self.fixture.adapter._signature
        def slow(*args):
            signature(*args)
            self.now += timedelta(seconds=2)
        with patch.object(self.fixture.adapter, "_signature", side_effect=slow):
            self.reject("DISPATCH_OUTSIDE_WINDOW")

    def test_example_keeps_artifact_and_source_digests(self):
        files = run_dispatch_example.run(self.fixture.node, self.fixture.node_sha)
        report = b.decode(files["RUN.json"])
        self.assertEqual(report["evidence_kind"], "local-recording-callback")
        self.assertEqual(report["observations"]["revoked_callback_calls"], 0)
        self.assertEqual(report["observations"]["valid_callback_calls"], 1)
        for name, digest in report["artifacts"].items():
            self.assertEqual(b.digest(files[name]), digest, name)
        for name, digest in report["sources"].items():
            self.assertEqual(b.digest((jwt.ROOT / name).read_bytes()), digest, name)


if __name__ == "__main__":
    unittest.main()
