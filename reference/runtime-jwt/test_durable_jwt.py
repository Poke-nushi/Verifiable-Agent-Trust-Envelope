"""Durable restore uses a fresh real ES256 verification before local dispatch."""
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import runtime_jwt as jwt
import test_runtime_jwt as fixtures

b = jwt.binding
s = b.durable_state_module()


class RuntimeJwtDurableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.RuntimeJwtTests.setUpClass()

    def setUp(self):
        self.fixture = fixtures.RuntimeJwtTests()
        self.fixture.setUp()
        self.now = self.fixture.now
        self.calls = []
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = s.DurableStateStore.create(Path(self.tmp.name) / "state", scope="local signed fixture",
            verifier_id=self.fixture.verifier.verifier_id)
        self.configure(self.fixture.verifier, self.store)
        self.bound = self.fixture.admit()
        self.request_id = b.decode(self.bound.request)["request_id"]

    def configure(self, verifier, store):
        verifier.state_store = store
        verifier.dispatch_boundary = b.DispatchBoundary(execute=lambda *args: self.calls.append(args), clock=lambda: self.now)
        return verifier

    def reopen(self):
        verifier = b.core.VateVerifier(verifier_id=self.fixture.verifier.verifier_id,
            policy=self.fixture.verifier.policy, runtime_evidence_verifier=self.fixture.adapter.as_runtime_verifier())
        return self.configure(verifier, s.DurableStateStore(self.store.directory, expected_anchor=self.store.anchor))

    def test_reopened_verifier_rechecks_signature_before_single_callback(self):
        verifier = self.reopen()
        restored = verifier.restore_admission(self.request_id)
        with patch.object(self.fixture.adapter, "_signature", wraps=self.fixture.adapter._signature) as signature:
            result = verifier.dispatch(restored)
            self.assertEqual(signature.call_count, 1)
        self.assertEqual(self.calls, [(self.bound.effective, result.checkpoint)])
        self.assertEqual(verifier.dispatch_status(self.request_id).state, "callback_returned")
        with self.assertRaisesRegex(b.Invalid, "DURABLE_OPERATION_ALREADY_ATTEMPTED"):
            self.reopen().restore_admission(self.request_id)

    def test_reopened_verifier_observes_current_revocation(self):
        self.fixture.trust = replace(self.fixture.trust, grants=(replace(self.fixture.grant, revoked=True),))
        verifier = self.reopen()
        with self.assertRaisesRegex(b.Invalid, "RUNTIME_EVIDENCE_VERIFICATION_FAILED"):
            verifier.dispatch(verifier.restore_admission(self.request_id))
        self.assertEqual(self.calls, [])
        self.assertEqual(verifier.dispatch_status(self.request_id).state, "ready")

    def test_reopened_verifier_rejects_changed_trust_key(self):
        self.fixture.trust = replace(self.fixture.trust,
            grants=(replace(self.fixture.grant, public_key_spki=b"x" * 91),))
        verifier = self.reopen()
        with self.assertRaisesRegex(b.Invalid, "RUNTIME_EVIDENCE_VERIFICATION_FAILED"):
            verifier.dispatch(verifier.restore_admission(self.request_id))
        self.assertEqual(self.calls, [])

    def test_reopened_verifier_cannot_extend_receipt_from_new_trust_snapshot(self):
        self.fixture.trust = replace(self.fixture.trust, issued_at=self.fixture.second + 40,
                                     expires_at=self.fixture.second + 300)
        self.now += timedelta(seconds=49)
        verifier = self.reopen()
        with self.assertRaisesRegex(b.Invalid, "DISPATCH_OUTSIDE_WINDOW"):
            verifier.dispatch(verifier.restore_admission(self.request_id))
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
