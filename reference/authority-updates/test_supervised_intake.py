"""Supervised HTTPS against the existing disposable loopback TLS fixture."""
import copy
import os
from pathlib import Path
import selectors
import ssl
import unittest
from unittest.mock import patch

import snapshot as s
import supervised_https as supervised
from https_source import HttpsSnapshotSource
from supervised_https import SupervisedHttpsSnapshotSource
import test_https_intake as https_fixtures
import test_authority_updates as authority_fixtures


class SupervisedIntakeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse fixture setup, not the parent's test cases or test results.
        https_fixtures.HttpsIntakeTests.setUpClass.__func__(cls)
        authority_fixtures.AuthorityUpdateTests.setUpClass()

    def setUp(self):
        self.http = https_fixtures.HttpsIntakeTests()
        self.http.cert, self.http.key = self.cert, self.key
        self.http.setUp()
        self.addCleanup(self.http.doCleanups)

    def source(self, path="/ok", **options):
        return SupervisedHttpsSnapshotSource(self.http.base + path, ca_file=self.cert, **options)

    def fixture(self, *, variants=None):
        fixture = authority_fixtures.AuthorityUpdateTests(); fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        if variants == "revocation-recovery":
            revoked = copy.deepcopy(fixture.claims); revoked["revision"] = 2
            revoked["delegation_grants"][0]["revoked"] = True
            variants = [fixture.claims, revoked, {**fixture.claims, "revision": 3}]
        tokens = fixture.setup_source(variants)
        return fixture, tokens

    def test_verified_https_delivers_exact_body(self):
        self.assertEqual(self.source()(), self.http.body)

    def test_ca_selection_is_captured_without_reopening_path(self):
        selected = Path(self.temporary.name) / "selected-ca.pem"
        selected.write_bytes(self.cert.read_bytes())
        source = SupervisedHttpsSnapshotSource(self.http.base + "/ok", ca_file=selected)
        selected.write_text("changed after selection")
        self.assertEqual(source(), self.http.body)
        with self.assertRaises(s.AuthorityError):
            SupervisedHttpsSnapshotSource(self.http.base + "/ok", ca_file=selected)

    def test_selected_ca_ignores_parent_keylog_configuration(self):
        keylog = Path(self.temporary.name) / "keylog"
        for destination in (keylog, Path(self.temporary.name)):
            with patch.dict(os.environ, {"SSLKEYLOGFILE": str(destination)}):
                self.assertEqual(self.source()(), self.http.body)
                self.assertEqual(os.environ["SSLKEYLOGFILE"], str(destination))
        self.assertFalse(keylog.exists())

    def test_pem_and_der_ca_data_and_exclusive_selection(self):
        pem = self.cert.read_text()
        for data in (pem, ssl.PEM_cert_to_DER_cert(pem)):
            self.assertEqual(HttpsSnapshotSource(self.http.base + "/ok", ca_data=data)(), self.http.body)
        for data in ("", b"", [], True):
            with self.subTest(data=repr(data)), self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_CA_CONFIGURATION_INVALID"):
                HttpsSnapshotSource(self.http.base + "/ok", ca_data=data)
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_CA_CONFIGURATION_INVALID"):
            HttpsSnapshotSource(self.http.base + "/ok", ca_file=self.cert, ca_data=pem)
        selected = Path(self.temporary.name) / "selected-ca.der"
        selected.write_bytes(ssl.PEM_cert_to_DER_cert(pem))
        self.assertEqual(SupervisedHttpsSnapshotSource(self.http.base + "/ok", ca_file=selected)(), self.http.body)

    def test_wrong_ca_and_hostname_are_rejected_before_http(self):
        for source in (SupervisedHttpsSnapshotSource(self.http.base + "/ok"),
                SupervisedHttpsSnapshotSource(self.http.base.replace("localhost", "127.0.0.1") + "/ok", ca_file=self.cert)):
            with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_FETCH_WORKER_FAILED"):
                source()
        self.assertEqual(self.http.hits, [])

    def test_redirect_and_invalid_response_are_rejected(self):
        with self.assertRaises(s.AuthorityError): self.source("/redirect")()
        self.assertEqual(self.http.hits, ["/redirect"])
        for path in ("/oversized", "/wrong-type", "/encoded", "/error"):
            with self.subTest(path=path), self.assertRaises(s.AuthorityError): self.source(path)()

    def test_refresh_failure_restart_revocation_and_valid_recovery(self):
        fixture, (allowed, revoked, recovered) = self.fixture(variants="revocation-recovery")
        self.http.body = allowed
        self.assertEqual(fixture.source.refresh(self.source())["revision"], 1)
        bound = fixture.admit()
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REFRESH_FAILED"):
            fixture.source.refresh(self.source("/slow", timeout_seconds=0.15))
        self.assertEqual(fixture.source.status()["revision"], 1)
        self.assertTrue(fixture.source.status()["unavailable"])
        fixture.source, fixture.managed = fixture.reopen()
        self.assertTrue(fixture.source.status()["unavailable"])
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_NOT_AVAILABLE"):
            fixture.managed.restore_admission(fixture.f.f.request["request_id"])
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_NOT_AVAILABLE"):
            fixture.managed.dispatch(bound, caller_proof=fixture.f.proof)
        self.assertEqual(fixture.calls, [])
        self.http.body = revoked
        self.assertEqual(fixture.source.refresh(self.source())["revision"], 2)
        restored = fixture.managed.restore_admission(fixture.f.f.request["request_id"])
        with self.assertRaisesRegex(s.b.Invalid, "CALLER_AUTHORIZATION_FAILED"):
            fixture.managed.dispatch(restored, caller_proof=fixture.f.proof)
        self.http.body = allowed
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REFRESH_FAILED"):
            fixture.source.refresh(self.source())
        self.assertEqual(fixture.source.status()["revision"], 2)
        self.assertEqual(fixture.calls, [])
        self.http.body = recovered
        self.assertEqual(fixture.source.refresh(self.source())["revision"], 3)
        self.assertFalse(fixture.source.status()["unavailable"])
        fixture.managed.dispatch(restored, caller_proof=fixture.f.proof)
        self.assertEqual(len(fixture.calls), 1)
        with self.assertRaises(s.b.Invalid):
            fixture.managed.dispatch(restored, caller_proof=fixture.f.proof)
        self.assertEqual(len(fixture.calls), 1)
        self.assertEqual(restored.receipt, bound.receipt)

    def test_https_success_cannot_replace_signature_verification(self):
        fixture, (allowed,) = self.fixture()
        fixture.source.accept(allowed)
        forged, _ = authority_fixtures.sign_snapshots(fixture.f.f.node, [fixture.claims])
        self.http.body = forged[0]
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REFRESH_FAILED"):
            fixture.source.refresh(self.source())
        self.assertTrue(fixture.source.status()["unavailable"])
        self.assertEqual(fixture.source.status()["revision"], 1)
        with self.assertRaises(s.AuthorityError): fixture.admit()
        self.assertEqual(fixture.calls, [])

    def test_busy_store_does_not_claim_failure_was_persisted(self):
        fixture, (allowed,) = self.fixture()
        fixture.source.accept(allowed)
        other, _ = fixture.reopen()
        with fixture.source.lease():
            with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REFRESH_FAILED"):
                other.refresh(self.source("/error"))
        self.assertFalse(fixture.source.status()["unavailable"])
        self.assertEqual(fixture.source.status()["revision"], 1)

    def test_interrupted_refresh_blocks_reopened_store_and_preserves_interrupt(self):
        fixture, (allowed,) = self.fixture()
        fixture.source.accept(allowed)
        bound = fixture.admit()
        fetch = self.source()
        selector = selectors.DefaultSelector()
        # Interrupt a real disposable worker while its parent is polling pipes.
        with patch.object(supervised.selectors, "DefaultSelector", return_value=selector), \
                patch.object(selector, "select", side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            fixture.source.refresh(fetch)
        self.assertFalse(fetch.cleanup_required)
        self.assertTrue(fixture.source.status()["unavailable"])
        fixture.source, fixture.managed = fixture.reopen()
        self.assertTrue(fixture.source.status()["unavailable"])
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_NOT_AVAILABLE"):
            fixture.managed.restore_admission(fixture.f.f.request["request_id"])
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_NOT_AVAILABLE"):
            fixture.managed.dispatch(bound, caller_proof=fixture.f.proof)
        self.assertEqual(fixture.calls, [])
        self.http.body = allowed
        fixture.source.refresh(self.source())
        restored = fixture.managed.restore_admission(fixture.f.f.request["request_id"])
        fixture.managed.dispatch(restored, caller_proof=fixture.f.proof)
        self.assertEqual(len(fixture.calls), 1)

    def test_termination_and_busy_interrupt_keep_original_exception(self):
        fixture, (allowed,) = self.fixture()
        fixture.source.accept(allowed)
        def terminate():
            raise SystemExit(7)
        with self.assertRaises(SystemExit) as caught:
            fixture.source.refresh(terminate)
        self.assertEqual(caught.exception.code, 7)
        self.assertTrue(fixture.source.status()["unavailable"])
        fixture.source.accept(allowed)
        other, _ = fixture.reopen()
        def interrupt():
            raise KeyboardInterrupt
        with fixture.source.lease(), self.assertRaises(KeyboardInterrupt):
            other.refresh(interrupt)
        self.assertFalse(fixture.source.status()["unavailable"])


if __name__ == "__main__":
    unittest.main()
