"""The signed legacy chain must retain a usable permit scope and one transaction."""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import trust_envelope_demo as demo


class PermitScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="vate-al2-scope-")
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        cls.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with patch.object(demo, "utc_now", return_value=cls.now):
            cls.bundle = demo.build_demo_bundle(cls.directory)

    def verify(self, *, permit=None, receipt=None, passport=None, runtime=None,
               drop_permit=(), drop_receipt=(), mode="stapled"):
        bundle = copy.deepcopy(self.bundle)
        for name, changes, omitted in (("permit", permit, drop_permit), ("receipt", receipt, drop_receipt),
                                       ("passport", passport, ()), ("runtime_proof", runtime, ())):
            if not changes and not omitted:
                continue
            payload = bundle["artifacts"][name]["payload"]
            payload.update(changes or {})
            for field in omitted:
                payload.pop(field)
            demo.resign_artifact(bundle, name, self.directory)
        demo.write_bundle(self.directory, bundle)
        # Pull uses the same signed bundle; the network transport is outside this test.
        with patch.object(demo, "utc_now", return_value=self.now), patch.object(
                demo, "http_get_text", return_value=demo.read_text(self.directory / "stapled-status.jws")):
            report = demo.verify_demo(self.directory, status_mode=mode, status_base="https://fixture.invalid")
        self.assertEqual(json.loads((self.directory / "verification-report.json").read_text()), report)
        checks = {c["name"]: c["ok"] for c in report["checks"]}
        self.assertTrue(checks["artifact_signer_roles"])
        self.assertTrue(checks["permit_signature"])
        self.assertTrue(checks["receipt_signature"])
        return report, {name for name, ok in checks.items() if not ok}

    def test_subject_actor_and_audience_need_real_identifiers(self):
        subject = self.bundle["artifacts"]["passport"]["payload"]["subject"]
        for field, changed in (
            ("subject_binding", {"passport": {"subject": {**subject, "root_id": ""}},
                                 "runtime": {"subject_id": ""}}),
            ("actor_binding", {"passport": {"subject": {**subject, "public_alias": ""}},
                               "permit": {"actor": ""}, "receipt": {"actor": ""}}),
            ("audience_binding", {"runtime": {"challenge_binding": {}}, "drop_permit": ("aud",),
                                  "drop_receipt": ("verifier",)}),
        ):
            with self.subTest(field=field):
                report, failures = self.verify(**changed)
                self.assertFalse(report["ok"])
                self.assertEqual(failures, {field})

    def test_fingerprints_bind_to_the_registered_runtime_key(self):
        permit = self.bundle["artifacts"]["permit"]["payload"]["proof_binding"]
        presented = self.bundle["artifacts"]["runtime_proof"]["payload"]["presented_key"]
        other = self.bundle["trust_bundle"]["keys"]["issuer-key-1"]["spki_sha256"]
        report, failures = self.verify(permit={"proof_binding": {**permit, "spki_sha256": other}},
                                       runtime={"presented_key": {**presented, "spki_sha256": other}})
        self.assertFalse(report["ok"])
        self.assertEqual(failures, {"proof_of_possession_binding"})

    def test_transaction_binding_applies_to_every_status_delivery(self):
        original = self.bundle["artifacts"]["permit"]["payload"]["transaction_id"]
        for mode in ("stapled", "push", "pull"):
            for transaction in (original, "txn:別の取引"):
                with self.subTest(mode=mode, transaction=transaction):
                    report, failures = self.verify(receipt={"transaction_id": transaction}, mode=mode)
                    self.assertEqual(report["ok"], transaction == original)
                    self.assertEqual(failures, set() if transaction == original else {"receipt_transaction_binding"})
        report, failures = self.verify(permit={"transaction_id": "txn:別の取引"},
                                       receipt={"transaction_id": "txn:別の取引"})
        self.assertTrue(report["ok"])
        self.assertEqual(failures, set())

    def test_missing_or_invalid_transaction_ids_cannot_match(self):
        for value in (None, "", True, 1, [], {}):
            with self.subTest(receipt=value):
                report, failures = self.verify(receipt={"transaction_id": value})
                self.assertFalse(report["ok"])
                self.assertEqual(failures, {"receipt_transaction_binding"})
            with self.subTest(permit_and_receipt=value):
                report, failures = self.verify(permit={"transaction_id": value}, receipt={"transaction_id": value})
                self.assertFalse(report["ok"])
                self.assertEqual(failures, {"verification_input"})
        report, failures = self.verify(drop_receipt=("transaction_id",))
        self.assertFalse(report["ok"])
        self.assertEqual(failures, {"receipt_transaction_binding"})
        report, failures = self.verify(drop_permit=("transaction_id",), drop_receipt=("transaction_id",))
        self.assertFalse(report["ok"])
        self.assertEqual(failures, {"verification_input"})

    def test_permit_action_shape_is_checked_before_chain_acceptance(self):
        for actions in ("task.execute", {"task.execute": False}, None, True, [], [""], ["task.execute", 1]):
            with self.subTest(actions=actions):
                report, failures = self.verify(permit={"actions": actions})
                self.assertFalse(report["ok"])
                self.assertEqual(failures, {"verification_input"})
        report, failures = self.verify(drop_permit=("actions",))
        self.assertFalse(report["ok"])
        self.assertEqual(failures, {"verification_input"})
        report, failures = self.verify(permit={"actions": ["task.execute", "task.execute"],
                                              "annotation": {"label": "permitted extension"}})
        self.assertTrue(report["ok"])
        self.assertEqual(failures, set())


if __name__ == "__main__":
    unittest.main()
