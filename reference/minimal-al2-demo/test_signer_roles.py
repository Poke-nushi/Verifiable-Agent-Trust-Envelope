"""The demo's selected signer roles are distinct from signature validity."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import trust_envelope_demo as demo


class SignerRoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="vate-al2-role-")
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        cls.bundle = demo.build_demo_bundle(cls.directory)

    def setUp(self):
        demo.write_bundle(self.directory, self.bundle)

    def sign(self, token, role, *, payload=None):
        header, original, _, _ = demo.decode_compact_jws(token)
        return demo.build_compact_jws(original if payload is None else payload,
            key_info={"kid": role + "-key-1", "alg": "ES256",
                      "private_key": demo.key_path(self.directory, role, "private")},
            typ=header["typ"], cty=header["cty"])

    def test_status_role_is_required_for_every_delivery(self):
        for mode in ("stapled", "push", "pull"):
            filename = "push-status-event.jws" if mode == "push" else "stapled-status.jws"
            for role, expected in (("status", True), ("runtime", False)):
                with self.subTest(mode=mode, role=role):
                    self.setUp()
                    token = self.sign(demo.read_text(self.directory / filename), role)
                    (self.directory / filename).write_text(token)
                    with patch.object(demo, "http_get_text", return_value=token):
                        report = demo.verify_demo(self.directory, status_mode=mode, status_base="https://fixture.invalid")
                    self.assertEqual(report["ok"], expected, report)
                    self.assertEqual(json.loads((self.directory / "verification-report.json").read_bytes()), report)
                    checks = {c["name"]: c["ok"] for c in report["checks"]}
                    self.assertTrue(checks["status_signature"])
                    self.assertEqual(checks["status_signer_role"], expected)

    def test_artifact_roles_come_from_the_verifier_profile(self):
        for name, expected_role in (("passport", "issuer"), ("runtime_proof", "attestor"),
                                    ("permit", "broker"), ("receipt", "runtime")):
            for role in (expected_role, "status"):
                with self.subTest(artifact=name, role=role):
                    self.setUp()
                    path = self.directory / (demo.ARTIFACT_SPECS[name]["basename"] + ".jws")
                    path.write_text(self.sign(demo.read_text(path), role))
                    report = demo.verify_demo(self.directory, status_mode="stapled")
                    self.assertEqual(report["ok"], role == expected_role, report)
                    if role != expected_role:
                        self.assertIn("artifact_signer_roles", {c["name"] for c in report["checks"] if not c["ok"]})

    def test_missing_status_role_and_unusable_unauthorized_payload_are_rejected(self):
        for missing_owner in (True, False):
            with self.subTest(missing_owner=missing_owner):
                self.setUp()
                if missing_owner:
                    trust = copy.deepcopy(self.bundle["trust_bundle"])
                    trust["keys"]["status-key-1"].pop("owner")
                    demo.write_json(self.directory / "trust-bundle.json", trust)
                else:
                    path = self.directory / "stapled-status.jws"
                    path.write_text(self.sign(demo.read_text(path), "runtime", payload={}))
                report = demo.verify_demo(self.directory, status_mode="stapled")
                checks = {c["name"]: c["ok"] for c in report["checks"]}
                self.assertFalse(report["ok"])
                self.assertFalse(checks["status_signer_role"])
                self.assertNotIn("status_payload", checks)


if __name__ == "__main__":
    unittest.main()
