import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from receive import InputError
import receive_v03 as receiver

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
INPUTS = ROOT / "inputs"


class V03Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.package = Path(self.temp.name) / "package"
        shutil.copytree(INPUTS / "published", self.package)
        self.pub = bytes.fromhex((INPUTS / "published.pub").read_text())

    def tearDown(self):
        self.temp.cleanup()

    def edit(self, path, fn):
        p = self.package / path
        obj = json.loads(p.read_text())
        fn(obj)
        p.write_text(json.dumps(obj))

    def report(self, **kwargs):
        return receiver.assess(self.package, **kwargs)

    def test_22_native_comparisons(self):
        sys.path.insert(0, str(ROOT))
        from compare_fixed import run
        self.assertEqual(run("vate")["selected_check_comparisons"], 66)

    def test_valid_unpinned_signature_leaves_receiver_unresolved(self):
        r = self.report()
        self.assertEqual(r["checks_status"], "matched")
        self.assertEqual(r["receiver_checks_status"], "not_assessed")
        self.assertEqual(r["checks"]["seal"]["signature"]["status"], "matched")

    def test_correct_pin_still_does_not_claim_identity_authority_or_execution(self):
        r = self.report(public_key=self.pub)
        self.assertEqual(r["receiver_checks_status"], "matched")
        for name in ("issuer_authority", "key_status_and_revocation", "execution_admission", "behavioral_truth"):
            self.assertIn(name, r["not_assessed"])
        self.assertNotIn("decision", r)

    def test_wrong_pin_is_separate_from_valid_signature(self):
        r = self.report(public_key=b"x" * 32)["checks"]["seal"]
        self.assertEqual(r["signature"]["status"], "matched")
        self.assertEqual(r["selected_key_binding"]["status"], "mismatched")
        self.assertEqual(r["status"], "mismatched")

    def test_attacker_pin_can_only_match_attacker(self):
        pub = bytes.fromhex((INPUTS / "attacker.pub").read_text())
        r = receiver.assess(INPUTS / "resealed", public_key=pub)
        self.assertEqual(r["receiver_checks_status"], "matched")
        self.assertEqual(r["checks"]["seal"]["selected_key_id"], hashlib.sha256(pub).hexdigest())
        self.assertIn("issuer_authority", r["not_assessed"])

    def test_tampered_evidence_keeps_seal_valid(self):
        r = receiver.assess(INPUTS / "tampered", public_key=self.pub)
        self.assertEqual([r["checks"][n]["status"] for n in ("evidence_files", "evidence_root", "seal")],
                         ["mismatched", "not_assessed", "matched"])

    def test_identity_and_unknown_manifest_fields_are_signed(self):
        for p in ("identity.json", "manifest.json"):
            with self.subTest(path=p):
                original = (self.package / p).read_bytes()
                self.edit(p, lambda obj: obj.update(extra="changed"))
                r = self.report(public_key=self.pub)
                self.assertEqual(r["checks"]["seal"]["signature"]["status"], "mismatched")
                (self.package / p).write_bytes(original)

    def test_lifecycle_is_not_an_assessed_surface(self):
        (self.package / "lifecycle.json").write_text('{"events":[{"event_type":"INVALID"}]}')
        r = self.report(public_key=self.pub)
        self.assertEqual(r["receiver_checks_status"], "matched")
        self.assertIn("lifecycle_transitions_and_event_signatures", r["not_assessed"])
        self.assertNotIn("lifecycle.json", {i["path"] for i in r["inputs"]})

    def test_evidence_type_can_change_without_changing_seal(self):
        def change(index):
            entry = index["entries"][0]
            entry["type"] = "OUTPUT" if entry["type"] != "OUTPUT" else "ACTION"
        self.edit("evidence/index.json", change)
        r = self.report(public_key=self.pub)
        self.assertEqual(r["receiver_checks_status"], "matched")
        self.assertIn("evidence_metadata_binding", r["not_assessed"])

    def test_malformed_signature_lengths_and_base64(self):
        for value in (None, [], {}, 8, "é", "%%%", base64.b64encode(b"x" * 63).decode(), base64.b64encode(b"x" * 65).decode()):
            with self.subTest(value=value):
                self.edit("signatures/seal.json", lambda obj: obj.update(signature=value))
                self.assertEqual(self.report()["checks"]["seal"]["status"], "mismatched")

    def test_malformed_recorded_public_keys(self):
        for value in (None, [], {}, 8, "é", "%%%", base64.b64encode(b"x" * 31).decode(), base64.b64encode(b"x" * 33).decode()):
            with self.subTest(value=value):
                self.edit("signatures/seal.json", lambda obj: obj.update(public_key=value))
                self.assertEqual(self.report()["checks"]["seal"]["reason"], "invalid_recorded_public_key")

    def test_wrong_key_identifier(self):
        self.edit("signatures/seal.json", lambda obj: obj.update(key_id="a" * 64))
        self.assertEqual(self.report()["checks"]["seal"]["reason"], "recorded_public_key_id_mismatch")

    def test_unsupported_seal_profiles_stay_unassessed(self):
        original = (self.package / "signatures/seal.json").read_bytes()
        for change in ({"schema": []}, {"schema": "other"}, {"signed": "manifest"}, {"algorithm": []}, {"algorithm": "other"}):
            with self.subTest(change=change):
                (self.package / "signatures/seal.json").write_bytes(original)
                self.edit("signatures/seal.json", lambda obj: obj.update(change))
                self.assertEqual(self.report()["checks"]["seal"]["status"], "not_assessed")

    def test_malformed_or_mixed_package_schemas_rejected(self):
        for value in ([], {}, None, "other", "uibc-core/0.3.0-proposal"):
            with self.subTest(value=value):
                self.edit("manifest.json", lambda obj: obj.update(schema=value))
                with self.assertRaises(InputError):
                    self.report()

    def test_selected_key_length_type_and_dual_mode(self):
        for kwargs in ({"public_key": b"x"}, {"public_key": "x" * 32},
                       {"key": b"x" * 32, "public_key": self.pub}):
            with self.subTest(kwargs=kwargs), self.assertRaises(InputError):
                self.report(**kwargs)

    def test_cli_rejects_embedded_pin_file(self):
        p = self.package / "embedded.pub"
        p.write_text(self.pub.hex() + "\n")
        r = subprocess.run([sys.executable, "-B", str(HERE / "receive_v03.py"), "--package", str(self.package),
                            "--pubkey", str(p)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 64)
        self.assertEqual(json.loads(r.stdout)["reason"], "key_must_be_outside_package")

    def test_cli_backend_absence_is_explicit(self):
        r = subprocess.run([sys.executable, "-S", "-B", str(HERE / "receive_v03.py"),
                            "--package", str(self.package)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 64)
        self.assertEqual(json.loads(r.stdout)["reason"], "ed25519_backend_unavailable")
        self.assertEqual(r.stderr, "")

    def test_cli_exit_zero_is_report_delivery_even_for_mismatch(self):
        r = subprocess.run([sys.executable, "-B", str(HERE / "receive_v03.py"), "--package", str(INPUTS / "resealed"),
                            "--pubkey", str(INPUTS / "published.pub")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(json.loads(r.stdout)["receiver_checks_status"], "mismatched")

    def test_duplicate_json_names_rejected(self):
        (self.package / "signatures/seal.json").write_text('{"algorithm":"Ed25519","algorithm":"HMAC-SHA256"}')
        with self.assertRaises(InputError) as exc:
            self.report()
        self.assertEqual(exc.exception.code, "duplicate_json_key")

    def test_reports_deterministic_and_inputs_unchanged(self):
        def files():
            return {str(p.relative_to(self.package)): p.read_bytes() for p in self.package.rglob("*") if p.is_file()}
        before = files()
        self.assertEqual(self.report(public_key=self.pub), self.report(public_key=self.pub))
        self.assertEqual(before, files())


if __name__ == "__main__":
    unittest.main()
