"""R1 key-admission and O1 diagnosis regressions, on disposable packages."""
import base64
import hashlib
import hmac
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from receive import InputError
from receive_v03 import assess

HERE = Path(__file__).resolve().parent
INPUTS = HERE.parent / "inputs"
IDENTITY_KEY = bytes.fromhex("01" + "00" * 31)
FIXED_SIGNATURE = IDENTITY_KEY + bytes(32)


class RevisionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.package = Path(self.tmp.name) / "sample"
        shutil.copytree(INPUTS / "published", self.package)
        self.normal_pin = bytes.fromhex((INPUTS / "published.pub").read_text())

    def tearDown(self):
        self.tmp.cleanup()

    def edit(self, path, **updates):
        p = self.package / path
        data = json.loads(p.read_text())
        data.update(updates)
        p.write_text(json.dumps(data))

    def set_public_key(self, key):
        self.edit("signatures/seal.json", public_key=base64.b64encode(key).decode(),
                  key_id=hashlib.sha256(key).hexdigest(),
                  signature=base64.b64encode(FIXED_SIGNATURE).decode())

    def test_review_counterexample_never_reports_signature_success(self):
        self.set_public_key(IDENTITY_KEY)
        signature = (self.package / "signatures/seal.json").read_bytes()
        payloads = []
        for owner in ("first payload", "changed payload without resigning"):
            with self.subTest(owner=owner):
                self.edit("identity.json", owner=owner)
                r = assess(self.package)
                payloads.append(r["checks"]["seal"]["payload_digest"])
                self.assertEqual(r["checks"]["seal"]["signature"],
                                 {"status": "not_assessed", "reason": "small_order_ed25519_public_key"})
                self.assertEqual(r["receiver_checks_status"], "not_assessed")
                self.assertEqual(signature, (self.package / "signatures/seal.json").read_bytes())
                with self.assertRaises(InputError) as error:
                    assess(self.package, public_key=IDENTITY_KEY)
                self.assertEqual(error.exception.code, "small_order_ed25519_public_key")
                r = assess(self.package, public_key=self.normal_pin)
                self.assertEqual(r["receiver_checks_status"], "mismatched")
                self.assertEqual(r["checks"]["seal"]["signature"]["status"], "not_assessed")
        self.assertNotEqual(*payloads)

    def test_all_sourced_key_encodings_blocked_in_recorded_and_selected_inputs(self):
        vectors = json.loads((HERE / "key-input-vectors.json").read_text())["vectors"]
        self.assertEqual(len(vectors), 48)
        for vector in vectors:
            with self.subTest(source=vector["source"]):
                key = bytes.fromhex(vector["public_key"])
                self.set_public_key(key)
                r = assess(self.package)
                self.assertEqual(r["checks"]["seal"]["signature"],
                                 {"status": "not_assessed", "reason": vector["reason"]})
                self.assertEqual(r["receiver_checks_status"], "not_assessed")
                r = assess(self.package, public_key=self.normal_pin)
                self.assertEqual(r["receiver_checks_status"], "mismatched")
                with self.assertRaises(InputError) as error:
                    assess(self.package, public_key=key)
                self.assertEqual(error.exception.code, vector["reason"])
                self.assertEqual(error.exception.input_name, "selected_public_key")

    def test_excluded_pin_is_rejected_before_package_is_opened(self):
        with self.assertRaises(InputError) as error:
            assess(Path(self.tmp.name) / "absent-package", public_key=IDENTITY_KEY)
        self.assertEqual(error.exception.code, "small_order_ed25519_public_key")

    def test_excluded_key_does_not_hide_wrong_key_identifier(self):
        self.set_public_key(IDENTITY_KEY)
        self.edit("signatures/seal.json", key_id="f" * 64)
        r = assess(self.package)["checks"]["seal"]
        self.assertEqual(r["status"], "mismatched")
        self.assertEqual(r["reason"], "recorded_public_key_id_mismatch")
        self.assertEqual(r["signature"]["status"], "not_assessed")

    def test_cli_excluded_pin_reports_input_error_without_backend(self):
        keyfile = Path(self.tmp.name) / "pin.hex"
        keyfile.write_text(IDENTITY_KEY.hex() + "\n")
        r = subprocess.run([sys.executable, "-S", "-B", str(HERE / "receive_v03.py"),
                            "--package", str(self.package), "--pubkey", str(keyfile)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 64)
        self.assertEqual(json.loads(r.stdout)["reason"], "small_order_ed25519_public_key")
        self.assertEqual(r.stderr, "")

    def test_cli_recorded_excluded_key_does_not_load_backend(self):
        self.set_public_key(IDENTITY_KEY)
        r = subprocess.run([sys.executable, "-S", "-B", str(HERE / "receive_v03.py"),
                            "--package", str(self.package)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        report = json.loads(r.stdout)
        self.assertEqual(report["receiver_checks_status"], "not_assessed")
        self.assertEqual(report["checks"]["seal"]["signature"]["reason"], "small_order_ed25519_public_key")
        self.assertEqual(r.stderr, "")

    def test_normal_keys_of_both_signs_still_verify_and_bind_content(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        observed_signs = set()
        for n in range(12):
            key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"disposable regression {n}".encode()).digest())
            public = key.public_key().public_bytes_raw()
            observed_signs.add(public[-1] >> 7)
            self.edit("identity.json", owner=f"normal synthetic owner {n}")
            def payload():
                return json.dumps({"identity": json.loads((self.package / "identity.json").read_text()),
                                   "manifest": json.loads((self.package / "manifest.json").read_text())},
                                  sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            self.edit("signatures/seal.json", public_key=base64.b64encode(public).decode(),
                      key_id=hashlib.sha256(public).hexdigest(), signature=base64.b64encode(key.sign(payload())).decode())
            self.assertEqual(assess(self.package, public_key=public)["receiver_checks_status"], "matched")
            self.edit("identity.json", owner="changed without new signature")
            self.assertEqual(assess(self.package, public_key=public)["receiver_checks_status"], "mismatched")
        self.assertEqual(observed_signs, {0, 1})

    def test_ed25519_key_restrictions_do_not_change_hmac_key_inputs(self):
        key = bytes(32)
        payload = json.dumps({"identity": json.loads((self.package / "identity.json").read_text()),
                              "manifest": json.loads((self.package / "manifest.json").read_text())},
                             sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        self.edit("signatures/seal.json", algorithm="HMAC-SHA256",
                  key_id=hashlib.sha256(key).hexdigest(), signature=base64.b64encode(hmac.digest(key, payload, "sha256")).decode())
        self.assertEqual(assess(self.package, key=key)["receiver_checks_status"], "matched")

    def test_no_selected_key_keeps_correct_diagnosis(self):
        r = assess(self.package)["checks"]["seal"]
        self.assertEqual(r["selected_key_binding"]["reason"], "receiver_key_not_selected")

    def test_selected_key_and_absent_seal_explained(self):
        for kwargs in ({"public_key": self.normal_pin}, {"key": bytes(32)}):
            with self.subTest(mode=list(kwargs)):
                r = assess(INPUTS / "unsigned", **kwargs)["checks"]["seal"]
                self.assertIsNotNone(r["selected_key_id"])
                self.assertEqual(r["selected_key_binding"], {"status": "not_assessed", "reason": "seal_absent"})

    def test_public_pin_for_hmac_explains_algorithm_mismatch(self):
        r = assess(INPUTS / "hmac-regenerated", public_key=self.normal_pin)
        self.assertEqual(r["receiver_checks_status"], "not_assessed")
        self.assertEqual(r["checks"]["seal"]["selected_key_binding"]["reason"], "public_key_cannot_select_hmac_signer")

    def test_selected_key_and_unsupported_profile_explained(self):
        self.edit("signatures/seal.json", signed="manifest-only")
        r = assess(self.package, public_key=self.normal_pin)["checks"]["seal"]
        self.assertEqual(r["selected_key_binding"], {"status": "not_assessed", "reason": "unsupported_seal_profile"})

    def test_selected_key_and_invalid_recorded_key_explained(self):
        self.edit("signatures/seal.json", public_key="not-base64")
        r = assess(self.package, public_key=self.normal_pin)["checks"]["seal"]
        self.assertEqual(r["selected_key_binding"], {"status": "not_assessed", "reason": "invalid_recorded_public_key"})


if __name__ == "__main__":
    unittest.main()
