"""Distribution and historical-replay boundaries; no network or real credentials."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "reference/runtime-support"))
from historical import historical_root, historical_api
from synthetic_s3 import synthetic_current_instance
from run_trial import generate


class DistributionTests(unittest.TestCase):
    def test_historical_manifest_is_checked_before_loading(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            frozen = root / "reference/historical-runtime/e845a6a8"
            shutil.copytree(historical_root(ROOT), frozen)
            path = frozen / "reference/receipt-linkage-example/recipient_example.py"
            path.write_bytes(path.read_bytes() + b"\n# changed\n")
            with self.assertRaisesRegex(ValueError, "historical source changed"):
                historical_api(root)

    def test_historical_manifest_edit_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            frozen = root / "reference/historical-runtime/e845a6a8"
            shutil.copytree(historical_root(ROOT), frozen)
            path = frozen / "MANIFEST.json"
            path.write_bytes(path.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "historical manifest changed"):
                historical_api(root)

    def test_historical_member_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            frozen = root / "reference/historical-runtime/e845a6a8"
            shutil.copytree(historical_root(ROOT), frozen)
            path = frozen / "reference/receipt-linkage-example/SOURCE-PINS.json"
            saved = root / "original-pins.json"
            saved.write_bytes(path.read_bytes())
            path.unlink()
            path.symlink_to(saved)
            with self.assertRaisesRegex(ValueError, "must not use symlinks"):
                historical_api(root)

    def test_historical_api_does_not_load_stale_bytecode(self):
        import os
        import py_compile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            frozen = root / "reference/historical-runtime/e845a6a8"
            shutil.copytree(historical_root(ROOT), frozen)
            path = frozen / "reference/recipient-assessment/vate_recipient.py"
            original = path.read_bytes()
            bad = b'raise RuntimeError("stale historical code")\n'
            path.write_bytes(bad + b" " * (len(original) - len(bad)))
            os.utime(path, (1700000000, 1700000000))
            py_compile.compile(str(path), doraise=True, invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
            path.write_bytes(original)
            os.utime(path, (1700000000, 1700000000))
            api, selected = historical_api(root)
            self.assertEqual(selected, frozen.resolve())
            self.assertEqual(api.API_CONTRACT, "vate-recipient-assessment-api-v1")

    def test_synthetic_derivative_preserves_raw_capture_members(self):
        original = ROOT / "reference/s3-observation-example/inputs/seaweedfs-4.48/instance"
        with tempfile.TemporaryDirectory() as directory:
            target = synthetic_current_instance(ROOT, Path(directory) / "instance")
            provenance = json.loads((target / "SYNTHETIC-PROVENANCE.json").read_bytes())
            for name, expected in provenance["original_files_sha256"].items():
                self.assertEqual(hashlib.sha256((original / name).read_bytes()).hexdigest(), expected)
                if Path(name).name not in ("sources.json", "manifest.json", "receiver-policy.json"):
                    self.assertEqual((original / name).read_bytes(), (target / name).read_bytes())
            with self.assertRaisesRegex(ValueError, "must be new"):
                synthetic_current_instance(ROOT, target)

    def test_generator_checks_openssl_before_running_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "not-executable"
            binary.write_bytes(b"must not execute")
            with patch("run_trial.signature_fixture") as signing:
                with self.assertRaisesRegex(ValueError, "expected SHA-256"):
                    generate(root / "output", binary, "0" * 64)
                signing.assert_not_called()
            self.assertFalse((root / "output").exists())

    def test_generator_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "prior-report"
            marker.write_bytes(b"unchanged")
            with patch("run_trial.signature_fixture") as signing:
                with self.assertRaisesRegex(ValueError, "new directory"):
                    generate(root, "/not/an/executable", "0" * 64)
                signing.assert_not_called()
            self.assertEqual(marker.read_bytes(), b"unchanged")

    def test_cli_can_initialize_from_unrelated_working_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = subprocess.run([sys.executable, "-B", str(HERE / "recipient_inbox.py"),
                "--db", str(root / "inbox.sqlite3"), "--source-root", str(ROOT), "init"],
                cwd=root, capture_output=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((root / "inbox.sqlite3").is_file())


if __name__ == "__main__":
    unittest.main()
