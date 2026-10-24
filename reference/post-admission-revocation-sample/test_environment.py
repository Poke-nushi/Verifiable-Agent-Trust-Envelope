from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from check_environment import ROOT, REQUIRED, verify_sources


class EnvironmentChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vate-env-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "sample with spaces"
        shutil.copytree(ROOT, self.root, ignore=shutil.ignore_patterns("__pycache__", ".venv"))

    def test_complete_and_moved_bundle(self):
        self.assertEqual(verify_sources(self.root), len(REQUIRED))

    def test_missing_changed_or_symlinked_source(self):
        path = self.root / "sample/provider.py"
        raw = path.read_bytes()
        path.unlink()
        with self.assertRaises(OSError):
            verify_sources(self.root)
        path.write_bytes(raw + b"\n# altered\n")
        with self.assertRaises(ValueError):
            verify_sources(self.root)
        path.unlink()
        path.symlink_to(ROOT / "sample/provider.py")
        with self.assertRaises(ValueError):
            verify_sources(self.root)

    def test_source_directory_symlink_rejected(self):
        shutil.rmtree(self.root / "sample")
        (self.root / "sample").symlink_to(ROOT / "sample", target_is_directory=True)
        with self.assertRaises(ValueError):
            verify_sources(self.root)

    def test_manifest_inventory_and_shape(self):
        path = self.root / "SOURCE-MANIFEST.json"
        good = json.loads(path.read_text())
        for altered in (None, [], {}, {**good, "files": {}},
                        {**good, "files": {**good["files"], "../outside": "0" * 64}}):
            with self.subTest(altered=altered):
                path.write_text(json.dumps(altered))
                with self.assertRaises(ValueError):
                    verify_sources(self.root)

    def test_demo_from_a_source_directory_alias(self):
        alias = Path(self.temp.name) / "source alias"
        alias.symlink_to(self.root, target_is_directory=True)
        output = Path(self.temp.name) / "new run"
        process = subprocess.run([sys.executable, "-E", "-s", "-B", str(alias / "sample/run_demo.py"),
                                  "run", "--scenario", "active", "--out", str(output)],
                                 cwd=self.temp.name, capture_output=True, text=True, timeout=90)
        self.assertEqual(process.returncode, 0, process.stderr)
        summary = json.loads((output / "SUMMARY.json").read_text())
        self.assertEqual(len(summary["source_sha256"]), 10)
        self.assertEqual(summary["results"][0]["outcome"], "effect_observed")
        self.assertTrue(summary["test_keys_deleted"])

    def test_stale_importable_files_rejected(self):
        for name in ("reference/execution-evidence-demo/provider.py", "sample/old.pyc",
                     "sample/old.so", "sample/old/__init__.py", "__pycache__/check_environment.cpython-314.pyc"):
            with self.subTest(name=name):
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"stale test data")
                with self.assertRaises(ValueError):
                    verify_sources(self.root)
                path.unlink()
        (self.root / "operator-notes.txt").write_text("Non-importable notes are not source files.\n")
        self.assertEqual(verify_sources(self.root), len(REQUIRED))

    def test_crash_worker_ignores_external_python_home(self):
        env = {**os.environ, "PYTHONHOME": str(Path(self.temp.name) / "nonexistent-python-home")}
        process = subprocess.run([sys.executable, "-E", "-s", "-B", str(self.root / "sample/test_revocation.py"),
                                  "IntegratedChecks.test_process_exit_releases_worker_and_recovers_actual_sqlite_boundary"],
                                 cwd=self.temp.name, env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn("Ran 1 test", process.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
