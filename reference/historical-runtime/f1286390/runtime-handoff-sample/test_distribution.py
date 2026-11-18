"""Check package completeness, contamination rejection, and isolated relocation."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from check_environment import ROOT, REQUIRED, verify_sources


class DistributionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="vate-handoff-package-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.source = self.work / "extracted source"
        self.source.mkdir()
        for name in REQUIRED | {"SOURCE-MANIFEST.json"}:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes())

    def test_complete_inventory(self):
        self.assertEqual(verify_sources(self.source), len(REQUIRED))

    def test_missing_native_helper(self):
        (self.source / "reference/recipient-inbox/recipient_inbox.py").unlink()
        with self.assertRaises(FileNotFoundError):
            verify_sources(self.source)

    def test_changed_native_helper(self):
        path = self.source / "reference/vate-verifier-core/vate_verifier_core.py"
        path.write_bytes(path.read_bytes() + b"\n# changed\n")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            verify_sources(self.source)

    def test_stale_importable_files(self):
        for name in ("inbox/json.py", "sample/stale.pyc", "reference/stale.so"):
            with self.subTest(name=name):
                path = self.source / name
                path.write_bytes(b"stale")
                try:
                    with self.assertRaisesRegex(ValueError, "unlisted importable"):
                        verify_sources(self.source)
                finally:
                    path.unlink()

    def test_symlinks_rejected(self):
        (self.source / "linked").symlink_to(self.work, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            verify_sources(self.source)

    def test_manifest_shape_is_structured_error(self):
        for value in ([], None, {"format": "vate-local-sample-files-1", "files": []}):
            with self.subTest(value=value):
                (self.source / "SOURCE-MANIFEST.json").write_text(json.dumps(value))
                result = subprocess.run([sys.executable, "-E", "-s", "-B", str(self.source / "check_environment.py"),
                    "--sources-only"], cwd=self.work, capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(json.loads(result.stdout)["status"], "error")
                self.assertNotIn(b"Traceback", result.stderr)

    def test_manifest_inventory_cannot_escape(self):
        path = self.source / "SOURCE-MANIFEST.json"
        value = json.loads(path.read_bytes())
        value["files"]["../outside.py"] = "0" * 64
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "inventory mismatch"):
            verify_sources(self.source)

    def test_relocation_and_pythonpath_isolation(self):
        trap = self.work / "trap"
        trap.mkdir()
        (trap / "demo_contract.py").write_text('raise RuntimeError("outside source imported")\n')
        code = '''import sys,json
from pathlib import Path
root=Path(sys.argv[1]).resolve()
sys.path.insert(0,str(root/'inbox'))
import bridge
import dependencies
assert bridge.ROOT == root
assert dependencies.ROOT == root
assert bridge.SAMPLE == root/'sample'
assert Path(dependencies.demo.__file__).resolve().is_relative_to(root)
assert Path(dependencies.crypto.__file__).resolve().is_relative_to(root)
bridge.check_sample()
print(json.dumps({'status':'ok','root':str(root)}))
'''
        env = dict(os.environ, PYTHONPATH=str(trap), PYTHONHOME=str(trap))
        result = subprocess.run([sys.executable, "-E", "-s", "-B", "-c", code, str(self.source)],
                                cwd=self.work, env=env, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "ok")
        self.assertEqual(verify_sources(self.source), len(REQUIRED))


if __name__ == "__main__":
    unittest.main()
