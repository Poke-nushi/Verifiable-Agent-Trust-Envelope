"""Regression checks for saved capture integrity and source-only SDK imports."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from receive import encoded, sha
from run_sdk_examples import CASES, checked_capture_manifest
from sdk.capture_sdk import snapshot_source

HERE = Path(__file__).resolve().parent


class CaptureReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.copy = Path(self.temp.name) / "capture"
        shutil.copytree(HERE / "captures/first", self.copy)

    def tearDown(self):
        self.temp.cleanup()

    def mutate_manifest(self, change):
        p = self.copy / "CAPTURE-MANIFEST.json"
        value = json.loads(p.read_bytes())
        change(value)
        p.write_bytes(encoded(value))

    def test_saved_first_and_second_inventories(self):
        self.assertEqual(len(checked_capture_manifest(self.copy, CASES)["cases"]), 4)
        self.assertEqual(len(checked_capture_manifest(HERE / "captures/second", (CASES[2],))["cases"]), 1)

    def test_changed_trace_is_rejected(self):
        p = self.copy / CASES[0] / "TRACE.json"
        value = json.loads(p.read_bytes())
        value["events"] = []
        p.write_bytes(encoded(value))
        with self.assertRaisesRegex(RuntimeError, "saved capture file changed"):
            checked_capture_manifest(self.copy, CASES)

    def test_changed_request_plan_and_raw_returns_are_rejected(self):
        for name in ("request.json", "receiver-plan.json", "native-tool-results.json"):
            with self.subTest(name=name):
                p = self.copy / CASES[0] / name
                raw = p.read_bytes()
                p.write_bytes(raw + b" ")
                with self.assertRaisesRegex(RuntimeError, "saved capture file changed"):
                    checked_capture_manifest(self.copy, CASES)
                p.write_bytes(raw)

    def test_duplicate_case_is_rejected(self):
        self.mutate_manifest(lambda m: m["cases"].append(m["cases"][0]))
        with self.assertRaisesRegex(RuntimeError, "unexpected or repeated"):
            checked_capture_manifest(self.copy, CASES)

    def test_missing_file_inventory_is_rejected(self):
        self.mutate_manifest(lambda m: m["files"].pop(CASES[0] + "/TRACE.json"))
        with self.assertRaisesRegex(RuntimeError, "inventory mismatch"):
            checked_capture_manifest(self.copy, CASES)

    def test_harness_change_is_visible(self):
        self.mutate_manifest(lambda m: m.update(capture_script_sha256="0" * 64))
        with self.assertRaisesRegex(RuntimeError, "harness differs"):
            checked_capture_manifest(self.copy, CASES)

    def test_wrong_sdk_module_hash_is_rejected(self):
        self.mutate_manifest(lambda m: m["imported_sdk_modules"][0].update(sha256="0" * 64))
        with self.assertRaisesRegex(RuntimeError, "SDK module differs"):
            checked_capture_manifest(self.copy, CASES)


class SourceSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.target = self.root / "snapshot"
        self.source.mkdir()
        self.target.mkdir()
        self.raw = b"value = 1\n"
        (self.source / "module.py").write_bytes(self.raw)
        self.pins = {"files": [{"path": "module.py", "bytes": len(self.raw), "sha256": sha(self.raw)}]}

    def tearDown(self):
        self.temp.cleanup()

    def test_only_verified_source_is_copied(self):
        (self.source / "module.pyc").write_bytes(b"stale bytecode")
        (self.source / "unlisted.py").write_bytes(b"raise RuntimeError()")
        snapshot_source(self.source, self.target, self.pins)
        self.assertEqual([p.name for p in self.target.iterdir()], ["module.py"])
        self.assertEqual((self.target / "module.py").read_bytes(), self.raw)

    def test_changed_source_is_rejected(self):
        (self.source / "module.py").write_bytes(b"value = 2\n")
        with self.assertRaisesRegex(RuntimeError, "SDK source changed"):
            snapshot_source(self.source, self.target, self.pins)
        self.assertFalse((self.target / "module.py").exists())

    def test_source_inventory_cannot_escape_snapshot(self):
        self.pins["files"][0]["path"] = "../module.py"
        with self.assertRaisesRegex(RuntimeError, "invalid SDK source inventory"):
            snapshot_source(self.source, self.target, self.pins)


if __name__ == "__main__":
    unittest.main()
