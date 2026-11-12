"""Saved example assessments preserve JSON types during CLI verification."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import example
from request_binding import decode, digest, encode


class SavedAssessmentTests(unittest.TestCase):
    def check_saved(self, files, saved):
        files = dict(files)
        files["assessment.json"] = saved
        manifest = decode(files["manifest.json"])
        manifest["artifacts"]["assessment.json"] = digest(saved)
        files["manifest.json"] = encode(manifest)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name, raw in files.items():
                (root / name).write_bytes(raw)
            return subprocess.run(
                [sys.executable, str(example.HERE / "example.py"), "check", "--bundle", str(root),
                 "--expected-admission-request", str(root / "admission-request.json")],
                capture_output=True, text=True, timeout=15,
            )

    def test_cli_rejects_numeric_saved_boolean_with_updated_digest(self):
        files = example.generate()
        for path in (("pass",), ("binding_requirement_met",),
                     ("decision_allows_immediate_execution",), ("checks", 0, "pass")):
            with self.subTest(path=path):
                assessment = decode(files["assessment.json"])
                target = assessment
                for key in path[:-1]:
                    target = target[key]
                self.assertIs(target[path[-1]], True)
                target[path[-1]] = 1
                result = self.check_saved(files, encode(assessment))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(result.stderr.strip(), "SAVED_ASSESSMENT_MISMATCH")
                self.assertEqual(result.stdout, "")

    def test_cli_accepts_equivalent_reformatted_saved_assessment(self):
        files = example.generate()
        assessment = decode(files["assessment.json"])
        reordered = dict(reversed(list(assessment.items())))
        saved = (json.dumps(reordered, indent=2, ensure_ascii=False) + "\n").encode()
        self.assertNotEqual(saved, files["assessment.json"])
        result = self.check_saved(files, saved)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertIs(report["generation_reproduced"], True)
        self.assertEqual(encode(report["request_binding"]), files["assessment.json"])


if __name__ == "__main__":
    unittest.main()
