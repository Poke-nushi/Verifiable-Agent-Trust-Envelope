#!/usr/bin/env python3
"""Tests for the VATE quickstart demo."""

from __future__ import annotations

import subprocess
import sys
import unittest
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO = REPO_ROOT / "reference" / "quickstart-demo" / "run_demo.py"


class QuickstartDemoTest(unittest.TestCase):
    def read_json(self, path: str) -> dict:
        with (REPO_ROOT / path).open(encoding="utf-8") as handle:
            return json.load(handle)

    def run_demo(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(DEMO), *args],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_default_demo_narrates_three_cases_and_claim_boundary(self) -> None:
        attenuate_receipt = self.read_json(
            "examples/receipts/admission-attenuate-max-amount.example.json"
        )
        attenuation = attenuate_receipt["attenuation"]
        result = self.run_demo()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("=== Scene 1/3: allow ===", result.stdout)
        self.assertIn("=== Scene 2/3: attenuate ===", result.stdout)
        self.assertIn("=== Scene 3/3: deny ===", result.stdout)
        self.assertIn("allow-valid-admission", result.stdout)
        self.assertIn("attenuate-max-amount", result.stdout)
        self.assertIn("deny-digest-mismatch-before-policy", result.stdout)
        self.assertIn(attenuation["original_request_hash"], result.stdout)
        self.assertIn(attenuation["effective_request_hash"], result.stdout)
        self.assertIn("This is a discussion draft demo.", result.stdout)
        self.assertLessEqual(len(result.stdout.splitlines()), 80)

    def test_list_outputs_committed_case_ids(self) -> None:
        result = self.run_demo("--list")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("allow-valid-admission", result.stdout)
        self.assertIn("attenuate-max-amount", result.stdout)
        self.assertIn("deny-digest-mismatch-before-policy", result.stdout)

    def test_json_outputs_selected_receipt(self) -> None:
        receipt = self.read_json("examples/receipts/admission-attenuate-max-amount.example.json")
        result = self.run_demo("--case", "attenuate-max-amount", "--json")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'"receipt_id": "{receipt["receipt_id"]}"', result.stdout)
        self.assertIn(f'"outcome": "{receipt["decision"]["outcome"]}"', result.stdout)
        self.assertNotIn("Scene 2/3", result.stdout)

    def test_post_execution_case_shows_post_execution_receipt(self) -> None:
        result = self.run_demo("--case", "post-execution-linkage-success")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("=== Scene 1/1: case ===", result.stdout)
        self.assertIn("post-execution-linkage-success", result.stdout)
        self.assertIn(
            "Artifact shown: post_execution_receipt -> examples/receipts/post-execution-success.example.json",
            result.stdout,
        )
        self.assertNotIn("Artifact shown: admission_receipt ->", result.stdout)
        self.assertIn("Decision      : SUCCESS", result.stdout)
        self.assertNotIn("Receipt       : admission receipt issued before execution", result.stdout)


if __name__ == "__main__":
    unittest.main()
