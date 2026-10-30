"""The example summary reports observations and fails under Python optimization."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
EXPECTED_CONTROLS = {
    "supported": ("verified", "authorized_under_policy", "matched"),
    "whitespace": ("verified", "authorized_under_policy", "matched"),
    "tampered": ("invalid", "not_assessed", "matched"),
    "ungranted-issuer": ("verified", "denied", "matched"),
    "expired-grant": ("verified", "denied", "matched"),
    "missing-proof": ("not_assessed", "not_assessed", "matched"),
    "unknown-key": ("not_assessed", "not_assessed", "matched"),
    "linkage-mismatch": ("verified", "authorized_under_policy", "mismatch"),
}


class TrialSummaryTests(unittest.TestCase):
    def test_every_control_checks_linkage_even_with_optimization(self):
        code = """
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
import json
import sys
import run_trial

expected = json.loads(sys.argv.pop(1))
target = sys.argv.pop(1)
results = []
for name, (signature, authority, linkage) in expected.items():
    if name == target:
        linkage = "mismatch" if linkage == "matched" else "matched"
    results.append({"signatures": {"post_execution": {"status": signature}},
                    "issuer_authority": {"post_execution": {"status": authority}},
                    "receipt_assessment": {"native_result": {"record_linkage": linkage}}})
fixture = SimpleNamespace(
    post=b'{"issuer":{"id":"test"},"admission":{"digest":{"value":"test"}}}',
    policy={"verification_keys": [None, None, None]},
    sign=lambda *args: b"mock-proof",
    assessor=lambda: SimpleNamespace(assess=Mock(side_effect=results)),
)
fixture.arguments = lambda: {"post": fixture.post}
def save(path):
    path.mkdir()
    return {}
fixture.save = save
with patch.object(run_trial, "Fixtures", return_value=fixture):
    run_trial.main()
"""
        environment = dict(os.environ)
        environment.pop("PYTHONOPTIMIZE", None)
        with tempfile.TemporaryDirectory(prefix="vate-jcs-every-linkage-") as directory:
            for mode in ([], ["-O"]):
                for name in EXPECTED_CONTROLS:
                    with self.subTest(mode=mode, name=name):
                        output = Path(directory) / (str(len(mode)) + "-" + name)
                        completed = subprocess.run(
                            [sys.executable, "-B", *mode, "-c", code, json.dumps(EXPECTED_CONTROLS),
                             name, "--output", str(output)],
                            cwd=ROOT, env=environment, capture_output=True, timeout=30)
                        self.assertNotEqual(completed.returncode, 0)
                        self.assertIn((name + ": unexpected receipt_linkage result").encode(), completed.stderr)
                        self.assertFalse((output / "SUMMARY.json").exists())

    def test_unexpected_results_fail_without_success_summary_even_with_optimization(self):
        code = """
from unittest.mock import patch
import sys
import run_trial

field = sys.argv.pop(1)
result = {"signatures": {"post_execution": {"status": "verified"}},
          "issuer_authority": {"post_execution": {"status": "authorized_under_policy"}},
          "receipt_assessment": {"native_result": {"record_linkage": "matched"}}}
if field == "signature":
    result["signatures"]["post_execution"]["status"] = "invalid"
elif field == "issuer_authority":
    result["issuer_authority"]["post_execution"]["status"] = "denied"
else:
    result["receipt_assessment"]["native_result"]["record_linkage"] = "mismatch"
with patch.object(run_trial.Fixtures, "assessor") as make_assessor:
    make_assessor.return_value.assess.return_value = result
    run_trial.main()
"""
        environment = dict(os.environ)
        environment.pop("PYTHONOPTIMIZE", None)
        with tempfile.TemporaryDirectory(prefix="vate-jcs-summary-") as directory:
            for mode in ([], ["-O"]):
                for field in ("signature", "issuer_authority", "receipt_linkage"):
                    with self.subTest(mode=mode, field=field):
                        output = Path(directory) / (str(len(mode)) + "-" + field)
                        completed = subprocess.run(
                            [sys.executable, "-B", *mode, "-c", code, field, "--output", str(output)],
                            cwd=ROOT, env=environment, capture_output=True, timeout=30)
                        self.assertNotEqual(completed.returncode, 0)
                        self.assertIn(("unexpected " + field + " result").encode(), completed.stderr)
                        self.assertFalse((output / "SUMMARY.json").exists())

    def test_success_summary_matches_each_saved_result(self):
        with tempfile.TemporaryDirectory(prefix="vate-jcs-summary-") as directory:
            output = Path(directory) / "run"
            completed = subprocess.run(
                [sys.executable, "-B", str(ROOT / "run_trial.py"), "--output", str(output)],
                capture_output=True, check=True, timeout=30)
            summary = json.loads((output / "SUMMARY.json").read_bytes())
            self.assertEqual(json.loads(completed.stdout), summary)
            self.assertEqual(summary["controls"], {
                name: dict(zip(("signature", "issuer_authority", "receipt_linkage"), values))
                for name, values in EXPECTED_CONTROLS.items()
            })
            for name, observed in summary["controls"].items():
                with self.subTest(name=name):
                    result = json.loads((output / name / "result.json").read_bytes())
                    self.assertEqual(observed, {
                        "signature": result["signatures"]["post_execution"]["status"],
                        "issuer_authority": result["issuer_authority"]["post_execution"]["status"],
                        "receipt_linkage": result["receipt_assessment"]["native_result"]["record_linkage"],
                    })


if __name__ == "__main__":
    unittest.main()
