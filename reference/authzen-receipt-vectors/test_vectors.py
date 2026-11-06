"""Replay, preservation and negative checks for the shared comparison vectors."""
from pathlib import Path
import os
import py_compile
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from vector_contract import ROOT, SAMPLE, CASES, decode, encode, sha, verify, load_reader


class VectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="vate-authzen-vector-test-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)

    def copy_data(self):
        data = self.work / "data"
        data.mkdir()
        shutil.copytree(ROOT / "cases", data / "cases")
        for name in ("MANIFEST.json", "VECTORS.json"):
            shutil.copyfile(ROOT / name, data / name)
        return data

    def rehash(self, data, path):
        manifest = decode((data / "MANIFEST.json").read_bytes())
        raw = (data / path).read_bytes()
        manifest["files"][path] = {"sha256": sha(raw), "bytes": len(raw)}
        (data / "MANIFEST.json").write_bytes(encode(manifest))

    def test_fixed_histories_and_inputs_unchanged(self):
        before = {str(p): sha(p.read_bytes()) for p in (ROOT / "cases").rglob("*") if p.is_file()}
        result = verify()
        self.assertEqual(result["snapshots_replayed"], 17)
        self.assertEqual(len(result["variants"]), 8)
        self.assertFalse(result["is_execution_ticket"])
        after = {str(p): sha(p.read_bytes()) for p in (ROOT / "cases").rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_missing_prior_receipt_is_not_invented(self):
        d = ROOT / "cases/01-lost-response-recovery/without-prior-receipt"
        result = decode((d / "expected-assessments.json").read_bytes())
        self.assertIsNone(result["pending"]["post_execution_receipt"])
        self.assertEqual(result["pending"]["unknown"], [])
        self.assertEqual(result["recovered"]["unknown"], [])
        self.assertEqual(result["recovered"]["post_execution_receipt"]["proof"], {"format": "none"})

    def test_fenced_handoff_is_conditional_not_a_pep_permit(self):
        p = ROOT / "cases/03-confirmed-nonexecution-handoff/fenced-handoff/expected-pep-decision.json"
        decision = decode(p.read_bytes())
        self.assertEqual(decision["phases"]["fenced"]["comparison_expectation"], "conditional_continuation")
        self.assertIn("fresh_pdp_evaluation", decision["phases"]["fenced"]["additional_requirements"])
        self.assertEqual(decision["actual_authzen_pep_execution"], "not_run")

    def test_missing_input_rejected(self):
        data = self.copy_data()
        (data / "cases/01-lost-response-recovery/without-prior-receipt/context.json").unlink()
        with self.assertRaisesRegex(ValueError, "tree inventory"):
            verify(data)

    def test_tampered_original_rejected(self):
        data = self.copy_data()
        path = data / "cases/01-lost-response-recovery/without-prior-receipt/pending-history.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            verify(data)

    def test_cross_case_input_still_rejected_after_rehash(self):
        data = self.copy_data()
        path = "cases/01-lost-response-recovery/without-prior-receipt/context.json"
        other = data / "cases/02-accepted-interrupted/zero-effects/context.json"
        (data / path).write_bytes(other.read_bytes())
        self.rehash(data, path)
        with self.assertRaisesRegex(ValueError, "resource outside selected provider"):
            verify(data)

    def test_modified_expected_receipt_rejected_after_rehash(self):
        data = self.copy_data()
        path = "cases/01-lost-response-recovery/without-prior-receipt/expected-receipts.json"
        receipt = decode((data / path).read_bytes())
        receipt["recovered"]["execution"]["runtime"] = "runtime-b"
        (data / path).write_bytes(encode(receipt))
        self.rehash(data, path)
        with self.assertRaisesRegex(ValueError, "receipt replay mismatch"):
            verify(data)

    def test_replay_cannot_be_relabelled_as_permission(self):
        data = self.copy_data()
        path = "cases/03-confirmed-nonexecution-handoff/fenced-handoff/expected-pep-decision.json"
        result = decode((data / path).read_bytes())
        result["is_execution_ticket"] = True
        (data / path).write_bytes(encode(result))
        self.rehash(data, path)
        with self.assertRaisesRegex(ValueError, "PEP comparison mismatch"):
            verify(data)

    def test_duplicate_json_key_rejected(self):
        data = self.copy_data()
        path = data / "MANIFEST.json"
        path.write_bytes(b'{"format":"wrong",' + path.read_bytes()[1:])
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            verify(data)

    def test_boolean_cannot_be_replaced_with_zero(self):
        data = self.copy_data()
        path = "cases/01-lost-response-recovery/without-prior-receipt/expected-assessments.json"
        result = decode((data / path).read_bytes())
        result["pending"]["is_execution_ticket"] = 0
        (data / path).write_bytes(encode(result))
        self.rehash(data, path)
        with self.assertRaisesRegex(ValueError, "assessment replay mismatch"):
            verify(data)

    def test_symlink_rejected(self):
        data = self.copy_data()
        path = data / "cases/01-lost-response-recovery/without-prior-receipt/context.json"
        raw = path.read_bytes()
        path.unlink()
        target = self.work / "outside.json"
        target.write_bytes(raw)
        path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            verify(data)

    def test_extra_private_file_rejected(self):
        data = self.copy_data()
        (data / "cases/key.pem").write_text("fixture-only unexpected file")
        with self.assertRaisesRegex(ValueError, "tree inventory"):
            verify(data)

    def test_extra_root_file_rejected(self):
        data = self.copy_data()
        (data / "unexpected-key.pem").write_text("fixture-only unexpected file")
        with self.assertRaisesRegex(ValueError, "unexpected fixture root entry"):
            verify(data)

    def test_manifest_file_array_returns_json_error(self):
        data = self.copy_data()
        manifest = decode((data / "MANIFEST.json").read_bytes())
        manifest["files"] = list(manifest["files"])
        (data / "MANIFEST.json").write_bytes(encode(manifest))
        result = subprocess.run([sys.executable, "-E", "-s", "-S", "-B", str(ROOT / "verify.py"),
                                 "--vectors", str(data)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
        self.assertEqual(decode(result.stdout)["status"], "error")
        self.assertEqual(result.stderr, "")

    def test_deeply_nested_manifest_returns_json_error(self):
        data = self.work / "deep-manifest"
        data.mkdir()
        (data / "MANIFEST.json").write_bytes(b"[" * 10000 + b"0" + b"]" * 10000)
        result = subprocess.run([sys.executable, "-E", "-s", "-S", "-B", str(ROOT / "verify.py"),
                                 "--vectors", str(data)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
        response = decode(result.stdout)
        self.assertEqual(response["status"], "error")
        self.assertFalse(response["is_execution_ticket"])
        self.assertTrue(response["reason"])
        self.assertEqual(result.stderr, "")

    def test_deeply_nested_vector_index_returns_json_error(self):
        data = self.copy_data()
        original = (data / "VECTORS.json").read_bytes().rstrip()
        self.assertTrue(original.endswith(b"}"))
        # Parser and encoder depth limits differ across Python versions.
        for depth in (990, 991, 992):
            with self.subTest(depth=depth):
                nested = b"[" * depth + b"0" + b"]" * depth
                (data / "VECTORS.json").write_bytes(original[:-1] + b',"extra":' + nested + b"}")
                self.rehash(data, "VECTORS.json")
                result = subprocess.run([sys.executable, "-E", "-s", "-S", "-B", str(ROOT / "verify.py"),
                                         "--vectors", str(data)], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
                response = decode(result.stdout)
                self.assertEqual(response["status"], "error")
                self.assertFalse(response["is_execution_ticket"])
                self.assertTrue(response["reason"])
                self.assertEqual(result.stderr, "")

    def test_missing_openssl_reports_unavailable(self):
        result = subprocess.run([sys.executable, "-E", "-s", "-S", "-B", str(ROOT / "verify.py")],
                                env={**os.environ, "PATH": ""}, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        self.assertEqual(decode(result.stdout), {"status": "unavailable", "reason": "executable_missing",
                                                "is_execution_ticket": False})
        self.assertEqual(result.stderr, "")

    def test_interaction_changes_rejected_after_rehash(self):
        data = self.copy_data()
        path = "cases/01-lost-response-recovery/without-prior-receipt/interactions.json"
        original = (data / path).read_bytes()
        for change in ("missing", "status", "method", "attempt", "handoff"):
            with self.subTest(change=change):
                calls = decode(original)
                if change == "missing":
                    calls = [calls[-1]]
                elif change == "status":
                    calls[1]["response"] = {"status": "completed"}
                elif change == "method":
                    calls[1]["method"] = "unrelated.submit"
                elif change == "attempt":
                    calls[1]["request"]["attempt_id"] = "unrelated-attempt"
                else:
                    calls[2]["response"]["result"]["is_execution_ticket"] = True
                (data / path).write_bytes(encode(calls))
                self.rehash(data, path)
                with self.assertRaisesRegex(ValueError, "interaction|submit|handoff"):
                    verify(data)

    def test_cached_source_checker_cannot_execute(self):
        sample = self.work / "sample"
        shutil.copytree(SAMPLE, sample)
        source = sample / "check_environment.py"
        marker = self.work / "cached-code-ran"
        substitute = self.work / "substitute.py"
        substitute.write_text("from pathlib import Path\nPath(" + repr(str(marker)) +
                              ").write_text('executed')\ndef verify_sources(root): return 48\n")
        cache = sample / "__pycache__" / ("check_environment." + sys.implementation.cache_tag + ".pyc")
        cache.parent.mkdir(exist_ok=True)
        py_compile.compile(str(substitute), cfile=str(cache), doraise=True,
                           invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
        raw = cache.read_bytes()
        info = source.stat()
        cache.write_bytes(raw[:8] + struct.pack("<II", int(info.st_mtime) & 0xffffffff, info.st_size) + raw[16:])
        result = subprocess.run([sys.executable, "-E", "-s", "-S", "-B", str(ROOT / "verify.py"),
                                 "--sample", str(sample)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
        self.assertIn("unlisted importable file", decode(result.stdout)["reason"])
        self.assertFalse(marker.exists(), "timestamp-valid cached code executed before source verification")

    def test_source_changes_rejected_before_import(self):
        sample = self.work / "sample"
        shutil.copytree(SAMPLE, sample)
        with (sample / "sample/handoff_reader.py").open("a") as stream:
            stream.write("\nraise RuntimeError('untrusted modified source')\n")
        with self.assertRaisesRegex(ValueError, "source mismatch"):
            load_reader(sample)

    def test_relocated_cli_with_optimization(self):
        destination = self.work / "relocated"
        shutil.copytree(ROOT, destination / ROOT.name)
        shutil.copytree(SAMPLE, destination / SAMPLE.name)
        result = subprocess.run([sys.executable, "-E", "-s", "-S", "-B", "-O",
                                 str(destination / ROOT.name / "verify.py")],
                                cwd=self.work, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(decode(result.stdout)["status"], "matched")

    def test_fresh_capture(self):
        data = self.work / "new-capture"
        result = subprocess.run([sys.executable, "-E", "-s", "-S", "-B", str(ROOT / "capture.py"), "--out", str(data)],
                                capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(verify(data)["snapshots_replayed"], 17)
        self.assertNotEqual((data / "MANIFEST.json").read_bytes(), (ROOT / "MANIFEST.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
