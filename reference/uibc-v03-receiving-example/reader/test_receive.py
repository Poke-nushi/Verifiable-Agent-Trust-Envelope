import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import receive
from receive import InputError, assess, load_key
import run_examples

HERE = Path(__file__).resolve().parent


class ReceivingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.package = self.root / "clean.uibc"
        shutil.copytree(HERE / "samples/regenerated/clean.uibc", self.package)
        self.key_path = self.root / "test-key.hex"
        shutil.copyfile(HERE / "samples/regenerated/DISPOSABLE-TEST-KEY.hex", self.key_path)
        self.key = load_key(self.key_path, self.package)

    def tearDown(self):
        self.temp.cleanup()

    def edit(self, relative, edit):
        path = self.package / relative
        data = json.loads(path.read_text())
        edit(data)
        path.write_text(json.dumps(data))

    def statuses(self, package=None, key=None):
        return {k: v["status"] for k, v in assess(package or self.package, key=key)["checks"].items()}

    def assert_input_error(self, reason):
        with self.assertRaises(InputError) as raised:
            assess(self.package, key=self.key)
        self.assertEqual(raised.exception.code, reason)

    def test_regenerated_strict_control(self):
        self.assertEqual(self.statuses(key=self.key),
                         dict(evidence_files="matched", evidence_root="matched", seal="matched"))

    def test_absent_key_is_not_assessed_even_for_clean(self):
        report = assess(self.package)
        self.assertEqual(report["checks_status"], "not_assessed")
        self.assertEqual(report["checks"]["seal"]["reason"], "verification_key_missing")

    def test_tampering_does_not_invalidate_unchanged_seal(self):
        (self.package / "evidence/files/action-log.txt").write_bytes(b"changed content\n")
        self.assertEqual(self.statuses(key=self.key),
                         dict(evidence_files="mismatched", evidence_root="not_assessed", seal="matched"))

    def test_wrong_key_does_not_invalidate_content_checks(self):
        self.assertEqual(self.statuses(key=b"x" * 32),
                         dict(evidence_files="matched", evidence_root="matched", seal="mismatched"))

    def test_changed_identity_invalidates_seal(self):
        self.edit("identity.json", lambda d: d.update(owner="different-owner"))
        self.assertEqual(self.statuses(key=self.key)["seal"], "mismatched")

    def test_changed_manifest_invalidates_root_and_seal(self):
        self.edit("manifest.json", lambda d: d.update(evidence_root="0" * 64))
        self.assertEqual(self.statuses(key=self.key),
                         dict(evidence_files="matched", evidence_root="mismatched", seal="mismatched"))

    def test_unknown_algorithm_not_assessed(self):
        self.edit("signatures/seal.json", lambda d: d.update(algorithm="other"))
        self.assertEqual(self.statuses(key=self.key)["seal"], "not_assessed")

    def test_wrong_signed_scope_not_assessed(self):
        self.edit("signatures/seal.json", lambda d: d.update(signed="identity"))
        self.assertEqual(self.statuses(key=self.key)["seal"], "not_assessed")

    def test_bad_base64_is_mismatch(self):
        for value in ("!!!", "", None, {}, "é"):
            with self.subTest(value=value):
                self.edit("signatures/seal.json", lambda d: d.update(signature=value))
                self.assertEqual(self.statuses(key=self.key)["seal"], "mismatched")

    def test_missing_seal_has_separate_key_conditions(self):
        (self.package / "signatures/seal.json").unlink()
        self.assertEqual(self.statuses()["seal"], "not_assessed")
        self.assertEqual(self.statuses(key=self.key)["seal"], "mismatched")

    def test_missing_evidence_is_mismatch(self):
        (self.package / "evidence/files/action-log.txt").unlink()
        report = assess(self.package, key=self.key)
        self.assertEqual(report["checks"]["evidence_files"]["entries"][0]["reason"], "missing_evidence_file")
        self.assertEqual(report["checks"]["seal"]["status"], "matched")

    def test_unknown_evidence_type(self):
        self.edit("evidence/index.json", lambda d: d["entries"][0].update(type="NEW_TYPE"))
        self.assertEqual(self.statuses(key=self.key)["evidence_files"], "mismatched")

    def test_empty_evidence_is_not_complete(self):
        self.edit("evidence/index.json", lambda d: d.update(entries=[]))
        self.assertEqual(assess(self.package, key=self.key)["checks_status"], "not_assessed")

    def test_unexamined_lifecycle_never_claimed_as_verified(self):
        (self.package / "lifecycle.json").write_bytes(b"invalid lifecycle")
        report = assess(self.package, key=self.key)
        self.assertEqual(report["checks_status"], "matched")
        self.assertIn("lifecycle_transitions_and_event_signatures", report["not_assessed"])
        self.assertIn("execution_admission", report["not_assessed"])
        self.assertNotIn("decision", report)
        self.assertNotIn("result", report)

    def test_original_published_clean_has_lf_mismatch(self):
        original = HERE / "samples/published/clean.uibc"
        report = assess(original)
        self.assertEqual(report["checks_status"], "mismatched")
        for entry in report["checks"]["evidence_files"]["entries"]:
            raw = (original / "evidence" / entry["path"]).read_bytes()
            self.assertNotEqual(hashlib.sha256(raw).hexdigest(), entry["declared_sha256"])
            self.assertEqual(hashlib.sha256(raw.replace(b"\n", b"\r\n")).hexdigest(),
                             entry["declared_sha256"])

    def test_no_input_mutation_and_deterministic_report(self):
        def snapshot():
            return {str(p): p.read_bytes() for p in self.package.rglob("*") if p.is_file()}
        before = snapshot()
        first = assess(self.package, key=self.key)
        self.assertEqual(first, assess(self.package, key=self.key))
        self.assertEqual(snapshot(), before)
        self.assertNotIn(self.key.hex(), json.dumps(first))

    def test_saved_native_comparison(self):
        report = run_examples.run()
        self.assertEqual(len(report["cases"]), 6)
        self.assertTrue(all(all(r["selected_check_agreement"].values()) for r in report["cases"]))

    def test_path_escape_rejected(self):
        for path in ("../identity.json", "/etc/passwd", "files//a", "files/./a",
                     "files/../a", "files\\a", "https://example.com/a", "", None):
            with self.subTest(path=path):
                self.edit("evidence/index.json", lambda d: d["entries"][0].update(path=path))
                self.assert_input_error("unsafe_relative_path")

    def test_symlink_file_rejected(self):
        target = self.package / "evidence/files/action-log.txt"
        target.unlink()
        target.symlink_to(self.key_path)
        self.assert_input_error("unreadable_or_linked_file")

    def test_symlink_directory_rejected(self):
        target = self.package / "evidence/files"
        shutil.rmtree(target)
        target.symlink_to(self.root, target_is_directory=True)
        self.assert_input_error("unreadable_or_linked_file")

    def test_root_symlink_rejected(self):
        path = self.root / "linked"
        path.symlink_to(self.package, target_is_directory=True)
        with self.assertRaises(InputError):
            assess(path)

    def test_package_with_invalid_path_is_a_structured_error(self):
        with self.assertRaises(InputError) as raised:
            assess("invalid\0package")
        self.assertEqual(raised.exception.code, "invalid_package_directory")
        self.assertEqual(raised.exception.input_name, "package")

    def test_fifo_rejected_without_blocking(self):
        path = self.package / "evidence/files/action-log.txt"
        path.unlink()
        os.mkfifo(path)
        self.assert_input_error("not_regular_file")

    def test_duplicate_json_names_rejected(self):
        (self.package / "identity.json").write_bytes(b'{"x":1,"x":2}')
        self.assert_input_error("duplicate_json_key")

    def test_invalid_json_values_rejected(self):
        for value in (b'{"x": NaN}', b'{"x": 1.5}', b'{"x":9007199254740992}',
                      b'{"x":"\\ud800"}', b'[]', b'{"x":"\xff"}'):
            with self.subTest(value=value):
                (self.package / "identity.json").write_bytes(value)
                with self.assertRaises(InputError):
                    assess(self.package)

    def test_depth_limit(self):
        (self.package / "identity.json").write_bytes(b'{"x":' + b'[' * 40 + b'0' + b']' * 40 + b'}')
        self.assert_input_error("json_depth_limit")

    def test_schema_mismatch(self):
        self.edit("manifest.json", lambda d: d.update(schema="uibc-core/future"))
        self.assert_input_error("unsupported_package_schema")

    def test_entry_limit(self):
        self.edit("evidence/index.json", lambda d: d.update(entries=[copy.deepcopy(d["entries"][0])] * 129))
        self.assert_input_error("invalid_evidence_entries")

    def test_invalid_index_shape(self):
        for entries in (None, {}, [None]):
            with self.subTest(entries=entries):
                self.edit("evidence/index.json", lambda d: d.update(entries=entries))
                with self.assertRaises(InputError):
                    assess(self.package)

    def test_file_size_limit(self):
        (self.package / "evidence/files/action-log.txt").write_bytes(b"x" * (receive.MAX_FILE_BYTES + 1))
        self.assert_input_error("file_size_limit")

    def test_aggregate_size_limit(self):
        with patch.object(receive, "MAX_TOTAL_BYTES", 300):
            self.assert_input_error("total_size_limit")

    def test_invalid_digest(self):
        self.edit("evidence/index.json", lambda d: d["entries"][0].update(content_hash="xyz"))
        self.assert_input_error("invalid_sha256")

    def test_missing_metadata_is_input_error(self):
        (self.package / "manifest.json").unlink()
        self.assert_input_error("missing_input")

    def test_internal_key_file_rejected(self):
        internal = self.package / "test.key"
        internal.write_bytes(self.key_path.read_bytes())
        with self.assertRaises(InputError) as raised:
            load_key(internal, self.package)
        self.assertEqual(raised.exception.code, "key_must_be_outside_package")

    def test_invalid_key_sizes(self):
        for key in (b"", b"x" * 31, b"x" * 33, "x" * 32):
            with self.subTest(key_type=type(key).__name__, size=len(key)):
                with self.assertRaises(InputError):
                    assess(self.package, key=key)

    def test_malformed_hex_key_rejected(self):
        self.key_path.write_text("z" * 64)
        with self.assertRaises(InputError):
            load_key(self.key_path, self.package)

    def test_key_symlink_loop_is_a_structured_error(self):
        loop = self.root / "loop"
        loop.symlink_to(loop)
        with self.assertRaises(InputError) as raised:
            load_key(loop, self.package)
        self.assertEqual(raised.exception.code, "unreadable_key")

    def test_key_with_invalid_path_is_a_structured_error(self):
        with self.assertRaises(InputError) as raised:
            load_key(Path("invalid\0path"), self.package)
        self.assertEqual(raised.exception.code, "unreadable_key")

    def test_key_with_trailing_data_is_rejected(self):
        self.key_path.write_text(self.key.hex() + "\ntrailing")
        with self.assertRaises(InputError) as raised:
            load_key(self.key_path, self.package)
        self.assertEqual(raised.exception.code, "expected_64_hex_test_key")

    def test_cli_emitted_report_is_not_an_allow_exit_code(self):
        result = subprocess.run([sys.executable, "-S", "-B", str(HERE / "receive.py"),
                                 "--package", str(self.package)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["checks_status"], "not_assessed")

    def test_cli_input_error_has_no_contents_or_paths(self):
        secret_marker = "private-input-should-not-be-printed"
        (self.package / "identity.json").write_text(secret_marker)
        result = subprocess.run([sys.executable, "-S", "-B", str(HERE / "receive.py"),
                                 "--package", str(self.package)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 64)
        self.assertEqual(json.loads(result.stdout)["reason"], "invalid_json")
        self.assertNotIn(secret_marker, result.stdout + result.stderr)
        self.assertNotIn(str(self.root), result.stdout + result.stderr)

    def test_cli_package_loop_with_key_is_a_structured_error(self):
        loop = self.root / "package-loop"
        loop.symlink_to(loop, target_is_directory=True)
        completed = subprocess.run(
            [sys.executable, "-S", "-B", str(HERE / "receive.py"),
             "--package", str(loop), "--key", str(self.key_path)],
            capture_output=True, text=True)
        self.assertEqual(completed.returncode, 64)
        self.assertEqual(json.loads(completed.stdout)["checks_status"], "invalid_input")
        self.assertEqual(completed.stderr, "")
        self.assertNotIn(str(self.root), completed.stdout)


if __name__ == "__main__":
    unittest.main()
