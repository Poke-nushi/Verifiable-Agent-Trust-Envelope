"""Check package completeness, contamination rejection, and isolated relocation."""
from pathlib import Path
from decimal import localcontext
import importlib.util
import hashlib
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

    def test_upstream_provenance_must_match_selected_bytes(self):
        path = self.source / "UPSTREAM-SOURCES.json"
        upstream = json.loads(path.read_bytes())
        upstream["patched_files"]["scripts/vate_conformance.py"]["sha256"] = "0" * 64
        path.write_text(json.dumps(upstream))
        manifest_path = self.source / "SOURCE-MANIFEST.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["files"]["UPSTREAM-SOURCES.json"] = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "patched upstream source mismatch"):
            verify_sources(self.source)

    def test_same_count_source_replacement_cannot_hide_helper_drift(self):
        path = self.source / "UPSTREAM-SOURCES.json"
        upstream = json.loads(path.read_bytes())
        name = "reference/minimal-al2-demo/trust_envelope_demo.py"
        count = len(upstream["unchanged_files"]) + len(upstream["patched_files"])
        for section in ("unchanged_files", "patched_files"):
            upstream[section].pop(name, None)
        upstream["unchanged_files"]["LICENSE"] = hashlib.sha256((self.source / "LICENSE").read_bytes()).hexdigest()
        self.assertEqual(len(upstream["unchanged_files"]) + len(upstream["patched_files"]), count)
        path.write_text(json.dumps(upstream))
        helper = self.source / name
        helper.write_bytes(helper.read_bytes() + b"\n# Unlisted shared helper drift.\n")
        manifest_path = self.source / "SOURCE-MANIFEST.json"
        manifest = json.loads(manifest_path.read_bytes())
        for changed in ("UPSTREAM-SOURCES.json", name):
            manifest["files"][changed] = hashlib.sha256((self.source / changed).read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "invalid upstream provenance"):
            verify_sources(self.source)

    def test_original_upstream_commit_and_hashes_are_fixed(self):
        path = self.source / "UPSTREAM-SOURCES.json"
        original = path.read_bytes()
        manifest_path = self.source / "SOURCE-MANIFEST.json"
        for mutation, error in (("commit", "invalid upstream provenance"), ("hash", "patched upstream source mismatch")):
            with self.subTest(mutation=mutation):
                upstream = json.loads(original)
                if mutation == "commit":
                    upstream["upstream_commit"] = "0" * 40
                else:
                    upstream["patched_files"]["scripts/vate_conformance.py"]["upstream_sha256"] = "0" * 64
                path.write_text(json.dumps(upstream))
                manifest = json.loads(manifest_path.read_bytes())
                manifest["files"]["UPSTREAM-SOURCES.json"] = hashlib.sha256(path.read_bytes()).hexdigest()
                manifest_path.write_text(json.dumps(manifest))
                with self.assertRaisesRegex(ValueError, error):
                    verify_sources(self.source)

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


class BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("handoff_runner_boundary", ROOT / "scripts/vate_conformance.py")
        cls.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.runner)

    def test_json_number_precision_and_type_preserving_paths(self):
        runner = self.runner
        for text in ("25.0", "25.000000000000000000", "0.1", "2.5e1"):
            self.assertEqual(runner.strict_json_loads(text), json.loads(text))
        for text in ("25.000000000000000001", "1e-400", "9007199254740993.0"):
            with self.assertRaisesRegex(ValueError, "loses decimal precision"):
                runner.strict_json_loads(text)
        check = {"kind": "path_match", "admission_path": "x", "post_execution_path": "x"}
        for left, right, matched in [(False, False, True), (False, 0, False), (True, 1, False),
                                      ({"v": [True]}, {"v": [1]}, False), (1, 1.0, True)]:
            with self.subTest(left=left, right=right):
                self.assertEqual(runner.linkage_check_violation({}, check, {"x": left}, {"x": right}), (not matched, None))
                self.assertEqual(not runner.semantic_projection_failures({"x": left}, {"x": right}, "value"), matched)

    def test_current_core_binding_dependencies_are_present(self):
        spec = importlib.util.spec_from_file_location("handoff_current_core", ROOT / "reference/vate-verifier-core/vate_verifier_core.py")
        core = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(core)
        verifier = core.VateVerifier(verifier_id="urn:test:handoff")
        with self.assertRaisesRegex(ValueError, "SCHEMA_INVALID"):
            verifier.admit(b"{}", original=b"{}")
        module = core.request_binding_module()
        self.assertTrue(Path(module.__file__).resolve().is_relative_to(ROOT))
        self.assertTrue(Path(module.durable_state_module().__file__).resolve().is_relative_to(ROOT))
        self.assertTrue(Path(module.caller_authority_module().__file__).resolve().is_relative_to(ROOT))
        operation = {"preimage_profile": module.PREIMAGE_PROFILE, "operation_id": "sample-api-test",
            "action": "commerce.purchase", "target": {"resource": "urn:test:order", "audience": "urn:test:runtime"},
            "payload": {"tool": "checkout", "order_id": "test-order", "amount": {"currency": "USD", "value": "24.50"}},
            "constraints": {"max_amount": {"currency": "USD", "value": "120.00"}, "tool_allowlist": ["checkout"]}}
        policy = {"policy_id": "test", "policy_version": "1", "policy_ref": "urn:test:policy",
            "allowed_actions": ["commerce.purchase"], "max_amount": {"currency": "USD", "value": "25.00"}}
        request = {"version": core.VERSION, "profile": core.PROFILE, "request_id": "test-request",
            "transaction_id": operation["operation_id"], "issued_at": "2026-11-17T00:00:00Z", "expires_at": "2026-11-17T00:05:00Z",
            "action": operation["action"], "target": operation["target"], "actor": "urn:test:actor", "principal": "urn:test:owner",
            "runtime": "urn:test:runtime", "audience": "urn:test:runtime", "input_hash": module.object_hash(operation),
            "constraints": operation["constraints"], "evidence_refs": [{"type": "local_policy", "uri": "urn:test:policy",
                "media_type": "application/json", "digest": module.digest(module.encode(policy))}]}
        bound = core.VateVerifier(verifier_id="urn:test:verifier", policy=policy).admit(
            module.encode(request), original=module.encode(operation), now=core.parse_time("2026-11-17T00:00:01Z"))
        self.assertEqual(json.loads(bound.receipt)["decision"]["outcome"], "attenuate")
        self.assertEqual(json.loads(bound.effective)["constraints"]["max_amount"]["value"], "25.00")

    def test_amount_aggregation_ignores_ambient_precision(self):
        admission = {"decision": {"outcome": "allow"}, "request": {"constraints": {
            "max_amount": {"currency": "USD", "value": "25.00"}}}}
        for precision in (3, 28):
            with localcontext() as context:
                context.prec = precision
                for amounts, valid in [(["25.00"], True), (["24.99", "0.01"], True),
                                      (["25.00", "0.000000000000000000000000001"], False), (["24.99", "0.02"], False)]:
                    post = {"result": {"side_effects": [{"type": "payment_authorization", "amount": {
                        "currency": "USD", "value": value}} for value in amounts]}}
                    self.assertEqual(not list(self.runner.iter_post_execution_side_effect_failures(admission, post)), valid)

    def test_descriptor_annotations_preserve_digest_checks(self):
        digest = {"alg": "sha-256", "value": "a" * 64}
        self.assertTrue(self.runner.digest_descriptors_match({**digest, "x_note": "annotation"}, digest))
        self.assertFalse(self.runner.digest_descriptors_match({**digest, "value": "b" * 64}, digest))
        self.assertFalse(self.runner.digest_descriptors_match({**digest, "value": "a" * 64 + "\n"}, digest))

    def test_schema_tokens_reject_trailing_line_breaks(self):
        from jsonschema import Draft202012Validator
        for name in ("admission-receipt", "admission-request", "post-execution-receipt"):
            defs = json.loads((ROOT / "schemas" / (name + ".schema.json")).read_bytes())["$defs"]
            cases = [(defs["digestDescriptor"]["properties"]["value"], "a" * 64),
                     (defs["profileHash"], "sha-256:" + "a" * 64)]
            if "moneyAmount" in defs:
                cases += [(defs["moneyAmount"]["properties"]["currency"], "USD"),
                          (defs["moneyAmount"]["properties"]["value"], "25.00")]
            for schema, value in cases:
                validator = Draft202012Validator(schema)
                self.assertTrue(validator.is_valid(value))
                for suffix in ("\n", "\r\n", " ", "\t"):
                    self.assertFalse(validator.is_valid(value + suffix), (name, value, suffix))


if __name__ == "__main__":
    unittest.main()
