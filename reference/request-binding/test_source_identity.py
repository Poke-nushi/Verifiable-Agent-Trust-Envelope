"""Executed-source identity checks on private copies; no installed cache edits."""
import hashlib
import json
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest

import request_binding as b


CHILD = '''import builtins, json, sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root / "reference/request-binding"))
if sys.argv[2] in ("ordinary", "mixed"):
    sys.path.insert(0, str(root / "reference/vate-verifier-core"))
    import vate_verifier_core as ordinary_core
    if sys.argv[2] == "mixed":
        file = Path(ordinary_core.__file__)
        file.write_bytes(file.read_bytes().replace(b"MAX_AMOUNT_TEXT_LENGTH = 64", b"MAX_AMOUNT_TEXT_LENGTH = 65"))
if sys.argv[2] == "no_frame":
    # Model the optional identity check's unsupported-interpreter branch,
    # without removing sys support from unrelated standard-library imports.
    class SystemWithoutFrame:
        def __getattr__(self, name):
            if name == "_getframe":
                raise AttributeError(name)
            return getattr(sys, name)
    original_import = builtins.__import__
    def import_without_frame(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "sys" and (globals or {}).get("__name__") in (
                "request_binding", "request_binding_vate_core", "durable_state"):
            return SystemWithoutFrame()
        return original_import(name, globals, locals, fromlist, level)
    builtins.__import__ = import_without_frame
import request_binding as b
import test_runtime_evidence as fixtures
s = b.durable_state_module()
f = fixtures.RuntimeEvidenceTests(); f.setUp()
without_store = b.decode(f.admit().assessment)["decision_allows_immediate_execution"]
f.verifier = f.new_verifier()
if sys.argv[2] in ("ordinary", "mixed"):
    f.verifier = ordinary_core.VateVerifier(verifier_id=f.verifier.verifier_id,
        policy=f.policy, runtime_evidence_verifier=f.adapter)
store = s.DurableStateStore.create(root / "state", scope="private identity fixture", verifier_id=f.verifier.verifier_id)
calls=[]
f.verifier.state_store=store
f.verifier.dispatch_boundary=b.DispatchBoundary(execute=lambda *args:calls.append(args),clock=lambda:f.now)
try:
    f.verifier.dispatch(f.admit())
    cause=None
except b.Invalid as exc:
    cause=exc.cause
try:
    state=f.verifier.dispatch_status(f.request["request_id"]).state
except b.Invalid as exc:
    state=exc.cause
print(json.dumps({"digests":[b.LOADED_SOURCE_SHA256,b.core.LOADED_SOURCE_SHA256,s.LOADED_SOURCE_SHA256],
    "cause":cause,"state":state,"calls":len(calls),"without_store":without_store}))
'''


class SourceIdentityTests(unittest.TestCase):
    files = ("reference/request-binding/request_binding.py",
             "reference/request-binding/durable_state.py",
             "reference/request-binding/example.py",
             "reference/request-binding/test_runtime_evidence.py",
             "reference/vate-verifier-core/vate_verifier_core.py")

    def copy_sources(self, directory):
        for name in self.files:
            target = directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(b.ROOT / name, target)

    def child(self, directory, *, optimize, mode="cache"):
        completed = subprocess.run([sys.executable, *(["-O"] if optimize else []), "-B", "-c", CHILD,
            str(directory), mode], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(completed.stdout)

    def test_current_sources_identify_loaded_modules(self):
        for module in (b, b.core, b.durable_state_module()):
            self.assertEqual(module.LOADED_SOURCE_SHA256, hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest())

    def test_stale_timestamp_cache_is_rejected_for_each_module(self):
        changes = ((self.files[0], b"MAX_DEPTH = 64", b"MAX_DEPTH = 65", 0),
                   (self.files[-1], b"MAX_AMOUNT_TEXT_LENGTH = 64", b"MAX_AMOUNT_TEXT_LENGTH = 65", 1),
                   (self.files[1], b"MAX_BYTES = 2 *", b"MAX_BYTES = 3 *", 2))
        for optimize in (0, 1):
            for name, old, new, index in changes:
                with self.subTest(module=name, optimize=optimize), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.copy_sources(root)
                    file = root / name
                    original = file.read_bytes()
                    stat = file.stat()
                    self.assertEqual(original.count(old), 1)
                    py_compile.compile(str(file), doraise=True, optimize=optimize,
                        invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
                    updated = original.replace(old, new)
                    self.assertEqual(len(original), len(updated))
                    file.write_bytes(updated)
                    os.utime(file, ns=(stat.st_atime_ns, stat.st_mtime_ns))
                    result = self.child(root, optimize=optimize)
                    self.assertIsNone(result["digests"][index])
                    self.assertEqual(result["cause"], "STATE_IMPLEMENTATION_CHANGED")
                    self.assertEqual(result["state"], "STATE_ADMISSION_NOT_FOUND")
                    self.assertEqual(result["calls"], 0)
                    self.assertTrue(result["without_store"])

    def test_unsupported_frame_check_blocks_only_durable_entry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_sources(root)
            result = self.child(root, optimize=0, mode="no_frame")
            self.assertEqual(result["digests"], [None, None, None])
            self.assertEqual(result["cause"], "STATE_IMPLEMENTATION_CHANGED")
            self.assertEqual(result["state"], "STATE_ADMISSION_NOT_FOUND")
            self.assertEqual(result["calls"], 0)
            self.assertTrue(result["without_store"])

    def test_ordinary_core_entry_accepts_same_source_and_rejects_mixed_versions(self):
        for optimize in (0, 1):
            for mode in ("ordinary", "mixed"):
                with self.subTest(optimize=optimize, mode=mode), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.copy_sources(root)
                    result = self.child(root, optimize=optimize, mode=mode)
                    if mode == "ordinary":
                        self.assertIsNone(result["cause"])
                        self.assertEqual(result["state"], "callback_returned")
                        self.assertEqual(result["calls"], 1)
                    else:
                        self.assertEqual(result["cause"], "STATE_IMPLEMENTATION_CHANGED")
                        self.assertEqual(result["state"], "STATE_ADMISSION_NOT_FOUND")
                        self.assertEqual(result["calls"], 0)


if __name__ == "__main__":
    unittest.main()
