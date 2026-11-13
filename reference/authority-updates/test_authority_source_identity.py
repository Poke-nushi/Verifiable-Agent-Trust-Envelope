"""Copied local sources: retained classes and stale bytecode cannot gain new identities."""
import json
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest

import snapshot as s

UNAVAILABLE_SOURCE = '''import json, shutil, sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root / "reference/authority-updates"))
read_bytes = Path.read_bytes
names = {"snapshot.py", "authority_store.py", "managed_verifier.py", "caller_jwt.py",
    "runtime_jwt.py", "caller_authority.py", "request_binding.py", "durable_state.py", "vate_verifier_core.py"}
def unavailable(path):
    if path.name in names:
        if sys.argv[2] == "read": raise PermissionError("local source fixture")
        return bytes([0])
    return read_bytes(path)
Path.read_bytes = unavailable
import managed_verifier as m
modules = (m, m.s, m.store_module, m.c, m.jwt, m.b, m.b.core,
    m.b.caller_authority_module(), m.b.durable_state_module())
try:
    m.s.module_identity(m.s)
    cause = None
except m.s.AuthorityError as exc:
    cause = exc.cause
node = Path(shutil.which("node")).resolve()
# Public P-256 key from the existing RFC 7515 Appendix A.3 fixture.
key = m.jwt.SPKI_PREFIX + m.jwt.decode_segment(b"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", 32) + \\
    m.jwt.decode_segment(b"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0", 32)
selection = m.s.AuthoritySelection("urn:example:authority", "urn:example:verifier", "purchase",
    "epoch-1", "key", key, 1, 30)
try:
    m.s.SnapshotVerifier(expected_profile=m.s.PROFILE, selection=selection,
        node=node, node_sha256=m.jwt.file_sha(node))
    constructor = None
except m.s.AuthorityError as exc:
    constructor = exc.cause
print(json.dumps({"digests":[module.LOADED_SOURCE_SHA256 for module in modules],
    "cause":cause, "constructor":constructor}))
'''

CHILD = '''import importlib, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / "reference/authority-updates"))
import test_authority_updates as fmod
import authority_store as st
import managed_verifier as mv
s = fmod.s
fmod.AuthorityUpdateTests.setUpClass()
f = fmod.AuthorityUpdateTests()
try:
    f.setUp()
    raw, = f.setup_source()
    f.source.accept(raw)
    print(json.dumps({"cause": None, "loaded": [s.LOADED_SOURCE_SHA256, st.LOADED_SOURCE_SHA256, mv.LOADED_SOURCE_SHA256]}))
except Exception as exc:
    print(json.dumps({"cause":getattr(exc,"cause",type(exc).__name__), "loaded":[s.LOADED_SOURCE_SHA256, st.LOADED_SOURCE_SHA256, mv.LOADED_SOURCE_SHA256]}))
finally: f.doCleanups()
'''

RELOAD = '''import importlib, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / "reference/authority-updates"))
import test_authority_updates as fmod
import authority_store as st
import managed_verifier as mv
s = fmod.s
fmod.AuthorityUpdateTests.setUpClass()
f = fmod.AuthorityUpdateTests(); f.setUp()
try:
    raw, = f.setup_source(); f.source.accept(raw)
    mode = sys.argv[2]
    module, name, old = {"snapshot":(s,"SnapshotVerifier", f.source.verifier),
        "store":(st,"AuthorityStore",f.source), "managed":(mv,"ManagedAuthorityVerifier",f.managed)}[mode]
    old_class = type(old)
    path = Path(module.__file__); path.write_bytes(path.read_bytes()+b"\\n# New local source version.\\n")
    importlib.invalidate_caches(); importlib.reload(module)
    options = dict(expected_profile=s.PROFILE, selection=s.AuthoritySelection(**vars(f.selection)),
        node=f.f.f.node, node_sha256=f.f.f.node_sha)
    verifier = s.SnapshotVerifier(**options)
    store_options = dict(verifier=verifier, expected_anchor=f.source.anchor, clock=lambda:f.now)
    source = st.AuthorityStore(f.directory, **store_options)
    managed_options = dict(source=source, verifier_id=f.f.f.verifier.verifier_id, policy=f.f.f.policy,
        state_store=f.f.store, execute=lambda *args:f.calls.append(args),
        max_runtime_token_age_seconds=60, max_caller_token_age_seconds=40)
    current = mv.ManagedAuthorityVerifier(**managed_options)
    f.managed=current; f.admit()
    if mode == "snapshot": probes=(lambda:old.configuration_id(), lambda:old_class(**options))
    elif mode == "store": probes=(lambda:old.status(), lambda:old_class(f.directory, **store_options))
    else: probes=(lambda:old._check(), lambda:old_class(**managed_options))
    outcomes=[]
    for probe in probes:
        try: probe(); outcomes.append("accepted")
        except Exception as exc: outcomes.append(getattr(exc,"cause",type(exc).__name__))
    print(json.dumps({"current":"accepted", "retained":outcomes, "calls":len(f.calls)}))
finally: f.doCleanups()
'''


class AuthoritySourceIdentityTests(unittest.TestCase):
    def test_source_read_or_compile_failure_keeps_imports_available_without_identity(self):
        for mode in ("read", "compile"):
            for optimize in (0, 1):
                with self.subTest(mode=mode, optimize=optimize):
                    completed = subprocess.run([sys.executable, *(["-O"] if optimize else []), "-B", "-c",
                        UNAVAILABLE_SOURCE, str(s.ROOT), mode], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, timeout=35)
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    result = json.loads(completed.stdout)
                    self.assertEqual(result["digests"], [None] * 9)
                    self.assertEqual(result["cause"], "AUTHORITY_IMPLEMENTATION_CHANGED")
                    self.assertEqual(result["constructor"], "AUTHORITY_IMPLEMENTATION_CHANGED")

    def copy_sources(self, root):
        for directory in ("request-binding", "vate-verifier-core", "runtime-jwt", "caller-authority", "authority-updates"):
            target = root / "reference" / directory; target.mkdir(parents=True)
            for source in (s.ROOT / "reference" / directory).iterdir():
                if source.suffix in (".py", ".mjs"): shutil.copyfile(source, target / source.name)

    def test_stale_bytecode_rejected_in_normal_and_optimized_python(self):
        changes = (("snapshot.py", b"MAX_REVISION = 2**53 - 1", b"MAX_REVISION = 2**53 - 2"),
            ("authority_store.py", b"APPLICATION_ID = 1447121990", b"APPLICATION_ID = 1447121991"),
            ("managed_verifier.py", b'"managed_source"', b'"managed_sourcz"'))
        for optimize in (0, 1):
            for index, (name, before, after) in enumerate(changes):
                with self.subTest(name=name, optimize=optimize), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp); self.copy_sources(root); path=root/"reference/authority-updates"/name
                    raw, stat = path.read_bytes(), path.stat(); self.assertEqual(raw.count(before), 1)
                    py_compile.compile(str(path), doraise=True, optimize=optimize,
                        invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
                    path.write_bytes(raw.replace(before,after)); self.assertEqual(path.stat().st_size, len(raw))
                    os.utime(path, ns=(stat.st_atime_ns,stat.st_mtime_ns))
                    result = self.child(CHILD, root, optimize)
                    self.assertIsNone(result["loaded"][index])
                    self.assertEqual(result["cause"], "AUTHORITY_IMPLEMENTATION_CHANGED")

    def child(self, code, root, optimize, *args):
        result = subprocess.run([sys.executable,*(["-O"] if optimize else []),"-B","-c",code,str(root),*args],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=35)
        self.assertEqual(result.returncode,0,result.stderr)
        return json.loads(result.stdout)

    def test_reload_does_not_relabel_retained_classes_or_instances(self):
        for optimize in (0, 1):
            for mode in ("snapshot", "store", "managed"):
                with self.subTest(mode=mode,optimize=optimize),tempfile.TemporaryDirectory() as tmp:
                    root=Path(tmp); self.copy_sources(root)
                    result=self.child(RELOAD,root,optimize,mode)
                    self.assertEqual(result["current"],"accepted")
                    self.assertEqual(result["retained"],["AUTHORITY_IMPLEMENTATION_CHANGED"]*2)
                    self.assertEqual(result["calls"],0)


if __name__ == "__main__":
    unittest.main()
