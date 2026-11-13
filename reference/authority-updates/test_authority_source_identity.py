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
