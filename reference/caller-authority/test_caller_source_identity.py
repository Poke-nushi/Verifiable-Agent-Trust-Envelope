"""Stale timestamp-valid bytecode must not acquire a fresh authority identity."""
import json
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest

import caller_jwt as c

CHILD = '''import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / "reference/caller-authority"))
import test_caller_authority as fixtures
fixtures.CallerAuthorityTests.setUpClass()
f = fixtures.CallerAuthorityTests()
try:
    f.setUp()
    f.admit()
    code = None
except Exception as exc:
    code = getattr(exc, "cause", getattr(exc, "code", type(exc).__name__))
finally:
    f.doCleanups()
print(json.dumps({"cause": code, "digests": [fixtures.c.LOADED_SOURCE_SHA256,
    fixtures.c.jwt.LOADED_SOURCE_SHA256, fixtures.a.LOADED_SOURCE_SHA256]}))
'''

RELOAD_CHILD = '''import importlib, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / "reference/caller-authority"))
import test_caller_authority as fixtures
c = fixtures.c
fixtures.CallerAuthorityTests.setUpClass()
f = fixtures.CallerAuthorityTests(); f.setUp()
try:
    old_class, old_backend = c.CallerJwtAuthorizer, f.authorizer.backend
    old_grant = dict(vars(f.grant))
    module = c if sys.argv[2] == "caller" else c.jwt
    source = Path(module.__file__)
    # A changed version must not lend its digest to a retained old class or
    # backend, even when the old implementation's validation would succeed.
    source.write_bytes(source.read_bytes() + b"\\n# New local source version.\\n")
    importlib.invalidate_caches(); importlib.reload(module)
    f.policy = c.AuthorityPolicy(f.policy.issued_at, f.policy.expires_at, (c.DelegationGrant(**old_grant),))
    options = dict(expected_profile=c.PROFILE, authority_id=f.authorizer.authority_id,
        node=f.f.node, node_sha256=f.f.node_sha, authority_policy_provider=lambda:f.policy,
        max_token_age_seconds=40, max_policy_age_seconds=30)
    current = c.CallerJwtAuthorizer(**options)
    current.verify(f.proof, f.context())
    outcomes = []
    if sys.argv[2] == "caller":
        probes = (lambda: old_class(**options), lambda: f.authorizer.as_caller_authorizer(),
                  lambda: f.authorizer.verify(f.proof, f.context()))
    else:
        current.backend = old_backend
        probes = (lambda: current.as_caller_authorizer(), lambda: current.verify(f.proof, f.context()))
    for probe in probes:
        try:
            probe(); outcomes.append("accepted")
        except Exception as exc:
            outcomes.append(getattr(exc, "code", type(exc).__name__))
    print(json.dumps({"current":"accepted", "retained":outcomes, "calls":len(f.calls)}))
finally:
    f.doCleanups()
'''


class CallerSourceIdentityTests(unittest.TestCase):
    def copy_sources(self, root):
        for directory in ("request-binding", "vate-verifier-core", "runtime-jwt", "caller-authority"):
            target = root / "reference" / directory
            target.mkdir(parents=True)
            for source in (c.ROOT / "reference" / directory).iterdir():
                if source.suffix in (".py", ".mjs"):
                    shutil.copyfile(source, target / source.name)

    def test_stale_loaded_sources_rejected_in_normal_and_optimized_interpreters(self):
        changes = (("reference/caller-authority/caller_jwt.py", b"len(policy.grants) <= 128", b"len(policy.grants) <= 129", 0),
            ("reference/runtime-jwt/runtime_jwt.py", b"MAX_TOKEN_BYTES = 64 *", b"MAX_TOKEN_BYTES = 65 *", 1),
            ("reference/request-binding/caller_authority.py", b"2**31 - 1", b"2**31 - 2", 2))
        for optimize in (0, 1):
            for name, old, new, index in changes:
                with self.subTest(module=name, optimize=optimize), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.copy_sources(root)
                    path = root / name
                    before, stat = path.read_bytes(), path.stat()
                    self.assertEqual(before.count(old), 1)
                    py_compile.compile(str(path), doraise=True, optimize=optimize,
                        invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
                    path.write_bytes(before.replace(old, new))
                    self.assertEqual(len(before), path.stat().st_size)
                    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
                    completed = subprocess.run([sys.executable, *(["-O"] if optimize else []), "-B", "-c",
                        CHILD, str(root)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    result = json.loads(completed.stdout)
                    self.assertIsNone(result["digests"][index])
                    self.assertEqual(result["cause"], "STATE_IMPLEMENTATION_CHANGED" if index == 2
                                     else "CALLER_IMPLEMENTATION_CHANGED")

    def test_reload_does_not_relabel_retained_caller_or_backend(self):
        for optimize in (0, 1):
            for mode in ("caller", "backend"):
                with self.subTest(optimize=optimize, mode=mode), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.copy_sources(root)
                    completed = subprocess.run([sys.executable, *(["-O"] if optimize else []), "-B", "-c",
                        RELOAD_CHILD, str(root), mode], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, timeout=30)
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    result = json.loads(completed.stdout)
                    self.assertEqual(result["current"], "accepted")
                    self.assertEqual(result["retained"], ["CALLER_IMPLEMENTATION_CHANGED"] * (3 if mode == "caller" else 2))
                    self.assertEqual(result["calls"], 0)

    def test_unstamped_authorizer_subclass_is_rejected(self):
        import test_caller_authority as fixtures
        fixtures.CallerAuthorityTests.setUpClass()
        fixture = fixtures.CallerAuthorityTests(); fixture.setUp()
        try:
            class Unstamped(c.CallerJwtAuthorizer):
                pass
            with self.assertRaisesRegex(c.jwt.RuntimeJwtError, "CALLER_IMPLEMENTATION_CHANGED"):
                Unstamped(expected_profile=c.PROFILE, authority_id="urn:example:authority",
                    node=fixture.f.node, node_sha256=fixture.f.node_sha,
                    authority_policy_provider=lambda: fixture.policy,
                    max_token_age_seconds=40, max_policy_age_seconds=30)
        finally:
            fixture.doCleanups()


if __name__ == "__main__":
    unittest.main()
