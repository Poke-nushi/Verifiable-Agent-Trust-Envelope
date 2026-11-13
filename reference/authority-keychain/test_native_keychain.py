"""Real OS Keychain and fresh publisher processes, using only disposable local fixtures."""
import base64
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest

import keychain_signer as k

HERE = Path(__file__).resolve().parent


@unittest.skipUnless(sys.platform == "darwin", "native Keychain tests require macOS")
class NativeKeychainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="vate-keychain-build-")
        cls.addClassCleanup(cls.build.cleanup)
        cls.helper = Path(cls.build.name).resolve() / "keychain-bridge"
        cls.admin = cls.helper.with_name("fixture-admin")
        for source, target in (("keychain_bridge.swift", cls.helper), ("fixture_keychain_admin.swift", cls.admin)):
            compiled = subprocess.run(["/usr/bin/swiftc", str(HERE / source), "-o", str(target)],
                                      capture_output=True, timeout=60)
            if compiled.returncode:
                raise RuntimeError("Keychain fixture compilation failed: " + compiled.stderr.decode())
        cls.helper_sha = k.jwt.file_sha(cls.helper)
        cls.node = Path(shutil.which("node")).resolve(strict=True)
        cls.node_sha = k.jwt.file_sha(cls.node)

    def admin_call(self, action, *, password=None, tag=None):
        command = [str(self.admin), action, str(self.keychain)]
        if tag is not None:
            command.append(tag)
        result = subprocess.run(command, input=password, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, "disposable Keychain operation failed: " + action)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vate-keychain-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.keychain = self.root / "fixture.keychain-db"
        self.password = secrets.token_hex(32).encode("ascii")
        self.addCleanup(self.delete_keychain)
        self.admin_call("create", password=self.password)
        self.provisioned = self.bridge("provision", "selected-key")
        self.public = base64.b64decode(self.provisioned["public_key_spki_base64"], validate=True)
        self.selection = k.s.AuthoritySelection("issuer", "audience", "scope", "epoch", "key", self.public, 1, 30)
        self.header = {"alg": "ES256", "typ": k.s.TOKEN_TYPE, "kid": "key"}
        self.claims = {"iss": "issuer", "aud": "audience", "scope": "scope", "epoch": "epoch", "revision": 1,
                       "iat": 100, "nbf": 100, "exp": 120, "runtime_grants": [], "delegation_grants": []}

    def delete_keychain(self):
        if self.keychain.exists():
            self.admin_call("delete")
            self.assertFalse(self.keychain.exists())

    def bridge(self, action, tag, *, succeeds=True):
        result = subprocess.run([str(self.helper), action, str(self.keychain), tag],
                                capture_output=True, timeout=10)
        if not succeeds:
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b"")
            self.assertEqual(result.stderr, b"KEYCHAIN_BRIDGE_FAILED\n")
            return None
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"")
        return json.loads(result.stdout)

    def signer(self, **overrides):
        args = dict(expected_profile=k.PROFILE, helper=self.helper, helper_sha256=self.helper_sha,
                    keychain=self.keychain, application_tag="selected-key", selection=self.selection)
        args.update(overrides)
        return k.KeychainSigner(**args)

    def verified_token(self):
        raw = self.signer()(self.header, self.claims)
        verifier = k.s.SnapshotVerifier(expected_profile=k.s.PROFILE, selection=self.selection,
                                       node=self.node, node_sha256=self.node_sha)
        verifier.verify(raw, k.jwt.numeric_date(101))
        return raw

    def test_native_signatures_verified_independently_by_node(self):
        self.assertEqual(len(self.public), 91)
        self.assertTrue(self.public.startswith(k.jwt.SPKI_PREFIX))
        self.assertIs(self.provisioned["private_key_extractable"], False)
        first, second = self.verified_token(), self.verified_token()
        self.assertEqual(first.split(b".")[:2], second.split(b".")[:2])
        self.assertEqual(self.provisioned, self.bridge("public-key", "selected-key"))

    def test_locked_key_fails_and_explicit_fixture_unlock_recovers_same_key(self):
        before = self.bridge("public-key", "selected-key")
        self.admin_call("lock")
        with self.assertRaisesRegex(k.s.AuthorityError, "^KEYCHAIN_SIGNER_FAILED$"):
            self.signer()(self.header, self.claims)
        self.bridge("public-key", "selected-key", succeeds=False)
        self.admin_call("unlock", password=self.password)
        self.assertEqual(before, self.bridge("public-key", "selected-key"))
        self.verified_token()

    def test_absent_tag_is_not_created(self):
        with self.assertRaisesRegex(k.s.AuthorityError, "^KEYCHAIN_SIGNER_FAILED$"):
            self.signer(application_tag="missing-key")(self.header, self.claims)
        self.bridge("public-key", "missing-key", succeeds=False)
        self.verified_token()

    def test_different_key_cannot_satisfy_selected_public_key(self):
        other = self.bridge("provision", "other-key")
        self.assertNotEqual(other["public_key_spki_base64"], self.provisioned["public_key_spki_base64"])
        with self.assertRaisesRegex(k.s.AuthorityError, "^KEYCHAIN_SIGNER_FAILED$"):
            self.signer(application_tag="other-key")(self.header, self.claims)

    def test_explicit_provisioning_never_replaces_existing_key(self):
        self.bridge("provision", "selected-key", succeeds=False)
        self.assertEqual(self.provisioned, self.bridge("public-key", "selected-key"))
        self.verified_token()

    def test_extractable_key_is_rejected_even_with_matching_tag(self):
        self.admin_call("add-extractable", tag="extractable-key")
        self.bridge("public-key", "extractable-key", succeeds=False)
        with self.assertRaisesRegex(k.s.AuthorityError, "^KEYCHAIN_SIGNER_FAILED$"):
            self.signer(application_tag="extractable-key")(self.header, self.claims)

    def test_ambiguous_tag_is_rejected(self):
        # Two keys match the tag. The issuer must not choose whichever is returned first.
        self.admin_call("add-extractable", tag="selected-key")
        self.bridge("public-key", "selected-key", succeeds=False)
        with self.assertRaisesRegex(k.s.AuthorityError, "^KEYCHAIN_SIGNER_FAILED$"):
            self.signer()(self.header, self.claims)

    def test_deleted_keychain_is_not_recreated(self):
        signer = self.signer()
        self.delete_keychain()
        with self.assertRaisesRegex(k.s.AuthorityError, "^KEYCHAIN_SIGNER_UNAVAILABLE$"):
            signer(self.header, self.claims)
        self.assertFalse(self.keychain.exists())

    def test_fresh_publishers_keep_revision_revocation_and_failure_state(self):
        config_path = self.root / "publisher.json"
        config = {"helper": str(self.helper), "helper_sha256": self.helper_sha,
            "keychain": str(self.keychain), "application_tag": "selected-key",
            "node": str(self.node), "node_sha256": self.node_sha, "store": str(self.root / "issuer"),
            "public_key_spki_base64": self.provisioned["public_key_spki_base64"]}
        config_path.write_text(json.dumps(config)); config_path.chmod(0o600)
        second = int((k.b.core.parse_time("2026-11-14T00:00:00Z") - k.jwt.EPOCH).total_seconds())
        observations = []
        def run(mode, offset):
            completed = subprocess.run([sys.executable, "-B", str(HERE / "fixture_publish.py"),
                str(config_path), mode, str(second + offset)], capture_output=True, timeout=20)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertFalse(completed.stderr)
            value = json.loads(completed.stdout)
            self.assertEqual(value["public_key_sha256"], hashlib.sha256(self.public).hexdigest())
            observations.append(value)
            return value
        initial = run("create", 0)
        self.assertTrue(initial["published"])
        self.assertEqual((initial["status"]["revision"], initial["delegation_count"]), (1, 1))
        denied = run("deny", 1)
        self.assertTrue(denied["published"])
        self.assertEqual((denied["status"]["revision"], denied["delegation_count"]), (2, 0))
        reopened = run("inspect", 2)
        self.assertEqual((reopened["status"]["revision"], reopened["delegation_count"]), (2, 0))
        repeated = run("deny", 3)
        self.assertEqual((repeated["status"]["revision"], repeated["delegation_count"]), (3, 0))
        self.admin_call("lock")
        failed = run("deny", 4)
        self.assertFalse(failed["published"])
        self.assertEqual(failed["cause"], "ISSUER_PUBLICATION_FAILED")
        self.assertEqual(failed["status"]["revision"], 3)
        self.assertTrue(failed["status"]["unavailable"])
        self.assertNotIn("token_base64", failed)
        self.assertTrue(run("inspect", 5)["status"]["unavailable"])
        self.admin_call("unlock", password=self.password)
        recovered = run("permit", 6)
        self.assertTrue(recovered["published"])
        self.assertEqual((recovered["status"]["revision"], recovered["delegation_count"]), (4, 1))
        self.assertEqual(len({value["pid"] for value in observations}), len(observations))
        # A reopened ledger still rejects an old signed snapshot; restarting never resets it.
        from fixture_publish import context
        from authority_store import AuthorityStore
        _, _, _, _, verifier, _, now = context(config, second + 7, True)
        store = AuthorityStore(config["store"], verifier=verifier, clock=lambda: now,
            expected_anchor=config_path.with_name("issuer-anchor.json").read_bytes())
        with self.assertRaisesRegex(k.s.AuthorityError, "ROLLBACK"):
            store.accept(base64.b64decode(initial["token_base64"]))
        self.assertEqual(store.status()["revision"], 4)


if __name__ == "__main__":
    unittest.main()
