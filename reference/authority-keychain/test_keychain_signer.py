"""Portable wrapper failure tests; no real Keychain or private keys."""
import base64
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import keychain_signer as k

# SEC 2's public P-256 base point, used only for wrapper shape validation.
PUBLIC = k.jwt.SPKI_PREFIX + bytes.fromhex(
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")


class SignerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.helper, self.keychain = self.root / "helper", self.root / "keychain"
        self.helper.write_text("#!/bin/sh\nexit 1\n"); self.helper.chmod(0o700)
        self.keychain.write_bytes(b"fixture, not a Keychain"); self.keychain.chmod(0o600)
        self.selection = k.s.AuthoritySelection("issuer", "audience", "scope", "epoch", "key", PUBLIC, 1, 30)
        self.header = {"alg": "ES256", "typ": k.s.TOKEN_TYPE, "kid": "key"}
        self.claims = {"iss": "issuer", "aud": "audience", "scope": "scope", "epoch": "epoch",
            "revision": 1, "iat": 100, "nbf": 100, "exp": 120, "runtime_grants": [], "delegation_grants": []}
        platform = patch.object(k.sys, "platform", "darwin"); platform.start(); self.addCleanup(platform.stop)

    def signer(self, **overrides):
        args = dict(expected_profile=k.PROFILE, helper=self.helper, helper_sha256=k.jwt.file_sha(self.helper),
                    keychain=self.keychain, application_tag="selected", selection=self.selection)
        args.update(overrides)
        return k.KeychainSigner(**args)

    def script(self, body):
        self.helper.write_text(f"#!{sys.executable}\n" + body + "\n")

    def response(self, request, **updates):
        result = {"contract": k.BRIDGE, "request_sha256": hashlib.sha256(request).hexdigest(),
                  "signature_base64": base64.b64encode(b"s" * 64).decode()}
        result.update(updates)
        return k.b.encode(result)

    def test_only_selected_authority_context_reaches_helper(self):
        signer = self.signer()
        changes = [("alg", "none"), ("typ", "JWT"), ("kid", "other"), ("extra", "x")]
        for field, value in changes:
            with self.subTest(field=field), patch.object(signer, "_process") as process:
                with self.assertRaisesRegex(k.s.AuthorityError, "CONTEXT_MISMATCH"):
                    signer({**self.header, field: value}, self.claims)
                process.assert_not_called()
        for field in ("iss", "aud", "scope", "epoch"):
            with self.subTest(field=field), patch.object(signer, "_process") as process:
                with self.assertRaisesRegex(k.s.AuthorityError, "CONTEXT_MISMATCH"):
                    signer(self.header, {**self.claims, field: "other"})
                process.assert_not_called()

    def test_response_binds_exact_request_and_preserves_signed_payload(self):
        signer = self.signer()
        with patch.object(signer, "_process", side_effect=self.response) as process:
            token = signer(self.header, self.claims)
        request = k.b.decode(process.call_args.args[0])
        self.assertEqual(request["keychain_path"], str(self.keychain))
        self.assertEqual(request["application_tag"], "selected")
        self.assertEqual(base64.b64decode(request["expected_public_key_spki_base64"]), PUBLIC)
        self.assertEqual(k.jwt.decode_segment(token.split(b".")[1], 65536), k.b.encode(self.claims))
        self.assertEqual(base64.b64decode(request["signing_input_base64"]), b".".join(token.split(b".")[:2]))

    def test_stale_or_invalid_bridge_output_is_rejected(self):
        signer = self.signer()
        responses = [lambda raw: self.response(raw, request_sha256="0" * 64),
            lambda raw: self.response(raw, contract="other"),
            lambda raw: self.response(raw, signature_base64="bad"),
            lambda raw: self.response(raw, signature_base64=base64.b64encode(b"x" * 63).decode()),
            lambda raw: self.response(raw, extra=True), lambda raw: b"[]", lambda raw: b"private error text"]
        for response in responses:
            with self.subTest(response=response), patch.object(signer, "_process", side_effect=response):
                with self.assertRaisesRegex(k.s.AuthorityError, "^KEYCHAIN_SIGNER_FAILED$"):
                    signer(self.header, self.claims)

    def test_helper_replacement_and_keychain_disappearance_stop_signing(self):
        signer = self.signer()
        self.helper.write_text("#!/bin/sh\nexit 0\n")
        with self.assertRaisesRegex(k.s.AuthorityError, "HELPER_CHANGED"):
            signer(self.header, self.claims)
        signer = self.signer()
        self.keychain.unlink()
        with self.assertRaisesRegex(k.s.AuthorityError, "UNAVAILABLE"):
            signer(self.header, self.claims)
        self.assertFalse(self.keychain.exists())

    def test_helper_changed_during_signing_discards_output(self):
        signer = self.signer()
        def changed(raw):
            self.helper.write_text("replacement")
            return self.response(raw)
        with patch.object(signer, "_process", side_effect=changed):
            with self.assertRaisesRegex(k.s.AuthorityError, "HELPER_CHANGED"):
                signer(self.header, self.claims)

    def test_unsafe_files_and_invalid_configuration_are_rejected(self):
        for options in ({"expected_profile": "other"}, {"timeout_seconds": True},
                {"timeout_seconds": float("nan")}, {"timeout_seconds": 0}, {"timeout_seconds": 11},
                {"helper_sha256": "bad"}, {"application_tag": "a\n"}, {"helper": "relative"},
                {"selection": replace(self.selection, public_key_spki=b"bad")}):
            with self.subTest(options=options), self.assertRaises(k.s.AuthorityError):
                self.signer(**options)
        self.keychain.chmod(0o644)
        with self.assertRaisesRegex(k.s.AuthorityError, "UNAVAILABLE"):
            self.signer()

    def test_unavailable_backend_is_sanitized(self):
        self.script("import sys; sys.stderr.write('private backend diagnostic'); sys.exit(1)")
        with self.assertRaisesRegex(k.s.AuthorityError, "^KEYCHAIN_SIGNER_FAILED$"):
            self.signer()(self.header, self.claims)

    def test_actual_pipe_overflow_is_bounded(self):
        self.script("import os; os.read(0, 4096); os.write(1, b'x' * 100000)")
        with self.assertRaisesRegex(k.s.AuthorityError, "^KEYCHAIN_SIGNER_FAILED$"):
            self.signer()(self.header, self.claims)

    def test_actual_timeout_reaps_child(self):
        self.script("import time; time.sleep(5)")
        started = time.monotonic()
        with self.assertRaisesRegex(k.s.AuthorityError, "^KEYCHAIN_SIGNER_TIMEOUT$"):
            self.signer(timeout_seconds=0.2)(self.header, self.claims)
        self.assertLess(time.monotonic() - started, 3)

    def test_loader_settings_are_not_inherited(self):
        self.script("import os,sys; sys.stdout.buffer.write(b'{}' if 'DYLD_INSERT_LIBRARIES' in os.environ else b'[]')")
        with patch.dict(os.environ, {"DYLD_INSERT_LIBRARIES": "fixture-value", "PYTHONPATH": "fixture-value"}):
            self.assertEqual(self.signer()._process(b"{}"), b"[]")

    def test_oversized_payload_never_invokes_signer(self):
        signer = self.signer()
        with patch.object(signer, "_process") as process:
            with self.assertRaisesRegex(k.s.AuthorityError, "INPUT_INVALID"):
                signer(self.header, {**self.claims, "runtime_grants": ["x" * 65536]})
            process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
