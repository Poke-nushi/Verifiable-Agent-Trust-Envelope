"""Constructor timeout domains, using synthetic files and no external actions."""
from contextlib import ExitStack
from decimal import Decimal
import math
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import snapshot as s
import https_source as https
import supervised_https as supervised

ROOT = Path(__file__).resolve().parents[2]
for relative in ("authority-issuer", "authority-keychain"):
    sys.path.insert(0, str(ROOT / "reference" / relative))
import service_client
import keychain_signer

jwt, caller = s.jwt, s.c


class IntegerSubclass(int):
    pass


class FloatSubclass(float):
    pass


class TimeoutConfigurationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.helper, self.keychain = self.root / "helper", self.root / "keychain"
        self.helper.write_bytes(b"#!/bin/sh\nexit 1\n")
        self.helper.chmod(0o700)
        self.keychain.write_bytes(b"synthetic fixture, not a Keychain")
        self.keychain.chmod(0o600)
        self.helper_sha = jwt.file_sha(self.helper)
        public = jwt.SPKI_PREFIX + bytes.fromhex(
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
        self.selection = s.AuthoritySelection("issuer", "audience", "scope", "epoch",
                                               "key", public, 1, 30)

    def assert_timeout_domain(self, constructor, maximum, error_type, attribute, cause,
                              read_timeout, *, backend=False):
        invalid = (
            ("huge_integer", 10 ** 1000), ("huge_negative_integer", -(10 ** 1000)),
            ("true", True), ("false", False), ("zero_integer", 0), ("zero_float", 0.0),
            ("negative_zero", -0.0), ("negative_integer", -1), ("negative_float", -0.1),
            ("above_maximum_integer", maximum + 1),
            ("above_maximum_float", math.nextafter(float(maximum), math.inf)),
            ("positive_infinity", math.inf), ("negative_infinity", -math.inf), ("nan", math.nan),
            ("none", None), ("string", "1"), ("decimal", Decimal("1")), ("complex", 1 + 0j),
            ("integer_subclass", IntegerSubclass(1)), ("float_subclass", FloatSubclass(1.0)),
        )
        # Reject before TLS setup, a helper subprocess, or an endpoint operation.
        with ExitStack() as stack:
            actions = [stack.enter_context(patch(target, side_effect=AssertionError(target)))
                       for target in ("subprocess.run", "subprocess.Popen", "socket.create_connection",
                                      "urllib.request.OpenerDirector.open", "ssl.create_default_context")]
            for label, timeout in invalid:
                with self.subTest(input=label):
                    with self.assertRaises(error_type) as caught:
                        constructor(timeout)
                    self.assertEqual(getattr(caught.exception, attribute), cause)
            for action in actions:
                action.assert_not_called()

        valid = (
            ("smallest_positive_float", math.nextafter(0.0, math.inf)), ("fraction", 0.5),
            ("integer", 1), ("float", 1.0), ("maximum_integer", maximum),
            ("maximum_float", float(maximum)),
            ("below_maximum_float", math.nextafter(float(maximum), 0.0)),
        )
        with ExitStack() as stack:
            process = stack.enter_context(patch("subprocess.run", return_value=
                subprocess.CompletedProcess([], 0, b"v22.0.0\n", b"")))
            actions = [stack.enter_context(patch(target, side_effect=AssertionError(target)))
                       for target in ("subprocess.Popen", "socket.create_connection",
                                      "urllib.request.OpenerDirector.open")]
            stack.enter_context(patch("ssl.create_default_context",
                                      side_effect=lambda **kwargs: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)))
            for label, timeout in valid:
                with self.subTest(input=label):
                    instance = constructor(timeout)
                    self.assertEqual(read_timeout(instance), timeout)
                    if backend:
                        self.assertEqual(process.call_args.args[0], [str(self.helper), "--version"])
                        self.assertEqual(process.call_args.kwargs["timeout"], timeout)
            self.assertEqual(process.call_count, len(valid) if backend else 0)
            for action in actions:
                action.assert_not_called()

    def backend_options(self, timeout):
        return dict(node=self.helper, node_sha256=self.helper_sha, timeout_seconds=timeout)

    def test_es256_backend_timeout_domain(self):
        self.assert_timeout_domain(lambda value: jwt.Es256Backend(**self.backend_options(value)),
            60, jwt.RuntimeJwtError, "code", "INVALID_CONFIGURATION", lambda value: value.timeout,
            backend=True)

    def test_runtime_verifier_inherits_backend_timeout_domain(self):
        self.assert_timeout_domain(lambda value: jwt.RuntimeJwtVerifier(
            expected_profile=jwt.PROFILE, trust_policy_provider=lambda: None,
            max_token_age_seconds=60, max_policy_age_seconds=60, **self.backend_options(value)),
            60, jwt.RuntimeJwtError, "code", "INVALID_CONFIGURATION", lambda value: value.timeout,
            backend=True)

    def test_caller_authorizer_inherits_backend_timeout_domain(self):
        self.assert_timeout_domain(lambda value: caller.CallerJwtAuthorizer(
            expected_profile=caller.PROFILE, authority_id="authority",
            authority_policy_provider=lambda: None, max_token_age_seconds=60,
            max_policy_age_seconds=60, **self.backend_options(value)),
            60, jwt.RuntimeJwtError, "code", "INVALID_CONFIGURATION", lambda value: value.backend.timeout,
            backend=True)

    def test_snapshot_verifier_inherits_backend_timeout_domain(self):
        self.assert_timeout_domain(lambda value: s.SnapshotVerifier(expected_profile=s.PROFILE,
            selection=self.selection, **self.backend_options(value)),
            60, jwt.RuntimeJwtError, "code", "INVALID_CONFIGURATION", lambda value: value.backend.timeout,
            backend=True)

    def test_https_source_timeout_domain(self):
        self.assert_timeout_domain(lambda value: https.HttpsSnapshotSource(
            "https://localhost.invalid/snapshot", timeout_seconds=value),
            30, s.AuthorityError, "cause", "AUTHORITY_TIMEOUT_INVALID", lambda value: value.timeout)

    def test_supervised_https_source_timeout_domain(self):
        self.assert_timeout_domain(lambda value: supervised.SupervisedHttpsSnapshotSource(
            "https://localhost.invalid/snapshot", timeout_seconds=value),
            30, s.AuthorityError, "cause", "AUTHORITY_TIMEOUT_INVALID", lambda value: value._config.timeout)

    def test_issuer_service_timeout_domain(self):
        self.assert_timeout_domain(lambda value: service_client.JsonService(
            "https://localhost.invalid", timeout_seconds=value),
            30, s.AuthorityError, "cause", "ISSUER_TIMEOUT_INVALID", lambda value: value.timeout)

    def test_keychain_signer_timeout_domain(self):
        with patch.object(keychain_signer.sys, "platform", "darwin"):
            self.assert_timeout_domain(lambda value: keychain_signer.KeychainSigner(
                expected_profile=keychain_signer.PROFILE, helper=self.helper,
                helper_sha256=self.helper_sha, keychain=self.keychain, application_tag="synthetic",
                selection=self.selection, timeout_seconds=value),
                10, s.AuthorityError, "cause", "KEYCHAIN_SIGNER_CONFIGURATION_INVALID",
                lambda value: value._config.timeout_seconds)


if __name__ == "__main__":
    unittest.main()
