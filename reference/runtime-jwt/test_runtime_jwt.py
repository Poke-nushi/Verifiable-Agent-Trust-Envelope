"""Real local ES256 signatures through the public admission entry; no dispatch."""
import base64
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import runtime_jwt as jwt
import example as purchase
from fixture_support import b64, sign_fixture

b = jwt.binding


class RuntimeJwtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        selected = shutil.which("node")
        if selected is None:
            raise RuntimeError("Node.js 22+ is required for this optional adapter suite")
        cls.node = Path(selected).resolve()
        cls.node_sha = jwt.file_sha(cls.node)

    def setUp(self):
        self.original, self.request, self.policy = purchase.inputs()
        self.request["runtime"] = "urn:example:runtime:purchase"
        self.now = b.core.parse_time(purchase.EVALUATED_AT)
        self.second = int((self.now - jwt.EPOCH).total_seconds())
        self.header = {"alg": "ES256", "kid": "key-1", "typ": jwt.TOKEN_TYPE}
        self.claims = {"iss": "urn:example:runtime-issuer", "sub": self.request["runtime"],
            "aud": self.request["audience"], "iat": self.second - 1, "nbf": self.second - 1,
            "exp": self.second + 120,
            "vate_context_hash": b.runtime_context_hash(b.encode(self.request), b.encode(self.original))}
        self.raw, key = sign_fixture(self.node, b.encode(self.header), b.encode(self.claims))
        self.grant = jwt.RuntimeIssuerGrant(self.claims["iss"], "key-1", key, self.request["runtime"],
            self.request["audience"], self.second - 10, self.second + 90)
        self.trust = jwt.RuntimeTrustPolicy(self.second - 2, self.second + 80, (self.grant,))
        self.adapter = self.new_adapter()
        self.verifier = b.core.VateVerifier(verifier_id="urn:example:verifier", policy=self.policy,
                                          runtime_evidence_verifier=self.adapter.as_runtime_verifier())
        self.attach()

    def new_adapter(self, **changes):
        options = dict(expected_profile=jwt.PROFILE, node=self.node, node_sha256=self.node_sha,
            trust_policy_provider=lambda: self.trust, max_token_age_seconds=60, max_policy_age_seconds=50)
        options.update(changes)
        return jwt.RuntimeJwtVerifier(**options)

    def attach(self):
        self.request["evidence_refs"] = [r for r in self.request["evidence_refs"] if r["type"] != "runtime_attestation"]
        self.request["evidence_refs"].append({"type": "runtime_attestation", "uri": "urn:example:jwt",
            "media_type": jwt.MEDIA_TYPE, "digest": b.digest(self.raw)})

    def resign(self, header_raw=None, claims_raw=None, **options):
        self.raw, key = sign_fixture(self.node,
            b.encode(self.header) if header_raw is None else header_raw,
            b.encode(self.claims) if claims_raw is None else claims_raw, **options)
        self.grant = replace(self.grant, public_key_spki=key)
        self.trust = replace(self.trust, grants=(self.grant,))
        self.attach()

    def context(self, now=None):
        return b.RuntimeEvidenceContext(b.encode(self.request), b.encode(self.original),
            b.encode(self.request["evidence_refs"][1]),
            b.runtime_context_hash(b.encode(self.request), b.encode(self.original)),
            self.request["runtime"], self.request["audience"], self.now if now is None else now)

    def admit(self, **options):
        options.setdefault("now", self.now)
        options.setdefault("evidence_artifacts", {"urn:example:jwt": self.raw})
        return self.verifier.admit(b.encode(self.request), original=b.encode(self.original), **options)

    def reject(self, code=None, **options):
        if code is not None:
            with self.assertRaisesRegex(jwt.RuntimeJwtError, "^" + code + "$"):
                self.adapter.verify(self.raw, self.context(options.get("now")))
        previous = self.verifier._seen_request_ids.copy()
        with patch.object(self.verifier, "_evaluate_policy", wraps=self.verifier._evaluate_policy) as policy:
            with self.assertRaises(b.Invalid):
                self.admit(**options)
            policy.assert_not_called()
        self.assertEqual(self.verifier._seen_request_ids, previous)

    def test_real_es256_admission_retains_token_and_authentication(self):
        result = self.admit()
        receipt, verified = b.decode(result.receipt), b.decode(result.runtime_verification)
        self.assertEqual(receipt["decision"]["outcome"], "attenuate")
        self.assertEqual(result.runtime_evidence, self.raw)
        self.assertEqual(verified["issuer"], self.claims["iss"])
        self.assertEqual(verified["verification"]["method"], jwt.PROFILE)
        self.assertEqual(verified["context_hash"], self.claims["vate_context_hash"])
        self.assertEqual(receipt["expires_at"], b.core.iso(self.now + timedelta(seconds=48)))
        self.assertTrue(b.decode(result.assessment)["binding_requirement_met"])
        checks = {c["name"]: c["status"] for c in b.decode(result.assessment)["checks"]}
        self.assertEqual(checks["evidence.authentication"], "not_checked")
        self.assertEqual(checks["execution.actual_input"], "not_checked")

    def test_rfc7515_appendix_a3_signature_vector(self):
        # Published public key/signature: https://www.rfc-editor.org/rfc/rfc7515#appendix-A.3
        # No private key from the RFC is used. This isolates the ES256 backend.
        x = jwt.decode_segment(b"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", 32)
        y = jwt.decode_segment(b"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0", 32)
        signing_input = (b"eyJhbGciOiJFUzI1NiJ9."
                         b"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
                         b"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ")
        signature = jwt.decode_segment(
            b"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q", 64)
        self.adapter._signature(signing_input, signature, jwt.SPKI_PREFIX + x + y)
        with self.assertRaisesRegex(jwt.RuntimeJwtError, "INVALID_SIGNATURE"):
            self.adapter._signature(signing_input + b"x", signature, jwt.SPKI_PREFIX + x + y)

    def test_allow_and_denial_keep_policy_meaning(self):
        for cap, amount, expected in (("20.00", "10.00", "allow"), ("120.00", "30.00", "deny")):
            with self.subTest(expected=expected):
                self.original, self.request, self.policy = purchase.inputs(cap=cap, purchase=amount)
                self.request["runtime"] = self.grant.runtime
                self.claims["vate_context_hash"] = b.runtime_context_hash(b.encode(self.request), b.encode(self.original))
                self.resign()
                self.verifier = b.core.VateVerifier(verifier_id="urn:example:v", policy=self.policy,
                    runtime_evidence_verifier=self.adapter.as_runtime_verifier())
                result = self.admit()
                self.assertEqual(b.decode(result.receipt)["decision"]["outcome"], expected)
                self.assertEqual(b.decode(result.runtime_verification)["verification"]["result"], "verified")
                self.assertEqual(b.decode(result.assessment)["decision_allows_immediate_execution"], expected == "allow")

    def test_new_permit_candidate_keeps_expiry_and_is_not_executable(self):
        result = self.admit(require_new_permit=True)
        self.assertEqual(b.decode(result.receipt)["expires_at"], b.core.iso(self.now + timedelta(seconds=48)))
        self.assertFalse(b.decode(result.assessment)["decision_allows_immediate_execution"])

    def test_signature_and_payload_changes_rejected_after_digest_refresh(self):
        original = self.raw
        h, p, s = original.split(b".")
        variants = [h + b"." + p + b"." + b64(b"\0" * 64),
                    h + b"." + b64(b.encode({**self.claims, "exp": self.second + 121})) + b"." + s]
        for raw in variants:
            with self.subTest(raw=raw[:12]):
                self.raw = raw
                self.attach()
                self.reject("INVALID_SIGNATURE")

    def test_header_and_key_identifier_must_be_supported(self):
        for patching, code in (({"alg": "none"}, "UNSUPPORTED_JWT_HEADER"),
                ({"alg": "HS256"}, "UNSUPPORTED_JWT_HEADER"), ({"typ": "JWT"}, "UNSUPPORTED_JWT_HEADER"),
                ({"kid": "other-key"}, "ISSUER_NOT_AUTHORIZED"), ({"jku": "https://unused.invalid/key"}, "UNSUPPORTED_JWT_HEADER"),
                ({"jwk": {}}, "UNSUPPORTED_JWT_HEADER"), ({"crit": []}, "UNSUPPORTED_JWT_HEADER"),
                ({"b64": False}, "UNSUPPORTED_JWT_HEADER")):
            with self.subTest(patching=patching):
                self.header = {"alg": "ES256", "kid": "key-1", "typ": jwt.TOKEN_TYPE, **patching}
                self.resign()
                self.reject(code)

    def test_signature_does_not_grant_issuer_runtime_or_audience_authority(self):
        original = self.claims.copy()
        for field in ("iss", "sub", "aud"):
            with self.subTest(field=field):
                self.claims = {**original, field: "urn:another"}
                self.resign()
                self.reject("ISSUER_NOT_AUTHORIZED")

    def test_an_unregistered_key_cannot_use_a_registered_kid(self):
        self.raw, _ = sign_fixture(self.node, b.encode(self.header), b.encode(self.claims))
        self.attach()
        self.reject("INVALID_SIGNATURE")

    def test_signed_claims_cannot_be_filled_from_expected_context(self):
        for field in jwt.CLAIM_FIELDS:
            with self.subTest(field=field):
                claims = {k: v for k, v in self.claims.items() if k != field}
                self.resign(claims_raw=b.encode(claims))
                self.reject("INVALID_JWT_CLAIMS")

    def test_signed_context_mismatch_and_request_reuse(self):
        self.claims["vate_context_hash"] = "sha-256:" + "0" * 64
        self.resign()
        self.reject("REQUEST_CONTEXT_MISMATCH")
        self.claims["vate_context_hash"] = self.context().context_hash
        self.resign()
        self.request["request_id"] = "another-request"
        self.reject("REQUEST_CONTEXT_MISMATCH")

    def test_context_runtime_and_audience_are_independently_matched(self):
        for field in ("runtime", "audience"):
            with self.subTest(field=field):
                context = replace(self.context(), **{field: "urn:different"})
                with self.assertRaisesRegex(jwt.RuntimeJwtError, "REQUEST_CONTEXT_MISMATCH"):
                    self.adapter.verify(self.raw, context)

    def test_raw_digest_is_checked_before_authentication(self):
        self.raw += b"\n"
        with patch.object(self.adapter, "verify", side_effect=AssertionError("must not run")):
            self.reject()

    def test_proof_removal_and_wrong_media_type_cannot_downgrade(self):
        self.request["evidence_refs"][1]["media_type"] = "application/json"
        self.reject()
        self.request["evidence_refs"].pop()
        self.reject(evidence_artifacts={})

    def test_strict_compact_encoding(self):
        h, p, s = self.raw.split(b".")
        for raw in (b"", self.raw + b"\n", h + b"=.." + s, h + b".." + s,
                    b".".join((h,p,s,b"extra")), b"\xff" + self.raw, b"a" * (jwt.MAX_TOKEN_BYTES + 1),
                    h + b"." + p + b"." + s + b"=", h + b"." + p + b".A"):
            with self.subTest(size=len(raw)):
                self.raw = raw
                self.attach()
                self.reject("INVALID_COMPACT_JWT")

    def test_strict_json_duplicate_fields_utf8_types_and_unknown_claims(self):
        for claims in (b'{"iss":"a","iss":"b"}', b'\xff', b'[]', b'{"a":NaN}',
                       b'{"a":"\\ud800"}', b'{"a":1.1}', b'[' * 70 + b']' * 70):
            with self.subTest(raw=claims[:30]):
                self.resign(claims_raw=claims)
                self.reject()
        self.resign(claims_raw=b.encode({**self.claims, "unrecognized": True}))
        self.reject("INVALID_JWT_CLAIMS")
        self.resign(header_raw=b'{"alg":"ES256","alg":"none","kid":"key-1","typ":"vate-runtime-evidence+jwt"}')
        self.reject("INVALID_JWT_JSON")

    def test_numeric_dates_reject_bool_fraction_and_overflow(self):
        for value in (True, -1, 253402300800, "123", None):
            with self.subTest(value=value):
                self.resign(claims_raw=b.encode({**self.claims, "iat": value}))
                self.reject("INVALID_NUMERIC_DATE")
        fractional = json.dumps({**self.claims, "iat": 1.25}).encode()
        self.resign(claims_raw=fractional)
        self.reject("INVALID_JWT_JSON")

    def test_exclusive_token_expiry_is_not_rounded_up(self):
        self.claims["exp"] = self.second + 1
        self.resign()
        last = self.now + timedelta(seconds=1, microseconds=-1)
        result = self.admit(now=last)
        self.assertEqual(b.decode(result.receipt)["expires_at"], b.core.iso(last))
        self.reject("TOKEN_OUTSIDE_WINDOW", now=self.now + timedelta(seconds=1))

    def test_future_not_before_issued_and_stale_tokens(self):
        baseline = self.claims.copy()
        for changes, code in (({"iat": self.second + 1}, "TOKEN_OUTSIDE_WINDOW"),
                ({"nbf": self.second + 1}, "TOKEN_OUTSIDE_WINDOW"),
                ({"exp": self.second}, "TOKEN_OUTSIDE_WINDOW"),
                ({"iat": self.second - 61}, "TOKEN_STALE")):
            with self.subTest(changes=changes):
                self.claims = {**baseline, **changes}
                self.resign()
                self.reject(code)

    def test_inclusive_freshness_and_non_utc_clock(self):
        self.claims["iat"] = self.second - 60
        self.grant = replace(self.grant, not_before=self.second - 100)
        self.resign()
        shifted = self.now.astimezone(timezone(timedelta(hours=9)))
        result = self.admit(now=shifted)
        self.assertEqual(b.decode(result.receipt)["expires_at"], b.core.iso(self.now))
        self.reject("TOKEN_STALE", now=self.now + timedelta(microseconds=1))

    def test_grant_expiry_caps_receipt_and_rejects_at_boundary(self):
        self.trust = replace(self.trust, grants=(replace(self.grant, expires_at=self.second + 1),))
        last = self.now + timedelta(seconds=1, microseconds=-1)
        self.assertEqual(self.adapter.verify(self.raw, self.context()).valid_until, b.core.iso(last))
        self.reject("GRANT_OUTSIDE_WINDOW", now=self.now + timedelta(seconds=1))

    def test_grant_must_cover_issuance_and_evaluation(self):
        self.trust = replace(self.trust, grants=(replace(self.grant, not_before=self.second),))
        self.reject("GRANT_OUTSIDE_WINDOW")

    def test_policy_expiry_and_freshness_cap_valid_until(self):
        self.trust = replace(self.trust, expires_at=self.second + 1)
        last = self.now + timedelta(seconds=1, microseconds=-1)
        self.assertEqual(self.adapter.verify(self.raw, self.context()).valid_until, b.core.iso(last))
        self.reject("TRUST_POLICY_OUTSIDE_WINDOW", now=self.now + timedelta(seconds=1))
        self.trust = replace(self.trust, issued_at=self.second - 50, expires_at=self.second + 80)
        self.assertEqual(self.adapter.verify(self.raw, self.context()).valid_until, b.core.iso(self.now))
        self.reject("TRUST_POLICY_STALE", now=self.now + timedelta(microseconds=1))

    def test_trust_policy_reloaded_and_revocation_removal_prevent_admission(self):
        self.adapter.verify(self.raw, self.context())
        self.trust = replace(self.trust, grants=(replace(self.grant, revoked=True),))
        self.reject("ISSUER_NOT_AUTHORIZED")
        self.trust = replace(self.trust, grants=())
        self.reject("ISSUER_NOT_AUTHORIZED")

    def test_future_stale_missing_or_failed_policy_rejected(self):
        baseline = self.trust
        for value, code in ((None, "INVALID_TRUST_POLICY"),
                (replace(baseline, issued_at=self.second + 1), "TRUST_POLICY_OUTSIDE_WINDOW"),
                (replace(baseline, issued_at=self.second - 51), "TRUST_POLICY_STALE")):
            self.trust = value
            self.reject(code)
        self.adapter.trust_policy_provider = lambda: (_ for _ in ()).throw(RuntimeError("private detail"))
        self.reject("TRUST_POLICY_UNAVAILABLE")

    def test_policy_change_during_verification_prevents_return(self):
        original = self.adapter._signature
        def changed(*args):
            original(*args)
            self.trust = replace(self.trust, grants=())
        with patch.object(self.adapter, "_signature", side_effect=changed):
            with self.assertRaisesRegex(jwt.RuntimeJwtError, "TRUST_POLICY_CHANGED"):
                self.adapter.verify(self.raw, self.context())
        self.trust = replace(self.trust, grants=(self.grant,))
        with patch.object(self.adapter, "_signature", side_effect=changed):
            self.reject()

    def test_ambiguous_grants_and_key_assignments_rejected(self):
        for grants in ((self.grant, self.grant),
                (self.grant, replace(self.grant, runtime="other", public_key_spki=jwt.SPKI_PREFIX + b"\0" * 64))):
            self.trust = replace(self.trust, grants=grants)
            self.reject("AMBIGUOUS_TRUST_POLICY")

    def test_policy_and_key_types_are_strict(self):
        for grant in (replace(self.grant, revoked=0), replace(self.grant, not_before=True),
                replace(self.grant, public_key_spki=bytearray(self.grant.public_key_spki)),
                replace(self.grant, public_key_spki=b"not a key"), replace(self.grant, issuer="")):
            self.trust = replace(self.trust, grants=(grant,))
            self.reject()
        self.trust = jwt.RuntimeTrustPolicy(self.second - 2, self.second + 80, [self.grant])
        self.reject("INVALID_TRUST_POLICY")

    def test_wrong_curve_and_der_signature_not_accepted(self):
        self.resign(curve="secp384r1")
        self.reject()
        self.resign(signature_encoding="der")
        self.reject("INVALID_COMPACT_JWT")

    def test_invalid_curve_point_does_not_verify(self):
        self.trust = replace(self.trust, grants=(replace(self.grant,
            public_key_spki=jwt.SPKI_PREFIX + b"\0" * 64),))
        self.reject("BACKEND_FAILED")

    def test_policy_dates_near_datetime_limit_fail_without_overflow(self):
        latest = jwt.MAX_NUMERIC_DATE
        self.trust = replace(self.trust, issued_at=latest - 1, expires_at=latest)
        _, _, deadline = self.adapter._policy(jwt.numeric_date(latest - 1))
        self.assertEqual(deadline, jwt.numeric_date(latest) - timedelta(microseconds=1))

    def test_backend_failure_wrong_response_and_timeout_fail_closed(self):
        for result in (subprocess.CompletedProcess([], 1, b"", b"private detail"),
                subprocess.CompletedProcess([], 0, b'{"verified":true}', b""),
                subprocess.CompletedProcess([], 0, b"x" * 2049, b"")):
            with patch.object(self.adapter, "_process", return_value=result):
                self.reject("BACKEND_FAILED")
        with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired("node", 1)):
            self.reject("BACKEND_TIMEOUT")

    def test_backend_pin_and_configuration_are_checked(self):
        with self.assertRaisesRegex(jwt.RuntimeJwtError, "BACKEND_CHANGED"):
            self.new_adapter(node_sha256="0" * 64)
        for change in ({"max_token_age_seconds": True}, {"max_policy_age_seconds": 0},
                       {"timeout_seconds": float("nan")}, {"expected_profile": "other"}):
            with self.assertRaises(jwt.RuntimeJwtError):
                self.new_adapter(**change)
        self.adapter.bridge_sha256 = "0" * 64
        self.reject("BACKEND_CHANGED")

    def test_backend_does_not_inherit_node_preload_options(self):
        with patch.dict(os.environ, {"NODE_OPTIONS": "--require=/nonexistent/private-config"}):
            self.assertEqual(self.adapter.verify(self.raw, self.context()).issuer, self.claims["iss"])

    def test_failed_authentication_preserves_prior_replay_ids(self):
        self.admit()
        prior = self.verifier._seen_request_ids.copy()
        self.trust = replace(self.trust, grants=())
        self.reject("ISSUER_NOT_AUTHORIZED")
        self.assertEqual(self.verifier._seen_request_ids, prior)

    def test_frozen_policy_input(self):
        with self.assertRaises(FrozenInstanceError):
            self.grant.runtime = "changed"
        with self.assertRaises(FrozenInstanceError):
            self.trust.grants = ()

    def test_cli_artifacts_reverify_with_saved_public_trust(self):
        with tempfile.TemporaryDirectory(prefix="vate-runtime-jwt-") as folder:
            output = Path(folder) / "run"
            command = [sys.executable, "-B", str(Path(__file__).with_name("run_example.py")),
                "--node", str(self.node), "--node-sha256", self.node_sha, "--output", str(output)]
            completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            report = b.decode((output / "RUN.json").read_bytes())
            self.assertEqual(report["observations"]["valid"], "attenuate")
            self.assertFalse(report["observations"]["new_permit_executable"])
            self.assertEqual(report["evidence_kind"], "local-fixture-no-dispatch")
            for name, digest in report["artifacts"].items():
                self.assertEqual(b.digest((output / name).read_bytes()), digest)
            data = b.decode((output / "trust-policy.json").read_bytes())
            entry = data["grants"][0]
            self.trust = jwt.RuntimeTrustPolicy(data["issued_at"], data["expires_at"],
                (jwt.RuntimeIssuerGrant(entry["issuer"], entry["kid"], base64.b64decode(entry["spki_base64"]),
                    entry["runtime"], entry["audience"], entry["not_before"], entry["expires_at"], entry["revoked"]),))
            self.original = b.decode((output / "original.json").read_bytes())
            self.request = b.decode((output / "admission-request.json").read_bytes())
            raw = (output / "runtime.jwt").read_bytes()
            verified = self.adapter.verify(raw, self.context())
            self.assertEqual(verified.issuer, entry["issuer"])
            saved = {path.name: path.read_bytes() for path in output.iterdir()}
            repeated = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            self.assertEqual(repeated.returncode, 2)
            self.assertEqual(saved, {path.name: path.read_bytes() for path in output.iterdir()})


if __name__ == "__main__":
    unittest.main()
