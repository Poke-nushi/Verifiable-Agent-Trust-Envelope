#!/usr/bin/env python3
"""Reproduce signed runtime admission locally, without dispatch or external services."""
import argparse
import base64
import copy
from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path

import runtime_jwt as jwt
import example as purchase
from fixture_support import b64, sign_fixture

b = jwt.binding


def run(node, node_sha256):
    original, request, policy = purchase.inputs()
    request["runtime"] = "urn:example:runtime:purchase"
    now = b.core.parse_time(purchase.EVALUATED_AT)
    second = int((now - jwt.EPOCH).total_seconds())
    trust = None
    adapter = jwt.RuntimeJwtVerifier(expected_profile=jwt.PROFILE, node=node, node_sha256=node_sha256,
        trust_policy_provider=lambda: trust, max_token_age_seconds=60, max_policy_age_seconds=50)
    claims = {"iss": "urn:example:runtime-issuer", "sub": request["runtime"], "aud": request["audience"],
        "iat": second - 1, "nbf": second - 1, "exp": second + 120,
        "vate_context_hash": b.runtime_context_hash(b.encode(request), b.encode(original))}
    header = {"alg": "ES256", "kid": "example-key", "typ": jwt.TOKEN_TYPE}
    token, public_key = sign_fixture(adapter.node, b.encode(header), b.encode(claims))
    grant = jwt.RuntimeIssuerGrant(claims["iss"], header["kid"], public_key, request["runtime"],
        request["audience"], second - 10, second + 90)
    trust = jwt.RuntimeTrustPolicy(second - 2, second + 80, (grant,))
    request["evidence_refs"].append({"type": "runtime_attestation", "uri": "urn:example:jwt",
        "media_type": jwt.MEDIA_TYPE, "digest": b.digest(token)})

    def admit(req, evidence, instant=now, **options):
        verifier = b.core.VateVerifier(verifier_id="urn:example:verifier", policy=policy,
            runtime_evidence_verifier=adapter.as_runtime_verifier())
        return verifier.admit(b.encode(req), original=b.encode(original), now=instant,
                              evidence_artifacts={"urn:example:jwt": evidence}, **options)

    result = admit(request, token)
    candidate = admit(request, token, require_new_permit=True)
    observations = {"valid": b.decode(result.receipt)["decision"]["outcome"],
        "new_permit_executable": b.decode(candidate.assessment)["decision_allows_immediate_execution"]}
    variants = []
    wrong_request = copy.deepcopy(request)
    wrong_request["request_id"] = "another-request"
    variants.append(("different_request", wrong_request, token, now))
    bad_token = b".".join(token.split(b".")[:2] + [b64(b"\0" * 64)])
    bad_request = copy.deepcopy(request)
    bad_request["evidence_refs"][1]["digest"] = b.digest(bad_token)
    variants.append(("invalid_signature", bad_request, bad_token, now))
    variants.append(("expired", request, token, now + timedelta(seconds=120)))
    for name, req, evidence, instant in variants:
        try:
            admit(req, evidence, instant)
            observations[name] = "unexpected_admission"
        except b.Invalid as exc:
            observations[name] = exc.cause
    trust = replace(trust, grants=(replace(grant, revoked=True),))
    try:
        admit(request, token)
        observations["revoked"] = "unexpected_admission"
    except b.Invalid as exc:
        observations["revoked"] = exc.cause
    expected = {"valid": "attenuate", "new_permit_executable": False,
        **{name: "RUNTIME_EVIDENCE_VERIFICATION_FAILED" for name in
           ("different_request", "invalid_signature", "expired", "revoked")}}
    if observations != expected:
        raise RuntimeError("local runtime JWT observations differ from expected results")
    source_paths = ["reference/runtime-jwt/" + name for name in
        ("runtime_jwt.py", "verify_es256.mjs", "fixture_signer.mjs", "fixture_support.py", "run_example.py")]
    source_paths += ["reference/request-binding/request_binding.py", "reference/request-binding/example.py",
                     "reference/vate-verifier-core/vate_verifier_core.py"]
    files = {"original.json": result.original, "admission-request.json": result.request,
        "effective.json": result.effective, "admission-receipt.json": result.receipt,
        "runtime-verification.json": result.runtime_verification, "assessment.json": result.assessment,
        "runtime.jwt": token, "policy.json": b.encode(policy),
        "trust-policy.json": b.encode({"issued_at": trust.issued_at, "expires_at": trust.expires_at,
            "max_policy_age_seconds": adapter.max_policy_age_seconds,
            "grants": [{"issuer": grant.issuer, "kid": grant.kid, "runtime": grant.runtime,
                "audience": grant.audience, "spki_base64": base64.b64encode(public_key).decode(),
                "not_before": grant.not_before, "expires_at": grant.expires_at, "revoked": False}]})}
    report = {"profile": jwt.PROFILE, "evidence_kind": "local-fixture-no-dispatch",
        "evaluated_at": b.core.iso(now), "observations": observations,
        "node_sha256": node_sha256,
        "artifacts": {name: b.digest(raw) for name, raw in files.items()},
        "sources": {name: b.digest((jwt.ROOT / name).read_bytes()) for name in source_paths}}
    files["RUN.json"] = b.encode(report)
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True)
    parser.add_argument("--node-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output directory must not already exist")
    files = run(args.node, args.node_sha256)
    args.output.mkdir(parents=True)
    for name, raw in files.items():
        (args.output / name).write_bytes(raw)
    print(json.dumps({"output": str(args.output), "observations": b.decode(files["RUN.json"])["observations"]}))


if __name__ == "__main__":
    main()
