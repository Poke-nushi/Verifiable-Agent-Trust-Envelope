#!/usr/bin/env python3
"""Exercise signed authority, revocation and restore with a local recording callback."""
import argparse
import base64
from dataclasses import replace
import json
from pathlib import Path
import tempfile

import caller_jwt as c
from fixture_support import sign_fixture

b, jwt = c.b, c.jwt


def run(node, node_sha256):
    # Import by path: this script and the runtime example share a basename.
    import importlib.util
    spec = importlib.util.spec_from_file_location("caller_runtime_fixture", c.ROOT / "reference/runtime-jwt/run_example.py")
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    files = fixture.run(node, node_sha256)
    prior = b.decode(files["RUN.json"])
    now = b.core.parse_time(prior["evaluated_at"])
    second = int((now - jwt.EPOCH).total_seconds())
    request, original = b.decode(files["admission-request.json"]), b.decode(files["original.json"])
    saved = b.decode(files["trust-policy.json"])
    trust = jwt.RuntimeTrustPolicy(saved["issued_at"], saved["expires_at"], tuple(
        jwt.RuntimeIssuerGrant(item["issuer"], item["kid"], base64.b64decode(item["spki_base64"]),
            item["runtime"], item["audience"], item["not_before"], item["expires_at"], item["revoked"])
        for item in saved["grants"]))
    runtime = jwt.RuntimeJwtVerifier(expected_profile=jwt.PROFILE, node=node, node_sha256=node_sha256,
        trust_policy_provider=lambda: trust, max_token_age_seconds=60, max_policy_age_seconds=50)
    header = {"alg": "ES256", "kid": "actor-key", "typ": c.TOKEN_TYPE}
    claims = {"iss": request["actor"], "sub": request["actor"], "aud": request["audience"],
        "iat": second - 1, "nbf": second - 1, "exp": second + 60, "grant_id": "purchase-grant",
        "request_sha256": b.digest(files["admission-request.json"])["value"],
        "original_sha256": b.digest(files["original.json"])["value"]}
    proof, key = sign_fixture(node, b.encode(header), b.encode(claims))
    grant = c.DelegationGrant("purchase-grant", request["principal"], request["actor"], "actor-key", key,
        request["runtime"], request["audience"], request["target"]["resource"], request["action"], "USD", "150.00",
        tuple(original["constraints"]["tool_allowlist"]), second - 10, second + 80)
    policy = c.AuthorityPolicy(second - 2, second + 80, (grant,))
    caller = c.CallerJwtAuthorizer(expected_profile=c.PROFILE, authority_id="urn:example:merchant-authority",
        node=node, node_sha256=node_sha256, authority_policy_provider=lambda: policy,
        max_token_age_seconds=40, max_policy_age_seconds=30)
    calls = []
    boundary = b.DispatchBoundary(execute=lambda *args: calls.append(args), clock=lambda: now)
    state = b.durable_state_module()
    observations = {}
    with tempfile.TemporaryDirectory() as temporary:
        store = state.DurableStateStore.create(Path(temporary) / "state", scope="local caller example",
                                                verifier_id="urn:example:verifier")
        def verifier(selected_store):
            return b.core.VateVerifier(verifier_id=store.verifier_id, policy=b.decode(files["policy.json"]),
                runtime_evidence_verifier=runtime.as_runtime_verifier(), caller_authorizer=caller.as_caller_authorizer(),
                dispatch_boundary=boundary, state_store=selected_store)
        initial = verifier(store)
        admitted = initial.admit(files["admission-request.json"], original=files["original.json"], now=now,
            evidence_artifacts={"urn:example:jwt": files["runtime.jwt"]}, caller_proof=proof)
        with boundary.update():
            policy = replace(policy, grants=(replace(grant, revoked=True),))
        try:
            initial.dispatch(admitted, caller_proof=proof)
        except b.Invalid as exc:
            observations["revoked"] = exc.cause
        observations["revoked_callback_calls"] = len(calls)
        with boundary.update():
            policy = replace(policy, grants=(grant,))
        reopened = verifier(state.DurableStateStore(store.directory, expected_anchor=store.anchor))
        restored = reopened.restore_admission(request["request_id"])
        result = reopened.dispatch(restored, caller_proof=proof)
        observations["restored_callback_calls"] = len(calls)
        observations["exact_effective_bytes"] = calls[0][0] == restored.effective
        observations["state"] = reopened.dispatch_status(request["request_id"]).state
        try:
            verifier(state.DurableStateStore(store.directory, expected_anchor=store.anchor)).restore_admission(request["request_id"])
        except b.Invalid as exc:
            observations["repeat_restore"] = exc.cause
        output = {"original.json": restored.original, "admission-request.json": restored.request,
            "admission-receipt.json": restored.receipt, "effective.json": restored.effective,
            "assessment.json": restored.assessment, "pre-dispatch.json": result.checkpoint,
            "dispatch-status.json": reopened.dispatch_status(request["request_id"]).record}
    expected = {"revoked": "CALLER_AUTHORIZATION_FAILED", "revoked_callback_calls": 0,
        "restored_callback_calls": 1, "exact_effective_bytes": True, "state": "callback_returned",
        "repeat_restore": "DURABLE_OPERATION_ALREADY_ATTEMPTED"}
    if observations != expected or any(proof in raw for raw in output.values()):
        raise RuntimeError("caller authority example did not meet expected observations")
    sources = dict(prior["sources"])
    for path in ("reference/caller-authority/caller_jwt.py", "reference/caller-authority/run_example.py",
                 "reference/request-binding/caller_authority.py", "reference/request-binding/durable_state.py"):
        sources[path] = b.digest((c.ROOT / path).read_bytes())
    output["RUN.json"] = b.encode({"contract": c.PROFILE, "evidence_kind": "local-recording-callback",
        "observations": observations, "sources": sources, "node_sha256": node_sha256,
        "artifacts": {name: b.digest(raw) for name, raw in output.items()}})
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True)
    parser.add_argument("--node-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    files = run(args.node, args.node_sha256)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, raw in files.items():
        (args.output / name).write_bytes(raw)
    print(json.dumps(b.decode(files["RUN.json"])["observations"], indent=2))


if __name__ == "__main__":
    main()
