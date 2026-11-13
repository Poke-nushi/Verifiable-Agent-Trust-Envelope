#!/usr/bin/env python3
"""Take signed policy updates through ordinary admission and a local callback."""
import argparse
import base64
import copy
import importlib.util
import json
from pathlib import Path
import tempfile

import snapshot as s
from authority_store import AuthorityStore
from managed_verifier import ManagedAuthorityVerifier
from fixture_support_updates import grant_json, sign_snapshots
from fixture_support import sign_fixture

b, c, jwt = s.b, s.c, s.jwt


def run(node, node_sha256):
    spec = importlib.util.spec_from_file_location("authority_runtime_fixture",
        s.ROOT / "reference/runtime-jwt/run_example.py")
    fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
    files = fixture.run(node, node_sha256)
    prior = b.decode(files["RUN.json"])
    now = b.core.parse_time(prior["evaluated_at"])
    second = int((now - jwt.EPOCH).total_seconds())
    request, original = b.decode(files["admission-request.json"]), b.decode(files["original.json"])
    saved = b.decode(files["trust-policy.json"])["grants"][0]
    runtime_grant = jwt.RuntimeIssuerGrant(saved["issuer"], saved["kid"], base64.b64decode(saved["spki_base64"]),
        saved["runtime"], saved["audience"], saved["not_before"], saved["expires_at"], saved["revoked"])
    caller_claims = {"iss": request["actor"], "sub": request["actor"], "aud": request["audience"],
        "iat": second - 1, "nbf": second - 1, "exp": second + 60, "grant_id": "purchase-grant",
        "request_sha256": b.digest(files["admission-request.json"])["value"],
        "original_sha256": b.digest(files["original.json"])["value"]}
    proof, actor_key = sign_fixture(node, b.encode({"alg": "ES256", "kid": "actor-key", "typ": c.TOKEN_TYPE}),
        b.encode(caller_claims))
    grant = c.DelegationGrant("purchase-grant", request["principal"], request["actor"], "actor-key", actor_key,
        request["runtime"], request["audience"], request["target"]["resource"], request["action"], "USD", "150.00",
        tuple(original["constraints"]["tool_allowlist"]), second - 10, second + 80)
    claims = {"iss": "urn:example:merchant-policy-authority", "aud": "urn:example:verifier",
        "scope": "merchant-purchase", "epoch": "epoch-1", "revision": 1,
        "iat": second - 2, "nbf": second - 2, "exp": second + 80,
        "runtime_grants": [grant_json(runtime_grant)], "delegation_grants": [grant_json(grant)]}
    revoked = copy.deepcopy(claims); revoked["revision"] = 2; revoked["delegation_grants"][0]["revoked"] = True
    restored = {**claims, "revision": 3}
    tokens, authority_key = sign_snapshots(node, [claims, revoked, restored])
    selection = s.AuthoritySelection(claims["iss"], claims["aud"], claims["scope"], claims["epoch"],
        "authority-key", authority_key, 1, 30)
    snapshot_verifier = s.SnapshotVerifier(expected_profile=s.PROFILE, selection=selection,
        node=node, node_sha256=node_sha256)
    observations, calls = {}, []
    with tempfile.TemporaryDirectory() as temporary:
        source = AuthorityStore.create(Path(temporary) / "authority", verifier=snapshot_verifier, clock=lambda: now)
        state_type = b.durable_state_module().DurableStateStore
        state = state_type.create(Path(temporary) / "dispatch", scope="authority update example",
                                  verifier_id=claims["aud"])
        def managed(selected_source, selected_state):
            return ManagedAuthorityVerifier(source=selected_source, verifier_id=claims["aud"],
                policy=b.decode(files["policy.json"]), state_store=selected_state,
                execute=lambda *args: calls.append(args), max_runtime_token_age_seconds=60,
                max_caller_token_age_seconds=40)
        current = managed(source, state)
        source.accept(tokens[0])
        admitted = current.admit(files["admission-request.json"], original=files["original.json"],
            evidence_artifacts={"urn:example:jwt": files["runtime.jwt"]}, caller_proof=proof)
        source.accept(tokens[1])
        # Reopen both independently anchored stores, retaining their fences.
        source = AuthorityStore(source.directory, verifier=snapshot_verifier,
                                expected_anchor=source.anchor, clock=lambda: now)
        current = managed(source, state_type(state.directory, expected_anchor=state.anchor))
        observations["reopened_revision"] = source.status()["revision"]
        try:
            source.accept(tokens[0])
        except s.AuthorityError as exc:
            observations["old_snapshot"] = exc.cause
        pending = current.restore_admission(request["request_id"])
        try:
            current.dispatch(pending, caller_proof=proof)
        except b.Invalid as exc:
            observations["revoked_dispatch"] = exc.cause
        observations["revoked_callback_calls"] = len(calls)
        source.accept(tokens[2])
        result = current.dispatch(pending, caller_proof=proof)
        observations.update(final_revision=source.status()["revision"], callback_calls=len(calls),
            exact_effective_bytes=calls[0][0] == pending.effective,
            receipt_unchanged=pending.receipt == admitted.receipt,
            dispatch_state=current.dispatch_status(request["request_id"]).state)
        output = {"original.json": pending.original, "admission-request.json": pending.request,
            "admission-receipt.json": pending.receipt, "effective.json": pending.effective,
            "assessment.json": pending.assessment, "pre-dispatch.json": result.checkpoint,
            "dispatch-status.json": current.dispatch_status(request["request_id"]).record,
            "snapshot-claims.example.json": b.encode(claims), "authority-status.json": b.encode(source.status())}
    expected = {"reopened_revision": 2, "old_snapshot": "AUTHORITY_ROLLBACK",
        "revoked_dispatch": "CALLER_AUTHORIZATION_FAILED", "revoked_callback_calls": 0,
        "final_revision": 3, "callback_calls": 1, "exact_effective_bytes": True,
        "receipt_unchanged": True, "dispatch_state": "callback_returned"}
    if observations != expected or any(proof in raw for raw in output.values()):
        raise RuntimeError("authority intake example did not meet expected observations")
    sources = dict(prior["sources"])
    paths = [*Path(__file__).parent.glob("*.py"), Path(__file__).with_name("fixture_signer.mjs"),
             Path(c.__file__), Path(jwt.__file__), s.ROOT / "reference/runtime-jwt/fixture_support.py"]
    for path in paths:
        if not path.name.startswith("test_"):
            sources[str(path.resolve().relative_to(s.ROOT))] = b.digest(path.read_bytes())
    output["RUN.json"] = b.encode({"contract": s.PROFILE, "evaluated_at": b.core.iso(now),
        "evidence_kind": "local-recording-callback", "observations": observations, "sources": sources,
        "node_sha256": node_sha256, "artifacts": {name: b.digest(raw) for name, raw in output.items()}})
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
