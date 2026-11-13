#!/usr/bin/env python3
"""Recheck signed evidence before a local recording callback; no purchase or network."""
import argparse
import base64
from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path

import runtime_jwt as jwt
import run_example as admission_example

b = jwt.binding


def run(node, node_sha256):
    files = admission_example.run(node, node_sha256)
    initial_run = files.pop("RUN.json")
    files["admission-run.json"] = initial_run
    policy = b.decode(files["policy.json"])
    saved = b.decode(files["trust-policy.json"])
    trust = jwt.RuntimeTrustPolicy(saved["issued_at"], saved["expires_at"], tuple(
        jwt.RuntimeIssuerGrant(item["issuer"], item["kid"], base64.b64decode(item["spki_base64"]),
            item["runtime"], item["audience"], item["not_before"], item["expires_at"], item["revoked"])
        for item in saved["grants"]))
    initial_trust = trust
    now = b.core.parse_time(b.decode(initial_run)["evaluated_at"])
    clock = now
    calls = []

    def record(effective, checkpoint):
        calls.append((effective, checkpoint))
        return "local callback returned"

    boundary = b.DispatchBoundary(execute=record, clock=lambda: clock)
    adapter = jwt.RuntimeJwtVerifier(expected_profile=jwt.PROFILE, node=node, node_sha256=node_sha256,
        trust_policy_provider=lambda: trust, max_token_age_seconds=60, max_policy_age_seconds=50)

    def admitted():
        verifier = b.core.VateVerifier(verifier_id="urn:example:verifier", policy=policy,
            runtime_evidence_verifier=adapter.as_runtime_verifier(), dispatch_boundary=boundary)
        bound = verifier.admit(files["admission-request.json"], original=files["original.json"], now=now,
            evidence_artifacts={"urn:example:jwt": files["runtime.jwt"]})
        return verifier, bound

    def rejection(verifier, bound):
        try:
            verifier.dispatch(bound)
        except b.Invalid as exc:
            return exc.cause
        raise RuntimeError("unexpected dispatch")

    valid, bound = admitted()
    clock += timedelta(seconds=2)
    result = valid.dispatch(bound)
    files["pre-dispatch.json"] = result.checkpoint
    observations = {"valid_callback_calls": len(calls),
        "callback_received_effective_bytes": calls[0][0] == files["effective.json"],
        "repeat": rejection(valid, bound)}
    revoked, revoked_bound = admitted()
    before = len(calls)
    with boundary.update():
        trust = replace(trust, grants=tuple(replace(grant, revoked=True) for grant in trust.grants))
    observations["revoked_after_admission"] = rejection(revoked, revoked_bound)
    observations["revoked_callback_calls"] = len(calls) - before
    with boundary.update():
        trust = initial_trust
    expired, expired_bound = admitted()
    clock = b.core.parse_time(b.decode(expired_bound.receipt)["expires_at"]) + timedelta(microseconds=1)
    observations["expired_after_admission"] = rejection(expired, expired_bound)
    observations["expired_callback_calls"] = len(calls) - before
    expected = {"valid_callback_calls": 1, "callback_received_effective_bytes": True,
        "repeat": "DISPATCH_ALREADY_ATTEMPTED",
        "revoked_after_admission": "RUNTIME_EVIDENCE_VERIFICATION_FAILED", "revoked_callback_calls": 0,
        "expired_after_admission": "DISPATCH_OUTSIDE_WINDOW", "expired_callback_calls": 0}
    if observations != expected:
        raise RuntimeError("dispatch observations differ from expected results")
    sources = b.decode(initial_run)["sources"]
    path = "reference/runtime-jwt/run_dispatch_example.py"
    sources[path] = b.digest((jwt.ROOT / path).read_bytes())
    files["RUN.json"] = b.encode({"contract": b.PRE_DISPATCH, "evidence_kind": "local-recording-callback",
        "observations": observations, "sources": sources, "node_sha256": node_sha256,
        "artifacts": {name: b.digest(raw) for name, raw in files.items()}})
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
