#!/usr/bin/env python3
"""Generate and recheck an unsigned purchase-cap example; no purchase is sent."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from request_binding import (
    ASSESSMENT, CONTRACT, MAX_BYTES, PREIMAGE_PROFILE, ROOT, Invalid,
    assess_request_binding, core, decode, digest, encode, exact, need, object_hash, reference,
)

HERE = Path(__file__).resolve().parent
SOURCE_FILES = (
    "reference/request-binding/request_binding.py",
    "reference/request-binding/example.py",
    "reference/request-binding/CONTRACT.md",
    "reference/request-binding/schemas/operation.schema.json",
    "reference/request-binding/schemas/binding.schema.json",
    "reference/request-binding/schemas/assessment.schema.json",
    "reference/vate-verifier-core/vate_verifier_core.py",
    "schemas/admission-request.schema.json",
    "schemas/admission-receipt.schema.json",
    "schemas/post-execution-receipt.schema.json",
)
ARTIFACT_FILES = {"original.json", "effective.json", "admission-request.json", "admission-receipt.json",
                  "core-result.json", "assessment.json", "post-execution.json", "policy.json"}
MANIFEST = "vate-request-binding-example-manifest-v1"
EVALUATED_AT = "2026-11-12T00:00:01Z"


def inputs(*, cap: str = "120.00", purchase: str = "24.50") -> tuple[dict, dict, dict]:
    operation = {
        "preimage_profile": PREIMAGE_PROFILE, "operation_id": "op-purchase-cap-001",
        "action": "commerce.purchase",
        "target": {"resource": "https://merchant.example/checkout", "audience": "https://agent.example/a2a"},
        "payload": {"tool": "merchant.checkout.confirm", "order_id": "order-purchase-cap-001",
                    "amount": {"currency": "USD", "value": purchase}},
        "constraints": {"max_amount": {"currency": "USD", "value": cap},
                        "tool_allowlist": ["merchant.checkout.confirm"]},
    }
    request = {
        "version": core.VERSION, "profile": core.PROFILE, "request_id": "areq-purchase-cap-001",
        "transaction_id": operation["operation_id"], "issued_at": "2026-11-12T00:00:00Z",
        "expires_at": "2026-11-12T00:05:00Z", "action": operation["action"],
        "target": operation["target"], "actor": "did:web:agent.example", "principal": "did:web:user.example",
        "runtime": "spiffe://agent.example/workload/purchase-agent", "audience": operation["target"]["audience"],
        "input_hash": object_hash(operation), "constraints": operation["constraints"],
        "evidence_refs": [{"type": "local_policy", "uri": "urn:vate:example:purchase-cap-policy",
                           "media_type": "application/json", "digest": {"alg": "sha-256", "value": "0" * 64}}],
    }
    policy = {"policy_id": "purchase-cap-example", "policy_version": "1",
              "policy_ref": "urn:vate:example:purchase-cap-policy", "allowed_actions": ["commerce.purchase"],
              "max_amount": {"currency": "USD", "value": "25.00"}}
    request["evidence_refs"][0]["digest"] = digest(encode(policy))
    return operation, request, policy


def synthetic_post(receipt: dict) -> dict:
    return {
        "version": core.VERSION, "profile": core.PROFILE, "receipt_type": "post_execution",
        "receipt_id": "postrec-purchase-cap-001", "issued_at": "2026-11-12T00:00:04Z",
        "issuer": {"id": "did:web:agent.example", "role": "runtime"},
        "admission": {"receipt_id": receipt["receipt_id"], "uri": "urn:vate:example:purchase-cap-admission",
                      "digest": digest(encode(receipt)), "decision": receipt["decision"]["outcome"]},
        "execution": {"transaction_id": receipt["request"]["transaction_id"], "started_at": "2026-11-12T00:00:02Z",
                      "finished_at": "2026-11-12T00:00:03Z", "runtime": receipt["subject"]["runtime"],
                      "effective_request_hash": receipt.get("attenuation", {}).get(
                          "effective_request_hash", receipt["request"]["input_hash"])},
        "result": {"outcome": "success", "output_hash": object_hash({"synthetic": True, "order": "order-purchase-cap-001"}),
                   "side_effects": [{"type": "commerce.purchase", "tool": "merchant.checkout.confirm",
                                     "amount": {"currency": "USD", "value": "24.50"}}], "policy_violations": []},
        "proof": {"format": "none"},
    }


def generate() -> dict[str, bytes]:
    operation, request, policy = inputs()
    verifier = core.VateVerifier(verifier_id="did:web:verifier.example", policy=policy)
    result = verifier.admit(encode(request), original=encode(operation), now=core.parse_time(EVALUATED_AT))
    need(result.effective is not None, "EXAMPLE_DID_NOT_ATTENUATE")
    post = synthetic_post(decode(result.receipt))
    linked = verifier.validate_post_execution_linkage(decode(result.receipt), post)
    need(linked["outcome"] == "success", "EXAMPLE_POST_LINKAGE_FAILED")
    files = {"original.json": result.original, "effective.json": result.effective,
             "admission-request.json": result.request, "admission-receipt.json": result.receipt,
             "core-result.json": result.core_result, "assessment.json": result.assessment,
             "post-execution.json": encode(post), "policy.json": encode(policy)}
    manifest = {"contract": MANIFEST, "evidence_kind": "synthetic-no-dispatch", "evaluated_at": EVALUATED_AT,
                "artifacts": {name: digest(raw) for name, raw in sorted(files.items())},
                "sources": {name: digest((ROOT / name).read_bytes()) for name in SOURCE_FILES}}
    files["manifest.json"] = encode(manifest)
    return files


def read_file(path: Path) -> bytes:
    """Bounded regular-file read without following a final symlink."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        need(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "NOT_A_REGULAR_FILE")
        raw = stream.read(MAX_BYTES + 1)
    need(len(raw) <= MAX_BYTES, "ARTIFACT_TOO_LARGE")
    return raw


def verify_example(directory: Path, expected_admission_bytes: bytes) -> dict:
    manifest = decode(read_file(directory / "manifest.json"))
    exact(manifest, {"contract", "evidence_kind", "evaluated_at", "artifacts", "sources"})
    need(manifest["contract"] == MANIFEST and manifest["evidence_kind"] == "synthetic-no-dispatch"
         and manifest["evaluated_at"] == EVALUATED_AT, "UNSUPPORTED_EXAMPLE")
    exact(manifest["artifacts"], ARTIFACT_FILES)
    exact(manifest["sources"], set(SOURCE_FILES))
    for name in SOURCE_FILES:
        need(manifest["sources"][name] == digest((ROOT / name).read_bytes()), "SOURCE_DIGEST_MISMATCH")
    files = {name: read_file(directory / name) for name in ARTIFACT_FILES}
    for name, raw in files.items():
        need(manifest["artifacts"][name] == digest(raw), "MANIFEST_DIGEST_MISMATCH")
    artifacts = {reference(raw)["uri"]: raw for raw in files.values()}
    assessment = assess_request_binding(files["admission-receipt.json"], artifacts,
                                        required_contract=CONTRACT,
                                        expected_admission_request_ref=reference(expected_admission_bytes))
    need(assessment["binding_requirement_met"], "REQUEST_BINDING_FAILED: " + json.dumps(assessment))
    # Python equality treats True/1 and False/0 as equal; preserve JSON types.
    need(encode(decode(files["assessment.json"])) == encode(assessment), "SAVED_ASSESSMENT_MISMATCH")
    # Reproduce the local generation separately from the content-only checker.
    verifier = core.VateVerifier(verifier_id="did:web:verifier.example", policy=decode(files["policy.json"]))
    reproduced = verifier.admit(files["admission-request.json"], original=files["original.json"],
                                 now=core.parse_time(EVALUATED_AT))
    need(reproduced.core_result == files["core-result.json"] and reproduced.receipt == files["admission-receipt.json"]
         and reproduced.effective == files["effective.json"], "GENERATION_MISMATCH")
    linked = verifier.validate_post_execution_linkage(decode(files["admission-receipt.json"]), decode(files["post-execution.json"]))
    need(linked["outcome"] == "success", "POST_LINKAGE_FAILED")
    return {"request_binding": assessment, "post_linkage": linked,
            "generation_reproduced": True, "execution_observed": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("generate")
    build.add_argument("--output", type=Path, required=True, help="New directory; existing directories are not overwritten")
    check = sub.add_parser("check")
    check.add_argument("--bundle", type=Path, required=True)
    check.add_argument("--expected-admission-request", type=Path, required=True,
                       help="Receiver-selected original admission request")
    args = parser.parse_args()
    try:
        if args.command == "generate":
            files = generate()
            args.output.mkdir(parents=True, exist_ok=False)
            for name, raw in files.items():
                (args.output / name).write_bytes(raw)
            print(json.dumps({"output": str(args.output), "files": sorted(files), "execution_observed": False}))
        else:
            result = verify_example(args.bundle, read_file(args.expected_admission_request))
            print(json.dumps(result, indent=2))
    except (Invalid, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
