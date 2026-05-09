#!/usr/bin/env python3
"""Dependency-free A2A-shaped VATE metadata adapter demo."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
EXTENSION_URI = "https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/a2a/admission/v0.2"
CORE = ROOT / "reference" / "vate-verifier-core" / "vate_verifier_core.py"
TASK_MESSAGE = ROOT / "reference" / "a2a-metadata-adapter-demo" / "task-message.example.json"


def load_core():
    spec = importlib.util.spec_from_file_location("vate_verifier_core", CORE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load verifier core from {CORE}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


core = load_core()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def resolve_local_uri(uri: str) -> Path:
    if not uri.startswith("local:"):
        raise ValueError(f"demo only resolves local: URIs, got {uri}")
    local_path = uri.removeprefix("local:")
    if not local_path or "\x00" in local_path:
        raise ValueError("local URI must contain a repository-relative path")
    relative_path = Path(local_path)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ValueError(f"local URI must not escape the repository root: {uri}")
    resolved = (ROOT / relative_path).resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"local URI must remain under the repository root: {uri}") from exc
    return resolved


def build_verifier() -> Any:
    return core.VateVerifier(
        verifier_id="did:web:verifier.example",
        policy={
            "policy_id": "merchant-purchase-al2",
            "policy_version": "2026-05-04.1",
            "policy_ref": "https://verifier.example/policies/merchant-purchase-al2/2026-05-04.1",
            "allowed_actions": ["commerce.purchase"],
            "max_amount": {
                "currency": "USD",
                "value": "25.00",
            },
        },
    )


def make_digest_mismatch_receipt(metadata: dict[str, Any]) -> dict[str, Any]:
    issued_at = "2026-05-04T03:00:30Z"
    return {
        "version": "vate-0.2",
        "profile": "VATE-AL2-Verifier-Admission-v0.2",
        "receipt_type": "admission",
        "receipt_id": "admrec-digest-mismatch",
        "issued_at": issued_at,
        "expires_at": metadata.get("expires_at", issued_at),
        "verifier": {
            "id": "did:web:verifier.example",
        },
        "request": {
            "request_id": "missing",
            "transaction_id": metadata.get("transaction_id", "missing"),
            "action": "missing",
            "input_hash": "missing",
        },
        "subject": {
            "principal": "missing",
            "actor": metadata.get("issuer", "missing"),
            "runtime": "missing",
        },
        "evidence": [
            {
                "type": "admission_request",
                "uri": metadata.get("admission_request", {}).get("uri", "missing"),
                "digest": metadata.get("admission_request", {}).get(
                    "digest",
                    {"alg": "sha-256", "value": "missing"},
                ),
                "verification": {
                    "result": "failed",
                    "checked_at": issued_at,
                    "method": "a2a-metadata-digest-check",
                    "failure_reason": "The digest-bound admission request reference did not match the artifact.",
                },
            }
        ],
        "policy": {
            "policy_id": "a2a-metadata-adapter-demo",
            "policy_version": "2026-05-04.1",
            "policy_ref": "local",
        },
        "decision": {
            "outcome": "deny",
            "reason_codes": ["DIGEST_MISMATCH", "FAIL_CLOSED"],
        },
    }


def build_post_execution_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    effective_hash = receipt.get("attenuation", {}).get(
        "effective_request_hash",
        receipt.get("request", {}).get("input_hash", "missing"),
    )
    return {
        "version": "vate-0.2",
        "profile": "VATE-AL2-Verifier-Admission-v0.2",
        "receipt_type": "post_execution",
        "receipt_id": "postrec-" + receipt["receipt_id"].removeprefix("admrec-"),
        "issued_at": "2026-05-04T03:02:30Z",
        "issuer": {
            "id": "did:web:agent.example",
            "role": "runtime",
        },
        "admission": {
            "receipt_id": receipt["receipt_id"],
            "uri": "local:generated/admission-receipts/" + receipt["receipt_id"] + ".json",
            "digest": {
                "alg": "sha-256",
                "value": core.canonical_hash(receipt).removeprefix("sha-256:"),
            },
            "decision": receipt["decision"]["outcome"],
        },
        "execution": {
            "transaction_id": receipt["request"]["transaction_id"],
            "started_at": "2026-05-04T03:01:00Z",
            "finished_at": "2026-05-04T03:02:00Z",
            "effective_request_hash": effective_hash,
            "runtime": receipt["subject"]["runtime"],
        },
        "result": {
            "outcome": "success",
            "output_hash": "sha-256:a2a-adapter-output",
            "side_effects": [],
            "policy_violations": [],
        },
    }


def adapt_task_message(task_message: dict[str, Any]) -> dict[str, Any]:
    metadata = task_message.get("metadata", {}).get(EXTENSION_URI)
    if metadata is None:
        raise ValueError("missing VATE A2A metadata extension object")
    if metadata.get("phase") != "admission_requested":
        raise ValueError(f"unsupported VATE metadata phase {metadata.get('phase')}")

    reference = metadata["admission_request"]
    admission_request = read_json(resolve_local_uri(reference["uri"]))
    verifier = build_verifier()
    if not verifier.validate_digest(admission_request, reference["digest"]):
        decision = {
            "decision": "deny",
            "reason_codes": ["DIGEST_MISMATCH", "FAIL_CLOSED"],
            "admission_receipt": make_digest_mismatch_receipt(metadata),
        }
    else:
        decision = verifier.admit(admission_request, now=core.parse_time("2026-05-04T03:00:30Z"))

    receipt = decision["admission_receipt"]
    receipt_digest = core.canonical_hash(receipt).removeprefix("sha-256:")
    response = {
        "task_id": task_message["task_id"],
        "kind": "task_response",
        "status": {
            "state": "submitted" if decision["decision"] in {"allow", "attenuate"} else "rejected"
        },
        "vate_decision": {
            "outcome": decision["decision"],
            "reason_codes": decision["reason_codes"],
        },
        "metadata": {
            EXTENSION_URI: {
                "profile": "VATE-AL2-Verifier-Admission-v0.2",
                "phase": "admission_issued",
                "transaction_id": metadata["transaction_id"],
                "assurance_level": "AL2",
                "decision": decision["decision"],
                "admission_receipt": {
                    "type": "admission_receipt",
                    "uri": "local:generated/admission-receipts/" + receipt["receipt_id"] + ".json",
                    "media_type": "application/vate-admission-receipt+json",
                    "digest": {
                        "alg": "sha-256",
                        "value": receipt_digest
                    }
                },
                "issuer": "did:web:verifier.example",
                "issued_at": receipt["issued_at"],
                "expires_at": receipt["expires_at"]
            }
        }
    }
    if decision["decision"] in {"allow", "attenuate"}:
        post_execution_receipt = build_post_execution_receipt(receipt)
        response["post_execution_metadata_example"] = {
            EXTENSION_URI: {
                "profile": "VATE-AL2-Verifier-Admission-v0.2",
                "phase": "post_execution_receipt_issued",
                "transaction_id": metadata["transaction_id"],
                "assurance_level": "AL2",
                "admission_receipt": response["metadata"][EXTENSION_URI]["admission_receipt"],
                "post_execution_receipt": {
                    "type": "post_execution_receipt",
                    "uri": "local:generated/post-execution-receipts/"
                    + post_execution_receipt["receipt_id"]
                    + ".json",
                    "media_type": "application/vate-post-execution-receipt+json",
                    "digest": {
                        "alg": "sha-256",
                        "value": core.canonical_hash(post_execution_receipt).removeprefix("sha-256:"),
                    },
                },
                "issuer": post_execution_receipt["issuer"]["id"],
                "issued_at": post_execution_receipt["issued_at"],
            }
        }
    return response


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run an A2A-shaped VATE metadata adapter demo")
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run-demo", help="run the adapter demo")
    run.add_argument("--task-message", default=str(TASK_MESSAGE), help="A2A-shaped task message JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "run-demo":
        response = adapt_task_message(read_json(Path(args.task_message)))
        json.dump(response, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    raise RuntimeError(f"unsupported command {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
