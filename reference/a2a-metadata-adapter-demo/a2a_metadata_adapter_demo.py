#!/usr/bin/env python3
"""Dependency-free A2A-shaped VATE metadata adapter demo."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reference/runtime-support"))
from vate_uri import is_absolute_uri

EXTENSION_URI = "https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/a2a/admission/v0.3"
CORE = ROOT / "reference" / "vate-verifier-core" / "vate_verifier_core.py"
TASK_MESSAGE = ROOT / "reference" / "a2a-metadata-adapter-demo" / "task-message.example.json"
PROFILE = "VATE-AL2-Verifier-Admission-v0.3"
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_PROFILE_HASH = "sha-256:" + ("0" * 64)
SAFE_DIGEST = {"alg": "sha-256", "value": "0" * 64}
INLINE_A2A_TASK_MESSAGE_URI = "inline:a2a-task-message"
INLINE_A2A_METADATA_URI = "inline:a2a-metadata"
# JSON null is a supplied input, distinct from an omitted failure source.
_SOURCE_NOT_PROVIDED = object()


def load_core():
    spec = importlib.util.spec_from_file_location("vate_verifier_core", CORE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load verifier core from {CORE}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


core = load_core()
binding = core.request_binding_module()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_raw(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        binding.need(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "NOT_A_REGULAR_FILE")
        raw = stream.read(binding.MAX_BYTES + 1)
    binding.need(len(raw) <= binding.MAX_BYTES, "ARTIFACT_TOO_LARGE")
    return raw


def resolve_local_uri(uri: str) -> Path:
    if not uri.startswith("local:"):
        raise ValueError(f"demo only resolves local: URIs, got {uri}")
    local_path = uri.removeprefix("local:")
    if not local_path or "\x00" in local_path:
        raise ValueError("local URI must contain a repository-relative path")
    relative_path = Path(local_path)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ValueError(f"local URI must not escape the repository root: {uri}")
    candidate = ROOT
    for part in relative_path.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValueError("local URI must not use symlinks")
    resolved = candidate.resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"local URI must remain under the repository root: {uri}") from exc
    return candidate


def original_request_bytes(task_message: dict[str, Any]) -> bytes:
    """Demo envelope transport; the ordinary VATE/A2A metadata is unchanged."""
    declaration = task_message.get("demo_request_binding")
    binding.exact(declaration, {"contract", "original_ref"})
    binding.need(declaration["contract"] == binding.CONTRACT, "UNSUPPORTED_BINDING_CONTRACT")
    ref = declaration["original_ref"]
    binding.exact(ref, {"uri", "media_type", "digest"})
    binding.text(ref["uri"])
    binding.need(ref["media_type"] == "application/json" and is_digest_descriptor(ref["digest"]),
                 "SCHEMA_INVALID")
    binding.exact(ref["digest"], {"alg", "value"})
    raw = read_raw(resolve_local_uri(ref["uri"]))
    binding.need(binding.digest(raw) == ref["digest"], "ORIGINAL_ARTIFACT_DIGEST_MISMATCH")
    return raw


def is_digest_descriptor(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("alg") == "sha-256"
        and isinstance(value.get("value"), str)
        and SHA256_HEX_RE.fullmatch(value["value"]) is not None
    )


def extension_area_failures(value: Any, label: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{label} must be an object"]
    if any(not isinstance(key, str) or not (
        re.fullmatch(r"x_[A-Za-z0-9_.-]+", key) or is_absolute_uri(key)
    ) for key in value):
        return [f"{label} keys must be URI strings or x_ names"]
    return []


def artifact_reference_failures(
    value: Any,
    *,
    label: str,
    expected_type: str | None = None,
    expected_media_type: str | None = None,
    evidence: bool = False,
) -> list[str]:
    failures: list[str] = []
    if not isinstance(value, dict):
        return [f"{label} must be an object"]
    allowed = {"type", "uri", "media_type", "digest"}
    if evidence:
        allowed |= {"signature_profile", "extensions", "annotations"}
    if set(value) - allowed:
        failures.append(f"{label} contains unknown fields")
    if not isinstance(value.get("type"), str) or not value["type"] or (
        expected_type is not None and value["type"] != expected_type
    ):
        failures.append(f"{label}.type must be {expected_type or 'a non-empty string'}")
    uri = value.get("uri")
    if not is_absolute_uri(uri):
        failures.append(f"{label}.uri must be a URI with a scheme")
    media_type = value.get("media_type")
    if not isinstance(media_type, str) or not media_type or (
        expected_media_type is not None and media_type != expected_media_type
    ):
        failures.append(f"{label}.media_type must be {expected_media_type or 'a non-empty string'}")
    if not is_digest_descriptor(value.get("digest")) or set(value["digest"]) != {"alg", "value"}:
        failures.append(f"{label}.digest must be a sha-256 lowercase hex digest descriptor")
    if evidence:
        if "extensions" in value:
            failures.extend(extension_area_failures(value["extensions"], f"{label}.extensions"))
        if "annotations" in value and not isinstance(value["annotations"], dict):
            failures.append(f"{label}.annotations must be an object")
        if "signature_profile" in value:
            profile = value["signature_profile"]
            if not isinstance(profile, dict) or set(profile) != {"format", "canonicalization", "required_headers"}:
                failures.append(f"{label}.signature_profile has an invalid shape")
            else:
                headers = profile["required_headers"]
                if any(not isinstance(profile[key], str) or not profile[key] for key in ("format", "canonicalization")) or (
                    not isinstance(headers, list) or not headers or
                    any(not isinstance(header, str) or not header for header in headers)
                ):
                    failures.append(f"{label}.signature_profile contains invalid values")
    return failures


def admission_requested_metadata_failures(metadata: Any) -> list[str]:
    failures: list[str] = []
    if not isinstance(metadata, dict):
        return ["metadata extension must be an object"]
    allowed = {"profile", "phase", "transaction_id", "assurance_level", "decision", "admission_request",
               "admission_receipt", "post_execution_receipt", "policy_snapshot", "evidence_refs",
               "issuer", "issued_at", "expires_at", "extensions", "annotations"}
    if set(metadata) - allowed:
        failures.append("metadata extension contains unknown core fields")
    if metadata.get("profile") != PROFILE:
        failures.append("profile must be VATE-AL2-Verifier-Admission-v0.3")
    if metadata.get("phase") != "admission_requested":
        failures.append("phase must be admission_requested")
    if metadata.get("assurance_level") != "AL2":
        failures.append("assurance_level must be AL2")
    for field in ("transaction_id", "issuer"):
        if not isinstance(metadata.get(field), str) or not metadata.get(field):
            failures.append(f"{field} must be a non-empty string")
    for field in ("issued_at", "expires_at"):
        if field == "issued_at" or field in metadata:
            if core.safe_parse_time(metadata.get(field)) is None:
                failures.append(f"{field} must be a supported RFC 3339 timestamp")
    if "decision" in metadata and metadata["decision"] not in ("allow", "attenuate", "deny"):
        failures.append("decision must be allow, attenuate, or deny")
    for field in ("admission_receipt", "post_execution_receipt", "policy_snapshot"):
        if field in metadata:
            failures.extend(artifact_reference_failures(metadata[field], label=field))
    if "evidence_refs" in metadata:
        if not isinstance(metadata["evidence_refs"], list):
            failures.append("evidence_refs must be an array")
        else:
            for index, reference in enumerate(metadata["evidence_refs"]):
                failures.extend(artifact_reference_failures(reference, label=f"evidence_refs[{index}]", evidence=True))
    if "extensions" in metadata:
        failures.extend(extension_area_failures(metadata["extensions"], "extensions"))
    if "annotations" in metadata and not isinstance(metadata["annotations"], dict):
        failures.append("annotations must be an object")
    failures.extend(
        artifact_reference_failures(
            metadata.get("admission_request"),
            label="admission_request",
            expected_type="admission_request",
            expected_media_type="application/vate-admission-request+json",
        )
    )
    return failures


def metadata_string(metadata: Any, field: str, fallback: str) -> str:
    if isinstance(metadata, dict) and isinstance(metadata.get(field), str) and metadata[field]:
        return metadata[field]
    return fallback


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
    return make_fail_closed_receipt(
        metadata,
        receipt_id="admrec-digest-mismatch",
        reason_codes=["DIGEST_MISMATCH", "FAIL_CLOSED"],
        failure_reason="The digest-bound admission request reference did not match the artifact.",
    )


def make_schema_invalid_receipt(
    metadata: Any,
    failure_reason: str,
    *,
    source_artifact: Any = _SOURCE_NOT_PROVIDED,
) -> dict[str, Any]:
    receipt_id = "admrec-schema-invalid-" + core.safe_digest_value(
        {
            "failure_reason": failure_reason,
            "source": source_artifact if source_artifact is not _SOURCE_NOT_PROVIDED else metadata,
        }
    )
    return make_fail_closed_receipt(
        metadata,
        receipt_id=receipt_id,
        reason_codes=["SCHEMA_INVALID", "FAIL_CLOSED"],
        failure_reason=failure_reason,
        source_artifact=source_artifact,
    )


def make_schema_invalid_decision(
    metadata: Any,
    failure_reason: str,
    *,
    source_artifact: Any = _SOURCE_NOT_PROVIDED,
    source_uri: str | None = None,
) -> dict[str, Any]:
    decision = {
        "decision": "deny",
        "reason_codes": ["SCHEMA_INVALID", "FAIL_CLOSED"],
        "admission_receipt": make_schema_invalid_receipt(
            metadata,
            failure_reason,
            source_artifact=source_artifact,
        ),
    }
    if source_artifact is not _SOURCE_NOT_PROVIDED:
        decision["demo_local_failure_source"] = make_demo_local_failure_source(
            source_artifact,
            source_uri=source_uri,
            failure_reason=failure_reason,
        )
    return decision


def failure_source_kind(source_uri: str | None) -> str:
    if source_uri == INLINE_A2A_TASK_MESSAGE_URI:
        return "a2a_task_message"
    if source_uri == INLINE_A2A_METADATA_URI:
        return "a2a_metadata"
    return "artifact"


def make_demo_local_failure_source(
    source_artifact: Any,
    *,
    source_uri: str | None,
    failure_reason: str,
) -> dict[str, Any]:
    evidence_uri = source_uri or INLINE_A2A_METADATA_URI
    return {
        "kind": failure_source_kind(evidence_uri),
        "uri": evidence_uri,
        "media_type": "application/json",
        "digest": {"alg": "sha-256", "value": core.safe_digest_value(source_artifact)},
        "failure_reason": failure_reason,
    }


def make_fail_closed_receipt(
    metadata: Any,
    *,
    receipt_id: str,
    reason_codes: list[str],
    failure_reason: str,
    source_artifact: Any = _SOURCE_NOT_PROVIDED,
) -> dict[str, Any]:
    issued_at = "2026-05-04T03:00:30Z"
    reference = metadata.get("admission_request", {}) if isinstance(metadata, dict) else {}
    if source_artifact is not _SOURCE_NOT_PROVIDED:
        # Demo-local source binding lives on the A2A response envelope, not in
        # the admission receipt schema contract.
        evidence_items = []
    elif isinstance(reference, dict) and is_digest_descriptor(reference.get("digest")):
        digest = reference["digest"]
        evidence_uri = reference.get("uri", "missing")
        evidence_items = [
            {
                "type": "admission_request",
                "uri": evidence_uri,
                "digest": digest,
                "verification": {
                    "result": "failed",
                    "checked_at": issued_at,
                    "method": "a2a-metadata-digest-check",
                    "failure_reason": failure_reason,
                },
            }
        ]
    else:
        evidence_items = []
    receipt = {
        "version": "vate-0.3",
        "profile": PROFILE,
        "receipt_type": "admission",
        "receipt_id": receipt_id,
        "issued_at": issued_at,
        "expires_at": issued_at,
        "verifier": {
            "id": "did:web:verifier.example",
        },
        "request": {
            "request_id": "missing",
            "transaction_id": metadata_string(metadata, "transaction_id", "missing"),
            "action": "missing",
            "input_hash": SAFE_PROFILE_HASH,
        },
        "subject": {
            "principal": "missing",
            "actor": metadata_string(metadata, "issuer", "missing"),
            "runtime": "missing",
        },
        "evidence": evidence_items,
        "policy": {
            "policy_id": "a2a-metadata-adapter-demo",
            "policy_version": "2026-05-04.1",
            "policy_ref": "local",
        },
        "decision": {
            "outcome": "deny",
            "reason_codes": reason_codes,
        },
    }
    return receipt


def generated_receipt_uri(receipt_type: str, receipt_id: str) -> str:
    """Illustrative reference: preserve the ID as one UTF-8 URI path segment."""
    directory = {"admission": "admission-receipts", "post_execution": "post-execution-receipts"}[receipt_type]
    return "local:generated/" + directory + "/" + quote(receipt_id, safe="") + ".json"


def build_post_execution_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    effective_hash = receipt.get("attenuation", {}).get(
        "effective_request_hash",
        receipt.get("request", {}).get("input_hash", "missing"),
    )
    return {
        "version": "vate-0.3",
        "profile": "VATE-AL2-Verifier-Admission-v0.3",
        "receipt_type": "post_execution",
        "receipt_id": "postrec-" + receipt["receipt_id"].removeprefix("admrec-"),
        "issued_at": "2026-05-04T03:02:30Z",
        "issuer": {
            "id": "did:web:agent.example",
            "role": "runtime",
        },
        "admission": {
            "receipt_id": receipt["receipt_id"],
            "uri": generated_receipt_uri("admission", receipt["receipt_id"]),
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
            "output_hash": core.canonical_hash({"a2a_adapter_output": receipt["receipt_id"]}),
            "side_effects": [],
            "policy_violations": [],
        },
    }


def task_string(task_message: Any, field: str, fallback: str) -> str:
    if isinstance(task_message, dict) and isinstance(task_message.get(field), str) and task_message[field]:
        return task_message[field]
    return fallback


def make_task_response(
    task_message: Any,
    metadata: Any,
    decision: dict[str, Any],
) -> dict[str, Any]:
    receipt = decision["admission_receipt"]
    receipt_digest = core.canonical_hash(receipt).removeprefix("sha-256:")
    response = {
        "task_id": task_string(task_message, "task_id", "missing"),
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
                "profile": "VATE-AL2-Verifier-Admission-v0.3",
                "phase": "admission_issued",
                "transaction_id": metadata_string(metadata, "transaction_id", "missing"),
                "assurance_level": "AL2",
                "decision": decision["decision"],
                "admission_receipt": {
                    "type": "admission_receipt",
                    "uri": generated_receipt_uri("admission", receipt["receipt_id"]),
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
    if "demo_local_failure_source" in decision:
        response["demo_local_failure_source"] = decision["demo_local_failure_source"]
    if "request_binding_assessment" in decision:
        response["request_binding_assessment"] = decision["request_binding_assessment"]
    if decision["decision"] in {"allow", "attenuate"}:
        post_execution_receipt = build_post_execution_receipt(receipt)
        response["post_execution_metadata_example"] = {
            EXTENSION_URI: {
                "profile": "VATE-AL2-Verifier-Admission-v0.3",
                "phase": "post_execution_receipt_issued",
                "transaction_id": metadata_string(metadata, "transaction_id", "missing"),
                "assurance_level": "AL2",
                "admission_receipt": response["metadata"][EXTENSION_URI]["admission_receipt"],
                "post_execution_receipt": {
                    "type": "post_execution_receipt",
                    "uri": generated_receipt_uri("post_execution", post_execution_receipt["receipt_id"]),
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


def adapt_task_message(task_message: Any) -> dict[str, Any]:
    if not isinstance(task_message, dict):
        decision = make_schema_invalid_decision(
            None,
            "task message must be a JSON object",
            source_artifact=task_message,
            source_uri=INLINE_A2A_TASK_MESSAGE_URI,
        )
        return make_task_response(task_message, None, decision)

    metadata_container = task_message.get("metadata")
    metadata = metadata_container.get(EXTENSION_URI) if isinstance(metadata_container, dict) else None
    if metadata is None:
        decision = make_schema_invalid_decision(
            None,
            "missing VATE A2A metadata extension object",
            source_artifact=task_message,
            source_uri=INLINE_A2A_TASK_MESSAGE_URI,
        )
        return make_task_response(task_message, None, decision)

    verifier = build_verifier()
    metadata_failures = admission_requested_metadata_failures(metadata)
    if metadata_failures:
        decision = make_schema_invalid_decision(
            metadata,
            "; ".join(metadata_failures),
            source_artifact=metadata,
            source_uri=INLINE_A2A_METADATA_URI,
        )
    else:
        reference = metadata["admission_request"]
        try:
            admission_bytes = read_raw(resolve_local_uri(reference["uri"]))
            admission_request = binding.decode(admission_bytes)
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            decision = {
                "decision": "deny",
                "reason_codes": ["SCHEMA_INVALID", "FAIL_CLOSED"],
                "admission_receipt": make_schema_invalid_receipt(metadata, str(exc)),
            }
        else:
            if not verifier.validate_digest(admission_request, reference["digest"]):
                decision = {
                    "decision": "deny",
                    "reason_codes": ["DIGEST_MISMATCH", "FAIL_CLOSED"],
                    "admission_receipt": make_digest_mismatch_receipt(metadata),
                }
            elif not isinstance(admission_request, dict):
                decision = {
                    "decision": "deny",
                    "reason_codes": ["SCHEMA_INVALID", "FAIL_CLOSED"],
                    "admission_receipt": make_schema_invalid_receipt(
                        metadata,
                        "digest-bound admission request artifact was not a JSON object",
                    ),
                }
            else:
                try:
                    binding.need(metadata["transaction_id"] == admission_request.get("transaction_id"),
                                 "TRANSACTION_MISMATCH")
                    original = original_request_bytes(task_message)
                    result = verifier.admit(admission_bytes, original=original,
                                            now=core.parse_time("2026-05-04T03:00:30Z"))
                    receipt = binding.decode(result.receipt)
                    decision = {
                        "decision": receipt["decision"]["outcome"],
                        "reason_codes": receipt["decision"]["reason_codes"],
                        "admission_receipt": receipt,
                        "request_binding_assessment": binding.decode(result.assessment),
                    }
                except (ValueError, TypeError, OSError) as exc:
                    decision = {
                        "decision": "deny", "reason_codes": ["SCHEMA_INVALID", "FAIL_CLOSED"],
                        "admission_receipt": make_schema_invalid_receipt(metadata, str(exc)),
                    }

    return make_task_response(task_message, metadata, decision)


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
