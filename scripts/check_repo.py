#!/usr/bin/env python3
"""Repository sanity checker for the public trust envelope draft repository.

This script intentionally stays dependency-free and fast. It validates obvious
shape mismatches, runs the educational demo, and checks expected failure cases.
It is not a full JSON Schema validator. For strict schema validation, use
scripts/check_repo_strict.py when jsonschema is available locally.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import math
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "reference" / "minimal-al2-demo" / "trust_envelope_demo.py"
HTTP_DEMO = ROOT / "reference" / "http-verifier-demo" / "http_verifier_demo.py"
VATE_CONFORMANCE = ROOT / "scripts" / "vate_conformance.py"
PULSE_EXTERNAL_SUT_STARTER_CHECK = ROOT / "scripts" / "check_pulse_external_sut_starter.py"
VATE_CORE = ROOT / "reference" / "vate-verifier-core" / "vate_verifier_core.py"
A2A_ADAPTER = ROOT / "reference" / "a2a-metadata-adapter-demo" / "a2a_metadata_adapter_demo.py"
EVIDENCE_VOCABULARY = ROOT / "registries" / "evidence-vocabulary.v0.3.json"
ARTIFACT_VERSIONING_DOC = ROOT / "docs" / "conformance" / "artifact-versioning.md"
JOSE_PROFILE_NOTES_DOC = ROOT / "docs" / "profiles" / "vate-jose-proof-profile-notes-2026-09.md"
NAMESPACE_MIGRATION_DOC = ROOT / "docs" / "namespace-migration.md"
EXTENSION_FIELDS_DOC = ROOT / "docs" / "extension-fields.md"
A2A_METADATA_BINDING_DOC = ROOT / "docs" / "a2a-metadata-binding-v0.3.md"
A2A_EXTENSION_SKETCH_DOC = ROOT / "docs" / "a2a-v1-extension-sketch-2026-05.md"
EXTERNAL_SUT_QUICKSTART_DOC = ROOT / "docs" / "conformance" / "external-sut-quickstart.md"
SUT_ADAPTER_CONTRACT_DOC = ROOT / "docs" / "conformance" / "sut-adapter-contract.md"
AL2_CORPUS_README = ROOT / "conformance" / "al2-vate-v0.3" / "README.md"
V03_RELEASE_NOTES = ROOT / "docs" / "release-notes" / "v0.3.0.md"
V031_RELEASE_NOTES = ROOT / "docs" / "release-notes" / "v0.3.1.md"
A2A_SIGNED_AGENT_CARD_PROOF = ROOT / "examples" / "jose" / "jose-detached-a2a-agent-card.example.json"
A2A_SIGNED_AGENT_CARD_PAYLOAD = ROOT / "examples" / "a2a" / "agent-card-v1-vate-extension.example.json"
JSON_ONLY_FILES = [
    "reference/a2a-metadata-adapter-demo/agent-card-extension.example.json",
    "examples/a2a/agent-card-v1-vate-extension.example.json",
]
EXAMPLE_PAIRS = [
    ("registries/evidence-vocabulary.v0.3.json", "schemas/evidence-vocabulary.schema.json"),
    ("examples/passport-credential.example.json", "schemas/passport-credential.schema.json"),
    ("examples/runtime-proof.example.json", "schemas/runtime-proof.schema.json"),
    ("examples/mission-permit.example.json", "schemas/mission-permit.schema.json"),
    ("examples/execution-receipt.example.json", "schemas/execution-receipt.schema.json"),
    ("examples/artifact-reference.example.json", "schemas/artifact-reference.schema.json"),
    ("examples/evidence-reference.example.json", "schemas/evidence-reference.schema.json"),
    ("examples/admission-request.example.json", "schemas/admission-request.schema.json"),
    ("examples/admission-request-runtime-proof-stale.example.json", "schemas/admission-request.schema.json"),
    ("examples/transport/mcp-oauth-admission-request.example.json", "schemas/admission-request.schema.json"),
    ("examples/transport/mcp-oauth-overscope-admission-request.example.json", "schemas/admission-request.schema.json"),
    ("examples/transport/mcp-oauth-upstream-denied-admission-request.example.json", "schemas/admission-request.schema.json"),
    ("examples/transport/mcp-oauth-token-passthrough-admission-request.example.json", "schemas/admission-request.schema.json"),
    ("examples/transport/mcp-oauth-resource-indicator-drift-admission-request.example.json", "schemas/admission-request.schema.json"),
    ("examples/transport/mcp-oauth-tool-class-mismatch-admission-request.example.json", "schemas/admission-request.schema.json"),
    ("examples/a2a/metadata-admission-requested.json", "schemas/a2a-vate-metadata.schema.json"),
    (
        "examples/a2a/metadata-admission-requested-with-signed-agent-card.json",
        "schemas/a2a-vate-metadata.schema.json",
    ),
    ("examples/a2a/metadata-admission-issued.json", "schemas/a2a-vate-metadata.schema.json"),
    ("examples/a2a/metadata-post-execution-issued.json", "schemas/a2a-vate-metadata.schema.json"),
    ("examples/receipts/admission-allow.example.json", "schemas/admission-receipt.schema.json"),
    ("examples/receipts/admission-attenuate-max-amount.example.json", "schemas/admission-receipt.schema.json"),
    ("examples/receipts/admission-deny-expired-permit.example.json", "schemas/admission-receipt.schema.json"),
    ("examples/receipts/admission-deny-audience-mismatch.example.json", "schemas/admission-receipt.schema.json"),
    ("examples/receipts/post-execution-success.example.json", "schemas/post-execution-receipt.schema.json"),
    ("examples/attenuation-tool-allowlist.example.json", "schemas/attenuation-effect.schema.json"),
    ("examples/attenuation-max-amount.example.json", "schemas/attenuation-effect.schema.json"),
    ("examples/attenuation-approval.example.json", "schemas/attenuation-effect.schema.json"),
    ("examples/trust-bundle.example.json", "schemas/trust-bundle.schema.json"),
    ("examples/trust-bundle-agent-card.example.json", "schemas/trust-bundle.schema.json"),
    ("examples/conformance-report.example.json", "schemas/conformance-report.schema.json"),
    ("examples/implementation-report.example.json", "schemas/implementation-report.schema.json"),
    ("examples/report-bundle-verification.example.json", "schemas/report-bundle-verification.schema.json"),
    ("examples/conformance/sut-results-pass.example.json", "schemas/sut-result.schema.json"),
    ("examples/external-sut-template/starter-sut-result.template.json", "schemas/sut-result.schema.json"),
    ("conformance/al2-vate-v0.3/corpus.json", "schemas/conformance-corpus.schema.json"),
    ("examples/policies/merchant-purchase-al2-policy-snapshot.example.json", "schemas/policy-snapshot.schema.json"),
    ("examples/policies/al2-repo-merge-policy-snapshot.example.json", "schemas/policy-snapshot.schema.json"),
    ("examples/status-bundle.example.json", "schemas/status-bundle.schema.json"),
    ("examples/status-entry.example.json", "schemas/status-entry.schema.json"),
    ("examples/status-event.example.json", "schemas/status-event.schema.json"),
    ("policies/al2-http-verifier.example.json", "schemas/verifier-policy.schema.json"),
    (
        "conformance/al2-http/positive/allow-active/expected-report.json",
        "conformance/al2-http/verification-report.schema.json",
    ),
    (
        "conformance/al2-http/positive/attenuate-tool-narrow/expected-report.json",
        "conformance/al2-http/verification-report.schema.json",
    ),
    (
        "conformance/al2-http/negative/deny-revoked/expected-report.json",
        "conformance/al2-http/verification-report.schema.json",
    ),
    (
        "conformance/al2-http/negative/deny-unknown-effect/expected-report.json",
        "conformance/al2-http/verification-report.schema.json",
    ),
    (
        "conformance/al2-vate-v0.3/cases/allow-valid-admission.json",
        "conformance/al2-vate-v0.3/conformance-case.schema.json",
    ),
    (
        "conformance/al2-vate-v0.3/cases/attenuate-max-amount.json",
        "conformance/al2-vate-v0.3/conformance-case.schema.json",
    ),
    (
        "conformance/al2-vate-v0.3/cases/deny-expired-permit.json",
        "conformance/al2-vate-v0.3/conformance-case.schema.json",
    ),
    (
        "conformance/al2-vate-v0.3/cases/deny-audience-mismatch.json",
        "conformance/al2-vate-v0.3/conformance-case.schema.json",
    ),
    (
        "conformance/al2-vate-v0.3/cases/post-execution-linkage-success.json",
        "conformance/al2-vate-v0.3/conformance-case.schema.json",
    ),
]


def value_at_path(value: object, path: tuple[object, ...]) -> object:
    current = value
    for part in path:
        current = current[part]  # type: ignore[index]
    return current


def path_exists(value: object, path: tuple[object, ...]) -> bool:
    try:
        value_at_path(value, path)
        return True
    except (KeyError, IndexError, TypeError):
        return False


def iter_example_pairs() -> list[tuple[str, str]]:
    pairs = list(EXAMPLE_PAIRS)
    pairs.extend(
        (str(path.relative_to(ROOT)), "schemas/admission-receipt.schema.json")
        for path in sorted((ROOT / "examples" / "receipts").glob("admission-*.example.json"))
    )
    pairs.extend(
        (str(path.relative_to(ROOT)), "schemas/post-execution-receipt.schema.json")
        for path in sorted((ROOT / "examples" / "receipts").glob("post-execution*.example.json"))
    )
    pairs.extend(
        (str(path.relative_to(ROOT)), "schemas/policy-snapshot.schema.json")
        for path in sorted((ROOT / "examples" / "policies").glob("*.example.json"))
    )
    pairs.extend(
        (str(path.relative_to(ROOT)), "schemas/jose-proof-fixture.schema.json")
        for path in sorted((ROOT / "examples" / "jose").glob("jose-*.example.json"))
    )
    pairs.extend(
        (str(path.relative_to(ROOT)), "schemas/admission-request.schema.json")
        for path in sorted((ROOT / "examples" / "transport").glob("*admission-request*.json"))
    )
    pairs.extend(
        (str(path.relative_to(ROOT)), "schemas/admission-request.schema.json")
        for path in sorted((ROOT / "examples" / "interop").glob("**/vate-admission-request*.json"))
    )
    pairs.extend(
        (str(path.relative_to(ROOT)), "schemas/admission-receipt.schema.json")
        for path in sorted((ROOT / "examples" / "interop").glob("**/vate-admission-receipt*.json"))
    )
    pairs.extend(
        (str(path.relative_to(ROOT)), "schemas/post-execution-receipt.schema.json")
        for path in sorted((ROOT / "examples" / "interop").glob("**/vate-post-execution-receipt*.json"))
    )
    pairs.extend(
        (str(path.relative_to(ROOT)), "conformance/al2-vate-v0.3/conformance-case.schema.json")
        for path in sorted((ROOT / "conformance" / "al2-vate-v0.3" / "cases").glob("*.json"))
    )
    return sorted(set(pairs))


def resolve_local_ref(root_schema: dict, schema: dict) -> dict:
    ref = schema.get("$ref")
    if not ref or not ref.startswith("#/"):
        return schema
    current = root_schema
    for part in ref[2:].split("/"):
        current = current[part]
    return current


def check(root_schema: dict, schema: dict, value, path: str = "root") -> list[str]:
    schema = resolve_local_ref(root_schema, schema)
    errors = []
    expected_type = schema.get("type")

    if expected_type == "object":
        if not isinstance(value, dict):
            return [f"{path}: expected object"]
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing required key {key}")
        properties = schema.get("properties", {})
        for key, child in properties.items():
            if key in value:
                errors.extend(check(root_schema, child, value[key], f"{path}.{key}"))
        return errors

    if expected_type == "array":
        if not isinstance(value, list):
            return [f"{path}: expected array"]
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: expected at least {schema['minItems']} items")
        item_schema = schema.get("items")
        if item_schema:
            for index, item in enumerate(value):
                errors.extend(check(root_schema, item_schema, item, f"{path}[{index}]"))
        return errors

    if expected_type == "string":
        if not isinstance(value, str):
            return [f"{path}: expected string"]
        if "const" in schema and value != schema["const"]:
            errors.append(f"{path}: expected const {schema['const']}")
        if "enum" in schema and value not in schema["enum"]:
            errors.append(f"{path}: expected one of {schema['enum']}")
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: expected minLength {schema['minLength']}")
        if schema.get("format") == "date-time":
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                errors.append(f"{path}: invalid date-time {value}")
        if schema.get("format") == "uri" and "://" not in value:
            errors.append(f"{path}: invalid uri {value}")
        return errors

    if expected_type == "number":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return [f"{path}: expected number"]
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: expected >= {schema['minimum']}")
        return errors

    if expected_type == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            return [f"{path}: expected integer"]
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: expected >= {schema['minimum']}")
        return errors

    if expected_type == "boolean":
        if not isinstance(value, bool):
            return [f"{path}: expected boolean"]
        return errors

    return errors


def run(cmd: list[str], *, cwd: Path = ROOT) -> None:
    subprocess.run(cmd, cwd=cwd, check=True)


def historical_pulse_source_is_available() -> bool:
    if not (ROOT / ".git").exists():
        return False
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(ROOT),
                "cat-file",
                "-e",
                "5a37f87de0190da44e619b1800261637e83dd7ed^{commit}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except FileNotFoundError:
        return False
    return result.returncode == 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-full-history",
        action="store_true",
        help=(
            "fail unless the historical VATE source commit pinned by the Pulse "
            "starter can be reloaded"
        ),
    )
    return parser.parse_args()


def run_expect_failure(cmd: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess:
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode == 0:
        raise AssertionError(f"expected command to fail: {' '.join(cmd)}")
    return result


def assert_report_error_contains(path: Path, expected: str) -> None:
    report = json.loads(path.read_text(encoding="utf-8"))
    errors = [str(error) for error in report.get("fatal_errors", [])]
    for case in report.get("cases", []):
        if isinstance(case, dict):
            errors.extend(str(error) for error in case.get("failures", []))
    if not any(expected in error for error in errors):
        raise AssertionError(f"{path}: expected report error containing {expected!r}")


def assert_bundle_check(path: Path, name: str, expected_pass: bool) -> None:
    report = json.loads(path.read_text(encoding="utf-8"))
    check = next(
        (
            item
            for item in report.get("checks", [])
            if isinstance(item, dict) and item.get("name") == name
        ),
        None,
    )
    if check is None or check.get("pass") is not expected_pass:
        raise AssertionError(f"{path}: expected bundle check {name!r} pass={expected_pass}")


def canonical_json_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def b64url_encode_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def rewrite_detached_jws_payload_digest(proof: dict, payload: dict) -> None:
    payload_b64u = b64url_encode_bytes(canonical_json_bytes(payload))
    proof["detached_payload_b64u"] = payload_b64u
    proof["detached_payload_sha256"] = {
        "alg": "sha-256",
        "value": hashlib.sha256(canonical_json_bytes(payload)).hexdigest(),
    }
    signing_input = f"{proof['protected_b64u']}.{payload_b64u}".encode("ascii")
    proof["signing_input_sha256"] = {
        "alg": "sha-256",
        "value": hashlib.sha256(signing_input).hexdigest(),
    }


def write_sut_result_without_jose_proof_artifacts(path: Path) -> None:
    sut_results = json.loads((ROOT / "examples" / "conformance" / "sut-results-pass.example.json").read_text())
    for result in sut_results.get("results", []):
        case_id = result.get("case_id")
        if isinstance(case_id, str) and "jose" in case_id:
            artifacts = result.get("artifacts")
            if isinstance(artifacts, dict):
                artifacts.pop("proof_artifacts", None)
    path.write_text(json.dumps(sut_results, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_sut_result_without_context_bindings(path: Path) -> None:
    sut_results = json.loads((ROOT / "examples" / "conformance" / "sut-results-pass.example.json").read_text())
    for result in sut_results.get("results", []):
        artifacts = result.get("artifacts")
        if not isinstance(artifacts, dict):
            continue
        contexts = artifacts.get("verification_context")
        if not isinstance(contexts, list):
            continue
        for context in contexts:
            if isinstance(context, dict):
                context.pop("context_bindings", None)
    path.write_text(json.dumps(sut_results, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_sut_result_with_conflicting_duplicate_context_binding(
    path: Path,
    *,
    conflicting_first: bool,
) -> None:
    sut_results = json.loads((ROOT / "examples" / "conformance" / "sut-results-pass.example.json").read_text())
    for result in sut_results.get("results", []):
        artifacts = result.get("artifacts")
        if not isinstance(artifacts, dict):
            continue
        contexts = artifacts.get("verification_context")
        if not isinstance(contexts, list):
            continue
        for context in contexts:
            if not isinstance(context, dict):
                continue
            bindings = context.get("context_bindings")
            if not isinstance(bindings, list):
                continue
            for index, binding in enumerate(bindings):
                if not isinstance(binding, dict):
                    continue
                digest = binding.get("digest")
                if not isinstance(digest, dict) or not isinstance(digest.get("value"), str):
                    continue
                correct = json.loads(json.dumps(binding))
                conflicting = json.loads(json.dumps(binding))
                current_digest = conflicting["digest"]["value"]
                conflicting["digest"]["value"] = "f" * 64 if current_digest == "0" * 64 else "0" * 64
                replacement = [conflicting, correct] if conflicting_first else [correct, conflicting]
                bindings[index:index + 1] = replacement
                path.write_text(json.dumps(sut_results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                return
    raise AssertionError("passing SUT result has no digest-bound verification context entry")


def write_sut_result_with_conflicting_duplicate_artifact_entry(
    path: Path,
    *,
    artifact_field: str,
    conflicting_first: bool,
) -> None:
    sut_results = json.loads((ROOT / "examples" / "conformance" / "sut-results-pass.example.json").read_text())
    for result in sut_results.get("results", []):
        artifacts = result.get("artifacts")
        if not isinstance(artifacts, dict):
            continue
        entries = artifacts.get(artifact_field)
        if not isinstance(entries, list):
            continue
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            digest = entry.get("digest")
            if not isinstance(digest, dict) or not isinstance(digest.get("value"), str):
                continue
            correct = json.loads(json.dumps(entry))
            conflicting = json.loads(json.dumps(entry))
            current_digest = conflicting["digest"]["value"]
            conflicting["digest"]["value"] = "f" * 64 if current_digest == "0" * 64 else "0" * 64
            replacement = [conflicting, correct] if conflicting_first else [correct, conflicting]
            entries[index:index + 1] = replacement
            path.write_text(json.dumps(sut_results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            return
    raise AssertionError(f"passing SUT result has no digest-bound {artifact_field} entry")


def generated_receipt_ref(path: Path, media_type: str) -> dict:
    return {
        "uri": f"https://independent.example/vate/{path.name}",
        "local_path": path.name,
        "media_type": media_type,
        "digest": {
            "alg": "sha-256",
            "value": hashlib.sha256(path.read_bytes()).hexdigest(),
        },
    }


def write_sut_result_with_generated_receipts(
    path: Path,
    *,
    tamper_allow_outcome: bool,
) -> None:
    sut_results = json.loads((ROOT / "examples" / "conformance" / "sut-results-pass.example.json").read_text())
    results = {
        result.get("case_id"): result
        for result in sut_results.get("results", [])
        if isinstance(result, dict)
    }

    generated_allow = json.loads((ROOT / "examples" / "receipts" / "admission-allow.example.json").read_text())
    generated_allow["receipt_id"] = "admrec-independent-allow-001"
    generated_allow["verifier"] = {
        "id": "did:web:independent.example",
        "key_id": "did:web:independent.example#key-1",
    }
    generated_allow["decision"]["human_readable_summary"] = "Independent verifier produced the same decision."
    if tamper_allow_outcome:
        generated_allow["decision"]["outcome"] = "deny"
    generated_allow_path = path.parent / (
        "generated-admission-allow-tampered.json" if tamper_allow_outcome else "generated-admission-allow.json"
    )
    generated_allow_path.write_text(json.dumps(generated_allow, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    allow_result = results["allow-valid-admission"]
    allow_result["artifact_mode"] = "generated-receipts"
    allow_result["generated_artifacts"] = {
        "admission_receipt": generated_receipt_ref(
            generated_allow_path,
            "application/vate-admission-receipt+json",
        )
    }

    generated_linkage_admission = json.loads(
        (ROOT / "examples" / "receipts" / "admission-attenuate-max-amount.example.json").read_text()
    )
    generated_linkage_admission["receipt_id"] = "admrec-independent-linkage-001"
    generated_linkage_admission["verifier"] = {
        "id": "did:web:independent.example",
        "key_id": "did:web:independent.example#key-1",
    }
    generated_linkage_admission["decision"]["human_readable_summary"] = (
        "Independent verifier produced the same attenuation decision."
    )
    generated_linkage_admission_path = path.parent / "generated-admission-linkage.json"
    generated_linkage_admission_path.write_text(
        json.dumps(generated_linkage_admission, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    generated_linkage_admission_ref = generated_receipt_ref(
        generated_linkage_admission_path,
        "application/vate-admission-receipt+json",
    )

    generated_post = json.loads(
        (ROOT / "examples" / "receipts" / "post-execution-success.example.json").read_text()
    )
    generated_post["receipt_id"] = "postrec-independent-linkage-001"
    generated_post["issuer"] = {
        "id": "spiffe://independent.example/runtime",
        "role": "runtime",
    }
    generated_post["admission"]["receipt_id"] = generated_linkage_admission["receipt_id"]
    generated_post["admission"]["uri"] = generated_linkage_admission_ref["uri"]
    generated_post["admission"]["digest"] = {
        "alg": "sha-256",
        "value": hashlib.sha256(canonical_json_bytes(generated_linkage_admission)).hexdigest(),
    }
    generated_post_path = path.parent / "generated-post-execution-linkage.json"
    generated_post_path.write_text(json.dumps(generated_post, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    linkage_result = results["post-execution-linkage-success"]
    linkage_result["artifact_mode"] = "generated-receipts"
    linkage_result["generated_artifacts"] = {
        "admission_receipt": generated_linkage_admission_ref,
        "post_execution_receipt": generated_receipt_ref(
            generated_post_path,
            "application/vate-post-execution-receipt+json",
        ),
    }
    path.write_text(json.dumps(sut_results, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def set_nested_json_value(value: dict, path: tuple[str, ...], replacement) -> None:
    current = value
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = replacement


def assert_strict_json_file(path: Path) -> dict:
    def reject_non_finite(value: str) -> None:
        raise AssertionError(f"{path}: non-finite JSON constant {value} was emitted")

    def parse_finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise AssertionError(f"{path}: non-finite JSON number {value} was emitted")
        return parsed

    return json.loads(
        path.read_text(encoding="utf-8"),
        parse_constant=reject_non_finite,
        parse_float=parse_finite_float,
    )


def assert_generated_receipt_mutation_fails(
    tmp_dir: Path,
    *,
    label: str,
    case_id: str,
    artifact_name: str,
    artifact_filename: str,
    field_path: tuple[str, ...],
    replacement,
    expected_error: str,
) -> None:
    variant_dir = tmp_dir / f"generated-shape-{label}"
    variant_dir.mkdir()
    sut_results_path = variant_dir / "sut-results.json"
    compare_report_path = variant_dir / "compare-report.json"
    implementation_report_path = variant_dir / "implementation-report.json"
    bundle_report_path = variant_dir / "bundle-report.json"
    write_sut_result_with_generated_receipts(sut_results_path, tamper_allow_outcome=False)

    artifact_path = variant_dir / artifact_filename
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    set_nested_json_value(artifact, field_path, replacement)
    artifact_path.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    sut_results = json.loads(sut_results_path.read_text(encoding="utf-8"))
    result = next(
        item
        for item in sut_results["results"]
        if isinstance(item, dict) and item.get("case_id") == case_id
    )
    result["generated_artifacts"][artifact_name]["digest"]["value"] = hashlib.sha256(
        artifact_path.read_bytes()
    ).hexdigest()
    sut_results_path.write_text(
        json.dumps(sut_results, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    compare_result = run_expect_failure(
        [
            sys.executable,
            str(VATE_CONFORMANCE),
            "compare",
            "--corpus-root",
            str(ROOT / "conformance" / "al2-vate-v0.3"),
            "--sut-results",
            str(sut_results_path),
            "--report",
            str(compare_report_path),
            "--implementation-report",
            str(implementation_report_path),
            "--conformance-report-uri",
            str(compare_report_path),
            "--implementation-report-uri",
            str(implementation_report_path),
        ]
    )
    if "Traceback" in compare_result.stderr:
        raise AssertionError(f"{label}: compare emitted a traceback")
    assert_strict_json_file(compare_report_path)
    assert_strict_json_file(implementation_report_path)
    assert_report_error_contains(compare_report_path, expected_error)

    bundle_result = run_expect_failure(
        [
            sys.executable,
            str(VATE_CONFORMANCE),
            "verify-bundle",
            "--corpus-root",
            str(ROOT / "conformance" / "al2-vate-v0.3"),
            "--sut-results",
            str(sut_results_path),
            "--conformance-report",
            str(compare_report_path),
            "--implementation-report",
            str(implementation_report_path),
            "--report",
            str(bundle_report_path),
        ]
    )
    if "Traceback" in bundle_result.stderr:
        raise AssertionError(f"{label}: verify-bundle emitted a traceback")
    assert_strict_json_file(bundle_report_path)
    assert_bundle_check(
        bundle_report_path,
        f"sut_results.generated_artifacts.{case_id}",
        False,
    )


def write_sut_result_with_generated_linkage_case(path: Path, case_id: str) -> None:
    sut_results = json.loads((ROOT / "examples" / "conformance" / "sut-results-pass.example.json").read_text())
    result = next(
        item
        for item in sut_results["results"]
        if isinstance(item, dict) and item.get("case_id") == case_id
    )
    case = json.loads(
        (ROOT / "conformance" / "al2-vate-v0.3" / "cases" / f"{case_id}.json").read_text()
    )
    generated_admission = json.loads((ROOT / case["artifacts"]["admission_receipt"]).read_text())
    generated_post = json.loads((ROOT / case["artifacts"]["post_execution_receipt"]).read_text())

    generated_admission["receipt_id"] = f"admrec-independent-{case_id}"
    generated_admission["verifier"] = {
        "id": "did:web:independent.example",
        "key_id": "did:web:independent.example#key-1",
    }
    generated_post["receipt_id"] = f"postrec-independent-{case_id}"
    generated_post["issuer"] = {
        "id": "spiffe://independent.example/runtime",
        "role": "runtime",
    }
    generated_post["admission"]["receipt_id"] = generated_admission["receipt_id"]
    generated_post["admission"]["digest"] = {
        "alg": "sha-256",
        "value": hashlib.sha256(canonical_json_bytes(generated_admission)).hexdigest(),
    }

    admission_path = path.parent / f"generated-{case_id}-admission.json"
    post_path = path.parent / f"generated-{case_id}-post-execution.json"
    admission_path.write_text(
        json.dumps(generated_admission, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    admission_ref = generated_receipt_ref(
        admission_path,
        "application/vate-admission-receipt+json",
    )
    generated_post["admission"]["uri"] = admission_ref["uri"]
    post_path.write_text(
        json.dumps(generated_post, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    result["artifact_mode"] = "generated-receipts"
    result["generated_artifacts"] = {
        "admission_receipt": admission_ref,
        "post_execution_receipt": generated_receipt_ref(
            post_path,
            "application/vate-post-execution-receipt+json",
        ),
    }
    path.write_text(json.dumps(sut_results, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def find_free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_health(url: str, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError(f"status service did not become healthy: {url}")


def assert_json_matches(actual_path: Path, expected_path: Path) -> None:
    actual = json.loads(actual_path.read_text(encoding="utf-8"))
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    if actual != expected:
        raise RuntimeError(f"{expected_path.relative_to(ROOT)} is stale; regenerate it with scripts/vate_conformance.py index")


def primary_reason_code(reason_codes: list) -> str | None:
    for code in reason_codes:
        if code not in {"POLICY_MATCH", "FAIL_CLOSED"}:
            return str(code)
    return None


def assert_primary_reason_codes(report_path: Path) -> None:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    for case in report.get("cases", []):
        expected_primary = primary_reason_code(case.get("expected_reason_codes", []))
        case_id = case.get("case_id", "unknown")
        if case.get("expected_primary_reason_code") != expected_primary:
            raise RuntimeError(f"{report_path}: {case_id} missing or incorrect expected_primary_reason_code")
        if "actual_reason_codes" in case:
            actual_primary = primary_reason_code(case.get("actual_reason_codes", []))
            if case.get("actual_primary_reason_code") != actual_primary:
                raise RuntimeError(f"{report_path}: {case_id} missing or incorrect actual_primary_reason_code")


def validate_examples() -> None:
    for example_rel, schema_rel in iter_example_pairs():
        example = json.loads((ROOT / example_rel).read_text())
        schema = json.loads((ROOT / schema_rel).read_text())
        errors = check(schema, schema, example)
        if errors:
            joined = "\n".join(errors)
            raise RuntimeError(f"{example_rel} failed validation:\n{joined}")
    for json_rel in JSON_ONLY_FILES:
        json.loads((ROOT / json_rel).read_text(encoding="utf-8"))


def load_vate_conformance_module():
    spec = importlib.util.spec_from_file_location("vate_conformance", VATE_CONFORMANCE)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load scripts/vate_conformance.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_vate_core_module():
    spec = importlib.util.spec_from_file_location("vate_verifier_core", VATE_CORE)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load reference/vate-verifier-core/vate_verifier_core.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_vate_conformance_display_paths_are_portable() -> None:
    conformance = load_vate_conformance_module()

    class WindowsLikePath:
        def resolve(self) -> "WindowsLikePath":
            return self

        def relative_to(self, root: Path) -> PureWindowsPath:
            return PureWindowsPath("conformance/al2-vate-v0.3/corpus.json")

    path = conformance.display_path(WindowsLikePath())
    if path != "conformance/al2-vate-v0.3/corpus.json":
        raise RuntimeError(
            "vate_conformance display_path must use POSIX separators in "
            f"digest-addressed report and corpus paths, got {path!r}"
        )


def check_linkage_missing_artifacts_fail_closed() -> None:
    conformance = load_vate_conformance_module()
    case = json.loads(
        (
            ROOT
            / "conformance"
            / "al2-vate-v0.3"
            / "cases"
            / "post-execution-linkage-success.json"
        ).read_text(encoding="utf-8")
    )
    admission = json.loads((ROOT / case["artifacts"]["admission_receipt"]).read_text(encoding="utf-8"))
    post_execution = json.loads(
        (ROOT / case["artifacts"]["post_execution_receipt"]).read_text(encoding="utf-8")
    )
    expected = ["POST_EXEC_LINKAGE_MISMATCH"]
    if conformance.actual_linkage_reason_codes(case, None, post_execution) != expected:
        raise RuntimeError("missing admission receipt must fail with the generic linkage reason")
    if conformance.actual_linkage_reason_codes(case, admission, None) != expected:
        raise RuntimeError("missing post-execution receipt must fail with the generic linkage reason")

    for missing_artifact in ("admission_receipt", "post_execution_receipt"):
        for variant_name in (
            "missing-key",
            "missing-path",
            "invalid-json",
            "json-array",
            "json-number",
            "directory",
        ):
            with tempfile.TemporaryDirectory(
                prefix=f"vate-{variant_name}-{missing_artifact}-"
            ) as tmp:
                tmp_path = Path(tmp)
                corpus_root = Path(tmp) / "corpus"
                case_dir = corpus_root / "cases"
                case_dir.mkdir(parents=True)
                missing_case = json.loads(json.dumps(case))
                if variant_name == "missing-key":
                    missing_case["artifacts"].pop(missing_artifact)
                    expected_artifact_failure = "artifact missing"
                elif variant_name == "missing-path":
                    missing_case["artifacts"][missing_artifact] = (
                        f"examples/receipts/does-not-exist-{missing_artifact}.json"
                    )
                    expected_artifact_failure = "artifact missing"
                else:
                    malformed_artifact = tmp_path / f"{variant_name}-{missing_artifact}.json"
                    if variant_name == "invalid-json":
                        malformed_artifact.write_text("{not-json\n", encoding="utf-8")
                        expected_artifact_failure = "artifact is not readable strict JSON"
                    elif variant_name == "json-array":
                        malformed_artifact.write_text("[]\n", encoding="utf-8")
                        expected_artifact_failure = "artifact must be a JSON object"
                    elif variant_name == "json-number":
                        malformed_artifact.write_text("7\n", encoding="utf-8")
                        expected_artifact_failure = "artifact must be a JSON object"
                    else:
                        malformed_artifact.mkdir()
                        expected_artifact_failure = "artifact missing"
                    missing_case["artifacts"][missing_artifact] = str(malformed_artifact)
                (case_dir / "post-execution-linkage-success.json").write_text(
                    json.dumps(missing_case, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                report_path = Path(tmp) / "report.json"
                result = run_expect_failure(
                    [
                        sys.executable,
                        str(VATE_CONFORMANCE),
                        "run",
                        "--corpus-root",
                        str(corpus_root),
                        "--report",
                        str(report_path),
                    ]
                )
                if "Traceback" in result.stderr:
                    raise RuntimeError(
                        f"{variant_name} {missing_artifact} must not emit a traceback"
                    )
                report = json.loads(report_path.read_text(encoding="utf-8"))
                cases = report.get("cases", [])
                if len(cases) != 1 or cases[0].get("actual_reason_codes") != expected:
                    raise RuntimeError(
                        f"{variant_name} {missing_artifact} must reach the CLI report "
                        "with the generic linkage reason"
                    )
                expected_failure = (
                    f"artifact_ref {missing_artifact}: {expected_artifact_failure}"
                )
                if expected_failure not in cases[0].get("failures", []):
                    raise RuntimeError(
                        f"{variant_name} {missing_artifact} must record a machine-readable "
                        "artifact failure"
                    )

    for direct_artifact in ("admission_receipt", "post_execution_receipt"):
        with tempfile.TemporaryDirectory(prefix=f"vate-direct-path-{direct_artifact}-") as tmp:
            corpus_root = Path(tmp) / "corpus"
            case_dir = corpus_root / "cases"
            case_dir.mkdir(parents=True)
            direct_path_case = json.loads(json.dumps(case))
            direct_path = direct_path_case["artifacts"][direct_artifact]
            for check in direct_path_case["artifact_reference_checks"]:
                if check["artifact"] == direct_artifact:
                    check["artifact"] = direct_path
            (case_dir / "post-execution-linkage-success.json").write_text(
                json.dumps(direct_path_case, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            report_path = Path(tmp) / "report.json"
            run(
                [
                    sys.executable,
                    str(VATE_CONFORMANCE),
                    "run",
                    "--corpus-root",
                    str(corpus_root),
                    "--report",
                    str(report_path),
                ]
            )
            report = json.loads(report_path.read_text(encoding="utf-8"))
            if report.get("summary") != {"total": 1, "passed": 1, "failed": 0, "skipped": 0}:
                raise RuntimeError(
                    f"artifact_reference_checks must preserve repo-relative path support for {direct_artifact}"
                )


def check_admission_handoff_semantics_fail_closed() -> None:
    conformance = load_vate_conformance_module()

    allow_receipt = json.loads(
        (ROOT / "examples" / "receipts" / "admission-allow.example.json").read_text(
            encoding="utf-8"
        )
    )
    attenuate_receipt = json.loads(
        (
            ROOT
            / "examples"
            / "receipts"
            / "admission-attenuate-max-amount.example.json"
        ).read_text(encoding="utf-8")
    )
    allow_receipt["request"]["constraints"] = {
        "max_amount": {"currency": "USD", "value": "10.00"}
    }
    allow_receipt["attenuation"] = attenuate_receipt["attenuation"]

    expected_constraints = allow_receipt["request"]["constraints"]
    if conformance.admitted_effective_constraints(allow_receipt) != expected_constraints:
        raise RuntimeError("allow decisions must not use stray attenuation constraints")

    expected_attenuation_failure = (
        "attenuation: must be absent unless decision.outcome is attenuate"
    )
    if expected_attenuation_failure not in conformance.evaluate_attenuation_checks(
        {}, allow_receipt
    ):
        raise RuntimeError("reference evaluation must reject attenuation on allow decisions")

    generated_failures = conformance.generated_admission_receipt_shape_failures(
        allow_receipt,
        "generated_artifacts.admission_receipt",
    )
    expected_generated_failure = (
        "generated_artifacts.admission_receipt.attenuation: "
        "must be absent unless decision.outcome is attenuate"
    )
    if expected_generated_failure not in generated_failures:
        raise RuntimeError("generated receipt checks must reject attenuation on allow decisions")

    valid_issued_at = allow_receipt["issued_at"]
    valid_expires_at = allow_receipt["expires_at"]
    timestamp_cases = (
        (
            "2026-07-01T00:00:00",
            "2026-07-01T00:10:00",
            {"issued_at", "expires_at"},
        ),
        ("2026-07-01T00:00:00", valid_expires_at, {"issued_at"}),
        (valid_issued_at, "2026-07-01T00:10:00", {"expires_at"}),
        ("2026-07-01", "2026-07-02", {"issued_at", "expires_at"}),
    )
    for issued_at, expires_at, expected_fields in timestamp_cases:
        invalid_generated = json.loads(json.dumps(allow_receipt))
        invalid_generated["issued_at"] = issued_at
        invalid_generated["expires_at"] = expires_at
        identity_failures = conformance.generated_receipt_identity_failures(
            invalid_generated,
            "generated_artifacts.admission_receipt",
            "admission",
        )
        for field in expected_fields:
            expected_failure = (
                f"generated_artifacts.admission_receipt.{field}: "
                "expected RFC3339 timestamp"
            )
            if expected_failure not in identity_failures:
                raise RuntimeError(
                    "generated receipt identity checks must reject timezone-less timestamps"
                )

    linkage_case = json.loads(
        (
            ROOT
            / "conformance"
            / "al2-vate-v0.3"
            / "cases"
            / "post-execution-linkage-success.json"
        ).read_text(encoding="utf-8")
    )
    admission = json.loads(
        (ROOT / linkage_case["artifacts"]["admission_receipt"]).read_text(
            encoding="utf-8"
        )
    )
    post_execution = json.loads(
        (ROOT / linkage_case["artifacts"]["post_execution_receipt"]).read_text(
            encoding="utf-8"
        )
    )
    for invalid_time in ("not-a-time", "2026-07-01T00:00:00", "2026-07-01"):
        invalid_admission = json.loads(json.dumps(admission))
        invalid_admission["issued_at"] = invalid_time
        invalid_admission["expires_at"] = invalid_time
        valid, failure = conformance.admission_time_window_valid(
            invalid_admission,
            post_execution,
        )
        if valid or failure != "admission timestamps must be valid":
            raise RuntimeError("invalid admission timestamps must close the linkage window")
        if "admission timestamps must be valid" not in conformance.post_execution_linkage_failures(
            invalid_admission,
            post_execution,
        ):
            raise RuntimeError("post-execution linkage must reject invalid admission timestamps")

    for invalid_time in ("2026-07-01T00:00:00", "2026-07-01"):
        invalid_post_execution = json.loads(json.dumps(post_execution))
        invalid_post_execution["execution"]["started_at"] = invalid_time
        invalid_post_execution["execution"]["finished_at"] = invalid_time
        valid, failure = conformance.admission_time_window_valid(
            admission,
            invalid_post_execution,
        )
        if valid or failure != "execution timestamps must be valid":
            raise RuntimeError("timezone-less execution timestamps must fail closed")
        if "execution timestamps must be valid" not in conformance.post_execution_linkage_failures(
            admission,
            invalid_post_execution,
        ):
            raise RuntimeError("post-execution linkage must reject timezone-less execution timestamps")


def check_case_artifact_readers_fail_closed() -> None:
    reader_cases = (
        (
            "allow-ap2-hnp-preauthorized-mandate.json",
            "ap2_mandate",
            "integrity ap2_mandate",
        ),
        ("deny-alg-not-allowed.json", "trust_bundle", "trust trust_bundle"),
        (
            "allow-jose-detached-runtime-attestation.json",
            "jose_proof",
            "jose jose_proof",
        ),
        (
            "allow-valid-with-policy-snapshot.json",
            "policy_snapshot",
            "policy_snapshot policy_snapshot",
        ),
        (
            "deny-attenuation-max-amount-type-edge.json",
            "bad_attenuation",
            "attenuation bad_attenuation",
        ),
        ("allow-valid-admission.json", "runtime_context", "al2_context runtime_context"),
    )
    case_dir = ROOT / "conformance" / "al2-vate-v0.3" / "cases"

    for case_filename, artifact_name, failure_label in reader_cases:
        source_case = json.loads((case_dir / case_filename).read_text(encoding="utf-8"))
        source_case.pop("pairing", None)
        for variant_name in (
            "missing-key",
            "missing-path",
            "invalid-json",
            "json-array",
            "json-number",
            "directory",
        ):
            with tempfile.TemporaryDirectory(
                prefix=f"vate-{variant_name}-{artifact_name}-"
            ) as tmp:
                tmp_path = Path(tmp)
                corpus_root = tmp_path / "corpus"
                temp_case_dir = corpus_root / "cases"
                temp_case_dir.mkdir(parents=True)
                variant = json.loads(json.dumps(source_case))
                if variant_name == "missing-key":
                    variant["artifacts"].pop(artifact_name)
                    expected_reason = "artifact missing"
                elif variant_name == "missing-path":
                    variant["artifacts"][artifact_name] = (
                        f"examples/does-not-exist-{artifact_name}.json"
                    )
                    expected_reason = "artifact missing"
                else:
                    invalid_artifact = tmp_path / f"{variant_name}-{artifact_name}.json"
                    if variant_name == "invalid-json":
                        invalid_artifact.write_text("{not-json\n", encoding="utf-8")
                        expected_reason = "artifact is not readable strict JSON"
                    elif variant_name == "json-array":
                        invalid_artifact.write_text("[]\n", encoding="utf-8")
                        expected_reason = "artifact must be a JSON object"
                    elif variant_name == "json-number":
                        invalid_artifact.write_text("7\n", encoding="utf-8")
                        expected_reason = "artifact must be a JSON object"
                    else:
                        invalid_artifact.mkdir()
                        expected_reason = "artifact missing"
                    variant["artifacts"][artifact_name] = str(invalid_artifact)

                (temp_case_dir / case_filename).write_text(
                    json.dumps(variant, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                report_path = tmp_path / "report.json"
                result = run_expect_failure(
                    [
                        sys.executable,
                        str(VATE_CONFORMANCE),
                        "run",
                        "--corpus-root",
                        str(corpus_root),
                        "--report",
                        str(report_path),
                    ]
                )
                if "Traceback" in result.stderr:
                    raise RuntimeError(
                        f"{variant_name} {artifact_name} must not emit a traceback"
                    )
                assert_strict_json_file(report_path)
                assert_report_error_contains(
                    report_path,
                    f"{failure_label}: {expected_reason}",
                )


def check_nested_artifact_shapes_fail_closed() -> None:
    conformance = load_vate_conformance_module()
    evidence_check_names = (
        "evidence.verification.result",
        "evidence.verification.failure_reason",
        "admission_receipt.evidence.verification.inferred_resource_authority",
        "admission_receipt.evidence.verification.inferred_tool_authority",
    )
    malformed_admissions = (
        (
            {"request": {}, "evidence": [None]},
            evidence_check_names,
        ),
        (
            {"request": {}, "evidence": ["invalid"]},
            evidence_check_names,
        ),
        (
            {"request": {}, "evidence": [{"verification": []}]},
            evidence_check_names,
        ),
        (
            {"request": [], "evidence": [{"verification": {}}]},
            ("request.audience", "target.audience"),
        ),
    )
    for admission, check_names in malformed_admissions:
        for check_name in check_names:
            result = conformance.bool_for_named_check(
                name=check_name,
                admission=admission,
                post_execution=None,
                a2a_metadata=None,
                jose_results=None,
            )
            if result is not False:
                raise RuntimeError(
                    f"malformed admission nested shape passed named check {check_name}"
                )
        if not conformance.directly_dereferenced_artifact_failures(
            admission,
            None,
        ):
            raise RuntimeError("malformed admission nested shape was not reported")

    malformed_post_execution = {"result": []}
    if conformance.bool_for_named_check(
        name="result.policy_violations",
        admission=None,
        post_execution=malformed_post_execution,
        a2a_metadata=None,
        jose_results=None,
    ):
        raise RuntimeError("malformed post-execution result passed named check")
    if not conformance.directly_dereferenced_artifact_failures(
        None,
        malformed_post_execution,
    ):
        raise RuntimeError("malformed post-execution result was not reported")

    canonical_corpus = ROOT / "conformance" / "al2-vate-v0.3"
    passing_sut = (
        ROOT / "examples" / "conformance" / "sut-results-pass.example.json"
    )
    with tempfile.TemporaryDirectory(prefix="vate-nested-artifact-shape-") as temp_dir:
        temp_root = Path(temp_dir)
        baseline_report = temp_root / "baseline-report.json"
        baseline_implementation = temp_root / "baseline-implementation.json"
        run(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "run",
                "--corpus-root",
                str(canonical_corpus),
                "--report",
                str(baseline_report),
                "--implementation-report",
                str(baseline_implementation),
                "--conformance-report-uri",
                str(baseline_report),
                "--implementation-report-uri",
                str(baseline_implementation),
            ]
        )

        variants = (
            (
                "evidence-null-item",
                "allow-valid-admission.json",
                "admission_receipt",
                lambda artifact: artifact.__setitem__("evidence", [None]),
                "admission_receipt.evidence[0]: expected object",
            ),
            (
                "evidence-scalar-item",
                "allow-valid-admission.json",
                "admission_receipt",
                lambda artifact: artifact.__setitem__("evidence", ["invalid"]),
                "admission_receipt.evidence[0]: expected object",
            ),
            (
                "verification-array",
                "allow-valid-admission.json",
                "admission_receipt",
                lambda artifact: artifact["evidence"][0].__setitem__(
                    "verification", []
                ),
                "admission_receipt.evidence[0].verification: expected object",
            ),
            (
                "request-array",
                "allow-valid-admission.json",
                "admission_receipt",
                lambda artifact: artifact.__setitem__("request", []),
                "admission_receipt.request: expected object",
            ),
            (
                "post-result-array",
                "post-execution-linkage-success.json",
                "post_execution_receipt",
                lambda artifact: artifact.__setitem__("result", []),
                "post_execution_receipt.result: expected object",
            ),
        )

        for label, case_filename, artifact_key, mutate, expected_failure in variants:
            corpus_root = temp_root / f"corpus-{label}"
            shutil.copytree(canonical_corpus, corpus_root)
            case_path = corpus_root / "cases" / case_filename
            case = json.loads(case_path.read_text(encoding="utf-8"))
            source_artifact_path = ROOT / case["artifacts"][artifact_key]
            artifact = json.loads(source_artifact_path.read_text(encoding="utf-8"))
            mutate(artifact)
            artifact_path = temp_root / f"{label}-artifact.json"
            artifact_path.write_text(
                json.dumps(artifact, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            case["artifacts"][artifact_key] = str(artifact_path)
            case_path.write_text(
                json.dumps(case, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            report_paths = {
                "run": temp_root / f"{label}-run.json",
                "compare": temp_root / f"{label}-compare.json",
                "verify-bundle": temp_root / f"{label}-bundle.json",
            }
            commands = {
                "run": [
                    sys.executable,
                    str(VATE_CONFORMANCE),
                    "run",
                    "--corpus-root",
                    str(corpus_root),
                    "--report",
                    str(report_paths["run"]),
                ],
                "compare": [
                    sys.executable,
                    str(VATE_CONFORMANCE),
                    "compare",
                    "--corpus-root",
                    str(corpus_root),
                    "--sut-results",
                    str(passing_sut),
                    "--report",
                    str(report_paths["compare"]),
                ],
                "verify-bundle": [
                    sys.executable,
                    str(VATE_CONFORMANCE),
                    "verify-bundle",
                    "--corpus-root",
                    str(corpus_root),
                    "--conformance-report",
                    str(baseline_report),
                    "--implementation-report",
                    str(baseline_implementation),
                    "--report",
                    str(report_paths["verify-bundle"]),
                ],
            }
            for command_name, command in commands.items():
                process = run_expect_failure(command)
                if "Traceback" in process.stderr:
                    raise RuntimeError(
                        f"{label} caused {command_name} traceback"
                    )
                assert_strict_json_file(report_paths[command_name])
            assert_report_error_contains(report_paths["run"], expected_failure)


def check_corpus_manifest_non_file_fails_closed() -> None:
    source_case = json.loads(
        (
            ROOT
            / "conformance"
            / "al2-vate-v0.3"
            / "cases"
            / "allow-ap2-hnp-preauthorized-mandate.json"
        ).read_text(encoding="utf-8")
    )
    source_case.pop("pairing", None)

    with tempfile.TemporaryDirectory(prefix="vate-manifest-non-file-") as tmp:
        tmp_path = Path(tmp)
        corpus_root = tmp_path / "corpus"
        case_dir = corpus_root / "cases"
        artifact_dir = corpus_root / "artifacts" / "non-file-ap2-mandate.json"
        case_dir.mkdir(parents=True)
        artifact_dir.mkdir(parents=True)
        shutil.copy2(
            ROOT / "conformance" / "al2-vate-v0.3" / "corpus.json",
            corpus_root / "corpus.json",
        )

        variant = json.loads(json.dumps(source_case))
        variant["artifacts"]["ap2_mandate"] = str(artifact_dir)
        (case_dir / "allow-ap2-hnp-preauthorized-mandate.json").write_text(
            json.dumps(variant, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        sut_results_path = tmp_path / "sut-results.json"
        sut_results_path.write_text("{}\n", encoding="utf-8")

        report_paths = {
            "run": tmp_path / "run-report.json",
            "compare": tmp_path / "compare-report.json",
            "verify-bundle": tmp_path / "bundle-report.json",
        }
        commands = {
            "run": [
                sys.executable,
                str(VATE_CONFORMANCE),
                "run",
                "--corpus-root",
                str(corpus_root),
                "--report",
                str(report_paths["run"]),
            ],
            "compare": [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(corpus_root),
                "--sut-results",
                str(sut_results_path),
                "--report",
                str(report_paths["compare"]),
            ],
            "verify-bundle": [
                sys.executable,
                str(VATE_CONFORMANCE),
                "verify-bundle",
                "--corpus-root",
                str(corpus_root),
                "--conformance-report",
                str(ROOT / "examples" / "conformance-report.example.json"),
                "--implementation-report",
                str(ROOT / "examples" / "implementation-report.example.json"),
                "--report",
                str(report_paths["verify-bundle"]),
            ],
        }

        for command_name, command in commands.items():
            result = run_expect_failure(command)
            if "Traceback" in result.stderr:
                raise RuntimeError(
                    f"{command_name} must not traceback for a non-file corpus artifact"
                )
            assert_strict_json_file(report_paths[command_name])

        manifest_error = "corpus manifest artifact is not a readable regular file"
        assert_report_error_contains(report_paths["run"], manifest_error)
        assert_report_error_contains(report_paths["compare"], manifest_error)
        assert_bundle_check(report_paths["verify-bundle"], "corpus.manifest[0]", False)


def check_bundle_corpus_index_fails_closed() -> None:
    variants = (
        ("missing", None, "corpus_index.json"),
        ("malformed", "{\n", "corpus_index.json"),
        ("array", "[]\n", "corpus_index.shape"),
        ("null", "null\n", "corpus_index.shape"),
    )
    with tempfile.TemporaryDirectory(prefix="vate-bundle-corpus-index-") as temp_dir:
        temp_base = Path(temp_dir)
        for label, replacement, expected_check in variants:
            corpus_root = temp_base / f"corpus-{label}"
            shutil.copytree(ROOT / "conformance" / "al2-vate-v0.3", corpus_root)
            corpus_index_path = corpus_root / "corpus.json"
            if replacement is None:
                corpus_index_path.unlink()
            else:
                corpus_index_path.write_text(replacement, encoding="utf-8")

            report_path = temp_base / f"bundle-{label}.json"
            result = run_expect_failure(
                [
                    sys.executable,
                    str(VATE_CONFORMANCE),
                    "verify-bundle",
                    "--corpus-root",
                    str(corpus_root),
                    "--conformance-report",
                    str(ROOT / "examples" / "conformance-report.example.json"),
                    "--implementation-report",
                    str(ROOT / "examples" / "implementation-report.example.json"),
                    "--report",
                    str(report_path),
                ]
            )
            if "Traceback" in result.stderr:
                raise RuntimeError(
                    f"verify-bundle must not traceback for corpus.json variant {label}"
                )
            assert_strict_json_file(report_path)
            assert_bundle_check(report_path, expected_check, False)


def check_generated_artifact_utf8_boundary() -> None:
    conformance = load_vate_conformance_module()
    with tempfile.TemporaryDirectory(prefix="vate-generated-artifact-encoding-") as tmp:
        tmp_path = Path(tmp)
        sut_results_path = tmp_path / "sut-results.json"
        sut_results_path.write_text("{}\n", encoding="utf-8")
        artifact_path = tmp_path / "generated-admission-utf16.json"
        artifact_path.write_bytes(
            json.dumps({"receipt_type": "admission"}).encode("utf-16")
        )
        reference = {
            "uri": "https://independent.example/vate/generated-admission-utf16.json",
            "local_path": artifact_path.name,
            "media_type": "application/vate-admission-receipt+json",
            "digest": {
                "alg": "sha-256",
                "value": hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
            },
        }
        artifact, resolved_path, failures = conformance.load_sut_generated_artifact(
            reference,
            sut_results_path,
            "generated_artifacts.admission_receipt",
        )
        if artifact is not None or resolved_path != artifact_path.resolve():
            raise RuntimeError("UTF-16 generated artifact must not be accepted as UTF-8 JSON")
        if not any("must be a UTF-8 JSON object" in failure for failure in failures):
            raise RuntimeError("UTF-16 generated artifact must fail with the encoding boundary")


def load_a2a_adapter_module():
    spec = importlib.util.spec_from_file_location("a2a_metadata_adapter_demo", A2A_ADAPTER)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load reference/a2a-metadata-adapter-demo/a2a_metadata_adapter_demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_a2a_adapter_local_uri_boundary() -> None:
    adapter = load_a2a_adapter_module()
    expected = ROOT / "examples" / "admission-request.example.json"
    if adapter.resolve_local_uri("local:examples/admission-request.example.json") != expected:
        raise RuntimeError("A2A adapter local URI resolver must preserve repository-relative local paths")
    unsafe_uris = [
        "local:",
        "local:/etc/passwd",
        "local:../AGENTS.md",
        "local:examples/../AGENTS.md",
        "https://verifier.example/vate/admission-request.json",
    ]
    for uri in unsafe_uris:
        try:
            adapter.resolve_local_uri(uri)
        except ValueError:
            continue
        raise RuntimeError(f"A2A adapter local URI resolver accepted unsafe URI {uri!r}")


def check_a2a_adapter_malformed_metadata_fail_closed() -> None:
    adapter = load_a2a_adapter_module()
    task_message = json.loads((ROOT / "reference" / "a2a-metadata-adapter-demo" / "task-message.example.json").read_text())
    missing_metadata_task = {"task_id": "task-missing-vate-metadata"}
    missing_metadata_response = adapter.adapt_task_message(missing_metadata_task)
    missing_metadata_decision = missing_metadata_response.get("vate_decision", {})
    if missing_metadata_decision.get("outcome") != "deny":
        raise RuntimeError("A2A adapter must deny task messages without the VATE metadata extension")
    if missing_metadata_decision.get("reason_codes") != ["SCHEMA_INVALID", "FAIL_CLOSED"]:
        raise RuntimeError("A2A adapter must fail closed when the VATE metadata extension is missing")
    missing_metadata_receipt = adapter.make_schema_invalid_receipt(
        None,
        "missing VATE A2A metadata extension object",
        source_artifact=missing_metadata_task,
    )
    assert_a2a_adapter_schema_invalid_response_binds_source(
        adapter,
        missing_metadata_response,
        missing_metadata_receipt,
        missing_metadata_task,
        "inline:a2a-task-message",
        "a2a_task_message",
        "missing VATE A2A metadata extension object",
        "missing VATE metadata",
    )

    malformed_task = ["not", "a", "task-message"]
    malformed_task_response = adapter.adapt_task_message(malformed_task)
    malformed_task_decision = malformed_task_response.get("vate_decision", {})
    if malformed_task_decision.get("outcome") != "deny":
        raise RuntimeError("A2A adapter must deny non-object task messages")
    if malformed_task_decision.get("reason_codes") != ["SCHEMA_INVALID", "FAIL_CLOSED"]:
        raise RuntimeError("A2A adapter must fail closed on non-object task messages")
    malformed_task_receipt = adapter.make_schema_invalid_receipt(
        None,
        "task message must be a JSON object",
        source_artifact=malformed_task,
    )
    assert_a2a_adapter_schema_invalid_response_binds_source(
        adapter,
        malformed_task_response,
        malformed_task_receipt,
        malformed_task,
        "inline:a2a-task-message",
        "a2a_task_message",
        "task message must be a JSON object",
        "non-object task message",
    )
    missing_receipt_uri = (
        missing_metadata_response
        .get("metadata", {})
        .get(adapter.EXTENSION_URI, {})
        .get("admission_receipt", {})
        .get("uri")
    )
    malformed_receipt_uri = (
        malformed_task_response
        .get("metadata", {})
        .get(adapter.EXTENSION_URI, {})
        .get("admission_receipt", {})
        .get("uri")
    )
    if missing_receipt_uri == malformed_receipt_uri:
        raise RuntimeError("A2A adapter schema-invalid receipt URIs must be unique per failure source")

    metadata = task_message["metadata"][adapter.EXTENSION_URI]
    metadata["admission_request"].pop("digest")
    metadata["expires_at"] = "not-a-date-time"

    response = adapter.adapt_task_message(task_message)
    decision = response.get("vate_decision", {})
    if decision.get("outcome") != "deny":
        raise RuntimeError("A2A adapter must deny malformed VATE metadata")
    if decision.get("reason_codes") != ["SCHEMA_INVALID", "FAIL_CLOSED"]:
        raise RuntimeError("A2A adapter must fail closed on malformed VATE metadata")
    metadata_failure_reason = "; ".join(adapter.admission_requested_metadata_failures(metadata))
    receipt = adapter.make_schema_invalid_receipt(
        metadata,
        metadata_failure_reason,
        source_artifact=metadata,
    )
    assert_a2a_adapter_schema_invalid_response_binds_source(
        adapter,
        response,
        receipt,
        metadata,
        "inline:a2a-metadata",
        "a2a_metadata",
        metadata_failure_reason,
        "malformed VATE metadata",
    )
    if receipt.get("expires_at") != receipt.get("issued_at"):
        raise RuntimeError("A2A fail-closed receipt must not copy malformed metadata expires_at")
    schema = json.loads((ROOT / "schemas" / "admission-receipt.schema.json").read_text(encoding="utf-8"))
    errors = check(schema, schema, receipt)
    if errors:
        raise RuntimeError(f"A2A fail-closed receipt must be schema-valid: {errors}")

    task_message = json.loads((ROOT / "reference" / "a2a-metadata-adapter-demo" / "task-message.example.json").read_text())
    metadata = task_message["metadata"][adapter.EXTENSION_URI]
    malformed_artifact: list[str] = ["not", "an", "admission-request"]
    with tempfile.TemporaryDirectory(prefix=".tmp-a2a-malformed-", dir=ROOT) as tmp:
        artifact_path = Path(tmp) / "malformed-admission-request.json"
        artifact_path.write_text(json.dumps(malformed_artifact), encoding="utf-8")
        metadata["admission_request"]["uri"] = "local:" + str(artifact_path.relative_to(ROOT))
        metadata["admission_request"]["digest"] = {
            "alg": "sha-256",
            "value": adapter.core.canonical_hash(malformed_artifact).removeprefix("sha-256:"),
        }
        response = adapter.adapt_task_message(task_message)
    decision = response.get("vate_decision", {})
    if decision.get("outcome") != "deny":
        raise RuntimeError("A2A adapter must deny digest-matching malformed admission artifacts")
    if decision.get("reason_codes") != ["SCHEMA_INVALID", "FAIL_CLOSED"]:
        raise RuntimeError("A2A adapter must fail closed on digest-matching malformed admission artifacts")


def assert_a2a_adapter_schema_invalid_response_binds_source(
    adapter,
    response: dict,
    expected_receipt: dict,
    source_artifact,
    source_uri: str,
    source_kind: str,
    expected_failure_reason: str,
    label: str,
) -> None:
    expected_receipt_digest = adapter.core.canonical_hash(expected_receipt).removeprefix("sha-256:")
    receipt_ref = response.get("metadata", {}).get(adapter.EXTENSION_URI, {}).get("admission_receipt", {})
    actual_receipt_digest = receipt_ref.get("digest", {}).get("value")
    if actual_receipt_digest != expected_receipt_digest:
        raise RuntimeError(f"A2A adapter schema-invalid response must reference the expected receipt for {label}")
    if "failure_source" in expected_receipt:
        raise RuntimeError("A2A adapter schema-invalid receipt must not carry demo-local failure_source")
    assert_a2a_adapter_response_binds_source(
        adapter,
        response,
        expected_receipt,
        source_artifact,
        source_uri,
        source_kind,
        expected_failure_reason,
        label,
    )


def assert_a2a_adapter_response_binds_source(
    adapter,
    response: dict,
    receipt: dict,
    source_artifact,
    source_uri: str,
    source_kind: str,
    expected_failure_reason: str,
    label: str,
) -> None:
    for evidence in receipt.get("evidence", []):
        if evidence.get("type") == "admission_request" and evidence.get("uri") == source_uri:
            raise RuntimeError(f"A2A adapter schema-invalid receipt must not classify {label} as admission_request evidence")
    failure_source = response.get("demo_local_failure_source", {})
    if failure_source.get("kind") != source_kind:
        raise RuntimeError(f"A2A adapter schema-invalid response must classify {label} as {source_kind}")
    if failure_source.get("uri") != source_uri:
        raise RuntimeError(f"A2A adapter schema-invalid response must use {source_uri} for {label}")
    expected_digest = adapter.core.safe_digest_value(source_artifact)
    actual_digest = failure_source.get("digest", {}).get("value")
    if actual_digest != expected_digest:
        raise RuntimeError(f"A2A adapter schema-invalid response must digest-bind {label}")
    if actual_digest == adapter.SAFE_DIGEST["value"]:
        raise RuntimeError(f"A2A adapter schema-invalid response must not use placeholder digest for {label}")
    if failure_source.get("failure_reason") != expected_failure_reason:
        raise RuntimeError(f"A2A adapter schema-invalid response must record the failure reason for {label}")


def check_al2_corpus_docs_synced() -> None:
    case_dir = ROOT / "conformance" / "al2-vate-v0.3" / "cases"
    case_paths = sorted(case_dir.glob("*.json"))
    readme = AL2_CORPUS_README.read_text(encoding="utf-8")
    missing_readme_cases = [
        str(path.relative_to(ROOT / "conformance" / "al2-vate-v0.3"))
        for path in case_paths
        if str(path.relative_to(ROOT / "conformance" / "al2-vate-v0.3")) not in readme
    ]
    if missing_readme_cases:
        raise RuntimeError(f"AL2 corpus README is missing cases: {missing_readme_cases}")

    v030_release_notes = " ".join(V03_RELEASE_NOTES.read_text(encoding="utf-8").split())
    if "63-case AL2 v0.3 draft conformance corpus" not in v030_release_notes:
        raise RuntimeError("v0.3.0 release notes must preserve the archived 63-case corpus count")
    if "63 AL2 v0.3 cases" not in v030_release_notes:
        raise RuntimeError("v0.3.0 release notes implementer case-count text must preserve the archived count")

    release_notes = " ".join(V031_RELEASE_NOTES.read_text(encoding="utf-8").split())
    if "66-case AL2 v0.3 draft conformance corpus" not in release_notes:
        raise RuntimeError("v0.3.1 release notes must preserve the archived 66-case corpus count")
    if "66 AL2 v0.3 cases" not in release_notes:
        raise RuntimeError("v0.3.1 release notes implementer case-count text must preserve the archived count")


def check_evidence_vocabulary_registry() -> None:
    registry = json.loads(EVIDENCE_VOCABULARY.read_text(encoding="utf-8"))
    evidence_types = registry.get("evidence_types")
    protocol_hints = registry.get("protocol_hints")
    if not isinstance(evidence_types, list) or not evidence_types:
        raise RuntimeError("evidence vocabulary registry must define evidence_types")
    if not isinstance(protocol_hints, list) or not protocol_hints:
        raise RuntimeError("evidence vocabulary registry must define protocol_hints")

    evidence_type_ids = {item.get("id") for item in evidence_types if isinstance(item, dict)}
    protocol_hint_ids = {item.get("id") for item in protocol_hints if isinstance(item, dict)}
    if len(evidence_type_ids) != len(evidence_types) or not all(isinstance(item, str) for item in evidence_type_ids):
        raise RuntimeError("evidence vocabulary registry has missing or duplicate evidence type ids")
    if len(protocol_hint_ids) != len(protocol_hints) or not all(isinstance(item, str) for item in protocol_hint_ids):
        raise RuntimeError("evidence vocabulary registry has missing or duplicate protocol hint ids")

    for item in evidence_types:
        allowed_hints = item.get("allowed_protocol_hints")
        if not isinstance(allowed_hints, list):
            raise RuntimeError(f"evidence type {item.get('id')} must define allowed_protocol_hints")
        unknown_hints = set(allowed_hints) - protocol_hint_ids
        if unknown_hints:
            raise RuntimeError(f"evidence type {item.get('id')} allows unknown protocol hints: {sorted(unknown_hints)}")

    for schema_rel in ("schemas/admission-request.schema.json", "schemas/admission-receipt.schema.json"):
        schema = json.loads((ROOT / schema_rel).read_text(encoding="utf-8"))
        schema_evidence_types = set(schema["$defs"]["evidenceType"]["enum"])
        schema_protocol_hints = set(schema["$defs"]["protocolHint"]["enum"])
        if schema_evidence_types != evidence_type_ids:
            raise RuntimeError(f"{schema_rel} evidence type enum does not match evidence vocabulary registry")
        if schema_protocol_hints != protocol_hint_ids:
            raise RuntimeError(f"{schema_rel} protocol hint enum does not match evidence vocabulary registry")

    evidence_ref_schema = json.loads((ROOT / "schemas/evidence-reference.schema.json").read_text(encoding="utf-8"))
    evidence_ref_types = set(evidence_ref_schema["properties"]["type"]["enum"])
    evidence_ref_hints = set(evidence_ref_schema["properties"]["protocol_hint"]["enum"])
    if evidence_ref_types != evidence_type_ids:
        raise RuntimeError("schemas/evidence-reference.schema.json type enum does not match evidence vocabulary registry")
    if evidence_ref_hints != protocol_hint_ids:
        raise RuntimeError(
            "schemas/evidence-reference.schema.json protocol_hint enum does not match evidence vocabulary registry"
        )

    conformance = load_vate_conformance_module()
    invalid_pair = {"type": "runtime_attestation", "protocol_hint": "ap2"}
    failures = conformance.validate_evidence_vocab_object(invalid_pair, label="negative evidence vocabulary pair")
    if not failures:
        raise RuntimeError("runner accepted an evidence type/protocol hint pair that is not registered")

    core = load_vate_core_module()
    if set(core.EVIDENCE_TYPES) != evidence_type_ids:
        raise RuntimeError("reference verifier core evidence type set does not match evidence vocabulary registry")
    core_allowed_hints = getattr(core, "ALLOWED_PROTOCOL_HINTS_BY_TYPE", None)
    expected_allowed_hints = {
        item["id"]: frozenset(item["allowed_protocol_hints"])
        for item in evidence_types
    }
    if core_allowed_hints != expected_allowed_hints:
        raise RuntimeError("reference verifier core evidence type/protocol hint map does not match registry")


def check_artifact_versioning_docs() -> None:
    if not ARTIFACT_VERSIONING_DOC.exists():
        raise RuntimeError(f"missing {ARTIFACT_VERSIONING_DOC.relative_to(ROOT)}")
    text = ARTIFACT_VERSIONING_DOC.read_text(encoding="utf-8")
    normalized_text = " ".join(text.split()).lower()
    required_phrases = [
        "active conformance artifact line on `main` is **`2026-09`**",
        "historical `2026-07` validation lane",
        "exact recorded tag or commit",
        "manifest digest",
        "not the publication date",
        "not a production-readiness claim",
        "intentionally reject a `2026-07` result",
    ]
    missing = [phrase for phrase in required_phrases if phrase not in normalized_text]
    if missing:
        raise RuntimeError(
            f"{ARTIFACT_VERSIONING_DOC.relative_to(ROOT)} is missing artifact versioning language: {missing}"
        )


def check_post_execution_linkage_kind_coverage() -> None:
    case_dir = ROOT / "conformance" / "al2-vate-v0.3" / "cases"
    observed_kinds: set[str] = set()
    conformance = load_vate_conformance_module()
    for case_path in case_dir.glob("post-execution-*.json"):
        case = json.loads(case_path.read_text(encoding="utf-8"))
        for check in case.get("linkage_checks", []):
            if isinstance(check, dict) and isinstance(check.get("kind"), str):
                observed_kinds.add(check["kind"])
        artifacts = case.get("artifacts")
        if not isinstance(artifacts, dict):
            continue
        admission_path = artifacts.get("admission_receipt")
        post_path = artifacts.get("post_execution_receipt")
        if not isinstance(admission_path, str) or not isinstance(post_path, str):
            continue
        admission = json.loads((ROOT / admission_path).read_text(encoding="utf-8"))
        post_execution = json.loads((ROOT / post_path).read_text(encoding="utf-8"))
        admission_block = post_execution.get("admission")
        if not isinstance(admission_block, dict):
            continue
        explicitly_broken_digest = any(
            isinstance(check, dict)
            and check.get("kind") == "admission_digest"
            and check.get("expect_match") is False
            for check in case.get("linkage_checks", [])
        )
        digest_matches = admission_block.get("digest") == conformance.digest_descriptor(admission)
        if digest_matches == explicitly_broken_digest:
            expected_state = "mismatch" if explicitly_broken_digest else "match"
            raise RuntimeError(
                f"{case['case_id']}: admission digest must {expected_state}; "
                "unrelated linkage failures must not leak into a single-purpose case"
            )
    required_kinds = {
        "admission_receipt_id",
        "admission_decision",
    }
    missing = sorted(required_kinds - observed_kinds)
    if missing:
        raise RuntimeError(f"post-execution linkage cases are missing explicit linkage kinds: {missing}")

    admission = json.loads((ROOT / "examples" / "receipts" / "admission-attenuate-max-amount.example.json").read_text())
    post_execution = json.loads((ROOT / "examples" / "receipts" / "post-execution-success.example.json").read_text())
    receipt_check = {
        "kind": "admission_receipt_id",
        "expect_match": True,
        "reason_code": "POST_EXEC_LINKAGE_MISMATCH",
    }
    decision_check = {
        "kind": "admission_decision",
        "expect_match": True,
        "reason_code": "POST_EXEC_LINKAGE_MISMATCH",
    }
    for check in (receipt_check, decision_check):
        violation, failure = conformance.linkage_check_violation({}, check, admission, post_execution)
        if violation or failure:
            raise RuntimeError(f"{check['kind']} should pass on the success post-execution fixture")

    mismatched_receipt = json.loads(json.dumps(post_execution))
    mismatched_receipt["admission"]["receipt_id"] = "wrong-admission-receipt-id"
    violation, failure = conformance.linkage_check_violation({}, receipt_check, admission, mismatched_receipt)
    if not violation or failure:
        raise RuntimeError("admission_receipt_id linkage kind did not detect a mismatched receipt id")

    mismatched_decision = json.loads(json.dumps(post_execution))
    mismatched_decision["admission"]["decision"] = "allow"
    violation, failure = conformance.linkage_check_violation({}, decision_check, admission, mismatched_decision)
    if not violation or failure:
        raise RuntimeError("admission_decision linkage kind did not detect a mismatched admission decision")

    missing_post_codes = conformance.actual_linkage_reason_codes(
        {
            "linkage_checks": [
                {
                    "kind": "admission_receipt_id",
                    "expect_match": True,
                }
            ]
        },
        admission,
        None,
    )
    if missing_post_codes != ["POST_EXEC_LINKAGE_MISMATCH"]:
        raise RuntimeError("missing post-execution artifacts must return a generic linkage mismatch without crashing")

    missing_admission_codes = conformance.actual_linkage_reason_codes(
        {
            "linkage_checks": [
                {
                    "kind": "admission_receipt_id",
                    "expect_match": True,
                }
            ]
        },
        None,
        post_execution,
    )
    if missing_admission_codes != ["POST_EXEC_LINKAGE_MISMATCH"]:
        raise RuntimeError("missing admission artifacts must return a generic linkage mismatch without crashing")


def check_transport_bound_fixture_coverage() -> None:
    case_dir = ROOT / "conformance" / "al2-vate-v0.3" / "cases"
    case_path = case_dir / "deny-mcp-oauth-upstream-denied.json"
    if not case_path.exists():
        raise RuntimeError(
            "transport-bound fixture coverage is missing deny-mcp-oauth-upstream-denied: "
            "MCP/OAuth coverage must include a denial where the requested VATE-local "
            "action stays stable but upstream OAuth authority is insufficient."
        )

    case = json.loads(case_path.read_text(encoding="utf-8"))
    artifacts = case.get("artifacts", {})
    admission_request = json.loads((ROOT / artifacts["admission_request"]).read_text(encoding="utf-8"))
    admission_receipt = json.loads((ROOT / artifacts["admission_receipt"]).read_text(encoding="utf-8"))

    request_action = admission_request.get("action")
    receipt_action = admission_receipt.get("request", {}).get("action")
    requested_tool = admission_request.get("constraints", {}).get("requested_tool")
    tool_allowlist = admission_request.get("constraints", {}).get("tool_allowlist", [])
    oauth = admission_request.get("constraints", {}).get("transport", {}).get("oauth", {})
    required_scope = oauth.get("required_scope")
    scopes = oauth.get("scopes", [])
    reason_codes = admission_receipt.get("decision", {}).get("reason_codes")
    evidence_results = [
        item.get("verification", {}).get("status_result")
        for item in admission_receipt.get("evidence", [])
        if item.get("type") == "oauth_access_token"
    ]

    if request_action != "crm.case.update" or receipt_action != request_action:
        raise RuntimeError("deny-mcp-oauth-upstream-denied must keep the requested action stable")
    if requested_tool != "cases.update" or requested_tool not in tool_allowlist:
        raise RuntimeError("deny-mcp-oauth-upstream-denied must keep the requested MCP tool locally allowed")
    if not isinstance(scopes, list) or required_scope in scopes:
        raise RuntimeError("deny-mcp-oauth-upstream-denied must make the OAuth required_scope absent from scopes")
    if reason_codes != ["ACTION_NOT_PERMITTED", "FAIL_CLOSED"]:
        raise RuntimeError("deny-mcp-oauth-upstream-denied must deny with ACTION_NOT_PERMITTED then FAIL_CLOSED")
    if "scope_missing" not in evidence_results:
        raise RuntimeError("deny-mcp-oauth-upstream-denied must record an OAuth scope_missing verification result")

    required_cases = {
        "deny-token-passthrough-as-authority": {
            "reason_codes": ["TOKEN_AUTHORITY_INSUFFICIENT", "FAIL_CLOSED"],
            "status_result": "token_present_without_authority",
            "request_checks": {
                ("constraints", "transport", "oauth", "token_present"): True,
                ("constraints", "transport", "oauth", "resource"): "mcp://crm.example/tools/cases.update",
                ("constraints", "transport", "oauth", "protected_resource"): "mcp://crm.example/tools/cases.update",
                ("constraints", "transport", "oauth", "upstream_authorization"): "missing",
                ("constraints", "transport", "oauth", "resource_binding"): "missing",
                ("constraints", "transport", "oauth", "required_scope"): "crm.case.update",
                ("constraints", "transport", "oauth", "scopes"): ["crm.case.update"],
                ("constraints", "transport", "oauth", "proof_of_possession"): "dpop-jkt:base64url-thumbprint",
                ("constraints", "transport", "mcp", "authorized_tool"): "cases.update",
                ("constraints", "transport", "mcp", "authorized_tool_class"): "write",
                ("constraints", "transport", "mcp", "requested_tool"): "cases.update",
                ("constraints", "transport", "mcp", "requested_tool_class"): "write",
                ("constraints", "requested_tool_class"): "write",
            },
            "receipt_checks": {
                ("request", "transport", "oauth", "resource"): "mcp://crm.example/tools/cases.update",
                ("request", "transport", "oauth", "protected_resource"): "mcp://crm.example/tools/cases.update",
                ("request", "transport", "oauth", "upstream_authorization"): "missing",
                ("request", "transport", "oauth", "resource_binding"): "missing",
                ("request", "transport", "oauth", "required_scope"): "crm.case.update",
                ("request", "transport", "oauth", "scopes"): ["crm.case.update"],
                ("request", "transport", "oauth", "proof_of_possession"): "dpop-jkt:base64url-thumbprint",
                ("request", "transport", "mcp", "authorized_tool"): "cases.update",
                ("request", "transport", "mcp", "authorized_tool_class"): "write",
                ("request", "transport", "mcp", "requested_tool"): "cases.update",
                ("request", "transport", "mcp", "requested_tool_class"): "write",
            },
            "forbidden_receipt_paths": [
                ("request", "transport", "oauth", "access_token"),
                ("evidence", 0, "verification", "full_token"),
                ("evidence", 0, "verification", "tool_payload"),
                ("evidence", 0, "verification", "prompt"),
            ],
            "required_redaction": {
                ("evidence", 0, "verification", "redaction", "token_material"): "omitted",
                ("evidence", 0, "verification", "redaction", "tool_payload"): "omitted",
                ("evidence", 0, "verification", "redaction", "resource_description"): "omitted",
            },
        },
        "deny-resource-indicator-drift": {
            "reason_codes": ["RESOURCE_INDICATOR_MISMATCH", "FAIL_CLOSED"],
            "status_result": "resource_indicator_mismatch",
            "request_checks": {
                ("constraints", "transport", "oauth", "protected_resource"): "https://mcp.crm.example/resources/case-search",
                ("constraints", "transport", "oauth", "resource_binding"): "mismatched",
                ("constraints", "transport", "oauth", "required_scope"): "crm.case.update",
                ("constraints", "transport", "oauth", "scopes"): ["crm.case.update"],
                ("constraints", "transport", "mcp", "authorized_tool"): "cases.update",
                ("constraints", "transport", "mcp", "authorized_tool_class"): "write",
                ("constraints", "transport", "mcp", "requested_tool"): "cases.update",
                ("constraints", "transport", "mcp", "requested_tool_class"): "write",
                ("requested_target_resource", "normalized"): "mcp://crm.example/tools/cases.update",
                ("constraints", "requested_tool_class"): "write",
            },
            "receipt_checks": {
                ("request", "requested_target_resource", "normalized"): "mcp://crm.example/tools/cases.update",
                ("request", "transport", "oauth", "resource_binding"): "mismatched",
                ("request", "transport", "oauth", "required_scope"): "crm.case.update",
                ("request", "transport", "oauth", "scopes"): ["crm.case.update"],
                ("request", "transport", "mcp", "authorized_tool"): "cases.update",
                ("request", "transport", "mcp", "authorized_tool_class"): "write",
                ("request", "transport", "mcp", "requested_tool"): "cases.update",
                ("request", "transport", "mcp", "requested_tool_class"): "write",
            },
            "forbidden_receipt_paths": [
                ("evidence", 0, "verification", "full_token"),
                ("evidence", 0, "verification", "tool_payload"),
                ("evidence", 0, "verification", "prompt"),
            ],
            "required_redaction": {
                ("evidence", 0, "verification", "redaction", "token_material"): "omitted",
                ("evidence", 0, "verification", "redaction", "tool_payload"): "omitted",
                ("evidence", 0, "verification", "redaction", "resource_description"): "omitted",
            },
        },
        "deny-mcp-tool-class-mismatch": {
            "reason_codes": ["TOOL_CLASS_MISMATCH", "FAIL_CLOSED"],
            "status_result": "tool_class_mismatch",
            "request_checks": {
                ("constraints", "transport", "oauth", "required_scope"): "crm.case.update",
                ("constraints", "transport", "oauth", "scopes"): ["crm.case.update"],
                ("constraints", "transport", "mcp", "authorized_tool"): "cases.update",
                ("constraints", "transport", "mcp", "authorized_tool_class"): "read",
                ("constraints", "transport", "mcp", "requested_tool"): "cases.update",
                ("constraints", "transport", "mcp", "requested_tool_class"): "write",
            },
            "receipt_checks": {
                ("request", "transport", "oauth", "required_scope"): "crm.case.update",
                ("request", "transport", "oauth", "scopes"): ["crm.case.update"],
                ("request", "transport", "mcp", "authorized_tool"): "cases.update",
                ("request", "transport", "mcp", "authorized_tool_class"): "read",
                ("request", "transport", "mcp", "requested_tool"): "cases.update",
                ("request", "transport", "mcp", "requested_tool_class"): "write",
            },
            "forbidden_receipt_paths": [
                ("evidence", 0, "verification", "full_token"),
                ("evidence", 0, "verification", "tool_payload"),
                ("evidence", 0, "verification", "prompt"),
            ],
            "required_redaction": {
                ("evidence", 0, "verification", "redaction", "token_material"): "omitted",
                ("evidence", 0, "verification", "redaction", "tool_payload"): "omitted",
                ("evidence", 0, "verification", "redaction", "resource_description"): "omitted",
            },
        },
    }
    for case_id, requirements in required_cases.items():
        extra_case_path = case_dir / f"{case_id}.json"
        if not extra_case_path.exists():
            raise RuntimeError(f"MCP/OAuth authority-confusion coverage is missing {case_id}")
        extra_case = json.loads(extra_case_path.read_text(encoding="utf-8"))
        extra_artifacts = extra_case.get("artifacts", {})
        request = json.loads((ROOT / extra_artifacts["admission_request"]).read_text(encoding="utf-8"))
        receipt = json.loads((ROOT / extra_artifacts["admission_receipt"]).read_text(encoding="utf-8"))
        if receipt.get("decision", {}).get("reason_codes") != requirements["reason_codes"]:
            raise RuntimeError(f"{case_id} must use reason_codes {requirements['reason_codes']}")
        if extra_case.get("expected", {}).get("reason_codes") != requirements["reason_codes"]:
            raise RuntimeError(f"{case_id} expected.reason_codes must match the receipt")
        status_results = [
            item.get("verification", {}).get("status_result")
            for item in receipt.get("evidence", [])
            if item.get("type") == "oauth_access_token"
        ]
        if requirements["status_result"] not in status_results:
            raise RuntimeError(f"{case_id} must record {requirements['status_result']} on OAuth evidence")
        for path, expected_value in requirements["request_checks"].items():
            actual_value = value_at_path(request, path)
            if actual_value != expected_value:
                raise RuntimeError(f"{case_id} must set {'.'.join(str(part) for part in path)} to {expected_value}")
        for path, expected_value in requirements.get("receipt_checks", {}).items():
            actual_value = value_at_path(receipt, path)
            if actual_value != expected_value:
                raise RuntimeError(f"{case_id} receipt must set {'.'.join(str(part) for part in path)} to {expected_value}")
        for path in requirements["forbidden_receipt_paths"]:
            if path_exists(receipt, path):
                raise RuntimeError(f"{case_id} must not echo sensitive diagnostic data at {path}")
        for path, expected_value in requirements["required_redaction"].items():
            actual_value = value_at_path(receipt, path)
            if actual_value != expected_value:
                raise RuntimeError(f"{case_id} must mark {'.'.join(str(part) for part in path)} as {expected_value}")

    def parse_fixture_time(value: object, *, label: str) -> datetime:
        if not isinstance(value, str):
            raise RuntimeError(f"{label} must be an RFC3339 timestamp string")
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    positive_control_cases = {
        "allow-mcp-oauth-token-authority-bound": {
            "request_checks": {
                ("constraints", "transport", "oauth", "token_present"): True,
                ("constraints", "transport", "oauth", "upstream_authorization"): "matched",
                ("constraints", "transport", "oauth", "resource_binding"): "matched",
                ("constraints", "transport", "oauth", "resource"): "mcp://crm.example/tools/cases.update",
                ("constraints", "transport", "mcp", "requested_tool_class"): "write",
            },
            "receipt_checks": {
                ("request", "transport", "oauth", "upstream_authorization"): "matched",
                ("request", "transport", "oauth", "resource_binding"): "matched",
                ("request", "transport", "oauth", "resource"): "mcp://crm.example/tools/cases.update",
                ("request", "transport", "mcp", "requested_tool_class"): "write",
            },
        },
        "allow-resource-indicator-aligned": {
            "request_checks": {
                ("requested_target_resource", "normalized"): "mcp://crm.example/tools/cases.update",
                ("constraints", "transport", "oauth", "resource"): "mcp://crm.example/tools/cases.update",
                ("constraints", "transport", "oauth", "protected_resource"): "mcp://crm.example/tools/cases.update",
                ("constraints", "transport", "oauth", "resource_binding"): "matched",
                ("constraints", "transport", "mcp", "requested_tool_class"): "write",
            },
            "receipt_checks": {
                ("request", "requested_target_resource", "normalized"): "mcp://crm.example/tools/cases.update",
                ("request", "transport", "oauth", "resource"): "mcp://crm.example/tools/cases.update",
                ("request", "transport", "oauth", "protected_resource"): "mcp://crm.example/tools/cases.update",
                ("request", "transport", "oauth", "resource_binding"): "matched",
                ("request", "transport", "mcp", "requested_tool_class"): "write",
            },
        },
        "allow-mcp-tool-class-aligned": {
            "request_checks": {
                ("constraints", "transport", "oauth", "resource"): "mcp://crm.example/tools/cases.update",
                ("constraints", "transport", "mcp", "authorized_tool"): "cases.update",
                ("constraints", "transport", "mcp", "authorized_tool_class"): "write",
                ("constraints", "transport", "mcp", "requested_tool"): "cases.update",
                ("constraints", "transport", "mcp", "requested_tool_class"): "write",
            },
            "receipt_checks": {
                ("request", "transport", "oauth", "resource"): "mcp://crm.example/tools/cases.update",
                ("request", "transport", "mcp", "authorized_tool"): "cases.update",
                ("request", "transport", "mcp", "authorized_tool_class"): "write",
                ("request", "transport", "mcp", "requested_tool"): "cases.update",
                ("request", "transport", "mcp", "requested_tool_class"): "write",
            },
        },
    }
    for case_id, requirements in positive_control_cases.items():
        positive_case_path = case_dir / f"{case_id}.json"
        if not positive_case_path.exists():
            raise RuntimeError(f"MCP/OAuth positive-control coverage is missing {case_id}")

        positive_case = json.loads(positive_case_path.read_text(encoding="utf-8"))
        positive_artifacts = positive_case.get("artifacts", {})
        request = json.loads((ROOT / positive_artifacts["admission_request"]).read_text(encoding="utf-8"))
        receipt = json.loads((ROOT / positive_artifacts["admission_receipt"]).read_text(encoding="utf-8"))

        if positive_case.get("category") != "positive":
            raise RuntimeError(f"{case_id} must be a positive-control case")
        expected = positive_case.get("expected", {})
        if expected.get("admission_decision") != "allow" or expected.get("should_execute") is not True:
            raise RuntimeError(f"{case_id} must allow execution as a positive control")
        if expected.get("reason_codes") != ["EVIDENCE_VERIFIED", "POLICY_MATCH"]:
            raise RuntimeError(f"{case_id} expected.reason_codes must be EVIDENCE_VERIFIED then POLICY_MATCH")
        if receipt.get("decision", {}).get("outcome") != "allow":
            raise RuntimeError(f"{case_id} receipt must allow")
        if receipt.get("decision", {}).get("reason_codes") != ["EVIDENCE_VERIFIED", "POLICY_MATCH"]:
            raise RuntimeError(f"{case_id} receipt reason_codes must be EVIDENCE_VERIFIED then POLICY_MATCH")

        if receipt.get("subject", {}).get("actor") != request.get("actor"):
            raise RuntimeError(f"{case_id} must keep actor aligned between request and receipt")
        if receipt.get("subject", {}).get("principal") != request.get("principal"):
            raise RuntimeError(f"{case_id} must keep principal aligned between request and receipt")
        if receipt.get("subject", {}).get("runtime") != request.get("runtime"):
            raise RuntimeError(f"{case_id} must keep runtime aligned between request and receipt")
        if receipt.get("request", {}).get("target_resource") != request.get("target", {}).get("resource"):
            raise RuntimeError(f"{case_id} must keep target resource aligned between request and receipt")
        if receipt.get("request", {}).get("action") != request.get("action"):
            raise RuntimeError(f"{case_id} must keep action aligned between request and receipt")

        for path, expected_value in requirements["request_checks"].items():
            actual_value = value_at_path(request, path)
            if actual_value != expected_value:
                raise RuntimeError(f"{case_id} must set {'.'.join(str(part) for part in path)} to {expected_value}")
        for path, expected_value in requirements["receipt_checks"].items():
            actual_value = value_at_path(receipt, path)
            if actual_value != expected_value:
                raise RuntimeError(f"{case_id} receipt must set {'.'.join(str(part) for part in path)} to {expected_value}")

        request_issued_at = parse_fixture_time(request.get("issued_at"), label=f"{case_id} request.issued_at")
        request_expires_at = parse_fixture_time(request.get("expires_at"), label=f"{case_id} request.expires_at")
        receipt_issued_at = parse_fixture_time(receipt.get("issued_at"), label=f"{case_id} receipt.issued_at")
        receipt_expires_at = parse_fixture_time(receipt.get("expires_at"), label=f"{case_id} receipt.expires_at")
        if receipt_expires_at != request_expires_at:
            raise RuntimeError(f"{case_id} must preserve the request freshness window in the receipt")
        if not request_issued_at <= receipt_issued_at <= request_expires_at:
            raise RuntimeError(f"{case_id} receipt issuance must fall inside the request freshness window")
        for index, evidence in enumerate(receipt.get("evidence", [])):
            verification = evidence.get("verification", {})
            if verification.get("result") != "verified":
                raise RuntimeError(f"{case_id} evidence[{index}] must be verified")
            checked_at = parse_fixture_time(
                verification.get("checked_at"),
                label=f"{case_id} evidence[{index}].verification.checked_at",
            )
            if not request_issued_at <= checked_at <= request_expires_at:
                raise RuntimeError(f"{case_id} evidence[{index}] check must fall inside the request freshness window")

    common_request_stable_paths = [
        ("actor",),
        ("principal",),
        ("runtime",),
        ("audience",),
        ("action",),
        ("target", "resource"),
        ("target", "audience"),
        ("issued_at",),
        ("expires_at",),
        ("constraints", "expected_runtime"),
        ("constraints", "requested_tool"),
        ("constraints", "requested_tool_class"),
        ("constraints", "tool_allowlist"),
    ]
    common_receipt_stable_paths = [
        ("subject", "actor"),
        ("subject", "principal"),
        ("subject", "runtime"),
        ("request", "action"),
        ("request", "target_resource"),
        ("request", "target_audience"),
        ("request", "transport", "mcp", "requested_tool"),
        ("request", "transport", "mcp", "requested_tool_class"),
        ("policy", "policy_id"),
        ("policy", "policy_version"),
        ("policy", "policy_ref"),
        ("issued_at",),
        ("expires_at",),
    ]
    authority_pairs = {
        "mcp-oauth-token-authority": {
            "negative": "deny-token-passthrough-as-authority",
            "positive": "allow-mcp-oauth-token-authority-bound",
            "mutation_axis": "oauth_authority_binding",
            "metadata_stable_fields": [
                "actor",
                "principal",
                "runtime",
                "audience",
                "action",
                "target.resource",
                "target.audience",
                "requested_tool",
                "requested_tool_class",
                "constraints.expected_runtime",
                "constraints.transport.oauth.issuer",
                "constraints.transport.oauth.audience",
                "constraints.transport.oauth.resource",
                "constraints.transport.oauth.protected_resource",
                "constraints.transport.oauth.token_present",
                "constraints.transport.oauth.token_kind",
                "constraints.transport.oauth.required_scope",
                "constraints.transport.oauth.scopes",
                "constraints.transport.oauth.proof_of_possession",
                "constraints.transport.mcp.authorized_tool",
                "constraints.transport.mcp.authorized_tool_class",
                "constraints.transport.mcp.requested_tool",
                "constraints.transport.mcp.requested_tool_class",
                "policy.policy_id",
                "issued_at",
                "expires_at",
            ],
            "metadata_mutated_fields": [
                "constraints.transport.oauth.upstream_authorization",
                "constraints.transport.oauth.resource_binding",
            ],
            "request_stable_paths": common_request_stable_paths + [
                ("constraints", "transport", "oauth", "issuer"),
                ("constraints", "transport", "oauth", "audience"),
                ("constraints", "transport", "oauth", "resource"),
                ("constraints", "transport", "oauth", "protected_resource"),
                ("constraints", "transport", "oauth", "token_present"),
                ("constraints", "transport", "oauth", "token_kind"),
                ("constraints", "transport", "oauth", "required_scope"),
                ("constraints", "transport", "oauth", "scopes"),
                ("constraints", "transport", "oauth", "proof_of_possession"),
                ("constraints", "transport", "mcp", "authorized_tool"),
                ("constraints", "transport", "mcp", "authorized_tool_class"),
                ("constraints", "transport", "mcp", "requested_tool"),
                ("constraints", "transport", "mcp", "requested_tool_class"),
            ],
            "receipt_stable_paths": common_receipt_stable_paths + [
                ("request", "transport", "oauth", "issuer"),
                ("request", "transport", "oauth", "audience"),
                ("request", "transport", "oauth", "resource"),
                ("request", "transport", "oauth", "protected_resource"),
                ("request", "transport", "oauth", "token_present"),
                ("request", "transport", "oauth", "token_kind"),
                ("request", "transport", "oauth", "required_scope"),
                ("request", "transport", "oauth", "scopes"),
                ("request", "transport", "oauth", "proof_of_possession"),
                ("request", "transport", "mcp", "authorized_tool"),
                ("request", "transport", "mcp", "authorized_tool_class"),
            ],
            "request_mutations": [
                (("constraints", "transport", "oauth", "upstream_authorization"), "missing", "matched"),
                (("constraints", "transport", "oauth", "resource_binding"), "missing", "matched"),
            ],
            "receipt_mutations": [
                (("request", "transport", "oauth", "upstream_authorization"), "missing", "matched"),
                (("request", "transport", "oauth", "resource_binding"), "missing", "matched"),
            ],
        },
        "mcp-oauth-resource-indicator": {
            "negative": "deny-resource-indicator-drift",
            "positive": "allow-resource-indicator-aligned",
            "mutation_axis": "oauth_resource_indicator_binding",
            "metadata_stable_fields": [
                "actor",
                "principal",
                "runtime",
                "audience",
                "action",
                "target.resource",
                "target.audience",
                "requested_target_resource.normalized",
                "requested_tool",
                "requested_tool_class",
                "constraints.expected_runtime",
                "constraints.transport.oauth.issuer",
                "constraints.transport.oauth.audience",
                "constraints.transport.oauth.required_scope",
                "constraints.transport.oauth.scopes",
                "constraints.transport.oauth.proof_of_possession",
                "constraints.transport.mcp.authorized_tool",
                "constraints.transport.mcp.authorized_tool_class",
                "constraints.transport.mcp.requested_tool",
                "constraints.transport.mcp.requested_tool_class",
                "policy.policy_id",
                "issued_at",
                "expires_at",
            ],
            "metadata_mutated_fields": [
                "constraints.transport.oauth.resource",
                "constraints.transport.oauth.protected_resource",
                "constraints.transport.oauth.resource_binding",
            ],
            "request_stable_paths": common_request_stable_paths + [
                ("requested_target_resource", "normalized"),
                ("constraints", "transport", "oauth", "issuer"),
                ("constraints", "transport", "oauth", "audience"),
                ("constraints", "transport", "oauth", "required_scope"),
                ("constraints", "transport", "oauth", "scopes"),
                ("constraints", "transport", "oauth", "proof_of_possession"),
                ("constraints", "transport", "mcp", "authorized_tool"),
                ("constraints", "transport", "mcp", "authorized_tool_class"),
                ("constraints", "transport", "mcp", "requested_tool"),
                ("constraints", "transport", "mcp", "requested_tool_class"),
            ],
            "receipt_stable_paths": common_receipt_stable_paths + [
                ("request", "requested_target_resource", "normalized"),
                ("request", "transport", "oauth", "issuer"),
                ("request", "transport", "oauth", "audience"),
                ("request", "transport", "oauth", "required_scope"),
                ("request", "transport", "oauth", "scopes"),
                ("request", "transport", "oauth", "proof_of_possession"),
                ("request", "transport", "mcp", "authorized_tool"),
                ("request", "transport", "mcp", "authorized_tool_class"),
            ],
            "request_mutations": [
                (("constraints", "transport", "oauth", "resource"), "mcp://crm.example/tools/cases.search", "mcp://crm.example/tools/cases.update"),
                (("constraints", "transport", "oauth", "protected_resource"), "https://mcp.crm.example/resources/case-search", "mcp://crm.example/tools/cases.update"),
                (("constraints", "transport", "oauth", "resource_binding"), "mismatched", "matched"),
            ],
            "receipt_mutations": [
                (("request", "transport", "oauth", "resource"), "mcp://crm.example/tools/cases.search", "mcp://crm.example/tools/cases.update"),
                (("request", "transport", "oauth", "protected_resource"), "https://mcp.crm.example/resources/case-search", "mcp://crm.example/tools/cases.update"),
                (("request", "transport", "oauth", "resource_binding"), "mismatched", "matched"),
            ],
        },
        "mcp-oauth-tool-class": {
            "negative": "deny-mcp-tool-class-mismatch",
            "positive": "allow-mcp-tool-class-aligned",
            "mutation_axis": "mcp_tool_class_binding",
            "metadata_stable_fields": [
                "actor",
                "principal",
                "runtime",
                "audience",
                "action",
                "target.resource",
                "target.audience",
                "requested_tool",
                "requested_tool_class",
                "constraints.expected_runtime",
                "constraints.transport.oauth.issuer",
                "constraints.transport.oauth.audience",
                "constraints.transport.oauth.resource",
                "constraints.transport.oauth.required_scope",
                "constraints.transport.oauth.scopes",
                "constraints.transport.oauth.proof_of_possession",
                "constraints.transport.mcp.authorized_tool",
                "constraints.transport.mcp.requested_tool",
                "constraints.transport.mcp.requested_tool_class",
                "policy.policy_id",
                "issued_at",
                "expires_at",
            ],
            "metadata_mutated_fields": [
                "constraints.transport.mcp.authorized_tool_class",
            ],
            "request_stable_paths": common_request_stable_paths + [
                ("constraints", "transport", "oauth", "issuer"),
                ("constraints", "transport", "oauth", "audience"),
                ("constraints", "transport", "oauth", "resource"),
                ("constraints", "transport", "oauth", "required_scope"),
                ("constraints", "transport", "oauth", "scopes"),
                ("constraints", "transport", "oauth", "proof_of_possession"),
                ("constraints", "transport", "mcp", "authorized_tool"),
                ("constraints", "transport", "mcp", "requested_tool"),
                ("constraints", "transport", "mcp", "requested_tool_class"),
            ],
            "receipt_stable_paths": common_receipt_stable_paths + [
                ("request", "transport", "oauth", "issuer"),
                ("request", "transport", "oauth", "audience"),
                ("request", "transport", "oauth", "resource"),
                ("request", "transport", "oauth", "required_scope"),
                ("request", "transport", "oauth", "scopes"),
                ("request", "transport", "oauth", "proof_of_possession"),
                ("request", "transport", "mcp", "authorized_tool"),
            ],
            "request_mutations": [
                (("constraints", "transport", "mcp", "authorized_tool_class"), "read", "write"),
            ],
            "receipt_mutations": [
                (("request", "transport", "mcp", "authorized_tool_class"), "read", "write"),
            ],
        },
    }
    corpus = json.loads((ROOT / "conformance" / "al2-vate-v0.3" / "corpus.json").read_text(encoding="utf-8"))
    corpus_cases = {item.get("case_id"): item for item in corpus.get("cases", [])}
    forbidden_semantic_stable_fields = {
        "request_id",
        "transaction_id",
        "input_hash",
        "correlation.mcp_session_id",
        "correlation.mcp_request_id",
        "evidence_refs.uri",
        "evidence_refs.digest",
        "receipt_id",
        "proof.signature_ref",
    }
    negative_inferred_authority_request_paths = [
        ("request", "transport", "oauth", "inferred_resource_authority"),
        ("request", "transport", "mcp", "inferred_tool_authority"),
    ]
    negative_inferred_authority_evidence_paths = [
        ("verification", "inferred_resource_authority"),
        ("verification", "inferred_tool_authority"),
    ]
    for pair_id, pair in authority_pairs.items():
        negative_case = json.loads((case_dir / f"{pair['negative']}.json").read_text(encoding="utf-8"))
        positive_case = json.loads((case_dir / f"{pair['positive']}.json").read_text(encoding="utf-8"))
        negative_request = json.loads((ROOT / negative_case["artifacts"]["admission_request"]).read_text(encoding="utf-8"))
        positive_request = json.loads((ROOT / positive_case["artifacts"]["admission_request"]).read_text(encoding="utf-8"))
        negative_receipt = json.loads((ROOT / negative_case["artifacts"]["admission_receipt"]).read_text(encoding="utf-8"))
        positive_receipt = json.loads((ROOT / positive_case["artifacts"]["admission_receipt"]).read_text(encoding="utf-8"))

        expected_stable_fields = negative_case.get("pairing", {}).get("stable_fields")
        expected_mutated_fields = negative_case.get("pairing", {}).get("mutated_fields")
        if not isinstance(expected_stable_fields, list) or not all(isinstance(field, str) for field in expected_stable_fields):
            raise RuntimeError(f"{pair['negative']} pairing.stable_fields must be a string array")
        if not isinstance(expected_mutated_fields, list) or not all(isinstance(field, str) for field in expected_mutated_fields):
            raise RuntimeError(f"{pair['negative']} pairing.mutated_fields must be a string array")
        missing_metadata_stable_fields = sorted(set(pair["metadata_stable_fields"]) - set(expected_stable_fields))
        if missing_metadata_stable_fields:
            raise RuntimeError(
                f"{pair_id} pairing.stable_fields must expose route-card lane fields: "
                f"{missing_metadata_stable_fields}"
            )
        forbidden_metadata_stable_fields = sorted(forbidden_semantic_stable_fields & set(expected_stable_fields))
        if forbidden_metadata_stable_fields:
            raise RuntimeError(
                f"{pair_id} pairing.stable_fields must not include fixture identity fields: "
                f"{forbidden_metadata_stable_fields}"
            )
        if expected_mutated_fields != pair["metadata_mutated_fields"]:
            raise RuntimeError(
                f"{pair_id} pairing.mutated_fields must declare only {pair['metadata_mutated_fields']}"
            )
        expected_negative_pairing = {
            "pair_id": pair_id,
            "role": "negative",
            "paired_case_id": pair["positive"],
            "mutation_axis": pair["mutation_axis"],
            "stable_fields": expected_stable_fields,
            "mutated_fields": expected_mutated_fields,
        }
        expected_positive_pairing = {
            "pair_id": pair_id,
            "role": "positive",
            "paired_case_id": pair["negative"],
            "mutation_axis": pair["mutation_axis"],
            "stable_fields": expected_stable_fields,
            "mutated_fields": expected_mutated_fields,
        }
        if negative_case.get("pairing") != expected_negative_pairing:
            raise RuntimeError(f"{pair['negative']} pairing metadata is not the expected mutation-minimal shape")
        if positive_case.get("pairing") != expected_positive_pairing:
            raise RuntimeError(f"{pair['positive']} pairing metadata is not the expected mutation-minimal shape")
        if corpus_cases.get(pair["negative"], {}).get("pairing") != negative_case.get("pairing"):
            raise RuntimeError(f"corpus index must expose the complete {pair['negative']} pairing metadata")
        if corpus_cases.get(pair["positive"], {}).get("pairing") != positive_case.get("pairing"):
            raise RuntimeError(f"corpus index must expose the complete {pair['positive']} pairing metadata")

        for path in pair["request_stable_paths"]:
            negative_value = value_at_path(negative_request, path)
            positive_value = value_at_path(positive_request, path)
            if negative_value != positive_value:
                raise RuntimeError(f"{pair_id} request stable field {'.'.join(str(part) for part in path)} drifted")
        for path in pair["receipt_stable_paths"]:
            negative_value = value_at_path(negative_receipt, path)
            positive_value = value_at_path(positive_receipt, path)
            if negative_value != positive_value:
                raise RuntimeError(f"{pair_id} receipt stable field {'.'.join(str(part) for part in path)} drifted")

        for path, negative_expected, positive_expected in pair["request_mutations"]:
            if value_at_path(negative_request, path) != negative_expected:
                raise RuntimeError(f"{pair['negative']} must set mutation field {'.'.join(str(part) for part in path)} to {negative_expected}")
            if value_at_path(positive_request, path) != positive_expected:
                raise RuntimeError(f"{pair['positive']} must set mutation field {'.'.join(str(part) for part in path)} to {positive_expected}")
        for path, negative_expected, positive_expected in pair["receipt_mutations"]:
            if value_at_path(negative_receipt, path) != negative_expected:
                raise RuntimeError(f"{pair['negative']} receipt must set mutation field {'.'.join(str(part) for part in path)} to {negative_expected}")
            if value_at_path(positive_receipt, path) != positive_expected:
                raise RuntimeError(f"{pair['positive']} receipt must set mutation field {'.'.join(str(part) for part in path)} to {positive_expected}")

        for path in negative_inferred_authority_request_paths:
            if path_exists(negative_receipt, path):
                raise RuntimeError(f"{pair['negative']} must not record inferred authority at {path}")
        for index, evidence in enumerate(negative_receipt.get("evidence", [])):
            for path in negative_inferred_authority_evidence_paths:
                if path_exists(evidence, path):
                    raise RuntimeError(f"{pair['negative']} evidence[{index}] must not record inferred authority at {path}")


def check_status_freshness_boundary_coverage() -> None:
    conformance = load_vate_conformance_module()
    for accepted in (
        "2026-07-01T00:00:00Z",
        "2026-07-01T00:00:00.1z",
        "2026-07-01T00:00:00.123456+00:00",
    ):
        if conformance.try_parse_time(accepted) is None:
            raise RuntimeError(f"supported RFC3339 timestamp was rejected: {accepted}")
    for rejected in (
        "2026-07-01T00:00:00.1234567Z",
        "2026-07-01T00:00:00.0000001+00:00",
    ):
        if conformance.try_parse_time(rejected) is not None:
            raise RuntimeError(f"sub-microsecond RFC3339 timestamp was truncated: {rejected}")

    case_path = ROOT / "conformance" / "al2-vate-v0.3" / "cases" / "allow-status-fresh-at-boundary.json"
    if not case_path.exists():
        raise RuntimeError(
            "status freshness coverage is missing allow-status-fresh-at-boundary: "
            "AL2 context checks must prove that the exact max_age_seconds boundary "
            "is still fresh."
        )
    case = json.loads(case_path.read_text(encoding="utf-8"))
    context_path = ROOT / case["artifacts"]["status_context"]
    context = json.loads(context_path.read_text(encoding="utf-8"))
    checked_at = datetime.fromisoformat(context["checked_at"].replace("Z", "+00:00"))
    source_issued_at = datetime.fromisoformat(context["source_issued_at"].replace("Z", "+00:00"))
    max_age_seconds = context.get("max_age_seconds")
    if (checked_at - source_issued_at).total_seconds() != max_age_seconds:
        raise RuntimeError("allow-status-fresh-at-boundary must exercise the exact max_age_seconds boundary")
    if case.get("expected", {}).get("admission_decision") != "allow":
        raise RuntimeError("allow-status-fresh-at-boundary must allow the exact freshness boundary")

    overprecision_context = json.loads(json.dumps(context))
    overprecision_context["source_issued_at"] = "2026-07-01T00:00:00Z"
    overprecision_context["checked_at"] = "2026-07-01T00:05:00.0000001Z"
    overprecision_context["max_age_seconds"] = 300
    freshness_check = next(
        check
        for check in case.get("al2_context_checks", [])
        if isinstance(check, dict) and check.get("kind") == "freshness"
    )
    overprecision_failures = conformance.evaluate_context_freshness_check(
        freshness_check,
        overprecision_context,
        require_status_context=True,
    )
    if not any(
        "freshness timestamps must be valid" in failure
        or "expected valid timestamp" in failure
        for failure in overprecision_failures
    ):
        raise RuntimeError(
            "300.0000001-second status age must be rejected, not truncated to fresh"
        )


def check_status_input_contract_coverage() -> None:
    conformance = load_vate_conformance_module()
    case_path = (
        ROOT
        / "conformance"
        / "al2-vate-v0.3"
        / "cases"
        / "deny-status-revoked.json"
    )
    case = json.loads(case_path.read_text(encoding="utf-8"))
    requirements = conformance.required_sut_artifacts(case)
    expected_inputs = requirements.get("input_artifacts")
    if not isinstance(expected_inputs, list) or len(expected_inputs) != 1:
        raise RuntimeError("deny-status-revoked must declare exactly one authoritative SUT input")
    if any(
        requirements.get(field)
        for field in ("receipt_artifacts", "verification_context", "proof_artifacts")
    ):
        raise RuntimeError(
            "explicit status input contract must not treat expected receipts or legacy context fields as SUT inputs"
        )

    expected_input = expected_inputs[0]
    case_artifact = expected_input.get("case_artifact")
    role = expected_input.get("role")
    expected_uri = expected_input.get("expected_uri")
    expected_media_type = expected_input.get("expected_media_type")
    expected_digest = expected_input.get("expected_digest")
    if (
        case_artifact != "status_context"
        or role != "status_evidence"
        or expected_uri != case["artifacts"]["status_context"]
        or expected_media_type != "application/json"
        or not isinstance(expected_digest, str)
        or len(expected_digest) != 64
    ):
        raise RuntimeError("deny-status-revoked authoritative input contract drifted")

    correct_ref = {
        "case_artifact": case_artifact,
        "role": role,
        "uri": case["artifacts"][case_artifact],
        "media_type": "application/json",
        "digest": {
            "alg": "sha-256",
            "value": expected_digest,
        },
    }
    valid_result = {"artifacts": {"input_artifacts": [correct_ref]}}
    if conformance.sut_result_artifact_failures(valid_result, requirements):
        raise RuntimeError("exact explicit status input reference must satisfy the SUT input contract")

    missing_failures = conformance.sut_result_artifact_failures({"artifacts": {}}, requirements)
    if not any("input_artifacts: required non-empty array" in failure for failure in missing_failures):
        raise RuntimeError("explicit status input contract must reject a missing input reference")

    wrong_digest_ref = json.loads(json.dumps(correct_ref))
    wrong_digest_ref["digest"]["value"] = "0" * 64
    wrong_digest_failures = conformance.sut_result_artifact_failures(
        {"artifacts": {"input_artifacts": [wrong_digest_ref]}},
        requirements,
    )
    if not any("expected corpus digest" in failure for failure in wrong_digest_failures):
        raise RuntimeError("explicit status input contract must reject a digest mismatch")

    wrong_uri_ref = json.loads(json.dumps(correct_ref))
    wrong_uri_ref["uri"] = case["artifacts"]["admission_receipt"]
    wrong_uri_failures = conformance.sut_result_artifact_failures(
        {"artifacts": {"input_artifacts": [wrong_uri_ref]}},
        requirements,
    )
    if not any("uri mismatch" in failure for failure in wrong_uri_failures):
        raise RuntimeError("explicit status input contract must bind the declared input URI")

    wrong_media_ref = json.loads(json.dumps(correct_ref))
    wrong_media_ref["media_type"] = "application/vate-admission-receipt+json"
    wrong_media_failures = conformance.sut_result_artifact_failures(
        {"artifacts": {"input_artifacts": [wrong_media_ref]}},
        requirements,
    )
    if not any("media_type mismatch" in failure for failure in wrong_media_failures):
        raise RuntimeError("explicit status input contract must bind the declared media type")

    extra_field_ref = json.loads(json.dumps(correct_ref))
    extra_field_ref["expected_receipt"] = case["artifacts"]["admission_receipt"]
    extra_field_failures = conformance.sut_result_artifact_failures(
        {"artifacts": {"input_artifacts": [extra_field_ref]}},
        requirements,
    )
    if not any("unsupported input artifact field" in failure for failure in extra_field_failures):
        raise RuntimeError("explicit status input references must reject unknown fields")

    extra_digest_field_ref = json.loads(json.dumps(correct_ref))
    extra_digest_field_ref["digest"]["expected_receipt"] = case["artifacts"][
        "admission_receipt"
    ]
    extra_digest_field_failures = conformance.sut_result_artifact_failures(
        {"artifacts": {"input_artifacts": [extra_digest_field_ref]}},
        requirements,
    )
    if not any(
        "unsupported input digest field" in failure
        for failure in extra_digest_field_failures
    ):
        raise RuntimeError(
            "explicit status input digest descriptors must reject unknown fields"
        )

    duplicate_failures = conformance.sut_result_artifact_failures(
        {"artifacts": {"input_artifacts": [correct_ref, correct_ref]}},
        requirements,
    )
    if not any("duplicate logical input artifact key" in failure for failure in duplicate_failures):
        raise RuntimeError("explicit status input contract must reject duplicate logical inputs")

    unexpected_ref = json.loads(json.dumps(correct_ref))
    unexpected_ref["case_artifact"] = "unexpected_context"
    unexpected_ref["role"] = "unexpected_role"
    unexpected_failures = conformance.sut_result_artifact_failures(
        {"artifacts": {"input_artifacts": [correct_ref, unexpected_ref]}},
        requirements,
    )
    if not any("unexpected case_artifact" in failure for failure in unexpected_failures):
        raise RuntimeError("explicit status input contract must reject undeclared extra inputs")

    legacy_failures = conformance.sut_result_artifact_failures(
        {
            "artifacts": {
                "input_artifacts": [correct_ref],
                "admission_receipt": {
                    "uri": case["artifacts"]["admission_receipt"],
                    "media_type": "application/vate-admission-receipt+json",
                    "digest": {"alg": "sha-256", "value": "0" * 64},
                },
            }
        },
        requirements,
    )
    if not any(
        "not allowed when the case declares authoritative sut_inputs" in failure
        for failure in legacy_failures
    ):
        raise RuntimeError("explicit status input contract must reject legacy expected-receipt input fields")

    aliased_receipt_failures = conformance.sut_result_artifact_failures(
        {
            "artifacts": {
                "input_artifacts": [correct_ref],
                "admission_receipt_fixture": {
                    "uri": case["artifacts"]["admission_receipt"],
                    "media_type": "application/vate-admission-receipt+json",
                    "digest": {"alg": "sha-256", "value": "0" * 64},
                },
            }
        },
        requirements,
    )
    if not any(
        "not allowed when the case declares authoritative sut_inputs" in failure
        for failure in aliased_receipt_failures
    ):
        raise RuntimeError("explicit status input contract must reject aliased receipt fields")

    legacy_case = json.loads(
        (
            ROOT
            / "conformance"
            / "al2-vate-v0.3"
            / "cases"
            / "allow-valid-admission.json"
        ).read_text(encoding="utf-8")
    )
    legacy_requirements = conformance.required_sut_artifacts(legacy_case)
    legacy_result = next(
        result
        for result in json.loads(
            (
                ROOT / "examples" / "conformance" / "sut-results-pass.example.json"
            ).read_text(encoding="utf-8")
        )["results"]
        if result.get("case_id") == "allow-valid-admission"
    )
    legacy_result_with_input = json.loads(json.dumps(legacy_result))
    legacy_result_with_input.setdefault("artifacts", {})["input_artifacts"] = [correct_ref]
    legacy_input_failures = conformance.sut_result_artifact_failures(
        legacy_result_with_input,
        legacy_requirements,
    )
    if not any(
        "not allowed when the case does not declare authoritative sut_inputs" in failure
        for failure in legacy_input_failures
    ):
        raise RuntimeError("legacy cases must reject explicit input_artifacts")

    legacy_case_without_artifacts = json.loads(json.dumps(legacy_case))
    legacy_case_without_artifacts["artifacts"] = None
    if conformance.sut_input_contract_failures(legacy_case_without_artifacts) != [
        "artifacts: expected object"
    ]:
        raise RuntimeError("legacy cases must fail closed on a non-object artifacts field")

    no_artifact_input_failures = conformance.sut_result_artifact_failures(
        {"artifacts": {"input_artifacts": [correct_ref]}},
        {
            "input_artifacts": [],
            "receipt_artifacts": [],
            "verification_context": [],
            "proof_artifacts": [],
        },
    )
    if not any(
        "not allowed when the case does not declare authoritative sut_inputs" in failure
        for failure in no_artifact_input_failures
    ):
        raise RuntimeError("no-artifact cases must reject explicit input_artifacts")

    revoked_context = json.loads(
        (ROOT / case["artifacts"][case_artifact]).read_text(encoding="utf-8")
    )
    status_check = case["al2_context_checks"][0]
    if conformance.evaluate_context_status_check(status_check, revoked_context):
        raise RuntimeError("valid revoked status context must satisfy its status check")

    unavailable_with_status = {
        "required": True,
        "availability": "unavailable",
        "status": "active",
    }
    unavailable_failures = conformance.evaluate_context_status_check(
        {
            "kind": "status",
            "artifact": "status_context",
            "expect_status": "unavailable",
            "expect_required": True,
            "expected_failure_reason": "STATUS_UNAVAILABLE",
        },
        unavailable_with_status,
    )
    if not any("must not carry a status value" in failure for failure in unavailable_failures):
        raise RuntimeError("unavailable status context must reject a carried status value")

    optional_unavailable_context = {
        "version": "vate-status-context-2026-09",
        "source": "status_bundle",
        "required": False,
        "availability": "unavailable",
        "checked_at": "2026-07-01T00:09:05Z",
    }
    optional_unavailable_failures = conformance.evaluate_context_status_check(
        {
            "kind": "status",
            "artifact": "status_context",
            "expect_status": "unavailable",
            "expect_required": False,
        },
        optional_unavailable_context,
    )
    if optional_unavailable_failures:
        raise RuntimeError(
            "required=false unavailable status context must remain a valid "
            f"non-failure result: {optional_unavailable_failures}"
        )

    unavailable_context = json.loads(
        (
            ROOT
            / "conformance"
            / "al2-vate-v0.3"
            / "fixtures"
            / "status-unavailable-context.json"
        ).read_text(encoding="utf-8")
    )
    unavailable_case = json.loads(
        (
            ROOT
            / "conformance"
            / "al2-vate-v0.3"
            / "cases"
            / "deny-status-unavailable-fail-closed.json"
        ).read_text(encoding="utf-8")
    )
    unavailable_check = unavailable_case["al2_context_checks"][0]
    invalid_optional_timestamp = dict(unavailable_context)
    invalid_optional_timestamp["source_issued_at"] = 42
    if not any(
        "source_issued_at: expected valid timestamp when present" in failure
        for failure in conformance.evaluate_context_status_check(
            unavailable_check,
            invalid_optional_timestamp,
        )
    ):
        raise RuntimeError("unavailable status context must validate optional source_issued_at")
    invalid_optional_max_age = dict(unavailable_context)
    invalid_optional_max_age["max_age_seconds"] = "300"
    if not any(
        "max_age_seconds: expected non-negative integer when present" in failure
        for failure in conformance.evaluate_context_status_check(
            unavailable_check,
            invalid_optional_max_age,
        )
    ):
        raise RuntimeError("unavailable status context must validate optional max_age_seconds")

    status_case_paths = sorted(
        (ROOT / "conformance" / "al2-vate-v0.3" / "cases").glob("*status*.json")
    )
    if len(status_case_paths) != 6:
        raise RuntimeError(
            f"expected 6 explicit status-input cases, found {len(status_case_paths)}"
        )
    for status_case_path in status_case_paths:
        status_case = json.loads(status_case_path.read_text(encoding="utf-8"))
        sut_inputs = status_case.get("sut_inputs")
        if not isinstance(sut_inputs, list) or not sut_inputs:
            raise RuntimeError(
                f"{status_case['case_id']}: status cases must declare authoritative sut_inputs"
            )
        for sut_input in sut_inputs:
            input_path = ROOT / status_case["artifacts"][sut_input["artifact"]]
            input_text = input_path.read_text(encoding="utf-8")
            if "failure_reason" in json.loads(input_text):
                raise RuntimeError(f"{status_case['case_id']}: status input must not carry failure_reason")
            for reason_code in status_case["expected"]["reason_codes"]:
                if reason_code in input_text:
                    raise RuntimeError(
                        f"{status_case['case_id']}: status input leaks expected reason code {reason_code}"
                    )

    stale_case = json.loads(
        (
            ROOT
            / "conformance"
            / "al2-vate-v0.3"
            / "cases"
            / "deny-status-stale-fail-closed.json"
        ).read_text(encoding="utf-8")
    )
    stale_context = json.loads(
        (ROOT / stale_case["artifacts"]["status_context"]).read_text(encoding="utf-8")
    )
    stale_status_check = next(
        check for check in stale_case["al2_context_checks"] if check["kind"] == "status"
    )
    not_required = dict(stale_context)
    not_required["required"] = False
    if not conformance.evaluate_context_status_check(stale_status_check, not_required):
        raise RuntimeError("stale status case must reject required=false")
    unavailable_stale = dict(stale_context)
    unavailable_stale["availability"] = "unavailable"
    unavailable_stale.pop("status", None)
    freshness_check = next(
        check for check in stale_case["al2_context_checks"] if check["kind"] == "freshness"
    )
    if not conformance.evaluate_context_freshness_check(freshness_check, unavailable_stale):
        raise RuntimeError("status freshness must reject availability=unavailable")

    wrong_version_with_answer = dict(stale_context)
    wrong_version_with_answer["version"] = "vate-status-context-2026-06"
    wrong_version_with_answer["failure_reason"] = "STATUS_STALE"
    wrong_version_failures = conformance.evaluate_context_freshness_check(
        freshness_check,
        wrong_version_with_answer,
        require_status_context=True,
    )
    if not any(".version: expected" in failure for failure in wrong_version_failures):
        raise RuntimeError("status freshness must fail closed on a wrong status-context version")
    if not any(
        "failure_reason: unsupported status context field" in failure
        for failure in wrong_version_failures
    ):
        raise RuntimeError("status freshness must reject an input-carried VATE failure reason")

    uppercase_utc = conformance.try_parse_time("2026-07-15T00:00:00Z")
    lowercase_utc = conformance.try_parse_time("2026-07-15T00:00:00z")
    offset_utc = conformance.try_parse_time("2026-07-15T00:00:00+00:00")
    if uppercase_utc is None or lowercase_utc is None or offset_utc is None:
        raise RuntimeError("runner must accept RFC3339 UTC timestamps using Z, z, or +00:00")
    if uppercase_utc != lowercase_utc or uppercase_utc != offset_utc:
        raise RuntimeError("equivalent RFC3339 UTC timestamp spellings must resolve identically")
    for invalid_timestamp in (
        "2026-07-01T24:00:00Z",
        "2026-W27-3T12:00:00Z",
        "2026-02-30T12:00:00Z",
        "not-a-time",
    ):
        if conformance.try_parse_time(invalid_timestamp) is not None:
            raise RuntimeError(
                f"runner must reject unsupported RFC3339 timestamp {invalid_timestamp}"
            )
        invalid_timestamp_context = json.loads(json.dumps(revoked_context))
        invalid_timestamp_context["checked_at"] = invalid_timestamp
        invalid_timestamp_failures = conformance.evaluate_context_status_check(
            status_check,
            invalid_timestamp_context,
        )
        if not any(
            "checked_at: expected valid timestamp" in failure
            for failure in invalid_timestamp_failures
        ):
            raise RuntimeError(
                f"status evaluation must reject invalid checked_at={invalid_timestamp}"
            )

    extra_case_field = json.loads(json.dumps(case))
    extra_case_field["sut_inputs"][0]["expected_failure_reason"] = "STATUS_REVOKED"
    extra_case_field_failures = conformance.sut_input_contract_failures(extra_case_field)
    if not any(
        "unsupported SUT input field" in failure
        for failure in extra_case_field_failures
    ):
        raise RuntimeError("case sut_inputs must reject unknown fields")

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_base = Path(temp_dir)
        for source_status_case_path in status_case_paths:
            case_id = source_status_case_path.stem
            temp_root = temp_base / f"corpus-missing-sut-inputs-{case_id}"
            shutil.copytree(ROOT / "conformance" / "al2-vate-v0.3", temp_root)
            missing_case_path = temp_root / "cases" / source_status_case_path.name
            missing_case = json.loads(missing_case_path.read_text(encoding="utf-8"))
            missing_case.pop("sut_inputs", None)
            missing_case_path.write_text(
                json.dumps(missing_case, indent=2) + "\n",
                encoding="utf-8",
            )
            expected_failure = "sut_inputs: required for cases with status context checks"

            try:
                conformance.make_corpus_index(temp_root)
            except RuntimeError as exc:
                if expected_failure not in str(exc):
                    raise RuntimeError(
                        f"index returned the wrong missing sut_inputs failure for {case_id}"
                    ) from exc
            else:
                raise RuntimeError(
                    f"index must fail closed when {case_id} omits sut_inputs"
                )

            missing_run = conformance.run_corpus(temp_root)
            if missing_run.get("cases") or not any(
                expected_failure in failure
                for failure in missing_run.get("fatal_errors", [])
            ):
                raise RuntimeError(
                    f"run must fail closed when {case_id} omits sut_inputs"
                )

            _, missing_digest, _ = conformance.corpus_manifest(temp_root)
            missing_sut = json.loads(
                (
                    ROOT / "examples" / "conformance" / "sut-results-pass.example.json"
                ).read_text(encoding="utf-8")
            )
            missing_sut["corpus"]["digest"] = missing_digest
            missing_sut_path = temp_base / f"sut-results-missing-{case_id}.json"
            missing_sut_path.write_text(
                json.dumps(missing_sut, indent=2) + "\n",
                encoding="utf-8",
            )
            missing_compare = conformance.compare_sut_results(
                temp_root,
                missing_sut_path,
            )
            if not any(
                expected_failure in failure
                for failure in missing_compare.get("fatal_errors", [])
            ):
                raise RuntimeError(
                    f"compare must fail closed when {case_id} omits sut_inputs"
                )

            missing_bundle = conformance.verify_report_bundle(
                temp_root,
                ROOT / "examples" / "conformance-report.example.json",
                ROOT / "examples" / "implementation-report.example.json",
                missing_sut_path,
            )
            if not any(
                check.get("name", "").startswith("corpus.sut_inputs[")
                and check.get("pass") is False
                and expected_failure in str(check.get("actual"))
                for check in missing_bundle.get("checks", [])
            ):
                raise RuntimeError(
                    f"verify-bundle must fail closed when {case_id} omits sut_inputs"
                )

        for label, malformed_inputs in (("empty", []), ("null", None)):
            temp_root = temp_base / f"corpus-{label}"
            shutil.copytree(ROOT / "conformance" / "al2-vate-v0.3", temp_root)
            malformed_case_path = temp_root / "cases" / "deny-status-revoked.json"
            malformed_case = json.loads(malformed_case_path.read_text(encoding="utf-8"))
            malformed_case["sut_inputs"] = malformed_inputs
            malformed_case_path.write_text(
                json.dumps(malformed_case, indent=2) + "\n",
                encoding="utf-8",
            )

            try:
                conformance.make_corpus_index(temp_root)
            except RuntimeError as exc:
                if "sut_inputs: expected non-empty array" not in str(exc):
                    raise RuntimeError(
                        f"index returned the wrong {label} sut_inputs failure"
                    ) from exc
            else:
                raise RuntimeError(f"index must fail closed on sut_inputs={malformed_inputs!r}")

            malformed_run = conformance.run_corpus(temp_root)
            if malformed_run.get("cases"):
                raise RuntimeError(
                    f"run must not evaluate cases after detecting sut_inputs={malformed_inputs!r}"
                )
            if not any(
                "sut_inputs: expected non-empty array" in failure
                for failure in malformed_run.get("fatal_errors", [])
            ):
                raise RuntimeError(f"run must fail closed on sut_inputs={malformed_inputs!r}")

            _, malformed_digest, _ = conformance.corpus_manifest(temp_root)
            malformed_sut = json.loads(
                (
                    ROOT / "examples" / "conformance" / "sut-results-pass.example.json"
                ).read_text(encoding="utf-8")
            )
            malformed_sut["corpus"]["digest"] = malformed_digest
            malformed_sut_path = temp_base / f"sut-results-{label}.json"
            malformed_sut_path.write_text(
                json.dumps(malformed_sut, indent=2) + "\n",
                encoding="utf-8",
            )
            malformed_report = conformance.compare_sut_results(temp_root, malformed_sut_path)
            if not any(
                "sut_inputs: expected non-empty array" in failure
                for failure in malformed_report.get("fatal_errors", [])
            ):
                raise RuntimeError(f"compare must fail closed on sut_inputs={malformed_inputs!r}")

            malformed_bundle = conformance.verify_report_bundle(
                temp_root,
                ROOT / "examples" / "conformance-report.example.json",
                ROOT / "examples" / "implementation-report.example.json",
                malformed_sut_path,
            )
            if not any(
                check.get("name", "").startswith("corpus.sut_inputs[")
                and check.get("pass") is False
                and "sut_inputs: expected non-empty array" in str(check.get("actual"))
                for check in malformed_bundle.get("checks", [])
            ):
                raise RuntimeError(
                    f"verify-bundle must fail closed on sut_inputs={malformed_inputs!r}"
                )

        malformed_artifact_values = (
            ("null", None),
            ("array", []),
            ("string", "not-an-object"),
            ("number", 0),
            ("boolean", False),
        )
        for label, malformed_artifacts in malformed_artifact_values:
            temp_root = temp_base / f"corpus-artifacts-{label}"
            shutil.copytree(ROOT / "conformance" / "al2-vate-v0.3", temp_root)
            malformed_case_path = temp_root / "cases" / "deny-status-revoked.json"
            malformed_case = json.loads(malformed_case_path.read_text(encoding="utf-8"))
            malformed_case["artifacts"] = malformed_artifacts
            malformed_case_path.write_text(
                json.dumps(malformed_case, indent=2) + "\n",
                encoding="utf-8",
            )
            expected_failure = "artifacts: expected object"

            try:
                conformance.make_corpus_index(temp_root)
            except RuntimeError as exc:
                if expected_failure not in str(exc):
                    raise RuntimeError(
                        f"index returned the wrong artifacts={label} failure"
                    ) from exc
            else:
                raise RuntimeError(f"index must fail closed on artifacts={label}")

            malformed_run = conformance.run_corpus(temp_root)
            if malformed_run.get("cases"):
                raise RuntimeError(
                    f"run must not evaluate cases after detecting artifacts={label}"
                )
            if not any(
                expected_failure in failure
                for failure in malformed_run.get("fatal_errors", [])
            ):
                raise RuntimeError(f"run must fail closed on artifacts={label}")

            _, malformed_digest, _ = conformance.corpus_manifest(temp_root)
            malformed_sut = json.loads(
                (
                    ROOT / "examples" / "conformance" / "sut-results-pass.example.json"
                ).read_text(encoding="utf-8")
            )
            malformed_sut["corpus"]["digest"] = malformed_digest
            malformed_sut_path = temp_base / f"sut-results-artifacts-{label}.json"
            malformed_sut_path.write_text(
                json.dumps(malformed_sut, indent=2) + "\n",
                encoding="utf-8",
            )
            malformed_report = conformance.compare_sut_results(
                temp_root,
                malformed_sut_path,
            )
            if not any(
                expected_failure in failure
                for failure in malformed_report.get("fatal_errors", [])
            ):
                raise RuntimeError(f"compare must fail closed on artifacts={label}")

            malformed_bundle = conformance.verify_report_bundle(
                temp_root,
                ROOT / "examples" / "conformance-report.example.json",
                ROOT / "examples" / "implementation-report.example.json",
                malformed_sut_path,
            )
            if not any(
                check.get("name") == "corpus.cases.envelope"
                and check.get("pass") is False
                and expected_failure in str(check.get("actual"))
                for check in malformed_bundle.get("checks", [])
            ):
                raise RuntimeError(f"verify-bundle must fail closed on artifacts={label}")

        legacy_sut = json.loads(
            (
                ROOT / "examples" / "conformance" / "sut-results-pass.example.json"
            ).read_text(encoding="utf-8")
        )
        legacy_sut_result = next(
            result
            for result in legacy_sut["results"]
            if result.get("case_id") == "allow-valid-admission"
        )
        legacy_sut_result.setdefault("artifacts", {})["input_artifacts"] = [correct_ref]
        legacy_sut_path = temp_base / "sut-results-legacy-extra-input.json"
        legacy_sut_path.write_text(
            json.dumps(legacy_sut, indent=2) + "\n",
            encoding="utf-8",
        )
        legacy_compare = conformance.compare_sut_results(
            ROOT / "conformance" / "al2-vate-v0.3",
            legacy_sut_path,
        )
        legacy_case_result = next(
            result
            for result in legacy_compare["cases"]
            if result.get("case_id") == "allow-valid-admission"
        )
        if legacy_case_result.get("pass") is not False or not any(
            "not allowed when the case does not declare authoritative sut_inputs" in failure
            for failure in legacy_case_result.get("failures", [])
        ):
            raise RuntimeError("compare must reject input_artifacts on a legacy case")

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_root = Path(temp_dir) / "corpus"
        shutil.copytree(ROOT / "conformance" / "al2-vate-v0.3", temp_root)
        status_fixture_path = temp_root / "fixtures" / "status-revoked-context.json"
        lowercase_status = json.loads(status_fixture_path.read_text(encoding="utf-8"))
        for field in ("source_issued_at", "checked_at"):
            lowercase_status[field] = lowercase_status[field][:-1] + "z"
        status_fixture_path.write_text(
            json.dumps(lowercase_status, indent=2) + "\n",
            encoding="utf-8",
        )
        status_case_path = temp_root / "cases" / "deny-status-revoked.json"
        lowercase_status_case = json.loads(status_case_path.read_text(encoding="utf-8"))
        lowercase_status_case["artifacts"]["status_context"] = str(
            status_fixture_path.resolve()
        )
        status_case_path.write_text(
            json.dumps(lowercase_status_case, indent=2) + "\n",
            encoding="utf-8",
        )
        lowercase_status_run = conformance.run_corpus(temp_root)
        lowercase_status_result = next(
            item
            for item in lowercase_status_run["cases"]
            if item["case_id"] == "deny-status-revoked"
        )
        if lowercase_status_result.get("pass") is not True:
            raise RuntimeError(
                "runner must accept schema-valid lowercase RFC3339 UTC designators: "
                f"{lowercase_status_result.get('failures')}"
            )

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_root = Path(temp_dir) / "corpus"
        shutil.copytree(ROOT / "conformance" / "al2-vate-v0.3", temp_root)
        stale_fixture_path = temp_root / "fixtures" / "status-stale-context.json"
        malformed_status = json.loads(stale_fixture_path.read_text(encoding="utf-8"))
        malformed_status["version"] = "vate-status-context-2026-06"
        malformed_status["failure_reason"] = "STATUS_STALE"
        stale_fixture_path.write_text(
            json.dumps(malformed_status, indent=2) + "\n",
            encoding="utf-8",
        )
        stale_case_path = temp_root / "cases" / "deny-status-stale-fail-closed.json"
        copied_stale_case = json.loads(stale_case_path.read_text(encoding="utf-8"))
        copied_stale_case["artifacts"]["status_context"] = str(
            stale_fixture_path.resolve()
        )
        stale_case_path.write_text(
            json.dumps(copied_stale_case, indent=2) + "\n",
            encoding="utf-8",
        )
        malformed_status_run = conformance.run_corpus(temp_root)
        stale_result = next(
            item
            for item in malformed_status_run["cases"]
            if item["case_id"] == "deny-status-stale-fail-closed"
        )
        if stale_result.get("pass") is not False or not any(
            "unsupported status context field" in failure
            or ".version: expected" in failure
            for failure in stale_result.get("failures", [])
        ):
            raise RuntimeError(
                "run must reject a wrong-version status context carrying the expected reason"
            )


def check_external_sut_template_partial_contract() -> None:
    conformance = load_vate_conformance_module()
    report = conformance.compare_sut_results(
        ROOT / "conformance" / "al2-vate-v0.3",
        ROOT / "examples" / "external-sut-template" / "starter-sut-result.template.json",
    )
    if report.get("fatal_errors"):
        raise RuntimeError(
            "external SUT starter template must match the current corpus digest without fatal errors: "
            f"{report['fatal_errors']}"
        )
    if report.get("summary") != {
        "total": 76,
        "passed": 3,
        "failed": 73,
        "skipped": 0,
    }:
        raise RuntimeError(
            "external SUT starter template must report 3/76 passing cases: "
            f"{report.get('summary')}"
        )
    failed_cases = [case for case in report.get("cases", []) if case.get("pass") is not True]
    if len(failed_cases) != 73 or any(
        case.get("failures") != ["sut result missing"] for case in failed_cases
    ):
        raise RuntimeError(
            "external SUT starter template failures must be exactly 73 missing result entries"
        )


def check_sut_result_envelope_fail_closed() -> None:
    conformance = load_vate_conformance_module()
    passing_path = ROOT / "examples" / "conformance" / "sut-results-pass.example.json"
    passing = json.loads(passing_path.read_text(encoding="utf-8"))

    for generated_at in (
        None,
        "2026-07-01T00:00:00.0000001Z",
        "2026-07-01T24:00:00Z",
        "2026-W27-3T12:00:00Z",
        "2026-02-30T12:00:00Z",
        "not-a-time",
    ):
        variant = json.loads(json.dumps(passing))
        if generated_at is None:
            variant.pop("generated_at", None)
        else:
            variant["generated_at"] = generated_at
        failures = conformance.sut_result_envelope_failures(variant)
        if not any("sut_results.generated_at" in failure for failure in failures):
            raise RuntimeError(
                f"SUT result envelope must reject generated_at={generated_at!r}"
            )

    for field in ("name", "type", "version", "language"):
        for invalid_value in (None, "", 7, False):
            variant = json.loads(json.dumps(passing))
            if invalid_value is None:
                variant["implementation"].pop(field, None)
            else:
                variant["implementation"][field] = invalid_value
            failures = conformance.sut_result_envelope_failures(variant)
            if not any(
                f"sut_results.implementation.{field}" in failure
                for failure in failures
            ):
                raise RuntimeError(
                    f"SUT result envelope must reject implementation.{field}={invalid_value!r}"
                )

    for invalid_results in (None, {}, "not-an-array", 7, False):
        variant = json.loads(json.dumps(passing))
        if invalid_results is None:
            variant.pop("results", None)
        else:
            variant["results"] = invalid_results
        failures = conformance.sut_result_envelope_failures(variant)
        if not any("sut_results.results" in failure for failure in failures):
            raise RuntimeError(
                f"SUT result envelope must reject results={invalid_results!r}"
            )

    with tempfile.TemporaryDirectory(prefix="vate-sut-envelope-") as temp_dir:
        temp_root = Path(temp_dir)
        malformed = json.loads(json.dumps(passing))
        malformed.pop("generated_at", None)
        malformed["implementation"] = {}
        malformed_path = temp_root / "sut-results.json"
        compare_path = temp_root / "compare-report.json"
        implementation_path = temp_root / "implementation-report.json"
        malformed_path.write_text(
            json.dumps(malformed, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        result = run_expect_failure(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(malformed_path),
                "--report",
                str(compare_path),
                "--implementation-report",
                str(implementation_path),
                "--conformance-report-uri",
                str(compare_path),
                "--implementation-report-uri",
                str(implementation_path),
            ]
        )
        if "Traceback" in result.stderr:
            raise RuntimeError("malformed SUT result envelope caused compare traceback")
        compare_report = assert_strict_json_file(compare_path)
        implementation_report = assert_strict_json_file(implementation_path)
        if conformance.conformance_report_status(compare_report) != "fail":
            raise RuntimeError("malformed SUT result envelope must not produce a passing report")
        if implementation_report.get("status") != "fail":
            raise RuntimeError(
                "malformed SUT result envelope must produce a failed implementation report"
            )
        assert_report_error_contains(compare_path, "sut_results.generated_at")
        for field in ("name", "type", "version", "language"):
            assert_report_error_contains(
                compare_path,
                f"sut_results.implementation.{field}",
            )

        for index, invalid_results in enumerate((None, {}, "not-an-array", 7, False)):
            malformed_results = json.loads(json.dumps(passing))
            if invalid_results is None:
                malformed_results.pop("results", None)
            else:
                malformed_results["results"] = invalid_results
            malformed_results_path = temp_root / f"sut-results-malformed-{index}.json"
            malformed_results_report_path = temp_root / f"compare-malformed-{index}.json"
            malformed_results_implementation_path = (
                temp_root / f"implementation-malformed-{index}.json"
            )
            malformed_results_path.write_text(
                json.dumps(malformed_results, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            malformed_results_process = run_expect_failure(
                [
                    sys.executable,
                    str(VATE_CONFORMANCE),
                    "compare",
                    "--corpus-root",
                    str(ROOT / "conformance" / "al2-vate-v0.3"),
                    "--sut-results",
                    str(malformed_results_path),
                    "--report",
                    str(malformed_results_report_path),
                    "--implementation-report",
                    str(malformed_results_implementation_path),
                    "--conformance-report-uri",
                    str(malformed_results_report_path),
                    "--implementation-report-uri",
                    str(malformed_results_implementation_path),
                ]
            )
            if "Traceback" in malformed_results_process.stderr:
                raise RuntimeError("malformed results shape caused compare traceback")
            malformed_results_report = assert_strict_json_file(
                malformed_results_report_path
            )
            malformed_results_implementation = assert_strict_json_file(
                malformed_results_implementation_path
            )
            if conformance.conformance_report_status(malformed_results_report) != "fail":
                raise RuntimeError("malformed results shape must fail the conformance report")
            if malformed_results_implementation.get("status") != "fail":
                raise RuntimeError("malformed results shape must fail the implementation report")
            assert_report_error_contains(
                malformed_results_report_path,
                "sut_results.results",
            )

        empty_corpus_root = temp_root / "empty-corpus"
        (empty_corpus_root / "cases").mkdir(parents=True)
        _, empty_digest, _ = conformance.corpus_manifest(empty_corpus_root)
        empty_submission = json.loads(json.dumps(passing))
        empty_submission.pop("results", None)
        empty_submission["corpus"]["digest"] = empty_digest
        empty_submission_path = temp_root / "empty-corpus-sut-results.json"
        empty_report_path = temp_root / "empty-corpus-compare.json"
        empty_implementation_path = temp_root / "empty-corpus-implementation.json"
        empty_submission_path.write_text(
            json.dumps(empty_submission, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        empty_process = run_expect_failure(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(empty_corpus_root),
                "--sut-results",
                str(empty_submission_path),
                "--report",
                str(empty_report_path),
                "--implementation-report",
                str(empty_implementation_path),
                "--conformance-report-uri",
                str(empty_report_path),
                "--implementation-report-uri",
                str(empty_implementation_path),
            ]
        )
        if "Traceback" in empty_process.stderr:
            raise RuntimeError("empty corpus compare caused traceback")
        empty_report = assert_strict_json_file(empty_report_path)
        empty_implementation = assert_strict_json_file(empty_implementation_path)
        if empty_report.get("summary") != {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
        }:
            raise RuntimeError("empty corpus compare must retain an explicit 0/0 summary")
        if conformance.conformance_report_status(empty_report) != "fail":
            raise RuntimeError("empty corpus compare must fail despite its 0/0 summary")
        if empty_implementation.get("status") != "fail":
            raise RuntimeError("empty corpus compare must fail the implementation report")
        assert_report_error_contains(empty_report_path, "no conformance case files found")
        assert_report_error_contains(empty_report_path, "sut_results.results")


def check_case_json_fail_closed() -> None:
    canonical_corpus = ROOT / "conformance" / "al2-vate-v0.3"
    passing_sut = ROOT / "examples" / "conformance" / "sut-results-pass.example.json"
    with tempfile.TemporaryDirectory(prefix="vate-malformed-case-") as temp_dir:
        temp_root = Path(temp_dir)
        baseline_compare = temp_root / "baseline-compare.json"
        baseline_implementation = temp_root / "baseline-implementation.json"
        run(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(canonical_corpus),
                "--sut-results",
                str(passing_sut),
                "--report",
                str(baseline_compare),
                "--implementation-report",
                str(baseline_implementation),
                "--conformance-report-uri",
                str(baseline_compare),
                "--implementation-report-uri",
                str(baseline_implementation),
            ]
        )
        malformed_corpus = temp_root / "corpus"
        shutil.copytree(canonical_corpus, malformed_corpus)
        target_case = malformed_corpus / "cases" / "allow-valid-admission.json"
        canonical_case = json.loads(target_case.read_text(encoding="utf-8"))
        expected_null = json.loads(json.dumps(canonical_case))
        expected_null["expected"] = None
        expected_array = json.loads(json.dumps(canonical_case))
        expected_array["expected"] = []
        expected_string = json.loads(json.dumps(canonical_case))
        expected_string["expected"] = "invalid"
        expected_number = json.loads(json.dumps(canonical_case))
        expected_number["expected"] = 7
        expected_bool = json.loads(json.dumps(canonical_case))
        expected_bool["expected"] = False
        expected_empty = json.loads(json.dumps(canonical_case))
        expected_empty["expected"] = {}
        reason_codes_null = json.loads(json.dumps(canonical_case))
        reason_codes_null["expected"]["reason_codes"] = None
        checks_null = json.loads(json.dumps(canonical_case))
        checks_null["expected"]["checks"] = None
        case_id_missing = json.loads(json.dumps(canonical_case))
        case_id_missing.pop("case_id", None)
        conformance = load_vate_conformance_module()
        collection_fields = (
            "validation_focus",
            "integrity_checks",
            "trust_checks",
            "jose_checks",
            "policy_snapshot_checks",
            "artifact_reference_checks",
            "linkage_checks",
            "attenuation_checks",
            "al2_context_checks",
        )
        malformed_collection_values = (
            {},
            None,
            "invalid",
            [None],
            [{}],
        )
        for collection_field in collection_fields:
            for malformed_value in malformed_collection_values:
                malformed_case = json.loads(json.dumps(canonical_case))
                malformed_case[collection_field] = malformed_value
                collection_failures = conformance.case_envelope_failures(
                    malformed_case
                )
                if not any(
                    collection_field in failure
                    for failure in collection_failures
                ):
                    raise RuntimeError(
                        f"{collection_field} malformed value was not rejected: "
                        f"{malformed_value!r}"
                    )

        for nested_label, collection_field, check_template, nested_field in (
            (
                "policy_snapshot_checks[0].reference_paths",
                "policy_snapshot_checks",
                {"artifact": "admission_receipt"},
                "reference_paths",
            ),
            (
                "policy_snapshot_checks[0].compare_fields",
                "policy_snapshot_checks",
                {"artifact": "admission_receipt"},
                "compare_fields",
            ),
            (
                "artifact_reference_checks[0].reference_paths",
                "artifact_reference_checks",
                {"artifact": "admission_receipt"},
                "reference_paths",
            ),
        ):
            for malformed_value in malformed_collection_values:
                malformed_case = json.loads(json.dumps(canonical_case))
                malformed_check = json.loads(json.dumps(check_template))
                malformed_check[nested_field] = malformed_value
                malformed_case[collection_field] = [malformed_check]
                nested_failures = conformance.case_envelope_failures(
                    malformed_case
                )
                if not any(
                    nested_label in failure for failure in nested_failures
                ):
                    raise RuntimeError(
                        f"{nested_label} malformed value was not rejected: "
                        f"{malformed_value!r}"
                    )

        valid_pairing = {
            "pair_id": "test-pair",
            "role": "positive",
            "paired_case_id": "paired-case",
            "mutation_axis": "test-axis",
            "stable_fields": ["expected.should_execute"],
            "mutated_fields": ["artifacts.admission_receipt"],
        }
        for pairing_field in ("stable_fields", "mutated_fields"):
            for malformed_value in malformed_collection_values:
                malformed_case = json.loads(json.dumps(canonical_case))
                malformed_pairing = json.loads(json.dumps(valid_pairing))
                malformed_pairing[pairing_field] = malformed_value
                malformed_case["pairing"] = malformed_pairing
                pairing_failures = conformance.case_envelope_failures(
                    malformed_case
                )
                if not any(
                    f"pairing.{pairing_field}" in failure
                    for failure in pairing_failures
                ):
                    raise RuntimeError(
                        f"pairing.{pairing_field} malformed value was not rejected: "
                        f"{malformed_value!r}"
                    )

        cli_collection_variants: list[tuple[str, str]] = []
        for label, malformed_value in (
            ("object", {}),
            ("null", None),
            ("scalar", "invalid"),
            ("item-null", [None]),
            ("item-empty", [{}]),
        ):
            malformed_case = json.loads(json.dumps(canonical_case))
            malformed_case["integrity_checks"] = malformed_value
            cli_collection_variants.append(
                (
                    f"integrity-checks-{label}",
                    json.dumps(malformed_case) + "\n",
                )
            )
        for collection_field in collection_fields:
            if collection_field == "integrity_checks":
                continue
            malformed_case = json.loads(json.dumps(canonical_case))
            malformed_case[collection_field] = [{}]
            cli_collection_variants.append(
                (
                    f"{collection_field.replace('_', '-')}-item-empty",
                    json.dumps(malformed_case) + "\n",
                )
            )
        for label, collection_field, malformed_check in (
            (
                "policy-reference-paths-item-empty",
                "policy_snapshot_checks",
                {
                    "artifact": "admission_receipt",
                    "reference_paths": [{}],
                },
            ),
            (
                "policy-compare-fields-item-empty",
                "policy_snapshot_checks",
                {
                    "artifact": "admission_receipt",
                    "compare_fields": [{}],
                },
            ),
            (
                "artifact-reference-paths-item-empty",
                "artifact_reference_checks",
                {
                    "artifact": "admission_receipt",
                    "reference_paths": [{}],
                },
            ),
        ):
            malformed_case = json.loads(json.dumps(canonical_case))
            malformed_case[collection_field] = [malformed_check]
            cli_collection_variants.append(
                (label, json.dumps(malformed_case) + "\n")
            )

        variants: tuple[tuple[str, str], ...] = (
            ("array", "[]\n"),
            ("null", "null\n"),
            ("scalar", '"not-an-object"\n'),
            ("malformed", '{"case_id":\n'),
            ("expected-null", json.dumps(expected_null) + "\n"),
            ("expected-array", json.dumps(expected_array) + "\n"),
            ("expected-string", json.dumps(expected_string) + "\n"),
            ("expected-number", json.dumps(expected_number) + "\n"),
            ("expected-bool", json.dumps(expected_bool) + "\n"),
            ("expected-empty", json.dumps(expected_empty) + "\n"),
            ("reason-codes-null", json.dumps(reason_codes_null) + "\n"),
            ("checks-null", json.dumps(checks_null) + "\n"),
            ("case-id-missing", json.dumps(case_id_missing) + "\n"),
            *cli_collection_variants,
        )
        for label, payload in variants:
            target_case.write_text(payload, encoding="utf-8")
            run_report = temp_root / f"run-{label}.json"
            compare_report = temp_root / f"compare-{label}.json"
            bundle_report = temp_root / f"bundle-{label}.json"
            index_out = temp_root / f"index-{label}.json"

            commands = (
                (
                    "run",
                    [
                        sys.executable,
                        str(VATE_CONFORMANCE),
                        "run",
                        "--corpus-root",
                        str(malformed_corpus),
                        "--report",
                        str(run_report),
                    ],
                    run_report,
                ),
                (
                    "compare",
                    [
                        sys.executable,
                        str(VATE_CONFORMANCE),
                        "compare",
                        "--corpus-root",
                        str(malformed_corpus),
                        "--sut-results",
                        str(passing_sut),
                        "--report",
                        str(compare_report),
                    ],
                    compare_report,
                ),
                (
                    "verify-bundle",
                    [
                        sys.executable,
                        str(VATE_CONFORMANCE),
                        "verify-bundle",
                        "--corpus-root",
                        str(malformed_corpus),
                        "--sut-results",
                        str(passing_sut),
                        "--conformance-report",
                        str(baseline_compare),
                        "--implementation-report",
                        str(baseline_implementation),
                        "--report",
                        str(bundle_report),
                    ],
                    bundle_report,
                ),
            )
            for command_name, command, report_path in commands:
                process = run_expect_failure(command)
                if "Traceback" in process.stderr:
                    raise RuntimeError(
                        f"{command_name} traceback for {label} corpus case"
                    )
                report = assert_strict_json_file(report_path)
                if command_name == "verify-bundle":
                    if report.get("status") != "fail" and not report.get(
                        "summary", {}
                    ).get("failed"):
                        raise RuntimeError(
                            f"verify-bundle must fail for {label} corpus case"
                        )
                    if "corpus case" not in json.dumps(report):
                        raise RuntimeError(
                            f"verify-bundle report must identify {label} corpus case failure"
                        )
                else:
                    assert_report_error_contains(report_path, "corpus case")

            index_process = run_expect_failure(
                [
                    sys.executable,
                    str(VATE_CONFORMANCE),
                    "index",
                    "--corpus-root",
                    str(malformed_corpus),
                    "--out",
                    str(index_out),
                ]
            )
            if "Traceback" in index_process.stderr:
                raise RuntimeError(f"index traceback for {label} corpus case")
            if "corpus case" not in index_process.stderr:
                raise RuntimeError(f"index must identify {label} corpus case failure")


def check_corpus_index_requires_cases() -> None:
    canonical_corpus = ROOT / "conformance" / "al2-vate-v0.3"
    canonical_index = canonical_corpus / "corpus.json"
    with tempfile.TemporaryDirectory(prefix="vate-index-case-floor-") as temp_dir:
        temp_root = Path(temp_dir)
        regenerated_index = temp_root / "canonical-corpus.json"
        run(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "index",
                "--corpus-root",
                str(canonical_corpus),
                "--out",
                str(regenerated_index),
            ]
        )
        if regenerated_index.read_bytes() != canonical_index.read_bytes():
            raise RuntimeError("canonical corpus index regeneration is not byte-identical")

        missing_cases_root = temp_root / "missing-cases"
        missing_cases_root.mkdir()
        empty_cases_root = temp_root / "empty-cases"
        (empty_cases_root / "cases").mkdir(parents=True)
        for label, corpus_root in (
            ("missing", missing_cases_root),
            ("empty", empty_cases_root),
        ):
            output_path = temp_root / f"{label}-corpus.json"
            process = run_expect_failure(
                [
                    sys.executable,
                    str(VATE_CONFORMANCE),
                    "index",
                    "--corpus-root",
                    str(corpus_root),
                    "--out",
                    str(output_path),
                ]
            )
            if "Traceback" in process.stderr:
                raise RuntimeError(f"index traceback for {label} cases directory")
            if output_path.exists():
                raise RuntimeError(f"index generated a zero-case corpus for {label} cases")
            expected_error = (
                "cases directory is missing" if label == "missing"
                else "no conformance case files found"
            )
            if expected_error not in process.stderr:
                raise RuntimeError(
                    f"index did not report the {label} cases failure: {process.stderr}"
                )


def check_case_artifact_reference_fail_closed() -> None:
    canonical_corpus = ROOT / "conformance" / "al2-vate-v0.3"
    passing_sut = ROOT / "examples" / "conformance" / "sut-results-pass.example.json"
    with tempfile.TemporaryDirectory(prefix="vate-case-artifact-contract-") as temp_dir:
        temp_root = Path(temp_dir)
        baseline_report = temp_root / "baseline-report.json"
        baseline_implementation = temp_root / "baseline-implementation.json"
        run(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(canonical_corpus),
                "--sut-results",
                str(passing_sut),
                "--report",
                str(baseline_report),
                "--implementation-report",
                str(baseline_implementation),
                "--conformance-report-uri",
                str(baseline_report),
                "--implementation-report-uri",
                str(baseline_implementation),
            ]
        )
        malformed_corpus = temp_root / "corpus"
        shutil.copytree(canonical_corpus, malformed_corpus)

        def assert_corpus_rejected(
            label: str,
            *,
            require_index_failure: bool = True,
        ) -> None:
            run_report = temp_root / f"{label}-run.json"
            compare_report = temp_root / f"{label}-compare.json"
            bundle_report = temp_root / f"{label}-bundle.json"
            commands = (
                (
                    "run",
                    [
                        sys.executable,
                        str(VATE_CONFORMANCE),
                        "run",
                        "--corpus-root",
                        str(malformed_corpus),
                        "--report",
                        str(run_report),
                    ],
                    run_report,
                ),
                (
                    "compare",
                    [
                        sys.executable,
                        str(VATE_CONFORMANCE),
                        "compare",
                        "--corpus-root",
                        str(malformed_corpus),
                        "--sut-results",
                        str(passing_sut),
                        "--report",
                        str(compare_report),
                    ],
                    compare_report,
                ),
                (
                    "verify-bundle",
                    [
                        sys.executable,
                        str(VATE_CONFORMANCE),
                        "verify-bundle",
                        "--corpus-root",
                        str(malformed_corpus),
                        "--sut-results",
                        str(passing_sut),
                        "--conformance-report",
                        str(baseline_report),
                        "--implementation-report",
                        str(baseline_implementation),
                        "--report",
                        str(bundle_report),
                    ],
                    bundle_report,
                ),
            )
            for command_name, command, report_path in commands:
                process = run_expect_failure(command)
                if "Traceback" in process.stderr:
                    raise RuntimeError(
                        f"{command_name} traceback for {label} artifact contract"
                    )
                report = assert_strict_json_file(report_path)
                if command_name == "verify-bundle":
                    if report.get("status") != "fail":
                        raise RuntimeError(
                            f"verify-bundle passed {label} artifact contract"
                        )
                elif report.get("summary", {}).get("failed", 0) == 0 and not report.get(
                    "fatal_errors"
                ):
                    raise RuntimeError(
                        f"{command_name} did not record {label} artifact failure"
                    )
            index_command = [
                sys.executable,
                str(VATE_CONFORMANCE),
                "index",
                "--corpus-root",
                str(malformed_corpus),
                "--out",
                str(temp_root / f"{label}-index.json"),
            ]
            if require_index_failure:
                index_process = run_expect_failure(index_command)
            else:
                run(index_command)
                index_process = None
            if index_process is not None and "Traceback" in index_process.stderr:
                raise RuntimeError(f"index traceback for {label} artifact contract")

        base_artifact_case_path = (
            malformed_corpus
            / "cases"
            / "deny-digest-mismatch-before-policy.json"
        )
        canonical_base_artifact_case = json.loads(
            base_artifact_case_path.read_text(encoding="utf-8")
        )
        for label, malformed_value in (
            ("artifact-object", {}),
            ("artifact-null", None),
            ("artifact-number", 7),
            ("artifact-boolean", False),
        ):
            malformed_case = json.loads(json.dumps(canonical_base_artifact_case))
            malformed_case["artifacts"]["base_artifact"] = malformed_value
            base_artifact_case_path.write_text(
                json.dumps(malformed_case, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            assert_corpus_rejected(label)
        base_artifact_case_path.write_text(
            json.dumps(
                canonical_base_artifact_case,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        policy_case_path = (
            malformed_corpus
            / "cases"
            / "allow-valid-with-policy-snapshot.json"
        )
        canonical_policy_case = json.loads(
            policy_case_path.read_text(encoding="utf-8")
        )
        policy_case = json.loads(json.dumps(canonical_policy_case))
        policy_case["policy_snapshot_checks"][0]["reference_paths"][0][
            "path"
        ] = "decision.outcome"
        policy_case_path.write_text(
            json.dumps(policy_case, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        assert_corpus_rejected("policy-reference-scalar")
        policy_case = json.loads(json.dumps(canonical_policy_case))
        policy_case["policy_snapshot_checks"][0]["reference_paths"][0][
            "artifact"
        ] = {}
        policy_case_path.write_text(
            json.dumps(policy_case, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        assert_corpus_rejected("policy-reference-artifact-object")
        policy_case_path.write_text(
            json.dumps(canonical_policy_case, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        case_mutations = (
            (
                "category-object",
                "allow-valid-admission.json",
                lambda case: case.__setitem__("category", {}),
            ),
            (
                "expected-check-enum-array",
                "allow-valid-admission.json",
                lambda case: case["expected"]["checks"][0].__setitem__(
                    "expected", []
                ),
            ),
            (
                "pairing-role-object",
                "deny-token-passthrough-as-authority.json",
                lambda case: case["pairing"].__setitem__("role", {}),
            ),
            (
                "al2-kind-array",
                "allow-status-fresh-at-boundary.json",
                lambda case: case["al2_context_checks"][0].__setitem__(
                    "kind", []
                ),
            ),
            (
                "linkage-kind-object",
                "post-execution-runtime-mismatch.json",
                lambda case: case["linkage_checks"][0].__setitem__(
                    "kind", {}
                ),
            ),
        )
        for label, filename, mutate in case_mutations:
            case_path = malformed_corpus / "cases" / filename
            canonical_case = json.loads(case_path.read_text(encoding="utf-8"))
            malformed_case = json.loads(json.dumps(canonical_case))
            mutate(malformed_case)
            case_path.write_text(
                json.dumps(malformed_case, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            assert_corpus_rejected(label)
            case_path.write_text(
                json.dumps(canonical_case, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

        status_case_path = (
            malformed_corpus / "cases" / "allow-status-fresh-at-boundary.json"
        )
        canonical_status_case = json.loads(
            status_case_path.read_text(encoding="utf-8")
        )
        malformed_status_case = json.loads(json.dumps(canonical_status_case))
        canonical_status_context_path = ROOT / canonical_status_case["artifacts"][
            "status_context"
        ]
        malformed_status_context = json.loads(
            canonical_status_context_path.read_text(encoding="utf-8")
        )
        malformed_status_context["availability"] = {}
        malformed_status_context_path = temp_root / "status-context-object.json"
        malformed_status_context_path.write_text(
            json.dumps(malformed_status_context, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        malformed_status_case["artifacts"]["status_context"] = str(
            malformed_status_context_path
        )
        status_case_path.write_text(
            json.dumps(malformed_status_case, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        assert_corpus_rejected(
            "status-availability-object",
            require_index_failure=False,
        )


def check_unhashable_validator_inputs_fail_closed() -> None:
    conformance = load_vate_conformance_module()
    canonical_case_path = (
        ROOT
        / "conformance"
        / "al2-vate-v0.3"
        / "cases"
        / "allow-valid-admission.json"
    )
    canonical_case = json.loads(canonical_case_path.read_text(encoding="utf-8"))

    direct_cases: list[tuple[str, Any, str]] = []
    malformed_values = ({}, [], None, 7, False)
    for value_index, malformed_value in enumerate(malformed_values):
        category_case = json.loads(json.dumps(canonical_case))
        category_case["category"] = malformed_value
        direct_cases.append(
            (
                f"case category malformed {value_index}",
                lambda case=category_case: conformance.case_envelope_failures(
                    case
                ),
                "category",
            )
        )
        check_enum_case = json.loads(json.dumps(canonical_case))
        check_enum_case["expected"]["checks"][0][
            "expected"
        ] = malformed_value
        direct_cases.append(
            (
                f"expected check enum malformed {value_index}",
                lambda case=check_enum_case: conformance.case_envelope_failures(
                    case
                ),
                "expected.checks",
            )
        )
        policy_case = {
            "policy_snapshot_checks": [
                {
                    "artifact": "policy_snapshot",
                    "reference_paths": [
                        {"artifact": malformed_value, "path": "policy"}
                    ],
                }
            ]
        }
        direct_cases.append(
            (
                f"policy reference malformed {value_index}",
                lambda case=policy_case: conformance.case_check_collection_failures(
                    case
                ),
                "reference_paths",
            )
        )
        pairing_case = {
            "pairing": {
                "pair_id": "pair",
                "role": malformed_value,
                "paired_case_id": "other",
                "mutation_axis": "axis",
                "stable_fields": ["field"],
                "mutated_fields": ["other_field"],
            }
        }
        direct_cases.append(
            (
                f"pairing role malformed {value_index}",
                lambda case=pairing_case: conformance.case_check_collection_failures(
                    case
                ),
                "pairing.role",
            )
        )
        al2_case = {
            "al2_context_checks": [
                {"kind": malformed_value, "artifact": "context"}
            ]
        }
        direct_cases.append(
            (
                f"AL2 kind malformed {value_index}",
                lambda case=al2_case: conformance.case_check_collection_failures(
                    case
                ),
                "al2_context_checks[0].kind",
            )
        )
        linkage_case = {"linkage_checks": [{"kind": malformed_value}]}
        direct_cases.append(
            (
                f"linkage kind malformed {value_index}",
                lambda case=linkage_case: conformance.case_check_collection_failures(
                    case
                ),
                "kind must be a string enum",
            )
        )
        status_context = {"availability": malformed_value}
        direct_cases.append(
            (
                f"status availability malformed {value_index}",
                lambda context=status_context: conformance.status_context_shape_failures(
                    context, "status"
                ),
                "availability",
            )
        )
        implementation_status_report = {"status": malformed_value}
        direct_cases.append(
            (
                f"implementation status malformed {value_index}",
                lambda report=implementation_status_report: conformance.implementation_report_contract_failures(
                    report
                ),
                "status",
            )
        )
        conformance_artifact_mode_report = {
            "sut_results": {"artifact_mode": malformed_value}
        }
        direct_cases.append(
            (
                f"report artifact mode malformed {value_index}",
                lambda report=conformance_artifact_mode_report: conformance.conformance_report_contract_failures(
                    report
                ),
                "artifact_mode",
            )
        )
        implementation_digest_basis_report = {
            "conformance_report": {"digest_basis": malformed_value}
        }
        direct_cases.append(
            (
                f"report digest basis malformed {value_index}",
                lambda report=implementation_digest_basis_report: conformance.implementation_report_contract_failures(
                    report
                ),
                "digest_basis",
            )
        )

    for label, call, expected_fragment in direct_cases:
        failures = call()
        if not isinstance(failures, list) or not any(
            expected_fragment in failure for failure in failures
        ):
            raise RuntimeError(
                f"{label} did not produce the expected validator failure"
            )


def check_context_binding_key_contract() -> None:
    conformance = load_vate_conformance_module()
    passing_sut_path = (
        ROOT / "examples" / "conformance" / "sut-results-pass.example.json"
    )
    passing_sut = json.loads(passing_sut_path.read_text(encoding="utf-8"))

    canonical_by_role: dict[str, dict] = {}
    for result in passing_sut["results"]:
        artifacts = result.get("artifacts")
        if not isinstance(artifacts, dict):
            continue
        for context in artifacts.get("verification_context", []):
            if not isinstance(context, dict):
                continue
            for binding in context.get("context_bindings", []):
                if isinstance(binding, dict) and isinstance(
                    binding.get("role"), str
                ):
                    canonical_by_role.setdefault(binding["role"], binding)

    expected_roles = {
        "admission_receipt",
        "admission_request",
        "transaction_id",
        "runtime",
        "evidence",
    }
    if set(canonical_by_role) != expected_roles:
        raise RuntimeError(
            "passing SUT example does not cover every context binding role"
        )
    for role in sorted(expected_roles):
        binding = json.loads(json.dumps(canonical_by_role[role]))
        binding["extension_object"] = {"review": "preserved"}
        binding["extension_string"] = "preserved"
        key, failures = conformance.validated_context_binding_key(
            binding,
            f"canonical.{role}",
        )
        if key is None or failures:
            raise RuntimeError(
                f"canonical {role} binding or extension metadata was rejected: "
                f"{failures}"
            )

    malformed_values = ([], {}, None, 7, False)
    direct_probes = (
        ("path", canonical_by_role["admission_receipt"]),
        ("evidence_type", canonical_by_role["admission_receipt"]),
    )
    for field, canonical_binding in direct_probes:
        for malformed_value in malformed_values:
            binding = json.loads(json.dumps(canonical_binding))
            binding[field] = malformed_value
            key, failures = conformance.validated_context_binding_key(
                binding,
                f"malformed.{field}",
            )
            if key is not None or not any(
                f".{field}: expected non-empty string" in failure
                for failure in failures
            ):
                raise RuntimeError(
                    f"malformed context binding {field}={malformed_value!r} "
                    "did not fail the central key contract"
                )
            shape_failures = conformance.context_binding_shape_failures(
                binding,
                f"malformed.{field}",
            )
            if not any(
                f".{field}: expected non-empty string" in failure
                for failure in shape_failures
            ):
                raise RuntimeError(
                    f"malformed optional context binding {field}="
                    f"{malformed_value!r} passed direct shape validation"
                )

    with tempfile.TemporaryDirectory(prefix="vate-context-binding-key-") as tmp:
        tmp_path = Path(tmp)
        extension_sut = json.loads(json.dumps(passing_sut))
        extension_sut["extension_object"] = {"review": "preserved"}
        extension_sut["extension_string"] = "preserved"
        extension_binding = None
        for result in extension_sut["results"]:
            artifacts = result.get("artifacts")
            if not isinstance(artifacts, dict):
                continue
            for context in artifacts.get("verification_context", []):
                if not isinstance(context, dict):
                    continue
                for binding in context.get("context_bindings", []):
                    if (
                        isinstance(binding, dict)
                        and binding.get("role") == "admission_receipt"
                    ):
                        extension_binding = binding
                        break
                if extension_binding is not None:
                    break
            if extension_binding is not None:
                break
        if extension_binding is None:
            raise RuntimeError(
                "could not locate admission_receipt binding for extension probe"
            )
        extension_binding["extension_object"] = {"review": "preserved"}
        extension_binding["extension_string"] = "preserved"
        extension_sut_path = tmp_path / "extension-sut.json"
        extension_report_path = tmp_path / "extension-report.json"
        extension_sut_path.write_text(
            json.dumps(extension_sut, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        run(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(extension_sut_path),
                "--report",
                str(extension_report_path),
            ]
        )
        extension_report = assert_strict_json_file(extension_report_path)
        if extension_report.get("summary") != {
            "total": 76,
            "passed": 76,
            "failed": 0,
            "skipped": 0,
        }:
            raise RuntimeError(
                "valid SUT/context binding extension metadata changed compare "
                f"results: {extension_report.get('summary')}"
            )

        for field in ("path", "evidence_type"):
            role = "admission_receipt"
            for value_index, malformed_value in enumerate(malformed_values):
                sut_results = json.loads(json.dumps(passing_sut))
                mutated = False
                for result in sut_results["results"]:
                    artifacts = result.get("artifacts")
                    if not isinstance(artifacts, dict):
                        continue
                    for context in artifacts.get("verification_context", []):
                        if not isinstance(context, dict):
                            continue
                        for binding in context.get("context_bindings", []):
                            if (
                                isinstance(binding, dict)
                                and binding.get("role") == role
                            ):
                                binding[field] = malformed_value
                                mutated = True
                                break
                        if mutated:
                            break
                    if mutated:
                        break
                if not mutated:
                    raise RuntimeError(
                        f"could not locate {role} binding for {field} probe"
                    )

                sut_path = tmp_path / f"{field}-{value_index}-sut.json"
                report_path = tmp_path / f"{field}-{value_index}-report.json"
                sut_path.write_text(
                    json.dumps(sut_results, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                process = run_expect_failure(
                    [
                        sys.executable,
                        str(VATE_CONFORMANCE),
                        "compare",
                        "--corpus-root",
                        str(ROOT / "conformance" / "al2-vate-v0.3"),
                        "--sut-results",
                        str(sut_path),
                        "--report",
                        str(report_path),
                    ]
                )
                if "Traceback" in process.stderr:
                    raise RuntimeError(
                        f"context binding {field} probe caused traceback"
                    )
                report = assert_strict_json_file(report_path)
                if report.get("summary", {}).get("failed", 0) < 1:
                    raise RuntimeError(
                        f"context binding {field} probe did not fail compare"
                    )
                assert_report_error_contains(
                    report_path,
                    f".{field}: expected non-empty string",
                )


def check_bundle_case_coverage_binding() -> None:
    conformance = load_vate_conformance_module()
    corpus_root = ROOT / "conformance" / "al2-vate-v0.3"
    sut_results = ROOT / "examples" / "conformance" / "sut-results-pass.example.json"
    with tempfile.TemporaryDirectory(prefix="vate-bundle-coverage-") as temp_dir:
        temp_root = Path(temp_dir)
        reference_report_path = temp_root / "reference-report.json"
        reference_implementation_path = temp_root / "reference-implementation.json"
        reference_bundle_path = temp_root / "reference-bundle.json"
        run(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "run",
                "--corpus-root",
                str(corpus_root),
                "--report",
                str(reference_report_path),
                "--implementation-report",
                str(reference_implementation_path),
                "--conformance-report-uri",
                str(reference_report_path),
                "--implementation-report-uri",
                str(reference_implementation_path),
            ]
        )
        run(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "verify-bundle",
                "--corpus-root",
                str(corpus_root),
                "--conformance-report",
                str(reference_report_path),
                "--implementation-report",
                str(reference_implementation_path),
                "--report",
                str(reference_bundle_path),
            ]
        )

        external_report_path = temp_root / "external-report.json"
        external_implementation_path = temp_root / "external-implementation.json"
        external_bundle_path = temp_root / "external-bundle.json"
        run(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(corpus_root),
                "--sut-results",
                str(sut_results),
                "--report",
                str(external_report_path),
                "--implementation-report",
                str(external_implementation_path),
                "--conformance-report-uri",
                str(external_report_path),
                "--implementation-report-uri",
                str(external_implementation_path),
            ]
        )
        run(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "verify-bundle",
                "--corpus-root",
                str(corpus_root),
                "--sut-results",
                str(sut_results),
                "--conformance-report",
                str(external_report_path),
                "--implementation-report",
                str(external_implementation_path),
                "--report",
                str(external_bundle_path),
            ]
        )

        reference_report = assert_strict_json_file(reference_report_path)
        reference_implementation = assert_strict_json_file(
            reference_implementation_path
        )

        def recompute_summary(cases: list[dict]) -> dict[str, int]:
            return {
                "total": len(cases),
                "passed": sum(1 for case in cases if case.get("pass") is True),
                "failed": sum(1 for case in cases if case.get("pass") is False),
                "skipped": 0,
            }

        variants: list[tuple[str, dict, dict, str]] = []

        zero_report = json.loads(json.dumps(reference_report))
        zero_report["cases"] = []
        zero_report["summary"] = {"total": 0, "passed": 0, "failed": 0, "skipped": 0}
        zero_implementation = json.loads(json.dumps(reference_implementation))
        variants.append(
            ("zero", zero_report, zero_implementation, "conformance_report.cases.coverage")
        )

        partial_report = json.loads(json.dumps(reference_report))
        partial_report["cases"] = partial_report["cases"][:-1]
        partial_report["summary"] = recompute_summary(partial_report["cases"])
        partial_implementation = json.loads(json.dumps(reference_implementation))
        variants.append(
            ("partial", partial_report, partial_implementation, "conformance_report.cases.coverage")
        )

        duplicate_report = json.loads(json.dumps(reference_report))
        duplicate_report["cases"].append(
            json.loads(json.dumps(duplicate_report["cases"][0]))
        )
        duplicate_report["summary"] = recompute_summary(duplicate_report["cases"])
        duplicate_implementation = json.loads(json.dumps(reference_implementation))
        variants.append(
            ("duplicate", duplicate_report, duplicate_implementation, "conformance_report.cases.shape")
        )

        unknown_report = json.loads(json.dumps(reference_report))
        unknown_report["cases"][0]["case_id"] = "unknown-case-id"
        unknown_report["summary"] = recompute_summary(unknown_report["cases"])
        unknown_implementation = json.loads(json.dumps(reference_implementation))
        variants.append(
            ("unknown", unknown_report, unknown_implementation, "conformance_report.cases.coverage")
        )

        expectation_report = json.loads(json.dumps(reference_report))
        expectation_report["cases"][0]["expected_outcome"] = "tampered"
        expectation_implementation = json.loads(json.dumps(reference_implementation))
        variants.append(
            (
                "expectation-tamper",
                expectation_report,
                expectation_implementation,
                "conformance_report.cases.expectations",
            )
        )

        arithmetic_report = json.loads(json.dumps(reference_report))
        arithmetic_report["summary"] = {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
        }
        arithmetic_implementation = json.loads(json.dumps(reference_implementation))
        variants.append(
            (
                "summary-arithmetic",
                arithmetic_report,
                arithmetic_implementation,
                "conformance_report.summary.arithmetic",
            )
        )

        implementation_count_report = json.loads(json.dumps(reference_report))
        implementation_count_implementation = json.loads(
            json.dumps(reference_implementation)
        )
        implementation_count_implementation["corpus"]["case_count"] = 0
        variants.append(
            (
                "implementation-case-count",
                implementation_count_report,
                implementation_count_implementation,
                "implementation_report.corpus.case_count",
            )
        )

        implementation_partial_report = json.loads(json.dumps(reference_report))
        implementation_partial_implementation = json.loads(
            json.dumps(reference_implementation)
        )
        implementation_partial_implementation["case_results"] = (
            implementation_partial_implementation["case_results"][:-1]
        )
        variants.append(
            (
                "implementation-partial",
                implementation_partial_report,
                implementation_partial_implementation,
                "implementation_report.case_results.coverage",
            )
        )

        for label, report, implementation, expected_failed_check in variants:
            if label not in {"implementation-case-count", "implementation-partial"}:
                implementation["summary"] = json.loads(json.dumps(report["summary"]))
                implementation["case_results"] = [
                    conformance.implementation_case_result(case)
                    for case in report["cases"]
                ]
                implementation["corpus"]["case_count"] = len(report["cases"])
            implementation["status"] = "pass"
            implementation["conformance_report"]["digest"] = (
                conformance.digest_descriptor(report)
            )
            report_path = temp_root / f"{label}-report.json"
            implementation_path = temp_root / f"{label}-implementation.json"
            bundle_path = temp_root / f"{label}-bundle.json"
            report_path.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            implementation_path.write_text(
                json.dumps(implementation, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            process = run_expect_failure(
                [
                    sys.executable,
                    str(VATE_CONFORMANCE),
                    "verify-bundle",
                    "--corpus-root",
                    str(corpus_root),
                    "--conformance-report",
                    str(report_path),
                    "--implementation-report",
                    str(implementation_path),
                    "--report",
                    str(bundle_path),
                ]
            )
            if "Traceback" in process.stderr:
                raise RuntimeError(f"bundle coverage variant {label} caused traceback")
            bundle = assert_strict_json_file(bundle_path)
            if bundle.get("status") != "fail":
                raise RuntimeError(f"bundle coverage variant {label} passed")
            assert_bundle_check(bundle_path, expected_failed_check, False)

        indexed_corpus = temp_root / "indexed-corpus"
        shutil.copytree(corpus_root, indexed_corpus)
        run(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "index",
                "--corpus-root",
                str(indexed_corpus),
                "--out",
                str(indexed_corpus / "corpus.json"),
            ]
        )
        indexed_report = temp_root / "indexed-report.json"
        indexed_implementation = temp_root / "indexed-implementation.json"
        run(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "run",
                "--corpus-root",
                str(indexed_corpus),
                "--report",
                str(indexed_report),
                "--implementation-report",
                str(indexed_implementation),
                "--conformance-report-uri",
                str(indexed_report),
                "--implementation-report-uri",
                str(indexed_implementation),
            ]
        )
        canonical_index = json.loads(
            (indexed_corpus / "corpus.json").read_text(encoding="utf-8")
        )
        actual_artifact_count = canonical_index["summary"]["artifact_count"]
        for label, artifact_count in (
            ("zero", 0),
            ("too-large", actual_artifact_count + 1),
            ("wrong-type", "invalid"),
        ):
            tampered_artifact_count_index = json.loads(
                json.dumps(canonical_index)
            )
            tampered_artifact_count_index["summary"][
                "artifact_count"
            ] = artifact_count
            (indexed_corpus / "corpus.json").write_text(
                json.dumps(
                    tampered_artifact_count_index,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            artifact_count_bundle = (
                temp_root / f"artifact-count-{label}-bundle.json"
            )
            artifact_count_process = run_expect_failure(
                [
                    sys.executable,
                    str(VATE_CONFORMANCE),
                    "verify-bundle",
                    "--corpus-root",
                    str(indexed_corpus),
                    "--conformance-report",
                    str(indexed_report),
                    "--implementation-report",
                    str(indexed_implementation),
                    "--report",
                    str(artifact_count_bundle),
                ]
            )
            if "Traceback" in artifact_count_process.stderr:
                raise RuntimeError(
                    f"corpus index artifact_count {label} caused traceback"
                )
            assert_bundle_check(
                artifact_count_bundle,
                "corpus_index.summary.artifact_count",
                False,
            )

        for label, field, value in (
            ("version-wrong", "version", "wrong-version"),
            ("profile-empty", "profile", ""),
            ("name-null", "name", None),
            ("root-wrong", "root", "wrong/root"),
            ("case-schema-empty", "case_schema", ""),
            ("digest-basis-null", "digest_basis", None),
        ):
            tampered_identity_index = json.loads(json.dumps(canonical_index))
            tampered_identity_index[field] = value
            (indexed_corpus / "corpus.json").write_text(
                json.dumps(
                    tampered_identity_index,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            identity_bundle = temp_root / f"identity-{label}-bundle.json"
            identity_process = run_expect_failure(
                [
                    sys.executable,
                    str(VATE_CONFORMANCE),
                    "verify-bundle",
                    "--corpus-root",
                    str(indexed_corpus),
                    "--conformance-report",
                    str(indexed_report),
                    "--implementation-report",
                    str(indexed_implementation),
                    "--report",
                    str(identity_bundle),
                ]
            )
            if "Traceback" in identity_process.stderr:
                raise RuntimeError(
                    f"corpus index identity {label} caused traceback"
                )
            assert_bundle_check(
                identity_bundle,
                "corpus_index.identity",
                False,
            )

        tampered_index = json.loads(json.dumps(canonical_index))
        tampered_index["cases"][0]["title"] = "tampered index title"
        (indexed_corpus / "corpus.json").write_text(
            json.dumps(tampered_index, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        tampered_index_bundle = temp_root / "tampered-index-bundle.json"
        tampered_index_process = run_expect_failure(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "verify-bundle",
                "--corpus-root",
                str(indexed_corpus),
                "--conformance-report",
                str(indexed_report),
                "--implementation-report",
                str(indexed_implementation),
                "--report",
                str(tampered_index_bundle),
            ]
        )
        if "Traceback" in tampered_index_process.stderr:
            raise RuntimeError("tampered corpus index caused verify-bundle traceback")
        assert_bundle_check(
            tampered_index_bundle,
            "corpus_index.cases.entries",
            False,
        )


def check_bundle_sut_actual_projection_binding() -> None:
    conformance = load_vate_conformance_module()
    corpus_root = ROOT / "conformance" / "al2-vate-v0.3"
    passing_sut_path = (
        ROOT / "examples" / "conformance" / "sut-results-pass.example.json"
    )
    passing_sut = json.loads(passing_sut_path.read_text(encoding="utf-8"))

    with tempfile.TemporaryDirectory(prefix="vate-bundle-sut-projection-") as temp_dir:
        temp_root = Path(temp_dir)

        def compare_variant(label: str, sut_results: dict) -> tuple[Path, Path, Path]:
            sut_path = temp_root / f"{label}-sut.json"
            report_path = temp_root / f"{label}-conformance.json"
            implementation_path = temp_root / f"{label}-implementation.json"
            sut_path.write_text(
                json.dumps(sut_results, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            process = run_expect_failure(
                [
                    sys.executable,
                    str(VATE_CONFORMANCE),
                    "compare",
                    "--corpus-root",
                    str(corpus_root),
                    "--sut-results",
                    str(sut_path),
                    "--report",
                    str(report_path),
                    "--implementation-report",
                    str(implementation_path),
                    "--conformance-report-uri",
                    str(report_path),
                    "--implementation-report-uri",
                    str(implementation_path),
                ]
            )
            if "Traceback" in process.stderr:
                raise RuntimeError(f"{label}: compare emitted a traceback")
            assert_strict_json_file(report_path)
            assert_strict_json_file(implementation_path)
            return sut_path, report_path, implementation_path

        def verify_bundle(
            label: str,
            sut_path: Path,
            report_path: Path,
            implementation_path: Path,
            *,
            expected_pass: bool,
            expected_failed_check: str | None = None,
        ) -> dict:
            bundle_path = temp_root / f"{label}-bundle.json"
            command = [
                sys.executable,
                str(VATE_CONFORMANCE),
                "verify-bundle",
                "--corpus-root",
                str(corpus_root),
                "--sut-results",
                str(sut_path),
                "--conformance-report",
                str(report_path),
                "--implementation-report",
                str(implementation_path),
                "--report",
                str(bundle_path),
            ]
            process = run(command) if expected_pass else run_expect_failure(command)
            if process is not None and "Traceback" in process.stderr:
                raise RuntimeError(f"{label}: verify-bundle emitted a traceback")
            bundle = assert_strict_json_file(bundle_path)
            expected_status = "pass" if expected_pass else "fail"
            if bundle.get("status") != expected_status:
                raise RuntimeError(
                    f"{label}: expected bundle {expected_status} actual {bundle.get('status')}"
                )
            if expected_failed_check is not None:
                assert_bundle_check(bundle_path, expected_failed_check, False)
            return bundle

        def synchronized_implementation(
            report: dict,
            implementation: dict,
        ) -> dict:
            synchronized = json.loads(json.dumps(implementation))
            synchronized["summary"] = json.loads(json.dumps(report["summary"]))
            synchronized["status"] = conformance.conformance_report_status(report)
            synchronized["case_results"] = [
                conformance.implementation_case_result(case)
                for case in report["cases"]
            ]
            report_sut = report.get("sut_results")
            if isinstance(report_sut, dict):
                synchronized["artifact_mode_counts"] = json.loads(
                    json.dumps(report_sut["artifact_mode_counts"])
                )
            synchronized["conformance_report"]["digest"] = (
                conformance.digest_descriptor(report)
            )
            return synchronized

        pulse_shaped_sut = json.loads(json.dumps(passing_sut))
        pulse_shaped_sut["results"][0]["outcome"] = "deny"
        pulse_shaped_sut["results"][0]["should_execute"] = False
        pulse_shaped_sut["results"][0]["reason_codes"] = ["FAIL_CLOSED"]
        pulse_shaped_sut["results"][1]["status"] = "skipped"
        pulse_paths = compare_variant("pulse-shaped", pulse_shaped_sut)
        pulse_report = assert_strict_json_file(pulse_paths[1])
        if (
            pulse_report.get("summary", {}).get("failed", 0) < 2
            or pulse_report.get("summary", {}).get("skipped") != 1
        ):
            raise RuntimeError(
                "Pulse-shaped compare must preserve semantic failure and skipped state"
            )
        verify_bundle(
            "pulse-shaped",
            *pulse_paths,
            expected_pass=True,
        )

        state_reports: dict[str, tuple[Path, Path, Path]] = {}
        for state in ("missing", "skipped", "error"):
            state_sut = json.loads(json.dumps(passing_sut))
            if state == "missing":
                state_sut["results"] = state_sut["results"][1:]
            else:
                state_sut["results"][0]["status"] = state
            paths = compare_variant(f"state-{state}", state_sut)
            state_reports[state] = paths
            verify_bundle(
                f"state-{state}",
                *paths,
                expected_pass=True,
            )

        for state, (sut_path, report_path, implementation_path) in state_reports.items():
            report = assert_strict_json_file(report_path)
            implementation = assert_strict_json_file(implementation_path)
            affected_case = report["cases"][0]
            affected_case["failures"] = [
                "non-completed state detail intentionally omitted"
            ]
            hidden_report_path = temp_root / f"state-{state}-hidden-conformance.json"
            hidden_implementation_path = (
                temp_root / f"state-{state}-hidden-implementation.json"
            )
            hidden_report_path.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            hidden_implementation_path.write_text(
                json.dumps(
                    synchronized_implementation(report, implementation),
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            verify_bundle(
                f"state-{state}-hidden",
                sut_path,
                hidden_report_path,
                hidden_implementation_path,
                expected_pass=False,
                expected_failed_check=(
                    "conformance_report.cases.sut_actual_projection"
                ),
            )

        baseline_report_path = temp_root / "baseline-conformance.json"
        baseline_implementation_path = temp_root / "baseline-implementation.json"
        run(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(corpus_root),
                "--sut-results",
                str(passing_sut_path),
                "--report",
                str(baseline_report_path),
                "--implementation-report",
                str(baseline_implementation_path),
                "--conformance-report-uri",
                str(baseline_report_path),
                "--implementation-report-uri",
                str(baseline_implementation_path),
            ]
        )
        baseline_report = assert_strict_json_file(baseline_report_path)
        baseline_implementation = assert_strict_json_file(
            baseline_implementation_path
        )

        source_tamper_sut = json.loads(json.dumps(passing_sut))
        source_tamper_sut["results"][0]["outcome"] = "deny"
        source_tamper_sut["results"][0]["should_execute"] = False
        source_tamper_sut["results"][0]["reason_codes"] = ["FAIL_CLOSED"]
        source_tamper_path = temp_root / "projection-source-tamper-sut.json"
        source_tamper_report = json.loads(json.dumps(baseline_report))
        source_tamper_implementation = json.loads(
            json.dumps(baseline_implementation)
        )
        source_tamper_path.write_text(
            json.dumps(source_tamper_sut, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        source_tamper_report["sut_results"]["digest"] = (
            conformance.digest_descriptor(source_tamper_sut)
        )
        source_tamper_implementation = synchronized_implementation(
            source_tamper_report,
            source_tamper_implementation,
        )
        source_tamper_report_path = (
            temp_root / "projection-source-tamper-conformance.json"
        )
        source_tamper_implementation_path = (
            temp_root / "projection-source-tamper-implementation.json"
        )
        source_tamper_report_path.write_text(
            json.dumps(source_tamper_report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        source_tamper_implementation_path.write_text(
            json.dumps(
                source_tamper_implementation,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        verify_bundle(
            "projection-source-tamper",
            source_tamper_path,
            source_tamper_report_path,
            source_tamper_implementation_path,
            expected_pass=False,
            expected_failed_check=(
                "conformance_report.cases.sut_actual_projection"
            ),
        )

        projection_mutations = (
            ("outcome", {"actual_outcome": "tampered"}),
            (
                "execution",
                {
                    "actual_should_execute": not baseline_report["cases"][0][
                        "actual_should_execute"
                    ]
                },
            ),
            (
                "reasons",
                {
                    "actual_reason_codes": ["FAIL_CLOSED"],
                    "actual_primary_reason_code": None,
                },
            ),
            (
                "artifact-mode",
                {
                    "artifact_mode": "generated-receipts",
                },
            ),
        )
        for label, replacements in projection_mutations:
            report = json.loads(json.dumps(baseline_report))
            implementation = json.loads(json.dumps(baseline_implementation))
            case = report["cases"][0]
            for field, value in replacements.items():
                case[field] = value
            case["pass"] = False
            case["failures"] = ["reported SUT projection differs from expectation"]
            report["summary"]["passed"] -= 1
            report["summary"]["failed"] += 1
            if label == "artifact-mode":
                report["sut_results"]["artifact_mode_counts"][
                    "corpus-fixture-validation"
                ] -= 1
                report["sut_results"]["artifact_mode_counts"][
                    "generated-receipts"
                ] += 1
            implementation = synchronized_implementation(report, implementation)
            report_path = temp_root / f"projection-{label}-conformance.json"
            implementation_path = (
                temp_root / f"projection-{label}-implementation.json"
            )
            report_path.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            implementation_path.write_text(
                json.dumps(implementation, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            verify_bundle(
                f"projection-{label}",
                passing_sut_path,
                report_path,
                implementation_path,
                expected_pass=False,
                expected_failed_check=(
                    "conformance_report.cases.sut_actual_projection"
                ),
            )

        structural_variants: list[tuple[str, dict]] = []
        non_object_sut = json.loads(json.dumps(passing_sut))
        non_object_sut["results"].append(None)
        structural_variants.append(("non-object", non_object_sut))
        missing_id_sut = json.loads(json.dumps(passing_sut))
        missing_id_result = json.loads(json.dumps(missing_id_sut["results"][0]))
        missing_id_result.pop("case_id", None)
        missing_id_sut["results"].append(missing_id_result)
        structural_variants.append(("missing-id", missing_id_sut))
        invalid_id_sut = json.loads(json.dumps(passing_sut))
        invalid_id_result = json.loads(json.dumps(invalid_id_sut["results"][0]))
        invalid_id_result["case_id"] = 1
        invalid_id_sut["results"].append(invalid_id_result)
        structural_variants.append(("invalid-id", invalid_id_sut))
        duplicate_sut = json.loads(json.dumps(passing_sut))
        duplicate_sut["results"].append(
            json.loads(json.dumps(duplicate_sut["results"][0]))
        )
        structural_variants.append(("duplicate", duplicate_sut))
        unknown_sut = json.loads(json.dumps(passing_sut))
        unknown_result = json.loads(json.dumps(unknown_sut["results"][0]))
        unknown_result["case_id"] = "unknown-case-id"
        unknown_sut["results"].append(unknown_result)
        structural_variants.append(("unknown", unknown_sut))

        for label, sut_results in structural_variants:
            sut_path = temp_root / f"structure-{label}-sut.json"
            report = json.loads(json.dumps(baseline_report))
            implementation = json.loads(json.dumps(baseline_implementation))
            sut_path.write_text(
                json.dumps(sut_results, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            report["sut_results"]["digest"] = conformance.digest_descriptor(
                sut_results
            )
            implementation = synchronized_implementation(report, implementation)
            report_path = temp_root / f"structure-{label}-conformance.json"
            implementation_path = (
                temp_root / f"structure-{label}-implementation.json"
            )
            report_path.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            implementation_path.write_text(
                json.dumps(implementation, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            verify_bundle(
                f"structure-{label}",
                sut_path,
                report_path,
                implementation_path,
                expected_pass=False,
                expected_failed_check="sut_results.results.structure",
            )


def check_bundle_report_contract_fail_closed() -> None:
    corpus_root = ROOT / "conformance" / "al2-vate-v0.3"
    sut_results = ROOT / "examples" / "conformance" / "sut-results-pass.example.json"
    with tempfile.TemporaryDirectory(prefix="vate-bundle-report-contract-") as temp_dir:
        temp_root = Path(temp_dir)

        def set_nested(document: dict, path: tuple[object, ...], value: object) -> None:
            current: object = document
            for part in path[:-1]:
                if isinstance(part, int):
                    current = current[part]  # type: ignore[index]
                else:
                    current = current[part]  # type: ignore[index]
            final = path[-1]
            if isinstance(final, int):
                current[final] = value  # type: ignore[index]
            else:
                current[final] = value  # type: ignore[index]

        for lane, include_sut in (("reference", False), ("external", True)):
            conformance_path = temp_root / f"{lane}-conformance.json"
            implementation_path = temp_root / f"{lane}-implementation.json"
            command = [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare" if include_sut else "run",
                "--corpus-root",
                str(corpus_root),
            ]
            if include_sut:
                command.extend(["--sut-results", str(sut_results)])
            command.extend(
                [
                    "--report",
                    str(conformance_path),
                    "--implementation-report",
                    str(implementation_path),
                    "--conformance-report-uri",
                    str(conformance_path),
                    "--implementation-report-uri",
                    str(implementation_path),
                ]
            )
            run(command)
            conformance = assert_strict_json_file(conformance_path)
            implementation = assert_strict_json_file(implementation_path)

            def verify_mutation(
                label: str,
                mutated_conformance: object,
                mutated_implementation: object,
                expected_failed_check: str,
            ) -> None:
                report_path = temp_root / f"{lane}-{label}-conformance.json"
                implementation_report_path = (
                    temp_root / f"{lane}-{label}-implementation.json"
                )
                bundle_path = temp_root / f"{lane}-{label}-bundle.json"
                report_path.write_text(
                    json.dumps(mutated_conformance, indent=2, sort_keys=True)
                    + "\n",
                    encoding="utf-8",
                )
                implementation_report_path.write_text(
                    json.dumps(mutated_implementation, indent=2, sort_keys=True)
                    + "\n",
                    encoding="utf-8",
                )
                verify_command = [
                    sys.executable,
                    str(VATE_CONFORMANCE),
                    "verify-bundle",
                    "--corpus-root",
                    str(corpus_root),
                    "--conformance-report",
                    str(report_path),
                    "--implementation-report",
                    str(implementation_report_path),
                    "--report",
                    str(bundle_path),
                ]
                if include_sut:
                    verify_command.extend(["--sut-results", str(sut_results)])
                process = run_expect_failure(verify_command)
                if "Traceback" in process.stderr:
                    raise RuntimeError(
                        f"{lane} bundle report mutation {label} caused traceback"
                    )
                bundle = assert_strict_json_file(bundle_path)
                if bundle.get("status") != "fail":
                    raise RuntimeError(
                        f"{lane} bundle report mutation {label} passed"
                    )
                assert_bundle_check(
                    bundle_path,
                    expected_failed_check,
                    False,
                )

            for shape_label, malformed_report in (
                ("null", None),
                ("array", []),
                ("scalar", "invalid"),
            ):
                verify_mutation(
                    f"conformance-shape-{shape_label}",
                    malformed_report,
                    json.loads(json.dumps(implementation)),
                    "conformance_report.shape",
                )
                verify_mutation(
                    f"implementation-shape-{shape_label}",
                    json.loads(json.dumps(conformance)),
                    malformed_report,
                    "implementation_report.shape",
                )

            missing_conformance_version = json.loads(json.dumps(conformance))
            missing_conformance_version.pop("version", None)
            verify_mutation(
                "conformance-version-missing",
                missing_conformance_version,
                json.loads(json.dumps(implementation)),
                "conformance_report.envelope",
            )
            conformance_mutations = (
                ("checked-at-null", ("checked_at",), None),
                ("corpus-null", ("corpus",), None),
                ("summary-null", ("summary",), None),
                ("cases-null", ("cases",), None),
                ("case-outcome-null", ("cases", 0, "actual_outcome"), None),
                (
                    "case-reasons-null",
                    ("cases", 0, "actual_reason_codes"),
                    None,
                ),
                ("case-pass-string", ("cases", 0, "pass"), "true"),
            )
            for label, path, value in conformance_mutations:
                mutated_conformance = json.loads(json.dumps(conformance))
                set_nested(mutated_conformance, path, value)
                verify_mutation(
                    label,
                    mutated_conformance,
                    json.loads(json.dumps(implementation)),
                    "conformance_report.envelope",
                )
            missing_nullable_conformance_field = json.loads(
                json.dumps(conformance)
            )
            missing_nullable_conformance_field["cases"][0].pop(
                "actual_should_execute", None
            )
            verify_mutation(
                "case-actual-should-execute-missing",
                missing_nullable_conformance_field,
                json.loads(json.dumps(implementation)),
                "conformance_report.envelope",
            )
            for case_id_label, malformed_case_id in (
                ("list", []),
                ("object", {}),
                ("null", None),
                ("number", 7),
                ("boolean", False),
            ):
                malformed_case_id_conformance = json.loads(
                    json.dumps(conformance)
                )
                malformed_case_id_conformance["cases"][0][
                    "case_id"
                ] = malformed_case_id
                verify_mutation(
                    f"conformance-case-id-{case_id_label}",
                    malformed_case_id_conformance,
                    json.loads(json.dumps(implementation)),
                    "conformance_report.envelope",
                )
            if include_sut:
                mutated_conformance = json.loads(json.dumps(conformance))
                mutated_conformance["sut_results"] = None
                verify_mutation(
                    "sut-results-null",
                    mutated_conformance,
                    json.loads(json.dumps(implementation)),
                    "conformance_report.envelope",
                )
                mutated_conformance = json.loads(json.dumps(conformance))
                mutated_conformance["sut_results"]["artifact_mode"] = {}
                verify_mutation(
                    "sut-results-artifact-mode-object",
                    mutated_conformance,
                    json.loads(json.dumps(implementation)),
                    "conformance_report.envelope",
                )

            pass_case_consistency_mutations = (
                ("outcome", "actual_outcome", "deny"),
                (
                    "should-execute",
                    "actual_should_execute",
                    not conformance["cases"][0]["expected_should_execute"],
                ),
                (
                    "primary-reason",
                    "actual_primary_reason_code",
                    "SCHEMA_INVALID",
                ),
                (
                    "reason-codes",
                    "actual_reason_codes",
                    ["SCHEMA_INVALID", "FAIL_CLOSED"],
                ),
                ("failures", "failures", ["contradicts pass=true"]),
                (
                    "expected-primary-derived",
                    "expected_primary_reason_code",
                    "SCHEMA_INVALID",
                ),
            )
            for label, field, value in pass_case_consistency_mutations:
                mutated_conformance = json.loads(json.dumps(conformance))
                mutated_conformance["cases"][0][field] = value
                verify_mutation(
                    f"pass-case-{label}-inconsistent",
                    mutated_conformance,
                    json.loads(json.dumps(implementation)),
                    "conformance_report.cases.internal_consistency",
                )

            missing_implementation_version = json.loads(json.dumps(implementation))
            missing_implementation_version.pop("version", None)
            verify_mutation(
                "implementation-version-missing",
                json.loads(json.dumps(conformance)),
                missing_implementation_version,
                "implementation_report.envelope",
            )
            implementation_mutations = (
                ("generated-at-null", ("generated_at",), None),
                ("status-object", ("status",), {}),
                ("implementation-null", ("implementation",), None),
                ("implementation-name-empty", ("implementation", "name"), ""),
                ("corpus-null", ("corpus",), None),
                ("manifest-null", ("corpus", "manifest"), None),
                ("summary-null", ("summary",), None),
                ("case-results-null", ("case_results",), None),
                (
                    "case-outcome-null",
                    ("case_results", 0, "actual_outcome"),
                    None,
                ),
                ("case-pass-integer", ("case_results", 0, "pass"), 1),
                ("conformance-report-null", ("conformance_report",), None),
                (
                    "conformance-report-digest-basis-object",
                    ("conformance_report", "digest_basis"),
                    {},
                ),
                ("limitations-null", ("limitations",), None),
            )
            for label, path, value in implementation_mutations:
                mutated_implementation = json.loads(json.dumps(implementation))
                set_nested(mutated_implementation, path, value)
                verify_mutation(
                    f"implementation-{label}",
                    json.loads(json.dumps(conformance)),
                    mutated_implementation,
                    "implementation_report.envelope",
                )

            failed_conformance = json.loads(json.dumps(conformance))
            failed_conformance["cases"][0]["pass"] = False
            failed_conformance["cases"][0]["failures"] = [
                "bounded comparison mismatch"
            ]
            failed_conformance["summary"]["passed"] -= 1
            failed_conformance["summary"]["failed"] += 1
            failed_implementation = json.loads(json.dumps(implementation))
            conformance_module = load_vate_conformance_module()
            failed_implementation["case_results"] = [
                conformance_module.implementation_case_result(case)
                for case in failed_conformance["cases"]
            ]
            failed_implementation["summary"] = json.loads(
                json.dumps(failed_conformance["summary"])
            )
            failed_implementation["status"] = "fail"
            failed_implementation["conformance_report"]["digest"] = {
                "alg": "sha-256",
                "value": hashlib.sha256(
                    canonical_json_bytes(failed_conformance)
                ).hexdigest(),
            }
            failed_conformance_path = temp_root / f"{lane}-valid-failed.json"
            failed_implementation_path = (
                temp_root / f"{lane}-valid-failed-implementation.json"
            )
            failed_bundle_path = temp_root / f"{lane}-valid-failed-bundle.json"
            failed_conformance_path.write_text(
                json.dumps(failed_conformance, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            failed_implementation_path.write_text(
                json.dumps(failed_implementation, indent=2, sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            failed_verify_command = [
                sys.executable,
                str(VATE_CONFORMANCE),
                "verify-bundle",
                "--corpus-root",
                str(corpus_root),
                "--conformance-report",
                str(failed_conformance_path),
                "--implementation-report",
                str(failed_implementation_path),
                "--report",
                str(failed_bundle_path),
            ]
            if include_sut:
                failed_verify_command.extend(["--sut-results", str(sut_results)])
            run(failed_verify_command)
            failed_bundle = assert_strict_json_file(failed_bundle_path)
            if failed_bundle.get("status") != "pass":
                raise RuntimeError(
                    f"{lane} internally consistent failed report did not preserve "
                    "bundle integrity responsibility"
                )
            missing_nullable_implementation_field = json.loads(
                json.dumps(implementation)
            )
            missing_nullable_implementation_field["case_results"][0].pop(
                "actual_primary_reason_code", None
            )
            verify_mutation(
                "implementation-case-primary-reason-missing",
                json.loads(json.dumps(conformance)),
                missing_nullable_implementation_field,
                "implementation_report.envelope",
            )
            for case_id_label, malformed_case_id in (
                ("list", []),
                ("object", {}),
                ("null", None),
                ("number", 7),
                ("boolean", False),
            ):
                malformed_case_id_implementation = json.loads(
                    json.dumps(implementation)
                )
                malformed_case_id_implementation["case_results"][0][
                    "case_id"
                ] = malformed_case_id
                verify_mutation(
                    f"implementation-case-id-{case_id_label}",
                    json.loads(json.dumps(conformance)),
                    malformed_case_id_implementation,
                    "implementation_report.envelope",
                )

            artifact_count = conformance["corpus"]["artifact_count"]
            for count_label, count_value in (
                ("zero", 0),
                ("too-large", artifact_count + 1),
                ("wrong-type", "invalid"),
            ):
                mutated_conformance = json.loads(json.dumps(conformance))
                mutated_conformance["corpus"]["artifact_count"] = count_value
                verify_mutation(
                    f"conformance-artifact-count-{count_label}",
                    mutated_conformance,
                    json.loads(json.dumps(implementation)),
                    "conformance_report.corpus.artifact_count",
                )
                mutated_implementation = json.loads(json.dumps(implementation))
                mutated_implementation["corpus"]["artifact_count"] = count_value
                verify_mutation(
                    f"implementation-artifact-count-{count_label}",
                    json.loads(json.dumps(conformance)),
                    mutated_implementation,
                    "implementation_report.corpus.artifact_count",
                )


def check_replay_boundary_coverage() -> None:
    case_path = ROOT / "conformance" / "al2-vate-v0.3" / "cases" / "allow-replay-state-unused.json"
    if not case_path.exists():
        raise RuntimeError(
            "replay coverage is missing allow-replay-state-unused: AL2 context checks "
            "must prove that an unused one-time replay key is not treated as replayed."
        )
    case = json.loads(case_path.read_text(encoding="utf-8"))
    context_path = ROOT / case["artifacts"]["replay_context"]
    context = json.loads(context_path.read_text(encoding="utf-8"))
    if context.get("state") != "unused":
        raise RuntimeError("allow-replay-state-unused must exercise an unused replay state")
    if case.get("expected", {}).get("admission_decision") != "allow":
        raise RuntimeError("allow-replay-state-unused must allow an unused replay key")

    conformance = load_vate_conformance_module()
    invalid_state_context = dict(context)
    invalid_state_context["state"] = "unknown"
    failures = conformance.evaluate_context_replay_check(
        {"kind": "replay", "artifact": "replay_context", "expect_replayed": False},
        invalid_state_context,
    )
    if not failures:
        raise RuntimeError("replay context checks must reject unknown replay states")


def check_p1_5_fixture_coverage() -> None:
    required_cases = {
        "deny-status-stale-just-over-boundary": ["STATUS_STALE", "FAIL_CLOSED"],
        "deny-replay-state-replayed": ["REPLAY_DETECTED", "FAIL_CLOSED"],
        "deny-digest-mismatch-before-policy": ["DIGEST_MISMATCH", "FAIL_CLOSED"],
        "deny-jose-es384-not-allowed": ["ALG_NOT_ALLOWED", "FAIL_CLOSED"],
        "deny-attenuation-approval-string": ["SCHEMA_INVALID", "FAIL_CLOSED"],
        "deny-attenuation-legacy-effective-constraints": ["SCHEMA_INVALID", "FAIL_CLOSED"],
        "deny-attenuation-malformed-money": ["SCHEMA_INVALID", "FAIL_CLOSED"],
        "deny-attenuation-negative-amount": ["SCHEMA_INVALID", "FAIL_CLOSED"],
    }
    case_dir = ROOT / "conformance" / "al2-vate-v0.3" / "cases"
    for case_id, expected_reason_codes in required_cases.items():
        case_path = case_dir / f"{case_id}.json"
        if not case_path.exists():
            raise RuntimeError(f"P1.5 fixture coverage is missing {case_id}")
        case = json.loads(case_path.read_text(encoding="utf-8"))
        if case.get("case_id") != case_id:
            raise RuntimeError(f"{case_path.relative_to(ROOT)} has mismatched case_id")
        expected = case.get("expected", {})
        if expected.get("admission_decision") != "deny":
            raise RuntimeError(f"{case_id} must be a deny case")
        if expected.get("should_execute") is not False:
            raise RuntimeError(f"{case_id} must set expected.should_execute to false")
        if expected.get("reason_codes") != expected_reason_codes:
            raise RuntimeError(f"{case_id} must use reason_codes {expected_reason_codes}")

    status_case = json.loads((case_dir / "deny-status-stale-just-over-boundary.json").read_text(encoding="utf-8"))
    status_context = json.loads((ROOT / status_case["artifacts"]["status_context"]).read_text(encoding="utf-8"))
    checked_at = datetime.fromisoformat(status_context["checked_at"].replace("Z", "+00:00"))
    source_issued_at = datetime.fromisoformat(status_context["source_issued_at"].replace("Z", "+00:00"))
    if (checked_at - source_issued_at).total_seconds() != status_context["max_age_seconds"] + 1:
        raise RuntimeError("deny-status-stale-just-over-boundary must be exactly one second beyond max_age_seconds")

    replay_case = json.loads((case_dir / "deny-replay-state-replayed.json").read_text(encoding="utf-8"))
    replay_context = json.loads((ROOT / replay_case["artifacts"]["replay_context"]).read_text(encoding="utf-8"))
    if replay_context.get("state") != "replayed":
        raise RuntimeError("deny-replay-state-replayed must exercise an explicit replayed state")

    digest_case = json.loads((case_dir / "deny-digest-mismatch-before-policy.json").read_text(encoding="utf-8"))
    integrity_checks = digest_case.get("integrity_checks", [])
    if not integrity_checks or integrity_checks[0].get("expect_match") is not False:
        raise RuntimeError("deny-digest-mismatch-before-policy must include a failing digest check")
    if "evaluation order" not in digest_case.get("validation_focus", []):
        raise RuntimeError("deny-digest-mismatch-before-policy must declare evaluation-order focus")

    jose_case = json.loads((case_dir / "deny-jose-es384-not-allowed.json").read_text(encoding="utf-8"))
    jose_checks = jose_case.get("jose_checks", [])
    if not jose_checks:
        raise RuntimeError("deny-jose-es384-not-allowed must include a jose_checks entry")
    jose_check = jose_checks[0]
    proof_package = jose_check.get("proof_package")
    if not isinstance(proof_package, str) or proof_package not in jose_case.get("artifacts", {}):
        raise RuntimeError("deny-jose-es384-not-allowed must reference a JOSE proof package artifact")
    jose_proof = json.loads((ROOT / jose_case["artifacts"][proof_package]).read_text(encoding="utf-8"))
    if jose_proof.get("protected", {}).get("alg") != "ES384":
        raise RuntimeError("deny-jose-es384-not-allowed must exercise protected alg ES384")
    if jose_check.get("expected_failure_reason") != "ALG_NOT_ALLOWED":
        raise RuntimeError("deny-jose-es384-not-allowed must fail with ALG_NOT_ALLOWED")

    attenuation_case = json.loads((case_dir / "deny-attenuation-negative-amount.json").read_text(encoding="utf-8"))
    attenuation = json.loads((ROOT / attenuation_case["artifacts"]["bad_attenuation"]).read_text(encoding="utf-8"))
    amount = attenuation.get("effective_constraints", {}).get("max_amount", {}).get("value")
    if not isinstance(amount, str) or not amount.startswith("-"):
        raise RuntimeError("deny-attenuation-negative-amount must exercise a negative max_amount value")

    conformance = load_vate_conformance_module()
    legacy_case = json.loads((case_dir / "deny-attenuation-legacy-effective-constraints.json").read_text(encoding="utf-8"))
    legacy_attenuation = json.loads((ROOT / legacy_case["artifacts"]["bad_attenuation"]).read_text(encoding="utf-8"))
    legacy_failures = conformance.attenuation_validation_failures(legacy_attenuation)
    if not any("max_amount_usd" in failure for failure in legacy_failures):
        raise RuntimeError("deny-attenuation-legacy-effective-constraints must reject max_amount_usd")
    if not any("resource" in failure and "target_resource" in failure for failure in legacy_failures):
        raise RuntimeError("deny-attenuation-legacy-effective-constraints must reject bare resource")

    approval_case = json.loads((case_dir / "deny-attenuation-approval-string.json").read_text(encoding="utf-8"))
    approval_attenuation = json.loads((ROOT / approval_case["artifacts"]["bad_attenuation"]).read_text(encoding="utf-8"))
    approval_failures = conformance.attenuation_validation_failures(approval_attenuation)
    if not any("approval must be an object" in failure for failure in approval_failures):
        raise RuntimeError("deny-attenuation-approval-string must reject string approval")

    money_case = json.loads((case_dir / "deny-attenuation-malformed-money.json").read_text(encoding="utf-8"))
    money_attenuation = json.loads((ROOT / money_case["artifacts"]["bad_attenuation"]).read_text(encoding="utf-8"))
    money_failures = conformance.attenuation_validation_failures(money_attenuation)
    if not any("currency" in failure for failure in money_failures):
        raise RuntimeError("deny-attenuation-malformed-money must reject malformed currency")
    if not any("canonical non-negative decimal string" in failure for failure in money_failures):
        raise RuntimeError("deny-attenuation-malformed-money must reject non-canonical decimal string values")


def check_p2_public_artifact_boundary() -> None:
    required_docs = {
        JOSE_PROFILE_NOTES_DOC: [
            "v0.2 decision",
            "no new jose dependency",
            "production signature verification remains outside",
        ],
        NAMESPACE_MIGRATION_DOC: [
            "repository-scoped draft uri",
            "persistent namespace",
            "migration conditions",
            "do not break existing v0.3 corpus",
        ],
        EXTENSION_FIELDS_DOC: [
            "unknown extension fields",
            "must not grant authority",
            "preserve",
            "additionalproperties",
        ],
        A2A_METADATA_BINDING_DOC: [
            "digest target",
            "validation responsibility",
            "jose-detached-a2a-agent-card.example.json",
        ],
        A2A_EXTENSION_SKETCH_DOC: [
            "digest-bound artifact is the canonicalized agent card payload",
            "jose-detached-a2a-agent-card.example.json",
        ],
        EXTERNAL_SUT_QUICKSTART_DOC: [
            "corpus-fixture-validation",
            "generated-receipts",
            "generated_artifacts",
            "does not prove artifact provenance",
        ],
        SUT_ADAPTER_CONTRACT_DOC: [
            "corpus-fixture-validation",
            "generated-receipts",
            "generated_artifacts",
            "bounded semantic projection",
            "does not prove who produced",
        ],
    }
    for path, phrases in required_docs.items():
        if not path.exists():
            raise RuntimeError(f"missing P2 artifact-boundary document: {path.relative_to(ROOT)}")
        normalized = " ".join(path.read_text(encoding="utf-8").split()).lower()
        missing = [phrase for phrase in phrases if phrase not in normalized]
        if missing:
            raise RuntimeError(f"{path.relative_to(ROOT)} is missing P2 artifact-boundary language: {missing}")
    if "what exact artifact should be digest-bound" in A2A_EXTENSION_SKETCH_DOC.read_text(encoding="utf-8").lower():
        raise RuntimeError("A2A extension sketch still treats the v0.3 signed Agent Card digest target as open")

    required_case_id = "allow-a2a-signed-agent-card-evidence"
    corpus = json.loads((ROOT / "conformance" / "al2-vate-v0.3" / "corpus.json").read_text(encoding="utf-8"))
    corpus_case_ids = {case.get("case_id") for case in corpus.get("cases", []) if isinstance(case, dict)}
    if required_case_id not in corpus_case_ids:
        raise RuntimeError(f"P2 A2A signed Agent Card fixture is not corpus-bound: missing {required_case_id}")

    sut_results = json.loads((ROOT / "examples" / "conformance" / "sut-results-pass.example.json").read_text())
    sut_case_ids = {result.get("case_id") for result in sut_results.get("results", []) if isinstance(result, dict)}
    if required_case_id not in sut_case_ids:
        raise RuntimeError(f"P2 A2A signed Agent Card fixture is not represented in the SUT sample: {required_case_id}")

    if not A2A_SIGNED_AGENT_CARD_PROOF.exists():
        raise RuntimeError(f"missing P2 A2A signed Agent Card fixture: {A2A_SIGNED_AGENT_CARD_PROOF.relative_to(ROOT)}")
    proof = json.loads(A2A_SIGNED_AGENT_CARD_PROOF.read_text(encoding="utf-8"))
    payload = json.loads(A2A_SIGNED_AGENT_CARD_PAYLOAD.read_text(encoding="utf-8"))
    protected = proof.get("protected")
    if not isinstance(protected, dict):
        raise RuntimeError("A2A signed Agent Card proof fixture must include a protected header object")
    if proof.get("evidence_type") != "signed_agent_card":
        raise RuntimeError("A2A signed Agent Card proof fixture must use evidence_type signed_agent_card")
    fixture_note = proof.get("fixture_signature_note")
    if not isinstance(fixture_note, str) or "not a production ecdsa signature" not in fixture_note.lower():
        raise RuntimeError("A2A signed Agent Card proof fixture must warn that signature_b64u is fixture data")
    if protected.get("typ") != "a2a-agent-card+jws":
        raise RuntimeError("A2A signed Agent Card proof fixture must use typ a2a-agent-card+jws")
    expected_protected_b64u = b64url_encode_bytes(canonical_json_bytes(protected))
    if proof.get("protected_b64u") != expected_protected_b64u:
        raise RuntimeError("A2A signed Agent Card proof fixture protected_b64u is not canonical")
    expected_payload_b64u = b64url_encode_bytes(canonical_json_bytes(payload))
    expected_payload_digest = {
        "alg": "sha-256",
        "value": hashlib.sha256(canonical_json_bytes(payload)).hexdigest(),
    }
    if proof.get("detached_payload_b64u") != expected_payload_b64u:
        raise RuntimeError("A2A signed Agent Card proof fixture payload b64u is not bound to the Agent Card example")
    if proof.get("detached_payload_sha256") != expected_payload_digest:
        raise RuntimeError("A2A signed Agent Card proof fixture payload digest is not bound to the Agent Card example")
    signing_input = f"{proof.get('protected_b64u')}.{proof.get('detached_payload_b64u')}".encode("ascii")
    expected_signing_input_digest = {
        "alg": "sha-256",
        "value": hashlib.sha256(signing_input).hexdigest(),
    }
    if proof.get("signing_input_sha256") != expected_signing_input_digest:
        raise RuntimeError("A2A signed Agent Card proof fixture signing input digest is not canonical")

    conformance = load_vate_conformance_module()
    case_path = ROOT / "conformance" / "al2-vate-v0.3" / "cases" / f"{required_case_id}.json"
    case = json.loads(case_path.read_text(encoding="utf-8"))

    with tempfile.TemporaryDirectory(prefix="vate-a2a-agent-card-negative-") as negative_dir:
        temp_dir = Path(negative_dir)
        bad_receipt = json.loads((ROOT / case["artifacts"]["admission_receipt"]).read_text(encoding="utf-8"))
        bad_receipt["evidence"][0]["digest"] = {
            "alg": "sha-256",
            "value": "0" * 64,
        }
        bad_receipt_path = temp_dir / "bad-admission-receipt.json"
        bad_receipt_path.write_text(json.dumps(bad_receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        bad_case = json.loads(json.dumps(case))
        bad_case["artifacts"]["admission_receipt"] = str(bad_receipt_path)
        bad_case_path = temp_dir / "bad-case.json"
        bad_case_path.write_text(json.dumps(bad_case, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if conformance.evaluate_case(bad_case_path)["pass"]:
            raise RuntimeError("A2A signed Agent Card case must fail when receipt evidence digest is not payload-bound")

    bad_payload = json.loads(json.dumps(payload))
    bad_payload["capabilities"]["extensions"][0]["uri"] = "https://example.invalid/not-vate"
    bad_proof = json.loads(json.dumps(proof))
    rewrite_detached_jws_payload_digest(bad_proof, bad_payload)
    trust_bundle = json.loads((ROOT / "examples" / "trust-bundle-agent-card.example.json").read_text(encoding="utf-8"))
    valid, failure_reason, _ = conformance.evaluate_jose_check(
        bad_proof,
        bad_payload,
        trust_bundle,
        {
            "checked_at": "2026-07-01T00:19:05Z",
            "expected_typ": "a2a-agent-card+jws",
        },
    )
    if valid or failure_reason != "SCHEMA_INVALID":
        raise RuntimeError("A2A signed Agent Card fixture must require the VATE extension declaration")

    agent_card_anchor = trust_bundle["issuers"][0]
    public_key = json.loads((ROOT / agent_card_anchor["public_key_ref"]).read_text(encoding="utf-8"))
    if public_key.get("kid") != agent_card_anchor.get("kid"):
        raise RuntimeError("A2A signed Agent Card trust bundle public_key_ref kid must match the trust anchor kid")


def check_rcl_projection_package() -> None:
    source_fixture_path = (
        ROOT
        / "conformance"
        / "al2-vate-v0.3"
        / "external"
        / "rcl"
        / "rcl-oracle-fixtures.v1.json"
    )
    projection_root = ROOT / "examples" / "interop" / "rcl-to-vate"
    projection_map_path = projection_root / "rcl-005-006-008-projection-map.v1.json"
    projection_doc_path = ROOT / "docs" / "interop" / "rcl-receipt-claim-projection.md"
    case_root = ROOT / "conformance" / "al2-vate-v0.3" / "cases"
    expected_source_sha256 = "4164151383605d9d68230d81cc9ae1dd31eb5cfb3fb1348289abf71ee64773ea"
    source_fixture_commit = "825986680dc53fa776038db814b8d1da1dfcba9c"
    source_harness_commit = "d6b7184e0d205672463f7f3284571e9e6a3e797d"
    source_fixture_rel = "conformance/al2-vate-v0.3/external/rcl/rcl-oracle-fixtures.v1.json"
    case_files = {
        "RCL-005": case_root / "rcl-005-authorization-params-mismatch.json",
        "RCL-006": case_root / "rcl-006-occurrence-action-linkage-mismatch.json",
        "RCL-008": case_root / "rcl-008-full-pipeline-acceptance-control.json",
    }

    if hashlib.sha256(source_fixture_path.read_bytes()).hexdigest() != expected_source_sha256:
        raise RuntimeError("RCL source fixture full-file SHA-256 drifted from the pinned source bytes")
    source_fixture = json.loads(source_fixture_path.read_text(encoding="utf-8"))
    fixtures = source_fixture.get("fixtures")
    if not isinstance(fixtures, list):
        raise RuntimeError("RCL source fixture must expose a fixtures array")
    fixtures_by_id = {
        fixture.get("id"): fixture
        for fixture in fixtures
        if isinstance(fixture, dict) and isinstance(fixture.get("id"), str)
    }
    expected_pointers = {"RCL-005": 4, "RCL-006": 5, "RCL-008": 7}
    for source_case_id, index in expected_pointers.items():
        if index >= len(fixtures) or fixtures[index].get("id") != source_case_id:
            raise RuntimeError(f"{source_case_id} source pointer /fixtures/{index} drifted")

    rcl_005 = fixtures_by_id["RCL-005"]
    rcl_006 = fixtures_by_id["RCL-006"]
    rcl_008 = fixtures_by_id["RCL-008"]
    if rcl_005.get("expected") != {
        "verdict": "reject",
        "claim_family": "authorization",
        "reason": "authorization: params do not match the action",
    }:
        raise RuntimeError("RCL-005 source expectation drifted")
    if rcl_006.get("expected") != {
        "verdict": "reject",
        "claim_family": "occurrence",
        "reason": "occurrence: acknowledgment bound to another action",
    }:
        raise RuntimeError("RCL-006 source expectation drifted")
    if rcl_008.get("expected") != {
        "verdict": "accept",
        "claim_family": None,
        "reason": "all four properties independently supported",
    }:
        raise RuntimeError("RCL-008 source acceptance-control expectation drifted")

    rcl_005_receipt = json.loads(json.dumps(rcl_005["receipt"]))
    rcl_008_receipt = json.loads(json.dumps(rcl_008["receipt"]))
    rcl_005_params_digest = rcl_005_receipt["claims"]["authorization"]["params_digest"]
    rcl_008_params_digest = rcl_008_receipt["claims"]["authorization"]["params_digest"]
    if rcl_005_params_digest == rcl_008_params_digest:
        raise RuntimeError("RCL-005 must change the authorization params digest relative to RCL-008")
    for receipt in (rcl_005_receipt, rcl_008_receipt):
        receipt["claims"]["authorization"].pop("sig", None)
        receipt.pop("envelope_sig", None)
    rcl_005_receipt["claims"]["authorization"]["params_digest"] = rcl_008_params_digest
    if rcl_005_receipt != rcl_008_receipt:
        raise RuntimeError("RCL-005 changed source semantics beyond params_digest and dependent signatures")

    rcl_006_receipt = json.loads(json.dumps(rcl_006["receipt"]))
    rcl_008_receipt = json.loads(json.dumps(rcl_008["receipt"]))
    rcl_006_occurrence_digest = rcl_006_receipt["claims"]["occurrence"]["action_digest"]
    rcl_008_occurrence_digest = rcl_008_receipt["claims"]["occurrence"]["action_digest"]
    if rcl_006_occurrence_digest == rcl_008_occurrence_digest:
        raise RuntimeError("RCL-006 must change the occurrence action digest relative to RCL-008")
    for receipt in (rcl_006_receipt, rcl_008_receipt):
        receipt["claims"]["occurrence"].pop("sig", None)
        receipt.pop("envelope_sig", None)
    rcl_006_receipt["claims"]["occurrence"]["action_digest"] = rcl_008_occurrence_digest
    if rcl_006_receipt != rcl_008_receipt:
        raise RuntimeError("RCL-006 changed source semantics beyond occurrence.action_digest and dependent signatures")

    projection_map = json.loads(projection_map_path.read_text(encoding="utf-8"))
    expected_source_metadata = {
        "repository": "https://github.com/msaleme/red-team-blue-team-agent-fabric",
        "license": "Apache-2.0",
    }
    for field, expected in expected_source_metadata.items():
        if projection_map.get("source", {}).get(field) != expected:
            raise RuntimeError(f"RCL projection source {field} drifted")
    fixture_metadata = projection_map.get("source", {}).get("fixture", {})
    harness_metadata = projection_map.get("source", {}).get("harness", {})
    if fixture_metadata.get("commit") != source_fixture_commit:
        raise RuntimeError("RCL projection fixture commit drifted")
    if fixture_metadata.get("path") != "fixtures/rcl/rcl-oracle-fixtures.v1.json":
        raise RuntimeError("RCL projection fixture source path drifted")
    if fixture_metadata.get("raw_sha256") != expected_source_sha256:
        raise RuntimeError("RCL projection provenance lost the full-file source digest")
    if fixture_metadata.get("vendored_path") != source_fixture_rel:
        raise RuntimeError("RCL projection provenance lost the vendored source path")
    if fixture_metadata.get("carriage") != "verbatim-full-file-bytes":
        raise RuntimeError("RCL source fixture must remain labelled as verbatim full-file bytes")
    if harness_metadata != {
        "commit": source_harness_commit,
        "path": "protocol_tests/receipt_claim_harness.py",
    }:
        raise RuntimeError("RCL source harness provenance drifted")
    if projection_map.get("source", {}).get("case_pointers") != {
        "RCL-005": "/fixtures/4",
        "RCL-006": "/fixtures/5",
        "RCL-008": "/fixtures/7",
    }:
        raise RuntimeError("RCL source case pointers drifted")

    expected_projection_paths = {
        "examples/interop/rcl-to-vate/action-transfer.derived-vate-projection.json",
        "examples/interop/rcl-to-vate/action-params.derived-vate-projection.json",
        "examples/interop/rcl-to-vate/action-other.derived-vate-projection.json",
        "examples/interop/rcl-to-vate/request-basis.derived-vate-projection.json",
        "examples/interop/rcl-to-vate/result-basis-settled.derived-vate-projection.json",
        "examples/interop/rcl-to-vate/vate-admission-request-rcl-005-006-008.derived-vate-projection.json",
        "examples/interop/rcl-to-vate/vate-admission-receipt-rcl-005.derived-vate-projection.json",
        "examples/interop/rcl-to-vate/vate-admission-receipt-rcl-006-008.derived-vate-projection.json",
        "examples/interop/rcl-to-vate/vate-post-execution-receipt-rcl-006.derived-vate-projection.json",
        "examples/interop/rcl-to-vate/vate-post-execution-receipt-rcl-008.derived-vate-projection.json",
    }
    projection_entries = projection_map.get("projection_artifacts")
    if not isinstance(projection_entries, list):
        raise RuntimeError("RCL projection map must list projection_artifacts")
    actual_projection_paths = {
        entry.get("path")
        for entry in projection_entries
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    }
    if actual_projection_paths != expected_projection_paths:
        raise RuntimeError("RCL derived projection artifact inventory drifted")
    for entry in projection_entries:
        path = entry.get("path")
        if entry.get("classification") != "derived-vate-projection":
            raise RuntimeError(f"{path}: must remain labelled as a derived VATE projection")
        if not isinstance(path, str) or not path.endswith(".derived-vate-projection.json"):
            raise RuntimeError(f"{path}: derived projection filename is not explicit")
        if not (ROOT / path).is_file():
            raise RuntimeError(f"{path}: derived projection artifact is missing")
        if not entry.get("source_case_pointers") or not entry.get("selected_preimage") or not entry.get("digest_basis"):
            raise RuntimeError(f"{path}: projection provenance is incomplete")

    action = json.loads((projection_root / "action-transfer.derived-vate-projection.json").read_text())
    action_params = json.loads((projection_root / "action-params.derived-vate-projection.json").read_text())
    other_action = json.loads((projection_root / "action-other.derived-vate-projection.json").read_text())
    request_basis = json.loads((projection_root / "request-basis.derived-vate-projection.json").read_text())
    result_basis = json.loads((projection_root / "result-basis-settled.derived-vate-projection.json").read_text())
    admission_request = json.loads(
        (projection_root / "vate-admission-request-rcl-005-006-008.derived-vate-projection.json").read_text()
    )
    deny_admission = json.loads(
        (projection_root / "vate-admission-receipt-rcl-005.derived-vate-projection.json").read_text()
    )
    allow_admission = json.loads(
        (projection_root / "vate-admission-receipt-rcl-006-008.derived-vate-projection.json").read_text()
    )
    mismatch_post = json.loads(
        (projection_root / "vate-post-execution-receipt-rcl-006.derived-vate-projection.json").read_text()
    )
    control_post = json.loads(
        (projection_root / "vate-post-execution-receipt-rcl-008.derived-vate-projection.json").read_text()
    )

    def contains_object_key(value: object, forbidden_key: str) -> bool:
        if isinstance(value, dict):
            return forbidden_key in value or any(
                contains_object_key(child, forbidden_key) for child in value.values()
            )
        if isinstance(value, list):
            return any(contains_object_key(child, forbidden_key) for child in value)
        return False

    projection_values = {
        "projection_map": projection_map,
        "action": action,
        "action_params": action_params,
        "other_action": other_action,
        "request_basis": request_basis,
        "result_basis": result_basis,
        "admission_request": admission_request,
        "deny_admission": deny_admission,
        "allow_admission": allow_admission,
        "mismatch_post": mismatch_post,
        "control_post": control_post,
    }
    for label, value in projection_values.items():
        for forbidden_key in ("pairing", "recomputation_boundary"):
            if contains_object_key(value, forbidden_key):
                raise RuntimeError(f"RCL {label} must not contain {forbidden_key}")

    def descriptor(value: object) -> dict[str, str]:
        return {
            "alg": "sha-256",
            "value": hashlib.sha256(canonical_json_bytes(value)).hexdigest(),
        }

    action_descriptor = descriptor(action)
    params_descriptor = descriptor(action_params)
    other_action_descriptor = descriptor(other_action)
    map_descriptor = descriptor(projection_map)
    if action != fixtures_by_id["RCL-008"]["receipt"]["action"]:
        raise RuntimeError("RCL selected action projection drifted from the source value")
    if action_params != action.get("params"):
        raise RuntimeError("RCL selected action-params projection drifted")
    if action_descriptor["value"] != fixtures_by_id["RCL-008"]["receipt"]["action_digest"]:
        raise RuntimeError("RCL selected action preimage no longer reproduces the source action digest")
    if params_descriptor["value"] != rcl_008_params_digest:
        raise RuntimeError("RCL selected params preimage no longer reproduces the control authorization digest")
    if other_action_descriptor["value"] != fixtures_by_id["RCL-006"]["receipt"]["claims"]["occurrence"]["action_digest"]:
        raise RuntimeError("RCL other-action preimage no longer reproduces the occurrence digest")

    request_hash = "sha-256:" + hashlib.sha256(canonical_json_bytes(request_basis)).hexdigest()
    result_hash = "sha-256:" + hashlib.sha256(canonical_json_bytes(result_basis)).hexdigest()
    if admission_request.get("input_hash") != request_hash:
        raise RuntimeError("RCL derived admission request input_hash lost its VATE request-basis preimage")
    for receipt in (deny_admission, allow_admission):
        if receipt.get("request", {}).get("input_hash") != request_hash:
            raise RuntimeError("RCL admission receipt input_hash lost its VATE request-basis preimage")
    for receipt in (mismatch_post, control_post):
        if receipt.get("execution", {}).get("effective_request_hash") != request_hash:
            raise RuntimeError("RCL post-execution effective_request_hash lost its VATE request-basis preimage")
        if receipt.get("result", {}).get("output_hash") != result_hash:
            raise RuntimeError("RCL post-execution output_hash lost its derived settled-result preimage")
    source_digest_values = {
        rcl_005_params_digest,
        rcl_008_params_digest,
        fixtures_by_id["RCL-008"]["receipt"]["action_digest"],
        fixtures_by_id["RCL-006"]["receipt"]["claims"]["occurrence"]["action_digest"],
        fixtures_by_id["RCL-008"]["receipt"]["claims"]["occurrence"]["outcome_digest"],
    }
    if request_hash in {"sha-256:" + value for value in source_digest_values}:
        raise RuntimeError("RCL source digest was projected into a VATE request hash field")
    if result_hash in {"sha-256:" + value for value in source_digest_values}:
        raise RuntimeError("RCL source digest was projected into the VATE output_hash field")

    for artifact in (admission_request, deny_admission, allow_admission):
        evidence = artifact.get("evidence_refs", artifact.get("evidence", []))
        if not evidence or evidence[0].get("digest") != map_descriptor:
            raise RuntimeError("RCL projection artifact is not bound to the projection map")
    if deny_admission["request"]["action_binding"]["digest"] != action_descriptor:
        raise RuntimeError("RCL-005 overloaded the admitted action binding with the authorization digest")
    if deny_admission["request"]["mapping_only"]["source_authorization"]["params_digest"] != {
        "alg": "sha-256",
        "value": rcl_005_params_digest,
    }:
        raise RuntimeError("RCL-005 mapping-only authorization descriptor drifted")
    if allow_admission["request"]["action_binding"]["digest"] != action_descriptor:
        raise RuntimeError("RCL-006/RCL-008 admitted action binding drifted")
    if allow_admission["request"]["mapping_only"]["source_authorization"]["params_digest"] != params_descriptor:
        raise RuntimeError("RCL-006/RCL-008 authorization control descriptor drifted")
    if mismatch_post["execution"]["action_binding"]["digest"] != other_action_descriptor:
        raise RuntimeError("RCL-006 occurrence binding no longer carries the other-action digest")
    if control_post["execution"]["action_binding"]["digest"] != action_descriptor:
        raise RuntimeError("RCL-008 occurrence binding no longer matches the admitted action")
    if mismatch_post.get("result", {}).get("outcome") != "success":
        raise RuntimeError("RCL-006 must preserve the settled occurrence as a successful result")

    cases = {
        source_case_id: json.loads(path.read_text(encoding="utf-8"))
        for source_case_id, path in case_files.items()
    }
    expected_case_results = {
        "RCL-005": {
            "admission_decision": "deny",
            "should_execute": False,
            "reason_codes": ["ACTION_NOT_PERMITTED", "FAIL_CLOSED"],
        },
        "RCL-006": {
            "admission_decision": "allow",
            "post_execution_outcome": "success",
            "should_execute": True,
            "reason_codes": ["POST_EXEC_LINKAGE_MISMATCH"],
        },
        "RCL-008": {
            "admission_decision": "allow",
            "post_execution_outcome": "success",
            "should_execute": True,
            "reason_codes": [
                "ADMISSION_RECEIPT_LINKED",
                "EFFECTIVE_REQUEST_HASH_MATCH",
                "NO_POLICY_VIOLATIONS",
            ],
        },
    }
    for source_case_id, case in cases.items():
        for forbidden_key in ("pairing", "recomputation_boundary"):
            if contains_object_key(case, forbidden_key):
                raise RuntimeError(f"{source_case_id} projection must not contain {forbidden_key}")
        if case.get("artifacts", {}).get("source_fixture") != source_fixture_rel:
            raise RuntimeError(f"{source_case_id} projection lost the complete pinned source fixture")
        if case.get("expected") != {
            **expected_case_results[source_case_id],
            "checks": case.get("expected", {}).get("checks", []),
        }:
            raise RuntimeError(f"{source_case_id} expected outcome or reason ordering drifted")
        if case.get("jose_checks") or case.get("trust_checks"):
            raise RuntimeError(f"{source_case_id} must keep source-profile validation outside the VATE projection")
    if "post_execution_receipt" in cases["RCL-005"].get("artifacts", {}):
        raise RuntimeError("RCL-005 projection must stop at admission")

    def has_artifact_check(
        case: dict,
        *,
        artifact: str,
        expect_match: bool,
        reference_artifact: str,
        path: str,
    ) -> bool:
        return any(
            check.get("artifact") == artifact
            and check.get("expect_match") is expect_match
            and {"artifact": reference_artifact, "path": path} in check.get("reference_paths", [])
            for check in case.get("artifact_reference_checks", [])
            if isinstance(check, dict)
        )

    if not has_artifact_check(
        cases["RCL-005"],
        artifact="action_params",
        expect_match=False,
        reference_artifact="admission_receipt",
        path="request.mapping_only.source_authorization.params_digest",
    ):
        raise RuntimeError("RCL-005 lost its expected authorization params mismatch recomputation")
    if not has_artifact_check(
        cases["RCL-005"],
        artifact="action",
        expect_match=True,
        reference_artifact="admission_receipt",
        path="request.action_binding.digest",
    ):
        raise RuntimeError("RCL-005 lost its correct admitted action binding")
    for artifact, expect_match, reference_artifact, path in (
        ("action", True, "admission_receipt", "request.action_binding.digest"),
        ("action", False, "post_execution_receipt", "execution.action_binding.digest"),
        ("other_action", False, "admission_receipt", "request.action_binding.digest"),
        ("other_action", True, "post_execution_receipt", "execution.action_binding.digest"),
    ):
        if not has_artifact_check(
            cases["RCL-006"],
            artifact=artifact,
            expect_match=expect_match,
            reference_artifact=reference_artifact,
            path=path,
        ):
            raise RuntimeError("RCL-006 lost its admitted/occurrence action recomputation matrix")
    rcl_006_path_match = [
        check
        for check in cases["RCL-006"].get("linkage_checks", [])
        if check.get("kind") == "path_match"
    ]
    if rcl_006_path_match != [
        {
            "kind": "path_match",
            "admission_path": "request.action_binding.digest",
            "post_execution_path": "execution.action_binding.digest",
            "expect_match": False,
            "reason_code": "POST_EXEC_LINKAGE_MISMATCH",
        }
    ]:
        raise RuntimeError("RCL-006 path_match contract drifted")
    rcl_008_path_match = [
        check
        for check in cases["RCL-008"].get("linkage_checks", [])
        if check.get("kind") == "path_match"
    ]
    if len(rcl_008_path_match) != 1 or rcl_008_path_match[0].get("expect_match") is not True:
        raise RuntimeError("RCL-008 must retain a matching full-pipeline action-binding control")

    conformance = load_vate_conformance_module()
    for source_case_id, path in case_files.items():
        result = conformance.evaluate_case(path)
        if result.get("pass") is not True:
            raise RuntimeError(f"{source_case_id} committed VATE projection does not pass: {result.get('failures')}")

    with tempfile.TemporaryDirectory(prefix="vate-rcl-projection-regression-") as tmp:
        tmp_root = Path(tmp)

        fixed_rcl_005_receipt = json.loads(json.dumps(deny_admission))
        fixed_rcl_005_receipt["request"]["mapping_only"]["source_authorization"]["params_digest"] = params_descriptor
        fixed_rcl_005_receipt_path = tmp_root / "rcl-005-fixed-receipt.json"
        fixed_rcl_005_receipt_path.write_text(
            json.dumps(fixed_rcl_005_receipt, indent=2) + "\n",
            encoding="utf-8",
        )
        fixed_rcl_005_case = json.loads(json.dumps(cases["RCL-005"]))
        fixed_rcl_005_case["artifacts"]["admission_receipt"] = str(fixed_rcl_005_receipt_path)
        fixed_rcl_005_case_path = tmp_root / "rcl-005-fixed-case.json"
        fixed_rcl_005_case_path.write_text(json.dumps(fixed_rcl_005_case, indent=2) + "\n", encoding="utf-8")
        fixed_rcl_005_result = conformance.evaluate_case(fixed_rcl_005_case_path)
        expected_rcl_005_failure = (
            "artifact_ref action_params/admission_receipt: "
            "expected digest match=False actual match=True"
        )
        if (
            fixed_rcl_005_result.get("pass") is True
            or expected_rcl_005_failure not in fixed_rcl_005_result.get("failures", [])
        ):
            raise RuntimeError(
                "RCL-005 params-mismatch repair did not fail for the intended recomputation condition: "
                f"{fixed_rcl_005_result.get('failures')}"
            )

        fixed_rcl_006_post = json.loads(json.dumps(mismatch_post))
        fixed_rcl_006_post["execution"]["action_binding"] = json.loads(
            json.dumps(allow_admission["request"]["action_binding"])
        )
        fixed_rcl_006_post_path = tmp_root / "rcl-006-fixed-post.json"
        fixed_rcl_006_post_path.write_text(json.dumps(fixed_rcl_006_post, indent=2) + "\n", encoding="utf-8")
        fixed_rcl_006_case = json.loads(json.dumps(cases["RCL-006"]))
        fixed_rcl_006_case["artifacts"]["post_execution_receipt"] = str(fixed_rcl_006_post_path)
        fixed_rcl_006_case_path = tmp_root / "rcl-006-fixed-case.json"
        fixed_rcl_006_case_path.write_text(json.dumps(fixed_rcl_006_case, indent=2) + "\n", encoding="utf-8")
        fixed_rcl_006_result = conformance.evaluate_case(fixed_rcl_006_case_path)
        expected_rcl_006_failures = {
            "linkage[6] path_match: expected violation=True actual violation=False",
            "artifact_ref action/post_execution_receipt: expected digest match=False actual match=True",
            "artifact_ref other_action/post_execution_receipt: expected digest match=True actual match=False",
        }
        actual_rcl_006_failures = set(fixed_rcl_006_result.get("failures", []))
        if (
            fixed_rcl_006_result.get("pass") is True
            or not expected_rcl_006_failures.issubset(actual_rcl_006_failures)
        ):
            raise RuntimeError(
                "RCL-006 action-linkage repair did not fail for the intended linkage conditions: "
                f"{fixed_rcl_006_result.get('failures')}"
            )

        reject_control_sut_results = json.loads(
            (ROOT / "examples" / "conformance" / "sut-results-pass.example.json").read_text()
        )
        reject_control_results = [
            result
            for result in reject_control_sut_results.get("results", [])
            if isinstance(result, dict)
            and result.get("case_id") == "rcl-008-full-pipeline-acceptance-control"
        ]
        if len(reject_control_results) != 1:
            raise RuntimeError("passing SUT example must contain exactly one RCL-008 result")
        reject_control_result = reject_control_results[0]
        reject_control_result["outcome"] = "deny"
        reject_control_result["should_execute"] = False
        reject_control_result["reason_codes"] = ["FAIL_CLOSED"]

        sut_result_schema = json.loads((ROOT / "schemas" / "sut-result.schema.json").read_text())
        reject_control_schema_errors = check(
            sut_result_schema,
            sut_result_schema,
            reject_control_sut_results,
        )
        if reject_control_schema_errors:
            raise RuntimeError(
                "RCL-008 reject-everything SUT mutation must remain schema-valid: "
                f"{reject_control_schema_errors}"
            )

        reject_control_sut_path = tmp_root / "rcl-008-reject-all-sut-results.json"
        reject_control_sut_path.write_text(
            json.dumps(reject_control_sut_results, indent=2) + "\n",
            encoding="utf-8",
        )
        reject_control_report = conformance.compare_sut_results(
            ROOT / "conformance" / "al2-vate-v0.3",
            reject_control_sut_path,
        )
        if reject_control_report.get("fatal_errors"):
            raise RuntimeError(
                "RCL-008 reject-everything SUT comparison produced fatal errors: "
                f"{reject_control_report['fatal_errors']}"
            )
        if reject_control_report.get("summary") != {
            "total": 76,
            "passed": 75,
            "failed": 1,
            "skipped": 0,
        }:
            raise RuntimeError(
                "RCL-008 reject-everything SUT comparison must report 75/76 passed: "
                f"{reject_control_report.get('summary')}"
            )
        reject_control_failed_cases = [
            case
            for case in reject_control_report.get("cases", [])
            if isinstance(case, dict) and case.get("pass") is not True
        ]
        expected_reject_control_failures = [
            "should_execute: expected True actual False",
            "outcome: expected success actual deny",
            "reason_codes: expected ['ADMISSION_RECEIPT_LINKED', "
            "'EFFECTIVE_REQUEST_HASH_MATCH', 'NO_POLICY_VIOLATIONS'] actual ['FAIL_CLOSED']",
            "primary_reason_code: expected ADMISSION_RECEIPT_LINKED actual None",
            "actual_reason_codes: FAIL_CLOSED must follow a primary denial reason",
        ]
        if len(reject_control_failed_cases) != 1:
            raise RuntimeError(
                "RCL-008 reject-everything SUT mutation must fail exactly one case: "
                f"{reject_control_failed_cases}"
            )
        reject_control_failure = reject_control_failed_cases[0]
        if (
            reject_control_failure.get("case_id") != "rcl-008-full-pipeline-acceptance-control"
            or reject_control_failure.get("actual_outcome") != "deny"
            or reject_control_failure.get("actual_should_execute") is not False
            or reject_control_failure.get("actual_reason_codes") != ["FAIL_CLOSED"]
            or reject_control_failure.get("failures") != expected_reject_control_failures
        ):
            raise RuntimeError(
                "RCL-008 reject-everything SUT mutation must fail only the expected outcome, "
                "execution-gate, and reason comparisons: "
                f"{reject_control_failure}"
            )

    corpus = json.loads((ROOT / "conformance" / "al2-vate-v0.3" / "corpus.json").read_text(encoding="utf-8"))
    if corpus.get("summary", {}).get("case_count") != 76:
        raise RuntimeError("canonical VATE corpus must contain 76 cases after the status-input slice")
    corpus_case_ids = {entry.get("case_id") for entry in corpus.get("cases", []) if isinstance(entry, dict)}
    expected_case_ids = {case["case_id"] for case in cases.values()}
    if not expected_case_ids.issubset(corpus_case_ids):
        raise RuntimeError("canonical corpus index is missing an RCL projection case")
    source_manifest_entry = next(
        (entry for entry in corpus.get("manifest", []) if entry.get("path") == source_fixture_rel),
        None,
    )
    if source_manifest_entry != {"path": source_fixture_rel, "sha256": expected_source_sha256}:
        raise RuntimeError("canonical corpus manifest lost the exact RCL source fixture bytes")
    sut_results = json.loads((ROOT / "examples" / "conformance" / "sut-results-pass.example.json").read_text())
    sut_case_ids = {entry.get("case_id") for entry in sut_results.get("results", []) if isinstance(entry, dict)}
    if not expected_case_ids.issubset(sut_case_ids):
        raise RuntimeError("passing SUT example is missing an RCL projection case")

    normalized_doc = " ".join(projection_doc_path.read_text(encoding="utf-8").split()).lower()
    required_doc_phrases = [
        source_fixture_commit,
        source_harness_commit,
        expected_source_sha256,
        "apache-2.0",
        "derived vate projection",
        "source-profile validation",
        "not an external sut run",
        "not rfc 8785/jcs",
        "issuecomment-5209176439",
        "issuecomment-5281915833",
        "issuecomment-5282295933",
    ]
    missing_doc_phrases = [phrase for phrase in required_doc_phrases if phrase not in normalized_doc]
    if missing_doc_phrases:
        raise RuntimeError(f"RCL projection documentation lost required boundaries: {missing_doc_phrases}")


def main() -> int:
    args = parse_args()
    validate_examples()
    check_evidence_vocabulary_registry()
    check_artifact_versioning_docs()
    check_post_execution_linkage_kind_coverage()
    check_transport_bound_fixture_coverage()
    check_status_freshness_boundary_coverage()
    check_status_input_contract_coverage()
    check_sut_result_envelope_fail_closed()
    check_case_json_fail_closed()
    check_case_artifact_reference_fail_closed()
    check_unhashable_validator_inputs_fail_closed()
    check_context_binding_key_contract()
    check_corpus_index_requires_cases()
    check_bundle_case_coverage_binding()
    check_bundle_sut_actual_projection_binding()
    check_bundle_report_contract_fail_closed()
    check_external_sut_template_partial_contract()
    check_replay_boundary_coverage()
    check_p1_5_fixture_coverage()
    check_p2_public_artifact_boundary()
    check_rcl_projection_package()
    check_vate_conformance_display_paths_are_portable()
    check_linkage_missing_artifacts_fail_closed()
    check_admission_handoff_semantics_fail_closed()
    check_case_artifact_readers_fail_closed()
    check_nested_artifact_shapes_fail_closed()
    check_corpus_manifest_non_file_fails_closed()
    check_bundle_corpus_index_fails_closed()
    check_generated_artifact_utf8_boundary()
    check_a2a_adapter_local_uri_boundary()
    check_a2a_adapter_malformed_metadata_fail_closed()
    check_al2_corpus_docs_synced()
    run([sys.executable, "-m", "py_compile", str(DEMO)])
    run([sys.executable, "-m", "py_compile", str(HTTP_DEMO)])
    run([sys.executable, "-m", "py_compile", str(VATE_CONFORMANCE)])
    run([sys.executable, "-m", "py_compile", str(PULSE_EXTERNAL_SUT_STARTER_CHECK)])
    run([sys.executable, str(PULSE_EXTERNAL_SUT_STARTER_CHECK), "--archive-safe"])
    if historical_pulse_source_is_available():
        run([sys.executable, str(PULSE_EXTERNAL_SUT_STARTER_CHECK), "--self-test"])
        print(
            "Pulse starter full-history gate: ok "
            "(historical VATE source commit reloaded; 33 validator negative probes passed; "
            "frozen Pulse verifier replay not run without --pulse-repo)"
        )
    elif args.require_full_history:
        print(
            "Pulse starter full-history gate required, but historical VATE source commit "
            "5a37f87de0190da44e619b1800261637e83dd7ed is unavailable; "
            "frozen Pulse verifier replay was not attempted",
            file=sys.stderr,
        )
        return 2
    else:
        print(
            "Pulse starter full-history gate: not run "
            "(historical VATE source commit unavailable in this source archive; "
            "frozen Pulse verifier replay also not run)"
        )
    run([sys.executable, "-m", "py_compile", str(VATE_CORE)])
    run([sys.executable, "-m", "py_compile", str(A2A_ADAPTER)])

    tmp_dir = Path(tempfile.mkdtemp(prefix="trust-envelope-check-"))
    port = find_free_port()
    status_base = f"http://127.0.0.1:{port}"
    server = None
    try:
        run([sys.executable, str(DEMO), "generate-demo", "--out", str(tmp_dir)])
        run([sys.executable, str(DEMO), "verify-demo", "--dir", str(tmp_dir), "--status-mode", "stapled"])
        run([sys.executable, str(DEMO), "verify-demo", "--dir", str(tmp_dir), "--status-mode", "push"])

        server = subprocess.Popen(
            [
                sys.executable,
                str(DEMO),
                "serve-status",
                "--dir",
                str(tmp_dir),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wait_for_health(f"{status_base}/healthz")
        run(
            [
                sys.executable,
                str(DEMO),
                "verify-demo",
                "--dir",
                str(tmp_dir),
                "--status-mode",
                "pull",
                "--status-base",
                status_base,
            ]
        )
        run(
            [
                sys.executable,
                str(DEMO),
                "fetch-status",
                "--dir",
                str(tmp_dir),
                "--status-base",
                status_base,
                "--mode",
                "all",
            ]
        )
        run([sys.executable, str(DEMO), "run-negative-tests", "--dir", str(tmp_dir)])
        run(
            [
                sys.executable,
                str(HTTP_DEMO),
                "run-corpus",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-http"),
                "--policy",
                str(ROOT / "policies" / "al2-http-verifier.example.json"),
            ]
        )
        run(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "run",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--report",
                str(tmp_dir / "vate-conformance-report.json"),
                "--implementation-report",
                str(tmp_dir / "vate-implementation-report.json"),
                "--implementation-name",
                "VATE reference artifact checker",
                "--implementation-type",
                "reference-artifact-checker",
                "--implementation-version",
                "0.2",
                "--implementation-language",
                "Python 3 standard library",
            ]
        )
        assert_primary_reason_codes(tmp_dir / "vate-conformance-report.json")
        generated_corpus_index = tmp_dir / "vate-corpus-index.json"
        run(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "index",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--out",
                str(generated_corpus_index),
            ]
        )
        assert_json_matches(generated_corpus_index, ROOT / "conformance" / "al2-vate-v0.3" / "corpus.json")
        assert_primary_reason_codes(generated_corpus_index)
        run(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(ROOT / "examples" / "conformance" / "sut-results-pass.example.json"),
                "--report",
                str(tmp_dir / "vate-sut-compare-report.json"),
                "--implementation-report",
                str(tmp_dir / "vate-sut-implementation-report.json"),
                "--conformance-report-uri",
                str(tmp_dir / "vate-sut-compare-report.json"),
                "--implementation-report-uri",
                str(tmp_dir / "vate-sut-implementation-report.json"),
            ]
        )
        assert_primary_reason_codes(tmp_dir / "vate-sut-compare-report.json")
        generated_sut_results = tmp_dir / "sut-results-generated-receipts.json"
        generated_compare_report = tmp_dir / "vate-sut-generated-receipts-report.json"
        generated_implementation_report = tmp_dir / "vate-sut-generated-receipts-implementation-report.json"
        generated_bundle_report = tmp_dir / "vate-sut-generated-receipts-bundle-report.json"
        write_sut_result_with_generated_receipts(
            generated_sut_results,
            tamper_allow_outcome=False,
        )
        run(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(generated_sut_results),
                "--report",
                str(generated_compare_report),
                "--implementation-report",
                str(generated_implementation_report),
                "--conformance-report-uri",
                str(generated_compare_report),
                "--implementation-report-uri",
                str(generated_implementation_report),
            ]
        )
        generated_report = json.loads(generated_compare_report.read_text(encoding="utf-8"))
        if generated_report.get("summary") != {"total": 76, "passed": 76, "failed": 0, "skipped": 0}:
            raise AssertionError("schema-valid independently identified generated receipts must pass compare")
        generated_cases = {
            case.get("case_id"): case
            for case in generated_report.get("cases", [])
            if isinstance(case, dict)
        }
        for case_id in ("allow-valid-admission", "post-execution-linkage-success"):
            case_result = generated_cases.get(case_id, {})
            if case_result.get("artifact_mode") != "generated-receipts" or case_result.get("pass") is not True:
                raise AssertionError(f"{case_id}: generated-receipts comparison did not pass")
        expected_mode_counts = {
            "corpus-fixture-validation": 74,
            "generated-receipts": 2,
        }
        if generated_report.get("sut_results", {}).get("artifact_mode_counts") != expected_mode_counts:
            raise AssertionError("conformance report must expose effective artifact mode counts")
        generated_implementation = json.loads(generated_implementation_report.read_text(encoding="utf-8"))
        if generated_implementation.get("artifact_mode_counts") != expected_mode_counts:
            raise AssertionError("implementation report must expose effective artifact mode counts")
        implementation_cases = {
            case.get("case_id"): case
            for case in generated_implementation.get("case_results", [])
            if isinstance(case, dict)
        }
        for case_id in ("allow-valid-admission", "post-execution-linkage-success"):
            if implementation_cases.get(case_id, {}).get("artifact_mode") != "generated-receipts":
                raise AssertionError(f"{case_id}: implementation report lost the effective artifact mode")

        run(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "verify-bundle",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(generated_sut_results),
                "--conformance-report",
                str(generated_compare_report),
                "--implementation-report",
                str(generated_implementation_report),
                "--report",
                str(generated_bundle_report),
            ]
        )
        for case_id in ("allow-valid-admission", "post-execution-linkage-success"):
            assert_bundle_check(
                generated_bundle_report,
                f"sut_results.generated_artifacts.{case_id}",
                True,
            )
        assert_bundle_check(
            generated_bundle_report,
            "conformance_report.sut_results.artifact_mode_counts",
            True,
        )
        assert_bundle_check(
            generated_bundle_report,
            "implementation_report.artifact_mode_counts",
            True,
        )

        generated_shape_variants = (
            (
                "decision-outcome-array",
                "allow-valid-admission",
                "admission_receipt",
                "generated-admission-allow.json",
                ("decision", "outcome"),
                [],
                "decision.outcome: expected allow, attenuate, or deny",
            ),
            (
                "decision-visibility-array",
                "allow-valid-admission",
                "admission_receipt",
                "generated-admission-allow.json",
                ("decision", "reason_visibility"),
                [],
                "decision.reason_visibility: expected disclosed, opaque, or withheld",
            ),
            (
                "proof-format-array",
                "allow-valid-admission",
                "admission_receipt",
                "generated-admission-allow.json",
                ("proof", "format"),
                [],
                "proof.format: unsupported proof format",
            ),
            (
                "attenuation-mode-array",
                "post-execution-linkage-success",
                "admission_receipt",
                "generated-admission-linkage.json",
                ("attenuation", "mode"),
                [],
                "attenuation: mode must be a supported attenuation mode",
            ),
            (
                "issuer-role-array",
                "post-execution-linkage-success",
                "post_execution_receipt",
                "generated-post-execution-linkage.json",
                ("issuer", "role"),
                [],
                "issuer.role: expected runtime, agent, verifier, or broker",
            ),
            (
                "post-admission-decision-array",
                "post-execution-linkage-success",
                "post_execution_receipt",
                "generated-post-execution-linkage.json",
                ("admission", "decision"),
                [],
                "admission.decision: expected allow or attenuate",
            ),
            (
                "policy-violation-token-array",
                "post-execution-linkage-success",
                "post_execution_receipt",
                "generated-post-execution-linkage.json",
                ("result", "policy_violations"),
                [[]],
                "policy_violations[0]: unknown token",
            ),
            (
                "generated-non-finite-json",
                "allow-valid-admission",
                "admission_receipt",
                "generated-admission-allow.json",
                ("ignored_extension_value",),
                float("nan"),
                "generated artifact must be a UTF-8 JSON object",
            ),
        )
        for (
            label,
            case_id,
            artifact_name,
            artifact_filename,
            field_path,
            replacement,
            expected_error,
        ) in generated_shape_variants:
            assert_generated_receipt_mutation_fails(
                tmp_dir,
                label=label,
                case_id=case_id,
                artifact_name=artifact_name,
                artifact_filename=artifact_filename,
                field_path=field_path,
                replacement=replacement,
                expected_error=expected_error,
            )

        enum_shape_variants = generated_shape_variants[:6]
        for invalid_label, invalid_value in (
            ("object", {}),
            ("null", None),
            ("number", 7),
        ):
            for (
                label,
                case_id,
                artifact_name,
                artifact_filename,
                field_path,
                _,
                expected_error,
            ) in enum_shape_variants:
                assert_generated_receipt_mutation_fails(
                    tmp_dir,
                    label=f"{label}-{invalid_label}",
                    case_id=case_id,
                    artifact_name=artifact_name,
                    artifact_filename=artifact_filename,
                    field_path=field_path,
                    replacement=invalid_value,
                    expected_error=expected_error,
                )

        for invalid_label, invalid_token in (
            ("object", {}),
            ("null", None),
            ("number", 7),
        ):
            assert_generated_receipt_mutation_fails(
                tmp_dir,
                label=f"policy-violation-token-{invalid_label}",
                case_id="post-execution-linkage-success",
                artifact_name="post_execution_receipt",
                artifact_filename="generated-post-execution-linkage.json",
                field_path=("result", "policy_violations"),
                replacement=[invalid_token],
                expected_error="policy_violations[0]: unknown token",
            )

        for non_finite_label, non_finite_token in (
            ("nan-literal", "NaN"),
            ("positive-exponent-overflow", "1e400"),
            ("negative-exponent-overflow", "-1e400"),
        ):
            non_finite_sut_dir = tmp_dir / f"non-finite-sut-json-{non_finite_label}"
            non_finite_sut_dir.mkdir()
            non_finite_sut_path = non_finite_sut_dir / "sut-results.json"
            non_finite_report_path = non_finite_sut_dir / "compare-report.json"
            non_finite_implementation_path = non_finite_sut_dir / "implementation-report.json"
            non_finite_bundle_path = non_finite_sut_dir / "bundle-report.json"
            non_finite_sut = json.loads(
                (ROOT / "examples" / "conformance" / "sut-results-pass.example.json").read_text()
            )
            sentinel = "__NON_FINITE_JSON_NUMBER__"
            non_finite_sut["implementation"]["non_finite_probe"] = sentinel
            raw_sut = json.dumps(non_finite_sut, indent=2, sort_keys=True) + "\n"
            encoded_sentinel = json.dumps(sentinel)
            if raw_sut.count(encoded_sentinel) != 1:
                raise AssertionError("non-finite JSON sentinel must occur exactly once")
            non_finite_sut_path.write_text(
                raw_sut.replace(encoded_sentinel, non_finite_token),
                encoding="utf-8",
            )
            non_finite_compare = run_expect_failure(
                [
                    sys.executable,
                    str(VATE_CONFORMANCE),
                    "compare",
                    "--corpus-root",
                    str(ROOT / "conformance" / "al2-vate-v0.3"),
                    "--sut-results",
                    str(non_finite_sut_path),
                    "--report",
                    str(non_finite_report_path),
                    "--implementation-report",
                    str(non_finite_implementation_path),
                    "--conformance-report-uri",
                    str(non_finite_report_path),
                    "--implementation-report-uri",
                    str(non_finite_implementation_path),
                ]
            )
            if "Traceback" in non_finite_compare.stderr:
                raise AssertionError(
                    f"{non_finite_label} SUT JSON caused compare traceback"
                )
            assert_strict_json_file(non_finite_report_path)
            assert_strict_json_file(non_finite_implementation_path)
            assert_report_error_contains(non_finite_report_path, "invalid strict JSON input")
            non_finite_bundle = run_expect_failure(
                [
                    sys.executable,
                    str(VATE_CONFORMANCE),
                    "verify-bundle",
                    "--corpus-root",
                    str(ROOT / "conformance" / "al2-vate-v0.3"),
                    "--sut-results",
                    str(non_finite_sut_path),
                    "--conformance-report",
                    str(non_finite_report_path),
                    "--implementation-report",
                    str(non_finite_implementation_path),
                    "--report",
                    str(non_finite_bundle_path),
                ]
            )
            if "Traceback" in non_finite_bundle.stderr:
                raise AssertionError(
                    f"{non_finite_label} SUT JSON caused verify-bundle traceback"
                )
            assert_strict_json_file(non_finite_bundle_path)
            assert_bundle_check(non_finite_bundle_path, "sut_results.json", False)

        malformed_mode_dir = tmp_dir / "malformed-artifact-mode"
        malformed_mode_dir.mkdir()
        malformed_mode_sut_path = malformed_mode_dir / "sut-results.json"
        malformed_mode_report_path = malformed_mode_dir / "compare-report.json"
        malformed_mode_implementation_path = malformed_mode_dir / "implementation-report.json"
        malformed_mode_bundle_path = malformed_mode_dir / "bundle-report.json"
        malformed_mode_sut = json.loads(
            (ROOT / "examples" / "conformance" / "sut-results-pass.example.json").read_text()
        )
        malformed_mode_sut["artifact_mode"] = {}
        malformed_mode_sut_path.write_text(
            json.dumps(malformed_mode_sut, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        malformed_mode_compare = run_expect_failure(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(malformed_mode_sut_path),
                "--report",
                str(malformed_mode_report_path),
                "--implementation-report",
                str(malformed_mode_implementation_path),
                "--conformance-report-uri",
                str(malformed_mode_report_path),
                "--implementation-report-uri",
                str(malformed_mode_implementation_path),
            ]
        )
        if "Traceback" in malformed_mode_compare.stderr:
            raise AssertionError("malformed artifact_mode caused compare traceback")
        assert_report_error_contains(malformed_mode_report_path, "sut_results.artifact_mode")
        malformed_mode_bundle = run_expect_failure(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "verify-bundle",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(malformed_mode_sut_path),
                "--conformance-report",
                str(malformed_mode_report_path),
                "--implementation-report",
                str(malformed_mode_implementation_path),
                "--report",
                str(malformed_mode_bundle_path),
            ]
        )
        if "Traceback" in malformed_mode_bundle.stderr:
            raise AssertionError("malformed artifact_mode caused verify-bundle traceback")
        assert_strict_json_file(malformed_mode_bundle_path)
        assert_bundle_check(malformed_mode_bundle_path, "sut_results.artifact_mode", False)

        malformed_check_sut = json.loads(
            (ROOT / "examples" / "conformance" / "sut-results-pass.example.json").read_text()
        )
        malformed_check_sut["results"][0]["checks"][0]["name"] = []
        malformed_check_sut_path = tmp_dir / "sut-results-malformed-check-name.json"
        malformed_check_report_path = tmp_dir / "compare-report-malformed-check-name.json"
        malformed_check_sut_path.write_text(
            json.dumps(malformed_check_sut, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        malformed_check_result = run_expect_failure(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(malformed_check_sut_path),
                "--report",
                str(malformed_check_report_path),
            ]
        )
        if "Traceback" in malformed_check_result.stderr:
            raise AssertionError("malformed check name caused compare traceback")
        assert_strict_json_file(malformed_check_report_path)
        assert_report_error_contains(malformed_check_report_path, "checks[0].name: expected non-empty string")

        negative_linkage_dir = tmp_dir / "negative-linkage"
        negative_linkage_dir.mkdir()
        negative_linkage_sut = negative_linkage_dir / "sut-results.json"
        negative_linkage_report = negative_linkage_dir / "compare-report.json"
        write_sut_result_with_generated_linkage_case(
            negative_linkage_sut,
            "post-execution-runtime-mismatch",
        )
        run(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(negative_linkage_sut),
                "--report",
                str(negative_linkage_report),
            ]
        )
        broken_link_results = json.loads(negative_linkage_sut.read_text(encoding="utf-8"))
        broken_link_entry = next(
            result
            for result in broken_link_results["results"]
            if result["case_id"] == "post-execution-runtime-mismatch"
        )
        broken_post_path = negative_linkage_dir / "generated-post-execution-runtime-mismatch-post-execution.json"
        broken_post = json.loads(broken_post_path.read_text(encoding="utf-8"))
        broken_post["admission"]["receipt_id"] = "admrec-unrelated"
        broken_post["admission"]["uri"] = "https://independent.example/vate/admission/unrelated"
        broken_post["admission"]["digest"]["value"] = "0" * 64
        broken_post_path.write_text(
            json.dumps(broken_post, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        broken_link_entry["generated_artifacts"]["post_execution_receipt"]["digest"]["value"] = (
            hashlib.sha256(broken_post_path.read_bytes()).hexdigest()
        )
        broken_link_sut = negative_linkage_dir / "sut-results-broken-admission-link.json"
        broken_link_sut.write_text(
            json.dumps(broken_link_results, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        broken_link_report = negative_linkage_dir / "compare-report-broken-admission-link.json"
        run_expect_failure(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(broken_link_sut),
                "--report",
                str(broken_link_report),
            ]
        )
        assert_report_error_contains(broken_link_report, "generated_artifacts.linkage.digest_match")
        assert_report_error_contains(broken_link_report, "generated_artifacts.linkage.receipt_id_match")
        assert_report_error_contains(broken_link_report, "generated_artifacts.linkage.uri_match")

        shape_dir = tmp_dir / "invalid-generated-shape"
        shape_dir.mkdir()
        invalid_shape_sut = shape_dir / "sut-results.json"
        write_sut_result_with_generated_receipts(invalid_shape_sut, tamper_allow_outcome=False)
        invalid_shape_receipt_path = shape_dir / "generated-admission-allow.json"
        invalid_shape_receipt = json.loads(invalid_shape_receipt_path.read_text(encoding="utf-8"))
        invalid_shape_receipt["verifier"] = {}
        invalid_shape_receipt["decision"]["reason_visibility"] = "secret-ish"
        invalid_shape_receipt["decision"]["reason_withheld"] = "yes"
        invalid_shape_receipt_path.write_text(
            json.dumps(invalid_shape_receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        invalid_shape_results = json.loads(invalid_shape_sut.read_text(encoding="utf-8"))
        invalid_shape_entry = next(
            result
            for result in invalid_shape_results["results"]
            if result["case_id"] == "allow-valid-admission"
        )
        invalid_shape_entry["generated_artifacts"]["admission_receipt"]["digest"]["value"] = (
            hashlib.sha256(invalid_shape_receipt_path.read_bytes()).hexdigest()
        )
        invalid_shape_sut.write_text(
            json.dumps(invalid_shape_results, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        invalid_shape_report = shape_dir / "compare-report.json"
        run_expect_failure(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(invalid_shape_sut),
                "--report",
                str(invalid_shape_report),
            ]
        )
        assert_report_error_contains(invalid_shape_report, "generated_artifacts.admission_receipt.verifier.id")
        assert_report_error_contains(
            invalid_shape_report,
            "generated_artifacts.admission_receipt.decision.reason_visibility",
        )
        assert_report_error_contains(
            invalid_shape_report,
            "generated_artifacts.admission_receipt.decision.reason_withheld",
        )

        malformed_decision_dir = tmp_dir / "malformed-generated-decision"
        malformed_decision_dir.mkdir()
        malformed_decision_sut = malformed_decision_dir / "sut-results.json"
        write_sut_result_with_generated_receipts(malformed_decision_sut, tamper_allow_outcome=False)
        malformed_decision_receipt_path = malformed_decision_dir / "generated-admission-allow.json"
        malformed_decision_receipt = json.loads(
            malformed_decision_receipt_path.read_text(encoding="utf-8")
        )
        malformed_decision_receipt["decision"] = "allow"
        malformed_decision_receipt_path.write_text(
            json.dumps(malformed_decision_receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        malformed_decision_results = json.loads(malformed_decision_sut.read_text(encoding="utf-8"))
        malformed_decision_entry = next(
            result
            for result in malformed_decision_results["results"]
            if result["case_id"] == "allow-valid-admission"
        )
        malformed_decision_entry["generated_artifacts"]["admission_receipt"]["digest"]["value"] = (
            hashlib.sha256(malformed_decision_receipt_path.read_bytes()).hexdigest()
        )
        malformed_decision_sut.write_text(
            json.dumps(malformed_decision_results, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        malformed_decision_report = malformed_decision_dir / "compare-report.json"
        run_expect_failure(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(malformed_decision_sut),
                "--report",
                str(malformed_decision_report),
            ]
        )
        assert_report_error_contains(
            malformed_decision_report,
            "generated_artifacts.admission_receipt.decision: expected object",
        )

        extra_artifact_dir = tmp_dir / "extra-generated-artifact"
        extra_artifact_dir.mkdir()
        extra_artifact_sut = extra_artifact_dir / "sut-results.json"
        write_sut_result_with_generated_receipts(extra_artifact_sut, tamper_allow_outcome=False)
        extra_artifact_results = json.loads(extra_artifact_sut.read_text(encoding="utf-8"))
        extra_artifact_entry = next(
            result
            for result in extra_artifact_results["results"]
            if result["case_id"] == "allow-valid-admission"
        )
        extra_artifact_entry["generated_artifacts"]["post_execution_receipt"] = {
            "uri": "https://independent.example/vate/nonexistent.json",
            "local_path": "nonexistent.json",
            "media_type": "application/vate-post-execution-receipt+json",
            "digest": {"alg": "sha-256", "value": "0" * 64},
        }
        extra_artifact_sut.write_text(
            json.dumps(extra_artifact_results, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        extra_artifact_report = extra_artifact_dir / "compare-report.json"
        run_expect_failure(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(extra_artifact_sut),
                "--report",
                str(extra_artifact_report),
            ]
        )
        assert_report_error_contains(
            extra_artifact_report,
            "generated_artifacts.post_execution_receipt: not applicable",
        )

        downgrade_results = json.loads(
            (ROOT / "examples" / "conformance" / "sut-results-pass.example.json").read_text()
        )
        downgrade_results["artifact_mode"] = "generated-receipts"
        for result in downgrade_results["results"]:
            result["artifact_mode"] = "corpus-fixture-validation"
        downgrade_sut = tmp_dir / "sut-results-generated-default-downgrade.json"
        downgrade_sut.write_text(
            json.dumps(downgrade_results, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        downgrade_report = tmp_dir / "compare-report-generated-default-downgrade.json"
        run_expect_failure(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(downgrade_sut),
                "--report",
                str(downgrade_report),
            ]
        )
        assert_report_error_contains(
            downgrade_report,
            "a generated-receipts default cannot be downgraded per case",
        )

        traversal_root = tmp_dir / "generated-path-boundary"
        traversal_sut_dir = traversal_root / "submission"
        traversal_sut_dir.mkdir(parents=True)
        traversal_sut = traversal_sut_dir / "sut-results.json"
        write_sut_result_with_generated_receipts(traversal_sut, tamper_allow_outcome=False)
        outside_receipt_path = traversal_root / "outside-receipt.json"
        outside_receipt = json.loads(
            (traversal_sut_dir / "generated-admission-allow.json").read_text(encoding="utf-8")
        )
        outside_receipt["receipt_id"] = "SENSITIVE-CANARY-MUST-NOT-BE-READ"
        outside_receipt_path.write_text(
            json.dumps(outside_receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        traversal_results = json.loads(traversal_sut.read_text(encoding="utf-8"))
        traversal_entry = next(
            result
            for result in traversal_results["results"]
            if result["case_id"] == "allow-valid-admission"
        )
        traversal_ref = traversal_entry["generated_artifacts"]["admission_receipt"]
        traversal_ref["local_path"] = "../outside-receipt.json"
        traversal_ref["digest"]["value"] = hashlib.sha256(outside_receipt_path.read_bytes()).hexdigest()
        traversal_sut.write_text(
            json.dumps(traversal_results, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        traversal_report = traversal_sut_dir / "compare-report.json"
        run_expect_failure(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(traversal_sut),
                "--report",
                str(traversal_report),
            ]
        )
        assert_report_error_contains(traversal_report, "parent traversal is not allowed")
        if "SENSITIVE-CANARY-MUST-NOT-BE-READ" in traversal_report.read_text(encoding="utf-8"):
            raise AssertionError("generated artifact path rejection leaked data from outside the submission root")

        wrong_media_results = json.loads(generated_sut_results.read_text(encoding="utf-8"))
        wrong_media_entry = next(
            result
            for result in wrong_media_results["results"]
            if result["case_id"] == "allow-valid-admission"
        )
        wrong_media_entry["generated_artifacts"]["admission_receipt"]["media_type"] = "application/json"
        wrong_media_sut_results = tmp_dir / "sut-results-generated-receipts-wrong-media.json"
        wrong_media_sut_results.write_text(
            json.dumps(wrong_media_results, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        wrong_media_report = tmp_dir / "vate-sut-generated-receipts-wrong-media-report.json"
        run_expect_failure(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(wrong_media_sut_results),
                "--report",
                str(wrong_media_report),
            ]
        )
        assert_report_error_contains(
            wrong_media_report,
            "generated_artifacts.admission_receipt.media_type",
        )

        generated_allow_path = tmp_dir / "generated-admission-allow.json"
        generated_allow = json.loads(generated_allow_path.read_text(encoding="utf-8"))
        generated_allow["decision"]["human_readable_summary"] = "Changed after the result digest was recorded."
        generated_allow_path.write_text(
            json.dumps(generated_allow, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        digest_tampered_report = tmp_dir / "vate-sut-generated-receipts-digest-tampered-report.json"
        run_expect_failure(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(generated_sut_results),
                "--report",
                str(digest_tampered_report),
            ]
        )
        assert_report_error_contains(
            digest_tampered_report,
            "generated_artifacts.admission_receipt.digest.value",
        )
        digest_tampered_bundle_report = tmp_dir / "vate-sut-generated-receipts-digest-tampered-bundle.json"
        run_expect_failure(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "verify-bundle",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(generated_sut_results),
                "--conformance-report",
                str(generated_compare_report),
                "--implementation-report",
                str(generated_implementation_report),
                "--report",
                str(digest_tampered_bundle_report),
            ]
        )
        assert_bundle_check(
            digest_tampered_bundle_report,
            "sut_results.generated_artifacts.allow-valid-admission",
            False,
        )

        write_sut_result_with_generated_receipts(
            generated_sut_results,
            tamper_allow_outcome=False,
        )
        generated_post_path = tmp_dir / "generated-post-execution-linkage.json"
        generated_post = json.loads(generated_post_path.read_text(encoding="utf-8"))
        generated_post["admission"]["digest"]["value"] = "0" * 64
        generated_post_path.write_text(
            json.dumps(generated_post, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        linkage_tampered_results = json.loads(generated_sut_results.read_text(encoding="utf-8"))
        linkage_entry = next(
            result
            for result in linkage_tampered_results["results"]
            if result["case_id"] == "post-execution-linkage-success"
        )
        linkage_entry["generated_artifacts"]["post_execution_receipt"]["digest"]["value"] = hashlib.sha256(
            generated_post_path.read_bytes()
        ).hexdigest()
        linkage_tampered_sut_results = tmp_dir / "sut-results-generated-receipts-linkage-tampered.json"
        linkage_tampered_sut_results.write_text(
            json.dumps(linkage_tampered_results, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        linkage_tampered_report = tmp_dir / "vate-sut-generated-receipts-linkage-tampered-report.json"
        run_expect_failure(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(linkage_tampered_sut_results),
                "--report",
                str(linkage_tampered_report),
            ]
        )
        assert_report_error_contains(
            linkage_tampered_report,
            "generated_artifacts.linkage.reason_codes",
        )

        tampered_generated_sut_results = tmp_dir / "sut-results-generated-receipts-tampered.json"
        tampered_generated_report = tmp_dir / "vate-sut-generated-receipts-tampered-report.json"
        write_sut_result_with_generated_receipts(
            tampered_generated_sut_results,
            tamper_allow_outcome=True,
        )
        run_expect_failure(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(tampered_generated_sut_results),
                "--report",
                str(tampered_generated_report),
            ]
        )
        assert_report_error_contains(
            tampered_generated_report,
            "generated_artifacts.admission_receipt.semantics.decision.outcome",
        )
        missing_jose_proofs = tmp_dir / "sut-results-missing-jose-proof-artifacts.json"
        write_sut_result_without_jose_proof_artifacts(missing_jose_proofs)
        run_expect_failure(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(missing_jose_proofs),
                "--report",
                str(tmp_dir / "vate-sut-missing-jose-proof-artifacts-report.json"),
            ]
        )
        missing_context_bindings = tmp_dir / "sut-results-missing-context-bindings.json"
        write_sut_result_without_context_bindings(missing_context_bindings)
        run_expect_failure(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "compare",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(missing_context_bindings),
                "--report",
                str(tmp_dir / "vate-sut-missing-context-bindings-report.json"),
            ]
        )
        for conflicting_first, order_label in (
            (False, "correct-then-conflicting"),
            (True, "conflicting-then-correct"),
        ):
            duplicate_bindings = tmp_dir / f"sut-results-duplicate-context-binding-{order_label}.json"
            duplicate_report = tmp_dir / f"vate-sut-duplicate-context-binding-{order_label}-report.json"
            write_sut_result_with_conflicting_duplicate_context_binding(
                duplicate_bindings,
                conflicting_first=conflicting_first,
            )
            run_expect_failure(
                [
                    sys.executable,
                    str(VATE_CONFORMANCE),
                    "compare",
                    "--corpus-root",
                    str(ROOT / "conformance" / "al2-vate-v0.3"),
                    "--sut-results",
                    str(duplicate_bindings),
                    "--report",
                    str(duplicate_report),
                ]
            )
            assert_report_error_contains(duplicate_report, "duplicate logical binding key")
        for artifact_field in ("verification_context", "proof_artifacts"):
            for conflicting_first, order_label in (
                (False, "correct-then-conflicting"),
                (True, "conflicting-then-correct"),
            ):
                duplicate_artifacts = tmp_dir / f"sut-results-duplicate-{artifact_field}-{order_label}.json"
                duplicate_report = tmp_dir / f"vate-sut-duplicate-{artifact_field}-{order_label}-report.json"
                write_sut_result_with_conflicting_duplicate_artifact_entry(
                    duplicate_artifacts,
                    artifact_field=artifact_field,
                    conflicting_first=conflicting_first,
                )
                run_expect_failure(
                    [
                        sys.executable,
                        str(VATE_CONFORMANCE),
                        "compare",
                        "--corpus-root",
                        str(ROOT / "conformance" / "al2-vate-v0.3"),
                        "--sut-results",
                        str(duplicate_artifacts),
                        "--report",
                        str(duplicate_report),
                    ]
                )
                assert_report_error_contains(
                    duplicate_report,
                    f"artifacts.{artifact_field}[1]: duplicate logical artifact key",
                )
        run(
            [
                sys.executable,
                str(VATE_CONFORMANCE),
                "verify-bundle",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-vate-v0.3"),
                "--sut-results",
                str(ROOT / "examples" / "conformance" / "sut-results-pass.example.json"),
                "--conformance-report",
                str(tmp_dir / "vate-sut-compare-report.json"),
                "--implementation-report",
                str(tmp_dir / "vate-sut-implementation-report.json"),
                "--report",
                str(tmp_dir / "vate-sut-bundle-verification.json"),
            ]
        )
        run([sys.executable, str(VATE_CORE), "self-test"])
        subprocess.run(
            [sys.executable, str(A2A_ADAPTER), "run-demo"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        print("trust envelope draft repo sanity check: ok")
        return 0
    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
