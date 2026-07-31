#!/usr/bin/env python3
"""Repository sanity checker for the public trust envelope draft repository.

This script intentionally stays dependency-free and fast. It validates obvious
shape mismatches, runs the educational demo, and checks expected failure cases.
It is not a full JSON Schema validator. For strict schema validation, use
scripts/check_repo_strict.py when jsonschema is available locally.
"""

from __future__ import annotations

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
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "reference" / "minimal-al2-demo" / "trust_envelope_demo.py"
HTTP_DEMO = ROOT / "reference" / "http-verifier-demo" / "http_verifier_demo.py"
VATE_CONFORMANCE = ROOT / "scripts" / "vate_conformance.py"
VATE_CORE = ROOT / "reference" / "vate-verifier-core" / "vate_verifier_core.py"
A2A_ADAPTER = ROOT / "reference" / "a2a-metadata-adapter-demo" / "a2a_metadata_adapter_demo.py"
EVIDENCE_VOCABULARY = ROOT / "registries" / "evidence-vocabulary.v0.3.json"
ARTIFACT_VERSIONING_DOC = ROOT / "docs" / "conformance" / "artifact-versioning.md"
JOSE_PROFILE_NOTES_DOC = ROOT / "docs" / "profiles" / "vate-jose-proof-profile-notes-2026-07.md"
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
        "july 2026 target interop artifact line",
        "corpus snapshot",
        "manifest digest",
        "not the publication date",
        "not a production-readiness claim",
        "do not rename",
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


def main() -> int:
    validate_examples()
    check_evidence_vocabulary_registry()
    check_artifact_versioning_docs()
    check_post_execution_linkage_kind_coverage()
    check_transport_bound_fixture_coverage()
    check_status_freshness_boundary_coverage()
    check_replay_boundary_coverage()
    check_p1_5_fixture_coverage()
    check_p2_public_artifact_boundary()
    check_vate_conformance_display_paths_are_portable()
    check_linkage_missing_artifacts_fail_closed()
    check_case_artifact_readers_fail_closed()
    check_corpus_manifest_non_file_fails_closed()
    check_generated_artifact_utf8_boundary()
    check_a2a_adapter_local_uri_boundary()
    check_a2a_adapter_malformed_metadata_fail_closed()
    check_al2_corpus_docs_synced()
    run([sys.executable, "-m", "py_compile", str(DEMO)])
    run([sys.executable, "-m", "py_compile", str(HTTP_DEMO)])
    run([sys.executable, "-m", "py_compile", str(VATE_CONFORMANCE)])
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
        if generated_report.get("summary") != {"total": 72, "passed": 72, "failed": 0, "skipped": 0}:
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
            "corpus-fixture-validation": 70,
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
