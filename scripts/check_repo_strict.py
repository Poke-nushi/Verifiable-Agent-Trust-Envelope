#!/usr/bin/env python3
"""Strict JSON Schema validation for the public trust envelope draft repository.

This script is optional. It requires the third-party ``jsonschema`` package in
the local Python environment and validates the example payloads against their
schemas using Draft 2020-12.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JSON_ONLY_FILES = [
    "reference/a2a-metadata-adapter-demo/agent-card-extension.example.json",
    "examples/a2a/agent-card-v1-vate-extension.example.json",
]
EXAMPLE_PAIRS = [
    ("examples/passport-credential.example.json", "schemas/passport-credential.schema.json"),
    ("examples/runtime-proof.example.json", "schemas/runtime-proof.schema.json"),
    ("examples/mission-permit.example.json", "schemas/mission-permit.schema.json"),
    ("examples/execution-receipt.example.json", "schemas/execution-receipt.schema.json"),
    ("examples/artifact-reference.example.json", "schemas/artifact-reference.schema.json"),
    ("examples/evidence-reference.example.json", "schemas/evidence-reference.schema.json"),
    ("examples/admission-request.example.json", "schemas/admission-request.schema.json"),
    ("examples/transport/mcp-oauth-admission-request.example.json", "schemas/admission-request.schema.json"),
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
        "conformance/al2-vate-v0.2/cases/allow-valid-admission.json",
        "conformance/al2-vate-v0.2/conformance-case.schema.json",
    ),
    (
        "conformance/al2-vate-v0.2/cases/attenuate-max-amount.json",
        "conformance/al2-vate-v0.2/conformance-case.schema.json",
    ),
    (
        "conformance/al2-vate-v0.2/cases/deny-expired-permit.json",
        "conformance/al2-vate-v0.2/conformance-case.schema.json",
    ),
    (
        "conformance/al2-vate-v0.2/cases/deny-audience-mismatch.json",
        "conformance/al2-vate-v0.2/conformance-case.schema.json",
    ),
    (
        "conformance/al2-vate-v0.2/cases/post-execution-linkage-success.json",
        "conformance/al2-vate-v0.2/conformance-case.schema.json",
    ),
    ("examples/trust-bundle.example.json", "schemas/trust-bundle.schema.json"),
    ("examples/conformance-report.example.json", "schemas/conformance-report.schema.json"),
    ("examples/implementation-report.example.json", "schemas/implementation-report.schema.json"),
    ("examples/report-bundle-verification.example.json", "schemas/report-bundle-verification.schema.json"),
    ("examples/conformance/sut-results-pass.example.json", "schemas/sut-result.schema.json"),
    ("conformance/al2-vate-v0.2/corpus.json", "schemas/conformance-corpus.schema.json"),
    ("examples/policies/merchant-purchase-al2-policy-snapshot.example.json", "schemas/policy-snapshot.schema.json"),
    ("examples/policies/al2-repo-merge-policy-snapshot.example.json", "schemas/policy-snapshot.schema.json"),
]


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
        (str(path.relative_to(ROOT)), "conformance/al2-vate-v0.2/conformance-case.schema.json")
        for path in sorted((ROOT / "conformance" / "al2-vate-v0.2" / "cases").glob("*.json"))
    )
    return sorted(set(pairs))


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def minimal_linkage_case(linkage_checks: list[dict]) -> dict:
    return {
        "version": "vate-conformance-0.2",
        "profile": "VATE-AL2-Verifier-Admission-v0.2",
        "case_id": "negative-schema-linkage-contract",
        "title": "Negative schema linkage contract",
        "category": "linkage",
        "purpose": "Strict schema validation should reject incomplete or inconsistent linkage checks.",
        "artifacts": {},
        "expected": {
            "post_execution_outcome": "failed",
            "should_execute": False,
            "reason_codes": ["POST_EXEC_ADMISSION_DIGEST_MISMATCH"],
            "checks": [],
        },
        "linkage_checks": linkage_checks,
    }


def iter_negative_schema_cases() -> list[tuple[str, dict, str]]:
    hex_digest = "0" * 64
    empty_summary = {"total": 0, "passed": 0, "failed": 0, "skipped": 0}
    return [
        (
            "incomplete linkage check",
            minimal_linkage_case(
                [
                    {
                        "kind": "admission_digest",
                        "reason_code": "POST_EXEC_ADMISSION_DIGEST_MISMATCH",
                    }
                ]
            ),
            "conformance/al2-vate-v0.2/conformance-case.schema.json",
        ),
        (
            "linkage reason code does not match kind",
            minimal_linkage_case(
                [
                    {
                        "kind": "runtime",
                        "admission_path": "subject.runtime",
                        "post_execution_path": "execution.runtime",
                        "expect_match": False,
                        "reason_code": "POST_EXEC_TRANSACTION_MISMATCH",
                    }
                ]
            ),
            "conformance/al2-vate-v0.2/conformance-case.schema.json",
        ),
        (
            "unknown policy violation token",
            minimal_linkage_case(
                [
                    {
                        "kind": "policy_violation",
                        "value": "unknown_policy_violation",
                        "expect_present": True,
                        "reason_code": "POST_EXEC_LINKAGE_MISMATCH",
                    }
                ]
            ),
            "conformance/al2-vate-v0.2/conformance-case.schema.json",
        ),
        (
            "conformance report without corpus",
            {
                "version": "vate-conformance-report-2026-07",
                "profile": "VATE-AL2-Verifier-Admission-v0.2",
                "checked_at": "2026-07-01T00:00:00Z",
                "summary": empty_summary,
                "cases": [],
            },
            "schemas/conformance-report.schema.json",
        ),
        (
            "SUT corpus digest is not lowercase sha-256 hex",
            {
                "version": "vate-sut-results-2026-07",
                "profile": "VATE-AL2-Verifier-Admission-v0.2",
                "generated_at": "2026-07-01T00:00:00Z",
                "implementation": {"name": "x", "type": "x", "version": "x", "language": "x"},
                "corpus": {
                    "profile": "VATE-AL2-Verifier-Admission-v0.2",
                    "digest": {"alg": "sha-256", "value": "not-a-digest"},
                },
                "results": [],
            },
            "schemas/sut-result.schema.json",
        ),
        (
            "implementation report without corpus manifest",
            {
                "version": "vate-implementation-report-2026-07",
                "profile": "VATE-AL2-Verifier-Admission-v0.2",
                "generated_at": "2026-07-01T00:00:00Z",
                "status": "pass",
                "implementation": {"name": "x", "type": "x", "version": "x", "language": "x"},
                "corpus": {
                    "name": "x",
                    "root": "x",
                    "case_count": 0,
                    "artifact_count": 0,
                    "digest": {"alg": "sha-256", "value": hex_digest},
                },
                "conformance_report": {
                    "uri": "x",
                    "media_type": "application/vate-conformance-report+json",
                    "digest": {"alg": "sha-256", "value": hex_digest},
                },
                "summary": empty_summary,
                "case_results": [],
            },
            "schemas/implementation-report.schema.json",
        ),
        (
            "implementation report case result without should_execute projection",
            {
                "version": "vate-implementation-report-2026-07",
                "profile": "VATE-AL2-Verifier-Admission-v0.2",
                "generated_at": "2026-07-01T00:00:00Z",
                "status": "pass",
                "implementation": {"name": "x", "type": "x", "version": "x", "language": "x"},
                "corpus": {
                    "name": "x",
                    "root": "x",
                    "case_count": 1,
                    "artifact_count": 1,
                    "digest": {"alg": "sha-256", "value": hex_digest},
                    "manifest": [{"path": "x", "sha256": hex_digest}],
                },
                "conformance_report": {
                    "uri": "x",
                    "media_type": "application/vate-conformance-report+json",
                    "digest": {"alg": "sha-256", "value": hex_digest},
                    "digest_basis": "json-sorted-no-whitespace",
                },
                "summary": {"total": 1, "passed": 1, "failed": 0, "skipped": 0},
                "case_results": [
                    {
                        "case_id": "x",
                        "expected_outcome": "allow",
                        "actual_outcome": "allow",
                        "pass": True,
                    }
                ],
            },
            "schemas/implementation-report.schema.json",
        ),
        (
            "report bundle verification without status",
            {
                "version": "vate-report-bundle-verification-2026-07",
                "profile": "VATE-AL2-Verifier-Admission-v0.2",
                "checked_at": "2026-07-01T00:00:00Z",
                "summary": {"total": 0, "passed": 0, "failed": 0},
                "artifacts": {
                    "corpus": {
                        "root": "conformance/al2-vate-v0.2",
                        "digest": {"alg": "sha-256", "value": hex_digest},
                        "artifact_count": 0,
                    },
                    "conformance_report": {
                        "path": "reports/conformance.json",
                        "digest": {"alg": "sha-256", "value": hex_digest},
                        "digest_basis": "json-sorted-no-whitespace",
                    },
                    "implementation_report": {
                        "path": "reports/implementation.json",
                        "digest": {"alg": "sha-256", "value": hex_digest},
                        "digest_basis": "json-sorted-no-whitespace",
                    },
                },
                "checks": [],
            },
            "schemas/report-bundle-verification.schema.json",
        ),
    ]


def main() -> int:
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise SystemExit(
            "jsonschema is not installed in this environment. "
            "Install it locally if you want strict schema validation."
        ) from exc

    for example_rel, schema_rel in iter_example_pairs():
        example_path = ROOT / example_rel
        schema_path = ROOT / schema_rel
        example = load_json(example_path)
        schema = load_json(schema_path)
        validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
        errors = sorted(validator.iter_errors(example), key=lambda item: list(item.path))
        if errors:
            first = errors[0]
            path = ".".join(str(part) for part in first.path) or "root"
            raise SystemExit(f"{example_rel} failed strict validation at {path}: {first.message}")

    for json_rel in JSON_ONLY_FILES:
        load_json(ROOT / json_rel)

    for label, example, schema_rel in iter_negative_schema_cases():
        schema = load_json(ROOT / schema_rel)
        validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
        errors = sorted(validator.iter_errors(example), key=lambda item: list(item.path))
        if not errors:
            raise SystemExit(f"{label} unexpectedly passed strict validation against {schema_rel}")

    print("app draft strict schema validation: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
