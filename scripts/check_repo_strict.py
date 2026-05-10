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
    ("registries/evidence-vocabulary.v0.3.json", "schemas/evidence-vocabulary.schema.json"),
    ("examples/passport-credential.example.json", "schemas/passport-credential.schema.json"),
    ("examples/runtime-proof.example.json", "schemas/runtime-proof.schema.json"),
    ("examples/mission-permit.example.json", "schemas/mission-permit.schema.json"),
    ("examples/execution-receipt.example.json", "schemas/execution-receipt.schema.json"),
    ("examples/artifact-reference.example.json", "schemas/artifact-reference.schema.json"),
    ("examples/evidence-reference.example.json", "schemas/evidence-reference.schema.json"),
    ("examples/admission-request.example.json", "schemas/admission-request.schema.json"),
    ("examples/transport/mcp-oauth-admission-request.example.json", "schemas/admission-request.schema.json"),
    ("examples/transport/mcp-oauth-overscope-admission-request.example.json", "schemas/admission-request.schema.json"),
    ("examples/transport/mcp-oauth-upstream-denied-admission-request.example.json", "schemas/admission-request.schema.json"),
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
    ("examples/trust-bundle.example.json", "schemas/trust-bundle.schema.json"),
    ("examples/conformance-report.example.json", "schemas/conformance-report.schema.json"),
    ("examples/implementation-report.example.json", "schemas/implementation-report.schema.json"),
    ("examples/report-bundle-verification.example.json", "schemas/report-bundle-verification.schema.json"),
    ("examples/conformance/sut-results-pass.example.json", "schemas/sut-result.schema.json"),
    ("conformance/al2-vate-v0.3/corpus.json", "schemas/conformance-corpus.schema.json"),
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
        (str(path.relative_to(ROOT)), "conformance/al2-vate-v0.3/conformance-case.schema.json")
        for path in sorted((ROOT / "conformance" / "al2-vate-v0.3" / "cases").glob("*.json"))
    )
    return sorted(set(pairs))


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def minimal_linkage_case(linkage_checks: list[dict]) -> dict:
    return {
        "version": "vate-conformance-0.3",
        "profile": "VATE-AL2-Verifier-Admission-v0.3",
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


def minimal_al2_context_case(al2_context_checks: list[dict]) -> dict:
    return {
        "version": "vate-conformance-0.3",
        "profile": "VATE-AL2-Verifier-Admission-v0.3",
        "case_id": "negative-schema-al2-context-contract",
        "title": "Negative schema AL2 context contract",
        "category": "positive",
        "purpose": "Strict schema validation should reject incomplete AL2 context checks.",
        "artifacts": {},
        "expected": {
            "admission_decision": "allow",
            "should_execute": True,
            "reason_codes": ["EVIDENCE_VERIFIED", "POLICY_MATCH"],
            "checks": [],
        },
        "al2_context_checks": al2_context_checks,
    }


def iter_negative_schema_cases() -> list[tuple[str, dict, str]]:
    hex_digest = "0" * 64
    empty_summary = {"total": 0, "passed": 0, "failed": 0, "skipped": 0}
    minimal_admission_request = {
        "version": "vate-0.3",
        "profile": "VATE-AL2-Verifier-Admission-v0.3",
        "request_id": "areq-negative-hash-001",
        "transaction_id": "txn-negative-hash-001",
        "issued_at": "2026-07-01T00:00:00Z",
        "expires_at": "2026-07-01T00:10:00Z",
        "action": "commerce.purchase",
        "target": {"resource": "https://merchant.example/checkout", "audience": "https://verifier.example/a2a"},
        "actor": "did:web:agent.example",
        "principal": "did:web:user.example",
        "runtime": "spiffe://agent.example/workload/purchase-agent",
        "audience": "https://verifier.example/a2a",
        "input_hash": "sha-256:" + hex_digest,
        "evidence_refs": [
            {
                "type": "payment_authority",
                "uri": "https://wallet.example/payment-authorities/negative",
                "media_type": "application/json",
                "digest": {"alg": "sha-256", "value": hex_digest},
            }
        ],
    }
    minimal_admission_receipt = {
        "version": "vate-0.3",
        "profile": "VATE-AL2-Verifier-Admission-v0.3",
        "receipt_type": "admission",
        "receipt_id": "admrec-negative-hash-001",
        "issued_at": "2026-07-01T00:00:00Z",
        "expires_at": "2026-07-01T00:10:00Z",
        "verifier": {"id": "did:web:verifier.example"},
        "request": {
            "request_id": "areq-negative-hash-001",
            "transaction_id": "txn-negative-hash-001",
            "action": "commerce.purchase",
            "input_hash": "sha-256:" + hex_digest,
        },
        "subject": {
            "principal": "did:web:user.example",
            "actor": "did:web:agent.example",
            "runtime": "spiffe://agent.example/workload/purchase-agent",
        },
        "evidence": [
            {
                "type": "payment_authority",
                "uri": "https://wallet.example/payment-authorities/negative",
                "digest": {"alg": "sha-256", "value": hex_digest},
                "verification": {
                    "result": "verified",
                    "checked_at": "2026-07-01T00:00:01Z",
                    "method": "negative-test",
                },
            }
        ],
        "policy": {
            "policy_id": "merchant-purchase-al2",
            "policy_version": "2026-07-01.1",
            "policy_ref": "https://verifier.example/policies/merchant-purchase-al2/2026-07-01.1",
        },
        "decision": {"outcome": "allow", "reason_codes": ["EVIDENCE_VERIFIED", "POLICY_MATCH"]},
    }
    minimal_post_execution_receipt = {
        "version": "vate-0.3",
        "profile": "VATE-AL2-Verifier-Admission-v0.3",
        "receipt_type": "post_execution",
        "receipt_id": "postrec-negative-hash-001",
        "issued_at": "2026-07-01T00:02:00Z",
        "issuer": {"id": "did:web:agent.example", "role": "runtime"},
        "admission": {
            "receipt_id": "admrec-negative-hash-001",
            "uri": "https://verifier.example/vate/admission-receipts/admrec-negative-hash-001",
            "digest": {"alg": "sha-256", "value": hex_digest},
            "decision": "allow",
        },
        "execution": {
            "transaction_id": "txn-negative-hash-001",
            "started_at": "2026-07-01T00:01:00Z",
            "finished_at": "2026-07-01T00:02:00Z",
            "effective_request_hash": "sha-256:" + hex_digest,
            "runtime": "spiffe://agent.example/workload/purchase-agent",
        },
        "result": {
            "outcome": "success",
            "output_hash": "sha-256:" + hex_digest,
            "side_effects": [],
            "policy_violations": [],
        },
    }
    return [
        (
            "A2A metadata unknown core field",
            {
                "profile": "VATE-AL2-Verifier-Admission-v0.3",
                "phase": "admission_requested",
                "transaction_id": "txn-negative-a2a-metadata",
                "assurance_level": "AL2",
                "admission_request": {
                    "type": "admission_request",
                    "uri": "https://verifier.example/vate/admission-requests/negative",
                    "media_type": "application/vate-admission-request+json",
                    "digest": {"alg": "sha-256", "value": hex_digest},
                },
                "issuer": "did:web:client.example",
                "issued_at": "2026-07-01T00:00:00Z",
                "unexpected_core_field": True,
            },
            "schemas/a2a-vate-metadata.schema.json",
        ),
        (
            "A2A metadata artifact URI is not absolute URI",
            {
                "profile": "VATE-AL2-Verifier-Admission-v0.3",
                "phase": "admission_requested",
                "transaction_id": "txn-negative-a2a-metadata-uri",
                "assurance_level": "AL2",
                "admission_request": {
                    "type": "admission_request",
                    "uri": "not-a-uri",
                    "media_type": "application/vate-admission-request+json",
                    "digest": {"alg": "sha-256", "value": hex_digest},
                },
                "issuer": "did:web:client.example",
                "issued_at": "2026-07-01T00:00:00Z",
            },
            "schemas/a2a-vate-metadata.schema.json",
        ),
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
            "conformance/al2-vate-v0.3/conformance-case.schema.json",
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
            "conformance/al2-vate-v0.3/conformance-case.schema.json",
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
            "conformance/al2-vate-v0.3/conformance-case.schema.json",
        ),
        (
            "replay context check without explicit expectation",
            minimal_al2_context_case(
                [
                    {
                        "kind": "replay",
                        "artifact": "replay_context",
                    }
                ]
            ),
            "conformance/al2-vate-v0.3/conformance-case.schema.json",
        ),
        (
            "freshness context check without explicit expectation",
            minimal_al2_context_case(
                [
                    {
                        "kind": "freshness",
                        "artifact": "status_context",
                    }
                ]
            ),
            "conformance/al2-vate-v0.3/conformance-case.schema.json",
        ),
        (
            "binding context check without explicit expectation",
            minimal_al2_context_case(
                [
                    {
                        "kind": "binding",
                        "artifact": "runtime_context",
                    }
                ]
            ),
            "conformance/al2-vate-v0.3/conformance-case.schema.json",
        ),
        (
            "conformance report without corpus",
            {
                "version": "vate-conformance-report-2026-07",
                "profile": "VATE-AL2-Verifier-Admission-v0.3",
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
                "profile": "VATE-AL2-Verifier-Admission-v0.3",
                "generated_at": "2026-07-01T00:00:00Z",
                "implementation": {"name": "x", "type": "x", "version": "x", "language": "x"},
                "corpus": {
                    "profile": "VATE-AL2-Verifier-Admission-v0.3",
                    "digest": {"alg": "sha-256", "value": "not-a-digest"},
                },
                "results": [],
            },
            "schemas/sut-result.schema.json",
        ),
        (
            "admission request input_hash is not a profile hash",
            {
                **minimal_admission_request,
                "input_hash": "sha-256:not-a-lowercase-hex-digest",
            },
            "schemas/admission-request.schema.json",
        ),
        (
            "admission request evidence_refs is empty",
            {
                **minimal_admission_request,
                "evidence_refs": [],
            },
            "schemas/admission-request.schema.json",
        ),
        (
            "admission receipt request input_hash is not a profile hash",
            {
                **minimal_admission_receipt,
                "request": {
                    **minimal_admission_receipt["request"],
                    "input_hash": "sha-256:not-a-lowercase-hex-digest",
                },
            },
            "schemas/admission-receipt.schema.json",
        ),
        (
            "admission receipt attenuation hashes are not profile hashes",
            {
                **minimal_admission_receipt,
                "decision": {"outcome": "attenuate", "reason_codes": ["LOCAL_POLICY_MAX_AMOUNT_NARROWED"]},
                "attenuation": {
                    "mode": "narrow",
                    "original_request_hash": "sha-256:not-a-lowercase-hex-digest",
                    "effective_request_hash": "sha-256:" + hex_digest,
                    "changes": [
                        {
                            "op": "replace",
                            "path": "/constraints/max_amount/value",
                            "reason_code": "LOCAL_POLICY_MAX_AMOUNT_NARROWED",
                        }
                    ],
                    "effective_constraints": {"max_amount": {"currency": "USD", "value": "25.00"}},
                    "require_new_permit": False,
                },
            },
            "schemas/admission-receipt.schema.json",
        ),
        (
            "post-execution effective_request_hash is not a profile hash",
            {
                **minimal_post_execution_receipt,
                "execution": {
                    **minimal_post_execution_receipt["execution"],
                    "effective_request_hash": "sha-256:not-a-lowercase-hex-digest",
                },
            },
            "schemas/post-execution-receipt.schema.json",
        ),
        (
            "post-execution output_hash is not a profile hash",
            {
                **minimal_post_execution_receipt,
                "result": {
                    **minimal_post_execution_receipt["result"],
                    "output_hash": "sha-256:not-a-lowercase-hex-digest",
                },
            },
            "schemas/post-execution-receipt.schema.json",
        ),
        (
            "admission request evidence digest is not lowercase sha-256 hex",
            {
                "version": "vate-0.3",
                "profile": "VATE-AL2-Verifier-Admission-v0.3",
                "request_id": "areq-negative-digest-001",
                "transaction_id": "txn-negative-digest-001",
                "issued_at": "2026-07-01T00:00:00Z",
                "expires_at": "2026-07-01T00:10:00Z",
                "action": "commerce.purchase",
                "target": {"resource": "https://merchant.example/checkout", "audience": "https://verifier.example/a2a"},
                "actor": "did:web:agent.example",
                "principal": "did:web:user.example",
                "runtime": "spiffe://agent.example/workload/purchase-agent",
                "audience": "https://verifier.example/a2a",
                "input_hash": "sha-256:" + hex_digest,
                "evidence_refs": [
                    {
                        "type": "payment_authority",
                        "uri": "https://wallet.example/payment-authorities/negative",
                        "media_type": "application/json",
                        "digest": {"alg": "md5", "value": "x"},
                    }
                ],
            },
            "schemas/admission-request.schema.json",
        ),
        (
            "admission receipt evidence digest is not lowercase sha-256 hex",
            {
                "version": "vate-0.3",
                "profile": "VATE-AL2-Verifier-Admission-v0.3",
                "receipt_type": "admission",
                "receipt_id": "admrec-negative-digest-001",
                "issued_at": "2026-07-01T00:00:00Z",
                "expires_at": "2026-07-01T00:10:00Z",
                "verifier": {"id": "did:web:verifier.example"},
                "request": {
                    "request_id": "areq-negative-digest-001",
                    "transaction_id": "txn-negative-digest-001",
                    "action": "commerce.purchase",
                    "input_hash": "sha-256:" + hex_digest,
                },
                "subject": {
                    "principal": "did:web:user.example",
                    "actor": "did:web:agent.example",
                    "runtime": "spiffe://agent.example/workload/purchase-agent",
                },
                "evidence": [
                    {
                        "type": "payment_authority",
                        "uri": "https://wallet.example/payment-authorities/negative",
                        "digest": {"alg": "md5", "value": "x"},
                        "verification": {
                            "result": "verified",
                            "checked_at": "2026-07-01T00:00:01Z",
                            "method": "negative-test",
                        },
                    }
                ],
                "policy": {
                    "policy_id": "merchant-purchase-al2",
                    "policy_version": "2026-07-01.1",
                    "policy_ref": "https://verifier.example/policies/merchant-purchase-al2/2026-07-01.1",
                    "policy_snapshot": {
                        "uri": "https://verifier.example/policies/merchant-purchase-al2/2026-07-01.1/snapshot",
                        "media_type": "application/json",
                        "digest": {"alg": "sha-256", "value": hex_digest},
                    },
                },
                "decision": {"outcome": "allow", "reason_codes": ["EVIDENCE_VERIFIED", "POLICY_MATCH"]},
            },
            "schemas/admission-receipt.schema.json",
        ),
        (
            "post-execution admission digest is not lowercase sha-256 hex",
            {
                "version": "vate-0.3",
                "profile": "VATE-AL2-Verifier-Admission-v0.3",
                "receipt_type": "post_execution",
                "receipt_id": "postrec-negative-digest-001",
                "issued_at": "2026-07-01T00:02:00Z",
                "issuer": {"id": "did:web:agent.example", "role": "runtime"},
                "admission": {
                    "receipt_id": "admrec-negative-digest-001",
                    "uri": "https://verifier.example/vate/admission-receipts/admrec-negative-digest-001",
                    "digest": {"alg": "md5", "value": "x"},
                    "decision": "allow",
                },
                "execution": {
                    "transaction_id": "txn-negative-digest-001",
                    "started_at": "2026-07-01T00:01:00Z",
                    "finished_at": "2026-07-01T00:02:00Z",
                    "effective_request_hash": "sha-256:" + hex_digest,
                    "runtime": "spiffe://agent.example/workload/purchase-agent",
                },
                "result": {
                    "outcome": "success",
                    "output_hash": "sha-256:" + hex_digest,
                    "side_effects": [],
                    "policy_violations": [],
                },
            },
            "schemas/post-execution-receipt.schema.json",
        ),
        (
            "implementation report without corpus manifest",
            {
                "version": "vate-implementation-report-2026-07",
                "profile": "VATE-AL2-Verifier-Admission-v0.3",
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
                "profile": "VATE-AL2-Verifier-Admission-v0.3",
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
                "profile": "VATE-AL2-Verifier-Admission-v0.3",
                "checked_at": "2026-07-01T00:00:00Z",
                "summary": {"total": 0, "passed": 0, "failed": 0},
                "artifacts": {
                    "corpus": {
                        "root": "conformance/al2-vate-v0.3",
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
