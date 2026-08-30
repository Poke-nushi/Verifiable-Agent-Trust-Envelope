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

from vate_conformance import try_parse_time

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
    ("examples/external-sut-template/starter-sut-result.template.json", "schemas/sut-result.schema.json"),
    ("examples/external-sut-pulse-starter/pulse-sut-result.template.json", "schemas/sut-result.schema.json"),
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
    pairs.extend(
        (str(path.relative_to(ROOT)), "schemas/status-context.schema.json")
        for path in sorted((ROOT / "conformance" / "al2-vate-v0.3" / "fixtures").glob("status-*-context.json"))
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
    minimal_conformance_result = {
        "case_id": "x",
        "category": "positive",
        "expected_outcome": "allow",
        "actual_outcome": "allow",
        "expected_should_execute": True,
        "actual_should_execute": True,
        "expected_primary_reason_code": "EVIDENCE_VERIFIED",
        "actual_primary_reason_code": "EVIDENCE_VERIFIED",
        "expected_reason_codes": ["EVIDENCE_VERIFIED", "POLICY_MATCH"],
        "actual_reason_codes": ["EVIDENCE_VERIFIED", "POLICY_MATCH"],
        "pass": True,
        "failures": [],
    }
    minimal_conformance_corpus = {
        "name": "al2-vate-v0.3",
        "root": "conformance/al2-vate-v0.3",
        "artifact_count": 1,
        "digest": {"alg": "sha-256", "value": hex_digest},
    }
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
    minimal_attenuation_effect = {
        "version": "app-effect-0.2",
        "mode": "narrow",
        "require_new_permit": False,
        "constraints": {
            "max_amount": {
                "currency": "USD",
                "value": "25.00",
            }
        },
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
            "passing conformance case with recorded failure",
            {
                "version": "vate-conformance-report-2026-07",
                "profile": "VATE-AL2-Verifier-Admission-v0.3",
                "checked_at": "2026-07-01T00:00:00Z",
                "summary": {
                    "total": 1,
                    "passed": 1,
                    "failed": 0,
                    "skipped": 0,
                },
                "corpus": minimal_conformance_corpus,
                "cases": [
                    {
                        **minimal_conformance_result,
                        "failures": ["contradicts pass=true"],
                    }
                ],
            },
            "schemas/conformance-report.schema.json",
        ),
        (
            "failed conformance case without failure detail",
            {
                "version": "vate-conformance-report-2026-07",
                "profile": "VATE-AL2-Verifier-Admission-v0.3",
                "checked_at": "2026-07-01T00:00:00Z",
                "summary": {
                    "total": 1,
                    "passed": 0,
                    "failed": 1,
                    "skipped": 0,
                },
                "corpus": minimal_conformance_corpus,
                "cases": [
                    {
                        **minimal_conformance_result,
                        "pass": False,
                        "failures": [],
                    }
                ],
            },
            "schemas/conformance-report.schema.json",
        ),
        (
            "SUT conformance report case without effective artifact mode",
            {
                "version": "vate-conformance-report-2026-07",
                "profile": "VATE-AL2-Verifier-Admission-v0.3",
                "checked_at": "2026-07-01T00:00:00Z",
                "summary": {"total": 1, "passed": 1, "failed": 0, "skipped": 0},
                "corpus": {
                    "name": "al2-vate-v0.3",
                    "root": "conformance/al2-vate-v0.3",
                    "artifact_count": 1,
                    "digest": {"alg": "sha-256", "value": hex_digest},
                },
                "sut_results": {
                    "path": "sut-results.json",
                    "digest": {"alg": "sha-256", "value": hex_digest},
                    "digest_basis": "json-sorted-no-whitespace",
                    "artifact_mode": "corpus-fixture-validation",
                    "artifact_mode_counts": {
                        "corpus-fixture-validation": 1,
                        "generated-receipts": 0,
                    },
                    "implementation": {},
                },
                "cases": [
                    {
                        "case_id": "x",
                        "category": "positive",
                        "expected_outcome": "allow",
                        "actual_outcome": "allow",
                        "expected_should_execute": True,
                        "actual_should_execute": True,
                        "expected_primary_reason_code": "EVIDENCE_VERIFIED",
                        "actual_primary_reason_code": "EVIDENCE_VERIFIED",
                        "expected_reason_codes": ["EVIDENCE_VERIFIED", "POLICY_MATCH"],
                        "actual_reason_codes": ["EVIDENCE_VERIFIED", "POLICY_MATCH"],
                        "pass": True,
                    }
                ],
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
            "admission receipt rejects attenuation on allow decisions",
            {
                **minimal_admission_receipt,
                "attenuation": {
                    "mode": "narrow",
                    "original_request_hash": "sha-256:" + "1" * 64,
                    "effective_request_hash": "sha-256:" + hex_digest,
                    "changes": [
                        {
                            "op": "replace",
                            "path": "/constraints/max_amount/value",
                            "reason_code": "LOCAL_POLICY_MAX_AMOUNT_NARROWED",
                        }
                    ],
                    "effective_constraints": {
                        "max_amount": {"currency": "USD", "value": "25.00"}
                    },
                    "require_new_permit": False,
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
            "admission receipt attenuation rejects unsupported mode",
            {
                **minimal_admission_receipt,
                "decision": {"outcome": "attenuate", "reason_codes": ["LOCAL_POLICY_MAX_AMOUNT_NARROWED"]},
                "attenuation": {
                    "mode": "unsupported",
                    "original_request_hash": "sha-256:" + "1" * 64,
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
            "admission receipt attenuation rejects legacy emitted aliases",
            {
                **minimal_admission_receipt,
                "decision": {"outcome": "attenuate", "reason_codes": ["LOCAL_POLICY_MAX_AMOUNT_NARROWED"]},
                "attenuation": {
                    "mode": "narrow",
                    "original_request_hash": "sha-256:" + "1" * 64,
                    "effective_request_hash": "sha-256:" + hex_digest,
                    "changes": [
                        {
                            "op": "replace",
                            "path": "/constraints/max_amount_usd",
                            "reason_code": "LOCAL_POLICY_MAX_AMOUNT_NARROWED",
                        }
                    ],
                    "effective_constraints": {
                        "max_amount_usd": 25,
                        "resource": "bucket:public/reports/*",
                    },
                    "require_new_permit": False,
                },
            },
            "schemas/admission-receipt.schema.json",
        ),
        (
            "admission receipt attenuation rejects string approval",
            {
                **minimal_admission_receipt,
                "decision": {"outcome": "attenuate", "reason_codes": ["NEW_PERMIT_REQUIRED"]},
                "attenuation": {
                    "mode": "require_new_permit",
                    "original_request_hash": "sha-256:" + "1" * 64,
                    "effective_request_hash": "sha-256:" + hex_digest,
                    "changes": [
                        {
                            "op": "replace",
                            "path": "/constraints/approval",
                            "reason_code": "NEW_PERMIT_REQUIRED",
                        }
                    ],
                    "effective_constraints": {"approval": "fresh_permit_required"},
                    "require_new_permit": True,
                },
            },
            "schemas/admission-receipt.schema.json",
        ),
        (
            "admission receipt attenuation rejects malformed money object",
            {
                **minimal_admission_receipt,
                "decision": {"outcome": "attenuate", "reason_codes": ["LOCAL_POLICY_MAX_AMOUNT_NARROWED"]},
                "attenuation": {
                    "mode": "narrow",
                    "original_request_hash": "sha-256:" + "1" * 64,
                    "effective_request_hash": "sha-256:" + hex_digest,
                    "changes": [
                        {
                            "op": "replace",
                            "path": "/constraints/max_amount/value",
                            "reason_code": "LOCAL_POLICY_MAX_AMOUNT_NARROWED",
                        }
                    ],
                    "effective_constraints": {
                        "max_amount": {
                            "currency": "12$",
                            "value": "01",
                        }
                    },
                    "require_new_permit": False,
                },
            },
            "schemas/admission-receipt.schema.json",
        ),
        (
            "admission receipt attenuation rejects empty effective constraints",
            {
                **minimal_admission_receipt,
                "decision": {"outcome": "attenuate", "reason_codes": ["LOCAL_POLICY_MAX_AMOUNT_NARROWED"]},
                "attenuation": {
                    "mode": "narrow",
                    "original_request_hash": "sha-256:" + "1" * 64,
                    "effective_request_hash": "sha-256:" + hex_digest,
                    "changes": [
                        {
                            "op": "replace",
                            "path": "/constraints/max_amount/value",
                            "reason_code": "LOCAL_POLICY_MAX_AMOUNT_NARROWED",
                        }
                    ],
                    "effective_constraints": {},
                    "require_new_permit": False,
                },
            },
            "schemas/admission-receipt.schema.json",
        ),
        (
            "admission receipt attenuation rejects empty changes",
            {
                **minimal_admission_receipt,
                "decision": {"outcome": "attenuate", "reason_codes": ["LOCAL_POLICY_MAX_AMOUNT_NARROWED"]},
                "attenuation": {
                    "mode": "narrow",
                    "original_request_hash": "sha-256:" + "1" * 64,
                    "effective_request_hash": "sha-256:" + hex_digest,
                    "changes": [],
                    "effective_constraints": {"max_amount": {"currency": "USD", "value": "25.00"}},
                    "require_new_permit": False,
                },
            },
            "schemas/admission-receipt.schema.json",
        ),
        (
            "admission receipt attenuation rejects incomplete changes",
            {
                **minimal_admission_receipt,
                "decision": {"outcome": "attenuate", "reason_codes": ["LOCAL_POLICY_MAX_AMOUNT_NARROWED"]},
                "attenuation": {
                    "mode": "narrow",
                    "original_request_hash": "sha-256:" + "1" * 64,
                    "effective_request_hash": "sha-256:" + hex_digest,
                    "changes": [
                        {
                            "op": "replace",
                            "path": "/constraints/max_amount/value",
                        }
                    ],
                    "effective_constraints": {"max_amount": {"currency": "USD", "value": "25.00"}},
                    "require_new_permit": False,
                },
            },
            "schemas/admission-receipt.schema.json",
        ),
        (
            "admission receipt attenuation rejects change paths outside safe roots",
            {
                **minimal_admission_receipt,
                "decision": {"outcome": "attenuate", "reason_codes": ["LOCAL_POLICY_MAX_AMOUNT_NARROWED"]},
                "attenuation": {
                    "mode": "narrow",
                    "original_request_hash": "sha-256:" + "1" * 64,
                    "effective_request_hash": "sha-256:" + hex_digest,
                    "changes": [
                        {
                            "op": "replace",
                            "path": "/policy/max_amount",
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
            "attenuation effect rejects empty constraints",
            {
                **minimal_attenuation_effect,
                "constraints": {},
            },
            "schemas/attenuation-effect.schema.json",
        ),
        (
            "attenuation effect rejects admission effective constraints view",
            {
                **minimal_attenuation_effect,
                "effective_constraints": {"max_amount": {"currency": "USD", "value": "25.00"}},
            },
            "schemas/attenuation-effect.schema.json",
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
            "implementation report mode counts without per-case artifact mode",
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
                "artifact_mode_counts": {
                    "corpus-fixture-validation": 1,
                    "generated-receipts": 0,
                },
                "case_results": [
                    {
                        "case_id": "x",
                        "expected_outcome": "allow",
                        "actual_outcome": "allow",
                        "expected_should_execute": True,
                        "actual_should_execute": True,
                        "expected_primary_reason_code": "EVIDENCE_VERIFIED",
                        "actual_primary_reason_code": "EVIDENCE_VERIFIED",
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
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError as exc:
        raise SystemExit(
            "jsonschema is not installed in this environment. "
            "Install it locally if you want strict schema validation."
        ) from exc

    format_checker = FormatChecker()

    @format_checker.checks("date-time")
    def is_supported_rfc3339_date_time(value: object) -> bool:
        return try_parse_time(value) is not None

    for accepted in (
        "2026-07-01T00:00:00Z",
        "2026-07-01T00:00:00.1z",
        "2026-07-01T00:00:00.123456+00:00",
    ):
        if not format_checker.conforms(accepted, "date-time"):
            raise SystemExit(
                f"strict date-time checker rejected supported RFC3339 timestamp {accepted}"
            )
    for rejected in (
        "2026-07-01T00:00:00.1234567Z",
        "2026-07-01T00:00:00.0000001+00:00",
        "2026-07-01T24:00:00Z",
        "2026-W27-3T12:00:00Z",
    ):
        if format_checker.conforms(rejected, "date-time"):
            raise SystemExit(
                f"strict date-time checker accepted unsupported timestamp {rejected}"
            )

    for example_rel, schema_rel in iter_example_pairs():
        example_path = ROOT / example_rel
        schema_path = ROOT / schema_rel
        example = load_json(example_path)
        schema = load_json(schema_path)
        validator = Draft202012Validator(schema, format_checker=format_checker)
        errors = sorted(validator.iter_errors(example), key=lambda item: list(item.path))
        if errors:
            first = errors[0]
            path = ".".join(str(part) for part in first.path) or "root"
            raise SystemExit(f"{example_rel} failed strict validation at {path}: {first.message}")

    sut_result_schema = load_json(ROOT / "schemas/sut-result.schema.json")
    sut_result_validator = Draft202012Validator(
        sut_result_schema,
        format_checker=format_checker,
    )
    sut_result_with_allowed_extensions = json.loads(
        json.dumps(
            load_json(
                ROOT / "examples/conformance/sut-results-pass.example.json"
            )
        )
    )
    sut_result_with_allowed_extensions["extension_object"] = {
        "review": "preserved"
    }
    sut_result_with_allowed_extensions["extension_string"] = "preserved"
    extension_binding = None
    for result in sut_result_with_allowed_extensions["results"]:
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
        raise SystemExit(
            "passing SUT example lacks admission_receipt context binding"
        )
    extension_binding["extension_object"] = {"review": "preserved"}
    extension_binding["extension_string"] = "preserved"
    allowed_extension_errors = list(
        sut_result_validator.iter_errors(sut_result_with_allowed_extensions)
    )
    if allowed_extension_errors:
        first = allowed_extension_errors[0]
        path = ".".join(str(part) for part in first.path) or "root"
        raise SystemExit(
            "valid SUT/context binding extension metadata unexpectedly failed "
            f"strict validation at {path}: {first.message}"
        )
    sut_result_with_input_digest_extension = json.loads(
        json.dumps(load_json(ROOT / "examples/conformance/sut-results-pass.example.json"))
    )
    explicit_result = next(
        result
        for result in sut_result_with_input_digest_extension["results"]
        if result.get("artifacts", {}).get("input_artifacts")
    )
    explicit_result["artifacts"]["input_artifacts"][0]["digest"][
        "expected_receipt"
    ] = "must-not-be-an-input"
    input_digest_errors = list(
        sut_result_validator.iter_errors(sut_result_with_input_digest_extension)
    )
    if not any(
        list(error.path)[-1:] == ["digest"]
        and "Additional properties are not allowed" in error.message
        for error in input_digest_errors
    ):
        raise SystemExit(
            "SUT input digest extension unexpectedly passed strict validation"
        )

    sut_result_with_empty_inputs = json.loads(
        json.dumps(load_json(ROOT / "examples/conformance/sut-results-pass.example.json"))
    )
    explicit_result_with_empty_inputs = next(
        result
        for result in sut_result_with_empty_inputs["results"]
        if result.get("artifacts", {}).get("input_artifacts")
    )
    explicit_result_with_empty_inputs["artifacts"]["input_artifacts"] = []
    empty_input_errors = list(
        sut_result_validator.iter_errors(sut_result_with_empty_inputs)
    )
    if not any(
        list(error.path)[-1:] == ["input_artifacts"]
        and error.validator == "minItems"
        for error in empty_input_errors
    ):
        raise SystemExit("empty SUT input_artifacts unexpectedly passed strict validation")

    case_schema = load_json(ROOT / "conformance/al2-vate-v0.3/conformance-case.schema.json")
    case_validator = Draft202012Validator(
        case_schema,
        format_checker=format_checker,
    )
    canonical_integrity_case = load_json(
        ROOT
        / "conformance/al2-vate-v0.3/cases/deny-digest-mismatch-before-policy.json"
    )
    for label, malformed_integrity_checks in (
        ("object", {}),
        ("null", None),
        ("scalar", "invalid"),
        ("null item", [None]),
        ("empty object item", [{}]),
    ):
        malformed_integrity_case = json.loads(
            json.dumps(canonical_integrity_case)
        )
        malformed_integrity_case["integrity_checks"] = (
            malformed_integrity_checks
        )
        integrity_errors = list(
            case_validator.iter_errors(malformed_integrity_case)
        )
        if not any(
            list(error.path)[:1] == ["integrity_checks"]
            for error in integrity_errors
        ):
            raise SystemExit(
                f"integrity_checks {label} unexpectedly passed strict validation"
            )
    case_with_input_extension = json.loads(
        json.dumps(
            load_json(
                ROOT
                / "conformance/al2-vate-v0.3/cases/deny-status-revoked.json"
            )
        )
    )
    case_with_input_extension["sut_inputs"][0][
        "expected_failure_reason"
    ] = "STATUS_REVOKED"
    case_input_errors = list(case_validator.iter_errors(case_with_input_extension))
    if not any(
        list(error.path)[-1:] == [0]
        and "Additional properties are not allowed" in error.message
        for error in case_input_errors
    ):
        raise SystemExit("case sut_inputs extension unexpectedly passed strict validation")

    status_case_paths = sorted(
        (ROOT / "conformance/al2-vate-v0.3/cases").glob("*.json")
    )
    status_case_count = 0
    for status_case_path in status_case_paths:
        status_case = load_json(status_case_path)
        if not any(
            isinstance(check, dict) and check.get("kind") == "status"
            for check in status_case.get("al2_context_checks", [])
        ):
            continue
        status_case_count += 1
        status_without_inputs = json.loads(json.dumps(status_case))
        status_without_inputs.pop("sut_inputs", None)
        missing_input_errors = list(case_validator.iter_errors(status_without_inputs))
        if not any(
            error.validator == "required" and "sut_inputs" in error.message
            for error in missing_input_errors
        ):
            raise SystemExit(
                f"{status_case_path.name}: status case without sut_inputs unexpectedly passed"
            )

        status_without_status_role = json.loads(json.dumps(status_case))
        for item in status_without_status_role["sut_inputs"]:
            item["role"] = "context_evidence"
        missing_role_errors = list(
            case_validator.iter_errors(status_without_status_role)
        )
        if not any(error.validator == "contains" for error in missing_role_errors):
            raise SystemExit(
                f"{status_case_path.name}: status case without status_evidence input unexpectedly passed"
            )
    if status_case_count != 6:
        raise SystemExit(
            f"expected 6 explicit status-input cases, found {status_case_count}"
        )

    revoked_without_reason = json.loads(
        json.dumps(
            load_json(
                ROOT / "conformance/al2-vate-v0.3/cases/deny-status-revoked.json"
            )
        )
    )
    revoked_check = next(
        check
        for check in revoked_without_reason["al2_context_checks"]
        if check.get("kind") == "status"
    )
    revoked_check.pop("expected_failure_reason", None)
    revoked_missing_reason_errors = list(case_validator.iter_errors(revoked_without_reason))
    if not any(
        error.validator == "required"
        and "expected_failure_reason" in error.message
        for error in revoked_missing_reason_errors
    ):
        raise SystemExit("revoked status check without STATUS_REVOKED unexpectedly passed")

    revoked_with_wrong_reason = json.loads(json.dumps(revoked_without_reason))
    revoked_wrong_check = next(
        check
        for check in revoked_with_wrong_reason["al2_context_checks"]
        if check.get("kind") == "status"
    )
    revoked_wrong_check["expected_failure_reason"] = "STATUS_UNAVAILABLE"
    revoked_wrong_reason_errors = list(
        case_validator.iter_errors(revoked_with_wrong_reason)
    )
    if not any(
        error.validator == "const" and error.validator_value == "STATUS_REVOKED"
        for error in revoked_wrong_reason_errors
    ):
        raise SystemExit("revoked status check with the wrong failure reason unexpectedly passed")

    unavailable_without_reason = json.loads(
        json.dumps(
            load_json(
                ROOT
                / "conformance/al2-vate-v0.3/cases/deny-status-unavailable-fail-closed.json"
            )
        )
    )
    unavailable_check = next(
        check
        for check in unavailable_without_reason["al2_context_checks"]
        if check.get("kind") == "status"
    )
    unavailable_check.pop("expected_failure_reason", None)
    unavailable_missing_reason_errors = list(
        case_validator.iter_errors(unavailable_without_reason)
    )
    if not any(
        error.validator == "required"
        and "expected_failure_reason" in error.message
        for error in unavailable_missing_reason_errors
    ):
        raise SystemExit(
            "required unavailable status check without STATUS_UNAVAILABLE unexpectedly passed"
        )

    active_with_reason = json.loads(
        json.dumps(
            load_json(
                ROOT / "conformance/al2-vate-v0.3/cases/allow-valid-with-status-fresh.json"
            )
        )
    )
    active_check = next(
        check
        for check in active_with_reason["al2_context_checks"]
        if check.get("kind") == "status"
    )
    active_check["expected_failure_reason"] = "STATUS_REVOKED"
    active_reason_errors = list(case_validator.iter_errors(active_with_reason))
    if not any(error.validator == "not" for error in active_reason_errors):
        raise SystemExit("active status check with a failure reason unexpectedly passed")

    status_context_schema = load_json(ROOT / "schemas/status-context.schema.json")
    status_context_validator = Draft202012Validator(
        status_context_schema,
        format_checker=format_checker,
    )
    optional_unavailable_status = {
        "version": "vate-status-context-2026-07",
        "source": "status_bundle",
        "required": False,
        "availability": "unavailable",
        "checked_at": "2026-07-01T00:09:05Z",
    }
    optional_unavailable_errors = list(
        status_context_validator.iter_errors(optional_unavailable_status)
    )
    if optional_unavailable_errors:
        first = optional_unavailable_errors[0]
        path = ".".join(str(part) for part in first.path) or "root"
        raise SystemExit(
            "required=false unavailable status context unexpectedly failed "
            f"strict validation at {path}: {first.message}"
        )
    lowercase_utc_status = json.loads(
        json.dumps(
            load_json(
                ROOT
                / "conformance/al2-vate-v0.3/fixtures/status-revoked-context.json"
            )
        )
    )
    for field in ("source_issued_at", "checked_at"):
        lowercase_utc_status[field] = lowercase_utc_status[field][:-1] + "z"
    if list(status_context_validator.iter_errors(lowercase_utc_status)):
        raise SystemExit("lowercase RFC3339 UTC status context unexpectedly failed schema validation")

    offset_utc_status = json.loads(
        json.dumps(
            load_json(
                ROOT
                / "conformance/al2-vate-v0.3/fixtures/status-revoked-context.json"
            )
        )
    )
    for field in ("source_issued_at", "checked_at"):
        offset_utc_status[field] = offset_utc_status[field][:-1] + "+00:00"
    if list(status_context_validator.iter_errors(offset_utc_status)):
        raise SystemExit("RFC3339 +00:00 status context unexpectedly failed schema validation")

    for invalid_timestamp in (
        "2026-07-01T24:00:00Z",
        "2026-W27-3T12:00:00Z",
        "2026-02-30T12:00:00Z",
        "not-a-time",
    ):
        invalid_status = json.loads(json.dumps(offset_utc_status))
        invalid_status["checked_at"] = invalid_timestamp
        invalid_errors = list(status_context_validator.iter_errors(invalid_status))
        if not any(
            list(error.path)[-1:] == ["checked_at"]
            and error.validator == "format"
            for error in invalid_errors
        ):
            raise SystemExit(
                f"invalid RFC3339 status timestamp unexpectedly passed: {invalid_timestamp}"
            )

    for json_rel in JSON_ONLY_FILES:
        load_json(ROOT / json_rel)

    for label, example, schema_rel in iter_negative_schema_cases():
        schema = load_json(ROOT / schema_rel)
        validator = Draft202012Validator(schema, format_checker=format_checker)
        errors = sorted(validator.iter_errors(example), key=lambda item: list(item.path))
        if not errors:
            raise SystemExit(f"{label} unexpectedly passed strict validation against {schema_rel}")

    print("app draft strict schema validation: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
