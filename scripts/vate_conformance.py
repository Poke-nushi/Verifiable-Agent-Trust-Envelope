#!/usr/bin/env python3
"""Runnable VATE AL2 v0.3 conformance corpus checker.

This runner intentionally uses only the Python standard library.
It validates the machine-readable behavior that matters for early interop:
decision outcomes, reason codes, attenuation shape, digest-bound references,
trust-bundle lookups, and post-execution linkage.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import json
import math
import re
import sys
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "VATE-AL2-Verifier-Admission-v0.3"
VATE_A2A_EXTENSION_URI = "https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/a2a/admission/v0.3"
CONFORMANCE_REPORT_VERSION = "vate-conformance-report-2026-09"
IMPLEMENTATION_REPORT_VERSION = "vate-implementation-report-2026-09"
BUNDLE_VERIFICATION_VERSION = "vate-report-bundle-verification-2026-09"
CORPUS_INDEX_VERSION = "vate-conformance-corpus-2026-09"
CORPUS_INDEX_FILENAME = "corpus.json"
SUT_RESULTS_VERSION = "vate-sut-results-2026-09"
EVIDENCE_VOCABULARY_VERSION = "vate-evidence-vocabulary-2026-09"
STATUS_CONTEXT_VERSION = "vate-status-context-2026-09"
SUT_ARTIFACT_MODE_CORPUS = "corpus-fixture-validation"
SUT_ARTIFACT_MODE_GENERATED = "generated-receipts"
SUT_ARTIFACT_MODES = {
    SUT_ARTIFACT_MODE_CORPUS,
    SUT_ARTIFACT_MODE_GENERATED,
}
GENERATED_ARTIFACT_NAMES = {
    "admission_receipt",
    "post_execution_receipt",
}
MAX_GENERATED_ARTIFACT_BYTES = 8 * 1024 * 1024
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
PROFILE_HASH_RE = re.compile(r"^sha-256:[0-9a-f]{64}$")
CANONICAL_MONEY_VALUE_RE = re.compile(r"^(0|[1-9][0-9]*)(\.[0-9]+)?$")
RFC3339_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]"
    r"(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d"
    r"(?:\.\d{1,6})?"
    r"(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)
EVIDENCE_VOCABULARY_PATH = ROOT / "registries" / "evidence-vocabulary.v0.3.json"
TERMINAL_REASON_CODES = {"FAIL_CLOSED", "POLICY_MATCH"}
PAIRING_REQUIRED_FIELDS = (
    "pair_id",
    "role",
    "paired_case_id",
    "mutation_axis",
    "stable_fields",
    "mutated_fields",
)
PAIRING_ROLES = {"positive", "negative"}
PAIRING_FORBIDDEN_STABLE_FIELDS = frozenset(
    {
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
)


def reject_non_finite_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value} is not allowed")


def parse_finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON number {value} is not allowed")
    return parsed


def strict_json_loads(value: str | bytes | bytearray) -> Any:
    return json.loads(
        value,
        parse_constant=reject_non_finite_json_constant,
        parse_float=parse_finite_json_float,
    )


def load_evidence_vocabulary() -> tuple[frozenset[str], frozenset[str], dict[str, frozenset[str]]]:
    registry = strict_json_loads(EVIDENCE_VOCABULARY_PATH.read_text(encoding="utf-8"))
    if registry.get("version") != EVIDENCE_VOCABULARY_VERSION:
        raise RuntimeError("evidence vocabulary registry version does not match the runner")
    if registry.get("profile") != PROFILE:
        raise RuntimeError("evidence vocabulary registry profile does not match the runner")
    evidence_type_items = registry.get("evidence_types")
    protocol_hint_items = registry.get("protocol_hints")
    if not isinstance(evidence_type_items, list) or not isinstance(protocol_hint_items, list):
        raise RuntimeError("evidence vocabulary registry must define evidence_types and protocol_hints arrays")

    evidence_types: set[str] = set()
    allowed_hints_by_type: dict[str, frozenset[str]] = {}
    for item in evidence_type_items:
        if not isinstance(item, dict):
            raise RuntimeError("evidence vocabulary evidence_types entries must be objects")
        evidence_type = item.get("id")
        allowed_hints = item.get("allowed_protocol_hints")
        if not isinstance(evidence_type, str) or not evidence_type:
            raise RuntimeError("evidence vocabulary evidence type entries must have non-empty id values")
        if evidence_type in evidence_types:
            raise RuntimeError(f"duplicate evidence type id in evidence vocabulary registry: {evidence_type}")
        if not isinstance(allowed_hints, list) or not all(isinstance(hint, str) and hint for hint in allowed_hints):
            raise RuntimeError(f"evidence type {evidence_type} must define allowed_protocol_hints")
        evidence_types.add(evidence_type)
        allowed_hints_by_type[evidence_type] = frozenset(allowed_hints)

    protocol_hints: set[str] = set()
    for item in protocol_hint_items:
        if not isinstance(item, dict):
            raise RuntimeError("evidence vocabulary protocol_hints entries must be objects")
        protocol_hint = item.get("id")
        if not isinstance(protocol_hint, str) or not protocol_hint:
            raise RuntimeError("evidence vocabulary protocol hint entries must have non-empty id values")
        if protocol_hint in protocol_hints:
            raise RuntimeError(f"duplicate protocol hint id in evidence vocabulary registry: {protocol_hint}")
        protocol_hints.add(protocol_hint)

    for evidence_type, allowed_hints in allowed_hints_by_type.items():
        unknown_hints = allowed_hints - protocol_hints
        if unknown_hints:
            raise RuntimeError(
                f"evidence type {evidence_type} allows unknown protocol hints: {sorted(unknown_hints)}"
            )

    return frozenset(evidence_types), frozenset(protocol_hints), allowed_hints_by_type


(
    CANONICAL_EVIDENCE_TYPES,
    CANONICAL_PROTOCOL_HINTS,
    ALLOWED_PROTOCOL_HINTS_BY_TYPE,
) = load_evidence_vocabulary()
LINKAGE_REASON_CODES_BY_KIND = {
    "admission_decision": "POST_EXEC_LINKAGE_MISMATCH",
    "admission_digest": "POST_EXEC_ADMISSION_DIGEST_MISMATCH",
    "admission_executable": "POST_EXEC_ADMISSION_DENIED",
    "admission_receipt_id": "POST_EXEC_LINKAGE_MISMATCH",
    "admission_time_window": "POST_EXEC_ADMISSION_EXPIRED",
    "effective_constraints": "POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED",
    "effective_request_hash": "POST_EXEC_EFFECTIVE_REQUEST_HASH_MISMATCH",
    "path_match": "POST_EXEC_LINKAGE_MISMATCH",
    "runtime": "POST_EXEC_RUNTIME_MISMATCH",
    "transaction_id": "POST_EXEC_TRANSACTION_MISMATCH",
}
POLICY_VIOLATION_REASON_CODES = {
    "admission_digest_mismatch": "POST_EXEC_ADMISSION_DIGEST_MISMATCH",
    "admission_expired_before_execution": "POST_EXEC_ADMISSION_EXPIRED",
    "admission_was_denied": "POST_EXEC_ADMISSION_DENIED",
    "effective_constraints_exceeded": "POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED",
    "effective_request_hash_mismatch": "POST_EXEC_EFFECTIVE_REQUEST_HASH_MISMATCH",
    "runtime_mismatch": "POST_EXEC_RUNTIME_MISMATCH",
    "transaction_id_mismatch": "POST_EXEC_TRANSACTION_MISMATCH",
}
CANONICAL_POLICY_VIOLATION_TOKENS = set(POLICY_VIOLATION_REASON_CODES)


def is_string_enum(value: Any, allowed: set[str] | frozenset[str]) -> bool:
    """Return true only for string members of an enumerated JSON vocabulary."""
    return isinstance(value, str) and value in allowed


def read_json(path: Path) -> Any:
    return strict_json_loads(path.read_text(encoding="utf-8"))


def case_check_collection_failures(case: dict[str, Any]) -> list[str]:
    """Validate every case-level collection that the runner iterates."""
    failures: list[str] = []

    if "pairing" in case:
        pairing = case.get("pairing")
        if not isinstance(pairing, dict):
            failures.append("pairing: expected object")
        else:
            allowed_pairing_fields = {
                "pair_id",
                "role",
                "paired_case_id",
                "mutation_axis",
                "stable_fields",
                "mutated_fields",
            }
            unexpected_pairing_fields = sorted(
                set(pairing) - allowed_pairing_fields
            )
            if unexpected_pairing_fields:
                failures.append(
                    f"pairing: unsupported fields {unexpected_pairing_fields}"
                )
            for field in (
                "pair_id",
                "role",
                "paired_case_id",
                "mutation_axis",
            ):
                value = pairing.get(field)
                if not isinstance(value, str) or not value:
                    failures.append(
                        f"pairing.{field}: expected non-empty string"
                    )
            if not is_string_enum(pairing.get("role"), PAIRING_ROLES):
                failures.append(
                    f"pairing.role: expected one of {sorted(PAIRING_ROLES)}"
                )
            for field in ("stable_fields", "mutated_fields"):
                value = pairing.get(field)
                if not isinstance(value, list) or not value:
                    failures.append(
                        f"pairing.{field}: expected non-empty array"
                    )
                    continue
                for index, item in enumerate(value):
                    if not isinstance(item, str) or not item:
                        failures.append(
                            f"pairing.{field}[{index}]: expected non-empty string"
                        )
                string_items = [
                    item for item in value if isinstance(item, str)
                ]
                if len(string_items) != len(set(string_items)):
                    failures.append(
                        f"pairing.{field}: duplicate values are not allowed"
                    )

    validation_focus = case.get("validation_focus")
    if "validation_focus" in case:
        if not isinstance(validation_focus, list):
            failures.append("validation_focus: expected array")
        else:
            for index, item in enumerate(validation_focus):
                if not isinstance(item, str) or not item:
                    failures.append(
                        f"validation_focus[{index}]: expected non-empty string"
                    )

    collection_fields = (
        "integrity_checks",
        "trust_checks",
        "jose_checks",
        "policy_snapshot_checks",
        "artifact_reference_checks",
        "linkage_checks",
        "attenuation_checks",
        "al2_context_checks",
    )
    collections: dict[str, list[Any]] = {}
    for field in collection_fields:
        if field not in case:
            collections[field] = []
            continue
        value = case.get(field)
        if not isinstance(value, list):
            failures.append(f"{field}: expected array")
            collections[field] = []
            continue
        collections[field] = value
        for index, item in enumerate(value):
            if not isinstance(item, dict):
                failures.append(f"{field}[{index}]: expected object")

    def require_string(item: dict[str, Any], label: str, field: str) -> None:
        value = item.get(field)
        if not isinstance(value, str) or not value:
            failures.append(f"{label}.{field}: expected non-empty string")

    def optional_string(item: dict[str, Any], label: str, field: str) -> None:
        if field in item:
            require_string(item, label, field)

    def require_bool(item: dict[str, Any], label: str, field: str) -> None:
        if not isinstance(item.get(field), bool):
            failures.append(f"{label}.{field}: expected boolean")

    def optional_bool(item: dict[str, Any], label: str, field: str) -> None:
        if field in item:
            require_bool(item, label, field)

    for index, item in enumerate(collections["integrity_checks"]):
        if not isinstance(item, dict):
            continue
        label = f"integrity_checks[{index}]"
        require_string(item, label, "artifact")
        digest = item.get("expected_digest")
        if not isinstance(digest, dict):
            failures.append(f"{label}.expected_digest: expected object")
        else:
            unexpected_digest_fields = sorted(
                set(digest) - {"alg", "value"}
            )
            if unexpected_digest_fields:
                failures.append(
                    f"{label}.expected_digest: unsupported fields "
                    f"{unexpected_digest_fields}"
                )
            if digest.get("alg") != "sha-256":
                failures.append(f"{label}.expected_digest.alg: expected sha-256")
            digest_value = digest.get("value")
            if not isinstance(digest_value, str) or SHA256_HEX_RE.fullmatch(digest_value) is None:
                failures.append(
                    f"{label}.expected_digest.value: expected lowercase SHA-256 hex"
                )
        optional_bool(item, label, "expect_match")

    for index, item in enumerate(collections["trust_checks"]):
        if not isinstance(item, dict):
            continue
        label = f"trust_checks[{index}]"
        for field in ("trust_bundle", "issuer_id", "kid", "evidence_type"):
            require_string(item, label, field)
        require_bool(item, label, "expect_trusted")
        for field in ("alg", "expected_failure_reason"):
            optional_string(item, label, field)
        if "checked_at" in item and try_parse_time(item.get("checked_at")) is None:
            failures.append(f"{label}.checked_at: expected supported RFC3339 timestamp")

    for index, item in enumerate(collections["jose_checks"]):
        if not isinstance(item, dict):
            continue
        label = f"jose_checks[{index}]"
        for field in ("proof_package", "detached_payload", "trust_bundle"):
            require_string(item, label, field)
        require_bool(item, label, "expect_valid")
        for field in ("expected_typ", "expected_failure_reason"):
            optional_string(item, label, field)
        if "checked_at" in item and try_parse_time(item.get("checked_at")) is None:
            failures.append(f"{label}.checked_at: expected supported RFC3339 timestamp")

    def reference_path_failures(
        item: dict[str, Any],
        *,
        label: str,
        allowed_artifacts: set[str],
        required: bool,
    ) -> None:
        if "reference_paths" not in item:
            if required:
                failures.append(f"{label}.reference_paths: required")
            return
        reference_paths = item.get("reference_paths")
        if not isinstance(reference_paths, list):
            failures.append(f"{label}.reference_paths: expected array")
            return
        for reference_index, reference in enumerate(reference_paths):
            reference_label = f"{label}.reference_paths[{reference_index}]"
            if not isinstance(reference, dict):
                failures.append(f"{reference_label}: expected object")
                continue
            artifact = reference.get("artifact")
            if not is_string_enum(artifact, allowed_artifacts):
                failures.append(
                    f"{reference_label}.artifact: expected one of {sorted(allowed_artifacts)}"
                )
            require_string(reference, reference_label, "path")

    for index, item in enumerate(collections["policy_snapshot_checks"]):
        if not isinstance(item, dict):
            continue
        label = f"policy_snapshot_checks[{index}]"
        require_string(item, label, "artifact")
        optional_bool(item, label, "expect_match")
        reference_path_failures(
            item,
            label=label,
            allowed_artifacts={"admission_receipt", "a2a_metadata"},
            required=False,
        )
        if "compare_fields" in item:
            compare_fields = item.get("compare_fields")
            if not isinstance(compare_fields, list):
                failures.append(f"{label}.compare_fields: expected array")
            else:
                for field_index, field in enumerate(compare_fields):
                    if not isinstance(field, str) or not field:
                        failures.append(
                            f"{label}.compare_fields[{field_index}]: expected non-empty string"
                        )

    for index, item in enumerate(collections["artifact_reference_checks"]):
        if not isinstance(item, dict):
            continue
        label = f"artifact_reference_checks[{index}]"
        require_string(item, label, "artifact")
        optional_bool(item, label, "expect_match")
        reference_path_failures(
            item,
            label=label,
            allowed_artifacts={
                "admission_request",
                "admission_receipt",
                "post_execution_receipt",
                "a2a_metadata",
            },
            required=True,
        )

    for index, item in enumerate(collections["linkage_checks"]):
        for failure in linkage_check_contract_failures(index, item):
            failures.append(f"linkage_checks: {failure}")

    for index, item in enumerate(collections["attenuation_checks"]):
        if not isinstance(item, dict):
            continue
        label = f"attenuation_checks[{index}]"
        require_string(item, label, "artifact")
        require_bool(item, label, "expect_valid")
        for field in ("source_path", "expected_failure_reason"):
            optional_string(item, label, field)

    for index, item in enumerate(collections["al2_context_checks"]):
        if not isinstance(item, dict):
            continue
        label = f"al2_context_checks[{index}]"
        kind = item.get("kind")
        if not is_string_enum(
            kind,
            {"freshness", "binding", "replay", "status"},
        ):
            failures.append(
                f"{label}.kind: expected freshness, binding, replay, or status"
            )
        require_string(item, label, "artifact")
        if kind == "freshness":
            require_bool(item, label, "expect_fresh")
        elif kind == "binding":
            require_bool(item, label, "expect_match")
        elif kind == "replay":
            require_bool(item, label, "expect_replayed")
        elif kind == "status":
            expect_status = item.get("expect_status")
            expect_required = item.get("expect_required")
            if not is_string_enum(
                expect_status,
                {"active", "revoked", "unavailable"},
            ):
                failures.append(
                    f"{label}.expect_status: expected active, revoked, or unavailable"
                )
            require_bool(item, label, "expect_required")
            expected_failure_reason = item.get("expected_failure_reason")
            if expect_status == "revoked":
                if expected_failure_reason != "STATUS_REVOKED":
                    failures.append(
                        f"{label}.expected_failure_reason: expected STATUS_REVOKED"
                    )
            elif expect_status == "unavailable" and expect_required is True:
                if expected_failure_reason != "STATUS_UNAVAILABLE":
                    failures.append(
                        f"{label}.expected_failure_reason: expected STATUS_UNAVAILABLE"
                    )
            elif is_string_enum(expect_status, {"active", "unavailable"}) and (
                expect_status == "active" or expect_required is False
            ):
                if "expected_failure_reason" in item:
                    failures.append(
                        f"{label}.expected_failure_reason: must be absent for "
                        f"{expect_status} status with expect_required={expect_required}"
                    )
        if "max_age_seconds" in item:
            max_age_seconds = item.get("max_age_seconds")
            if (
                isinstance(max_age_seconds, bool)
                or not isinstance(max_age_seconds, int)
                or max_age_seconds < 0
            ):
                failures.append(
                    f"{label}.max_age_seconds: expected non-negative integer"
                )
        optional_string(item, label, "expected_failure_reason")
    return failures


def case_envelope_failures(case: dict[str, Any]) -> list[str]:
    """Dependency-free checks for the case shape required before evaluation."""
    failures: list[str] = []
    required_fields = (
        "version",
        "profile",
        "case_id",
        "title",
        "category",
        "purpose",
        "artifacts",
        "expected",
    )
    for field in required_fields:
        if field not in case:
            failures.append(f"{field}: required")

    if case.get("version") != "vate-conformance-0.3":
        failures.append(
            "version: expected vate-conformance-0.3 "
            f"actual {case.get('version')}"
        )
    if case.get("profile") != PROFILE:
        failures.append(f"profile: expected {PROFILE} actual {case.get('profile')}")
    for field in ("case_id", "title", "purpose"):
        value = case.get(field)
        if not isinstance(value, str) or not value:
            failures.append(f"{field}: expected non-empty string")

    category = case.get("category")
    if not is_string_enum(category, {"positive", "negative", "linkage"}):
        failures.append(
            "category: expected one of ['linkage', 'negative', 'positive'] "
            f"actual {category}"
        )
    artifacts = case.get("artifacts")
    if not isinstance(artifacts, dict):
        failures.append("artifacts: expected object")
    else:
        for field in (
            "a2a_metadata",
            "admission_request",
            "admission_receipt",
            "policy_snapshot",
            "post_execution_receipt",
            "base_artifact",
        ):
            if field in artifacts and (
                not isinstance(artifacts.get(field), str)
                or not artifacts.get(field)
            ):
                failures.append(
                    f"artifacts.{field}: expected non-empty file-reference string"
                )
        if "mutation" in artifacts and not isinstance(
            artifacts.get("mutation"), dict
        ):
            failures.append("artifacts.mutation: expected object")

    expected = case.get("expected")
    if not isinstance(expected, dict):
        failures.append("expected: expected object")
        return failures
    should_execute = expected.get("should_execute")
    if not isinstance(should_execute, bool):
        failures.append("expected.should_execute: expected boolean")

    reason_codes = expected.get("reason_codes")
    if not isinstance(reason_codes, list):
        failures.append("expected.reason_codes: expected array")
    else:
        for index, reason_code in enumerate(reason_codes):
            if not isinstance(reason_code, str) or not reason_code:
                failures.append(
                    f"expected.reason_codes[{index}]: expected non-empty string"
                )

    checks = expected.get("checks")
    if not isinstance(checks, list):
        failures.append("expected.checks: expected array")
    else:
        for index, check in enumerate(checks):
            label = f"expected.checks[{index}]"
            if not isinstance(check, dict):
                failures.append(f"{label}: expected object")
                continue
            name = check.get("name")
            if not isinstance(name, str) or not name:
                failures.append(f"{label}.name: expected non-empty string")
            expected_value = check.get("expected")
            if not is_string_enum(
                expected_value,
                {"pass", "fail", "present", "absent"},
            ):
                failures.append(
                    f"{label}.expected: expected pass, fail, present, or absent"
                )

    if is_string_enum(category, {"positive", "negative"}):
        decision = expected.get("admission_decision")
        if not is_string_enum(decision, {"allow", "attenuate", "deny"}):
            failures.append(
                "expected.admission_decision: expected allow, attenuate, or deny"
            )
    elif category == "linkage":
        outcome = expected.get("post_execution_outcome")
        if not is_string_enum(
            outcome,
            {"success", "partial_success", "failed", "cancelled"},
        ):
            failures.append(
                "expected.post_execution_outcome: expected success, partial_success, "
                "failed, or cancelled"
            )
    failures.extend(case_check_collection_failures(case))
    return failures


def load_corpus_case_records(
    corpus_root: Path,
) -> tuple[list[tuple[Path, dict[str, Any]]], list[str]]:
    """Load corpus cases without allowing one bad case to escape as a traceback."""
    records: list[tuple[Path, dict[str, Any]]] = []
    failures: list[str] = []
    for case_path in sorted((corpus_root / "cases").glob("*.json")):
        label = display_path(case_path.resolve())
        try:
            case = read_json(case_path)
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            failures.append(
                f"corpus case {label}: invalid strict JSON input "
                f"({type(exc).__name__}: {exc})"
            )
            continue
        if not isinstance(case, dict):
            failures.append(
                f"corpus case {label}: expected object, actual {type(case).__name__}"
            )
            continue
        envelope_failures = case_envelope_failures(case)
        if envelope_failures:
            failures.extend(
                f"corpus case {label}: {failure}"
                for failure in envelope_failures
            )
            continue
        records.append((case_path, case))
    return records, failures


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, allow_nan=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def pairing_string_array_failures(case_id: str, pairing: dict[str, Any], field: str) -> list[str]:
    value = pairing.get(field)
    if not isinstance(value, list):
        return [f"{case_id}.pairing.{field}: expected non-empty string array"]
    failures: list[str] = []
    if not value:
        failures.append(f"{case_id}.pairing.{field}: expected at least one field")
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            failures.append(f"{case_id}.pairing.{field}[{index}]: expected non-empty string")
    string_items = [item for item in value if isinstance(item, str)]
    if len(set(string_items)) != len(string_items):
        failures.append(f"{case_id}.pairing.{field}: duplicate field names are not allowed")
    return failures


def corpus_pairing_failures(corpus_root: Path) -> list[str]:
    case_records, case_load_failures = load_corpus_case_records(corpus_root)
    cases_by_id: dict[str, dict[str, Any]] = {}
    pairing_case_ids: list[str] = []
    pair_members: dict[str, set[str]] = {}
    failures: list[str] = list(case_load_failures)

    for case_path, case in case_records:
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            failures.append(f"{display_path(case_path.resolve())}: missing string case_id")
            continue
        if case_id in cases_by_id:
            failures.append(f"case_id {case_id}: duplicate case id")
            continue
        cases_by_id[case_id] = case

    for case_id in sorted(cases_by_id):
        case = cases_by_id[case_id]
        pairing = case.get("pairing")
        if pairing is None:
            continue
        pairing_case_ids.append(case_id)
        if not isinstance(pairing, dict):
            failures.append(f"{case_id}.pairing: expected object")
            continue
        for field in PAIRING_REQUIRED_FIELDS:
            if field not in pairing:
                failures.append(f"{case_id}.pairing.{field}: required")
        for field in ("pair_id", "role", "paired_case_id", "mutation_axis"):
            value = pairing.get(field)
            if not isinstance(value, str) or not value:
                failures.append(f"{case_id}.pairing.{field}: expected non-empty string")
        role = pairing.get("role")
        if isinstance(role, str) and role not in PAIRING_ROLES:
            failures.append(f"{case_id}.pairing.role: expected one of {sorted(PAIRING_ROLES)}")
        category = case.get("category")
        if not is_string_enum(category, PAIRING_ROLES):
            failures.append(f"{case_id}.pairing.category: expected positive or negative case category")
        elif isinstance(role, str) and role in PAIRING_ROLES and role != category:
            failures.append(f"{case_id}.pairing.role: expected {category} to match case category")

        failures.extend(pairing_string_array_failures(case_id, pairing, "stable_fields"))
        failures.extend(pairing_string_array_failures(case_id, pairing, "mutated_fields"))
        stable_fields = pairing.get("stable_fields")
        mutated_fields = pairing.get("mutated_fields")
        if isinstance(stable_fields, list) and isinstance(mutated_fields, list):
            stable_set = {item for item in stable_fields if isinstance(item, str)}
            mutated_set = {item for item in mutated_fields if isinstance(item, str)}
            overlap = sorted(stable_set & mutated_set)
            if overlap:
                failures.append(f"{case_id}.pairing: stable_fields and mutated_fields overlap: {overlap}")
            forbidden_stable_fields = sorted(stable_set & PAIRING_FORBIDDEN_STABLE_FIELDS)
            if forbidden_stable_fields:
                failures.append(
                    f"{case_id}.pairing.stable_fields: fixture identity fields are not stable semantics: "
                    f"{forbidden_stable_fields}"
                )

        pair_id = pairing.get("pair_id")
        if isinstance(pair_id, str) and pair_id:
            pair_members.setdefault(pair_id, set()).add(case_id)

    for case_id in sorted(pairing_case_ids):
        pairing = cases_by_id[case_id].get("pairing")
        if not isinstance(pairing, dict):
            continue
        paired_case_id = pairing.get("paired_case_id")
        if not isinstance(paired_case_id, str) or not paired_case_id:
            continue
        if paired_case_id == case_id:
            failures.append(f"{case_id}.pairing.paired_case_id: must not point to itself")
            continue
        paired_case = cases_by_id.get(paired_case_id)
        if paired_case is None:
            failures.append(f"{case_id}.pairing.paired_case_id: unknown case_id {paired_case_id}")
            continue
        paired_pairing = paired_case.get("pairing")
        if not isinstance(paired_pairing, dict):
            failures.append(f"{case_id}.pairing.paired_case_id: paired case {paired_case_id} has no pairing object")
            continue
        if paired_pairing.get("paired_case_id") != case_id:
            failures.append(f"{case_id}.pairing: paired case {paired_case_id} does not point back")
        role = pairing.get("role")
        paired_role = paired_pairing.get("role")
        if (
            isinstance(role, str)
            and role in PAIRING_ROLES
            and isinstance(paired_role, str)
            and paired_role in PAIRING_ROLES
            and role == paired_role
        ):
            failures.append(f"{case_id}.pairing.role: paired case {paired_case_id} must use the opposite role")
        for field in ("pair_id", "mutation_axis", "stable_fields", "mutated_fields"):
            if paired_pairing.get(field) != pairing.get(field):
                failures.append(f"{case_id}.pairing.{field}: does not match paired case {paired_case_id}")

    for pair_id, members in sorted(pair_members.items()):
        if len(members) != 2:
            failures.append(f"pairing {pair_id}: expected exactly 2 cases, found {len(members)}")

    return failures


def iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    if RFC3339_TIMESTAMP_RE.fullmatch(value) is None:
        raise ValueError("timestamp must use the supported RFC3339 date-time form")
    normalized = value
    if normalized[10] == "t":
        normalized = normalized[:10] + "T" + normalized[11:]
    if normalized.endswith(("Z", "z")):
        normalized = normalized[:-1] + "+00:00"
    return datetime.fromisoformat(normalized)


def try_parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = parse_time(value)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def b64url_encode_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64url_decode_text(value: Any) -> bytes | None:
    if not isinstance(value, str) or not value:
        return None
    if len(value) % 4 == 1:
        return None
    if any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for char in value):
        return None
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (binascii.Error, ValueError):
        return None


def sha256_value(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def digest_descriptor(value: Any) -> dict[str, str]:
    return {"alg": "sha-256", "value": sha256_value(value)}


def is_profile_hash(value: Any) -> bool:
    return isinstance(value, str) and PROFILE_HASH_RE.fullmatch(value) is not None


def profile_hash_failures(value: Any, *, label: str) -> list[str]:
    if is_profile_hash(value):
        return []
    return [f"{label} must be sha-256 followed by a lowercase 64-character hex digest"]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def case_artifacts(case: dict[str, Any]) -> dict[str, Any]:
    artifacts = case.get("artifacts")
    return artifacts if isinstance(artifacts, dict) else {}


def resolve_artifact_path(case: dict[str, Any], key_or_path: str) -> Path:
    artifacts = case_artifacts(case)
    rel = artifacts.get(key_or_path, key_or_path)
    if not isinstance(rel, str) or not rel:
        raise TypeError("artifact path must be a non-empty string")
    path = Path(rel)
    if path.is_absolute():
        return path
    return ROOT / path


def read_case_artifact(
    case: dict[str, Any],
    key_or_path: str,
) -> tuple[Any | None, str | None]:
    if not isinstance(key_or_path, str) or not key_or_path:
        return None, "artifact reference must be a non-empty string"
    try:
        path = resolve_artifact_path(case, key_or_path)
    except (TypeError, ValueError):
        return None, "artifact reference is invalid"
    if not path.is_file():
        return None, "artifact missing"
    try:
        artifact = read_json(path)
    except (OSError, UnicodeDecodeError, ValueError):
        return None, "artifact is not readable strict JSON"
    if not isinstance(artifact, dict):
        return None, "artifact must be a JSON object"
    return artifact, None


def case_artifact_sha256(case: dict[str, Any], key_or_path: str) -> str | None:
    _, artifact_failure = read_case_artifact(case, key_or_path)
    if artifact_failure:
        return None
    path = resolve_artifact_path(case, key_or_path)
    try:
        return sha256_file(path)
    except OSError:
        return None


def load_artifact(case: dict[str, Any], key: str) -> dict[str, Any] | None:
    rel = case_artifacts(case).get(key)
    if not isinstance(rel, str) or not rel:
        return None
    artifact, _ = read_case_artifact(case, key)
    return artifact


def referenced_paths(case: dict[str, Any]) -> tuple[list[Path], list[str]]:
    paths: list[Path] = []
    failures: list[str] = []

    def add_reference(key_or_path: Any, label: str) -> None:
        if not isinstance(key_or_path, str) or not key_or_path:
            failures.append(f"{label}: expected non-empty artifact reference")
            return
        try:
            paths.append(resolve_artifact_path(case, key_or_path))
        except (TypeError, ValueError):
            failures.append(f"{label}: artifact path is invalid")

    for key, value in case_artifacts(case).items():
        if isinstance(value, str):
            add_reference(key, f"artifacts.{key}")
    for index, check in enumerate(case.get("integrity_checks", [])):
        add_reference(
            check.get("artifact") if isinstance(check, dict) else None,
            f"integrity_checks[{index}].artifact",
        )
    for index, check in enumerate(case.get("trust_checks", [])):
        add_reference(
            check.get("trust_bundle") if isinstance(check, dict) else None,
            f"trust_checks[{index}].trust_bundle",
        )
    for index, check in enumerate(case.get("jose_checks", [])):
        if not isinstance(check, dict):
            failures.append(f"jose_checks[{index}]: expected object")
            continue
        for key in ("proof_package", "detached_payload", "trust_bundle"):
            if key in check:
                add_reference(check.get(key), f"jose_checks[{index}].{key}")
    for index, check in enumerate(case.get("policy_snapshot_checks", [])):
        add_reference(
            check.get("artifact") if isinstance(check, dict) else None,
            f"policy_snapshot_checks[{index}].artifact",
        )
    return paths, failures


def policy_snapshot_reference_contract_failures(
    case: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    for check_index, check in enumerate(case.get("policy_snapshot_checks", [])):
        if not isinstance(check, dict):
            continue
        reference_paths = check.get(
            "reference_paths",
            [
                {
                    "artifact": "admission_receipt",
                    "path": "policy.policy_snapshot",
                }
            ],
        )
        if not isinstance(reference_paths, list):
            continue
        for reference_index, reference in enumerate(reference_paths):
            if not isinstance(reference, dict):
                continue
            label = (
                f"policy_snapshot_checks[{check_index}]"
                f".reference_paths[{reference_index}]"
            )
            source_name = reference.get("artifact")
            source, source_failure = read_case_artifact(case, source_name)
            if source_failure:
                failures.append(
                    f"{label}: {source_name}: {source_failure}"
                )
                continue
            reference_path = reference.get("path")
            if not isinstance(reference_path, str) or not reference_path:
                failures.append(f"{label}.path: expected non-empty string")
                continue
            try:
                snapshot_ref = get_path(source, reference_path)
            except (KeyError, IndexError, TypeError, ValueError):
                failures.append(f"{label}: reference path missing")
                continue
            if not isinstance(snapshot_ref, dict):
                failures.append(
                    f"{label}: reference path must resolve to an object"
                )
    return failures


def corpus_manifest(
    corpus_root: Path,
) -> tuple[list[dict[str, str]], dict[str, str], list[str]]:
    corpus_index_path = (corpus_root / CORPUS_INDEX_FILENAME).resolve()
    paths: set[Path] = set()
    failures: set[str] = set()

    def add_manifest_path(path: Path) -> None:
        resolved = path.resolve()
        if resolved == corpus_index_path:
            return
        if not resolved.is_file():
            failures.add(
                "corpus manifest artifact is not a readable regular file: "
                f"{display_path(resolved)}"
            )
            return
        paths.add(resolved)

    for path in corpus_root.rglob("*.json"):
        add_manifest_path(path)
    case_records, case_load_failures = load_corpus_case_records(corpus_root)
    failures.update(case_load_failures)
    for _, case in case_records:
        case_paths, reference_failures = referenced_paths(case)
        failures.update(reference_failures)
        failures.update(policy_snapshot_reference_contract_failures(case))
        for path in case_paths:
            add_manifest_path(path)

    manifest: list[dict[str, str]] = []
    for path in sorted(paths, key=display_path):
        try:
            digest = sha256_file(path)
        except OSError as exc:
            failures.add(
                "corpus manifest artifact could not be hashed: "
                f"{display_path(path)} ({type(exc).__name__})"
            )
            continue
        manifest.append({"path": display_path(path), "sha256": digest})
    return (
        manifest,
        {"alg": "sha-256", "value": sha256_value(manifest)},
        sorted(failures),
    )


def case_index_entry(case_path: Path) -> dict[str, Any]:
    case = read_json(case_path)
    expected = case.get("expected", {})
    expected_reason_codes = [str(code) for code in expected.get("reason_codes", [])]
    if case["category"] == "linkage":
        expected_outcome_value = str(expected.get("post_execution_outcome", "missing"))
    else:
        expected_outcome_value = str(
            expected.get("admission_decision", expected.get("post_execution_outcome", "missing"))
        )
    entry = {
        "case_id": case["case_id"],
        "path": display_path(case_path.resolve()),
        "category": case["category"],
        "title": case.get("title", case["case_id"]),
        "expected_outcome": expected_outcome_value,
        "expected_should_execute": expected_should_execute(case),
        "expected_primary_reason_code": primary_reason_code(expected_reason_codes),
        "expected_reason_codes": expected_reason_codes,
        "validation_focus": case.get("validation_focus", []),
        "artifacts": case_artifacts(case),
    }
    if "pairing" in case:
        entry["pairing"] = case["pairing"]
    if "sut_inputs" in case:
        entry["sut_inputs"] = case["sut_inputs"]
    return entry


def category_counts(cases: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for case in cases:
        category = str(case["category"])
        counts[category] = counts.get(category, 0) + 1
    return dict(sorted(counts.items()))


def make_corpus_index(corpus_root: Path) -> dict[str, Any]:
    cases_dir = corpus_root / "cases"
    if not cases_dir.is_dir():
        raise RuntimeError(
            f"corpus cases directory is missing: {display_path(cases_dir.resolve())}"
        )
    case_records, case_load_failures = load_corpus_case_records(corpus_root)
    if case_load_failures:
        raise RuntimeError(
            "invalid corpus case input:\n- " + "\n- ".join(case_load_failures)
        )
    if not case_records:
        raise RuntimeError("no conformance case files found")
    case_paths = [case_path for case_path, _ in case_records]
    pairing_failures = corpus_pairing_failures(corpus_root)
    if pairing_failures:
        raise RuntimeError("invalid corpus pairing metadata:\n- " + "\n- ".join(pairing_failures))
    input_contract_failures = corpus_sut_input_contract_failures(corpus_root)
    if input_contract_failures:
        raise RuntimeError(
            "invalid corpus SUT input contract:\n- " + "\n- ".join(input_contract_failures)
        )
    cases = [case_index_entry(path) for path in case_paths]
    manifest, digest, manifest_failures = corpus_manifest(corpus_root)
    if manifest_failures:
        raise RuntimeError("invalid corpus manifest:\n- " + "\n- ".join(manifest_failures))
    return {
        "version": CORPUS_INDEX_VERSION,
        "profile": PROFILE,
        "name": corpus_root.name,
        "root": display_path(corpus_root.resolve()),
        "case_schema": display_path((corpus_root / "conformance-case.schema.json").resolve()),
        "conformance_report_schema": "schemas/conformance-report.schema.json",
        "implementation_report_schema": "schemas/implementation-report.schema.json",
        "digest_basis": {
            "alg": "sha-256",
            "canonicalization": "JSON objects are sorted by key with insignificant whitespace removed before hashing.",
            "manifest_excludes": [
                display_path((corpus_root / CORPUS_INDEX_FILENAME).resolve())
            ],
        },
        "summary": {
            "case_count": len(cases),
            "category_counts": category_counts(cases),
            "artifact_count": len(manifest),
        },
        "digest": digest,
        "cases": cases,
        "manifest": manifest,
        "runner": {
            "command": "python3 scripts/vate_conformance.py run --corpus-root conformance/al2-vate-v0.3 --report /tmp/vate-conformance-report.json",
            "index_command": "python3 scripts/vate_conformance.py index --corpus-root conformance/al2-vate-v0.3 --out conformance/al2-vate-v0.3/corpus.json",
        },
        "limitations": [
            "This corpus index is an implementation aid, not a production endorsement statement.",
            "Passing the listed cases does not imply production readiness or endorsement.",
        ],
    }


def get_path(value: Any, dotted_path: str) -> Any:
    current = value
    for raw_part in dotted_path.split("."):
        part = raw_part
        if "[" in part and part.endswith("]"):
            name, index = part[:-1].split("[", 1)
            if name:
                current = current[name]
            current = current[int(index)]
            continue
        current = current[part]
    return current


def has_path(value: Any, dotted_path: str) -> bool:
    try:
        get_path(value, dotted_path)
        return True
    except (KeyError, IndexError, TypeError, ValueError):
        return False


def actual_decision(admission_receipt: dict[str, Any] | None) -> str:
    if admission_receipt is None:
        return "missing"
    decision = admission_receipt.get("decision")
    if not isinstance(decision, dict):
        return "missing"
    outcome = decision.get("outcome")
    return outcome if isinstance(outcome, str) else "missing"


def actual_reason_codes(admission_receipt: dict[str, Any] | None) -> list[str]:
    if admission_receipt is None:
        return []
    decision = admission_receipt.get("decision")
    if not isinstance(decision, dict):
        return []
    codes = decision.get("reason_codes")
    if not isinstance(codes, list):
        return []
    return [code for code in codes if isinstance(code, str)]


def primary_reason_code(reason_codes: list[str]) -> str | None:
    for code in reason_codes:
        if not isinstance(code, str):
            continue
        if code not in TERMINAL_REASON_CODES:
            return code
    return None


def reason_code_order_failures(codes: list[str], outcome: str, *, label: str) -> list[str]:
    failures: list[str] = []
    if not all(isinstance(code, str) and code for code in codes):
        return [f"{label}: reason codes must be non-empty strings"]
    if len(codes) != len(set(codes)):
        failures.append(f"{label}: duplicate reason codes are not allowed")

    if "FAIL_CLOSED" in codes:
        if outcome != "deny":
            failures.append(f"{label}: FAIL_CLOSED requires deny outcome")
        if codes[-1] != "FAIL_CLOSED":
            failures.append(f"{label}: FAIL_CLOSED must be last")
        if len(codes) == 1:
            failures.append(f"{label}: FAIL_CLOSED must follow a primary denial reason")

    if "POLICY_MATCH" in codes:
        if outcome != "allow":
            failures.append(f"{label}: POLICY_MATCH requires allow outcome")
        if codes[-1] != "POLICY_MATCH":
            failures.append(f"{label}: POLICY_MATCH must be last for allow outcomes")

    return failures


def decode_json_pointer_segment(segment: str) -> str | None:
    decoded = ""
    index = 0
    while index < len(segment):
        char = segment[index]
        if char != "~":
            decoded += char
            index += 1
            continue
        if index + 1 >= len(segment):
            return None
        escape = segment[index + 1]
        if escape == "0":
            decoded += "~"
        elif escape == "1":
            decoded += "/"
        else:
            return None
        index += 2
    return decoded


def safe_attenuation_path_failures(path: Any) -> list[str]:
    if not isinstance(path, str) or not path:
        return ["change path must be a non-empty JSON Pointer string"]
    if any(ord(char) < 32 for char in path):
        return ["change path must not contain control characters"]
    if not path.startswith("/"):
        return ["change path must start with '/'"]

    decoded_segments: list[str] = []
    for raw_segment in path.split("/")[1:]:
        if raw_segment == "":
            return ["change path must not contain empty segments"]
        decoded = decode_json_pointer_segment(raw_segment)
        if decoded is None:
            return ["change path contains an invalid JSON Pointer escape"]
        if decoded in {".", "..", "__proto__", "prototype", "constructor"}:
            return [f"change path contains unsafe segment {decoded!r}"]
        decoded_segments.append(decoded)

    allowed_roots = {"approval", "constraints", "runtime", "target", "tools"}
    if not decoded_segments or decoded_segments[0] not in allowed_roots:
        return ["change path is outside the AL2 attenuation boundary"]
    return []


def decimal_amount_failures(value: Any, *, label: str) -> list[str]:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return [f"{label} must be a string or number"]
    if isinstance(value, str) and not CANONICAL_MONEY_VALUE_RE.fullmatch(value):
        return [f"{label} must be a canonical non-negative decimal string"]
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return [f"{label} must be a finite non-negative decimal"]
    if not amount.is_finite() or amount < 0:
        return [f"{label} must be a finite non-negative decimal"]
    return []


def attenuation_validation_failures(
    attenuation: Any,
    *,
    decision_reason_codes: list[str] | None = None,
) -> list[str]:
    failures: list[str] = []
    if not isinstance(attenuation, dict):
        return ["attenuation must be an object"]

    mode = attenuation.get("mode")
    if not isinstance(mode, str) or mode not in {
        "narrow",
        "require_new_permit",
        "deny_if_not_accepted",
    }:
        failures.append("mode must be a supported attenuation mode")

    original_hash = attenuation.get("original_request_hash")
    effective_hash = attenuation.get("effective_request_hash")
    failures.extend(profile_hash_failures(original_hash, label="original_request_hash"))
    failures.extend(profile_hash_failures(effective_hash, label="effective_request_hash"))
    if is_profile_hash(original_hash) and original_hash == effective_hash:
        failures.append("effective_request_hash must differ from original_request_hash")

    require_new_permit = attenuation.get("require_new_permit")
    if not isinstance(require_new_permit, bool):
        failures.append("require_new_permit must be a boolean")
    if mode == "require_new_permit" and require_new_permit is not True:
        failures.append("mode require_new_permit requires require_new_permit true")

    changes = attenuation.get("changes")
    if not isinstance(changes, list) or not changes:
        failures.append("changes must be a non-empty array")
    else:
        for index, change in enumerate(changes):
            if not isinstance(change, dict):
                failures.append(f"changes[{index}] must be an object")
                continue
            operation = change.get("op")
            if not isinstance(operation, str) or operation not in {"add", "remove", "replace"}:
                failures.append(f"changes[{index}].op must be add, remove, or replace")
            for failure in safe_attenuation_path_failures(change.get("path")):
                failures.append(f"changes[{index}].path: {failure}")
            reason_code = change.get("reason_code")
            if not isinstance(reason_code, str) or not reason_code:
                failures.append(f"changes[{index}].reason_code must be a non-empty string")
            elif decision_reason_codes is not None and reason_code not in decision_reason_codes:
                failures.append(f"changes[{index}].reason_code must appear in decision.reason_codes")

    effective_constraints = attenuation.get("effective_constraints")
    if not isinstance(effective_constraints, dict) or not effective_constraints:
        failures.append("effective_constraints must be a non-empty object")
    else:
        if "max_amount_usd" in effective_constraints:
            failures.append("effective_constraints.max_amount_usd is a legacy input alias; use max_amount")
        if "resource" in effective_constraints:
            failures.append("effective_constraints.resource is a legacy input alias; use target_resource")

        max_amount = effective_constraints.get("max_amount")
        if max_amount is not None:
            if not isinstance(max_amount, dict):
                failures.append("effective_constraints.max_amount must be an object")
            else:
                currency = max_amount.get("currency")
                if (
                    not isinstance(currency, str)
                    or len(currency) != 3
                    or not all("A" <= char <= "Z" for char in currency)
                ):
                    failures.append("effective_constraints.max_amount.currency must be a 3-letter uppercase code")
                failures.extend(
                    decimal_amount_failures(
                        max_amount.get("value"),
                        label="effective_constraints.max_amount.value",
                    )
                )

        tool_allowlist = effective_constraints.get("tool_allowlist")
        if tool_allowlist is not None and (
            not isinstance(tool_allowlist, list)
            or not all(isinstance(tool, str) and tool for tool in tool_allowlist)
        ):
            failures.append("effective_constraints.tool_allowlist must be an array of non-empty strings")

        target_resource = effective_constraints.get("target_resource")
        if target_resource is not None and (not isinstance(target_resource, str) or not target_resource):
            failures.append("effective_constraints.target_resource must be a non-empty string")

        approval = effective_constraints.get("approval")
        if approval is not None:
            if not isinstance(approval, dict):
                failures.append("effective_constraints.approval must be an object")
            else:
                approval_mode = approval.get("mode")
                if not isinstance(approval_mode, str) or not approval_mode:
                    failures.append("effective_constraints.approval.mode must be a non-empty string")
                policy_ref = approval.get("policy_ref")
                if policy_ref is not None and (not isinstance(policy_ref, str) or not policy_ref):
                    failures.append("effective_constraints.approval.policy_ref must be a non-empty string")

        expires_at = effective_constraints.get("expires_at")
        if expires_at is not None and try_parse_time(expires_at) is None:
            failures.append("effective_constraints.expires_at must be an RFC3339 timestamp")

    return failures


def attenuation_failure_reason(failures: list[str]) -> str | None:
    if not failures:
        return None
    return "SCHEMA_INVALID"


def expected_should_execute(case: dict[str, Any]) -> bool:
    return bool(case.get("expected", {}).get("should_execute", False))


def actual_should_execute(admission_receipt: dict[str, Any] | None) -> bool:
    if admission_receipt is None:
        return False
    decision = admission_receipt.get("decision")
    if not isinstance(decision, dict):
        return False
    outcome = decision.get("outcome")
    if outcome == "deny":
        return False
    if outcome == "attenuate":
        attenuation = admission_receipt.get("attenuation")
        if not isinstance(attenuation, dict) or attenuation.get("require_new_permit") is True:
            return False
    return isinstance(outcome, str) and outcome in {"allow", "attenuate"}


def append_unique(items: list[str], item: str) -> None:
    if item not in items:
        items.append(item)


def actual_linkage_reason_codes(
    case: dict[str, Any],
    admission_receipt: dict[str, Any] | None,
    post_execution_receipt: dict[str, Any] | None,
) -> list[str]:
    if admission_receipt is None or post_execution_receipt is None:
        return ["POST_EXEC_LINKAGE_MISMATCH"]

    violation_codes: list[str] = []
    for check in case.get("linkage_checks", []):
        if not isinstance(check, dict):
            continue
        violation, failure = linkage_check_violation(case, check, admission_receipt, post_execution_receipt)
        reason_code = check.get("reason_code")
        if (violation or failure) and isinstance(reason_code, str) and reason_code:
            append_unique(violation_codes, reason_code)
    if violation_codes:
        return violation_codes

    if not case.get("linkage_checks") and post_execution_linkage_failures(admission_receipt, post_execution_receipt):
        return ["POST_EXEC_LINKAGE_MISMATCH"]

    codes = ["ADMISSION_RECEIPT_LINKED", "EFFECTIVE_REQUEST_HASH_MATCH"]
    result = post_execution_receipt.get("result")
    if isinstance(result, dict) and result.get("policy_violations") == []:
        codes.append("NO_POLICY_VIOLATIONS")
    return codes


def linkage_check_contract_failures(index: int, check: Any) -> list[str]:
    if not isinstance(check, dict):
        return [f"linkage[{index}]: expected object"]

    failures: list[str] = []
    kind = check.get("kind")
    if not isinstance(kind, str):
        return [f"linkage[{index}]: kind must be a string enum"]
    if kind in {"transaction_id", "runtime", "effective_request_hash", "path_match"}:
        required = ("admission_path", "post_execution_path", "expect_match")
    elif kind in {"admission_receipt_id", "admission_decision"}:
        required = ("expect_match",)
    elif kind == "admission_digest":
        required = ("post_execution_path", "expect_match")
    elif kind in {"admission_executable", "admission_time_window", "effective_constraints"}:
        required = ("expect_valid",)
    elif kind == "policy_violation":
        required = ("value", "expect_present")
    else:
        return [f"linkage[{index}] {kind!r}: unsupported linkage check kind"]

    for field in required:
        if field not in check:
            failures.append(f"linkage[{index}] {kind}: missing required field {field}")

    for field in ("admission_path", "post_execution_path", "value"):
        if field in required and field in check and (not isinstance(check.get(field), str) or not check.get(field)):
            failures.append(f"linkage[{index}] {kind}: {field} must be a non-empty string")

    for field in ("expect_match", "expect_valid", "expect_present"):
        if field in required and field in check and not isinstance(check.get(field), bool):
            failures.append(f"linkage[{index}] {kind}: {field} must be boolean")

    expected_reason_code = LINKAGE_REASON_CODES_BY_KIND.get(kind)
    if kind == "policy_violation":
        value = check.get("value")
        expected_reason_code = (
            POLICY_VIOLATION_REASON_CODES.get(value)
            if isinstance(value, str)
            else None
        )
        if expected_reason_code is None:
            failures.append(f"linkage[{index}] policy_violation: unknown policy violation token {value!r}")

    actual_reason_code = check.get("reason_code")
    if expected_reason_code is not None and actual_reason_code != expected_reason_code:
        failures.append(
            f"linkage[{index}] {kind}: expected reason_code {expected_reason_code} actual {actual_reason_code}"
        )
    return failures


def post_execution_policy_violation_token_failures(post_execution: dict[str, Any] | None) -> list[str]:
    if post_execution is None:
        return []
    result = post_execution.get("result")
    if not isinstance(result, dict):
        return ["post_execution.result: expected object"]
    violations = result.get("policy_violations")
    if not isinstance(violations, list):
        return ["post_execution.result.policy_violations: expected array"]
    failures: list[str] = []
    for index, token in enumerate(violations):
        if not isinstance(token, str) or token not in CANONICAL_POLICY_VIOLATION_TOKENS:
            failures.append(f"post_execution.result.policy_violations[{index}]: unknown token {token!r}")
    return failures


def admitted_effective_request_hash(admission_receipt: dict[str, Any]) -> Any:
    if actual_decision(admission_receipt) == "attenuate":
        attenuation = admission_receipt.get("attenuation")
        return attenuation.get("effective_request_hash") if isinstance(attenuation, dict) else None
    request = admission_receipt.get("request")
    return request.get("input_hash") if isinstance(request, dict) else None


def admitted_effective_constraints(admission_receipt: dict[str, Any]) -> dict[str, Any]:
    if actual_decision(admission_receipt) == "attenuate":
        attenuation = admission_receipt.get("attenuation")
        attenuation_constraints = (
            attenuation.get("effective_constraints") if isinstance(attenuation, dict) else None
        )
        if isinstance(attenuation_constraints, dict):
            return attenuation_constraints
    request = admission_receipt.get("request")
    request_constraints = request.get("constraints") if isinstance(request, dict) else None
    if isinstance(request_constraints, dict):
        return request_constraints
    return {}


def post_execution_linkage_failures(
    admission_receipt: dict[str, Any] | None,
    post_execution_receipt: dict[str, Any] | None,
) -> list[str]:
    failures: list[str] = []
    if admission_receipt is None or post_execution_receipt is None:
        return ["admission or post-execution artifact missing"]

    admission_block = post_execution_receipt.get("admission", {})
    execution = post_execution_receipt.get("execution", {})
    if not isinstance(admission_block, dict) or not isinstance(execution, dict):
        return ["post-execution admission or execution block missing"]

    admission_decision = actual_decision(admission_receipt)
    if admission_decision == "deny":
        failures.append("post-execution receipt must not link to a denied admission")
    if admission_decision not in {"allow", "attenuate"}:
        failures.append("admission decision must be allow or attenuate for post-execution linkage")
    attenuation = admission_receipt.get("attenuation")
    if admission_decision == "attenuate" and (
        not isinstance(attenuation, dict) or attenuation.get("require_new_permit") is True
    ):
        failures.append("post-execution receipt must not link to an admission requiring a new permit")

    if admission_block.get("receipt_id") != admission_receipt.get("receipt_id"):
        failures.append("admission receipt_id mismatch")
    if admission_block.get("decision") != admission_decision:
        failures.append("admission decision mismatch")
    if admission_block.get("digest") != {"alg": "sha-256", "value": sha256_value(admission_receipt)}:
        failures.append("admission digest mismatch")

    raw_request = admission_receipt.get("request")
    raw_subject = admission_receipt.get("subject")
    request = raw_request if isinstance(raw_request, dict) else {}
    subject = raw_subject if isinstance(raw_subject, dict) else {}
    if execution.get("transaction_id") != request.get("transaction_id"):
        failures.append("transaction_id mismatch")
    if execution.get("runtime") != subject.get("runtime"):
        failures.append("runtime mismatch")
    expected_request_hash = admitted_effective_request_hash(admission_receipt)
    actual_request_hash = execution.get("effective_request_hash")
    if (
        not is_profile_hash(expected_request_hash)
        or not is_profile_hash(actual_request_hash)
        or actual_request_hash != expected_request_hash
    ):
        failures.append("effective_request_hash mismatch")

    started_at = try_parse_time(execution.get("started_at"))
    finished_at = try_parse_time(execution.get("finished_at"))
    admission_issued_at = try_parse_time(admission_receipt.get("issued_at"))
    admission_expires_at = try_parse_time(admission_receipt.get("expires_at"))
    if admission_issued_at is None or admission_expires_at is None:
        failures.append("admission timestamps must be valid")
    if started_at is None or finished_at is None:
        failures.append("execution timestamps must be valid")
    else:
        if finished_at < started_at:
            failures.append("execution finished before it started")
        if admission_issued_at is not None and started_at < admission_issued_at:
            failures.append("execution started before admission was issued")
        if admission_expires_at is not None and started_at > admission_expires_at:
            failures.append("execution started after admission expiry")
        if admission_expires_at is not None and finished_at > admission_expires_at:
            failures.append("execution finished after admission expiry")

    failures.extend(post_execution_side_effect_failures(admission_receipt, post_execution_receipt))
    return failures


def post_execution_side_effect_failures(
    admission_receipt: dict[str, Any],
    post_execution_receipt: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    max_amount = admitted_effective_constraints(admission_receipt).get("max_amount")
    if not isinstance(max_amount, dict):
        return failures
    max_currency = max_amount.get("currency")
    max_value = max_amount.get("value")
    max_failures = decimal_amount_failures(max_value, label="admitted max_amount.value")
    if max_failures or not isinstance(max_currency, str):
        return failures
    max_decimal = Decimal(str(max_value))
    total_decimal = Decimal("0")

    result = post_execution_receipt.get("result")
    if not isinstance(result, dict):
        return ["post_execution.result must be an object"]
    side_effects = result.get("side_effects", [])
    if not isinstance(side_effects, list):
        failures.append("side_effects must be an array")
        return failures
    for index, side_effect in enumerate(side_effects):
        if not isinstance(side_effect, dict) or "amount" not in side_effect:
            continue
        amount = side_effect.get("amount")
        if not isinstance(amount, dict):
            failures.append(f"side_effects[{index}].amount must be an object")
            continue
        currency = amount.get("currency")
        value = amount.get("value")
        if currency != max_currency:
            failures.append(f"side_effects[{index}].amount currency exceeds admitted currency boundary")
            continue
        amount_failures = decimal_amount_failures(value, label=f"side_effects[{index}].amount.value")
        if amount_failures:
            failures.extend(amount_failures)
            continue
        total_decimal += Decimal(str(value))
        if total_decimal > max_decimal:
            failures.append("side_effects aggregate amount exceeds admitted max_amount")
            break
    return failures


def admission_executable_for_post_execution(admission_receipt: dict[str, Any]) -> bool:
    admission_decision = actual_decision(admission_receipt)
    if admission_decision not in {"allow", "attenuate"}:
        return False
    if admission_decision != "attenuate":
        return True
    attenuation = admission_receipt.get("attenuation")
    return isinstance(attenuation, dict) and attenuation.get("require_new_permit") is not True


def admission_time_window_valid(
    admission_receipt: dict[str, Any],
    post_execution_receipt: dict[str, Any],
) -> tuple[bool, str | None]:
    execution = post_execution_receipt.get("execution", {})
    if not isinstance(execution, dict):
        return False, "execution block missing"
    started_at = try_parse_time(execution.get("started_at"))
    finished_at = try_parse_time(execution.get("finished_at"))
    admission_issued_at = try_parse_time(admission_receipt.get("issued_at"))
    admission_expires_at = try_parse_time(admission_receipt.get("expires_at"))
    if admission_issued_at is None or admission_expires_at is None:
        return False, "admission timestamps must be valid"
    if started_at is None or finished_at is None:
        return False, "execution timestamps must be valid"
    if finished_at < started_at:
        return False, "execution finished before it started"
    if admission_issued_at is not None and started_at < admission_issued_at:
        return False, "execution started before admission was issued"
    if admission_expires_at is not None and started_at > admission_expires_at:
        return False, "execution started after admission expiry"
    if admission_expires_at is not None and finished_at > admission_expires_at:
        return False, "execution finished after admission expiry"
    return True, None


def linkage_check_violation(
    case: dict[str, Any],
    check: dict[str, Any],
    admission: dict[str, Any] | None,
    post_execution: dict[str, Any] | None,
) -> tuple[bool, str | None]:
    if not isinstance(check, dict):
        return True, "linkage check must be an object"
    if admission is None or post_execution is None:
        return True, "admission or post-execution artifact missing"

    kind = check.get("kind")
    if not isinstance(kind, str):
        return True, "linkage check kind must be a string enum"
    try:
        if kind in {"transaction_id", "runtime", "effective_request_hash", "path_match"}:
            left = get_path(admission, check["admission_path"])
            right = get_path(post_execution, check["post_execution_path"])
            return left != right, None
        if kind == "admission_digest":
            artifact_name = check.get("artifact", "admission_receipt")
            artifact, artifact_failure = read_case_artifact(case, artifact_name)
            if artifact_failure:
                return True, f"{artifact_name}: {artifact_failure}"
            expected_digest = {"alg": "sha-256", "value": sha256_value(artifact)}
            actual_digest = get_path(post_execution, check.get("post_execution_path", "admission.digest"))
            return actual_digest != expected_digest, None
        if kind == "admission_receipt_id":
            actual_receipt_id = get_path(post_execution, "admission.receipt_id")
            return actual_receipt_id != admission.get("receipt_id"), None
        if kind == "admission_decision":
            actual_admission_decision = get_path(post_execution, "admission.decision")
            return actual_admission_decision != actual_decision(admission), None
        if kind == "admission_executable":
            return not admission_executable_for_post_execution(admission), None
        if kind == "admission_time_window":
            valid, failure = admission_time_window_valid(admission, post_execution)
            if failure in {"execution block missing", "execution timestamps must be valid"}:
                return not valid, failure
            return not valid, None
        if kind == "effective_constraints":
            return bool(post_execution_side_effect_failures(admission, post_execution)), None
        if kind == "policy_violation":
            violations = post_execution.get("result", {}).get("policy_violations", [])
            if not isinstance(violations, list):
                return True, "policy_violations must be an array"
            expected_value = check.get("value")
            if not isinstance(expected_value, str) or not expected_value:
                return True, "policy_violation check requires value"
            return expected_value in violations, None
    except (AttributeError, KeyError, IndexError, TypeError, ValueError) as exc:
        return True, f"{kind} linkage check path missing: {exc}"
    return True, f"unsupported linkage check kind {kind}"


def expected_linkage_violation(check: dict[str, Any]) -> bool:
    if "expect_match" in check:
        return not bool(check.get("expect_match"))
    if "expect_valid" in check:
        return not bool(check.get("expect_valid"))
    if "expect_present" in check:
        return bool(check.get("expect_present"))
    return False


def expected_outcome(case: dict[str, Any]) -> str:
    expected = case["expected"]
    if case["category"] == "linkage":
        return str(expected.get("post_execution_outcome", "missing"))
    return str(expected.get("admission_decision", expected.get("post_execution_outcome", "missing")))


def observed_outcome(case: dict[str, Any], admission: dict[str, Any] | None, post_execution: dict[str, Any] | None) -> str:
    if case["category"] == "linkage":
        if post_execution is None:
            return "missing"
        result = post_execution.get("result")
        return str(result.get("outcome", "missing")) if isinstance(result, dict) else "missing"
    if "admission_decision" in case["expected"]:
        return actual_decision(admission)
    if post_execution is None:
        return "missing"
    result = post_execution.get("result")
    return str(result.get("outcome", "missing")) if isinstance(result, dict) else "missing"


def bool_for_named_check(
    *,
    name: str,
    admission: dict[str, Any] | None,
    post_execution: dict[str, Any] | None,
    a2a_metadata: dict[str, Any] | None,
    jose_results: dict[str, bool] | None,
) -> bool:
    if name.startswith("jose."):
        return bool(jose_results and jose_results.get(name))
    if name == "decision.outcome":
        return admission is not None and actual_decision(admission) in {"allow", "attenuate"}
    if name == "evidence.verification.result":
        if admission is None:
            return False
        evidence = admission.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            return False
        verification_items: list[dict[str, Any]] = []
        for item in evidence:
            if not isinstance(item, dict):
                return False
            verification = item.get("verification")
            if not isinstance(verification, dict):
                return False
            verification_items.append(verification)
        return all(
            verification.get("result") == "verified"
            for verification in verification_items
        )
    if name == "evidence.verification.failure_reason":
        if admission is None:
            return False
        evidence = admission.get("evidence")
        if not isinstance(evidence, list):
            return False
        return any(
            isinstance(item, dict)
            and isinstance(item.get("verification"), dict)
            and "failure_reason" in item["verification"]
            for item in evidence
        )
    if name == "admission_receipt.evidence.verification.inferred_resource_authority":
        if admission is None:
            return False
        evidence = admission.get("evidence")
        if not isinstance(evidence, list):
            return False
        return any(
            isinstance(item, dict)
            and isinstance(item.get("verification"), dict)
            and "inferred_resource_authority" in item["verification"]
            for item in evidence
        )
    if name == "admission_receipt.evidence.verification.inferred_tool_authority":
        if admission is None:
            return False
        evidence = admission.get("evidence")
        if not isinstance(evidence, list):
            return False
        return any(
            isinstance(item, dict)
            and isinstance(item.get("verification"), dict)
            and "inferred_tool_authority" in item["verification"]
            for item in evidence
        )
    if name == "policy.policy_version":
        return admission is not None and has_path(admission, "policy.policy_version")
    if name == "post_execution_receipt":
        return post_execution is not None
    if name in {"request.audience", "target.audience"}:
        if admission is None:
            return False
        request = admission.get("request")
        if not isinstance(request, dict):
            return False
        audience = request.get("audience")
        target_audience = request.get("target_audience")
        return (
            isinstance(audience, str)
            and bool(audience)
            and isinstance(target_audience, str)
            and bool(target_audience)
            and audience == target_audience
        )
    if name == "result.policy_violations":
        if post_execution is None:
            return False
        result = post_execution.get("result")
        if not isinstance(result, dict):
            return False
        return result.get("policy_violations") == []

    artifact: dict[str, Any] | None
    dotted = name
    if name.startswith("a2a_metadata."):
        artifact = a2a_metadata
        dotted = name.removeprefix("a2a_metadata.")
    elif name.startswith("post_execution."):
        artifact = post_execution
        dotted = name.removeprefix("post_execution.")
    elif name.startswith("admission_receipt."):
        artifact = admission
        dotted = name.removeprefix("admission_receipt.")
    else:
        artifact = admission
    return artifact is not None and has_path(artifact, dotted)


def directly_dereferenced_artifact_failures(
    admission: dict[str, Any] | None,
    post_execution: dict[str, Any] | None,
) -> list[str]:
    """Validate only nested artifact nodes the dependency-free runner reads."""
    failures: list[str] = []
    if admission is not None:
        request = admission.get("request")
        if not isinstance(request, dict):
            failures.append("admission_receipt.request: expected object")
        evidence = admission.get("evidence")
        if not isinstance(evidence, list):
            failures.append("admission_receipt.evidence: expected array")
        else:
            for index, item in enumerate(evidence):
                label = f"admission_receipt.evidence[{index}]"
                if not isinstance(item, dict):
                    failures.append(f"{label}: expected object")
                    continue
                if not isinstance(item.get("verification"), dict):
                    failures.append(f"{label}.verification: expected object")
    if post_execution is not None and not isinstance(
        post_execution.get("result"), dict
    ):
        failures.append("post_execution_receipt.result: expected object")
    return failures


def evaluate_expected_check(
    *,
    name: str,
    expected: str,
    admission: dict[str, Any] | None,
    post_execution: dict[str, Any] | None,
    a2a_metadata: dict[str, Any] | None,
    jose_results: dict[str, bool] | None,
) -> bool:
    value = bool_for_named_check(
        name=name,
        admission=admission,
        post_execution=post_execution,
        a2a_metadata=a2a_metadata,
        jose_results=jose_results,
    )
    if expected == "pass":
        return value
    if expected == "fail":
        return not value
    if expected == "present":
        return value
    if expected == "absent":
        return not value
    return False


def evaluate_integrity_checks(case: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for check in case.get("integrity_checks", []):
        artifact_name = check["artifact"]
        artifact, artifact_failure = read_case_artifact(case, artifact_name)
        if artifact_failure:
            failures.append(f"integrity {artifact_name}: {artifact_failure}")
            continue
        actual = sha256_value(artifact)
        expected_digest = check["expected_digest"]["value"]
        expect_match = bool(check.get("expect_match", True))
        matched = actual == expected_digest
        if matched != expect_match:
            failures.append(
                f"integrity {check['artifact']}: expected match={expect_match} actual match={matched}"
            )
    return failures


def evaluate_trust_checks(case: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for check in case.get("trust_checks", []):
        bundle_name = check["trust_bundle"]
        bundle, artifact_failure = read_case_artifact(case, bundle_name)
        if artifact_failure:
            failures.append(f"trust {bundle_name}: {artifact_failure}")
            continue
        trusted, failure_reason = evaluate_trust_check(bundle, check)
        expect_trusted = bool(check.get("expect_trusted", True))
        if trusted != expect_trusted:
            failures.append(
                f"trust {check['issuer_id']} {check['kid']}: expected trusted={expect_trusted} actual trusted={trusted}"
            )
        expected_failure = check.get("expected_failure_reason")
        if expected_failure and failure_reason != expected_failure:
            failures.append(
                f"trust {check['issuer_id']} {check['kid']}: expected failure={expected_failure} actual failure={failure_reason}"
            )
    return failures


def evaluate_trust_check(bundle: dict[str, Any], check: dict[str, Any]) -> tuple[bool, str | None]:
    issuers = bundle.get("issuers")
    if not isinstance(issuers, list) or not issuers:
        return False, "SCHEMA_INVALID"
    if not all(isinstance(issuer, dict) for issuer in issuers):
        return False, "SCHEMA_INVALID"

    issuer_matches = [
        issuer for issuer in issuers
        if issuer.get("issuer_id") == check["issuer_id"]
    ]
    if not issuer_matches:
        return False, "UNKNOWN_TRUST_ANCHOR"

    key_matches = [
        issuer for issuer in issuer_matches
        if issuer.get("kid") == check["kid"]
    ]
    if not key_matches:
        return False, "UNKNOWN_TRUST_ANCHOR"
    if len(key_matches) > 1:
        return False, "SCHEMA_INVALID"

    issuer = key_matches[0]
    status = issuer.get("status", "active")
    if is_string_enum(status, {"revoked", "disabled", "suspended"}):
        return False, "TRUST_ANCHOR_REVOKED"
    if status != "active":
        return False, "SCHEMA_INVALID"

    if "checked_at" in check:
        checked_at_value = check.get("checked_at")
        checked_at = try_parse_time(checked_at_value)
        if checked_at is None:
            return False, "SCHEMA_INVALID"
        if "not_before" in issuer:
            not_before = issuer.get("not_before")
            not_before_time = try_parse_time(not_before)
            if not_before_time is None:
                return False, "SCHEMA_INVALID"
            if checked_at < not_before_time:
                return False, "TRUST_ANCHOR_NOT_YET_VALID"
        if "not_after" in issuer:
            not_after = issuer.get("not_after")
            not_after_time = try_parse_time(not_after)
            if not_after_time is None:
                return False, "SCHEMA_INVALID"
            if checked_at > not_after_time:
                return False, "TRUST_ANCHOR_EXPIRED"

    if "alg" in check:
        alg = check.get("alg")
        if not isinstance(alg, str) or not alg:
            return False, "SCHEMA_INVALID"
        allowed_algs = issuer.get("allowed_algs")
        if allowed_algs is None:
            issuer_alg = issuer.get("alg")
            if not isinstance(issuer_alg, str) or not issuer_alg:
                return False, "SCHEMA_INVALID"
            allowed_algs = [issuer_alg]
        if (
            not isinstance(allowed_algs, list)
            or not allowed_algs
            or not all(isinstance(allowed_alg, str) and allowed_alg for allowed_alg in allowed_algs)
        ):
            return False, "SCHEMA_INVALID"
        if alg not in allowed_algs:
            return False, "ALG_NOT_ALLOWED"

    evidence_type = check.get("evidence_type")
    if not isinstance(evidence_type, str) or not evidence_type:
        return False, "SCHEMA_INVALID"
    if evidence_type not in CANONICAL_EVIDENCE_TYPES:
        return False, "SCHEMA_INVALID"

    allowed_evidence_types = issuer.get("allowed_evidence_types")
    if (
        not isinstance(allowed_evidence_types, list)
        or not allowed_evidence_types
        or not all(isinstance(evidence_type, str) and evidence_type for evidence_type in allowed_evidence_types)
    ):
        return False, "SCHEMA_INVALID"
    if evidence_type not in allowed_evidence_types:
        return False, "ISSUER_NOT_AUTHORIZED"

    return True, None


def evaluate_jose_checks(case: dict[str, Any]) -> tuple[dict[str, bool], list[str]]:
    aggregate_results: dict[str, bool] = {}
    failures: list[str] = []
    for check in case.get("jose_checks", []):
        loaded: dict[str, Any] = {}
        for field in ("proof_package", "detached_payload", "trust_bundle"):
            artifact_name = check[field]
            artifact, artifact_failure = read_case_artifact(case, artifact_name)
            if artifact_failure:
                failures.append(f"jose {artifact_name}: {artifact_failure}")
            else:
                loaded[field] = artifact
        if len(loaded) != 3:
            continue
        proof = loaded["proof_package"]
        detached_payload = loaded["detached_payload"]
        trust_bundle = loaded["trust_bundle"]
        valid, failure_reason, check_results = evaluate_jose_check(proof, detached_payload, trust_bundle, check)
        for name, result in check_results.items():
            aggregate_results[name] = aggregate_results.get(name, True) and result

        expect_valid = bool(check.get("expect_valid", True))
        if valid != expect_valid:
            failures.append(f"jose {check['proof_package']}: expected valid={expect_valid} actual valid={valid}")
        expected_failure = check.get("expected_failure_reason")
        if expected_failure and failure_reason != expected_failure:
            failures.append(
                f"jose {check['proof_package']}: expected failure={expected_failure} actual failure={failure_reason}"
            )
    return aggregate_results, failures


def evaluate_jose_check(
    proof: dict[str, Any],
    detached_payload: dict[str, Any],
    trust_bundle: dict[str, Any],
    check: dict[str, Any],
) -> tuple[bool, str | None, dict[str, bool]]:
    check_results = {
        "jose.protected_header": False,
        "jose.detached_payload_digest": False,
        "jose.signing_input": False,
    }

    if proof.get("proof_type") != "detached_jws":
        return False, "SCHEMA_INVALID", check_results
    if proof.get("payload_canonicalization") != "json-sorted-no-whitespace":
        return False, "SCHEMA_INVALID", check_results

    protected = proof.get("protected")
    if not isinstance(protected, dict):
        return False, "SCHEMA_INVALID", check_results

    protected_b64u = proof.get("protected_b64u")
    expected_protected_b64u = b64url_encode_bytes(canonical_bytes(protected))
    decoded_protected = b64url_decode_text(protected_b64u)
    if decoded_protected is None:
        return False, "SCHEMA_INVALID", check_results
    try:
        decoded_protected_json = strict_json_loads(decoded_protected.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False, "SCHEMA_INVALID", check_results
    if protected_b64u != expected_protected_b64u or decoded_protected_json != protected:
        return False, "SCHEMA_INVALID", check_results
    check_results["jose.protected_header"] = True

    payload_b64u = proof.get("detached_payload_b64u")
    expected_payload_b64u = b64url_encode_bytes(canonical_bytes(detached_payload))
    payload_digest = {
        "alg": "sha-256",
        "value": sha256_value(detached_payload),
    }
    if payload_b64u != expected_payload_b64u or proof.get("detached_payload_sha256") != payload_digest:
        return False, "DIGEST_MISMATCH", check_results
    check_results["jose.detached_payload_digest"] = True

    signing_input = f"{protected_b64u}.{payload_b64u}".encode("ascii")
    signing_input_digest = {
        "alg": "sha-256",
        "value": hashlib.sha256(signing_input).hexdigest(),
    }
    if proof.get("signing_input_sha256") != signing_input_digest:
        return False, "SIGNATURE_INVALID", check_results
    check_results["jose.signing_input"] = True

    alg = protected.get("alg")
    kid = protected.get("kid")
    typ = protected.get("typ")
    if not isinstance(alg, str) or not alg or not isinstance(kid, str) or not kid or not isinstance(typ, str) or not typ:
        return False, "SCHEMA_INVALID", check_results
    if alg == "none":
        return False, "ALG_NOT_ALLOWED", check_results
    expected_typ = check.get("expected_typ")
    if expected_typ and typ != expected_typ:
        return False, "SCHEMA_INVALID", check_results

    if protected.get("crit", []):
        return False, "SCHEMA_INVALID", check_results

    if b64url_decode_text(proof.get("signature_b64u")) is None:
        return False, "SIGNATURE_INVALID", check_results

    evidence_type = proof.get("evidence_type")
    issuer = proof.get("issuer")
    if not isinstance(evidence_type, str) or not evidence_type or not isinstance(issuer, str) or not issuer:
        return False, "SCHEMA_INVALID", check_results
    if evidence_type not in CANONICAL_EVIDENCE_TYPES:
        return False, "SCHEMA_INVALID", check_results
    if evidence_type == "signed_agent_card":
        capabilities = detached_payload.get("capabilities")
        extensions = capabilities.get("extensions") if isinstance(capabilities, dict) else None
        if not isinstance(extensions, list) or not extensions:
            return False, "SCHEMA_INVALID", check_results
        vate_extension = next(
            (
                extension for extension in extensions
                if isinstance(extension, dict) and extension.get("uri") == VATE_A2A_EXTENSION_URI
            ),
            None,
        )
        if vate_extension is None:
            return False, "SCHEMA_INVALID", check_results
        params = vate_extension.get("params")
        if not isinstance(params, dict):
            return False, "SCHEMA_INVALID", check_results
        profiles = params.get("profiles")
        if not isinstance(profiles, list) or PROFILE not in profiles:
            return False, "SCHEMA_INVALID", check_results
        binding = params.get("signed_agent_card_binding")
        if not isinstance(binding, dict):
            return False, "SCHEMA_INVALID", check_results
        if binding.get("mode") != "digest_bound_reference" or binding.get("evidence_type") != "signed_agent_card":
            return False, "SCHEMA_INVALID", check_results
    elif detached_payload.get("evidence_type") != evidence_type or detached_payload.get("issuer") != issuer:
        return False, "SCHEMA_INVALID", check_results
    trust_check = {
        "issuer_id": issuer,
        "kid": kid,
        "alg": alg,
        "evidence_type": evidence_type,
    }
    if "checked_at" in check:
        trust_check["checked_at"] = check.get("checked_at")
    trusted, failure_reason = evaluate_trust_check(
        trust_bundle,
        trust_check,
    )
    if not trusted:
        return False, failure_reason, check_results

    return True, None, check_results


def evaluate_linkage_checks(
    case: dict[str, Any],
    admission: dict[str, Any] | None,
    post_execution: dict[str, Any] | None,
) -> list[str]:
    failures: list[str] = []
    for index, check in enumerate(case.get("linkage_checks", [])):
        contract_failures = linkage_check_contract_failures(index, check)
        if contract_failures:
            failures.extend(contract_failures)
            continue
        violation, failure = linkage_check_violation(case, check, admission, post_execution)
        if failure:
            failures.append(f"linkage[{index}] {check.get('kind', 'unknown')}: {failure}")
        expected_violation = expected_linkage_violation(check)
        if violation != expected_violation:
            failures.append(
                f"linkage[{index}] {check.get('kind', 'unknown')}: "
                f"expected violation={expected_violation} actual violation={violation}"
            )
    return failures


def evaluate_policy_snapshot_checks(
    case: dict[str, Any],
    admission: dict[str, Any] | None,
    a2a_metadata: dict[str, Any] | None,
) -> list[str]:
    failures: list[str] = []
    for check in case.get("policy_snapshot_checks", []):
        artifact_name = check["artifact"]
        artifact, artifact_failure = read_case_artifact(case, artifact_name)
        if artifact_failure:
            failures.append(f"policy_snapshot {artifact_name}: {artifact_failure}")
            continue
        artifact_digest = {
            "alg": "sha-256",
            "value": sha256_value(artifact),
        }
        expect_match = bool(check.get("expect_match", True))
        reference_paths = check.get(
            "reference_paths",
            [
                {
                    "artifact": "admission_receipt",
                    "path": "policy.policy_snapshot",
                }
            ],
        )

        references: list[tuple[str, dict[str, Any]]] = []
        for reference in reference_paths:
            artifact_name = reference["artifact"]
            if artifact_name == "admission_receipt":
                source = admission
            elif artifact_name == "a2a_metadata":
                source = a2a_metadata
            else:
                failures.append(f"policy_snapshot {artifact_name}: unsupported reference artifact")
                continue
            if source is None:
                failures.append(f"policy_snapshot {artifact_name}: artifact missing")
                continue
            try:
                snapshot_ref = get_path(source, reference["path"])
            except (KeyError, IndexError, TypeError, ValueError):
                failures.append(f"policy_snapshot {artifact_name}: reference path missing")
                continue
            if not isinstance(snapshot_ref, dict):
                failures.append(
                    f"policy_snapshot {artifact_name}: reference path must resolve to an object"
                )
                continue
            references.append((artifact_name, snapshot_ref))

            digest_matches = snapshot_ref.get("digest") == artifact_digest
            if digest_matches != expect_match:
                failures.append(
                    f"policy_snapshot {artifact_name}: expected digest match={expect_match} actual match={digest_matches}"
                )

        if len(references) < 2:
            continue

        first_name, first_ref = references[0]
        for name, snapshot_ref in references[1:]:
            for field in check.get("compare_fields", ["uri", "media_type", "digest"]):
                if first_ref.get(field) != snapshot_ref.get(field):
                    failures.append(f"policy_snapshot {first_name}/{name}: field {field} mismatch")
    return failures


def evaluate_artifact_reference_checks(
    case: dict[str, Any],
    admission_request: dict[str, Any] | None,
    admission: dict[str, Any] | None,
    post_execution: dict[str, Any] | None,
    a2a_metadata: dict[str, Any] | None,
) -> list[str]:
    failures: list[str] = []
    sources = {
        "admission_request": admission_request,
        "admission_receipt": admission,
        "post_execution_receipt": post_execution,
        "a2a_metadata": a2a_metadata,
    }
    for check in case.get("artifact_reference_checks", []):
        artifact_name = check["artifact"]
        artifact, artifact_failure = read_case_artifact(case, artifact_name)
        if artifact_failure:
            failures.append(f"artifact_ref {artifact_name}: {artifact_failure}")
            continue
        artifact_digest = {
            "alg": "sha-256",
            "value": sha256_value(artifact),
        }
        expect_match = bool(check.get("expect_match", True))
        for reference in check.get("reference_paths", []):
            source_name = reference["artifact"]
            source = sources.get(source_name)
            if source is None:
                failures.append(f"artifact_ref {artifact_name}/{source_name}: artifact missing")
                continue
            try:
                reference_digest = get_path(source, reference["path"])
            except (KeyError, IndexError, TypeError, ValueError):
                failures.append(f"artifact_ref {artifact_name}/{source_name}: reference path missing")
                continue
            digest_matches = reference_digest == artifact_digest
            if digest_matches != expect_match:
                failures.append(
                    f"artifact_ref {artifact_name}/{source_name}: "
                    f"expected digest match={expect_match} actual match={digest_matches}"
                )
    return failures


def evaluate_attenuation_checks(case: dict[str, Any], admission: dict[str, Any] | None) -> list[str]:
    failures: list[str] = []
    if admission is not None:
        if actual_decision(admission) == "attenuate":
            for failure in attenuation_validation_failures(
                admission.get("attenuation"),
                decision_reason_codes=actual_reason_codes(admission),
            ):
                failures.append(f"attenuation: {failure}")
        elif "attenuation" in admission:
            failures.append("attenuation: must be absent unless decision.outcome is attenuate")

    for check in case.get("attenuation_checks", []):
        artifact_name = check["artifact"]
        artifact, artifact_failure = read_case_artifact(case, artifact_name)
        if artifact_failure:
            failures.append(f"attenuation {artifact_name}: {artifact_failure}")
            continue
        source_path = check.get("source_path")
        if source_path:
            try:
                artifact = get_path(artifact, source_path)
            except (KeyError, IndexError, TypeError, ValueError):
                failures.append(f"attenuation {check['artifact']}: source path missing")
                continue

        validation_failures = attenuation_validation_failures(artifact)
        valid = not validation_failures
        expect_valid = bool(check.get("expect_valid", True))
        if valid != expect_valid:
            failures.append(
                f"attenuation {check['artifact']}: expected valid={expect_valid} actual valid={valid}"
            )

        expected_failure = check.get("expected_failure_reason")
        actual_failure = attenuation_failure_reason(validation_failures)
        if expected_failure and actual_failure != expected_failure:
            failures.append(
                f"attenuation {check['artifact']}: expected failure={expected_failure} actual failure={actual_failure}"
            )
    return failures


def evaluate_evidence_vocabulary_checks(
    admission_request: dict[str, Any] | None,
    admission: dict[str, Any] | None,
) -> list[str]:
    failures: list[str] = []
    if admission_request is not None:
        evidence_refs = admission_request.get("evidence_refs", [])
        if not isinstance(evidence_refs, list):
            failures.append("admission_request.evidence_refs: expected array")
        for index, evidence_ref in enumerate(evidence_refs if isinstance(evidence_refs, list) else []):
            failures.extend(
                validate_evidence_vocab_object(
                    evidence_ref,
                    label=f"admission_request.evidence_refs[{index}]",
                )
            )
    if admission is not None:
        evidence_items = admission.get("evidence", [])
        if not isinstance(evidence_items, list):
            failures.append("admission_receipt.evidence: expected array")
        for index, evidence in enumerate(evidence_items if isinstance(evidence_items, list) else []):
            failures.extend(
                validate_evidence_vocab_object(
                    evidence,
                    label=f"admission_receipt.evidence[{index}]",
                )
            )
    return failures


def validate_evidence_vocab_object(value: Any, *, label: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{label}: expected object"]
    failures: list[str] = []
    evidence_type = value.get("type")
    if not isinstance(evidence_type, str) or not evidence_type:
        failures.append(f"{label}.type must be a non-empty string")
    elif evidence_type not in CANONICAL_EVIDENCE_TYPES:
        failures.append(f"{label}.type is not in the canonical evidence type registry")

    protocol_hint = value.get("protocol_hint")
    if protocol_hint is not None:
        if not isinstance(protocol_hint, str) or not protocol_hint:
            failures.append(f"{label}.protocol_hint must be a non-empty string")
        elif protocol_hint not in CANONICAL_PROTOCOL_HINTS:
            failures.append(f"{label}.protocol_hint is not in the canonical protocol hint registry")
        elif is_string_enum(evidence_type, CANONICAL_EVIDENCE_TYPES):
            allowed_hints = ALLOWED_PROTOCOL_HINTS_BY_TYPE.get(evidence_type, frozenset())
            if protocol_hint not in allowed_hints:
                failures.append(f"{label}.protocol_hint is not allowed for evidence type {evidence_type}")
    return failures


def evaluate_al2_context_checks(case: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    checks = case.get("al2_context_checks", [])
    raw_sut_inputs = case.get("sut_inputs")
    sut_inputs = raw_sut_inputs if isinstance(raw_sut_inputs, list) else []
    status_artifacts = {
        check.get("artifact")
        for check in checks
        if isinstance(check, dict)
        and check.get("kind") == "status"
        and isinstance(check.get("artifact"), str)
    }
    status_artifacts.update(
        item.get("artifact")
        for item in sut_inputs
        if isinstance(item, dict)
        and item.get("role") == "status_evidence"
        and isinstance(item.get("artifact"), str)
    )
    for check in checks:
        artifact_name = check["artifact"]
        artifact, artifact_failure = read_case_artifact(case, artifact_name)
        if artifact_failure:
            failures.append(f"al2_context {artifact_name}: {artifact_failure}")
            continue
        kind = check.get("kind")
        if kind == "freshness":
            failures.extend(
                evaluate_context_freshness_check(
                    check,
                    artifact,
                    require_status_context=artifact_name in status_artifacts,
                )
            )
        elif kind == "binding":
            failures.extend(evaluate_context_binding_check(check, artifact))
        elif kind == "replay":
            failures.extend(evaluate_context_replay_check(check, artifact))
        elif kind == "status":
            failures.extend(evaluate_context_status_check(check, artifact))
        else:
            failures.append(f"al2_context {check.get('artifact')}: unsupported kind {kind}")
    return failures


def status_context_shape_failures(artifact: Any, label: str) -> list[str]:
    if not isinstance(artifact, dict):
        return [f"{label}: expected status context object"]

    failures: list[str] = []
    allowed_fields = {
        "version",
        "source",
        "required",
        "availability",
        "status",
        "source_issued_at",
        "checked_at",
        "max_age_seconds",
    }
    for field in sorted(set(artifact) - allowed_fields):
        failures.append(f"{label}.{field}: unsupported status context field")
    if artifact.get("version") != STATUS_CONTEXT_VERSION:
        failures.append(
            f"{label}.version: expected {STATUS_CONTEXT_VERSION} actual {artifact.get('version')}"
        )
    if artifact.get("source") != "status_bundle":
        failures.append(
            f"{label}.source: expected status_bundle actual {artifact.get('source')}"
        )
    if not isinstance(artifact.get("required"), bool):
        failures.append(f"{label}.required: expected boolean")

    availability = artifact.get("availability")
    if not is_string_enum(availability, {"available", "unavailable"}):
        failures.append(f"{label}.availability: expected available or unavailable")
    if try_parse_time(artifact.get("checked_at")) is None:
        failures.append(f"{label}.checked_at: expected valid timestamp")

    has_source_issued_at = "source_issued_at" in artifact
    if has_source_issued_at and try_parse_time(artifact.get("source_issued_at")) is None:
        failures.append(f"{label}.source_issued_at: expected valid timestamp when present")
    has_max_age_seconds = "max_age_seconds" in artifact
    max_age_seconds = artifact.get("max_age_seconds")
    if has_max_age_seconds and (
        isinstance(max_age_seconds, bool)
        or not isinstance(max_age_seconds, int)
        or max_age_seconds < 0
    ):
        failures.append(f"{label}.max_age_seconds: expected non-negative integer when present")

    if availability == "available":
        if not is_string_enum(artifact.get("status"), {"active", "revoked"}):
            failures.append(f"{label}.status: available context requires active or revoked")
        if not has_source_issued_at:
            failures.append(f"{label}.source_issued_at: available context requires timestamp")
        if not has_max_age_seconds:
            failures.append(f"{label}.max_age_seconds: available context requires integer")
    elif availability == "unavailable" and "status" in artifact:
        failures.append(f"{label}.status: unavailable context must not carry a status value")

    return failures


def evaluate_context_status_check(check: dict[str, Any], artifact: dict[str, Any]) -> list[str]:
    failures = status_context_shape_failures(
        artifact,
        f"al2_context {check['artifact']}",
    )
    if failures:
        return failures
    expected_status = check.get("expect_status")
    expected_required = check.get("expect_required")
    availability = artifact.get("availability")
    required = artifact.get("required")

    if not is_string_enum(
        expected_status,
        {"active", "revoked", "unavailable"},
    ):
        failures.append(
            f"al2_context {check['artifact']}: status check requires a supported expect_status"
        )
    if not isinstance(expected_required, bool):
        failures.append(
            f"al2_context {check['artifact']}: status check requires boolean expect_required"
        )
    if not is_string_enum(availability, {"available", "unavailable"}):
        failures.append(
            f"al2_context {check['artifact']}: availability must be available or unavailable"
        )
    if not isinstance(required, bool):
        failures.append(f"al2_context {check['artifact']}: required must be boolean")
    if failures:
        return failures

    if availability == "available":
        actual_status = artifact.get("status")
        if not is_string_enum(actual_status, {"active", "revoked"}):
            failures.append(
                f"al2_context {check['artifact']}: available status must be active or revoked"
            )
    else:
        actual_status = "unavailable"
        if "status" in artifact:
            failures.append(
                f"al2_context {check['artifact']}: unavailable status must not carry a status value"
            )

    if actual_status != expected_status:
        failures.append(
            f"al2_context {check['artifact']}: expected status={expected_status} actual status={actual_status}"
        )
    if required != expected_required:
        failures.append(
            f"al2_context {check['artifact']}: expected required={expected_required} actual required={required}"
        )

    expected_failure = check.get("expected_failure_reason")
    if actual_status == "revoked":
        actual_failure = "STATUS_REVOKED"
    elif actual_status == "unavailable" and required:
        actual_failure = "STATUS_UNAVAILABLE"
    else:
        actual_failure = None
    if expected_failure is not None and actual_failure != expected_failure:
        failures.append(
            f"al2_context {check['artifact']}: expected failure={expected_failure} actual failure={actual_failure}"
        )
    if expected_failure is None and actual_failure is not None:
        failures.append(
            f"al2_context {check['artifact']}: unexpected derived failure={actual_failure}"
        )
    return failures


def sut_input_contract_failures(case: dict[str, Any]) -> list[str]:
    raw_context_checks = case.get("al2_context_checks")
    status_artifacts = {
        check.get("artifact")
        for check in raw_context_checks
        if isinstance(check, dict)
        and check.get("kind") == "status"
        and isinstance(check.get("artifact"), str)
        and check.get("artifact")
    } if isinstance(raw_context_checks, list) else set()

    artifacts = case.get("artifacts")
    if not isinstance(artifacts, dict):
        if "sut_inputs" in case or status_artifacts:
            return ["sut_inputs: case artifacts must be an object"]
        return ["artifacts: expected object"]
    if "sut_inputs" not in case:
        if status_artifacts:
            return ["sut_inputs: required for cases with status context checks"]
        return []
    raw_inputs = case["sut_inputs"]
    if not isinstance(raw_inputs, list) or not raw_inputs:
        return ["sut_inputs: expected non-empty array"]

    failures: list[str] = []
    seen: dict[tuple[str, str], int] = {}
    for index, item in enumerate(raw_inputs):
        label = f"sut_inputs[{index}]"
        if not isinstance(item, dict):
            failures.append(f"{label}: expected object")
            continue
        for field in sorted(set(item) - {"artifact", "role", "media_type"}):
            failures.append(f"{label}.{field}: unsupported SUT input field")
        artifact_name = item.get("artifact")
        role = item.get("role")
        media_type = item.get("media_type")
        if not isinstance(artifact_name, str) or not artifact_name:
            failures.append(f"{label}.artifact: expected non-empty string")
        elif not isinstance(artifacts.get(artifact_name), str):
            failures.append(f"{label}.artifact: missing string artifact path for {artifact_name}")
        if not isinstance(role, str) or not role:
            failures.append(f"{label}.role: expected non-empty string")
        if not isinstance(media_type, str) or not media_type:
            failures.append(f"{label}.media_type: expected non-empty string")
        if isinstance(artifact_name, str) and artifact_name and isinstance(role, str) and role:
            key = (artifact_name, role)
            first_index = seen.get(key)
            if first_index is not None:
                failures.append(
                    f"{label}: duplicate logical input artifact={artifact_name} role={role}; "
                    f"first used at index {first_index}"
                )
            else:
                seen[key] = index
    for artifact_name in sorted(status_artifacts):
        if (artifact_name, "status_evidence") not in seen:
            failures.append(
                "sut_inputs: status context check requires "
                f"artifact={artifact_name} role=status_evidence"
            )
    return failures


def corpus_sut_input_contract_failures(corpus_root: Path) -> list[str]:
    case_records, case_load_failures = load_corpus_case_records(corpus_root)
    failures: list[str] = list(case_load_failures)
    for case_path, case in case_records:
        case_id = case.get("case_id")
        label = case_id if isinstance(case_id, str) and case_id else display_path(case_path.resolve())
        for failure in sut_input_contract_failures(case):
            failures.append(f"{label}.{failure}")
    return failures


def evaluate_context_freshness_check(
    check: dict[str, Any],
    artifact: dict[str, Any],
    *,
    require_status_context: bool = False,
) -> list[str]:
    checked_at = try_parse_time(artifact.get("checked_at"))
    source_issued_at = try_parse_time(artifact.get("source_issued_at"))
    max_age_seconds = artifact.get("max_age_seconds", check.get("max_age_seconds"))
    is_status_context = require_status_context or artifact.get("version") == STATUS_CONTEXT_VERSION
    failures: list[str] = (
        status_context_shape_failures(artifact, f"al2_context {check['artifact']}")
        if is_status_context
        else []
    )
    if not isinstance(check.get("expect_fresh"), bool):
        failures.append(f"al2_context {check['artifact']}: freshness check requires boolean expect_fresh")
    if checked_at is None or source_issued_at is None:
        failures.append(f"al2_context {check['artifact']}: freshness timestamps must be valid")
    if isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int) or max_age_seconds < 0:
        failures.append(f"al2_context {check['artifact']}: max_age_seconds must be a non-negative integer")
    if is_status_context and artifact.get("availability") != "available":
        failures.append(
            f"al2_context {check['artifact']}: freshness requires availability=available"
        )
    if failures:
        return failures
    age_seconds = (checked_at - source_issued_at).total_seconds()
    fresh = 0 <= age_seconds <= max_age_seconds
    expect_fresh = check["expect_fresh"]
    if fresh != expect_fresh:
        failures.append(f"al2_context {check['artifact']}: expected fresh={expect_fresh} actual fresh={fresh}")
    if not fresh and is_status_context:
        actual_failure = "STATUS_STALE"
    else:
        actual_failure = artifact.get("failure_reason") if not fresh else None
    expected_failure = check.get("expected_failure_reason")
    if expected_failure and actual_failure != expected_failure:
        failures.append(
            f"al2_context {check['artifact']}: expected failure={expected_failure} actual failure={actual_failure}"
        )
    return failures


def evaluate_context_binding_check(check: dict[str, Any], artifact: dict[str, Any]) -> list[str]:
    expected_value = artifact.get("expected")
    actual_value = artifact.get("actual")
    matched = expected_value == actual_value
    failures: list[str] = []
    if not isinstance(check.get("expect_match"), bool):
        failures.append(f"al2_context {check['artifact']}: binding check requires boolean expect_match")
    if not isinstance(expected_value, str) or not expected_value or not isinstance(actual_value, str) or not actual_value:
        failures.append(f"al2_context {check['artifact']}: binding values must be non-empty strings")
    if failures:
        return failures
    expect_match = check["expect_match"]
    if matched != expect_match:
        failures.append(f"al2_context {check['artifact']}: expected match={expect_match} actual match={matched}")
    actual_failure = artifact.get("failure_reason") if not matched else None
    expected_failure = check.get("expected_failure_reason")
    if expected_failure and actual_failure != expected_failure:
        failures.append(
            f"al2_context {check['artifact']}: expected failure={expected_failure} actual failure={actual_failure}"
        )
    return failures


def evaluate_context_replay_check(check: dict[str, Any], artifact: dict[str, Any]) -> list[str]:
    replay_key = artifact.get("replay_key")
    nonce = artifact.get("nonce")
    state = artifact.get("state")
    failures: list[str] = []
    if not isinstance(check.get("expect_replayed"), bool):
        failures.append(f"al2_context {check['artifact']}: replay check requires boolean expect_replayed")
    if not isinstance(replay_key, str) or not replay_key or not isinstance(nonce, str) or not nonce:
        failures.append(f"al2_context {check['artifact']}: replay_key and nonce must be non-empty strings")
    if not is_string_enum(state, {"unused", "consumed", "replayed"}):
        failures.append(f"al2_context {check['artifact']}: replay state must be unused, consumed, or replayed")
    if failures:
        return failures
    expect_replayed = check["expect_replayed"]
    replayed = is_string_enum(state, {"consumed", "replayed"})
    if replayed != expect_replayed:
        failures.append(f"al2_context {check['artifact']}: expected replayed={expect_replayed} actual replayed={replayed}")
    actual_failure = artifact.get("failure_reason") if replayed else None
    expected_failure = check.get("expected_failure_reason")
    if expected_failure and actual_failure != expected_failure:
        failures.append(
            f"al2_context {check['artifact']}: expected failure={expected_failure} actual failure={actual_failure}"
        )
    return failures


def evaluate_case(case_path: Path) -> dict[str, Any]:
    case = read_json(case_path)
    admission_request = load_artifact(case, "admission_request")
    admission = load_artifact(case, "admission_receipt")
    post_execution = load_artifact(case, "post_execution_receipt")
    a2a_metadata = load_artifact(case, "a2a_metadata")

    expected_codes = [str(code) for code in case["expected"]["reason_codes"]]
    if case["category"] == "linkage":
        actual_codes = actual_linkage_reason_codes(case, admission, post_execution)
    else:
        actual_codes = actual_reason_codes(admission)
    expected = expected_outcome(case)
    actual = observed_outcome(case, admission, post_execution)
    expected_execute = expected_should_execute(case)
    actual_execute = actual_should_execute(admission)
    jose_results, jose_failures = evaluate_jose_checks(case)

    failures: list[str] = []
    failures.extend(
        directly_dereferenced_artifact_failures(admission, post_execution)
    )
    if actual != expected:
        failures.append(f"outcome: expected {expected} actual {actual}")
    if actual_execute != expected_execute:
        failures.append(f"should_execute: expected {expected_execute} actual {actual_execute}")
    if actual_codes != expected_codes:
        failures.append(f"reason_codes: expected {expected_codes} actual {actual_codes}")
    failures.extend(reason_code_order_failures(expected_codes, expected, label="expected_reason_codes"))
    failures.extend(reason_code_order_failures(actual_codes, actual, label="actual_reason_codes"))

    for check in case["expected"].get("checks", []):
        if not evaluate_expected_check(
            name=check["name"],
            expected=check["expected"],
            admission=admission,
            post_execution=post_execution,
            a2a_metadata=a2a_metadata,
            jose_results=jose_results,
        ):
            failures.append(f"check {check['name']}: expected {check['expected']}")

    failures.extend(evaluate_integrity_checks(case))
    failures.extend(evaluate_trust_checks(case))
    failures.extend(jose_failures)
    failures.extend(evaluate_linkage_checks(case, admission, post_execution))
    failures.extend(post_execution_policy_violation_token_failures(post_execution))
    failures.extend(evaluate_policy_snapshot_checks(case, admission, a2a_metadata))
    failures.extend(evaluate_artifact_reference_checks(case, admission_request, admission, post_execution, a2a_metadata))
    failures.extend(evaluate_attenuation_checks(case, admission))
    failures.extend(evaluate_evidence_vocabulary_checks(admission_request, admission))
    failures.extend(evaluate_al2_context_checks(case))
    failures.extend(sut_input_contract_failures(case))

    return {
        "case_id": case["case_id"],
        "category": case["category"],
        "expected_outcome": expected,
        "actual_outcome": actual,
        "expected_should_execute": expected_execute,
        "actual_should_execute": actual_execute,
        "expected_primary_reason_code": primary_reason_code(expected_codes),
        "actual_primary_reason_code": primary_reason_code(actual_codes),
        "expected_reason_codes": expected_codes,
        "actual_reason_codes": actual_codes,
        "pass": not failures,
        "failures": failures,
    }


def run_corpus(corpus_root: Path) -> dict[str, Any]:
    case_paths = sorted((corpus_root / "cases").glob("*.json"))
    _, case_load_failures = load_corpus_case_records(corpus_root)
    input_contract_failures = corpus_sut_input_contract_failures(corpus_root)
    cases = (
        []
        if case_load_failures or input_contract_failures
        else [evaluate_case(path) for path in case_paths]
    )
    manifest, digest, manifest_failures = corpus_manifest(corpus_root)
    fatal_errors = list(
        dict.fromkeys(
            case_load_failures
            + corpus_pairing_failures(corpus_root)
            + input_contract_failures
            + manifest_failures
        )
    )
    failed = sum(1 for item in cases if not item["pass"])
    report = {
        "version": CONFORMANCE_REPORT_VERSION,
        "profile": PROFILE,
        "checked_at": iso_now(),
        "summary": {
            "total": len(cases),
            "passed": len(cases) - failed,
            "failed": failed,
            "skipped": 0,
        },
        "corpus": {
            "name": corpus_root.name,
            "root": display_path(corpus_root.resolve()),
            "artifact_count": len(manifest),
            "digest": digest,
        },
        "cases": cases,
    }
    if not case_paths:
        fatal_errors.append("no conformance case files found")
    if fatal_errors:
        report["fatal_errors"] = fatal_errors
    return report


def load_case_expectations(corpus_root: Path) -> list[dict[str, Any]]:
    expectations: list[dict[str, Any]] = []
    case_records, _ = load_corpus_case_records(corpus_root)
    for _, case in case_records:
        expected_reason_codes = [str(code) for code in case["expected"]["reason_codes"]]
        expectations.append(
            {
                "case_id": case["case_id"],
                "category": case["category"],
                "expected_outcome": expected_outcome(case),
                "expected_should_execute": expected_should_execute(case),
                "expected_primary_reason_code": primary_reason_code(expected_reason_codes),
                "expected_reason_codes": expected_reason_codes,
                "expected_checks": [
                    {
                        "name": check["name"],
                        "expected": check["expected"],
                    }
                    for check in case["expected"].get("checks", [])
                ],
                "required_artifacts": required_sut_artifacts(case),
                "case": case,
            }
        )
    return expectations


def required_sut_artifacts(case: dict[str, Any]) -> dict[str, Any]:
    artifacts = case_artifacts(case)
    input_artifacts: list[dict[str, str | None]] = []
    if "sut_inputs" in case:
        raw_explicit_inputs = case["sut_inputs"]
        explicit_inputs = raw_explicit_inputs if isinstance(raw_explicit_inputs, list) else []
        for item in explicit_inputs:
            if not isinstance(item, dict):
                continue
            artifact_name = item.get("artifact")
            role = item.get("role")
            media_type = item.get("media_type")
            if (
                isinstance(artifact_name, str)
                and artifact_name
                and isinstance(role, str)
                and role
                and isinstance(media_type, str)
                and media_type
            ):
                input_artifacts.append(
                    {
                        "case_artifact": artifact_name,
                        "role": role,
                        "expected_uri": artifacts.get(artifact_name),
                        "expected_media_type": media_type,
                        "expected_digest": case_artifact_sha256(case, artifact_name),
                    }
                )

        return {
            "input_artifacts": input_artifacts,
            "receipt_artifacts": [],
            "verification_context": [],
            "proof_artifacts": [],
        }

    receipt_artifacts: list[dict[str, str]] = []
    for artifact_name in ("admission_receipt", "post_execution_receipt"):
        if isinstance(artifacts, dict) and artifact_name in artifacts:
            receipt_artifacts.append(
                {
                    "name": artifact_name,
                    "expected_digest": case_artifact_sha256(case, artifact_name),
                }
            )

    context_artifacts: list[dict[str, str]] = []
    for check in case.get("al2_context_checks", []):
        if not isinstance(check, dict):
            continue
        artifact_name = check.get("artifact")
        kind = check.get("kind")
        if isinstance(artifact_name, str) and artifact_name and isinstance(kind, str) and kind:
            context_artifacts.append(
                {
                    "case_artifact": artifact_name,
                    "kind": kind,
                    "expected_digest": case_artifact_sha256(case, artifact_name),
                    "context_bindings": required_context_bindings(case, check),
                }
            )

    proof_artifacts: list[dict[str, str]] = []
    jose_artifact_kinds = {
        "proof_package": "jose_proof_package",
        "detached_payload": "jose_detached_payload",
        "trust_bundle": "jose_trust_bundle",
    }
    for check in case.get("jose_checks", []):
        if not isinstance(check, dict):
            continue
        for field, kind in jose_artifact_kinds.items():
            artifact_name = check.get(field)
            if isinstance(artifact_name, str) and artifact_name:
                proof_artifacts.append(
                    {
                        "case_artifact": artifact_name,
                        "kind": kind,
                        "expected_digest": case_artifact_sha256(case, artifact_name),
                    }
                )

    return {
        "input_artifacts": input_artifacts,
        "receipt_artifacts": receipt_artifacts,
        "verification_context": context_artifacts,
        "proof_artifacts": proof_artifacts,
    }


def artifact_file_binding(
    case: dict[str, Any],
    role: str,
    source_artifact: str,
) -> dict[str, Any] | None:
    digest = case_artifact_sha256(case, source_artifact)
    if digest is None:
        return None
    return {
        "role": role,
        "source_artifact": source_artifact,
        "digest": {
            "alg": "sha-256",
            "value": digest,
        },
    }


def value_binding(artifact: dict[str, Any], role: str, source_artifact: str, path: str) -> dict[str, Any] | None:
    try:
        value = get_path(artifact, path)
    except (KeyError, IndexError, TypeError, ValueError):
        return None
    if not isinstance(value, str) or not value:
        return None
    return {
        "role": role,
        "source_artifact": source_artifact,
        "path": path,
        "value": value,
    }


def evidence_bindings(artifact: dict[str, Any], source_artifact: str, path: str, evidence_type: str) -> list[dict[str, Any]]:
    try:
        items = get_path(artifact, path)
    except (KeyError, IndexError, TypeError, ValueError):
        return []
    if not isinstance(items, list):
        return []
    bindings: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict) or item.get("type") != evidence_type:
            continue
        bindings.append(
            {
                "role": "evidence",
                "source_artifact": source_artifact,
                "path": f"{path}[{index}]",
                "evidence_type": evidence_type,
                "digest": digest_descriptor(item),
            }
        )
    return bindings


def context_evidence_type(context_artifact: dict[str, Any], check_kind: Any) -> str | None:
    source = context_artifact.get("source")
    if is_string_enum(source, {"runtime_attestation", "status_bundle"}):
        return source
    if check_kind == "binding" and context_artifact.get("binding") == "runtime":
        return "runtime_attestation"
    if check_kind == "replay":
        return "admission_request"
    return None


def append_binding_once(bindings: list[dict[str, Any]], binding: dict[str, Any] | None) -> None:
    if binding is not None and binding not in bindings:
        bindings.append(binding)


def required_context_bindings(case: dict[str, Any], check: dict[str, Any]) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    artifacts = case_artifacts(case)

    admission_receipt = load_artifact(case, "admission_receipt")
    admission_request = load_artifact(case, "admission_request")
    if isinstance(artifacts, dict) and "admission_receipt" in artifacts and admission_receipt is not None:
        append_binding_once(bindings, artifact_file_binding(case, "admission_receipt", "admission_receipt"))
        append_binding_once(
            bindings,
            value_binding(admission_receipt, "transaction_id", "admission_receipt", "request.transaction_id"),
        )
    if isinstance(artifacts, dict) and "admission_request" in artifacts and admission_request is not None:
        append_binding_once(bindings, artifact_file_binding(case, "admission_request", "admission_request"))

    context_artifact_name = check.get("artifact")
    context_artifact, _ = (
        read_case_artifact(case, context_artifact_name)
        if isinstance(context_artifact_name, str) and context_artifact_name
        else ({}, None)
    )
    if not isinstance(context_artifact, dict):
        context_artifact = {}
    if check.get("kind") == "binding" and admission_receipt is not None:
        append_binding_once(
            bindings,
            value_binding(admission_receipt, "runtime", "admission_receipt", "subject.runtime"),
        )

    evidence_type = context_evidence_type(context_artifact, check.get("kind"))
    if evidence_type and admission_receipt is not None:
        for binding in evidence_bindings(admission_receipt, "admission_receipt", "evidence", evidence_type):
            append_binding_once(bindings, binding)
    if evidence_type and admission_request is not None:
        for binding in evidence_bindings(admission_request, "admission_request", "evidence_refs", evidence_type):
            append_binding_once(bindings, binding)
    return bindings


def digest_descriptor_failures(value: Any, label: str) -> list[str]:
    failures: list[str] = []
    if not isinstance(value, dict):
        return [f"{label}: expected digest object"]
    if value.get("alg") != "sha-256":
        failures.append(f"{label}.alg: expected sha-256 actual {value.get('alg')}")
    digest_value = value.get("value")
    if not isinstance(digest_value, str) or not SHA256_HEX_RE.fullmatch(digest_value):
        failures.append(f"{label}.value: expected lowercase sha-256 hex digest")
    return failures


def sut_artifact_ref_failures(value: Any, label: str, *, require_media_type: bool) -> list[str]:
    failures: list[str] = []
    if not isinstance(value, dict):
        return [f"{label}: expected artifact reference object"]
    uri = value.get("uri")
    if not isinstance(uri, str) or not uri:
        failures.append(f"{label}.uri: expected non-empty string")
    media_type = value.get("media_type")
    if require_media_type and (not isinstance(media_type, str) or not media_type):
        failures.append(f"{label}.media_type: expected non-empty string")
    elif media_type is not None and not isinstance(media_type, str):
        failures.append(f"{label}.media_type: expected string when present")
    failures.extend(digest_descriptor_failures(value.get("digest"), f"{label}.digest"))
    return failures


def sut_artifact_digest_match_failures(value: Any, label: str, expected_digest: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    digest = value.get("digest")
    if not isinstance(digest, dict):
        return []
    actual_digest = digest.get("value")
    if not isinstance(expected_digest, str):
        return [f"{label}.digest.value: missing expected corpus digest"]
    if actual_digest != expected_digest:
        return [f"{label}.digest.value: expected corpus digest {expected_digest} actual {actual_digest}"]
    return []


def sut_verification_context_failures(value: Any, label: str) -> list[str]:
    failures = sut_artifact_ref_failures(value, label, require_media_type=False)
    if not isinstance(value, dict):
        return failures
    kind = value.get("kind")
    if not isinstance(kind, str) or not kind:
        failures.append(f"{label}.kind: expected non-empty string")
    case_artifact = value.get("case_artifact")
    if not isinstance(case_artifact, str) or not case_artifact:
        failures.append(f"{label}.case_artifact: expected non-empty string")
    raw_bindings = value.get("context_bindings")
    if not isinstance(raw_bindings, list) or not raw_bindings:
        failures.append(f"{label}.context_bindings: expected non-empty array")
    else:
        seen_binding_keys: dict[
            tuple[str, str, str | None, str | None], int
        ] = {}
        for index, binding in enumerate(raw_bindings):
            binding_label = f"{label}.context_bindings[{index}]"
            key, shape_failures = validated_context_binding_key(
                binding,
                binding_label,
            )
            failures.extend(shape_failures)
            if key is None:
                continue
            first_index = seen_binding_keys.get(key)
            if first_index is not None:
                failures.append(
                    f"{binding_label}: duplicate logical binding key "
                    f"role={key[0]} source_artifact={key[1]} path={key[2]} "
                    f"evidence_type={key[3]}; first used at index {first_index}"
                )
            else:
                seen_binding_keys[key] = index
    return failures


def context_binding_shape_failures(value: Any, label: str) -> list[str]:
    _, failures = validated_context_binding_key(value, label)
    return failures


def validated_context_binding_key(
    value: Any,
    label: str,
) -> tuple[
    tuple[str, str, str | None, str | None] | None,
    list[str],
]:
    """Validate a context binding and return only a hash-safe logical key."""
    failures: list[str] = []
    if not isinstance(value, dict):
        return None, [f"{label}: expected object"]
    role = value.get("role")
    if not isinstance(role, str) or role not in {
        "admission_receipt",
        "admission_request",
        "transaction_id",
        "runtime",
        "evidence",
    }:
        failures.append(f"{label}.role: expected known context binding role")
    source_artifact = value.get("source_artifact")
    if not isinstance(source_artifact, str) or not source_artifact:
        failures.append(f"{label}.source_artifact: expected non-empty string")

    requires_digest = isinstance(role, str) and role in {
        "admission_receipt",
        "admission_request",
        "evidence",
    }
    if "digest" in value or requires_digest:
        failures.extend(
            digest_descriptor_failures(value.get("digest"), f"{label}.digest")
        )

    requires_path = isinstance(role, str) and role in {
        "transaction_id",
        "runtime",
        "evidence",
    }
    path = value.get("path") if "path" in value else None
    if "path" in value or requires_path:
        if not isinstance(path, str) or not path:
            failures.append(f"{label}.path: expected non-empty string")

    requires_value = isinstance(role, str) and role in {
        "transaction_id",
        "runtime",
    }
    bound_value = value.get("value") if "value" in value else None
    if "value" in value or requires_value:
        if not isinstance(bound_value, str) or not bound_value:
            failures.append(f"{label}.value: expected non-empty string")

    requires_evidence_type = role == "evidence"
    evidence_type = (
        value.get("evidence_type") if "evidence_type" in value else None
    )
    if "evidence_type" in value or requires_evidence_type:
        if not isinstance(evidence_type, str) or not evidence_type:
            failures.append(
                f"{label}.evidence_type: expected non-empty string"
            )

    if failures:
        return None, failures
    assert isinstance(role, str)
    assert isinstance(source_artifact, str)
    return (role, source_artifact, path, evidence_type), []


def context_binding_match_failures(
    actual_bindings: Any,
    expected_bindings: list[dict[str, Any]],
    label: str,
) -> list[str]:
    if not expected_bindings:
        return []
    if not isinstance(actual_bindings, list):
        return [f"{label}: expected context binding array"]

    actual_by_key: dict[
        tuple[str, str, str | None, str | None], dict[str, Any]
    ] = {}
    duplicate_keys: set[tuple[str, str, str | None, str | None]] = set()
    for index, binding in enumerate(actual_bindings):
        key, _ = validated_context_binding_key(
            binding,
            f"{label}[{index}]",
        )
        if key is None or not isinstance(binding, dict):
            continue
        if key in actual_by_key:
            duplicate_keys.add(key)
        else:
            actual_by_key[key] = binding
    failures: list[str] = []
    for index, expected in enumerate(expected_bindings):
        key, key_failures = validated_context_binding_key(
            expected,
            f"{label}.expected[{index}]",
        )
        if key is None:
            failures.extend(key_failures)
            continue
        if key in duplicate_keys:
            continue
        actual = actual_by_key.get(key)
        if actual is None:
            failures.append(
                f"{label}: missing role={key[0]} source_artifact={key[1]} path={key[2]} evidence_type={key[3]}"
            )
            continue
        if "digest" in expected and actual.get("digest") != expected.get("digest"):
            failures.append(f"{label}: digest mismatch for role={key[0]} source_artifact={key[1]} path={key[2]}")
        if "value" in expected and actual.get("value") != expected.get("value"):
            failures.append(f"{label}: value mismatch for role={key[0]} source_artifact={key[1]} path={key[2]}")
    return failures


def sut_proof_artifact_failures(value: Any, label: str) -> list[str]:
    failures = sut_artifact_ref_failures(value, label, require_media_type=True)
    if not isinstance(value, dict):
        return failures
    kind = value.get("kind")
    if not isinstance(kind, str) or kind not in {
        "jose_proof_package",
        "jose_detached_payload",
        "jose_trust_bundle",
    }:
        failures.append(f"{label}.kind: expected JOSE proof artifact kind")
    case_artifact = value.get("case_artifact")
    if not isinstance(case_artifact, str) or not case_artifact:
        failures.append(f"{label}.case_artifact: expected non-empty string")
    return failures


def sut_input_artifact_failures(value: Any, label: str) -> list[str]:
    failures = sut_artifact_ref_failures(value, label, require_media_type=True)
    if not isinstance(value, dict):
        return failures
    allowed_fields = {"case_artifact", "role", "uri", "media_type", "digest"}
    for field in sorted(set(value) - allowed_fields):
        failures.append(f"{label}.{field}: unsupported input artifact field")
    digest = value.get("digest")
    if isinstance(digest, dict):
        for field in sorted(set(digest) - {"alg", "value"}):
            failures.append(f"{label}.digest.{field}: unsupported input digest field")
    case_artifact = value.get("case_artifact")
    role = value.get("role")
    if not isinstance(case_artifact, str) or not case_artifact:
        failures.append(f"{label}.case_artifact: expected non-empty string")
    if not isinstance(role, str) or not role:
        failures.append(f"{label}.role: expected non-empty string")
    return failures


def artifact_entries_by_logical_key(
    entries: list[Any],
    label: str,
) -> tuple[dict[tuple[str, str], dict[str, Any]], set[tuple[str, str]], list[str]]:
    available: dict[tuple[str, str], dict[str, Any]] = {}
    duplicate_keys: set[tuple[str, str]] = set()
    first_index_by_key: dict[tuple[str, str], int] = {}
    failures: list[str] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        case_artifact = entry.get("case_artifact")
        kind = entry.get("kind")
        if not isinstance(case_artifact, str) or not case_artifact:
            continue
        if not isinstance(kind, str) or not kind:
            continue
        key = (case_artifact, kind)
        first_index = first_index_by_key.get(key)
        if first_index is not None:
            duplicate_keys.add(key)
            failures.append(
                f"{label}[{index}]: duplicate logical artifact key "
                f"case_artifact={key[0]} kind={key[1]}; first used at index {first_index}"
            )
        else:
            first_index_by_key[key] = index
            available[key] = entry
    return available, duplicate_keys, failures


def sut_result_artifact_failures(result: dict[str, Any], requirements: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    required_inputs = [
        item for item in requirements.get("input_artifacts", [])
        if isinstance(item, dict)
        and isinstance(item.get("case_artifact"), str)
        and isinstance(item.get("role"), str)
    ]
    required_receipts = [
        receipt for receipt in requirements.get("receipt_artifacts", [])
        if isinstance(receipt, dict) and isinstance(receipt.get("name"), str)
    ]
    required_contexts = [
        context for context in requirements.get("verification_context", [])
        if isinstance(context, dict)
    ]
    required_proofs = [
        proof for proof in requirements.get("proof_artifacts", [])
        if isinstance(proof, dict)
    ]
    artifacts = result.get("artifacts")
    if (
        not required_inputs
        and isinstance(artifacts, dict)
        and "input_artifacts" in artifacts
    ):
        failures.append(
            "artifacts.input_artifacts: not allowed when the case does not declare authoritative sut_inputs"
        )
    if not required_inputs and not required_receipts and not required_contexts and not required_proofs:
        return failures

    if not isinstance(artifacts, dict):
        return ["artifacts: expected object with required artifact references"]

    if required_inputs:
        for key in sorted(set(artifacts) - {"input_artifacts"}):
            failures.append(
                f"artifacts.{key}: not allowed when the case declares authoritative sut_inputs"
            )

        raw_inputs = artifacts.get("input_artifacts")
        if not isinstance(raw_inputs, list) or not raw_inputs:
            failures.append("artifacts.input_artifacts: required non-empty array for this case")
            raw_inputs = []
        elif not all(isinstance(item, dict) for item in raw_inputs):
            failures.append("artifacts.input_artifacts: expected array of objects")
            raw_inputs = [item for item in raw_inputs if isinstance(item, dict)]

        actual_by_key: dict[tuple[str, str], dict[str, Any]] = {}
        duplicate_keys: set[tuple[str, str]] = set()
        for index, item in enumerate(raw_inputs):
            label = f"artifacts.input_artifacts[{index}]"
            failures.extend(sut_input_artifact_failures(item, label))
            if not isinstance(item, dict):
                continue
            case_artifact = item.get("case_artifact")
            role = item.get("role")
            if not isinstance(case_artifact, str) or not case_artifact:
                continue
            if not isinstance(role, str) or not role:
                continue
            key = (case_artifact, role)
            if key in actual_by_key:
                duplicate_keys.add(key)
                failures.append(
                    f"{label}: duplicate logical input artifact key "
                    f"case_artifact={case_artifact} role={role}"
                )
            else:
                actual_by_key[key] = item

        for expected_input in required_inputs:
            key = (expected_input["case_artifact"], expected_input["role"])
            if key in duplicate_keys:
                continue
            actual_input = actual_by_key.get(key)
            if actual_input is None:
                failures.append(
                    "artifacts.input_artifacts: "
                    f"missing case_artifact={key[0]} role={key[1]}"
                )
                continue
            failures.extend(
                sut_artifact_digest_match_failures(
                    actual_input,
                    f"artifacts.input_artifacts case_artifact={key[0]} role={key[1]}",
                    expected_input.get("expected_digest"),
                )
            )
            expected_uri = expected_input.get("expected_uri")
            if actual_input.get("uri") != expected_uri:
                failures.append(
                    "artifacts.input_artifacts: "
                    f"uri mismatch for case_artifact={key[0]} role={key[1]}; "
                    f"expected {expected_uri} actual {actual_input.get('uri')}"
                )
            expected_media_type = expected_input.get("expected_media_type")
            if actual_input.get("media_type") != expected_media_type:
                failures.append(
                    "artifacts.input_artifacts: "
                    f"media_type mismatch for case_artifact={key[0]} role={key[1]}; "
                    f"expected {expected_media_type} actual {actual_input.get('media_type')}"
                )

        expected_keys = {
            (expected_input["case_artifact"], expected_input["role"])
            for expected_input in required_inputs
        }
        for case_artifact, role in sorted(set(actual_by_key) - expected_keys):
            failures.append(
                "artifacts.input_artifacts: "
                f"unexpected case_artifact={case_artifact} role={role}"
            )

    for required_receipt in required_receipts:
        artifact_name = required_receipt["name"]
        label = f"artifacts.{artifact_name}"
        if artifact_name not in artifacts:
            failures.append(f"{label}: required for this case")
            continue
        artifact_ref = artifacts.get(artifact_name)
        failures.extend(sut_artifact_ref_failures(artifact_ref, label, require_media_type=True))
        failures.extend(
            sut_artifact_digest_match_failures(
                artifact_ref,
                label,
                required_receipt.get("expected_digest"),
            )
        )

    raw_contexts = artifacts.get("verification_context", [])
    if required_contexts:
        if not isinstance(raw_contexts, list) or not raw_contexts:
            failures.append("artifacts.verification_context: required non-empty array for this case")
            raw_contexts = []
        elif not all(isinstance(context, dict) for context in raw_contexts):
            failures.append("artifacts.verification_context: expected array of objects")
            raw_contexts = [context for context in raw_contexts if isinstance(context, dict)]
        for index, context in enumerate(raw_contexts):
            failures.extend(
                sut_verification_context_failures(
                    context,
                    f"artifacts.verification_context[{index}]",
                )
            )

        available_contexts, duplicate_context_keys, duplicate_context_failures = artifact_entries_by_logical_key(
            raw_contexts,
            "artifacts.verification_context",
        )
        failures.extend(duplicate_context_failures)
        for expected_context in required_contexts:
            key = (expected_context.get("case_artifact"), expected_context.get("kind"))
            if key in duplicate_context_keys:
                continue
            context_ref = available_contexts.get(key)
            if context_ref is None:
                failures.append(
                    "artifacts.verification_context: "
                    f"missing case_artifact={key[0]} kind={key[1]}"
                )
                continue
            failures.extend(
                sut_artifact_digest_match_failures(
                    context_ref,
                    f"artifacts.verification_context case_artifact={key[0]} kind={key[1]}",
                    expected_context.get("expected_digest"),
                )
            )
            failures.extend(
                context_binding_match_failures(
                    context_ref.get("context_bindings"),
                    [
                        binding
                        for binding in expected_context.get("context_bindings", [])
                        if isinstance(binding, dict)
                    ],
                    f"artifacts.verification_context case_artifact={key[0]} kind={key[1]}.context_bindings",
                )
            )
    elif raw_contexts is not None:
        if not isinstance(raw_contexts, list):
            failures.append("artifacts.verification_context: expected array when present")
        else:
            for index, context in enumerate(raw_contexts):
                failures.extend(
                    sut_verification_context_failures(
                        context,
                        f"artifacts.verification_context[{index}]",
                    )
                )
            _, _, duplicate_context_failures = artifact_entries_by_logical_key(
                raw_contexts,
                "artifacts.verification_context",
            )
            failures.extend(duplicate_context_failures)

    raw_proofs = artifacts.get("proof_artifacts", [])
    if required_proofs:
        if not isinstance(raw_proofs, list) or not raw_proofs:
            failures.append("artifacts.proof_artifacts: required non-empty array for this case")
            raw_proofs = []
        elif not all(isinstance(proof, dict) for proof in raw_proofs):
            failures.append("artifacts.proof_artifacts: expected array of objects")
            raw_proofs = [proof for proof in raw_proofs if isinstance(proof, dict)]
        for index, proof in enumerate(raw_proofs):
            failures.extend(
                sut_proof_artifact_failures(
                    proof,
                    f"artifacts.proof_artifacts[{index}]",
                )
            )

        available_proofs, duplicate_proof_keys, duplicate_proof_failures = artifact_entries_by_logical_key(
            raw_proofs,
            "artifacts.proof_artifacts",
        )
        failures.extend(duplicate_proof_failures)
        for expected_proof in required_proofs:
            key = (expected_proof.get("case_artifact"), expected_proof.get("kind"))
            if key in duplicate_proof_keys:
                continue
            proof_ref = available_proofs.get(key)
            if proof_ref is None:
                failures.append(
                    "artifacts.proof_artifacts: "
                    f"missing case_artifact={key[0]} kind={key[1]}"
                )
                continue
            failures.extend(
                sut_artifact_digest_match_failures(
                    proof_ref,
                    f"artifacts.proof_artifacts case_artifact={key[0]} kind={key[1]}",
                    expected_proof.get("expected_digest"),
                )
            )
    elif raw_proofs is not None:
        if not isinstance(raw_proofs, list):
            failures.append("artifacts.proof_artifacts: expected array when present")
        else:
            for index, proof in enumerate(raw_proofs):
                failures.extend(
                    sut_proof_artifact_failures(
                        proof,
                        f"artifacts.proof_artifacts[{index}]",
                    )
                )
            _, _, duplicate_proof_failures = artifact_entries_by_logical_key(
                raw_proofs,
                "artifacts.proof_artifacts",
            )
            failures.extend(duplicate_proof_failures)

    return failures


def resolve_sut_generated_artifact_path(
    value: dict[str, Any],
    sut_results_path: Path,
    label: str,
) -> tuple[Path | None, list[str]]:
    local_path = value.get("local_path")
    if local_path is not None and (not isinstance(local_path, str) or not local_path):
        return None, [f"{label}.local_path: expected non-empty string when present"]

    path_value = local_path if isinstance(local_path, str) and local_path else value.get("uri")
    if not isinstance(path_value, str) or not path_value:
        return None, [f"{label}: local artifact path is unavailable"]
    if "://" in path_value:
        return None, [f"{label}.local_path: required when uri is not a local path"]

    raw_path = Path(path_value)
    if raw_path.is_absolute():
        return None, [f"{label}.local_path: absolute paths are not allowed"]
    if ".." in raw_path.parts:
        return None, [f"{label}.local_path: parent traversal is not allowed"]

    artifact_root = sut_results_path.parent.resolve()
    candidate = (artifact_root / raw_path).resolve()
    if not candidate.is_relative_to(artifact_root):
        return None, [f"{label}.local_path: resolved path escapes the SUT result directory"]
    if not candidate.is_file():
        return None, [f"{label}: generated artifact file not found under {artifact_root.as_posix()}"]
    return candidate, []


def load_sut_generated_artifact(
    value: Any,
    sut_results_path: Path,
    label: str,
) -> tuple[dict[str, Any] | None, Path | None, list[str]]:
    failures = sut_artifact_ref_failures(value, label, require_media_type=True)
    if not isinstance(value, dict):
        return None, None, failures

    path, path_failures = resolve_sut_generated_artifact_path(value, sut_results_path, label)
    failures.extend(path_failures)
    if path is None:
        return None, None, failures

    try:
        file_size = path.stat().st_size
    except OSError as exc:
        failures.append(f"{label}: unable to inspect generated artifact: {exc}")
        return None, path, failures
    if file_size > MAX_GENERATED_ARTIFACT_BYTES:
        failures.append(
            f"{label}: generated artifact exceeds {MAX_GENERATED_ARTIFACT_BYTES} byte limit"
        )
        return None, path, failures

    try:
        with path.open("rb") as artifact_file:
            raw_bytes = artifact_file.read(MAX_GENERATED_ARTIFACT_BYTES + 1)
    except OSError as exc:
        failures.append(f"{label}: unable to read generated artifact: {exc}")
        return None, path, failures
    if len(raw_bytes) > MAX_GENERATED_ARTIFACT_BYTES:
        failures.append(
            f"{label}: generated artifact exceeds {MAX_GENERATED_ARTIFACT_BYTES} byte limit"
        )
        return None, path, failures

    digest = value.get("digest")
    submitted_digest = digest.get("value") if isinstance(digest, dict) else None
    actual_digest = hashlib.sha256(raw_bytes).hexdigest()
    if submitted_digest != actual_digest:
        failures.append(
            f"{label}.digest.value: expected submitted artifact digest {submitted_digest} actual {actual_digest}"
        )

    try:
        artifact_text = raw_bytes.decode("utf-8")
        artifact = strict_json_loads(artifact_text)
    except (UnicodeDecodeError, ValueError) as exc:
        failures.append(f"{label}: generated artifact must be a UTF-8 JSON object: {exc}")
        return None, path, failures
    if not isinstance(artifact, dict):
        failures.append(f"{label}: generated artifact must be a JSON object")
        return None, path, failures
    return artifact, path, failures


def semantic_projection_failures(
    expected: Any,
    actual: Any,
    label: str,
    *,
    limit: int = 8,
) -> list[str]:
    failures: list[str] = []

    def visit(expected_value: Any, actual_value: Any, path: str) -> None:
        if len(failures) >= limit:
            return
        if isinstance(expected_value, dict):
            if not isinstance(actual_value, dict):
                failures.append(f"{path}: expected object actual {type(actual_value).__name__}")
                return
            for key in sorted(set(expected_value) | set(actual_value)):
                if key not in expected_value:
                    failures.append(f"{path}.{key}: unexpected semantic field")
                elif key not in actual_value:
                    failures.append(f"{path}.{key}: required semantic field missing")
                else:
                    visit(expected_value[key], actual_value[key], f"{path}.{key}")
                if len(failures) >= limit:
                    return
            return
        if isinstance(expected_value, list):
            if not isinstance(actual_value, list):
                failures.append(f"{path}: expected array actual {type(actual_value).__name__}")
                return
            if len(expected_value) != len(actual_value):
                failures.append(f"{path}: expected {len(expected_value)} items actual {len(actual_value)}")
                return
            for index, (expected_item, actual_item) in enumerate(zip(expected_value, actual_value)):
                visit(expected_item, actual_item, f"{path}[{index}]")
                if len(failures) >= limit:
                    return
            return
        if expected_value != actual_value:
            failures.append(f"{path}: expected {expected_value!r} actual {actual_value!r}")

    visit(expected, actual, label)
    return failures


def admission_receipt_semantic_projection(receipt: dict[str, Any]) -> dict[str, Any]:
    decision = receipt.get("decision")
    projected_decision: Any
    if isinstance(decision, dict):
        projected_decision = {
            "outcome": decision.get("outcome"),
            "reason_codes": decision.get("reason_codes"),
            "reason_visibility": decision.get("reason_visibility"),
            "reason_withheld": decision.get("reason_withheld"),
        }
    else:
        projected_decision = decision
    return {
        "version": receipt.get("version"),
        "profile": receipt.get("profile"),
        "receipt_type": receipt.get("receipt_type"),
        "issued_at": receipt.get("issued_at"),
        "expires_at": receipt.get("expires_at"),
        "request": receipt.get("request"),
        "subject": receipt.get("subject"),
        "evidence": receipt.get("evidence"),
        "policy": receipt.get("policy"),
        "decision": projected_decision,
        "attenuation": receipt.get("attenuation"),
    }


def post_execution_receipt_semantic_projection(receipt: dict[str, Any]) -> dict[str, Any]:
    admission = receipt.get("admission")
    projected_admission: Any
    if isinstance(admission, dict):
        projected_admission = {"decision": admission.get("decision")}
    else:
        projected_admission = admission
    return {
        "version": receipt.get("version"),
        "profile": receipt.get("profile"),
        "receipt_type": receipt.get("receipt_type"),
        "issued_at": receipt.get("issued_at"),
        "admission": projected_admission,
        "execution": receipt.get("execution"),
        "result": receipt.get("result"),
    }


def non_empty_string_field_failures(
    value: dict[str, Any],
    field: str,
    label: str,
    *,
    required: bool = True,
) -> list[str]:
    if field not in value and not required:
        return []
    field_value = value.get(field)
    if not isinstance(field_value, str) or not field_value:
        return [f"{label}.{field}: expected non-empty string"]
    return []


def generated_proof_shape_failures(value: Any, label: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{label}: expected object when present"]

    failures: list[str] = []
    proof_format = value.get("format")
    if "format" in value and (
        not isinstance(proof_format, str)
        or proof_format not in {
            "detached_jws",
            "jwt",
            "vc_proof",
            "external",
            "none",
        }
    ):
        failures.append(f"{label}.format: unsupported proof format {proof_format!r}")
    for field in ("alg", "kid", "signature_ref"):
        failures.extend(non_empty_string_field_failures(value, field, label, required=False))
    return failures


def generated_decision_shape_failures(value: Any, label: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{label}: expected object"]

    failures: list[str] = []
    outcome = value.get("outcome")
    if not isinstance(outcome, str) or outcome not in {"allow", "attenuate", "deny"}:
        failures.append(f"{label}.outcome: expected allow, attenuate, or deny")
    reason_codes = value.get("reason_codes")
    if not isinstance(reason_codes, list):
        failures.append(f"{label}.reason_codes: expected array")
    else:
        for index, reason_code in enumerate(reason_codes):
            if not isinstance(reason_code, str) or not reason_code:
                failures.append(f"{label}.reason_codes[{index}]: expected non-empty string")

    visibility = value.get("reason_visibility")
    if "reason_visibility" in value and (
        not isinstance(visibility, str)
        or visibility not in {"disclosed", "opaque", "withheld"}
    ):
        failures.append(f"{label}.reason_visibility: expected disclosed, opaque, or withheld")
    reason_withheld = value.get("reason_withheld")
    if "reason_withheld" in value and not isinstance(reason_withheld, bool):
        failures.append(f"{label}.reason_withheld: expected boolean when present")
    if visibility == "disclosed" and reason_withheld is True:
        failures.append(f"{label}.reason_withheld: disclosed reasons cannot be withheld")
    if reason_withheld is True and not is_string_enum(
        visibility,
        {"opaque", "withheld"},
    ):
        failures.append(f"{label}.reason_visibility: true reason_withheld requires opaque or withheld")
    failures.extend(
        non_empty_string_field_failures(value, "human_readable_summary", label, required=False)
    )
    return failures


def generated_admission_receipt_shape_failures(receipt: dict[str, Any], label: str) -> list[str]:
    failures: list[str] = []
    verifier = receipt.get("verifier")
    if not isinstance(verifier, dict):
        failures.append(f"{label}.verifier: expected object")
    else:
        failures.extend(non_empty_string_field_failures(verifier, "id", f"{label}.verifier"))
        failures.extend(
            non_empty_string_field_failures(
                verifier,
                "key_id",
                f"{label}.verifier",
                required=False,
            )
        )
    decision = receipt.get("decision")
    failures.extend(generated_decision_shape_failures(decision, f"{label}.decision"))
    decision_outcome = decision.get("outcome") if isinstance(decision, dict) else None
    if decision_outcome == "attenuate" and "attenuation" not in receipt:
        failures.append(f"{label}.attenuation: required when decision.outcome is attenuate")
    elif decision_outcome != "attenuate" and "attenuation" in receipt:
        failures.append(f"{label}.attenuation: must be absent unless decision.outcome is attenuate")
    if decision_outcome == "attenuate" and "attenuation" in receipt:
        decision_codes = (
            decision.get("reason_codes")
            if isinstance(decision, dict) and isinstance(decision.get("reason_codes"), list)
            else None
        )
        for failure in attenuation_validation_failures(
            receipt.get("attenuation"),
            decision_reason_codes=decision_codes,
        ):
            failures.append(f"{label}.attenuation: {failure}")
    if "proof" in receipt:
        failures.extend(generated_proof_shape_failures(receipt.get("proof"), f"{label}.proof"))
    return failures


def generated_post_execution_receipt_shape_failures(
    receipt: dict[str, Any],
    label: str,
) -> list[str]:
    failures: list[str] = []
    issuer = receipt.get("issuer")
    if not isinstance(issuer, dict):
        failures.append(f"{label}.issuer: expected object")
    else:
        failures.extend(non_empty_string_field_failures(issuer, "id", f"{label}.issuer"))
        issuer_role = issuer.get("role")
        if not isinstance(issuer_role, str) or issuer_role not in {
            "runtime",
            "agent",
            "verifier",
            "broker",
        }:
            failures.append(f"{label}.issuer.role: expected runtime, agent, verifier, or broker")
        failures.extend(
            non_empty_string_field_failures(
                issuer,
                "key_id",
                f"{label}.issuer",
                required=False,
            )
        )

    admission = receipt.get("admission")
    if not isinstance(admission, dict):
        failures.append(f"{label}.admission: expected object")
    else:
        for field in ("receipt_id", "uri"):
            failures.extend(non_empty_string_field_failures(admission, field, f"{label}.admission"))
        failures.extend(digest_descriptor_failures(admission.get("digest"), f"{label}.admission.digest"))
        admission_decision = admission.get("decision")
        if not isinstance(admission_decision, str) or admission_decision not in {"allow", "attenuate"}:
            failures.append(f"{label}.admission.decision: expected allow or attenuate")

    if "proof" in receipt:
        failures.extend(generated_proof_shape_failures(receipt.get("proof"), f"{label}.proof"))
    return failures


def generated_receipt_identity_failures(receipt: dict[str, Any], label: str, receipt_type: str) -> list[str]:
    failures: list[str] = []
    if receipt.get("receipt_type") != receipt_type:
        failures.append(f"{label}.receipt_type: expected {receipt_type} actual {receipt.get('receipt_type')}")
    receipt_id = receipt.get("receipt_id")
    if not isinstance(receipt_id, str) or not receipt_id:
        failures.append(f"{label}.receipt_id: expected non-empty string")
    issued_at = receipt.get("issued_at")
    if try_parse_time(issued_at) is None:
        failures.append(f"{label}.issued_at: expected RFC3339 timestamp")
    if receipt_type == "admission":
        expires_at = receipt.get("expires_at")
        issued = try_parse_time(issued_at)
        expires = try_parse_time(expires_at)
        if expires is None:
            failures.append(f"{label}.expires_at: expected RFC3339 timestamp")
        elif issued is not None and expires < issued:
            failures.append(f"{label}.expires_at: must not precede issued_at")
    return failures


def admission_link_relation_state(
    admission_receipt: dict[str, Any],
    post_execution_receipt: dict[str, Any],
) -> dict[str, bool]:
    admission_block = post_execution_receipt.get("admission")
    if not isinstance(admission_block, dict):
        return {
            "receipt_id_match": False,
            "decision_match": False,
            "digest_match": False,
        }
    return {
        "receipt_id_match": admission_block.get("receipt_id") == admission_receipt.get("receipt_id"),
        "decision_match": admission_block.get("decision") == actual_decision(admission_receipt),
        "digest_match": admission_block.get("digest") == digest_descriptor(admission_receipt),
    }


def generated_link_relation_failures(
    expected_admission: dict[str, Any],
    expected_post: dict[str, Any],
    generated_admission: dict[str, Any],
    generated_post: dict[str, Any],
    generated_admission_uri: Any,
) -> list[str]:
    expected_state = admission_link_relation_state(expected_admission, expected_post)
    generated_state = admission_link_relation_state(generated_admission, generated_post)
    failures: list[str] = []
    for relation in sorted(expected_state):
        if generated_state[relation] != expected_state[relation]:
            failures.append(
                "generated_artifacts.linkage."
                f"{relation}: expected relation {expected_state[relation]} actual {generated_state[relation]}"
            )
    generated_admission_block = generated_post.get("admission")
    linked_uri = (
        generated_admission_block.get("uri")
        if isinstance(generated_admission_block, dict)
        else None
    )
    if not isinstance(generated_admission_uri, str) or linked_uri != generated_admission_uri:
        failures.append(
            "generated_artifacts.linkage.uri_match: post-execution admission.uri must equal "
            "generated_artifacts.admission_receipt.uri"
        )
    return failures


def generated_sut_artifact_failures(
    result: dict[str, Any],
    expected: dict[str, Any],
    sut_results_path: Path,
) -> list[str]:
    failures: list[str] = []
    generated = result.get("generated_artifacts")
    if not isinstance(generated, dict):
        return ["generated_artifacts: expected object for generated-receipts mode"]

    case = expected["case"]
    artifact_map = case_artifacts(case)
    required_receipt_names = {
        name
        for name in GENERATED_ARTIFACT_NAMES
        if isinstance(artifact_map.get(name), str)
    }
    unknown_names = set(generated) - GENERATED_ARTIFACT_NAMES
    for name in sorted(unknown_names):
        failures.append(f"generated_artifacts.{name}: unsupported generated artifact name")
    unexpected_names = (set(generated) & GENERATED_ARTIFACT_NAMES) - required_receipt_names
    for name in sorted(unexpected_names):
        failures.append(f"generated_artifacts.{name}: not applicable to case {expected['case_id']}")

    generated_admission: dict[str, Any] | None = None
    generated_admission_path: Path | None = None
    expected_admission: dict[str, Any] | None = None
    if "admission_receipt" in required_receipt_names:
        label = "generated_artifacts.admission_receipt"
        if "admission_receipt" not in generated:
            failures.append(f"{label}: required for generated-receipts mode")
        else:
            generated_admission, generated_admission_path, load_failures = load_sut_generated_artifact(
                generated.get("admission_receipt"),
                sut_results_path,
                label,
            )
            failures.extend(load_failures)
            admission_ref = generated.get("admission_receipt")
            if (
                isinstance(admission_ref, dict)
                and admission_ref.get("media_type") != "application/vate-admission-receipt+json"
            ):
                failures.append(
                    f"{label}.media_type: expected application/vate-admission-receipt+json "
                    f"actual {admission_ref.get('media_type')}"
                )
            if generated_admission is not None:
                failures.extend(generated_receipt_identity_failures(generated_admission, label, "admission"))
                failures.extend(generated_admission_receipt_shape_failures(generated_admission, label))
                expected_admission = load_artifact(case, "admission_receipt")
                if expected_admission is None:
                    failures.append(f"{label}: corpus admission receipt is unavailable")
                else:
                    failures.extend(
                        semantic_projection_failures(
                            admission_receipt_semantic_projection(expected_admission),
                            admission_receipt_semantic_projection(generated_admission),
                            f"{label}.semantics",
                        )
                    )
                if case.get("category") != "linkage":
                    if actual_decision(generated_admission) != expected["expected_outcome"]:
                        failures.append(
                            f"{label}.decision.outcome: expected {expected['expected_outcome']} "
                            f"actual {actual_decision(generated_admission)}"
                        )
                    generated_codes = actual_reason_codes(generated_admission)
                    if generated_codes != expected["expected_reason_codes"]:
                        failures.append(
                            f"{label}.decision.reason_codes: expected {expected['expected_reason_codes']} "
                            f"actual {generated_codes}"
                        )
                generated_execute = actual_should_execute(generated_admission)
                if generated_execute != expected["expected_should_execute"]:
                    failures.append(
                        f"{label}.should_execute: expected {expected['expected_should_execute']} "
                        f"actual {generated_execute}"
                    )

    generated_post: dict[str, Any] | None = None
    expected_post: dict[str, Any] | None = None
    if "post_execution_receipt" in required_receipt_names:
        label = "generated_artifacts.post_execution_receipt"
        if "post_execution_receipt" not in generated:
            failures.append(f"{label}: required for generated-receipts mode")
        else:
            generated_post, _, load_failures = load_sut_generated_artifact(
                generated.get("post_execution_receipt"),
                sut_results_path,
                label,
            )
            failures.extend(load_failures)
            post_ref = generated.get("post_execution_receipt")
            if (
                isinstance(post_ref, dict)
                and post_ref.get("media_type") != "application/vate-post-execution-receipt+json"
            ):
                failures.append(
                    f"{label}.media_type: expected application/vate-post-execution-receipt+json "
                    f"actual {post_ref.get('media_type')}"
                )
            if generated_post is not None:
                failures.extend(generated_receipt_identity_failures(generated_post, label, "post_execution"))
                failures.extend(generated_post_execution_receipt_shape_failures(generated_post, label))
                expected_post = load_artifact(case, "post_execution_receipt")
                if expected_post is None:
                    failures.append(f"{label}: corpus post-execution receipt is unavailable")
                else:
                    failures.extend(
                        semantic_projection_failures(
                            post_execution_receipt_semantic_projection(expected_post),
                            post_execution_receipt_semantic_projection(generated_post),
                            f"{label}.semantics",
                        )
                    )

    if (
        case.get("category") == "linkage"
        and generated_admission is not None
        and generated_post is not None
        and expected_admission is not None
        and expected_post is not None
    ):
        failures.extend(
            generated_link_relation_failures(
                expected_admission,
                expected_post,
                generated_admission,
                generated_post,
                (
                    generated.get("admission_receipt", {}).get("uri")
                    if isinstance(generated.get("admission_receipt"), dict)
                    else None
                ),
            )
        )
        generated_case = copy.deepcopy(case)
        generated_case.setdefault("artifacts", {})["admission_receipt"] = str(generated_admission_path)
        generated_codes = actual_linkage_reason_codes(generated_case, generated_admission, generated_post)
        if generated_codes != expected["expected_reason_codes"]:
            failures.append(
                "generated_artifacts.linkage.reason_codes: "
                f"expected {expected['expected_reason_codes']} actual {generated_codes}"
            )
        generated_outcome = observed_outcome(generated_case, generated_admission, generated_post)
        if generated_outcome != expected["expected_outcome"]:
            failures.append(
                "generated_artifacts.post_execution_receipt.result.outcome: "
                f"expected {expected['expected_outcome']} actual {generated_outcome}"
            )
        for failure in evaluate_linkage_checks(generated_case, generated_admission, generated_post):
            failures.append(f"generated_artifacts.linkage: {failure}")
        for failure in post_execution_policy_violation_token_failures(generated_post):
            failures.append(f"generated_artifacts.post_execution_receipt: {failure}")

    return failures


def sut_result_envelope_failures(sut_results: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if try_parse_time(sut_results.get("generated_at")) is None:
        failures.append("sut_results.generated_at: expected valid RFC3339 date-time")

    if "results" not in sut_results or not isinstance(sut_results.get("results"), list):
        failures.append("sut_results.results: expected array")

    implementation = sut_results.get("implementation")
    if not isinstance(implementation, dict):
        failures.append("sut_results.implementation: expected object")
        return failures
    for field in ("name", "type", "version", "language"):
        value = implementation.get(field)
        if not isinstance(value, str) or not value:
            failures.append(
                f"sut_results.implementation.{field}: expected non-empty string"
            )
    return failures


def normalize_sut_results(
    sut_results: dict[str, Any],
    canonical_case_ids: list[str],
) -> dict[str, Any]:
    """Normalize one supplied SUT result without evaluating corpus expectations."""
    structural_failures: list[str] = []
    default_mode = sut_results.get("artifact_mode", SUT_ARTIFACT_MODE_CORPUS)
    default_mode_failure: str | None = None
    if not isinstance(default_mode, str) or default_mode not in SUT_ARTIFACT_MODES:
        default_mode_failure = (
            "sut_results.artifact_mode: expected one of "
            f"{sorted(SUT_ARTIFACT_MODES)} actual {default_mode}"
        )
        default_mode = SUT_ARTIFACT_MODE_CORPUS

    raw_results = sut_results.get("results")
    if not isinstance(raw_results, list):
        structural_failures.append("sut_results.results: expected array")
        raw_results = []

    results_by_case: dict[str, dict[str, Any]] = {}
    result_indexes_by_case: dict[str, int] = {}
    duplicate_case_ids: set[str] = set()
    for index, result in enumerate(raw_results):
        if not isinstance(result, dict):
            structural_failures.append(
                f"sut_results.results[{index}]: expected object"
            )
            continue
        case_id = result.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            structural_failures.append(
                f"sut_results.results[{index}]: expected non-empty string case_id"
            )
            continue
        if case_id in results_by_case:
            duplicate_case_ids.add(case_id)
        results_by_case[case_id] = result
        result_indexes_by_case[case_id] = index
    for case_id in sorted(duplicate_case_ids):
        structural_failures.append(
            f"sut_results.results: duplicate case_id {case_id}"
        )

    canonical_case_id_set = set(canonical_case_ids)
    for case_id in sorted(set(results_by_case) - canonical_case_id_set):
        structural_failures.append(
            f"sut_results.results: unknown case_id {case_id}"
        )

    normalized_cases: list[dict[str, Any]] = []
    artifact_mode_counts = {
        mode: 0 for mode in sorted(SUT_ARTIFACT_MODES)
    }
    skipped_count = 0
    for case_id in canonical_case_ids:
        result = results_by_case.get(case_id)
        artifact_mode = default_mode
        artifact_mode_failures: list[str] = []
        field_failures: list[str] = []
        if result is None:
            actual_outcome = "missing"
            actual_should_execute_value = None
            actual_reason_codes: list[str] = []
            status = "missing"
            state_failure = "sut result missing"
            field_failures.append(state_failure)
        else:
            raw_artifact_mode = result.get("artifact_mode", default_mode)
            if (
                not isinstance(raw_artifact_mode, str)
                or raw_artifact_mode not in SUT_ARTIFACT_MODES
            ):
                artifact_mode_failures.append(
                    "artifact_mode: expected one of "
                    f"{sorted(SUT_ARTIFACT_MODES)} actual {raw_artifact_mode}"
                )
            else:
                artifact_mode = raw_artifact_mode
            if (
                default_mode == SUT_ARTIFACT_MODE_GENERATED
                and artifact_mode != SUT_ARTIFACT_MODE_GENERATED
            ):
                artifact_mode_failures.append(
                    "artifact_mode: a generated-receipts default cannot be "
                    "downgraded per case"
                )
            field_failures.extend(artifact_mode_failures)

            raw_outcome = result.get("outcome")
            if isinstance(raw_outcome, str) and raw_outcome:
                actual_outcome = raw_outcome
            else:
                actual_outcome = "missing"
                field_failures.append("outcome: expected non-empty string")

            raw_should_execute = result.get("should_execute")
            if isinstance(raw_should_execute, bool):
                actual_should_execute_value = raw_should_execute
            else:
                actual_should_execute_value = None
                field_failures.append("should_execute: expected boolean")

            raw_reason_codes = result.get("reason_codes", [])
            if not isinstance(raw_reason_codes, list):
                actual_reason_codes = []
                field_failures.append("reason_codes: expected array")
            else:
                actual_reason_codes = [
                    code
                    for code in raw_reason_codes
                    if isinstance(code, str) and code
                ]
                if len(actual_reason_codes) != len(raw_reason_codes):
                    field_failures.append(
                        "reason_codes: expected non-empty string entries"
                    )

            status = result.get("status")
            state_failure = None
            if status == "skipped":
                state_failure = "sut result skipped"
                skipped_count += 1
            elif status != "completed":
                state_failure = (
                    "sut result status: expected completed actual "
                    f"{status}"
                )
            if state_failure is not None:
                field_failures.append(state_failure)

        artifact_mode_counts[artifact_mode] += 1
        normalized_cases.append(
            {
                "case_id": case_id,
                "result": result,
                "result_index": result_indexes_by_case.get(case_id),
                "status": status,
                "state_failure": state_failure,
                "artifact_mode": artifact_mode,
                "artifact_mode_failures": artifact_mode_failures,
                "actual_outcome": actual_outcome,
                "actual_should_execute": actual_should_execute_value,
                "actual_reason_codes": actual_reason_codes,
                "actual_primary_reason_code": primary_reason_code(
                    actual_reason_codes
                ),
                "field_failures": field_failures,
            }
        )

    return {
        "default_artifact_mode": default_mode,
        "default_artifact_mode_failure": default_mode_failure,
        "structural_failures": structural_failures,
        "cases": normalized_cases,
        "cases_by_id": {
            case["case_id"]: case for case in normalized_cases
        },
        "artifact_mode_counts": artifact_mode_counts,
        "skipped_count": skipped_count,
    }


def compare_sut_results(corpus_root: Path, sut_results_path: Path) -> dict[str, Any]:
    case_paths = sorted((corpus_root / "cases").glob("*.json"))
    _, case_load_failures = load_corpus_case_records(corpus_root)
    pairing_failures = corpus_pairing_failures(corpus_root)
    input_contract_failures = corpus_sut_input_contract_failures(corpus_root)
    expectations = load_case_expectations(corpus_root)
    manifest, digest, manifest_failures = corpus_manifest(corpus_root)

    fatal_errors: list[str] = list(
        dict.fromkeys(
            case_load_failures
            + list(pairing_failures)
            + input_contract_failures
            + manifest_failures
        )
    )
    if not case_paths:
        fatal_errors.append("no conformance case files found")
    elif not expectations:
        fatal_errors.append("no valid conformance cases loaded")
    try:
        sut_results = read_json(sut_results_path)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        fatal_errors.append(
            "sut_results: invalid strict JSON input "
            f"({type(exc).__name__}: {exc})"
        )
        sut_results = {}
    if not isinstance(sut_results, dict):
        fatal_errors.append("sut_results: expected object")
        sut_results = {}
    if sut_results.get("version") != SUT_RESULTS_VERSION:
        fatal_errors.append(f"sut_results.version: expected {SUT_RESULTS_VERSION} actual {sut_results.get('version')}")
    if sut_results.get("profile") != PROFILE:
        fatal_errors.append(f"sut_results.profile: expected {PROFILE} actual {sut_results.get('profile')}")
    fatal_errors.extend(sut_result_envelope_failures(sut_results))

    sut_corpus = sut_results.get("corpus", {})
    if not isinstance(sut_corpus, dict):
        fatal_errors.append("sut_results.corpus: expected object")
        sut_corpus = {}
    if sut_corpus.get("profile") != PROFILE:
        fatal_errors.append(f"sut_results.corpus.profile: expected {PROFILE} actual {sut_corpus.get('profile')}")
    if sut_corpus.get("digest") != digest:
        fatal_errors.append("sut_results.corpus.digest: does not match current corpus digest")

    sut_implementation = sut_results.get("implementation")
    if not isinstance(sut_implementation, dict):
        sut_implementation = {}

    normalized_sut_results = normalize_sut_results(
        sut_results,
        [expected["case_id"] for expected in expectations],
    )
    default_artifact_mode = normalized_sut_results[
        "default_artifact_mode"
    ]
    default_mode_failure = normalized_sut_results[
        "default_artifact_mode_failure"
    ]
    if default_mode_failure is not None:
        fatal_errors.append(default_mode_failure)
    fatal_errors.extend(normalized_sut_results["structural_failures"])

    cases: list[dict[str, Any]] = []
    for expected in expectations:
        normalized_result = normalized_sut_results["cases_by_id"][
            expected["case_id"]
        ]
        result = normalized_result["result"]
        failures = list(normalized_result["field_failures"])
        artifact_mode = normalized_result["artifact_mode"]
        actual_outcome = normalized_result["actual_outcome"]
        actual_should_execute_value = normalized_result[
            "actual_should_execute"
        ]
        actual_reason_codes = normalized_result["actual_reason_codes"]
        actual_primary_reason_code = normalized_result[
            "actual_primary_reason_code"
        ]
        if result is not None:
            if (
                isinstance(actual_should_execute_value, bool)
                and actual_should_execute_value
                != expected["expected_should_execute"]
            ):
                failures.append(
                    "should_execute: "
                    f"expected {expected['expected_should_execute']} actual "
                    f"{actual_should_execute_value}"
                )

            if actual_outcome != expected["expected_outcome"]:
                failures.append(f"outcome: expected {expected['expected_outcome']} actual {actual_outcome}")
            if actual_reason_codes != expected["expected_reason_codes"]:
                failures.append(f"reason_codes: expected {expected['expected_reason_codes']} actual {actual_reason_codes}")
            if actual_primary_reason_code != expected["expected_primary_reason_code"]:
                failures.append(
                    "primary_reason_code: "
                    f"expected {expected['expected_primary_reason_code']} "
                    f"actual {actual_primary_reason_code}"
                )
            failures.extend(
                reason_code_order_failures(
                    expected["expected_reason_codes"],
                    expected["expected_outcome"],
                    label="expected_reason_codes",
                )
            )
            failures.extend(
                reason_code_order_failures(
                    actual_reason_codes,
                    actual_outcome,
                    label="actual_reason_codes",
                )
            )

            raw_checks = result.get("checks", [])
            if raw_checks is None:
                raw_checks = []
            if not isinstance(raw_checks, list):
                failures.append("checks: expected array")
                raw_checks = []
            check_results: dict[str, dict[str, Any]] = {}
            for check_index, check in enumerate(raw_checks):
                if not isinstance(check, dict):
                    failures.append(f"checks[{check_index}]: expected object")
                    continue
                check_name = check.get("name")
                if not isinstance(check_name, str) or not check_name:
                    failures.append(f"checks[{check_index}].name: expected non-empty string")
                    continue
                if check_name in check_results:
                    failures.append(f"checks[{check_index}].name: duplicate check name {check_name}")
                    continue
                check_results[check_name] = check
            for check in expected["expected_checks"]:
                actual_check = check_results.get(check["name"])
                if actual_check is None:
                    failures.append(f"check {check['name']}: missing")
                    continue
                if actual_check.get("pass") is not True:
                    failures.append(f"check {check['name']}: expected pass")
            failures.extend(sut_result_artifact_failures(result, expected["required_artifacts"]))
            if artifact_mode == SUT_ARTIFACT_MODE_GENERATED:
                failures.extend(generated_sut_artifact_failures(result, expected, sut_results_path))
            elif "generated_artifacts" in result:
                failures.append(
                    "generated_artifacts: set artifact_mode to generated-receipts before claiming generated output"
                )

        cases.append(
            {
                "case_id": expected["case_id"],
                "category": expected["category"],
                "artifact_mode": artifact_mode,
                "expected_outcome": expected["expected_outcome"],
                "actual_outcome": actual_outcome,
                "expected_should_execute": expected["expected_should_execute"],
                "actual_should_execute": actual_should_execute_value,
                "expected_primary_reason_code": expected["expected_primary_reason_code"],
                "actual_primary_reason_code": actual_primary_reason_code,
                "expected_reason_codes": expected["expected_reason_codes"],
                "actual_reason_codes": actual_reason_codes,
                "pass": not failures,
                "failures": failures,
            }
        )

    failed = sum(1 for case in cases if not case["pass"])
    skipped = normalized_sut_results["skipped_count"]
    artifact_mode_counts = effective_sut_artifact_mode_counts(
        normalized_sut_results
    )
    report = {
        "version": CONFORMANCE_REPORT_VERSION,
        "profile": PROFILE,
        "checked_at": iso_now(),
        "summary": {
            "total": len(cases),
            "passed": len(cases) - failed,
            "failed": failed,
            "skipped": skipped,
        },
        "corpus": {
            "name": corpus_root.name,
            "root": display_path(corpus_root.resolve()),
            "artifact_count": len(manifest),
            "digest": digest,
        },
        "sut_results": {
            "path": display_path(sut_results_path.resolve()),
            "digest": digest_descriptor(sut_results),
            "digest_basis": "json-sorted-no-whitespace",
            "artifact_mode": default_artifact_mode,
            "artifact_mode_counts": artifact_mode_counts,
            "implementation": sut_implementation,
        },
        "cases": cases,
    }
    if fatal_errors:
        report["fatal_errors"] = fatal_errors
    return report


def add_bundle_check(
    checks: list[dict[str, Any]],
    name: str,
    passed: bool,
    *,
    expected: Any | None = None,
    actual: Any | None = None,
    details: str | None = None,
) -> None:
    check: dict[str, Any] = {
        "name": name,
        "pass": passed,
    }
    if expected is not None:
        check["expected"] = expected
    if actual is not None:
        check["actual"] = actual
    if details:
        check["details"] = details
    checks.append(check)


def add_generated_artifact_bundle_checks(
    checks: list[dict[str, Any]],
    normalized_sut_results: dict[str, Any],
    sut_results_path: Path,
    corpus_root: Path,
) -> None:
    default_mode_failure = normalized_sut_results[
        "default_artifact_mode_failure"
    ]
    if default_mode_failure is not None:
        add_bundle_check(
            checks,
            "sut_results.artifact_mode",
            False,
            expected=sorted(SUT_ARTIFACT_MODES),
            actual=default_mode_failure,
        )

    expectations = {
        expected["case_id"]: expected
        for expected in load_case_expectations(corpus_root)
    }
    for normalized_result in normalized_sut_results["cases"]:
        result = normalized_result["result"]
        if result is None:
            continue
        case_id = normalized_result["case_id"]
        result_index = normalized_result["result_index"]
        mode = normalized_result["artifact_mode"]
        artifact_mode_failures = normalized_result[
            "artifact_mode_failures"
        ]
        if artifact_mode_failures:
            add_bundle_check(
                checks,
                f"sut_results.artifact_mode.result_{result_index}",
                False,
                expected="valid effective artifact mode",
                actual=artifact_mode_failures,
            )
            continue
        if mode != SUT_ARTIFACT_MODE_GENERATED:
            if "generated_artifacts" in result:
                add_bundle_check(
                    checks,
                    f"sut_results.generated_artifacts.result_{result_index}",
                    False,
                    details="generated_artifacts requires artifact_mode generated-receipts",
                )
            continue
        expected = expectations.get(case_id)
        if expected is None:
            add_bundle_check(
                checks,
                f"sut_results.generated_artifacts.result_{result_index}",
                False,
                details=f"generated-receipts result has unknown case_id {case_id!r}",
            )
            continue
        failures = generated_sut_artifact_failures(result, expected, sut_results_path)
        add_bundle_check(
            checks,
            f"sut_results.generated_artifacts.{case_id}",
            not failures,
            details=(
                "generated receipt digests, bounded semantics, and linkage revalidated"
                if not failures
                else "; ".join(failures)
            ),
        )


def effective_sut_artifact_mode_counts(
    normalized_sut_results: dict[str, Any],
) -> dict[str, int]:
    return dict(normalized_sut_results["artifact_mode_counts"])


def sut_result_report_projection_failures(
    normalized_sut_results: dict[str, Any],
    conformance_cases: Any,
) -> list[str]:
    if not isinstance(conformance_cases, list):
        return ["conformance_report.cases: expected array"]

    report_cases_by_id: dict[str, dict[str, Any]] = {}
    for case in conformance_cases:
        if not isinstance(case, dict):
            continue
        case_id = case.get("case_id")
        if isinstance(case_id, str) and case_id not in report_cases_by_id:
            report_cases_by_id[case_id] = case

    failures: list[str] = []
    state_failure_prefix = "sut result status: expected completed actual "
    for normalized_result in normalized_sut_results["cases"]:
        case_id = normalized_result["case_id"]
        report_case = report_cases_by_id.get(case_id)
        if report_case is None:
            failures.append(f"{case_id}: conformance report case missing")
            continue

        expected_projection = {
            "actual_outcome": normalized_result["actual_outcome"],
            "actual_should_execute": normalized_result[
                "actual_should_execute"
            ],
            "actual_reason_codes": normalized_result[
                "actual_reason_codes"
            ],
            "actual_primary_reason_code": normalized_result[
                "actual_primary_reason_code"
            ],
            "artifact_mode": normalized_result["artifact_mode"],
        }
        actual_projection = {
            field: report_case.get(field) for field in expected_projection
        }
        if actual_projection != expected_projection:
            failures.append(
                f"{case_id}: expected actual projection {expected_projection} "
                f"actual {actual_projection}"
            )

        recorded_failures = report_case.get("failures")
        recorded_failure_strings = (
            recorded_failures
            if isinstance(recorded_failures, list)
            and all(isinstance(item, str) for item in recorded_failures)
            else []
        )
        recorded_state_failures = [
            item
            for item in recorded_failure_strings
            if item in {"sut result missing", "sut result skipped"}
            or item.startswith(state_failure_prefix)
        ]
        expected_state_failure = normalized_result["state_failure"]
        expected_state_failures = (
            [expected_state_failure]
            if isinstance(expected_state_failure, str)
            else []
        )
        if recorded_state_failures != expected_state_failures:
            failures.append(
                f"{case_id}: expected state failures "
                f"{expected_state_failures} actual {recorded_state_failures}"
            )
        if expected_state_failures and report_case.get("pass") is not False:
            failures.append(
                f"{case_id}: non-completed SUT state requires pass=false"
            )
    return failures


def non_empty_string_failure(value: Any, label: str) -> list[str]:
    if isinstance(value, str) and value:
        return []
    return [f"{label}: expected non-empty string"]


def non_negative_integer_failure(value: Any, label: str) -> list[str]:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return []
    return [f"{label}: expected non-negative integer"]


def digest_contract_failures(value: Any, label: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{label}: expected digest object"]
    failures: list[str] = []
    if value.get("alg") != "sha-256":
        failures.append(f"{label}.alg: expected sha-256")
    digest_value = value.get("value")
    if (
        not isinstance(digest_value, str)
        or SHA256_HEX_RE.fullmatch(digest_value) is None
    ):
        failures.append(
            f"{label}.value: expected lowercase SHA-256 hex"
        )
    return failures


def string_array_contract_failures(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        return [f"{label}: expected array"]
    failures: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            failures.append(f"{label}[{index}]: expected non-empty string")
    return failures


def artifact_mode_counts_contract_failures(
    value: Any,
    label: str,
) -> list[str]:
    if not isinstance(value, dict):
        return [f"{label}: expected object"]
    failures: list[str] = []
    expected_fields = set(SUT_ARTIFACT_MODES)
    if set(value) != expected_fields:
        failures.append(
            f"{label}: expected exactly {sorted(expected_fields)}"
        )
    for field in sorted(expected_fields):
        failures.extend(
            non_negative_integer_failure(value.get(field), f"{label}.{field}")
        )
    return failures


def conformance_case_contract_failures(value: Any, label: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{label}: expected object"]
    failures: list[str] = []
    required_fields = {
        "case_id",
        "category",
        "expected_outcome",
        "actual_outcome",
        "expected_should_execute",
        "actual_should_execute",
        "expected_primary_reason_code",
        "actual_primary_reason_code",
        "expected_reason_codes",
        "actual_reason_codes",
        "pass",
        "failures",
    }
    for field in sorted(required_fields - set(value)):
        failures.append(f"{label}.{field}: required")
    for field in ("case_id", "category", "expected_outcome", "actual_outcome"):
        failures.extend(non_empty_string_failure(value.get(field), f"{label}.{field}"))
    artifact_mode = value.get("artifact_mode")
    if "artifact_mode" in value and not is_string_enum(
        artifact_mode,
        SUT_ARTIFACT_MODES,
    ):
        failures.append(
            f"{label}.artifact_mode: expected one of {sorted(SUT_ARTIFACT_MODES)}"
        )
    if not isinstance(value.get("expected_should_execute"), bool):
        failures.append(f"{label}.expected_should_execute: expected boolean")
    actual_should_execute = value.get("actual_should_execute")
    if actual_should_execute is not None and not isinstance(
        actual_should_execute, bool
    ):
        failures.append(
            f"{label}.actual_should_execute: expected boolean or null"
        )
    for field in (
        "expected_primary_reason_code",
        "actual_primary_reason_code",
    ):
        reason_code = value.get(field)
        if reason_code is not None and (
            not isinstance(reason_code, str) or not reason_code
        ):
            failures.append(f"{label}.{field}: expected non-empty string or null")
    failures.extend(
        string_array_contract_failures(
            value.get("expected_reason_codes"),
            f"{label}.expected_reason_codes",
        )
    )
    failures.extend(
        string_array_contract_failures(
            value.get("actual_reason_codes"),
            f"{label}.actual_reason_codes",
        )
    )
    if not isinstance(value.get("pass"), bool):
        failures.append(f"{label}.pass: expected boolean")
    if "failures" in value:
        failures.extend(
            string_array_contract_failures(
                value.get("failures"), f"{label}.failures"
            )
        )
    return failures


def conformance_case_consistency_failures(value: Any, label: str) -> list[str]:
    """Validate one report case without re-running raw SUT semantics."""
    if not isinstance(value, dict):
        return []

    failures: list[str] = []
    expected_reason_codes = value.get("expected_reason_codes")
    actual_reason_codes = value.get("actual_reason_codes")
    expected_reasons_valid = (
        isinstance(expected_reason_codes, list)
        and all(
            isinstance(code, str) and code
            for code in expected_reason_codes
        )
    )
    actual_reasons_valid = (
        isinstance(actual_reason_codes, list)
        and all(
            isinstance(code, str) and code
            for code in actual_reason_codes
        )
    )
    if expected_reasons_valid:
        derived_expected_primary = primary_reason_code(expected_reason_codes)
        if value.get("expected_primary_reason_code") != derived_expected_primary:
            failures.append(
                f"{label}.expected_primary_reason_code: expected derived value "
                f"{derived_expected_primary!r}"
            )
    if actual_reasons_valid:
        derived_actual_primary = primary_reason_code(actual_reason_codes)
        if value.get("actual_primary_reason_code") != derived_actual_primary:
            failures.append(
                f"{label}.actual_primary_reason_code: expected derived value "
                f"{derived_actual_primary!r}"
            )

    passed = value.get("pass")
    recorded_failures = value.get("failures")
    if passed is True:
        for expected_field, actual_field in (
            ("expected_outcome", "actual_outcome"),
            ("expected_should_execute", "actual_should_execute"),
            (
                "expected_primary_reason_code",
                "actual_primary_reason_code",
            ),
            ("expected_reason_codes", "actual_reason_codes"),
        ):
            if value.get(expected_field) != value.get(actual_field):
                failures.append(
                    f"{label}.{actual_field}: pass=true requires equality with "
                    f"{expected_field}"
                )
        if recorded_failures != []:
            failures.append(f"{label}.failures: pass=true requires an empty array")
    elif passed is False:
        if not isinstance(recorded_failures, list) or not recorded_failures:
            failures.append(
                f"{label}.failures: pass=false requires at least one failure"
            )
    return failures


def conformance_cases_consistency_failures(cases: Any) -> list[str]:
    if not isinstance(cases, list):
        return []
    failures: list[str] = []
    for index, case in enumerate(cases):
        failures.extend(
            conformance_case_consistency_failures(case, f"cases[{index}]")
        )
    return failures


def implementation_case_contract_failures(value: Any, label: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{label}: expected object"]
    failures: list[str] = []
    required_fields = {
        "case_id",
        "expected_outcome",
        "actual_outcome",
        "expected_should_execute",
        "actual_should_execute",
        "expected_primary_reason_code",
        "actual_primary_reason_code",
        "pass",
    }
    for field in sorted(required_fields - set(value)):
        failures.append(f"{label}.{field}: required")
    for field in ("case_id", "expected_outcome", "actual_outcome"):
        failures.extend(non_empty_string_failure(value.get(field), f"{label}.{field}"))
    artifact_mode = value.get("artifact_mode")
    if "artifact_mode" in value and not is_string_enum(
        artifact_mode,
        SUT_ARTIFACT_MODES,
    ):
        failures.append(
            f"{label}.artifact_mode: expected one of {sorted(SUT_ARTIFACT_MODES)}"
        )
    if not isinstance(value.get("expected_should_execute"), bool):
        failures.append(f"{label}.expected_should_execute: expected boolean")
    actual_should_execute = value.get("actual_should_execute")
    if actual_should_execute is not None and not isinstance(
        actual_should_execute, bool
    ):
        failures.append(
            f"{label}.actual_should_execute: expected boolean or null"
        )
    for field in (
        "expected_primary_reason_code",
        "actual_primary_reason_code",
    ):
        reason_code = value.get(field)
        if reason_code is not None and (
            not isinstance(reason_code, str) or not reason_code
        ):
            failures.append(f"{label}.{field}: expected non-empty string or null")
    if not isinstance(value.get("pass"), bool):
        failures.append(f"{label}.pass: expected boolean")
    return failures


def report_corpus_contract_failures(
    value: Any,
    label: str,
    *,
    implementation: bool,
) -> list[str]:
    if not isinstance(value, dict):
        return [f"{label}: expected object"]
    failures: list[str] = []
    for field in ("name", "root"):
        failures.extend(non_empty_string_failure(value.get(field), f"{label}.{field}"))
    failures.extend(
        non_negative_integer_failure(
            value.get("artifact_count"), f"{label}.artifact_count"
        )
    )
    failures.extend(digest_contract_failures(value.get("digest"), f"{label}.digest"))
    if not implementation:
        return failures
    failures.extend(
        non_negative_integer_failure(
            value.get("case_count"), f"{label}.case_count"
        )
    )
    manifest = value.get("manifest")
    if not isinstance(manifest, list):
        failures.append(f"{label}.manifest: expected array")
        return failures
    for index, item in enumerate(manifest):
        item_label = f"{label}.manifest[{index}]"
        if not isinstance(item, dict):
            failures.append(f"{item_label}: expected object")
            continue
        failures.extend(
            non_empty_string_failure(item.get("path"), f"{item_label}.path")
        )
        sha256 = item.get("sha256")
        if not isinstance(sha256, str) or SHA256_HEX_RE.fullmatch(sha256) is None:
            failures.append(f"{item_label}.sha256: expected lowercase SHA-256 hex")
    return failures


def conformance_report_contract_failures(report: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if report.get("version") != CONFORMANCE_REPORT_VERSION:
        failures.append(
            f"version: expected {CONFORMANCE_REPORT_VERSION}"
        )
    if report.get("profile") != PROFILE:
        failures.append(f"profile: expected {PROFILE}")
    if try_parse_time(report.get("checked_at")) is None:
        failures.append("checked_at: expected supported RFC3339 timestamp")
    cases = report.get("cases")
    if not isinstance(cases, list):
        failures.append("cases: expected array")
    else:
        for index, case in enumerate(cases):
            failures.extend(
                conformance_case_contract_failures(case, f"cases[{index}]")
            )
    failures.extend(conformance_summary_failures(report.get("summary"), cases))
    failures.extend(
        report_corpus_contract_failures(
            report.get("corpus"), "corpus", implementation=False
        )
    )
    if "fatal_errors" in report:
        failures.extend(
            string_array_contract_failures(
                report.get("fatal_errors"), "fatal_errors"
            )
        )
    if "sut_results" in report:
        sut_results = report.get("sut_results")
        if not isinstance(sut_results, dict):
            failures.append("sut_results: expected object")
        else:
            failures.extend(
                non_empty_string_failure(sut_results.get("path"), "sut_results.path")
            )
            failures.extend(
                digest_contract_failures(
                    sut_results.get("digest"), "sut_results.digest"
                )
            )
            if sut_results.get("digest_basis") != "json-sorted-no-whitespace":
                failures.append(
                    "sut_results.digest_basis: expected json-sorted-no-whitespace"
                )
            if not is_string_enum(
                sut_results.get("artifact_mode"),
                SUT_ARTIFACT_MODES,
            ):
                failures.append(
                    "sut_results.artifact_mode: expected supported artifact mode"
                )
            failures.extend(
                artifact_mode_counts_contract_failures(
                    sut_results.get("artifact_mode_counts"),
                    "sut_results.artifact_mode_counts",
                )
            )
            if not isinstance(sut_results.get("implementation"), dict):
                failures.append("sut_results.implementation: expected object")
    return failures


def implementation_report_contract_failures(report: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if report.get("version") != IMPLEMENTATION_REPORT_VERSION:
        failures.append(
            f"version: expected {IMPLEMENTATION_REPORT_VERSION}"
        )
    if report.get("profile") != PROFILE:
        failures.append(f"profile: expected {PROFILE}")
    if try_parse_time(report.get("generated_at")) is None:
        failures.append("generated_at: expected supported RFC3339 timestamp")
    if not is_string_enum(
        report.get("status"),
        {"pass", "fail", "partial", "not_applicable"},
    ):
        failures.append("status: expected pass, fail, partial, or not_applicable")
    implementation = report.get("implementation")
    if not isinstance(implementation, dict):
        failures.append("implementation: expected object")
    else:
        for field in ("name", "type", "version", "language"):
            failures.extend(
                non_empty_string_failure(
                    implementation.get(field), f"implementation.{field}"
                )
            )
        for field in ("source", "commit", "environment"):
            if field in implementation:
                failures.extend(
                    non_empty_string_failure(
                        implementation.get(field), f"implementation.{field}"
                    )
                )
    failures.extend(
        report_corpus_contract_failures(
            report.get("corpus"), "corpus", implementation=True
        )
    )
    conformance_report = report.get("conformance_report")
    if not isinstance(conformance_report, dict):
        failures.append("conformance_report: expected object")
    else:
        failures.extend(
            non_empty_string_failure(
                conformance_report.get("uri"), "conformance_report.uri"
            )
        )
        if (
            conformance_report.get("media_type")
            != "application/vate-conformance-report+json"
        ):
            failures.append(
                "conformance_report.media_type: expected "
                "application/vate-conformance-report+json"
            )
        failures.extend(
            digest_contract_failures(
                conformance_report.get("digest"), "conformance_report.digest"
            )
        )
        if not is_string_enum(
            conformance_report.get("digest_basis"),
            {"json-sorted-no-whitespace", "exact-bytes"},
        ):
            failures.append(
                "conformance_report.digest_basis: expected supported digest basis"
            )
    case_results = report.get("case_results")
    if not isinstance(case_results, list):
        failures.append("case_results: expected array")
    else:
        for index, case in enumerate(case_results):
            failures.extend(
                implementation_case_contract_failures(
                    case, f"case_results[{index}]"
                )
            )
    failures.extend(
        conformance_summary_failures(report.get("summary"), case_results)
    )
    if "artifact_mode_counts" in report:
        failures.extend(
            artifact_mode_counts_contract_failures(
                report.get("artifact_mode_counts"), "artifact_mode_counts"
            )
        )
    if "limitations" in report:
        failures.extend(
            string_array_contract_failures(
                report.get("limitations"), "limitations"
            )
        )
    return failures


def case_collection_failures(
    value: Any,
    *,
    label: str,
    require_pass: bool,
) -> tuple[list[str], list[str]]:
    if not isinstance(value, list):
        return [], [f"{label}: expected array"]
    case_ids: list[str] = []
    failures: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        item_label = f"{label}[{index}]"
        if not isinstance(item, dict):
            failures.append(f"{item_label}: expected object")
            continue
        case_id = item.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            failures.append(f"{item_label}.case_id: expected non-empty string")
        else:
            if case_id in seen:
                failures.append(f"{item_label}.case_id: duplicate case_id {case_id}")
            seen.add(case_id)
            case_ids.append(case_id)
        if require_pass and not isinstance(item.get("pass"), bool):
            failures.append(f"{item_label}.pass: expected boolean")
    return case_ids, failures


def conformance_summary_failures(
    summary: Any,
    cases: Any,
) -> list[str]:
    if not isinstance(summary, dict):
        return ["summary: expected object"]
    if not isinstance(cases, list):
        return ["cases: expected array before summary arithmetic"]
    failures: list[str] = []
    values: dict[str, int] = {}
    for field in ("total", "passed", "failed", "skipped"):
        value = summary.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            failures.append(f"summary.{field}: expected non-negative integer")
        else:
            values[field] = value
    if len(values) != 4:
        return failures

    passed = sum(
        1 for case in cases if isinstance(case, dict) and case.get("pass") is True
    )
    failed = sum(
        1 for case in cases if isinstance(case, dict) and case.get("pass") is False
    )
    if values["total"] != len(cases):
        failures.append(
            f"summary.total: expected {len(cases)} from cases actual {values['total']}"
        )
    if values["passed"] != passed:
        failures.append(
            f"summary.passed: expected {passed} from cases actual {values['passed']}"
        )
    if values["failed"] != failed:
        failures.append(
            f"summary.failed: expected {failed} from cases actual {values['failed']}"
        )
    if values["passed"] + values["failed"] != values["total"]:
        failures.append("summary: passed + failed must equal total")
    if values["skipped"] > values["failed"]:
        failures.append("summary.skipped: cannot exceed failed cases")
    return failures


def conformance_case_expectation_failures(
    cases: Any,
    corpus_root: Path,
) -> list[str]:
    if not isinstance(cases, list):
        return ["conformance_report.cases: expected array"]
    expected_by_id = {
        expected["case_id"]: expected
        for expected in load_case_expectations(corpus_root)
    }
    fields = (
        "category",
        "expected_outcome",
        "expected_should_execute",
        "expected_primary_reason_code",
        "expected_reason_codes",
    )
    failures: list[str] = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            continue
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            continue
        expected = expected_by_id.get(case_id)
        if expected is None:
            continue
        for field in fields:
            if case.get(field) != expected.get(field):
                failures.append(
                    f"conformance_report.cases[{index}].{field}: does not match "
                    f"canonical case {case_id}"
                )
    return failures


def summary_status(summary: Any) -> str:
    if not isinstance(summary, dict):
        return "fail"
    total = summary.get("total")
    passed = summary.get("passed")
    failed = summary.get("failed")
    skipped = summary.get("skipped")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in (total, passed, failed, skipped)
    ):
        return "fail"
    if total <= 0 or passed + failed != total or skipped > failed:
        return "fail"
    if failed:
        return "fail"
    if skipped:
        return "partial"
    return "pass"


def conformance_report_status(report: dict[str, Any]) -> str:
    if report.get("fatal_errors"):
        return "fail"
    return summary_status(report.get("summary"))


def implementation_case_result(case: dict[str, Any]) -> dict[str, Any]:
    result = {
        "case_id": case.get("case_id"),
        "expected_outcome": case.get("expected_outcome"),
        "actual_outcome": case.get("actual_outcome"),
        "expected_should_execute": case.get("expected_should_execute"),
        "actual_should_execute": case.get("actual_should_execute"),
        "expected_primary_reason_code": case.get("expected_primary_reason_code"),
        "actual_primary_reason_code": case.get("actual_primary_reason_code"),
        "pass": case.get("pass"),
    }
    artifact_mode = case.get("artifact_mode")
    if isinstance(artifact_mode, str) and artifact_mode in SUT_ARTIFACT_MODES:
        result["artifact_mode"] = artifact_mode
    return result


def implementation_case_results_match(
    conformance_report: dict[str, Any],
    implementation_report: dict[str, Any],
) -> bool:
    conformance_cases = conformance_report.get("cases")
    implementation_cases = implementation_report.get("case_results")
    if not isinstance(conformance_cases, list) or not isinstance(implementation_cases, list):
        return False
    if not all(isinstance(case, dict) for case in conformance_cases):
        return False
    expected = [implementation_case_result(case) for case in conformance_cases]
    return implementation_cases == expected


def json_object_or_empty(value: Any, checks: list[dict[str, Any]], label: str) -> dict[str, Any]:
    if isinstance(value, dict):
        add_bundle_check(checks, f"{label}.shape", True)
        return value
    add_bundle_check(
        checks,
        f"{label}.shape",
        False,
        expected="object",
        actual=type(value).__name__,
    )
    return {}


def read_bundle_json_or_empty(
    path: Path,
    checks: list[dict[str, Any]],
    label: str,
) -> Any:
    try:
        return read_json(path)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        add_bundle_check(
            checks,
            f"{label}.json",
            False,
            expected="strict UTF-8 JSON",
            actual=type(exc).__name__,
            details=f"input could not be parsed as strict JSON: {exc}",
        )
        return {}


def verify_report_bundle(
    corpus_root: Path,
    conformance_report_path: Path,
    implementation_report_path: Path,
    sut_results_path: Path | None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    raw_conformance_report = read_bundle_json_or_empty(
        conformance_report_path,
        checks,
        "conformance_report",
    )
    raw_implementation_report = read_bundle_json_or_empty(
        implementation_report_path,
        checks,
        "implementation_report",
    )
    raw_sut_results = (
        read_bundle_json_or_empty(sut_results_path, checks, "sut_results")
        if sut_results_path
        else None
    )
    cases_dir = corpus_root / "cases"
    case_records, case_load_failures = load_corpus_case_records(corpus_root)
    canonical_case_ids = [case.get("case_id") for _, case in case_records]
    canonical_case_ids = [
        case_id for case_id in canonical_case_ids if isinstance(case_id, str)
    ]
    add_bundle_check(
        checks,
        "corpus.cases.directory",
        cases_dir.is_dir(),
        expected="readable cases directory",
        actual=(display_path(cases_dir.resolve()) if cases_dir.is_dir() else "missing"),
    )
    add_bundle_check(
        checks,
        "corpus.cases.envelope",
        not case_load_failures,
        expected="all case files are valid case objects",
        actual=case_load_failures,
    )
    add_bundle_check(
        checks,
        "corpus.cases.non_empty",
        bool(canonical_case_ids),
        expected="at least one valid conformance case",
        actual=len(canonical_case_ids),
    )
    add_bundle_check(
        checks,
        "corpus.cases.unique",
        len(canonical_case_ids) == len(set(canonical_case_ids)),
        expected="unique canonical case_id values",
        actual=canonical_case_ids,
    )
    manifest, corpus_digest, manifest_failures = corpus_manifest(corpus_root)
    for index, failure in enumerate(manifest_failures):
        add_bundle_check(
            checks,
            f"corpus.manifest[{index}]",
            False,
            expected="readable regular file",
            actual=failure,
        )
    for index, failure in enumerate(corpus_sut_input_contract_failures(corpus_root)):
        add_bundle_check(
            checks,
            f"corpus.sut_inputs[{index}]",
            False,
            expected="valid authoritative SUT input contract",
            actual=failure,
        )

    conformance_report = json_object_or_empty(raw_conformance_report, checks, "conformance_report")
    implementation_report = json_object_or_empty(raw_implementation_report, checks, "implementation_report")
    sut_results = (
        json_object_or_empty(raw_sut_results, checks, "sut_results")
        if sut_results_path
        else None
    )
    normalized_sut_results = (
        normalize_sut_results(sut_results, canonical_case_ids)
        if sut_results_path and isinstance(sut_results, dict)
        else None
    )
    conformance_envelope_failures = conformance_report_contract_failures(
        conformance_report
    )
    add_bundle_check(
        checks,
        "conformance_report.envelope",
        not conformance_envelope_failures,
        expected="dependency-free conformance report contract",
        actual=conformance_envelope_failures,
    )
    implementation_envelope_failures = implementation_report_contract_failures(
        implementation_report
    )
    add_bundle_check(
        checks,
        "implementation_report.envelope",
        not implementation_envelope_failures,
        expected="dependency-free implementation report contract",
        actual=implementation_envelope_failures,
    )

    add_bundle_check(
        checks,
        "conformance_report.version",
        conformance_report.get("version") == CONFORMANCE_REPORT_VERSION,
        expected=CONFORMANCE_REPORT_VERSION,
        actual=conformance_report.get("version"),
    )
    add_bundle_check(
        checks,
        "conformance_report.profile",
        conformance_report.get("profile") == PROFILE,
        expected=PROFILE,
        actual=conformance_report.get("profile"),
    )
    add_bundle_check(
        checks,
        "implementation_report.version",
        implementation_report.get("version") == IMPLEMENTATION_REPORT_VERSION,
        expected=IMPLEMENTATION_REPORT_VERSION,
        actual=implementation_report.get("version"),
    )
    add_bundle_check(
        checks,
        "implementation_report.profile",
        implementation_report.get("profile") == PROFILE,
        expected=PROFILE,
        actual=implementation_report.get("profile"),
    )

    raw_corpus_index = read_bundle_json_or_empty(
        corpus_root / CORPUS_INDEX_FILENAME,
        checks,
        "corpus_index",
    )
    if isinstance(raw_corpus_index, dict):
        corpus_index = raw_corpus_index
    else:
        add_bundle_check(
            checks,
            "corpus_index.shape",
            False,
            expected="object",
            actual=type(raw_corpus_index).__name__,
        )
        corpus_index = {}
    expected_corpus_index_identity = {
        "version": CORPUS_INDEX_VERSION,
        "profile": PROFILE,
        "name": corpus_root.name,
        "root": display_path(corpus_root.resolve()),
        "case_schema": display_path(
            (corpus_root / "conformance-case.schema.json").resolve()
        ),
        "digest_basis": {
            "alg": "sha-256",
            "canonicalization": (
                "JSON objects are sorted by key with insignificant whitespace "
                "removed before hashing."
            ),
            "manifest_excludes": [
                display_path(
                    (corpus_root / CORPUS_INDEX_FILENAME).resolve()
                )
            ],
        },
    }
    actual_corpus_index_identity = {
        field: corpus_index.get(field)
        for field in expected_corpus_index_identity
    }
    add_bundle_check(
        checks,
        "corpus_index.identity",
        actual_corpus_index_identity == expected_corpus_index_identity,
        expected=expected_corpus_index_identity,
        actual=actual_corpus_index_identity,
    )
    add_bundle_check(
        checks,
        "corpus_index.digest",
        corpus_index.get("digest") == corpus_digest,
        expected=corpus_digest,
        actual=corpus_index.get("digest"),
    )
    add_bundle_check(
        checks,
        "corpus_index.manifest",
        corpus_index.get("manifest") == manifest,
        details="committed corpus.json manifest matches the recomputed corpus manifest",
    )

    corpus_index_case_ids, corpus_index_case_failures = case_collection_failures(
        corpus_index.get("cases"),
        label="corpus_index.cases",
        require_pass=False,
    )
    add_bundle_check(
        checks,
        "corpus_index.cases.shape",
        not corpus_index_case_failures,
        expected="case objects with unique non-empty case_id values",
        actual=corpus_index_case_failures,
    )
    add_bundle_check(
        checks,
        "corpus_index.cases.coverage",
        not corpus_index_case_failures
        and bool(canonical_case_ids)
        and sorted(corpus_index_case_ids) == sorted(canonical_case_ids),
        expected=sorted(canonical_case_ids),
        actual=sorted(corpus_index_case_ids),
    )
    expected_index_cases = [
        case_index_entry(case_path) for case_path, _ in case_records
    ]
    add_bundle_check(
        checks,
        "corpus_index.cases.entries",
        corpus_index.get("cases") == expected_index_cases,
        details="corpus index case entries match the loaded canonical case files",
    )
    corpus_index_summary = corpus_index.get("summary")
    expected_category_counts = category_counts(
        [case for _, case in case_records]
    )
    add_bundle_check(
        checks,
        "corpus_index.summary.case_count",
        isinstance(corpus_index_summary, dict)
        and corpus_index_summary.get("case_count") == len(canonical_case_ids),
        expected=len(canonical_case_ids),
        actual=(
            corpus_index_summary.get("case_count")
            if isinstance(corpus_index_summary, dict)
            else None
        ),
    )
    add_bundle_check(
        checks,
        "corpus_index.summary.category_counts",
        isinstance(corpus_index_summary, dict)
        and corpus_index_summary.get("category_counts") == expected_category_counts,
        expected=expected_category_counts,
        actual=(
            corpus_index_summary.get("category_counts")
            if isinstance(corpus_index_summary, dict)
            else None
        ),
    )
    corpus_index_artifact_count = (
        corpus_index_summary.get("artifact_count")
        if isinstance(corpus_index_summary, dict)
        else None
    )
    add_bundle_check(
        checks,
        "corpus_index.summary.artifact_count",
        isinstance(corpus_index_artifact_count, int)
        and not isinstance(corpus_index_artifact_count, bool)
        and corpus_index_artifact_count == len(manifest),
        expected=len(manifest),
        actual=corpus_index_artifact_count,
    )

    conformance_cases = conformance_report.get("cases")
    conformance_case_ids, conformance_case_failures = case_collection_failures(
        conformance_cases,
        label="conformance_report.cases",
        require_pass=True,
    )
    add_bundle_check(
        checks,
        "conformance_report.cases.shape",
        not conformance_case_failures,
        expected="case result objects with unique case_id and boolean pass",
        actual=conformance_case_failures,
    )
    add_bundle_check(
        checks,
        "conformance_report.cases.coverage",
        not conformance_case_failures
        and bool(canonical_case_ids)
        and sorted(conformance_case_ids) == sorted(canonical_case_ids),
        expected=sorted(canonical_case_ids),
        actual=sorted(conformance_case_ids),
    )
    expectation_failures = conformance_case_expectation_failures(
        conformance_cases,
        corpus_root,
    )
    add_bundle_check(
        checks,
        "conformance_report.cases.expectations",
        not expectation_failures,
        expected="canonical expected case projection",
        actual=expectation_failures,
    )
    conformance_consistency_failures = (
        conformance_cases_consistency_failures(conformance_cases)
    )
    add_bundle_check(
        checks,
        "conformance_report.cases.internal_consistency",
        not conformance_consistency_failures,
        expected=(
            "pass cases have matching expected/actual projections and no failures; "
            "failed cases carry at least one failure"
        ),
        actual=conformance_consistency_failures,
    )
    conformance_arithmetic_failures = conformance_summary_failures(
        conformance_report.get("summary"),
        conformance_cases,
    )
    add_bundle_check(
        checks,
        "conformance_report.summary.arithmetic",
        not conformance_arithmetic_failures,
        expected="summary counts derived from cases",
        actual=conformance_arithmetic_failures,
    )

    conformance_corpus = conformance_report.get("corpus", {})
    add_bundle_check(
        checks,
        "conformance_report.corpus.digest",
        isinstance(conformance_corpus, dict) and conformance_corpus.get("digest") == corpus_digest,
        expected=corpus_digest,
        actual=conformance_corpus.get("digest") if isinstance(conformance_corpus, dict) else None,
    )
    conformance_artifact_count = (
        conformance_corpus.get("artifact_count")
        if isinstance(conformance_corpus, dict)
        else None
    )
    add_bundle_check(
        checks,
        "conformance_report.corpus.artifact_count",
        isinstance(conformance_artifact_count, int)
        and not isinstance(conformance_artifact_count, bool)
        and conformance_artifact_count == len(manifest),
        expected=len(manifest),
        actual=conformance_artifact_count,
    )

    implementation_corpus = implementation_report.get("corpus", {})
    add_bundle_check(
        checks,
        "implementation_report.corpus.digest",
        isinstance(implementation_corpus, dict) and implementation_corpus.get("digest") == corpus_digest,
        expected=corpus_digest,
        actual=implementation_corpus.get("digest") if isinstance(implementation_corpus, dict) else None,
    )
    add_bundle_check(
        checks,
        "implementation_report.corpus.manifest",
        isinstance(implementation_corpus, dict) and implementation_corpus.get("manifest") == manifest,
        details="implementation report manifest matches the recomputed corpus manifest",
    )
    add_bundle_check(
        checks,
        "implementation_report.corpus.case_count",
        isinstance(implementation_corpus, dict)
        and implementation_corpus.get("case_count") == len(canonical_case_ids),
        expected=len(canonical_case_ids),
        actual=(
            implementation_corpus.get("case_count")
            if isinstance(implementation_corpus, dict)
            else None
        ),
    )
    implementation_artifact_count = (
        implementation_corpus.get("artifact_count")
        if isinstance(implementation_corpus, dict)
        else None
    )
    add_bundle_check(
        checks,
        "implementation_report.corpus.artifact_count",
        isinstance(implementation_artifact_count, int)
        and not isinstance(implementation_artifact_count, bool)
        and implementation_artifact_count == len(manifest),
        expected=len(manifest),
        actual=implementation_artifact_count,
    )

    implementation_cases = implementation_report.get("case_results")
    implementation_case_ids, implementation_case_failures = case_collection_failures(
        implementation_cases,
        label="implementation_report.case_results",
        require_pass=True,
    )
    add_bundle_check(
        checks,
        "implementation_report.case_results.shape",
        not implementation_case_failures,
        expected="case result objects with unique case_id and boolean pass",
        actual=implementation_case_failures,
    )
    add_bundle_check(
        checks,
        "implementation_report.case_results.coverage",
        not implementation_case_failures
        and bool(canonical_case_ids)
        and sorted(implementation_case_ids) == sorted(canonical_case_ids),
        expected=sorted(canonical_case_ids),
        actual=sorted(implementation_case_ids),
    )

    conformance_digest = digest_descriptor(raw_conformance_report)
    implementation_conformance = implementation_report.get("conformance_report", {})
    add_bundle_check(
        checks,
        "implementation_report.conformance_report.digest",
        isinstance(implementation_conformance, dict)
        and implementation_conformance.get("digest") == conformance_digest,
        expected=conformance_digest,
        actual=implementation_conformance.get("digest") if isinstance(implementation_conformance, dict) else None,
    )
    add_bundle_check(
        checks,
        "implementation_report.conformance_report.digest_basis",
        isinstance(implementation_conformance, dict)
        and implementation_conformance.get("digest_basis") == "json-sorted-no-whitespace",
        expected="json-sorted-no-whitespace",
        actual=implementation_conformance.get("digest_basis") if isinstance(implementation_conformance, dict) else None,
    )

    add_bundle_check(
        checks,
        "implementation_report.summary",
        implementation_report.get("summary") == conformance_report.get("summary"),
        expected=conformance_report.get("summary"),
        actual=implementation_report.get("summary"),
    )
    add_bundle_check(
        checks,
        "implementation_report.status",
        implementation_report.get("status") == conformance_report_status(conformance_report),
        expected=conformance_report_status(conformance_report),
        actual=implementation_report.get("status"),
    )
    add_bundle_check(
        checks,
        "implementation_report.case_results",
        implementation_case_results_match(conformance_report, implementation_report),
        details="implementation case_results are the conformance report case projection",
    )

    conformance_sut = conformance_report.get("sut_results")
    if isinstance(conformance_sut, dict):
        conformance_mode_counts = conformance_sut.get("artifact_mode_counts")
        raw_conformance_cases = conformance_report.get("cases")
        conformance_cases_for_counts = raw_conformance_cases if isinstance(raw_conformance_cases, list) else []
        case_mode_counts = {
            mode: sum(
                1
                for case in conformance_cases_for_counts
                if isinstance(case, dict) and case.get("artifact_mode") == mode
            )
            for mode in sorted(SUT_ARTIFACT_MODES)
        }
        add_bundle_check(
            checks,
            "conformance_report.sut_results.artifact_mode_counts",
            conformance_mode_counts == case_mode_counts,
            expected=case_mode_counts,
            actual=conformance_mode_counts,
        )
        add_bundle_check(
            checks,
            "implementation_report.artifact_mode_counts",
            implementation_report.get("artifact_mode_counts") == conformance_mode_counts,
            expected=conformance_mode_counts,
            actual=implementation_report.get("artifact_mode_counts"),
        )
    if sut_results_path:
        sut_digest = digest_descriptor(sut_results)
        sut_corpus = sut_results.get("corpus", {}) if isinstance(sut_results, dict) else {}
        submitted_default_mode = (
            normalized_sut_results["default_artifact_mode"]
            if isinstance(normalized_sut_results, dict)
            else None
        )
        submitted_mode_counts = (
            effective_sut_artifact_mode_counts(normalized_sut_results)
            if isinstance(normalized_sut_results, dict)
            else None
        )
        sut_envelope_failures = (
            sut_result_envelope_failures(sut_results)
            if isinstance(sut_results, dict)
            else ["sut_results: expected object"]
        )
        add_bundle_check(
            checks,
            "sut_results.envelope",
            not sut_envelope_failures,
            expected="valid SUT result envelope",
            actual=sut_envelope_failures,
        )
        sut_structure_failures = (
            normalized_sut_results["structural_failures"]
            if isinstance(normalized_sut_results, dict)
            else ["sut_results: expected object"]
        )
        add_bundle_check(
            checks,
            "sut_results.results.structure",
            not sut_structure_failures,
            expected=(
                "result objects with unique non-empty canonical case_id values"
            ),
            actual=sut_structure_failures,
        )
        add_bundle_check(
            checks,
            "sut_results.version",
            isinstance(sut_results, dict) and sut_results.get("version") == SUT_RESULTS_VERSION,
            expected=SUT_RESULTS_VERSION,
            actual=sut_results.get("version") if isinstance(sut_results, dict) else None,
        )
        add_bundle_check(
            checks,
            "sut_results.profile",
            isinstance(sut_results, dict) and sut_results.get("profile") == PROFILE,
            expected=PROFILE,
            actual=sut_results.get("profile") if isinstance(sut_results, dict) else None,
        )
        add_bundle_check(
            checks,
            "sut_results.corpus.digest",
            isinstance(sut_corpus, dict) and sut_corpus.get("digest") == corpus_digest,
            expected=corpus_digest,
            actual=sut_corpus.get("digest") if isinstance(sut_corpus, dict) else None,
        )
        add_bundle_check(
            checks,
            "conformance_report.sut_results.digest",
            isinstance(conformance_sut, dict) and conformance_sut.get("digest") == sut_digest,
            expected=sut_digest,
            actual=conformance_sut.get("digest") if isinstance(conformance_sut, dict) else None,
        )
        add_bundle_check(
            checks,
            "conformance_report.sut_results.digest_basis",
            isinstance(conformance_sut, dict)
            and conformance_sut.get("digest_basis") == "json-sorted-no-whitespace",
            expected="json-sorted-no-whitespace",
            actual=conformance_sut.get("digest_basis") if isinstance(conformance_sut, dict) else None,
        )
        add_bundle_check(
            checks,
            "conformance_report.sut_results.implementation",
            isinstance(conformance_sut, dict)
            and isinstance(sut_results, dict)
            and conformance_sut.get("implementation") == sut_results.get("implementation"),
            expected=sut_results.get("implementation") if isinstance(sut_results, dict) else None,
            actual=conformance_sut.get("implementation") if isinstance(conformance_sut, dict) else None,
        )
        add_bundle_check(
            checks,
            "conformance_report.sut_results.artifact_mode",
            isinstance(conformance_sut, dict)
            and conformance_sut.get("artifact_mode") == submitted_default_mode,
            expected=submitted_default_mode,
            actual=conformance_sut.get("artifact_mode") if isinstance(conformance_sut, dict) else None,
        )
        add_bundle_check(
            checks,
            "conformance_report.sut_results.submitted_artifact_mode_counts",
            isinstance(conformance_sut, dict)
            and conformance_sut.get("artifact_mode_counts") == submitted_mode_counts,
            expected=submitted_mode_counts,
            actual=(
                conformance_sut.get("artifact_mode_counts")
                if isinstance(conformance_sut, dict)
                else None
            ),
        )
        projection_failures = (
            sut_result_report_projection_failures(
                normalized_sut_results,
                conformance_cases,
            )
            if isinstance(normalized_sut_results, dict)
            else ["sut_results: expected normalized result set"]
        )
        add_bundle_check(
            checks,
            "conformance_report.cases.sut_actual_projection",
            not sut_structure_failures and not projection_failures,
            expected=(
                "actual projection and non-completed state failures derived "
                "from the supplied SUT result"
            ),
            actual=(sut_structure_failures + projection_failures),
        )
        if isinstance(normalized_sut_results, dict):
            add_generated_artifact_bundle_checks(
                checks,
                normalized_sut_results,
                sut_results_path,
                corpus_root,
            )
        expected_skipped = (
            normalized_sut_results["skipped_count"]
            if isinstance(normalized_sut_results, dict)
            else 0
        )
        conformance_summary = conformance_report.get("summary")
        add_bundle_check(
            checks,
            "conformance_report.summary.skipped",
            isinstance(conformance_summary, dict)
            and conformance_summary.get("skipped") == expected_skipped,
            expected=expected_skipped,
            actual=(
                conformance_summary.get("skipped")
                if isinstance(conformance_summary, dict)
                else None
            ),
        )
    else:
        add_bundle_check(
            checks,
            "sut_results.provided",
            conformance_sut is None,
            expected="no SUT result file is required for a reference run bundle",
            actual="SUT result file missing" if conformance_sut is not None else "not applicable",
        )
        conformance_summary = conformance_report.get("summary")
        add_bundle_check(
            checks,
            "conformance_report.summary.skipped",
            isinstance(conformance_summary, dict)
            and conformance_summary.get("skipped") == 0,
            expected=0,
            actual=(
                conformance_summary.get("skipped")
                if isinstance(conformance_summary, dict)
                else None
            ),
        )

    failed = sum(1 for check in checks if not check["pass"])
    report = {
        "version": BUNDLE_VERIFICATION_VERSION,
        "profile": PROFILE,
        "checked_at": iso_now(),
        "status": "fail" if failed else "pass",
        "summary": {
            "total": len(checks),
            "passed": len(checks) - failed,
            "failed": failed,
        },
        "artifacts": {
            "corpus": {
                "root": display_path(corpus_root.resolve()),
                "digest": corpus_digest,
                "artifact_count": len(manifest),
            },
            "conformance_report": {
                "path": display_path(conformance_report_path.resolve()),
                "digest": digest_descriptor(raw_conformance_report),
                "digest_basis": "json-sorted-no-whitespace",
            },
            "implementation_report": {
                "path": display_path(implementation_report_path.resolve()),
                "digest": digest_descriptor(raw_implementation_report),
                "digest_basis": "json-sorted-no-whitespace",
            },
        },
        "checks": checks,
    }
    if sut_results_path and isinstance(sut_results, dict):
        report["artifacts"]["sut_results"] = {
            "path": display_path(sut_results_path.resolve()),
            "digest": digest_descriptor(raw_sut_results),
            "digest_basis": "json-sorted-no-whitespace",
        }
    return report


def text_field(source: dict[str, Any], key: str, default: str) -> str:
    value = source.get(key)
    return value if isinstance(value, str) and value else default


def implementation_metadata(args: argparse.Namespace, conformance_report: dict[str, Any]) -> dict[str, Any]:
    sut_results = conformance_report.get("sut_results")
    if isinstance(sut_results, dict) and isinstance(sut_results.get("implementation"), dict):
        source = sut_results["implementation"]
        implementation = {
            "name": text_field(source, "name", "Unknown external VATE verifier"),
            "type": text_field(source, "type", "external-verifier"),
            "version": text_field(source, "version", "unknown"),
            "language": text_field(source, "language", "unknown"),
        }
        for optional in ("source", "commit", "environment"):
            if isinstance(source.get(optional), str) and source[optional]:
                implementation[optional] = source[optional]
        return implementation

    implementation = {
        "name": getattr(args, "implementation_name", "Unknown VATE verifier"),
        "type": getattr(args, "implementation_type", "external-verifier"),
        "version": getattr(args, "implementation_version", "unknown"),
        "language": getattr(args, "implementation_language", "unknown"),
    }
    if getattr(args, "implementation_repo", None):
        implementation["source"] = args.implementation_repo
    if getattr(args, "implementation_commit", None):
        implementation["commit"] = args.implementation_commit
    if getattr(args, "environment", None):
        implementation["environment"] = args.environment
    return implementation


def add_optional_integrity_metadata(report: dict[str, Any], args: argparse.Namespace) -> None:
    publication: dict[str, Any] = {}
    if getattr(args, "implementation_report_uri", None):
        publication["uri"] = args.implementation_report_uri
    if getattr(args, "publication_controlled_origin", None):
        publication["controlled_origin"] = args.publication_controlled_origin
    if getattr(args, "publication_published_at", None):
        publication["published_at"] = args.publication_published_at
    if getattr(args, "publication_immutability", None):
        publication["immutability"] = args.publication_immutability
    if publication:
        report["publication"] = publication

    if getattr(args, "proof_uri", None):
        proof = {
            "format": getattr(args, "proof_format", None) or "other",
            "uri": args.proof_uri,
        }
        if getattr(args, "proof_key_ref", None):
            proof["key_ref"] = args.proof_key_ref
        if getattr(args, "proof_covered_artifact", None):
            proof["covered_artifact"] = args.proof_covered_artifact
        report["proofs"] = [proof]


def make_implementation_report(args: argparse.Namespace, conformance_report: dict[str, Any]) -> dict[str, Any]:
    corpus_root = Path(args.corpus_root)
    manifest, digest, _ = corpus_manifest(corpus_root)

    report = {
        "version": IMPLEMENTATION_REPORT_VERSION,
        "profile": PROFILE,
        "generated_at": conformance_report["checked_at"],
        "status": conformance_report_status(conformance_report),
        "implementation": implementation_metadata(args, conformance_report),
        "corpus": {
            "name": corpus_root.name,
            "root": display_path(corpus_root.resolve()),
            "case_count": conformance_report["summary"]["total"],
            "artifact_count": len(manifest),
            "digest": digest,
            "manifest": manifest,
        },
        "conformance_report": {
            "uri": args.conformance_report_uri or str(Path(args.report)),
            "media_type": "application/vate-conformance-report+json",
            "digest": {
                "alg": "sha-256",
                "value": sha256_value(conformance_report),
            },
            "digest_basis": "json-sorted-no-whitespace",
        },
        "summary": conformance_report["summary"],
        "case_results": [
            implementation_case_result(case)
            for case in conformance_report["cases"]
        ],
        "limitations": [
            "This report records one implementation run against one corpus snapshot.",
            "Passing cases do not imply production readiness or endorsement.",
        ],
    }
    conformance_sut = conformance_report.get("sut_results")
    if isinstance(conformance_sut, dict):
        mode_counts = conformance_sut.get("artifact_mode_counts")
        if isinstance(mode_counts, dict):
            report["artifact_mode_counts"] = copy.deepcopy(mode_counts)
    add_optional_integrity_metadata(report, args)
    return report


def add_implementation_report_args(parser: argparse.ArgumentParser, *, include_identity: bool) -> None:
    parser.add_argument("--implementation-report", help="optional path to write an implementation report")
    parser.add_argument("--implementation-report-uri", help="durable URI where the implementation report will be published")
    parser.add_argument("--publication-controlled-origin", help="origin or repository namespace controlled by the implementer")
    parser.add_argument("--publication-published-at", help="publication timestamp for the implementation report")
    parser.add_argument(
        "--publication-immutability",
        choices=["content_addressed", "release_asset", "git_commit", "versioned_url", "mutable_url"],
        help="immutability level of the published implementation report URI",
    )
    parser.add_argument(
        "--proof-format",
        choices=["detached_jws", "signed_git_tag", "sigstore_bundle", "other"],
        help="optional external proof format for the report or release bundle",
    )
    parser.add_argument("--proof-uri", help="URI of an optional external proof artifact")
    parser.add_argument("--proof-key-ref", help="key or identity reference for the optional external proof")
    parser.add_argument(
        "--proof-covered-artifact",
        choices=["implementation_report", "conformance_report", "sut_results", "release_bundle"],
        help="artifact covered by the optional external proof",
    )
    parser.add_argument("--conformance-report-uri")
    if include_identity:
        parser.add_argument("--implementation-name", default="VATE reference artifact checker")
        parser.add_argument("--implementation-type", default="reference-artifact-checker")
        parser.add_argument("--implementation-version", default="0.2")
        parser.add_argument("--implementation-language", default="Python 3 standard library")
        parser.add_argument("--implementation-repo")
        parser.add_argument("--implementation-commit")
        parser.add_argument("--environment")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check VATE AL2 v0.3 fixture artifacts or compare external SUT results")
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run", help="check repository fixture artifacts with the reference runner")
    run.add_argument("--corpus-root", required=True, help="corpus root containing cases/")
    run.add_argument("--report", required=True, help="path to write the machine-readable report")
    add_implementation_report_args(run, include_identity=True)
    index = subparsers.add_parser("index", help="write a language-neutral corpus index")
    index.add_argument("--corpus-root", required=True, help="corpus root containing cases/")
    index.add_argument("--out", required=True, help="path to write the corpus index")
    compare = subparsers.add_parser("compare", help="compare external SUT results against a corpus snapshot")
    compare.add_argument("--corpus-root", required=True, help="corpus root containing cases/")
    compare.add_argument("--sut-results", required=True, help="path to SUT result JSON")
    compare.add_argument("--report", required=True, help="path to write the comparison report")
    add_implementation_report_args(compare, include_identity=False)
    verify_bundle = subparsers.add_parser("verify-bundle", help="verify a report bundle digest chain")
    verify_bundle.add_argument("--corpus-root", required=True, help="corpus root containing corpus.json and cases/")
    verify_bundle.add_argument("--sut-results", help="optional SUT result JSON for external comparison bundles")
    verify_bundle.add_argument("--conformance-report", required=True, help="path to the conformance report JSON")
    verify_bundle.add_argument("--implementation-report", required=True, help="path to the implementation report JSON")
    verify_bundle.add_argument("--report", required=True, help="path to write the bundle verification report")
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if getattr(args, "publication_published_at", None) and try_parse_time(args.publication_published_at) is None:
        raise SystemExit("--publication-published-at must be a valid date-time")

    publication_metadata_args = [
        getattr(args, "publication_controlled_origin", None),
        getattr(args, "publication_published_at", None),
        getattr(args, "publication_immutability", None),
        getattr(args, "proof_uri", None),
    ]
    if any(publication_metadata_args) and not getattr(args, "implementation_report", None):
        raise SystemExit("publication and proof metadata require --implementation-report")
    if any(publication_metadata_args) and not getattr(args, "implementation_report_uri", None):
        raise SystemExit("publication and proof metadata require --implementation-report-uri")
    if any(publication_metadata_args) and not getattr(args, "conformance_report_uri", None):
        raise SystemExit("publication and proof metadata require --conformance-report-uri")

    proof_metadata_args = [
        getattr(args, "proof_format", None),
        getattr(args, "proof_key_ref", None),
        getattr(args, "proof_covered_artifact", None),
    ]
    if any(proof_metadata_args) and not getattr(args, "proof_uri", None):
        raise SystemExit("--proof-format, --proof-key-ref, and --proof-covered-artifact require --proof-uri")


def main() -> int:
    args = parse_args()
    validate_args(args)
    if args.command == "run":
        report = run_corpus(Path(args.corpus_root))
        write_json(Path(args.report), report)
        if args.implementation_report:
            write_json(Path(args.implementation_report), make_implementation_report(args, report))
        if report.get("fatal_errors") or report["summary"]["failed"]:
            return 1
        return 0
    if args.command == "index":
        try:
            index = make_corpus_index(Path(args.corpus_root))
        except (OSError, UnicodeDecodeError, ValueError, RuntimeError) as exc:
            print(f"corpus index generation failed: {exc}", file=sys.stderr)
            return 1
        write_json(Path(args.out), index)
        return 0
    if args.command == "compare":
        report = compare_sut_results(Path(args.corpus_root), Path(args.sut_results))
        write_json(Path(args.report), report)
        if args.implementation_report:
            write_json(Path(args.implementation_report), make_implementation_report(args, report))
        if report.get("fatal_errors") or report["summary"]["failed"]:
            return 1
        return 0
    if args.command == "verify-bundle":
        report = verify_report_bundle(
            Path(args.corpus_root),
            Path(args.conformance_report),
            Path(args.implementation_report),
            Path(args.sut_results) if args.sut_results else None,
        )
        write_json(Path(args.report), report)
        if report["summary"]["failed"]:
            return 1
        return 0
    raise RuntimeError(f"unsupported command {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
