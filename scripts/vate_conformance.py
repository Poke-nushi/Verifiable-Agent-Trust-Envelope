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
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "VATE-AL2-Verifier-Admission-v0.3"
VATE_A2A_EXTENSION_URI = "https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/a2a/admission/v0.3"
CONFORMANCE_REPORT_VERSION = "vate-conformance-report-2026-07"
IMPLEMENTATION_REPORT_VERSION = "vate-implementation-report-2026-07"
BUNDLE_VERIFICATION_VERSION = "vate-report-bundle-verification-2026-07"
CORPUS_INDEX_VERSION = "vate-conformance-corpus-2026-07"
CORPUS_INDEX_FILENAME = "corpus.json"
SUT_RESULTS_VERSION = "vate-sut-results-2026-07"
EVIDENCE_VOCABULARY_VERSION = "vate-evidence-vocabulary-2026-07"
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
PROFILE_HASH_RE = re.compile(r"^sha-256:[0-9a-f]{64}$")
CANONICAL_MONEY_VALUE_RE = re.compile(r"^(0|[1-9][0-9]*)(\.[0-9]+)?$")
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


def load_evidence_vocabulary() -> tuple[frozenset[str], frozenset[str], dict[str, frozenset[str]]]:
    registry = json.loads(EVIDENCE_VOCABULARY_PATH.read_text(encoding="utf-8"))
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


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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
    case_paths = sorted((corpus_root / "cases").glob("*.json"))
    cases_by_id: dict[str, dict[str, Any]] = {}
    pairing_case_ids: list[str] = []
    pair_members: dict[str, set[str]] = {}
    failures: list[str] = []

    for case_path in case_paths:
        case = read_json(case_path)
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
        if category not in PAIRING_ROLES:
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
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def try_parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return parse_time(value)
    except ValueError:
        return None


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


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
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def resolve_artifact_path(case: dict[str, Any], key_or_path: str) -> Path:
    artifacts = case.get("artifacts", {})
    rel = artifacts.get(key_or_path, key_or_path)
    path = Path(rel)
    if path.is_absolute():
        return path
    return ROOT / path


def load_artifact(case: dict[str, Any], key: str) -> dict[str, Any] | None:
    rel = case.get("artifacts", {}).get(key)
    if not rel:
        return None
    return read_json(resolve_artifact_path(case, key))


def referenced_paths(case: dict[str, Any]) -> list[Path]:
    paths: list[Path] = []
    for key, value in case.get("artifacts", {}).items():
        if isinstance(value, str):
            paths.append(resolve_artifact_path(case, key))
    for check in case.get("integrity_checks", []):
        paths.append(resolve_artifact_path(case, check["artifact"]))
    for check in case.get("trust_checks", []):
        paths.append(resolve_artifact_path(case, check["trust_bundle"]))
    for check in case.get("jose_checks", []):
        for key in ("proof_package", "detached_payload", "trust_bundle"):
            if key in check:
                paths.append(resolve_artifact_path(case, check[key]))
    for check in case.get("policy_snapshot_checks", []):
        paths.append(resolve_artifact_path(case, check["artifact"]))
    return paths


def corpus_manifest(corpus_root: Path) -> tuple[list[dict[str, str]], dict[str, str]]:
    corpus_index_path = (corpus_root / CORPUS_INDEX_FILENAME).resolve()
    paths: set[Path] = set(
        path.resolve()
        for path in corpus_root.rglob("*.json")
        if path.resolve() != corpus_index_path
    )
    for case_path in sorted((corpus_root / "cases").glob("*.json")):
        case = read_json(case_path)
        for path in referenced_paths(case):
            if path.exists():
                paths.add(path.resolve())

    manifest = [
        {
            "path": display_path(path),
            "sha256": sha256_file(path),
        }
        for path in sorted(paths, key=display_path)
    ]
    return manifest, {"alg": "sha-256", "value": sha256_value(manifest)}


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
        "artifacts": case.get("artifacts", {}),
    }
    if "pairing" in case:
        entry["pairing"] = case["pairing"]
    return entry


def category_counts(cases: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for case in cases:
        category = str(case["category"])
        counts[category] = counts.get(category, 0) + 1
    return dict(sorted(counts.items()))


def make_corpus_index(corpus_root: Path) -> dict[str, Any]:
    case_paths = sorted((corpus_root / "cases").glob("*.json"))
    pairing_failures = corpus_pairing_failures(corpus_root)
    if pairing_failures:
        raise RuntimeError("invalid corpus pairing metadata:\n- " + "\n- ".join(pairing_failures))
    cases = [case_index_entry(path) for path in case_paths]
    manifest, digest = corpus_manifest(corpus_root)
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
    return str(admission_receipt.get("decision", {}).get("outcome", "missing"))


def actual_reason_codes(admission_receipt: dict[str, Any] | None) -> list[str]:
    if admission_receipt is None:
        return []
    codes = admission_receipt.get("decision", {}).get("reason_codes", [])
    return [str(code) for code in codes]


def primary_reason_code(reason_codes: list[str]) -> str | None:
    for code in reason_codes:
        if code not in TERMINAL_REASON_CODES:
            return code
    return None


def reason_code_order_failures(codes: list[str], outcome: str, *, label: str) -> list[str]:
    failures: list[str] = []
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
    if mode not in {"narrow", "require_new_permit", "deny_if_not_accepted"}:
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
            if change.get("op") not in {"add", "remove", "replace"}:
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
    outcome = admission_receipt.get("decision", {}).get("outcome")
    if outcome == "deny":
        return False
    if outcome == "attenuate" and admission_receipt.get("attenuation", {}).get("require_new_permit") is True:
        return False
    return outcome in {"allow", "attenuate"}


def append_unique(items: list[str], item: str) -> None:
    if item not in items:
        items.append(item)


def actual_linkage_reason_codes(
    case: dict[str, Any],
    admission_receipt: dict[str, Any] | None,
    post_execution_receipt: dict[str, Any] | None,
) -> list[str]:
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
    if post_execution_receipt.get("result", {}).get("policy_violations") == []:
        codes.append("NO_POLICY_VIOLATIONS")
    return codes


def linkage_check_contract_failures(index: int, check: Any) -> list[str]:
    if not isinstance(check, dict):
        return [f"linkage[{index}]: expected object"]

    failures: list[str] = []
    kind = check.get("kind")
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
        expected_reason_code = POLICY_VIOLATION_REASON_CODES.get(value)
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
    violations = post_execution.get("result", {}).get("policy_violations")
    if not isinstance(violations, list):
        return ["post_execution.result.policy_violations: expected array"]
    failures: list[str] = []
    for index, token in enumerate(violations):
        if token not in CANONICAL_POLICY_VIOLATION_TOKENS:
            failures.append(f"post_execution.result.policy_violations[{index}]: unknown token {token!r}")
    return failures


def admitted_effective_request_hash(admission_receipt: dict[str, Any]) -> Any:
    if actual_decision(admission_receipt) == "attenuate":
        return admission_receipt.get("attenuation", {}).get("effective_request_hash")
    return admission_receipt.get("request", {}).get("input_hash")


def admitted_effective_constraints(admission_receipt: dict[str, Any]) -> dict[str, Any]:
    attenuation_constraints = admission_receipt.get("attenuation", {}).get("effective_constraints")
    if isinstance(attenuation_constraints, dict):
        return attenuation_constraints
    request_constraints = admission_receipt.get("request", {}).get("constraints")
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
    if (
        admission_decision == "attenuate"
        and admission_receipt.get("attenuation", {}).get("require_new_permit") is True
    ):
        failures.append("post-execution receipt must not link to an admission requiring a new permit")

    if admission_block.get("receipt_id") != admission_receipt.get("receipt_id"):
        failures.append("admission receipt_id mismatch")
    if admission_block.get("decision") != admission_decision:
        failures.append("admission decision mismatch")
    if admission_block.get("digest") != {"alg": "sha-256", "value": sha256_value(admission_receipt)}:
        failures.append("admission digest mismatch")

    request = admission_receipt.get("request", {})
    subject = admission_receipt.get("subject", {})
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

    side_effects = post_execution_receipt.get("result", {}).get("side_effects", [])
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
    return not (
        admission_decision == "attenuate"
        and admission_receipt.get("attenuation", {}).get("require_new_permit") is True
    )


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
    try:
        if kind in {"transaction_id", "runtime", "effective_request_hash", "path_match"}:
            left = get_path(admission, check["admission_path"])
            right = get_path(post_execution, check["post_execution_path"])
            return left != right, None
        if kind == "admission_digest":
            artifact_name = check.get("artifact", "admission_receipt")
            artifact = read_json(resolve_artifact_path(case, artifact_name))
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
    except (KeyError, IndexError, TypeError, ValueError) as exc:
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
        return str(post_execution.get("result", {}).get("outcome", "missing"))
    if "admission_decision" in case["expected"]:
        return actual_decision(admission)
    if post_execution is None:
        return "missing"
    return str(post_execution.get("result", {}).get("outcome", "missing"))


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
        return all(item.get("verification", {}).get("result") == "verified" for item in admission.get("evidence", []))
    if name == "evidence.verification.failure_reason":
        if admission is None:
            return False
        return any(has_path(item, "verification.failure_reason") for item in admission.get("evidence", []))
    if name == "admission_receipt.evidence.verification.inferred_resource_authority":
        if admission is None:
            return False
        return any(
            has_path(item, "verification.inferred_resource_authority")
            for item in admission.get("evidence", [])
        )
    if name == "admission_receipt.evidence.verification.inferred_tool_authority":
        if admission is None:
            return False
        return any(
            has_path(item, "verification.inferred_tool_authority")
            for item in admission.get("evidence", [])
        )
    if name == "policy.policy_version":
        return admission is not None and has_path(admission, "policy.policy_version")
    if name == "post_execution_receipt":
        return post_execution is not None
    if name in {"request.audience", "target.audience"}:
        if admission is None:
            return False
        request = admission.get("request", {})
        return request.get("audience") == request.get("target_audience")
    if name == "result.policy_violations":
        if post_execution is None:
            return False
        return post_execution.get("result", {}).get("policy_violations") == []

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
        artifact = read_json(resolve_artifact_path(case, check["artifact"]))
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
        bundle = read_json(resolve_artifact_path(case, check["trust_bundle"]))
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
    if status in {"revoked", "disabled", "suspended"}:
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
        proof = read_json(resolve_artifact_path(case, check["proof_package"]))
        detached_payload = read_json(resolve_artifact_path(case, check["detached_payload"]))
        trust_bundle = read_json(resolve_artifact_path(case, check["trust_bundle"]))
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
        decoded_protected_json = json.loads(decoded_protected.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
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
        artifact = read_json(resolve_artifact_path(case, check["artifact"]))
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
        artifact = read_json(resolve_artifact_path(case, artifact_name))
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
    if admission is not None and actual_decision(admission) == "attenuate":
        for failure in attenuation_validation_failures(
            admission.get("attenuation"),
            decision_reason_codes=actual_reason_codes(admission),
        ):
            failures.append(f"attenuation: {failure}")

    for check in case.get("attenuation_checks", []):
        artifact = read_json(resolve_artifact_path(case, check["artifact"]))
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
        elif evidence_type in CANONICAL_EVIDENCE_TYPES:
            allowed_hints = ALLOWED_PROTOCOL_HINTS_BY_TYPE.get(evidence_type, frozenset())
            if protocol_hint not in allowed_hints:
                failures.append(f"{label}.protocol_hint is not allowed for evidence type {evidence_type}")
    return failures


def evaluate_al2_context_checks(case: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for check in case.get("al2_context_checks", []):
        artifact = read_json(resolve_artifact_path(case, check["artifact"]))
        kind = check.get("kind")
        if kind == "freshness":
            failures.extend(evaluate_context_freshness_check(check, artifact))
        elif kind == "binding":
            failures.extend(evaluate_context_binding_check(check, artifact))
        elif kind == "replay":
            failures.extend(evaluate_context_replay_check(check, artifact))
        else:
            failures.append(f"al2_context {check.get('artifact')}: unsupported kind {kind}")
    return failures


def evaluate_context_freshness_check(check: dict[str, Any], artifact: dict[str, Any]) -> list[str]:
    checked_at = try_parse_time(artifact.get("checked_at"))
    source_issued_at = try_parse_time(artifact.get("source_issued_at"))
    max_age_seconds = artifact.get("max_age_seconds", check.get("max_age_seconds"))
    failures: list[str] = []
    if not isinstance(check.get("expect_fresh"), bool):
        failures.append(f"al2_context {check['artifact']}: freshness check requires boolean expect_fresh")
    if checked_at is None or source_issued_at is None:
        failures.append(f"al2_context {check['artifact']}: freshness timestamps must be valid")
    if isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int) or max_age_seconds < 0:
        failures.append(f"al2_context {check['artifact']}: max_age_seconds must be a non-negative integer")
    if failures:
        return failures
    age_seconds = (checked_at - source_issued_at).total_seconds()
    fresh = 0 <= age_seconds <= max_age_seconds
    expect_fresh = check["expect_fresh"]
    if fresh != expect_fresh:
        failures.append(f"al2_context {check['artifact']}: expected fresh={expect_fresh} actual fresh={fresh}")
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
    if state not in {"unused", "consumed", "replayed"}:
        failures.append(f"al2_context {check['artifact']}: replay state must be unused, consumed, or replayed")
    if failures:
        return failures
    expect_replayed = check["expect_replayed"]
    replayed = state in {"consumed", "replayed"}
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
    cases = [evaluate_case(path) for path in case_paths]
    manifest, digest = corpus_manifest(corpus_root)
    fatal_errors = corpus_pairing_failures(corpus_root)
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
    for case_path in sorted((corpus_root / "cases").glob("*.json")):
        case = read_json(case_path)
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
            }
        )
    return expectations


def required_sut_artifacts(case: dict[str, Any]) -> dict[str, Any]:
    artifacts = case.get("artifacts", {})
    receipt_artifacts: list[dict[str, str]] = []
    for artifact_name in ("admission_receipt", "post_execution_receipt"):
        if isinstance(artifacts, dict) and artifact_name in artifacts:
            receipt_artifacts.append(
                {
                    "name": artifact_name,
                    "expected_digest": sha256_file(resolve_artifact_path(case, artifact_name)),
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
                    "expected_digest": sha256_file(resolve_artifact_path(case, artifact_name)),
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
                        "expected_digest": sha256_file(resolve_artifact_path(case, artifact_name)),
                    }
                )

    return {
        "receipt_artifacts": receipt_artifacts,
        "verification_context": context_artifacts,
        "proof_artifacts": proof_artifacts,
    }


def artifact_file_binding(case: dict[str, Any], role: str, source_artifact: str) -> dict[str, Any]:
    return {
        "role": role,
        "source_artifact": source_artifact,
        "digest": {
            "alg": "sha-256",
            "value": sha256_file(resolve_artifact_path(case, source_artifact)),
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
    if source in {"runtime_attestation", "status_bundle"}:
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
    artifacts = case.get("artifacts", {})

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
    context_artifact = (
        read_json(resolve_artifact_path(case, context_artifact_name))
        if isinstance(context_artifact_name, str) and context_artifact_name
        else {}
    )
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
        for index, binding in enumerate(raw_bindings):
            failures.extend(context_binding_shape_failures(binding, f"{label}.context_bindings[{index}]"))
    return failures


def context_binding_shape_failures(value: Any, label: str) -> list[str]:
    failures: list[str] = []
    if not isinstance(value, dict):
        return [f"{label}: expected object"]
    role = value.get("role")
    if role not in {"admission_receipt", "admission_request", "transaction_id", "runtime", "evidence"}:
        failures.append(f"{label}.role: expected known context binding role")
    source_artifact = value.get("source_artifact")
    if not isinstance(source_artifact, str) or not source_artifact:
        failures.append(f"{label}.source_artifact: expected non-empty string")

    if role in {"admission_receipt", "admission_request", "evidence"}:
        failures.extend(digest_descriptor_failures(value.get("digest"), f"{label}.digest"))
    if role in {"transaction_id", "runtime", "evidence"}:
        path = value.get("path")
        if not isinstance(path, str) or not path:
            failures.append(f"{label}.path: expected non-empty string")
    if role in {"transaction_id", "runtime"}:
        bound_value = value.get("value")
        if not isinstance(bound_value, str) or not bound_value:
            failures.append(f"{label}.value: expected non-empty string")
    if role == "evidence":
        evidence_type = value.get("evidence_type")
        if not isinstance(evidence_type, str) or not evidence_type:
            failures.append(f"{label}.evidence_type: expected non-empty string")
    return failures


def context_binding_key(binding: dict[str, Any]) -> tuple[Any, Any, Any, Any]:
    return (
        binding.get("role"),
        binding.get("source_artifact"),
        binding.get("path"),
        binding.get("evidence_type"),
    )


def context_binding_match_failures(
    actual_bindings: Any,
    expected_bindings: list[dict[str, Any]],
    label: str,
) -> list[str]:
    if not expected_bindings:
        return []
    if not isinstance(actual_bindings, list):
        return [f"{label}: expected context binding array"]

    actual_by_key: dict[tuple[Any, Any, Any, Any], dict[str, Any]] = {
        context_binding_key(binding): binding
        for binding in actual_bindings
        if isinstance(binding, dict)
    }
    failures: list[str] = []
    for expected in expected_bindings:
        key = context_binding_key(expected)
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
    if kind not in {"jose_proof_package", "jose_detached_payload", "jose_trust_bundle"}:
        failures.append(f"{label}.kind: expected JOSE proof artifact kind")
    case_artifact = value.get("case_artifact")
    if not isinstance(case_artifact, str) or not case_artifact:
        failures.append(f"{label}.case_artifact: expected non-empty string")
    return failures


def sut_result_artifact_failures(result: dict[str, Any], requirements: dict[str, Any]) -> list[str]:
    failures: list[str] = []
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
    if not required_receipts and not required_contexts and not required_proofs:
        return failures

    artifacts = result.get("artifacts")
    if not isinstance(artifacts, dict):
        return ["artifacts: expected object with required artifact references"]

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

        available_contexts: dict[tuple[Any, Any], dict[str, Any]] = {
            (context.get("case_artifact"), context.get("kind")): context
            for context in raw_contexts
            if isinstance(context, dict)
        }
        for expected_context in required_contexts:
            key = (expected_context.get("case_artifact"), expected_context.get("kind"))
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

        available_proofs: dict[tuple[Any, Any], dict[str, Any]] = {
            (proof.get("case_artifact"), proof.get("kind")): proof
            for proof in raw_proofs
            if isinstance(proof, dict)
        }
        for expected_proof in required_proofs:
            key = (expected_proof.get("case_artifact"), expected_proof.get("kind"))
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

    return failures


def compare_sut_results(corpus_root: Path, sut_results_path: Path) -> dict[str, Any]:
    sut_results = read_json(sut_results_path)
    pairing_failures = corpus_pairing_failures(corpus_root)
    expectations = load_case_expectations(corpus_root)
    manifest, digest = corpus_manifest(corpus_root)

    fatal_errors: list[str] = list(pairing_failures)
    if not isinstance(sut_results, dict):
        fatal_errors.append("sut_results: expected object")
        sut_results = {}
    if sut_results.get("version") != SUT_RESULTS_VERSION:
        fatal_errors.append(f"sut_results.version: expected {SUT_RESULTS_VERSION} actual {sut_results.get('version')}")
    if sut_results.get("profile") != PROFILE:
        fatal_errors.append(f"sut_results.profile: expected {PROFILE} actual {sut_results.get('profile')}")

    sut_corpus = sut_results.get("corpus", {})
    if not isinstance(sut_corpus, dict):
        fatal_errors.append("sut_results.corpus: expected object")
        sut_corpus = {}
    if sut_corpus.get("profile") != PROFILE:
        fatal_errors.append(f"sut_results.corpus.profile: expected {PROFILE} actual {sut_corpus.get('profile')}")
    if sut_corpus.get("digest") != digest:
        fatal_errors.append("sut_results.corpus.digest: does not match current corpus digest")

    sut_implementation = sut_results.get("implementation", {})
    if not isinstance(sut_implementation, dict):
        fatal_errors.append("sut_results.implementation: expected object")
        sut_implementation = {}

    raw_results = sut_results.get("results", [])
    if not isinstance(raw_results, list):
        fatal_errors.append("sut_results.results: expected array")
        raw_results = []

    result_by_case: dict[str, dict[str, Any]] = {}
    duplicate_cases: set[str] = set()
    for index, result in enumerate(raw_results):
        if not isinstance(result, dict):
            fatal_errors.append(f"sut_results.results[{index}]: expected object")
            continue
        case_id = result.get("case_id")
        if not isinstance(case_id, str):
            fatal_errors.append(f"sut_results.results[{index}]: result missing string case_id")
            continue
        if case_id in result_by_case:
            duplicate_cases.add(case_id)
        result_by_case[case_id] = result
    for case_id in sorted(duplicate_cases):
        fatal_errors.append(f"sut_results.results: duplicate case_id {case_id}")

    expected_case_ids = {case["case_id"] for case in expectations}
    for case_id in sorted(set(result_by_case) - expected_case_ids):
        fatal_errors.append(f"sut_results.results: unknown case_id {case_id}")

    cases: list[dict[str, Any]] = []
    for expected in expectations:
        result = result_by_case.get(expected["case_id"])
        failures: list[str] = []
        if result is None:
            actual_outcome = "missing"
            actual_should_execute_value = None
            actual_reason_codes: list[str] = []
            failures.append("sut result missing")
        else:
            actual_outcome = str(result.get("outcome", "missing"))
            raw_should_execute = result.get("should_execute")
            if isinstance(raw_should_execute, bool):
                actual_should_execute_value = raw_should_execute
                if actual_should_execute_value != expected["expected_should_execute"]:
                    failures.append(
                        "should_execute: "
                        f"expected {expected['expected_should_execute']} actual {actual_should_execute_value}"
                    )
            else:
                actual_should_execute_value = None
                failures.append("should_execute: expected boolean")
            raw_reason_codes = result.get("reason_codes", [])
            if not isinstance(raw_reason_codes, list):
                actual_reason_codes = []
                failures.append("reason_codes: expected array")
            else:
                actual_reason_codes = [str(code) for code in raw_reason_codes]
            status = result.get("status")
            if status == "skipped":
                failures.append("sut result skipped")
            elif status != "completed":
                failures.append(f"sut result status: expected completed actual {status}")

            if actual_outcome != expected["expected_outcome"]:
                failures.append(f"outcome: expected {expected['expected_outcome']} actual {actual_outcome}")
            if actual_reason_codes != expected["expected_reason_codes"]:
                failures.append(f"reason_codes: expected {expected['expected_reason_codes']} actual {actual_reason_codes}")
            if primary_reason_code(actual_reason_codes) != expected["expected_primary_reason_code"]:
                failures.append(
                    "primary_reason_code: "
                    f"expected {expected['expected_primary_reason_code']} "
                    f"actual {primary_reason_code(actual_reason_codes)}"
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
            check_results = {
                check.get("name"): check
                for check in raw_checks
                if isinstance(check, dict)
            }
            for check in expected["expected_checks"]:
                actual_check = check_results.get(check["name"])
                if actual_check is None:
                    failures.append(f"check {check['name']}: missing")
                    continue
                if actual_check.get("pass") is not True:
                    failures.append(f"check {check['name']}: expected pass")
            failures.extend(sut_result_artifact_failures(result, expected["required_artifacts"]))

        cases.append(
            {
                "case_id": expected["case_id"],
                "category": expected["category"],
                "expected_outcome": expected["expected_outcome"],
                "actual_outcome": actual_outcome,
                "expected_should_execute": expected["expected_should_execute"],
                "actual_should_execute": actual_should_execute_value,
                "expected_primary_reason_code": expected["expected_primary_reason_code"],
                "actual_primary_reason_code": primary_reason_code(actual_reason_codes),
                "expected_reason_codes": expected["expected_reason_codes"],
                "actual_reason_codes": actual_reason_codes,
                "pass": not failures,
                "failures": failures,
            }
        )

    failed = sum(1 for case in cases if not case["pass"])
    skipped = sum(1 for result in result_by_case.values() if result.get("status") == "skipped")
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


def summary_status(summary: Any) -> str:
    if not isinstance(summary, dict):
        return "fail"
    if summary.get("failed"):
        return "fail"
    if summary.get("skipped"):
        return "partial"
    return "pass"


def conformance_report_status(report: dict[str, Any]) -> str:
    if report.get("fatal_errors"):
        return "fail"
    return summary_status(report.get("summary"))


def implementation_case_results_match(
    conformance_report: dict[str, Any],
    implementation_report: dict[str, Any],
) -> bool:
    conformance_cases = conformance_report.get("cases")
    implementation_cases = implementation_report.get("case_results")
    if not isinstance(conformance_cases, list) or not isinstance(implementation_cases, list):
        return False
    expected = [
        {
            "case_id": case.get("case_id"),
            "expected_outcome": case.get("expected_outcome"),
            "actual_outcome": case.get("actual_outcome"),
            "expected_should_execute": case.get("expected_should_execute"),
            "actual_should_execute": case.get("actual_should_execute"),
            "expected_primary_reason_code": case.get("expected_primary_reason_code"),
            "actual_primary_reason_code": case.get("actual_primary_reason_code"),
            "pass": case.get("pass"),
        }
        for case in conformance_cases
    ]
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


def verify_report_bundle(
    corpus_root: Path,
    conformance_report_path: Path,
    implementation_report_path: Path,
    sut_results_path: Path | None,
) -> dict[str, Any]:
    raw_conformance_report = read_json(conformance_report_path)
    raw_implementation_report = read_json(implementation_report_path)
    raw_sut_results = read_json(sut_results_path) if sut_results_path else None
    manifest, corpus_digest = corpus_manifest(corpus_root)

    checks: list[dict[str, Any]] = []
    conformance_report = json_object_or_empty(raw_conformance_report, checks, "conformance_report")
    implementation_report = json_object_or_empty(raw_implementation_report, checks, "implementation_report")
    sut_results = (
        json_object_or_empty(raw_sut_results, checks, "sut_results")
        if sut_results_path
        else None
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

    corpus_index = read_json(corpus_root / CORPUS_INDEX_FILENAME)
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

    conformance_corpus = conformance_report.get("corpus", {})
    add_bundle_check(
        checks,
        "conformance_report.corpus.digest",
        isinstance(conformance_corpus, dict) and conformance_corpus.get("digest") == corpus_digest,
        expected=corpus_digest,
        actual=conformance_corpus.get("digest") if isinstance(conformance_corpus, dict) else None,
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
    if sut_results_path:
        sut_digest = digest_descriptor(sut_results)
        sut_corpus = sut_results.get("corpus", {}) if isinstance(sut_results, dict) else {}
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
    else:
        add_bundle_check(
            checks,
            "sut_results.provided",
            conformance_sut is None,
            expected="no SUT result file is required for a reference run bundle",
            actual="SUT result file missing" if conformance_sut is not None else "not applicable",
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
    manifest, digest = corpus_manifest(corpus_root)

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
            {
                "case_id": case["case_id"],
                "expected_outcome": case["expected_outcome"],
                "actual_outcome": case["actual_outcome"],
                "expected_should_execute": case["expected_should_execute"],
                "actual_should_execute": case["actual_should_execute"],
                "expected_primary_reason_code": case["expected_primary_reason_code"],
                "actual_primary_reason_code": case["actual_primary_reason_code"],
                "pass": case["pass"],
            }
            for case in conformance_report["cases"]
        ],
        "limitations": [
            "This report records one implementation run against one corpus snapshot.",
            "Passing cases do not imply production readiness or endorsement.",
        ],
    }
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
        write_json(Path(args.out), make_corpus_index(Path(args.corpus_root)))
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
