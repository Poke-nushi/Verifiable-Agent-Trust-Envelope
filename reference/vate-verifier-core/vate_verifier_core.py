#!/usr/bin/env python3
"""Dependency-free VATE AL2 verifier core.

This module is intentionally small. It provides deterministic verifier behavior
for conformance fixtures and adapter demos without defining production JOSE,
PKI, identity, or payment protocols.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

PROFILE = "VATE-AL2-Verifier-Admission-v0.2"
VERSION = "vate-0.2"
EXECUTABLE_ADMISSION_DECISIONS = {"allow", "attenuate"}
PROFILE_HASH_RE = re.compile(r"^sha-256:[0-9a-f]{64}$")


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_hash(value: Any) -> str:
    return "sha-256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def digest_value(value: Any) -> str:
    return canonical_hash(value).removeprefix("sha-256:")


def is_profile_hash(value: Any) -> bool:
    return isinstance(value, str) and PROFILE_HASH_RE.fullmatch(value) is not None


def safe_parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return parse_time(value)
    except ValueError:
        return None


def safe_decimal_amount(value: Any) -> Decimal | None:
    if isinstance(value, bool):
        return None
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    if not amount.is_finite() or amount < 0:
        return None
    return amount


def safe_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def side_effects_exceed_constraints(
    side_effects: Any,
    effective_constraints: Any,
) -> bool:
    if not isinstance(side_effects, list) or not isinstance(effective_constraints, dict):
        return False

    max_amount = effective_constraints.get("max_amount")
    if isinstance(max_amount, dict):
        max_value = safe_decimal_amount(max_amount.get("value"))
        max_currency = max_amount.get("currency")
        if max_value is None or not isinstance(max_currency, str):
            return True
        total_amount = Decimal("0")
        for effect in side_effects:
            if not isinstance(effect, dict):
                continue
            amount = effect.get("amount")
            if not isinstance(amount, dict):
                continue
            actual_value = safe_decimal_amount(amount.get("value"))
            actual_currency = amount.get("currency")
            if actual_value is None or not isinstance(actual_currency, str):
                return True
            if actual_currency != max_currency:
                return True
            total_amount += actual_value
            if total_amount > max_value:
                return True

    tool_allowlist = effective_constraints.get("tool_allowlist")
    if isinstance(tool_allowlist, list):
        allowed_tools = {str(tool) for tool in tool_allowlist}
        for effect in side_effects:
            if not isinstance(effect, dict):
                continue
            tool = effect.get("tool") or effect.get("tool_id") or effect.get("name")
            if tool is not None and str(tool) not in allowed_tools:
                return True

    return False


def admitted_effective_constraints(admission_receipt: dict[str, Any]) -> dict[str, Any]:
    attenuation_constraints = admission_receipt.get("attenuation", {}).get("effective_constraints")
    if isinstance(attenuation_constraints, dict):
        return attenuation_constraints
    request_constraints = admission_receipt.get("request", {}).get("constraints")
    if isinstance(request_constraints, dict):
        return request_constraints
    return {}


def get_amount(request: dict[str, Any]) -> tuple[str, float] | None:
    amount = request.get("constraints", {}).get("max_amount")
    if not isinstance(amount, dict):
        return None
    try:
        return str(amount.get("currency", "USD")), float(amount["value"])
    except (KeyError, TypeError, ValueError):
        return None


def set_amount(request: dict[str, Any], currency: str, value: float) -> dict[str, Any]:
    effective = copy.deepcopy(request)
    effective.setdefault("constraints", {})["max_amount"] = {
        "currency": currency,
        "value": f"{value:.2f}",
    }
    return effective


class VateVerifier:
    """Small verifier core for AL2 admission examples."""

    def __init__(
        self,
        *,
        verifier_id: str,
        policy: dict[str, Any] | None = None,
        trust_bundle: dict[str, Any] | None = None,
        fail_closed: bool = True,
    ) -> None:
        self.verifier_id = verifier_id
        self.policy = policy or {}
        self.trust_bundle = trust_bundle or {"issuers": []}
        self.fail_closed = fail_closed
        self._seen_request_ids: set[str] = set()

    def admit(self, admission_request: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        now = now or utc_now()
        failures = self._validate_admission_request(admission_request, now=now)
        if failures:
            codes = [failures[0]]
            if self.fail_closed and "FAIL_CLOSED" not in codes:
                codes.append("FAIL_CLOSED")
            receipt = self._make_receipt(admission_request, now=now, outcome="deny", reason_codes=codes)
            return {
                "decision": "deny",
                "reason_codes": codes,
                "admission_receipt": receipt,
            }

        attenuation = self._maybe_attenuate(admission_request)
        if attenuation:
            receipt = self._make_receipt(
                attenuation["effective_request"],
                now=now,
                outcome="attenuate",
                reason_codes=attenuation["reason_codes"],
                attenuation=attenuation["attenuation"],
            )
            return {
                "decision": "attenuate",
                "reason_codes": attenuation["reason_codes"],
                "admission_receipt": receipt,
            }

        receipt = self._make_receipt(
            admission_request,
            now=now,
            outcome="allow",
            reason_codes=["EVIDENCE_VERIFIED", "POLICY_MATCH"],
        )
        return {
            "decision": "allow",
            "reason_codes": ["EVIDENCE_VERIFIED", "POLICY_MATCH"],
            "admission_receipt": receipt,
        }

    def validate_post_execution_linkage(
        self,
        admission_receipt: dict[str, Any],
        post_execution_receipt: dict[str, Any],
    ) -> dict[str, Any]:
        admission = post_execution_receipt.get("admission")
        execution = post_execution_receipt.get("execution")
        result = post_execution_receipt.get("result")
        if not isinstance(admission, dict) or not isinstance(execution, dict) or not isinstance(result, dict):
            return {
                "outcome": "failed",
                "reason_codes": ["POST_EXEC_LINKAGE_MISMATCH"],
            }

        failures: list[str] = []
        expected_hash = admission_receipt.get("attenuation", {}).get(
            "effective_request_hash",
            admission_receipt.get("request", {}).get("input_hash"),
        )
        if admission.get("receipt_id") != admission_receipt.get("receipt_id"):
            failures.append("POST_EXEC_LINKAGE_MISMATCH")

        if not self.validate_digest(admission_receipt, admission.get("digest", {})):
            failures.append("POST_EXEC_ADMISSION_DIGEST_MISMATCH")

        receipt_decision = admission_receipt.get("decision", {}).get("outcome")
        post_decision = admission.get("decision")
        if receipt_decision not in EXECUTABLE_ADMISSION_DECISIONS or post_decision == "deny":
            failures.append("POST_EXEC_ADMISSION_DENIED")
        elif post_decision != receipt_decision:
            failures.append("POST_EXEC_LINKAGE_MISMATCH")

        if execution.get("transaction_id") != admission_receipt.get("request", {}).get("transaction_id"):
            failures.append("POST_EXEC_TRANSACTION_MISMATCH")

        if execution.get("runtime") != admission_receipt.get("subject", {}).get("runtime"):
            failures.append("POST_EXEC_RUNTIME_MISMATCH")

        execution_hash = execution.get("effective_request_hash")
        if (
            not is_profile_hash(expected_hash)
            or not is_profile_hash(execution_hash)
            or execution_hash != expected_hash
        ):
            failures.append("POST_EXEC_EFFECTIVE_REQUEST_HASH_MISMATCH")

        issued_at = safe_parse_time(admission_receipt.get("issued_at"))
        expires_at = safe_parse_time(admission_receipt.get("expires_at"))
        started_at = safe_parse_time(execution.get("started_at"))
        finished_at = safe_parse_time(execution.get("finished_at"))
        if (
            issued_at is None
            or expires_at is None
            or started_at is None
            or finished_at is None
            or started_at < issued_at
            or finished_at < started_at
            or expires_at < started_at
            or expires_at < finished_at
        ):
            failures.append("POST_EXEC_ADMISSION_EXPIRED")

        effective_constraints = admitted_effective_constraints(admission_receipt)
        policy_violations = result.get("policy_violations")
        if policy_violations or side_effects_exceed_constraints(result.get("side_effects"), effective_constraints):
            failures.append("POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED")

        if failures:
            return {
                "outcome": "failed",
                "reason_codes": list(dict.fromkeys(failures)),
            }

        return {
            "outcome": "success",
            "reason_codes": [
                "ADMISSION_RECEIPT_LINKED",
                "ADMISSION_DIGEST_MATCH",
                "ADMISSION_DECISION_EXECUTABLE",
                "TRANSACTION_MATCH",
                "RUNTIME_MATCH",
                "ADMISSION_WINDOW_VALID",
                "EFFECTIVE_REQUEST_HASH_MATCH",
                "EFFECTIVE_CONSTRAINTS_OBSERVED",
                "NO_POLICY_VIOLATIONS",
            ],
        }

    def validate_digest(self, artifact: dict[str, Any], digest: dict[str, str]) -> bool:
        if not isinstance(digest, dict):
            return False
        if digest.get("alg") != "sha-256":
            return False
        return hashlib.sha256(canonical_bytes(artifact)).hexdigest() == digest.get("value")

    def is_trusted(self, *, issuer_id: str, kid: str, evidence_type: str) -> bool:
        for issuer in self.trust_bundle.get("issuers", []):
            if issuer.get("issuer_id") != issuer_id:
                continue
            if issuer.get("kid") != kid:
                continue
            if evidence_type not in issuer.get("allowed_evidence_types", []):
                continue
            return True
        return False

    def verify_jws_hook(self, proof: dict[str, Any]) -> bool:
        """Demo hook for proof verification.

        Production profiles must replace this with real JOSE verification.
        In the conformance core, an explicit `verification_result: failed` fails.
        """

        return proof.get("verification_result", "verified") != "failed"

    def _validate_admission_request(self, request: dict[str, Any], *, now: datetime) -> list[str]:
        required = [
            "version",
            "profile",
            "request_id",
            "transaction_id",
            "issued_at",
            "expires_at",
            "action",
            "target",
            "actor",
            "principal",
            "runtime",
            "audience",
            "input_hash",
            "evidence_refs",
        ]
        if any(key not in request for key in required):
            return ["SCHEMA_INVALID"]
        if request["version"] != VERSION or request["profile"] != PROFILE:
            return ["SCHEMA_INVALID"]
        if not is_profile_hash(request.get("input_hash")):
            return ["SCHEMA_INVALID"]
        if request["request_id"] in self._seen_request_ids:
            return ["REPLAY_DETECTED"]
        self._seen_request_ids.add(request["request_id"])

        issued_at = safe_parse_time(request.get("issued_at"))
        expires_at = safe_parse_time(request.get("expires_at"))
        if issued_at is None or expires_at is None:
            return ["SCHEMA_INVALID"]
        if issued_at > now:
            return ["PERMIT_NOT_YET_VALID"]
        if expires_at < now:
            return ["PERMIT_EXPIRED"]

        if request.get("target", {}).get("audience") != request.get("audience"):
            return ["AUDIENCE_MISMATCH"]

        expected_runtime = request.get("constraints", {}).get("expected_runtime")
        if expected_runtime and request.get("runtime") != expected_runtime:
            return ["RUNTIME_MISMATCH"]

        status = request.get("constraints", {}).get("status")
        if isinstance(status, dict):
            state = status.get("state")
            if state in {"revoked", "suspended", "quarantined"}:
                return ["STATUS_REVOKED"]
            checked_at = status.get("checked_at")
            freshness_seconds = safe_int(status.get("freshness_seconds", 0))
            if freshness_seconds is None or freshness_seconds < 0:
                return ["SCHEMA_INVALID"]
            if checked_at and freshness_seconds:
                checked_at_time = safe_parse_time(checked_at)
                if checked_at_time is None:
                    return ["SCHEMA_INVALID"]
                age = (now - checked_at_time).total_seconds()
                if age > freshness_seconds:
                    return ["STATUS_STALE"]

        allowed_actions = self.policy.get("allowed_actions")
        if allowed_actions and request["action"] not in allowed_actions:
            return ["ACTION_NOT_PERMITTED"]

        return []

    def _maybe_attenuate(self, request: dict[str, Any]) -> dict[str, Any] | None:
        max_amount = self.policy.get("max_amount")
        requested = get_amount(request)
        if max_amount is None or requested is None:
            return None
        currency, requested_value = requested
        max_value = float(max_amount["value"])
        if requested_value <= max_value:
            return None

        effective = set_amount(request, currency, max_value)
        attenuation = {
            "mode": "narrow",
            "original_request_hash": canonical_hash(request),
            "effective_request_hash": canonical_hash(effective),
            "changes": [
                {
                    "op": "replace",
                    "path": "/constraints/max_amount/value",
                    "from": f"{requested_value:.2f}",
                    "to": f"{max_value:.2f}",
                    "reason_code": "LOCAL_POLICY_MAX_AMOUNT_NARROWED",
                }
            ],
            "effective_constraints": effective.get("constraints", {}),
            "require_new_permit": False,
        }
        return {
            "effective_request": effective,
            "reason_codes": ["LOCAL_POLICY_MAX_AMOUNT_NARROWED"],
            "attenuation": attenuation,
        }

    def _make_receipt(
        self,
        request: dict[str, Any],
        *,
        now: datetime,
        outcome: str,
        reason_codes: list[str],
        attenuation: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        receipt = {
            "version": VERSION,
            "profile": PROFILE,
            "receipt_type": "admission",
            "receipt_id": "admrec-" + request.get("request_id", "schema-invalid"),
            "issued_at": iso(now),
            "expires_at": request.get("expires_at", iso(now)),
            "verifier": {
                "id": self.verifier_id,
            },
            "request": {
                "request_id": request.get("request_id", "missing"),
                "transaction_id": request.get("transaction_id", "missing"),
                "action": request.get("action", "missing"),
                "input_hash": request.get("input_hash", canonical_hash(request)),
            },
            "subject": {
                "principal": request.get("principal", "missing"),
                "actor": request.get("actor", "missing"),
                "runtime": request.get("runtime", "missing"),
            },
            "evidence": [
                {
                    "type": evidence.get("type", "unknown"),
                    "uri": evidence.get("uri", "missing"),
                    "digest": evidence.get("digest", {"alg": "sha-256", "value": "missing"}),
                    "verification": {
                        "result": "verified" if outcome != "deny" else "failed",
                        "checked_at": iso(now),
                        "method": "vate-verifier-core",
                    },
                }
                for evidence in request.get("evidence_refs", [])
            ],
            "policy": {
                "policy_id": self.policy.get("policy_id", "local-policy"),
                "policy_version": self.policy.get("policy_version", "unversioned"),
                "policy_ref": self.policy.get("policy_ref", "local"),
            },
            "decision": {
                "outcome": outcome,
                "reason_codes": reason_codes,
            },
        }
        if isinstance(request.get("constraints"), dict):
            receipt["request"]["constraints"] = copy.deepcopy(request["constraints"])
        if attenuation is not None:
            receipt["attenuation"] = attenuation
        return receipt


def sample_request() -> dict[str, Any]:
    return {
        "version": VERSION,
        "profile": PROFILE,
        "request_id": "areq-core-self-test-001",
        "transaction_id": "txn-core-self-test-001",
        "issued_at": "2026-07-01T00:00:00Z",
        "expires_at": "2026-07-01T00:10:00Z",
        "action": "commerce.purchase",
        "target": {
            "resource": "https://merchant.example/checkout",
            "audience": "https://verifier.example/a2a"
        },
        "actor": "did:web:agent.example",
        "principal": "did:web:user.example",
        "runtime": "spiffe://agent.example/workload/purchase-agent",
        "audience": "https://verifier.example/a2a",
        "input_hash": "sha-256:a0b7d342a0c1eec92f653fb11227398206a66d8fb66f1eefc6ec7812f2741d3c",
        "constraints": {
            "max_amount": {
                "currency": "USD",
                "value": "120.00"
            }
        },
        "evidence_refs": [
            {
                "type": "payment_authority",
                "uri": "https://wallet.example/payment-authorities/self-test",
                "media_type": "application/json",
                "digest": {
                    "alg": "sha-256",
                    "value": "1af1019b9c5418522a8473029f095e2b3d27d30c839976a4765e722af32d6031"
                }
            }
        ]
    }


def run_self_test() -> None:
    now = parse_time("2026-07-01T00:01:00Z")
    verifier = VateVerifier(
        verifier_id="did:web:verifier.example",
        policy={
            "policy_id": "merchant-purchase-al2",
            "policy_version": "2026-07-01.1",
            "policy_ref": "https://verifier.example/policies/merchant-purchase-al2/2026-07-01.1",
            "allowed_actions": ["commerce.purchase"],
            "max_amount": {
                "currency": "USD",
                "value": "25.00",
            },
        },
    )

    def assert_schema_invalid_denial(request: dict[str, Any]) -> None:
        result = verifier.admit(request, now=now)
        assert result["decision"] == "deny"
        assert result["reason_codes"] == ["SCHEMA_INVALID", "FAIL_CLOSED"]

    attenuated = verifier.admit(sample_request(), now=now)
    assert attenuated["decision"] == "attenuate"
    assert attenuated["admission_receipt"]["attenuation"]["effective_request_hash"]

    allowed_request = set_amount(sample_request(), "USD", 10.0)
    allowed_request["request_id"] = "areq-core-self-test-allow-001"
    allowed = verifier.admit(allowed_request, now=now)
    assert allowed["decision"] == "allow"
    allowed_receipt = allowed["admission_receipt"]
    assert allowed_receipt["request"]["constraints"]["max_amount"]["value"] == "10.00"

    invalid_hash_request = sample_request()
    invalid_hash_request["request_id"] = "areq-core-self-test-invalid-hash-001"
    invalid_hash_request["input_hash"] = "sha-256:not-a-lowercase-hex-digest"
    assert_schema_invalid_denial(invalid_hash_request)

    malformed_issued_at_request = sample_request()
    malformed_issued_at_request["request_id"] = "areq-core-self-test-malformed-issued-at-001"
    malformed_issued_at_request["issued_at"] = "not-a-timestamp"
    assert_schema_invalid_denial(malformed_issued_at_request)

    malformed_expires_at_request = sample_request()
    malformed_expires_at_request["request_id"] = "areq-core-self-test-malformed-expires-at-001"
    malformed_expires_at_request["expires_at"] = "not-a-timestamp"
    assert_schema_invalid_denial(malformed_expires_at_request)

    malformed_status_checked_at_request = sample_request()
    malformed_status_checked_at_request["request_id"] = "areq-core-self-test-malformed-status-checked-at-001"
    malformed_status_checked_at_request["constraints"]["status"] = {
        "state": "valid",
        "checked_at": "not-a-timestamp",
        "freshness_seconds": 300,
    }
    assert_schema_invalid_denial(malformed_status_checked_at_request)

    malformed_status_freshness_request = sample_request()
    malformed_status_freshness_request["request_id"] = "areq-core-self-test-malformed-status-freshness-001"
    malformed_status_freshness_request["constraints"]["status"] = {
        "state": "valid",
        "checked_at": "2026-07-01T00:00:00Z",
        "freshness_seconds": "not-an-int",
    }
    assert_schema_invalid_denial(malformed_status_freshness_request)

    denied_request = sample_request()
    denied_request["request_id"] = "areq-core-self-test-deny-001"
    denied_request["target"]["audience"] = "https://unexpected.example/a2a"
    denied = verifier.admit(denied_request, now=now)
    assert denied["decision"] == "deny"
    assert denied["reason_codes"] == ["AUDIENCE_MISMATCH", "FAIL_CLOSED"]

    admission_receipt = attenuated["admission_receipt"]
    post_execution = {
        "admission": {
            "receipt_id": admission_receipt["receipt_id"],
            "digest": {
                "alg": "sha-256",
                "value": digest_value(admission_receipt),
            },
            "decision": admission_receipt["decision"]["outcome"],
        },
        "execution": {
            "transaction_id": admission_receipt["request"]["transaction_id"],
            "effective_request_hash": admission_receipt["attenuation"]["effective_request_hash"],
            "runtime": admission_receipt["subject"]["runtime"],
            "started_at": "2026-07-01T00:02:00Z",
            "finished_at": "2026-07-01T00:03:00Z",
        },
        "result": {
            "side_effects": [
                {
                    "type": "payment_authorization",
                    "amount": {
                        "currency": "USD",
                        "value": "25.00",
                    },
                }
            ],
            "policy_violations": []
        },
    }
    linkage = verifier.validate_post_execution_linkage(admission_receipt, post_execution)
    assert linkage["outcome"] == "success"

    allow_post_execution = copy.deepcopy(post_execution)
    allow_post_execution["admission"] = {
        "receipt_id": allowed_receipt["receipt_id"],
        "digest": {
            "alg": "sha-256",
            "value": digest_value(allowed_receipt),
        },
        "decision": allowed_receipt["decision"]["outcome"],
    }
    allow_post_execution["execution"]["transaction_id"] = allowed_receipt["request"]["transaction_id"]
    allow_post_execution["execution"]["effective_request_hash"] = allowed_receipt["request"]["input_hash"]
    allow_post_execution["execution"]["runtime"] = allowed_receipt["subject"]["runtime"]
    allow_post_execution["result"]["side_effects"][0]["amount"]["value"] = "12.00"
    linkage = verifier.validate_post_execution_linkage(allowed_receipt, allow_post_execution)
    assert linkage["outcome"] == "failed"
    assert "POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED" in linkage["reason_codes"]

    bad_transaction = copy.deepcopy(post_execution)
    bad_transaction["execution"]["transaction_id"] = "txn-core-self-test-spoofed"
    linkage = verifier.validate_post_execution_linkage(admission_receipt, bad_transaction)
    assert linkage["outcome"] == "failed"
    assert "POST_EXEC_TRANSACTION_MISMATCH" in linkage["reason_codes"]

    bad_runtime = copy.deepcopy(post_execution)
    bad_runtime["execution"]["runtime"] = "spiffe://agent.example/workload/spoofed-runtime"
    linkage = verifier.validate_post_execution_linkage(admission_receipt, bad_runtime)
    assert linkage["outcome"] == "failed"
    assert "POST_EXEC_RUNTIME_MISMATCH" in linkage["reason_codes"]

    denied_linkage = copy.deepcopy(post_execution)
    denied_linkage["admission"]["decision"] = "deny"
    linkage = verifier.validate_post_execution_linkage(admission_receipt, denied_linkage)
    assert linkage["outcome"] == "failed"
    assert "POST_EXEC_ADMISSION_DENIED" in linkage["reason_codes"]

    expired_linkage = copy.deepcopy(post_execution)
    expired_linkage["execution"]["started_at"] = "2026-07-01T00:11:00Z"
    expired_linkage["execution"]["finished_at"] = "2026-07-01T00:12:00Z"
    linkage = verifier.validate_post_execution_linkage(admission_receipt, expired_linkage)
    assert linkage["outcome"] == "failed"
    assert "POST_EXEC_ADMISSION_EXPIRED" in linkage["reason_codes"]

    exceeded_constraints = copy.deepcopy(post_execution)
    exceeded_constraints["result"]["side_effects"][0]["amount"]["value"] = "30.00"
    linkage = verifier.validate_post_execution_linkage(admission_receipt, exceeded_constraints)
    assert linkage["outcome"] == "failed"
    assert "POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED" in linkage["reason_codes"]

    aggregate_exceeded_constraints = copy.deepcopy(post_execution)
    aggregate_exceeded_constraints["result"]["side_effects"] = [
        {
            "type": "payment_authorization",
            "amount": {
                "currency": "USD",
                "value": "20.00",
            },
        },
        {
            "type": "payment_authorization",
            "amount": {
                "currency": "USD",
                "value": "10.00",
            },
        },
    ]
    linkage = verifier.validate_post_execution_linkage(admission_receipt, aggregate_exceeded_constraints)
    assert linkage["outcome"] == "failed"
    assert "POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED" in linkage["reason_codes"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VATE verifier core utility")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("self-test", help="run dependency-free verifier core self-test")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "self-test":
        run_self_test()
        return 0
    raise RuntimeError(f"unsupported command {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
