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
from datetime import datetime, timezone
from typing import Any

PROFILE = "VATE-AL2-Verifier-Admission-v0.2"
VERSION = "vate-0.2"


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
        expected_hash = admission_receipt.get("attenuation", {}).get(
            "effective_request_hash",
            admission_receipt.get("request", {}).get("input_hash"),
        )
        actual_hash = post_execution_receipt.get("execution", {}).get("effective_request_hash")
        receipt_id_matches = (
            post_execution_receipt.get("admission", {}).get("receipt_id") == admission_receipt.get("receipt_id")
        )
        hash_matches = expected_hash == actual_hash
        if receipt_id_matches and hash_matches:
            return {
                "outcome": "success",
                "reason_codes": [
                    "ADMISSION_RECEIPT_LINKED",
                    "EFFECTIVE_REQUEST_HASH_MATCH",
                    "NO_POLICY_VIOLATIONS",
                ],
            }
        return {
            "outcome": "failed",
            "reason_codes": ["POST_EXEC_LINKAGE_MISMATCH"],
        }

    def validate_digest(self, artifact: dict[str, Any], digest: dict[str, str]) -> bool:
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
        if request["request_id"] in self._seen_request_ids:
            return ["REPLAY_DETECTED"]
        self._seen_request_ids.add(request["request_id"])

        issued_at = parse_time(request["issued_at"])
        expires_at = parse_time(request["expires_at"])
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
            freshness_seconds = int(status.get("freshness_seconds", 0))
            if checked_at and freshness_seconds:
                age = (now - parse_time(checked_at)).total_seconds()
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
        "input_hash": "sha-256:self-test-input",
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
                    "value": "payment-authority-digest"
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
    attenuated = verifier.admit(sample_request(), now=now)
    assert attenuated["decision"] == "attenuate"
    assert attenuated["admission_receipt"]["attenuation"]["effective_request_hash"]

    allowed_request = set_amount(sample_request(), "USD", 10.0)
    allowed_request["request_id"] = "areq-core-self-test-allow-001"
    allowed = verifier.admit(allowed_request, now=now)
    assert allowed["decision"] == "allow"

    denied_request = sample_request()
    denied_request["request_id"] = "areq-core-self-test-deny-001"
    denied_request["target"]["audience"] = "https://unexpected.example/a2a"
    denied = verifier.admit(denied_request, now=now)
    assert denied["decision"] == "deny"
    assert denied["reason_codes"] == ["AUDIENCE_MISMATCH", "FAIL_CLOSED"]

    post_execution = {
        "admission": {
            "receipt_id": attenuated["admission_receipt"]["receipt_id"],
        },
        "execution": {
            "effective_request_hash": attenuated["admission_receipt"]["attenuation"]["effective_request_hash"],
        },
        "result": {
            "policy_violations": []
        },
    }
    linkage = verifier.validate_post_execution_linkage(attenuated["admission_receipt"], post_execution)
    assert linkage["outcome"] == "success"


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
