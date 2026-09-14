"""Demo-local file-set admission composed with the unchanged VATE core."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from demo_contract import (
    ACTION, CONTRACT, FILE_RE, RUNTIME, VERIFIER, action_binding, core, decode,
    digest, encode, exact, identifier, need, object_hash, time_value, validate_operation,
)

LOCAL_CHECKS = ["operation_shape_and_sandbox", "permit_identity_and_input_binding",
                "policy_shape_and_known_evaluators", "request_and_evidence_binding"]
MAX_PERMIT_LIFETIME = timedelta(minutes=10)


@dataclass(frozen=True)
class Authorization:
    """Immutable preimages, held explicitly instead of reconstructed from a receipt."""

    original: bytes
    permit: bytes
    request: bytes
    core_result: bytes
    receipt: bytes
    effective: bytes | None
    record: bytes


def make_policy(*, require_new_permit: bool = False) -> dict:
    return {"policy_id": "demo-file-set", "policy_version": "1", "policy_ref": "local:policy.json",
            "allowed_actions": [ACTION], "allowed_output_names": ["summary.txt"],
            "require_new_permit": require_new_permit}


def make_permit(operation: dict, authorization_key: str, *, issued_at: str, status: str = "active") -> dict:
    return {"contract": CONTRACT, "authorization_key": authorization_key,
            "operation_key": operation["operation_key"], "input_hash": object_hash(operation),
            "issued_at": issued_at, "expires_at": core.iso(time_value(issued_at) + MAX_PERMIT_LIFETIME),
            "status": status}


def make_request(operation: dict, permit: dict, permit_uri: str) -> dict:
    return {
        "version": core.VERSION, "profile": core.PROFILE,
        "request_id": "request-" + permit["authorization_key"],
        "transaction_id": operation["operation_key"], "issued_at": permit["issued_at"],
        "expires_at": permit["expires_at"], "action": operation["action"],
        "target": {"resource": operation["target"]["resource"], "audience": RUNTIME},
        "actor": "urn:vate:demo:requester", "principal": "urn:vate:demo:local-owner",
        "runtime": RUNTIME, "audience": RUNTIME, "input_hash": object_hash(operation),
        "constraints": {"tool_allowlist": [ACTION], "target_resource": operation["target"]["resource"],
                        "demo_output_names": [f["name"] for f in operation["target"]["files"]],
                        "expected_runtime": RUNTIME, "status": {"state": permit["status"]}},
        "evidence_refs": [{"type": "mission_permit", "uri": permit_uri,
                           "media_type": "application/json", "digest": digest(encode(permit))}],
    }


def evaluate(operation: dict, permit: dict, policy: dict, *, resource: str,
             permit_uri: str, evaluated_at: str) -> Authorization:
    """Validate local inputs, run the core, then apply a local subset contract.

    The permit is a controller-owned, unsigned demo record. A matching digest
    proves content binding here, not credentials, issuer authenticity or PKI.
    """
    validate_operation(operation, resource)
    exact(permit, {"contract", "authorization_key", "operation_key", "input_hash", "issued_at",
                   "expires_at", "status"}, "permit")
    identifier(permit["authorization_key"])
    need(permit["contract"] == CONTRACT and permit["operation_key"] == operation["operation_key"]
         and permit["input_hash"] == object_hash(operation), "permit input/operation mismatch")
    need(permit["status"] in ("active", "revoked"), "unknown permit status")
    lifetime = time_value(permit["expires_at"]) - time_value(permit["issued_at"])
    need(timedelta(0) < lifetime <= MAX_PERMIT_LIFETIME, "invalid permit window")
    exact(policy, {"policy_id", "policy_version", "policy_ref", "allowed_actions", "allowed_output_names",
                   "require_new_permit"}, "policy")
    need(policy["allowed_actions"] == [ACTION], "unsupported policy action")
    need(policy["policy_id"] == "demo-file-set" and policy["policy_version"] == "1"
         and policy["policy_ref"] == "local:policy.json", "unsupported local policy")
    names = policy["allowed_output_names"]
    need(isinstance(names, list) and all(isinstance(n, str) and FILE_RE.fullmatch(n) for n in names)
         and names == sorted(set(names)), "invalid policy output names")
    need(type(policy["require_new_permit"]) is bool, "new-permit policy must be boolean")
    request = make_request(operation, permit, permit_uri)
    need(request["evidence_refs"][0]["digest"] == digest(encode(permit)), "permit digest mismatch")
    verifier = core.VateVerifier(verifier_id=VERIFIER, policy=policy)
    core_result = verifier.admit(request, now=time_value(evaluated_at))
    receipt = copy.deepcopy(core_result["admission_receipt"])
    receipt["proof"] = {"format": "none"}
    effective = None
    if core_result["decision"] == "allow":
        effective = copy.deepcopy(operation)
        effective["target"]["files"] = [f for f in operation["target"]["files"] if f["name"] in names]
        if not effective["target"]["files"]:
            receipt["decision"] = {"outcome": "deny", "reason_codes": ["DEMO_NO_ALLOWED_OUTPUTS"]}
            effective = None
        elif effective != operation:
            constraints = copy.deepcopy(request["constraints"])
            constraints["demo_output_names"] = [f["name"] for f in effective["target"]["files"]]
            receipt["decision"] = {"outcome": "attenuate", "reason_codes": ["DEMO_OUTPUT_SET_NARROWED"]}
            receipt["attenuation"] = {
                "mode": "require_new_permit" if policy["require_new_permit"] else "narrow",
                "original_request_hash": object_hash(operation), "effective_request_hash": object_hash(effective),
                "changes": [{"op": "replace", "path": "/target/files", "from": operation["target"]["files"],
                             "to": effective["target"]["files"], "reason_code": "DEMO_OUTPUT_SET_NARROWED",
                             "source_evidence_ref": "local:policy.json"}],
                "effective_constraints": constraints, "require_new_permit": policy["require_new_permit"],
            }
        elif policy["require_new_permit"]:
            receipt["decision"] = {"outcome": "deny", "reason_codes": ["DEMO_FRESH_PERMIT_WITHOUT_NARROWING"]}
            effective = None
    else:
        need(core_result["decision"] == "deny", "unexpected core attenuation; file demo never uses amounts")
    receipt["request"]["action_binding"] = action_binding(effective if effective is not None else operation)
    # The raw core record is retained separately. This field describes exactly
    # the additional check performed by this issuer, with no signature claim.
    receipt["evidence"][0]["verification"]["method"] = "demo-local-permit-binding-and-vate-core"
    record = {
        "contract": CONTRACT, "evaluated_at": evaluated_at,
        "local_checks": [{"name": name, "pass": True} for name in LOCAL_CHECKS],
        "core_decision": core_result["decision"], "final_decision": receipt["decision"]["outcome"],
        "original_input_hash": object_hash(operation),
        "effective_input_hash": object_hash(effective) if effective is not None else None,
        "admission_request_object_hash": object_hash(request),
        "receipt_digest": digest(encode(receipt)), "policy_digest": digest(encode(policy)),
        "permit_digest": digest(encode(permit)), "core_result_digest": digest(encode(core_result)),
    }
    return Authorization(encode(operation), encode(permit), encode(request), encode(core_result),
                         encode(receipt), encode(effective) if effective is not None else None, encode(record))


def assert_authorization(auth: Authorization, policy: dict, resource: str, permit_uri: str) -> None:
    """Recheck all required local inputs and the core result before dispatch."""
    computed = evaluate(decode(auth.original), decode(auth.permit), policy, resource=resource,
                        permit_uri=permit_uri, evaluated_at=decode(auth.record)["evaluated_at"])
    need(auth == computed, "admission capsule differs from recomputed decision/preimages")
