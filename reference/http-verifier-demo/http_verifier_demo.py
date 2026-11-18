#!/usr/bin/env python3
"""HTTP verifier wedge demo for AL2-style digital write flows in this draft.

This demo reuses the compact JWS helpers from the minimal AL2 demo and adds a
verifier-centered HTTP API with explicit allow / attenuate / deny decisions.
It is intentionally educational and not production-ready.
"""

from __future__ import annotations

import argparse
import copy
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
from datetime import datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reference/runtime-support"))
from vate_uri import is_absolute_uri

MINIMAL_DEMO = ROOT / "reference" / "minimal-al2-demo" / "trust_envelope_demo.py"
DEFAULT_POLICY = ROOT / "policies" / "al2-http-verifier.example.json"
DEFAULT_CORPUS = ROOT / "conformance" / "al2-http"
APPROVAL_MODES = frozenset({"policy_auto", "human_required"})
ASSURANCE_LEVELS = ("AL0", "AL1", "AL2", "AL3", "AL4")
RESPONSE_FILES = ("http-verifier-response.json", "verifier-admission-receipt.json", "verifier-admission-receipt.jws")
AGE_FIELDS = tuple(f"{kind}_max_age_seconds" for kind in ("status", "runtime", "permit"))
ATTENUATION_HANDLERS = {
    "resource": "replace",
    "max_amount_usd": "min",
    "max_redelegation_depth": "min",
    "tool_allowlist": "intersect",
    "approval": "escalate",
}


def load_minimal_demo():
    spec = importlib.util.spec_from_file_location("app_minimal_al2_demo", MINIMAL_DEMO)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load minimal demo module from {MINIMAL_DEMO}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


demo = load_minimal_demo()
STATUS_KINDS = demo.STATUS_KINDS


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    return demo.read_json(path)


def write_text(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data.rstrip() + "\n", encoding="utf-8")


def canonical_hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(demo.canonical(value)).hexdigest()


def ensure_verifier_key(bundle: dict[str, Any], out_dir: Path) -> None:
    verifier_key = demo.generate_keypair(out_dir, "verifier")
    bundle["trust_bundle"]["keys"][verifier_key["kid"]] = {
        "owner": "verifier",
        "alg": verifier_key["alg"],
        "public_key": str(verifier_key["public_key"].relative_to(out_dir)),
        "spki_sha256": verifier_key["spki_sha256"],
    }


def policy_default_for_dir(directory: Path) -> Path:
    return directory.resolve().parent.parent / "policy.json"


class PolicyFileError(ValueError):
    """The selected local policy could not be read or interpreted."""


def read_policy_file(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        policy = demo.parse_demo_json(raw.decode("utf-8"))
        validate_policy(policy)
    except (OSError, ValueError) as exc:
        raise PolicyFileError(f"cannot use verifier policy {path}: {exc}") from exc
    return policy, raw


def load_policy(path: Path) -> dict[str, Any]:
    return read_policy_file(path)[0]


def freshness_limit(policy: dict[str, Any], field: str) -> int | float:
    value = policy["freshness"].get(field)
    if (type(value) not in (int, float) or value < 1
            or (isinstance(value, float) and (not math.isfinite(value) or not value.is_integer()))):
        raise ValueError(f"{field} must be a positive integer number of seconds")
    return value


def assurance_value(label: Any, field: str = "assurance_level") -> int:
    if label not in ASSURANCE_LEVELS:
        raise ValueError(f"{field} must be one of AL0 through AL4")
    return ASSURANCE_LEVELS.index(label)


def string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{field} must be an array of non-empty strings")
    return value


def validate_policy_identity(policy: Any) -> None:
    if not isinstance(policy, dict):
        raise ValueError("verifier policy must be an object")
    for field in ("policy_id", "policy_version"):
        demo.required_text(policy, field)


def copy_json_value(value: Any) -> Any:
    """Take a private copy without coercing Python-only values into JSON types."""
    if isinstance(value, dict):
        members = value.copy()
        if not all(isinstance(key, str) for key in members):
            raise ValueError("policy JSON object keys must be strings")
        return {key: copy_json_value(item) for key, item in members.items()}
    if isinstance(value, list):
        return [copy_json_value(item) for item in value.copy()]
    if value is None or type(value) in (str, bool, int) or (type(value) is float and math.isfinite(value)):
        return value
    raise ValueError("policy values must be JSON data with finite numbers")


def validate_policy(policy: Any) -> None:
    """Validate the local policy contract before any membership or threshold decision."""
    validate_policy_identity(policy)
    if policy.get("version") != "app-verifier-policy-0.1" or policy.get("profile") != "AL2-http":
        raise ValueError("verifier policy requires version app-verifier-policy-0.1 and profile AL2-http")
    if not is_absolute_uri(policy.get("verifier_id")):
        raise ValueError("verifier_id must be an absolute URI")
    assurance_value(policy.get("required_assurance_level"), "required_assurance_level")
    if not isinstance(policy.get("fail_closed"), bool):
        raise ValueError("fail_closed must be a boolean")
    states = policy.get("accepted_states")
    if not isinstance(states, dict) or set(states) != set(STATUS_KINDS):
        raise ValueError("accepted_states must contain exactly passport, runtime, and permit")
    for kind in STATUS_KINDS:
        accepted = string_list(states[kind], f"accepted_states.{kind}")
        if demo.BLOCKING_STATUS_STATES.intersection(accepted):
            raise ValueError(f"accepted_states.{kind} cannot include a suspended, revoked, or quarantined state")
    if not isinstance(policy.get("freshness"), dict):
        raise ValueError("freshness must be an object")
    for field in AGE_FIELDS:
        freshness_limit(policy, field)
    for field in ("allowed_actions", "allowed_resources"):
        string_list(policy.get(field), field)
    handlers = policy.get("attenuation_handlers")
    if not isinstance(handlers, dict):
        raise ValueError("attenuation_handlers must be an object")
    for field, handler in handlers.items():
        if field not in ATTENUATION_HANDLERS or handler != ATTENUATION_HANDLERS[field]:
            raise ValueError(f"unsupported attenuation_handlers entry for {field}")


def record(checks: list[dict[str, Any]], phase: str, name: str, ok: bool, details: str) -> None:
    checks.append({"phase": phase, "name": name, "ok": ok, "details": details})


def scenario_definitions() -> dict[str, dict[str, Any]]:
    def allow_active(bundle: dict[str, Any]) -> None:
        return None

    def attenuate_tool_narrow(bundle: dict[str, Any]) -> None:
        permit_entry = bundle["status_store"]["entries"]["permit"]
        permit_entry["state"] = "attenuated"
        permit_entry["reason"] = "tool-scope-tightened"
        permit_entry["effect"] = {
            "mode": "narrow",
            "require_new_permit": False,
            "constraints": {
                "tool_allowlist": ["read_file"],
            },
        }

    def deny_revoked(bundle: dict[str, Any]) -> None:
        permit_entry = bundle["status_store"]["entries"]["permit"]
        permit_entry["state"] = "revoked"
        permit_entry["reason"] = "risk-detected"
        permit_entry.pop("effect", None)

    def deny_unknown_effect(bundle: dict[str, Any]) -> None:
        permit_entry = bundle["status_store"]["entries"]["permit"]
        permit_entry["state"] = "attenuated"
        permit_entry["reason"] = "vendor-risk-escalation"
        permit_entry["effect"] = {
            "mode": "narrow",
            "require_new_permit": False,
            "constraints": {
                "vendor_risk_tier": "trusted-only",
            },
        }

    return {
        "allow-active": {
            "category": "positive",
            "description": "active permit and matching request produce an allow decision",
            "request": {
                "action": "task.execute",
                "resource": "project:demo-alpha",
                "tool": "summarize",
                "payload": {
                    "op": "summarize",
                    "artifact": "project:demo-alpha",
                },
            },
            "mutate": allow_active,
        },
        "attenuate-tool-narrow": {
            "category": "positive",
            "description": "attenuated permit narrows tool scope and produces an attenuate decision",
            "request": {
                "action": "task.execute",
                "resource": "project:demo-alpha",
                "tool": "read_file",
                "payload": {
                    "op": "read",
                    "artifact": "project:demo-alpha/spec-summary.md",
                },
            },
            "mutate": attenuate_tool_narrow,
        },
        "deny-revoked": {
            "category": "negative",
            "description": "revoked permit status produces a deny decision",
            "request": {
                "action": "task.execute",
                "resource": "project:demo-alpha",
                "tool": "summarize",
                "payload": {
                    "op": "summarize",
                    "artifact": "project:demo-alpha",
                },
            },
            "mutate": deny_revoked,
        },
        "deny-unknown-effect": {
            "category": "negative",
            "description": "attenuated permit with an unknown machine-readable effect produces a deny decision",
            "request": {
                "action": "task.execute",
                "resource": "project:demo-alpha",
                "tool": "read_file",
                "payload": {
                    "op": "read",
                    "artifact": "project:demo-alpha/spec-summary.md",
                },
            },
            "mutate": deny_unknown_effect,
        },
    }


def build_request(bundle: dict[str, Any], scenario_name: str) -> dict[str, Any]:
    scenario = scenario_definitions()[scenario_name]
    return {
        "transaction_id": bundle["artifacts"]["permit"]["payload"]["transaction_id"],
        "requested_action": scenario["request"]["action"],
        "requested_resource": scenario["request"]["resource"],
        "requested_tool": scenario["request"]["tool"],
        "request_payload": scenario["request"]["payload"],
        "app_context": {
            "passport": {
                "jws": bundle["artifacts"]["passport"]["token"],
            },
            "runtime_proof": {
                "jws": bundle["artifacts"]["runtime_proof"]["token"],
            },
            "mission_permit": {
                "jws": bundle["artifacts"]["permit"]["token"],
            },
            "status": {
                "delivery": "stapled",
                "jws": bundle["status_tokens"]["stapled"],
            },
        },
    }


def validate_legacy_execution_receipts(root: Path, seen: set[Path], legacy: set[Path]) -> None:
    """Recognize the previous generator's identical, signed fixture before retiring it."""
    if not seen.intersection(legacy):
        return
    base = root / "_base"
    problem = "unrecognized execution receipts in the existing HTTP demo; choose a new directory"
    if not legacy.issubset(seen):
        raise demo.DemoOutputError(problem)
    try:
        copies = {name: (base / name).read_bytes() for name in ("execution-receipt.json", "execution-receipt.jws")}
        if any((root / path).read_bytes() != copies[path.name] for path in legacy):
            raise demo.DemoOutputError(problem)
        spec = demo.ARTIFACT_SPECS["receipt"]
        verified = demo.verify_role_bound_jws(
            out_dir=base, trust_bundle=read_json(base / "trust-bundle.json"),
            token=demo.read_text(base / "execution-receipt.jws"),
            expected_typ=spec["typ"], expected_cty=spec["cty"], expected_role="runtime")
        body = verified["payload"]
        recognized = (verified["ok"] and body.get("receipt_id") == "aer:demo-receipt"
                      and body.get("receipt_phase") == "post_execution"
                      and demo.canonical(body) == demo.canonical(read_json(base / "execution-receipt.json")))
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
        raise demo.DemoOutputError(problem) from exc
    if not recognized:
        raise demo.DemoOutputError(problem)


def generate_demo(out_dir: Path, *, policy_path: Path) -> None:
    policy, policy_bytes = read_policy_file(policy_path)
    with demo.staged_output(out_dir) as staged:
        generate_scenarios(staged, policy, policy_bytes)
        scenarios = [Path("scenarios") / name for name in scenario_definitions()]
        reports = {directory / file for directory in scenarios for file in RESPONSE_FILES}
        legacy = {directory / file for directory in [Path("_base"), *scenarios]
                  for file in ("execution-receipt.json", "execution-receipt.jws")}
        seed = Path("policy.json") if policy_path.resolve() == (out_dir / "policy.json").resolve() else None
        demo.publish_output(staged, out_dir, optional_files=reports | legacy, seed=seed,
                            validate_previous=lambda root, seen: validate_legacy_execution_receipts(root, seen, legacy))


def generate_scenarios(out_dir: Path, policy: dict[str, Any], policy_bytes: bytes) -> None:
    base_dir = out_dir / "_base"
    bundle = demo.build_demo_bundle(base_dir, audience=policy["verifier_id"], include_execution_receipt=False)
    ensure_verifier_key(bundle, base_dir)
    demo.write_bundle(base_dir, bundle)

    (out_dir / "policy.json").write_bytes(policy_bytes)

    scenario_root = out_dir / "scenarios"
    for scenario_name, scenario in scenario_definitions().items():
        scenario_dir = scenario_root / scenario_name
        scenario_bundle = copy.deepcopy(bundle)
        scenario["mutate"](scenario_bundle)
        demo.issue_status_tokens(scenario_bundle, base_dir)
        demo.write_bundle(scenario_dir, scenario_bundle, template_dir=base_dir)
        write_json(scenario_dir / "request.json", build_request(scenario_bundle, scenario_name))
        write_json(
            scenario_dir / "scenario.json",
            {
                "version": "app-http-scenario-0.1",
                "name": scenario_name,
                "category": scenario["category"],
                "description": scenario["description"],
            },
        )


def verify_status(
    *,
    verifier_dir: Path,
    trust_bundle: dict[str, Any],
    app_context: dict[str, Any],
    checks: list[dict[str, Any]],
) -> dict[str, Any] | None:
    status = app_context.get("status", {})
    delivery = status.get("delivery", "stapled")
    token = status.get("jws", "")
    expected_typ = demo.STATUS_TYP if delivery != "push" else demo.STATUS_EVENT_TYP
    expected_cty = demo.STATUS_CONTENT_TYPE if delivery != "push" else demo.STATUS_EVENT_CONTENT_TYPE
    verification = demo.verify_role_bound_jws(
        out_dir=verifier_dir,
        trust_bundle=trust_bundle,
        token=token,
        expected_typ=expected_typ,
        expected_cty=expected_cty,
        expected_role="status",
    )
    record(checks, "status", "status_signature", verification["signature_ok"], verification["details"])
    record(checks, "status", "status_signer_role", verification["signer_role_ok"], verification["signer_role_details"])
    if not verification["ok"]:
        return None

    try:
        payload = demo.validated_status_payload(verification["payload"])
    except demo.StatusEffectError as exc:
        checks_by_field = {"constraints": "policy_attenuation_effect_valid", "mode": "policy_attenuation_mode",
                           "require_new_permit": "policy_attenuation_reissue"}
        record(checks, "status", checks_by_field[exc.field], False, str(exc))
        raise
    return payload


def verify_identity(
    *,
    verifier_dir: Path,
    trust_bundle: dict[str, Any],
    request: dict[str, Any],
    policy: dict[str, Any],
    checks: list[dict[str, Any]],
) -> dict[str, Any] | None:
    verification = demo.verify_role_bound_jws(
        out_dir=verifier_dir,
        trust_bundle=trust_bundle,
        token=request["app_context"]["passport"]["jws"],
        expected_typ=demo.ARTIFACT_SPECS["passport"]["typ"],
        expected_cty=demo.ARTIFACT_SPECS["passport"]["cty"],
        expected_role=demo.ARTIFACT_SPECS["passport"]["role"],
    )
    record(checks, "identity", "passport_signature", verification["signature_ok"], verification["details"])
    record(checks, "identity", "passport_signer_role", verification["signer_role_ok"], verification["signer_role_details"])
    payload = verification["payload"]
    if not verification["ok"]:
        return None

    demo.required_text(payload, "passport_id")
    for field in ("root_id", "public_alias"):
        demo.required_text(payload.get("subject"), field)
    required_level = policy["required_assurance_level"]
    record(
        checks,
        "identity",
        "passport_assurance_level",
        assurance_value(payload["assurance_level"]) >= assurance_value(required_level),
        f"passport assurance level is {payload['assurance_level']}, policy requires {required_level}",
    )
    return payload


def verify_runtime(
    *,
    verifier_dir: Path,
    trust_bundle: dict[str, Any],
    request: dict[str, Any],
    passport: dict[str, Any],
    policy: dict[str, Any],
    checks: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    verification = demo.verify_role_bound_jws(
        out_dir=verifier_dir,
        trust_bundle=trust_bundle,
        token=request["app_context"]["runtime_proof"]["jws"],
        expected_typ=demo.ARTIFACT_SPECS["runtime_proof"]["typ"],
        expected_cty=demo.ARTIFACT_SPECS["runtime_proof"]["cty"],
        expected_role=demo.ARTIFACT_SPECS["runtime_proof"]["role"],
    )
    record(checks, "runtime", "runtime_proof_signature", verification["signature_ok"], verification["details"])
    record(checks, "runtime", "runtime_proof_signer_role", verification["signer_role_ok"], verification["signer_role_details"])
    payload = verification["payload"]
    header = verification["header"]
    if not verification["ok"]:
        return None, {}

    demo.required_text(payload, "runtime_id")
    subject_id = demo.required_text(payload, "subject_id")
    audience = demo.required_text(payload.get("challenge_binding"), "aud")
    record(
        checks,
        "runtime",
        "runtime_subject_binding",
        subject_id == passport["subject"]["root_id"],
        "runtime subject matches passport root id",
    )
    record(
        checks,
        "runtime",
        "runtime_audience",
        audience == policy["verifier_id"],
        "runtime audience matches verifier policy",
    )
    record(
        checks,
        "runtime",
        "runtime_presented_key_owner",
        demo.registered_key(trust_bundle, payload.get("presented_key", {}).get("kid")).get("owner") == "runtime",
        "runtime presented key resolves to a runtime-owned key",
    )
    return payload, header


def verify_permit(
    *,
    verifier_dir: Path,
    trust_bundle: dict[str, Any],
    request: dict[str, Any],
    passport: dict[str, Any],
    runtime_proof: dict[str, Any],
    runtime_header: dict[str, Any],
    policy: dict[str, Any],
    checks: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    verification = demo.verify_role_bound_jws(
        out_dir=verifier_dir,
        trust_bundle=trust_bundle,
        token=request["app_context"]["mission_permit"]["jws"],
        expected_typ=demo.ARTIFACT_SPECS["permit"]["typ"],
        expected_cty=demo.ARTIFACT_SPECS["permit"]["cty"],
        expected_role=demo.ARTIFACT_SPECS["permit"]["role"],
    )
    record(checks, "permit", "mission_permit_signature", verification["signature_ok"], verification["details"])
    record(checks, "permit", "mission_permit_signer_role", verification["signer_role_ok"], verification["signer_role_details"])
    payload = verification["payload"]
    header = verification["header"]
    if not verification["ok"]:
        return None, {}

    permit_transaction, actions = demo.validated_permit_scope(payload)
    for field in ("permit_id", "actor", "aud"):
        demo.required_text(payload, field)
    if "principal" in payload:
        demo.required_text(payload, "principal")
    record(
        checks,
        "permit",
        "permit_transaction_binding",
        request["transaction_id"] == permit_transaction,
        "request transaction matches the mission permit transaction",
    )
    record(
        checks,
        "permit",
        "permit_actor_binding",
        payload["actor"] == passport["subject"]["public_alias"],
        "permit actor matches passport alias",
    )
    record(
        checks,
        "permit",
        "permit_audience",
        payload["aud"] == policy["verifier_id"],
        "permit audience matches verifier policy",
    )
    record(
        checks,
        "permit",
        "permit_action_scope",
        request["requested_action"] in actions,
        "requested action is within the permit action scope",
    )
    record(
        checks,
        "permit",
        "permit_resource_scope",
        request["requested_resource"] == payload.get("constraints", {}).get("resource"),
        "requested resource matches the mission permit resource scope",
    )
    record(
        checks,
        "permit",
        "permit_tool_scope",
        request["requested_tool"] in tool_allowlist(payload.get("constraints", {}).get("tool_allowlist", [])),
        "requested tool is within the mission permit tool allowlist",
    )
    record(
        checks,
        "permit",
        "permit_proof_binding",
        demo.runtime_key_bound(verifier_dir, trust_bundle, payload, runtime_proof)
        and runtime_header.get("kid") != header.get("kid"),
        "permit proof binding matches the runtime-presented key",
    )
    return payload, header


def check_time_windows(checks, policy, status, passport, runtime, permit, checked_at: datetime) -> None:
    valid_from = demo.parse_time(passport["valid_from"])
    valid_until = demo.parse_time(passport["valid_until"])
    record(checks, "identity", "passport_window", valid_from <= checked_at <= valid_until,
           "passport is valid at the admission decision time")
    windows = (
        ("status", "status_document_window", status["generated_at"], status["next_update_at"]),
        ("runtime", "runtime_window", runtime["issued_at"], runtime["expires_at"]),
        ("permit", "permit_window", permit["issued_at"], permit["constraints"]["expires_at"]),
    )
    for kind, check, start, expiry in windows:
        issued_at, expires_at = demo.parse_time(start), demo.parse_time(expiry)
        max_age = freshness_limit(policy, f"{kind}_max_age_seconds")
        age_us = (checked_at - issued_at) // timedelta(microseconds=1)
        record(checks, kind, check, issued_at <= checked_at <= expires_at and age_us <= int(max_age) * 1_000_000,
               f"{kind} must be current and at most {max_age} seconds old at the admission decision")


def tool_allowlist(value: Any) -> list[str]:
    return string_list(value, "tool_allowlist")


def approval_requirement(value: Any) -> dict[str, Any]:
    if (not isinstance(value, dict) or not isinstance(value.get("mode"), str)
            or value["mode"] not in APPROVAL_MODES):
        raise ValueError("approval must select policy_auto or human_required")
    if "policy_ref" in value and (not isinstance(value["policy_ref"], str) or not value["policy_ref"]):
        raise ValueError("approval policy_ref must be a non-empty string")
    return copy.deepcopy(value)


def same_json_value(left: Any, right: Any) -> bool:
    """JSON booleans are distinct from numbers, including inside annotations."""
    if isinstance(left, bool) or isinstance(right, bool):
        return left is right
    if isinstance(left, dict):
        return isinstance(right, dict) and left.keys() == right.keys() and all(
            same_json_value(value, right[key]) for key, value in left.items())
    if isinstance(left, list):
        return isinstance(right, list) and len(left) == len(right) and all(
            same_json_value(a, b) for a, b in zip(left, right))
    return left == right


def narrow_approval(original: Any, proposed: Any) -> dict[str, Any]:
    original = approval_requirement(original)
    proposed = approval_requirement(proposed)
    if original["mode"] == "human_required" and proposed["mode"] != "human_required":
        raise ValueError("attenuation cannot remove required human approval")
    # An omitted reference or annotation is retained; changing an existing one
    # has no defined strengthening relation in this local profile.
    if any(key != "mode" and key in proposed and not same_json_value(proposed[key], value)
           for key, value in original.items()):
        raise ValueError("attenuation cannot replace an existing approval requirement")
    return {**original, **proposed}


def effective_permit_constraints(permit: dict[str, Any]) -> dict[str, Any]:
    constraints = copy.deepcopy(permit["constraints"])
    if not isinstance(constraints, dict):
        raise ValueError("permit constraints must be an object")
    demo.required_text(constraints, "resource")
    for key in ("max_amount_usd", "max_redelegation_depth"):
        constraint_limit(key, constraints.get(key))
    tool_allowlist(constraints.get("tool_allowlist", []))
    approval = approval_requirement(permit.get("approval"))
    if "approval" in constraints:
        approval = narrow_approval(approval, constraints["approval"])
    constraints["approval"] = approval
    return constraints


def constraint_limit(key: str, value: Any) -> int | float:
    if (type(value) not in (int, float) or value < 0
            or (isinstance(value, float) and not math.isfinite(value))
            or (key == "max_redelegation_depth" and isinstance(value, float) and not value.is_integer())):
        raise ValueError(f"{key} must be a finite non-negative "
                         + ("integer" if key == "max_redelegation_depth" else "number"))
    return value


def apply_effect(
    base_constraints: dict[str, Any],
    effect: dict[str, Any],
    policy: dict[str, Any],
) -> tuple[dict[str, Any] | None, list[str]]:
    handlers = policy["attenuation_handlers"]
    effect_constraints = effect.get("constraints")
    if not isinstance(effect_constraints, dict) or not isinstance(handlers, dict):
        raise ValueError("attenuation constraints and handler selection must be objects")
    unknown = sorted(set(effect_constraints) - (set(handlers) & set(ATTENUATION_HANDLERS)))
    if unknown:
        return None, unknown

    narrowed = copy.deepcopy(base_constraints)
    for key, value in effect_constraints.items():
        handler = handlers[key]
        if handler != ATTENUATION_HANDLERS[key]:
            raise ValueError(f"unsupported attenuation handler {handler} for {key}")
        if handler == "intersect":
            base = tool_allowlist(narrowed.get(key, []))
            narrowed[key] = sorted(set(base).intersection(tool_allowlist(value)))
        elif handler == "min":
            value = constraint_limit(key, value)
            narrowed[key] = min(narrowed[key], value)
        elif handler == "replace":
            if not isinstance(value, str) or not value or value != narrowed.get(key):
                raise ValueError("an exact resource scope cannot be replaced during attenuation")
        elif handler == "escalate":
            narrowed[key] = narrow_approval(narrowed.get(key), value)
    return narrowed, []


def build_attenuations(
    *,
    original_constraints: dict[str, Any],
    effective_constraints: dict[str, Any],
    effect: dict[str, Any],
    status_entry: dict[str, Any],
) -> list[dict[str, Any]]:
    attenuations = []
    for key in sorted(effect["constraints"]):
        original = original_constraints.get(key)
        applied = effective_constraints.get(key)
        if same_json_value(original, applied):
            continue
        attenuations.append(
            {
                "field": f"constraints.{key}",
                "original": original,
                "applied": applied,
                "reason_code": status_entry["reason"],
                "source_status_ref": status_entry["id"],
            }
        )
    return attenuations


def request_within_constraints(
    request: dict[str, Any],
    *,
    constraints: dict[str, Any],
    permit: dict[str, Any],
) -> bool:
    if request["requested_resource"] != constraints.get("resource"):
        return False

    tools = tool_allowlist(constraints.get("tool_allowlist", []))
    if request["requested_tool"] not in tools:
        return False

    approval = approval_requirement(permit.get("approval"))
    if "approval" in constraints:
        approval = narrow_approval(approval, constraints["approval"])
    if approval["mode"] == "human_required":
        reference = request.get("approval_ref")
        if not isinstance(reference, str) or not reference.strip():
            return False

    return True


def build_receipt(
    *,
    verifier_dir: Path,
    request: dict[str, Any],
    policy: dict[str, Any],
    trust_bundle: dict[str, Any],
    permit: dict[str, Any],
    runtime_proof: dict[str, Any],
    decision: str,
    attenuations: list[dict[str, Any]],
    response_payload: dict[str, Any],
    status_entries: dict[str, Any],
    started_at: datetime,
    finished_at: datetime,
) -> tuple[dict[str, Any], str]:
    receipt_id = f"aer:http-verifier:{request['transaction_id']}:{decision}:admission"
    receipt = {
        "version": "aer-0.1",
        "receipt_id": receipt_id,
        "receipt_phase": "admission",
        "transaction_id": request["transaction_id"],
        "actor": permit["actor"],
        "runtime_ref": runtime_proof["runtime_id"],
        "permit_ref": permit["permit_id"],
        "verifier": policy["verifier_id"],
        "issuer_role": "verifier",
        "decision": decision,
        "attenuations": attenuations,
        "skill": {
            "id": request["requested_action"],
            "version": "0.1.0",
        },
        "input_hash": canonical_hash(request.get("request_payload", {})),
        "output_hash": canonical_hash(response_payload),
        "policy_ref": policy["policy_id"],
        "policy_id": policy["policy_id"],
        "policy_version": policy["policy_version"],
        "correlation": {
            "transaction_id": request["transaction_id"],
            "runtime_ref": runtime_proof["runtime_id"],
            "permit_ref": permit["permit_id"],
            "attestation_id": receipt_id,
        },
        "evidence_refs": [
            f"urn:app:decision:{decision}",
            f"urn:app:permit-state:{status_entries['permit']['state']}",
        ],
        "artifact_digests": {
            "request": canonical_hash(request),
            "response": canonical_hash(response_payload),
        },
        "started_at": demo.iso(started_at),
        "finished_at": demo.iso(finished_at),
        "outcome": "success" if decision in {"allow", "attenuate"} else "failure",
    }
    if "principal" in permit:
        receipt["principal"] = permit["principal"]
    verifier_key = {
        "kid": "verifier-key-1",
        "alg": "ES256",
        "private_key": demo.key_path(verifier_dir, "verifier", "private"),
    }
    spec = demo.ARTIFACT_SPECS["receipt"]
    try:
        token = demo.build_compact_jws(
            receipt,
            key_info=verifier_key,
            typ=spec["typ"],
            cty=spec["cty"],
        )
        verification = demo.verify_role_bound_jws(
            out_dir=verifier_dir, trust_bundle=trust_bundle, token=token,
            expected_typ=spec["typ"], expected_cty=spec["cty"], expected_role="verifier")
        if not verification["ok"]:
            raise RuntimeError("the receipt signing key does not match its verifier registration")
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        raise RuntimeError("could not produce a verifiable admission receipt") from exc
    return receipt, token


def verification_report(request, policy, checks, *, decision, receipt_emitted, checked_at=None):
    return {
        "version": "app-verification-report-0.1",
        "profile": "AL2-http",
        "checked_at": demo.iso(checked_at if checked_at is not None else demo.utc_now()),
        "policy_id": policy["policy_id"],
        "policy_version": policy["policy_version"],
        "decision": decision,
        "receipt_emitted": receipt_emitted,
        "receipt_phase": "admission",
        "request": {
            "action": request["requested_action"],
            "resource": request["requested_resource"],
            "tool": request["requested_tool"],
        },
        "failed_checks": sorted(check["name"] for check in checks if not check["ok"]),
        "passed_checks": sorted(check["name"] for check in checks if check["ok"]),
        "request_binding": {"status": "not_checked", "pass": None,
                            "binding_requirement_met": False,
                            "cause": "LEGACY_AER_PROFILE"},
    }


def rejected_input_response(request, policy, checks):
    # Unauthenticated or unusable artifact fields cannot supply receipt identity.
    return {"decision": "deny", "check_details": checks,
            "verification_report": verification_report(request, policy, checks,
                                                        decision="deny", receipt_emitted=False)}


def verify_execute_request(
    *,
    verifier_dir: Path,
    request: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    return evaluate_execute_request(verifier_dir=verifier_dir, request=request, policy=policy, checks=[])


class RequestEnvelopeError(ValueError):
    """The caller did not send a usable request envelope."""


def evaluate_execute_request(
    *,
    verifier_dir: Path,
    request: dict[str, Any],
    policy: dict[str, Any],
    checks: list[dict[str, Any]],
) -> dict[str, Any]:
    started_at = demo.utc_now()
    if not isinstance(request, dict) or any(
        not isinstance(request.get(name), str) or not request[name]
        for name in ("transaction_id", "requested_action", "requested_resource", "requested_tool")
    ):
        raise RequestEnvelopeError("request must contain non-empty transaction_id, requested_action, requested_resource, and requested_tool")
    record(checks, "request", "request_shape", True, "request envelope contains the required identifiers")
    try:
        policy = copy_json_value(policy)
        validate_policy(policy)
        return _evaluate_validated_request(verifier_dir=verifier_dir, request=request, policy=policy, checks=checks,
                                           started_at=started_at)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
        # Without a usable policy identity a rejection report cannot be attributed.
        validate_policy_identity(policy)
        record(checks, "request", "verification_input", False,
               f"unable to interpret verification input ({type(exc).__name__}): {exc}")
        return rejected_input_response(request, policy, checks)


def _evaluate_validated_request(
    *,
    verifier_dir: Path,
    request: dict[str, Any],
    policy: dict[str, Any],
    checks: list[dict[str, Any]],
    started_at: datetime,
) -> dict[str, Any]:
    try:
        trust_bundle = read_json(verifier_dir / "trust-bundle.json")
        if not isinstance(trust_bundle, dict) or not isinstance(trust_bundle.get("keys"), dict):
            raise ValueError("expected a local trust bundle with keys")
    except ValueError as exc:
        raise RuntimeError("could not read the verifier's local trust bundle") from exc

    status_payload = verify_status(
        verifier_dir=verifier_dir,
        trust_bundle=trust_bundle,
        app_context=request["app_context"],
        checks=checks,
    )
    if status_payload is None:
        return rejected_input_response(request, policy, checks)
    passport = verify_identity(
        verifier_dir=verifier_dir,
        trust_bundle=trust_bundle,
        request=request,
        policy=policy,
        checks=checks,
    )
    if passport is None:
        return rejected_input_response(request, policy, checks)
    runtime_proof, runtime_header = verify_runtime(
        verifier_dir=verifier_dir,
        trust_bundle=trust_bundle,
        request=request,
        passport=passport,
        policy=policy,
        checks=checks,
    )
    if runtime_proof is None:
        return rejected_input_response(request, policy, checks)
    permit, _ = verify_permit(
        verifier_dir=verifier_dir,
        trust_bundle=trust_bundle,
        request=request,
        passport=passport,
        runtime_proof=runtime_proof,
        runtime_header=runtime_header,
        policy=policy,
        checks=checks,
    )
    if permit is None:
        return rejected_input_response(request, policy, checks)

    entries = status_payload.get("entries", {})
    record(
        checks,
        "status",
        "status_entry_ids",
        entries.get("passport", {}).get("id") == passport.get("passport_id")
        and entries.get("runtime", {}).get("id") == runtime_proof.get("runtime_id")
        and entries.get("permit", {}).get("id") == permit.get("permit_id"),
        "status entries refer to the presented passport, runtime proof, and mission permit",
    )
    for object_type in STATUS_KINDS:
        acceptable = policy["accepted_states"][object_type]
        state = entries.get(object_type, {}).get("state")
        record(
            checks,
            "status",
            f"{object_type}_state_acceptable",
            state not in demo.BLOCKING_STATUS_STATES and state in acceptable,
            f"{object_type} state is {state}, policy accepts {acceptable}",
        )

    record(
        checks,
        "policy",
        "policy_action_allowed",
        request["requested_action"] in policy["allowed_actions"],
        "requested action is allowed by verifier policy",
    )
    record(
        checks,
        "policy",
        "policy_resource_allowed",
        request["requested_resource"] in policy["allowed_resources"],
        "requested resource is allowed by verifier policy",
    )

    effective_constraints = effective_permit_constraints(permit)
    original_constraints = copy.deepcopy(effective_constraints)
    attenuations: list[dict[str, Any]] = []
    decision = "allow"

    unsupported, reissue = demo.status_attenuation_requirements(entries)
    record(checks, "policy", "status_attenuation_scope", not unsupported,
           f"unsupported narrowing on {', '.join(unsupported)}" if unsupported else "supported status scope")
    record(checks, "policy", "policy_attenuation_reissue", not reissue,
           f"new permit required by {', '.join(reissue)}" if reissue else "no status entry requires a new permit")

    permit_state = entries.get("permit", {}).get("state")
    if permit_state == "attenuated":
        permit_status = entries.get("permit", {})
        effect = permit_status.get("effect", {})
        record(
            checks,
            "policy",
            "policy_attenuation_mode",
            effect.get("mode") == "narrow",
            "attenuated permits must use mode=narrow in this demo profile",
        )
        try:
            narrowed, unknown_fields = apply_effect(effective_constraints, effect, policy)
        except ValueError as exc:
            narrowed = None
            record(checks, "policy", "policy_attenuation_effect_valid", False, str(exc))
        else:
            record(checks, "policy", "policy_attenuation_effect_valid", True,
                   "attenuation uses supported types and preserves the original obligations")
            record(checks, "policy", "policy_attenuation_effect_known", not unknown_fields,
                   "attenuation effect fields are known to the verifier policy" if not unknown_fields
                   else f"unknown attenuation effect fields: {', '.join(unknown_fields)}")
        if narrowed is not None:
            effective_constraints = narrowed
            attenuations = build_attenuations(
                original_constraints=original_constraints,
                effective_constraints=effective_constraints,
                effect=effect,
                status_entry=permit_status,
            )
        record(
            checks,
            "policy",
            "policy_request_within_effective_constraints",
            narrowed is not None
            and request_within_constraints(request, constraints=effective_constraints, permit=permit),
            "requested operation remains within the narrowed effective constraints",
        )
        if all(check["ok"] for check in checks):
            decision = "attenuate"
    else:
        record(
            checks,
            "policy",
            "policy_attenuation_mode",
            True,
            "permit is not attenuated",
        )
        record(
            checks,
            "policy",
            "policy_attenuation_effect_known",
            True,
            "permit is not attenuated",
        )
        record(
            checks,
            "policy",
            "policy_request_within_effective_constraints",
            request_within_constraints(request, constraints=effective_constraints, permit=permit),
            "requested operation remains within the permit constraints",
        )

    finished_at = demo.utc_now()
    if finished_at < started_at:
        raise RuntimeError("the verifier clock moved backwards during evaluation")
    check_time_windows(checks, policy, status_payload, passport, runtime_proof, permit, finished_at)
    if not all(check["ok"] for check in checks):
        decision = "deny"

    report = verification_report(request, policy, checks, decision=decision, receipt_emitted=True, checked_at=finished_at)
    if decision == "attenuate":
        report["effective_constraints"] = effective_constraints
    if attenuations:
        report["attenuations"] = attenuations

    response_payload = {
        "decision": decision,
        "policy_id": policy["policy_id"],
        "policy_version": policy["policy_version"],
        "receipt_phase": "admission",
        "failed_checks": report["failed_checks"],
        "effective_constraints": report.get("effective_constraints"),
        "attenuations": attenuations,
    }
    receipt, token = build_receipt(
        verifier_dir=verifier_dir,
        request=request,
        policy=policy,
        trust_bundle=trust_bundle,
        permit=permit,
        runtime_proof=runtime_proof,
        decision=decision,
        attenuations=attenuations,
        response_payload=response_payload,
        status_entries=entries,
        started_at=started_at,
        finished_at=finished_at,
    )

    return {
        "decision": decision,
        "verification_report": report,
        "check_details": checks,
        "admission_receipt": receipt,
        "admission_receipt_jws": token,
    }


def store_response_artifacts(directory: Path, response: dict[str, Any]) -> None:
    clear_response_artifacts(directory)
    try:
        if response["verification_report"]["receipt_emitted"]:
            write_json(directory / "verifier-admission-receipt.json", response["admission_receipt"])
            write_text(directory / "verifier-admission-receipt.jws", response["admission_receipt_jws"])
        write_json(directory / "http-verifier-response.json", response)
    except (OSError, ValueError, TypeError, KeyError):
        clear_response_artifacts(directory)
        raise


def clear_response_artifacts(directory: Path) -> None:
    failure = None
    for filename in RESPONSE_FILES:
        try:
            (directory / filename).unlink(missing_ok=True)
        except OSError as exc:
            failure = exc
    if failure is not None:
        raise failure


def serve(directory: Path, *, policy_path: Path, host: str, port: int) -> None:
    try:
        policy = load_policy(policy_path)
    except PolicyFileError:
        clear_response_artifacts(directory)
        raise

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path.rstrip("/") == "/healthz":
                body = json.dumps({"ok": True}).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_error(HTTPStatus.NOT_FOUND, "unsupported path")

        def do_POST(self) -> None:  # noqa: N802
            if self.path.rstrip("/") != "/execute":
                self.send_error(HTTPStatus.NOT_FOUND, "unsupported path")
                return

            try:
                clear_response_artifacts(directory)
                try:
                    content_length = int(self.headers.get("Content-Length", "0"))
                    if content_length < 0:
                        raise ValueError("Content-Length must not be negative")
                    raw = self.rfile.read(content_length)
                    request = demo.parse_demo_json(raw.decode("utf-8"))
                except ValueError as exc:
                    raise RequestEnvelopeError("invalid request length or JSON body") from exc
                response = verify_execute_request(verifier_dir=directory, request=request, policy=policy)
                store_response_artifacts(directory, response)
                body = json.dumps(response, indent=2, sort_keys=True).encode("utf-8")
            except RequestEnvelopeError as exc:
                self.send_error(HTTPStatus.BAD_REQUEST, str(exc))
                return
            except Exception:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Verifier could not complete the request")
                return
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

    server = ThreadingHTTPServer((host, port), Handler)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def http_post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        return demo.parse_demo_json(response.read().decode("utf-8"))


def execute_demo(directory: Path, *, base_url: str) -> dict[str, Any]:
    clear_response_artifacts(directory)
    request_body = read_json(directory / "request.json")
    response = http_post_json(f"{base_url.rstrip('/')}/execute", request_body)
    store_response_artifacts(directory, response)
    return response


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
    raise RuntimeError(f"HTTP verifier did not become healthy: {url}")


def compare_subset(expected: Any, actual: Any) -> bool:
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        return all(key in actual and compare_subset(value, actual[key]) for key, value in expected.items())
    return same_json_value(expected, actual)


def run_corpus(corpus_root: Path, *, policy_path: Path) -> dict[str, Any]:
    cases = sorted(corpus_root.rglob("case.json"))
    if not cases:
        return {"ok": False, "checked_at": demo.iso(demo.utc_now()), "results": [],
                "error": f"no HTTP corpus cases found in {corpus_root}"}
    temp_dir = Path(tempfile.mkdtemp(prefix="app-http-verifier-"))
    try:
        generate_demo(temp_dir, policy_path=policy_path)
        results = []
        for case_path in cases:
            case = read_json(case_path)
            expected = read_json(case_path.with_name("expected-report.json"))
            scenario_dir = temp_dir / "scenarios" / case["scenario"]
            port = find_free_port()
            base_url = f"http://127.0.0.1:{port}"
            server = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "serve",
                    "--dir",
                    str(scenario_dir),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                ],
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                wait_for_health(f"{base_url}/healthz")
                response = execute_demo(scenario_dir, base_url=base_url)
                report = response["verification_report"]
                results.append(
                    {
                        "name": case["name"],
                        "scenario": case["scenario"],
                        "ok": compare_subset(expected, report),
                        "decision": report["decision"],
                        "failed_checks": report["failed_checks"],
                    }
                )
            finally:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
        summary = {
            "ok": all(item["ok"] for item in results),
            "checked_at": demo.iso(demo.utc_now()),
            "results": results,
        }
        write_json(temp_dir / "conformance-summary.json", summary)
        return summary
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HTTP verifier wedge demo for Verifiable Agent Trust Envelope")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate-demo", help="generate verifier demo scenarios")
    generate.add_argument("--out", required=True, help="output directory")
    generate.add_argument("--policy", default=str(DEFAULT_POLICY), help="policy JSON to copy into the demo root")

    serve_parser = subparsers.add_parser("serve", help="serve the HTTP verifier demo")
    serve_parser.add_argument("--dir", required=True, help="scenario directory")
    serve_parser.add_argument("--policy", help="policy JSON path")
    serve_parser.add_argument("--host", default="127.0.0.1", help="host to bind")
    serve_parser.add_argument("--port", type=int, default=8050, help="port to bind")

    execute = subparsers.add_parser("execute-demo", help="send request.json to a running verifier")
    execute.add_argument("--dir", required=True, help="scenario directory")
    execute.add_argument("--base-url", required=True, help="base URL of the verifier service")

    corpus = subparsers.add_parser("run-corpus", help="replay the machine-readable conformance corpus")
    corpus.add_argument("--corpus-root", default=str(DEFAULT_CORPUS), help="conformance corpus directory")
    corpus.add_argument("--policy", default=str(DEFAULT_POLICY), help="policy JSON path")

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "generate-demo":
        generate_demo(Path(args.out), policy_path=Path(args.policy))
    elif args.command == "serve":
        directory = Path(args.dir)
        policy_path = Path(args.policy) if args.policy else policy_default_for_dir(directory)
        serve(directory, policy_path=policy_path, host=args.host, port=args.port)
    elif args.command == "execute-demo":
        execute_demo(Path(args.dir), base_url=args.base_url)
    elif args.command == "run-corpus":
        summary = run_corpus(Path(args.corpus_root), policy_path=Path(args.policy))
        if not summary["ok"]:
            raise SystemExit(summary.get("error", "HTTP verifier corpus run failed"))


if __name__ == "__main__":
    try:
        main()
    except (PolicyFileError, demo.DemoOutputError) as exc:
        raise SystemExit(str(exc)) from exc
