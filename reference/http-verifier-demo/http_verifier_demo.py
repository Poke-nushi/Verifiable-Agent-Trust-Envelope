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
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
MINIMAL_DEMO = ROOT / "reference" / "minimal-al2-demo" / "trust_envelope_demo.py"
DEFAULT_POLICY = ROOT / "policies" / "al2-http-verifier.example.json"
DEFAULT_CORPUS = ROOT / "conformance" / "al2-http"


def load_minimal_demo():
    spec = importlib.util.spec_from_file_location("app_minimal_al2_demo", MINIMAL_DEMO)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load minimal demo module from {MINIMAL_DEMO}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


demo = load_minimal_demo()


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


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
    candidate = directory.parent.parent / "policy.json"
    if candidate.exists():
        return candidate
    return DEFAULT_POLICY


def load_policy(path: Path) -> dict[str, Any]:
    return read_json(path)


def assurance_value(label: str) -> int:
    if not label.startswith("AL"):
        return -1
    try:
        return int(label[2:])
    except ValueError:
        return -1


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


def generate_demo(out_dir: Path, *, policy_path: Path) -> None:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    base_dir = out_dir / "_base"
    policy = load_policy(policy_path)
    bundle = demo.build_demo_bundle(base_dir)
    ensure_verifier_key(bundle, base_dir)
    bundle["artifacts"]["runtime_proof"]["payload"]["challenge_binding"]["aud"] = policy["verifier_id"]
    bundle["artifacts"]["permit"]["payload"]["aud"] = policy["verifier_id"]
    demo.issue_artifact_tokens(bundle, base_dir)
    demo.write_bundle(base_dir, bundle)

    shutil.copy2(policy_path, out_dir / "policy.json")

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
    policy: dict[str, Any],
    checks: list[dict[str, Any]],
) -> dict[str, Any]:
    status = app_context.get("status", {})
    delivery = status.get("delivery", "stapled")
    token = status.get("jws", "")
    expected_typ = demo.STATUS_TYP if delivery != "push" else demo.STATUS_EVENT_TYP
    expected_cty = demo.STATUS_CONTENT_TYPE if delivery != "push" else demo.STATUS_EVENT_CONTENT_TYPE
    verification = demo.verify_compact_jws(
        out_dir=verifier_dir,
        trust_bundle=trust_bundle,
        token=token,
        expected_typ=expected_typ,
        expected_cty=expected_cty,
    )
    record(checks, "status", "status_signature", verification["ok"], verification["details"])
    if not verification["payload"]:
        return {"entries": {}}

    payload = demo.normalize_status_payload(verification["payload"])
    now = demo.utc_now()
    generated_at = demo.parse_time(payload["generated_at"])
    next_update_at = demo.parse_time(payload["next_update_at"])
    max_age = policy["freshness"]["status_max_age_seconds"]
    age_seconds = max(0, (now - generated_at).total_seconds())
    record(
        checks,
        "status",
        "status_document_window",
        generated_at <= now <= next_update_at and age_seconds <= max_age,
        f"status delivery is {delivery} and age is {int(age_seconds)}s",
    )
    return payload


def verify_identity(
    *,
    verifier_dir: Path,
    trust_bundle: dict[str, Any],
    request: dict[str, Any],
    policy: dict[str, Any],
    checks: list[dict[str, Any]],
) -> dict[str, Any]:
    verification = demo.verify_compact_jws(
        out_dir=verifier_dir,
        trust_bundle=trust_bundle,
        token=request["app_context"]["passport"]["jws"],
        expected_typ=demo.ARTIFACT_SPECS["passport"]["typ"],
        expected_cty=demo.ARTIFACT_SPECS["passport"]["cty"],
    )
    record(checks, "identity", "passport_signature", verification["ok"], verification["details"])
    payload = verification["payload"]
    if not payload:
        return {}

    now = demo.utc_now()
    valid_from = demo.parse_time(payload["valid_from"])
    valid_until = demo.parse_time(payload["valid_until"])
    record(
        checks,
        "identity",
        "passport_window",
        valid_from <= now <= valid_until,
        "passport is valid at verification time",
    )
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
) -> tuple[dict[str, Any], dict[str, Any]]:
    verification = demo.verify_compact_jws(
        out_dir=verifier_dir,
        trust_bundle=trust_bundle,
        token=request["app_context"]["runtime_proof"]["jws"],
        expected_typ=demo.ARTIFACT_SPECS["runtime_proof"]["typ"],
        expected_cty=demo.ARTIFACT_SPECS["runtime_proof"]["cty"],
    )
    record(checks, "runtime", "runtime_proof_signature", verification["ok"], verification["details"])
    payload = verification["payload"]
    header = verification["header"]
    if not payload:
        return {}, {}

    now = demo.utc_now()
    issued_at = demo.parse_time(payload["issued_at"])
    expires_at = demo.parse_time(payload["expires_at"])
    max_age = policy["freshness"]["runtime_max_age_seconds"]
    age_seconds = max(0, (now - issued_at).total_seconds())
    record(
        checks,
        "runtime",
        "runtime_window",
        issued_at <= now <= expires_at and age_seconds <= max_age,
        f"runtime proof age is {int(age_seconds)}s",
    )
    record(
        checks,
        "runtime",
        "runtime_subject_binding",
        payload.get("subject_id") == passport.get("subject", {}).get("root_id"),
        "runtime subject matches passport root id",
    )
    record(
        checks,
        "runtime",
        "runtime_audience",
        payload.get("challenge_binding", {}).get("aud") == policy["verifier_id"],
        "runtime audience matches verifier policy",
    )
    record(
        checks,
        "runtime",
        "runtime_presented_key_owner",
        trust_bundle["keys"].get(payload.get("presented_key", {}).get("kid"), {}).get("owner") == "runtime",
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
) -> tuple[dict[str, Any], dict[str, Any]]:
    verification = demo.verify_compact_jws(
        out_dir=verifier_dir,
        trust_bundle=trust_bundle,
        token=request["app_context"]["mission_permit"]["jws"],
        expected_typ=demo.ARTIFACT_SPECS["permit"]["typ"],
        expected_cty=demo.ARTIFACT_SPECS["permit"]["cty"],
    )
    record(checks, "permit", "mission_permit_signature", verification["ok"], verification["details"])
    payload = verification["payload"]
    header = verification["header"]
    if not payload:
        return {}, {}

    now = demo.utc_now()
    issued_at = demo.parse_time(payload["issued_at"])
    expires_at = demo.parse_time(payload["constraints"]["expires_at"])
    record(
        checks,
        "permit",
        "permit_window",
        issued_at <= now <= expires_at,
        "mission permit is valid at verification time",
    )
    record(
        checks,
        "permit",
        "permit_actor_binding",
        payload.get("actor") == passport.get("subject", {}).get("public_alias"),
        "permit actor matches passport alias",
    )
    record(
        checks,
        "permit",
        "permit_audience",
        payload.get("aud") == policy["verifier_id"],
        "permit audience matches verifier policy",
    )
    record(
        checks,
        "permit",
        "permit_action_scope",
        request["requested_action"] in payload.get("actions", []),
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
        request["requested_tool"] in payload.get("constraints", {}).get("tool_allowlist", []),
        "requested tool is within the mission permit tool allowlist",
    )
    record(
        checks,
        "permit",
        "permit_proof_binding",
        payload.get("proof_binding", {}).get("kid") == runtime_proof.get("presented_key", {}).get("kid")
        and payload.get("proof_binding", {}).get("spki_sha256")
        == runtime_proof.get("presented_key", {}).get("spki_sha256")
        and runtime_header.get("kid") != header.get("kid"),
        "permit proof binding matches the runtime-presented key",
    )
    return payload, header


def apply_effect(
    base_constraints: dict[str, Any],
    effect: dict[str, Any],
    policy: dict[str, Any],
) -> tuple[dict[str, Any] | None, list[str]]:
    handlers = policy["attenuation_handlers"]
    effect_constraints = effect.get("constraints", {})
    unknown = sorted(set(effect_constraints) - set(handlers))
    if unknown:
        return None, unknown

    narrowed = copy.deepcopy(base_constraints)
    for key, value in effect_constraints.items():
        handler = handlers[key]
        if handler == "intersect":
            base = narrowed.get(key, [])
            narrowed[key] = sorted(set(base).intersection(value))
        elif handler == "min":
            base = narrowed.get(key)
            narrowed[key] = value if base is None else min(base, value)
        elif handler == "replace":
            narrowed[key] = value
        elif handler == "escalate":
            narrowed[key] = value
        else:
            raise ValueError(f"unsupported attenuation handler {handler} for {key}")
    return narrowed, []


def request_within_constraints(
    request: dict[str, Any],
    *,
    constraints: dict[str, Any],
    permit: dict[str, Any],
) -> bool:
    if request["requested_resource"] != constraints.get("resource"):
        return False

    tools = constraints.get("tool_allowlist", [])
    if tools and request["requested_tool"] not in tools:
        return False

    approval = constraints.get("approval") or permit.get("approval", {})
    if approval.get("mode") == "human_required" and not request.get("approval_ref"):
        return False

    return True


def build_receipt(
    *,
    verifier_dir: Path,
    request: dict[str, Any],
    policy: dict[str, Any],
    permit: dict[str, Any],
    runtime_proof: dict[str, Any],
    decision: str,
    response_payload: dict[str, Any],
    status_entries: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    started_at = demo.utc_now()
    finished_at = demo.utc_now()
    receipt = {
        "version": "aer-0.1",
        "receipt_id": f"aer:http-verifier:{request['transaction_id']}:{decision}",
        "transaction_id": request["transaction_id"],
        "actor": permit["actor"],
        "principal": permit.get("principal"),
        "runtime_ref": runtime_proof["runtime_id"],
        "permit_ref": permit["permit_id"],
        "verifier": policy["verifier_id"],
        "issuer_role": "verifier",
        "skill": {
            "id": request["requested_action"],
            "version": "0.1.0",
        },
        "input_hash": canonical_hash(request.get("request_payload", {})),
        "output_hash": canonical_hash(response_payload),
        "policy_ref": policy["policy_id"],
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
    verifier_key = {
        "kid": "verifier-key-1",
        "alg": "ES256",
        "private_key": demo.key_path(verifier_dir, "verifier", "private"),
    }
    token = demo.build_compact_jws(
        receipt,
        key_info=verifier_key,
        typ=demo.ARTIFACT_SPECS["receipt"]["typ"],
        cty=demo.ARTIFACT_SPECS["receipt"]["cty"],
    )
    return receipt, token


def verify_execute_request(
    *,
    verifier_dir: Path,
    request: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    trust_bundle = read_json(verifier_dir / "trust-bundle.json")
    checks: list[dict[str, Any]] = []
    record(checks, "request", "request_shape", True, "request body parsed as JSON")

    status_payload = verify_status(
        verifier_dir=verifier_dir,
        trust_bundle=trust_bundle,
        app_context=request["app_context"],
        policy=policy,
        checks=checks,
    )
    passport = verify_identity(
        verifier_dir=verifier_dir,
        trust_bundle=trust_bundle,
        request=request,
        policy=policy,
        checks=checks,
    )
    runtime_proof, runtime_header = verify_runtime(
        verifier_dir=verifier_dir,
        trust_bundle=trust_bundle,
        request=request,
        passport=passport,
        policy=policy,
        checks=checks,
    )
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
    for object_type in ("passport", "runtime", "permit"):
        acceptable = policy["accepted_states"][object_type]
        state = entries.get(object_type, {}).get("state")
        record(
            checks,
            "status",
            f"{object_type}_state_acceptable",
            state in acceptable,
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

    effective_constraints = copy.deepcopy(permit.get("constraints", {}))
    decision = "allow"

    permit_state = entries.get("permit", {}).get("state")
    if permit_state == "attenuated":
        effect = entries.get("permit", {}).get("effect", {})
        record(
            checks,
            "policy",
            "policy_attenuation_mode",
            effect.get("mode") == "narrow",
            "attenuated permits must use mode=narrow in this demo profile",
        )
        narrowed, unknown_fields = apply_effect(effective_constraints, effect, policy)
        record(
            checks,
            "policy",
            "policy_attenuation_effect_known",
            not unknown_fields,
            "attenuation effect fields are known to the verifier policy"
            if not unknown_fields
            else f"unknown attenuation effect fields: {', '.join(unknown_fields)}",
        )
        record(
            checks,
            "policy",
            "policy_attenuation_reissue",
            not effect.get("require_new_permit", False),
            "attenuation does not require permit re-issuance",
        )
        if narrowed is not None:
            effective_constraints = narrowed
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
            "policy_attenuation_reissue",
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

    if not all(check["ok"] for check in checks):
        decision = "deny"

    report = {
        "version": "app-verification-report-0.1",
        "profile": "AL2-http",
        "checked_at": demo.iso(demo.utc_now()),
        "policy_id": policy["policy_id"],
        "decision": decision,
        "receipt_emitted": True,
        "request": {
            "action": request["requested_action"],
            "resource": request["requested_resource"],
            "tool": request["requested_tool"],
        },
        "failed_checks": sorted(check["name"] for check in checks if not check["ok"]),
        "passed_checks": sorted(check["name"] for check in checks if check["ok"]),
    }
    if decision == "attenuate":
        report["effective_constraints"] = effective_constraints

    response_payload = {
        "decision": decision,
        "policy_id": policy["policy_id"],
        "failed_checks": report["failed_checks"],
        "effective_constraints": report.get("effective_constraints"),
    }
    receipt, token = build_receipt(
        verifier_dir=verifier_dir,
        request=request,
        policy=policy,
        permit=permit,
        runtime_proof=runtime_proof,
        decision=decision,
        response_payload=response_payload,
        status_entries=entries,
    )

    return {
        "decision": decision,
        "verification_report": report,
        "check_details": checks,
        "execution_receipt": receipt,
        "execution_receipt_jws": token,
    }


def store_response_artifacts(directory: Path, response: dict[str, Any]) -> None:
    write_json(directory / "http-verifier-response.json", response)
    write_json(directory / "verifier-execution-receipt.json", response["execution_receipt"])
    write_text(directory / "verifier-execution-receipt.jws", response["execution_receipt_jws"])


def serve(directory: Path, *, policy_path: Path, host: str, port: int) -> None:
    policy = load_policy(policy_path)

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

            content_length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(content_length)
            try:
                request = json.loads(raw.decode("utf-8"))
                response = verify_execute_request(verifier_dir=directory, request=request, policy=policy)
                store_response_artifacts(directory, response)
                body = json.dumps(response, indent=2, sort_keys=True).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:  # pragma: no cover - demo server path
                self.send_error(HTTPStatus.BAD_REQUEST, str(exc))

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
        return json.loads(response.read().decode("utf-8"))


def execute_demo(directory: Path, *, base_url: str) -> dict[str, Any]:
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
    if isinstance(expected, list):
        if not isinstance(actual, list):
            return False
        return expected == actual
    return expected == actual


def run_corpus(corpus_root: Path, *, policy_path: Path) -> dict[str, Any]:
    temp_dir = Path(tempfile.mkdtemp(prefix="app-http-verifier-"))
    try:
        generate_demo(temp_dir, policy_path=policy_path)
        results = []
        for case_path in sorted(corpus_root.rglob("case.json")):
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
                    "--policy",
                    str(policy_path),
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
            raise SystemExit("HTTP verifier corpus run failed")


if __name__ == "__main__":
    main()
