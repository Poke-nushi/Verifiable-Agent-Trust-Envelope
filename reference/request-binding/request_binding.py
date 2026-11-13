"""Request preimage binding used by the VATE core's default admission API.

Only the purchase-cap profile and one max-amount replacement are supported.
This module checks content relationships, not signatures or execution authority.
"""

from __future__ import annotations

import copy
from contextlib import contextmanager
import hashlib
import importlib.util
import inspect
import json
import re
import sys
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Mapping

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = "vate-request-binding-v1"
PREIMAGE_PROFILE = "vate-purchase-cap-request-v1"
TRANSFORMATION_PROFILE = "vate-max-amount-only-v1"
CANONICALIZATION = "vate-v0.3-fixture-json"
ASSESSMENT = "vate-request-binding-assessment-v1"
MAX_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 64
MAX_SAFE_INTEGER = 9007199254740991
AMOUNT_RE = re.compile(r"(?:0|[1-9][0-9]{0,17})(?:\.[0-9]{1,8})?\Z")
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
ACTION = "commerce.purchase"
RUNTIME_CONTEXT = "vate-runtime-admission-context-v1"
RUNTIME_VERIFICATION = "vate-runtime-evidence-verification-v1"
PRE_DISPATCH = "vate-pre-dispatch-check-v1"
# A timestamp-valid .pyc can execute stale code after a same-size source update.
# Identify source only after it compiles to the code actually being executed.
_source = Path(__file__).read_bytes()
LOADED_SOURCE_SHA256 = (hashlib.sha256(_source).hexdigest() if hasattr(sys, "_getframe")
    and sys._getframe().f_code == compile(_source, sys._getframe().f_code.co_filename,
        "exec", dont_inherit=True, optimize=sys.flags.optimize) else None)
del _source


def _load_core() -> Any:
    spec = importlib.util.spec_from_file_location(
        "request_binding_vate_core", ROOT / "reference/vate-verifier-core/vate_verifier_core.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("VATE core unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


core = _load_core()


class Invalid(ValueError):
    """The supplied content failed a named binding check."""

    def __init__(self, cause: str) -> None:
        super().__init__(cause)
        self.cause = cause


class Unavailable(Invalid):
    """Required content or a supported contract was not supplied."""


def need(condition: bool, cause: str) -> None:
    if not condition:
        raise Invalid(cause)


def exact(value: Any, required: set[str], optional: set[str] | None = None) -> None:
    need(type(value) is dict and required <= value.keys()
         and value.keys() <= required | (optional or set()), "SCHEMA_INVALID")


def text(value: Any) -> None:
    need(isinstance(value, str) and bool(value), "SCHEMA_INVALID")


def _json_domain(value: Any, depth: int = 0) -> None:
    need(depth <= MAX_DEPTH, "JSON_DEPTH_EXCEEDED")
    if isinstance(value, str):
        need(not any(0xD800 <= ord(char) <= 0xDFFF for char in value), "INVALID_UNICODE")
    elif value is None or type(value) is bool:
        return
    elif type(value) is int:
        need(abs(value) <= MAX_SAFE_INTEGER, "UNSAFE_JSON_INTEGER")
    elif type(value) is list:
        for item in value:
            _json_domain(item, depth + 1)
    elif type(value) is dict:
        for key, item in value.items():
            need(isinstance(key, str), "SCHEMA_INVALID")
            _json_domain(key, depth + 1)
            _json_domain(item, depth + 1)
    else:
        raise Invalid("UNSUPPORTED_JSON_VALUE")


def encode(value: Any) -> bytes:
    _json_domain(value)
    raw = json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")
    need(len(raw) <= MAX_BYTES, "ARTIFACT_TOO_LARGE")
    return raw


class _JsonParser:
    """Bounded token reader shared in behavior with the TypeScript receiver.

    Validate in source order, before platform JSON integer/depth limits apply.
    The standard decoder is used only for one quoted string at a time.
    """

    number = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
    string_decoder = json.JSONDecoder()

    def __init__(self, source: str) -> None:
        self.source, self.offset = source, 0

    def whitespace(self) -> None:
        while self.offset < len(self.source) and self.source[self.offset] in " \n\r\t":
            self.offset += 1

    def consume(self, token: str) -> bool:
        if not self.source.startswith(token, self.offset):
            return False
        self.offset += len(token)
        return True

    def string(self) -> str:
        need(self.source[self.offset:self.offset + 1] == '"', "INVALID_JSON")
        value, self.offset = self.string_decoder.raw_decode(self.source, self.offset)
        _json_domain(value)
        return value

    def value(self, depth: int = 0) -> Any:
        need(depth <= MAX_DEPTH, "JSON_DEPTH_EXCEEDED")
        self.whitespace()
        if self.source[self.offset:self.offset + 1] == '"':
            return self.string()
        if self.consume("{"):
            result = {}
            self.whitespace()
            if self.consume("}"):
                return result
            while True:
                self.whitespace()
                key = self.string()
                self.whitespace()
                need(self.consume(":"), "INVALID_JSON")
                item = self.value(depth + 1)
                need(key not in result, "DUPLICATE_JSON_KEY")
                result[key] = item
                self.whitespace()
                if self.consume("}"):
                    return result
                need(self.consume(","), "INVALID_JSON")
        if self.consume("["):
            items = []
            self.whitespace()
            if self.consume("]"):
                return items
            while True:
                items.append(self.value(depth + 1))
                self.whitespace()
                if self.consume("]"):
                    return items
                need(self.consume(","), "INVALID_JSON")
        for token, value in (("true", True), ("false", False), ("null", None)):
            if self.consume(token):
                return value
        for token in ("NaN", "Infinity", "-Infinity"):
            need(not self.consume(token), "UNSUPPORTED_JSON_NUMBER")
        match = self.number.match(self.source, self.offset)
        need(match is not None, "INVALID_JSON")
        token = match.group()
        self.offset = match.end()
        need(not any(c in token for c in ".eE"), "UNSUPPORTED_JSON_NUMBER")
        digits, limit = token.lstrip("-"), str(MAX_SAFE_INTEGER)
        need(len(digits) < len(limit) or (len(digits) == len(limit) and digits <= limit),
             "UNSAFE_JSON_INTEGER")
        return int(token)

    def parse(self) -> Any:
        value = self.value()
        self.whitespace()
        need(self.offset == len(self.source), "INVALID_JSON")
        return value


def decode(raw: bytes) -> Any:
    need(type(raw) is bytes, "SCHEMA_INVALID")
    need(len(raw) <= MAX_BYTES, "ARTIFACT_TOO_LARGE")

    try:
        return _JsonParser(raw.decode("utf-8")).parse()
    except Invalid:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Invalid("INVALID_JSON") from exc


def digest(raw: bytes) -> dict[str, str]:
    return {"alg": "sha-256", "value": hashlib.sha256(raw).hexdigest()}


def object_hash(value: Any) -> str:
    return "sha-256:" + digest(encode(value))["value"]


def reference(raw: bytes) -> dict:
    descriptor = digest(raw)
    return {"uri": "urn:sha256:" + descriptor["value"],
            "media_type": "application/json", "digest": descriptor}


def validate_reference(ref: Any) -> None:
    exact(ref, {"uri", "media_type", "digest"})
    exact(ref["digest"], {"alg", "value"})
    need(ref["digest"]["alg"] == "sha-256"
         and isinstance(ref["digest"]["value"], str)
         and HASH_RE.fullmatch(ref["digest"]["value"]) is not None, "SCHEMA_INVALID")
    need(ref["media_type"] == "application/json"
         and ref["uri"] == "urn:sha256:" + ref["digest"]["value"], "SCHEMA_INVALID")


def resolve(ref: dict, artifacts: Mapping[str, bytes]) -> dict:
    validate_reference(ref)
    if ref["uri"] not in artifacts:
        raise Unavailable("ARTIFACT_NOT_SUPPLIED")
    raw = artifacts[ref["uri"]]
    need(type(raw) is bytes, "SCHEMA_INVALID")
    need(len(raw) <= MAX_BYTES, "ARTIFACT_TOO_LARGE")
    need(digest(raw) == ref["digest"], "DIGEST_MISMATCH")
    result = decode(raw)
    need(type(result) is dict, "SCHEMA_INVALID")
    return result


def amount(value: Any) -> Decimal:
    need(isinstance(value, str) and AMOUNT_RE.fullmatch(value) is not None,
         "INVALID_DECIMAL_AMOUNT")
    return Decimal(value)


def money(value: Any) -> None:
    exact(value, {"currency", "value"})
    need(isinstance(value["currency"], str)
         and re.fullmatch(r"[A-Z]{3}", value["currency"]) is not None, "SCHEMA_INVALID")
    amount(value["value"])


def constraints(value: Any) -> None:
    exact(value, {"max_amount", "tool_allowlist"})
    money(value["max_amount"])
    allowed = value["tool_allowlist"]
    need(type(allowed) is list and 0 < len(allowed) <= 32
         and all(isinstance(tool, str) and tool for tool in allowed), "SCHEMA_INVALID")
    need(len(set(allowed)) == len(allowed), "SCHEMA_INVALID")


def validate_operation(operation: Any) -> None:
    exact(operation, {"preimage_profile", "operation_id", "action", "target", "payload", "constraints"})
    need(operation["preimage_profile"] == PREIMAGE_PROFILE
         and operation["action"] == ACTION, "UNSUPPORTED_OPERATION_PROFILE")
    text(operation["operation_id"])
    exact(operation["target"], {"resource", "audience"})
    for value in operation["target"].values():
        text(value)
    exact(operation["payload"], {"tool", "order_id", "amount"})
    text(operation["payload"]["tool"])
    text(operation["payload"]["order_id"])
    money(operation["payload"]["amount"])
    constraints(operation["constraints"])


def payload_within_constraints(operation: dict) -> bool:
    payload = operation["payload"]
    cap = operation["constraints"]["max_amount"]
    return (payload["amount"]["currency"] == cap["currency"]
            and amount(payload["amount"]["value"]) <= amount(cap["value"])
            and payload["tool"] in operation["constraints"]["tool_allowlist"])


def validate_admission(request: Any, original: dict) -> None:
    exact(request, {"version", "profile", "request_id", "transaction_id", "issued_at", "expires_at",
                    "action", "target", "actor", "principal", "runtime", "audience", "input_hash",
                    "constraints", "evidence_refs"})
    need(request["version"] == core.VERSION and request["profile"] == core.PROFILE, "SCHEMA_INVALID")
    for key in ("request_id", "transaction_id", "actor", "principal", "runtime", "audience"):
        text(request[key])
    issued, expires = core.safe_parse_time(request["issued_at"]), core.safe_parse_time(request["expires_at"])
    need(issued is not None and expires is not None and issued <= expires, "INVALID_REQUEST_WINDOW")
    refs = request["evidence_refs"]
    need(type(refs) is list and bool(refs)
         and all(type(ref) is dict and isinstance(ref.get("type"), str)
                 and ("protocol_hint" not in ref or isinstance(ref["protocol_hint"], str))
                 and core.is_valid_evidence_reference(ref) for ref in refs), "SCHEMA_INVALID")
    need(len({(ref["type"], ref["uri"]) for ref in refs}) == len(refs), "DUPLICATE_EVIDENCE_REFERENCE")
    need(request["input_hash"] == object_hash(original), "INPUT_HASH_MISMATCH")
    need(request["transaction_id"] == original["operation_id"]
         and request["action"] == original["action"]
         and request["target"] == original["target"]
         and request["audience"] == original["target"]["audience"]
         and request["constraints"] == original["constraints"], "ADMISSION_REQUEST_MISMATCH")


def action_binding(operation: dict) -> dict:
    return {"type": "profile_defined_digest", "preimage_profile": PREIMAGE_PROFILE,
            "canonicalization": CANONICALIZATION, "digest": digest(encode(operation))}


def _same_json(left: Any, right: Any) -> bool:
    """Compare decoded JSON without serializing or equating bools with ints."""
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(_same_json(left[key], right[key]) for key in left)
    if type(left) is list:
        return len(left) == len(right) and all(_same_json(a, b) for a, b in zip(left, right))
    return left == right


def _receipt_evidence_references(receipt: dict, request: dict) -> None:
    """Bind reference identities, not the truth of their verification claims."""
    expected = {(ref["type"], ref["uri"]): ref for ref in request["evidence_refs"]}
    items = receipt.get("evidence")
    need(type(items) is list and len(items) == len(expected), "RECEIPT_EVIDENCE_MISMATCH")
    seen = set()
    for item in items:
        need(type(item) is dict and isinstance(item.get("type"), str)
             and isinstance(item.get("uri"), str), "RECEIPT_EVIDENCE_MISMATCH")
        key = (item["type"], item["uri"])
        need(key in expected and key not in seen, "RECEIPT_EVIDENCE_MISMATCH")
        seen.add(key)
        ref = expected[key]
        fields = ("type", "uri", "digest", "protocol_hint")
        need(_same_json({k: item[k] for k in fields if k in item},
                        {k: ref[k] for k in fields if k in ref}), "RECEIPT_EVIDENCE_MISMATCH")
        # v0.3 receipt evidence does not require media_type. If supplied, it
        # must preserve the request's value; annotation extensions stay intact.
        need("media_type" not in item or item["media_type"] == ref["media_type"],
             "RECEIPT_EVIDENCE_MISMATCH")


def _receipt_context(receipt: dict, request: dict) -> str:
    for key, expected in (("version", core.VERSION), ("profile", core.PROFILE), ("receipt_type", "admission")):
        need(receipt.get(key) == expected, "SCHEMA_INVALID")
    text(receipt.get("receipt_id"))
    summary = receipt.get("request")
    need(type(summary) is dict, "SCHEMA_INVALID")
    for key in ("request_id", "transaction_id", "action", "input_hash", "constraints"):
        need(summary.get(key) == request[key], "RECEIPT_REQUEST_MISMATCH")
    subject = receipt.get("subject")
    need(type(subject) is dict, "SCHEMA_INVALID")
    for key in ("principal", "actor", "runtime"):
        need(subject.get(key) == request[key], "RECEIPT_SUBJECT_MISMATCH")
    decision = receipt.get("decision")
    need(type(decision) is dict and decision.get("outcome") in ("allow", "attenuate", "deny"), "SCHEMA_INVALID")
    codes = decision.get("reason_codes")
    need(type(codes) is list and bool(codes)
         and all(isinstance(code, str) and code for code in codes), "SCHEMA_INVALID")
    issued, expires = core.safe_parse_time(receipt.get("issued_at")), core.safe_parse_time(receipt.get("expires_at"))
    need(issued is not None and expires is not None and issued <= expires, "INVALID_RECEIPT_WINDOW")
    if decision["outcome"] != "deny":
        need(core.parse_time(request["issued_at"]) <= issued <= expires <= core.parse_time(request["expires_at"]),
             "RECEIPT_WINDOW_EXCEEDS_REQUEST")
    return decision["outcome"]


def reconstruct(original: dict, attenuation: Any, codes: list[str]) -> dict:
    exact(attenuation, {"mode", "original_request_hash", "effective_request_hash", "changes",
                        "effective_constraints", "require_new_permit"})
    need(type(attenuation["require_new_permit"]) is bool, "SCHEMA_INVALID")
    need(attenuation["mode"] in ("narrow", "require_new_permit"), "UNSUPPORTED_TRANSFORMATION")
    need(attenuation["mode"] != "require_new_permit" or attenuation["require_new_permit"], "SCHEMA_INVALID")
    changes = attenuation["changes"]
    need(type(changes) is list and len(changes) == 1, "UNSUPPORTED_TRANSFORMATION")
    change = changes[0]
    exact(change, {"op", "path", "from", "to", "reason_code"})
    need(change["op"] == "replace" and change["path"] == "/constraints/max_amount/value",
         "UNSUPPORTED_TRANSFORMATION")
    need(change["reason_code"] == "LOCAL_POLICY_MAX_AMOUNT_NARROWED"
         and change["reason_code"] in codes, "ATTENUATION_REASON_MISMATCH")
    old = original["constraints"]["max_amount"]["value"]
    need(type(change["from"]) is str and change["from"] == old, "ATTENUATION_FROM_MISMATCH")
    need(amount(change["to"]) < amount(old), "CONSTRAINT_NOT_NARROWED")
    result = copy.deepcopy(original)
    result["constraints"]["max_amount"]["value"] = change["to"]
    return result


def assess_request_binding(receipt_bytes: bytes, artifacts: Mapping[str, bytes], *,
                           required_contract: str = CONTRACT,
                           expected_admission_request_ref: dict | None = None) -> dict:
    """Return a receiver-generated assessment; never fetch URLs or mutate inputs.

    The expected admission reference must come from the receiver's selected
    request. A declaration or a self-reported pass inside a receipt is not a pin.
    """
    text(required_contract)
    need(type(receipt_bytes) is bytes and isinstance(artifacts, Mapping), "SCHEMA_INVALID")
    report: dict = {"contract": ASSESSMENT, "required_contract": required_contract,
                    "receipt_digest": digest(receipt_bytes), "status": "not_checked", "pass": None,
                    "binding_requirement_met": False, "decision_allows_immediate_execution": False,
                    "checks": []}
    check = "receipt.json"

    def passed(name: str) -> None:
        report["checks"].append({"name": name, "status": "checked", "pass": True})

    try:
        receipt = decode(receipt_bytes)
        need(type(receipt) is dict, "SCHEMA_INVALID")
        passed(check)
        check = "binding.contract"
        if "request_binding" not in receipt:
            raise Unavailable("BINDING_NOT_DECLARED")
        binding = receipt["request_binding"]
        exact(binding, {"contract", "preimage_profile", "canonicalization", "transformation_profile",
                        "admission_request_ref", "original_ref"}, {"effective_ref"})
        if (required_contract != CONTRACT or binding["contract"] != CONTRACT
                or binding["preimage_profile"] != PREIMAGE_PROFILE
                or binding["canonicalization"] != CANONICALIZATION
                or binding["transformation_profile"] != TRANSFORMATION_PROFILE):
            raise Unavailable("UNSUPPORTED_BINDING_PROFILE")
        for key in ("admission_request_ref", "original_ref", "effective_ref"):
            if key in binding:
                validate_reference(binding[key])
        passed(check)
        check = "receiver.admission_request"
        if expected_admission_request_ref is None:
            raise Unavailable("EXPECTED_ADMISSION_REQUEST_NOT_SUPPLIED")
        validate_reference(expected_admission_request_ref)
        need(binding["admission_request_ref"] == expected_admission_request_ref, "ADMISSION_REFERENCE_MISMATCH")
        passed(check)
        loaded: dict = {}
        for name, field in (("original", "original_ref"), ("admission", "admission_request_ref")):
            check = name + ".artifact"
            loaded[name] = resolve(binding[field], artifacts)
            passed(check)
        original, request = loaded["original"], loaded["admission"]
        check = "original.profile"
        validate_operation(original)
        passed(check)
        check = "original.admission_binding"
        validate_admission(request, original)
        passed(check)
        check = "receipt.context"
        decision = _receipt_context(receipt, request)
        passed(check)
        check = "receipt.evidence_references"
        _receipt_evidence_references(receipt, request)
        passed(check)
        check = "effective.artifact"
        if decision == "deny":
            need("effective_ref" not in binding and "attenuation" not in receipt
                 and "action_binding" not in receipt["request"], "DENIED_EFFECTIVE_REQUEST")
            passed(check)
        else:
            if "effective_ref" not in binding:
                raise Unavailable("EFFECTIVE_REFERENCE_NOT_SUPPLIED")
            effective = resolve(binding["effective_ref"], artifacts)
            validate_operation(effective)
            passed(check)
            check = "attenuation.reconstruction"
            if decision == "allow":
                need("attenuation" not in receipt, "UNEXPECTED_ATTENUATION")
                need(effective == original, "ALLOW_REQUEST_CHANGED")
            else:
                reconstructed = reconstruct(original, receipt.get("attenuation"), receipt["decision"]["reason_codes"])
                need(effective == reconstructed, "EFFECTIVE_RECONSTRUCTION_MISMATCH")
                attenuation = receipt["attenuation"]
                need(attenuation["original_request_hash"] == object_hash(original), "ORIGINAL_HASH_MISMATCH")
                need(attenuation["effective_request_hash"] == object_hash(effective), "EFFECTIVE_HASH_MISMATCH")
                need(attenuation["effective_constraints"] == effective["constraints"], "EFFECTIVE_CONSTRAINTS_MISMATCH")
            passed(check)
            check = "effective.action_binding"
            need(receipt["request"].get("action_binding") == action_binding(effective), "ACTION_BINDING_MISMATCH")
            passed(check)
            check = "effective.payload_constraints"
            need(payload_within_constraints(original) and payload_within_constraints(effective), "PAYLOAD_EXCEEDS_CONSTRAINTS")
            passed(check)
        report.update(status="checked", **{"pass": True}, binding_requirement_met=True,
                      decision_allows_immediate_execution=(decision == "allow" or
                          decision == "attenuate" and not receipt["attenuation"]["require_new_permit"]))
    except Invalid as exc:
        missing = isinstance(exc, Unavailable)
        report["status"] = "not_checked" if missing else "checked"
        report["pass"] = None if missing else False
        report["checks"].append({"name": check, "status": report["status"],
                                 "pass": report["pass"], "cause": exc.cause})
    report["checks"].append({"name": "evidence.authentication", "status": "not_checked",
                             "pass": None, "cause": "EVIDENCE_AUTHENTICATION_NOT_PERFORMED"})
    report["checks"].append({"name": "execution.actual_input", "status": "not_checked",
                             "pass": None, "cause": "EXECUTION_OBSERVATION_NOT_SUPPLIED"})
    return report


@dataclass(frozen=True)
class RuntimeEvidenceContext:
    """Immutable expectations supplied to a verifier-selected adapter."""

    admission_request: bytes
    original: bytes
    evidence_reference: bytes
    context_hash: str
    runtime: str
    audience: str
    now: datetime


@dataclass(frozen=True)
class AuthenticatedRuntimeClaims:
    """Adapter output derived from authenticated evidence, never received JSON.

    The adapter authenticates the issuer's authority for the runtime and these
    claims. All times use the supported RFC3339 form; valid_until is inclusive.
    Principal/actor authority and execution are not established by this result.
    """

    artifact_sha256: str
    context_hash: str
    runtime: str
    audience: str
    issuer: str
    issued_at: str
    not_before: str
    valid_until: str


@dataclass(frozen=True)
class RuntimeEvidenceVerifier:
    """Trusted application configuration, not a request-selected verifier.

    verify must authenticate the exact bytes, use independently configured
    trust material, and return AuthenticatedRuntimeClaims or raise on failure.
    """

    method: str
    media_type: str
    max_age_seconds: int
    verify: Callable[[bytes, RuntimeEvidenceContext], AuthenticatedRuntimeClaims]
    protocol_hint: str | None = None


def runtime_context_hash(admission_request_bytes: bytes, original_bytes: bytes) -> str:
    """Hash the validated request and policy refs, excluding runtime proof refs.

    Excluding the runtime proof's reference avoids hashing a proof into itself.
    The full admission bytes, including that reference, remain receipt-bound.
    """
    request, original = decode(admission_request_bytes), decode(original_bytes)
    validate_operation(original)
    validate_admission(request, original)
    context = {**request, "evidence_refs": [ref for ref in request["evidence_refs"]
                                           if ref["type"] != "runtime_attestation"]}
    return object_hash({"contract": RUNTIME_CONTEXT, "admission": context})


def _verify_runtime_evidence(adapter: Any, ref: dict, raw: bytes, request: dict,
                             admission_bytes: bytes, original_bytes: bytes,
                             now: datetime) -> dict:
    need(type(adapter) is RuntimeEvidenceVerifier, "INVALID_RUNTIME_VERIFIER")
    need(type(adapter.method) is str and bool(adapter.method)
         and type(adapter.media_type) is str and bool(adapter.media_type)
         and type(adapter.max_age_seconds) is int and adapter.max_age_seconds > 0
         and callable(adapter.verify)
         and (adapter.protocol_hint is None or type(adapter.protocol_hint) is str
              and adapter.protocol_hint in core.ALLOWED_PROTOCOL_HINTS_BY_TYPE["runtime_attestation"]),
         "INVALID_RUNTIME_VERIFIER")
    try:
        freshness_window = timedelta(seconds=adapter.max_age_seconds)
    except OverflowError:
        raise Invalid("INVALID_RUNTIME_VERIFIER") from None
    need(ref["media_type"] == adapter.media_type and ref.get("protocol_hint") == adapter.protocol_hint,
         "UNSUPPORTED_RUNTIME_EVIDENCE_FORMAT")
    need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "INVALID_RUNTIME_EVIDENCE_BYTES")
    raw_digest = digest(raw)
    need(ref["digest"]["value"] == raw_digest["value"], "RUNTIME_EVIDENCE_DIGEST_MISMATCH")
    context = RuntimeEvidenceContext(
        admission_bytes, original_bytes, encode(ref),
        runtime_context_hash(admission_bytes, original_bytes), request["runtime"], request["audience"], now)
    try:
        claims = adapter.verify(raw, context)
    except Exception:
        # Adapter diagnostics may contain native proof/key material. Return a
        # stable failure without copying those details into an admission error.
        raise Invalid("RUNTIME_EVIDENCE_VERIFICATION_FAILED") from None
    need(type(claims) is AuthenticatedRuntimeClaims, "INVALID_RUNTIME_VERIFICATION_RESULT")
    need(all(type(value) is str and bool(value) for value in (
        claims.artifact_sha256, claims.context_hash, claims.runtime, claims.audience,
        claims.issuer, claims.issued_at, claims.not_before, claims.valid_until)),
        "INVALID_RUNTIME_VERIFICATION_RESULT")
    need(claims.artifact_sha256 == raw_digest["value"], "RUNTIME_VERIFICATION_ARTIFACT_MISMATCH")
    need(claims.context_hash == context.context_hash, "RUNTIME_VERIFICATION_CONTEXT_MISMATCH")
    need(claims.runtime == request["runtime"], "RUNTIME_VERIFICATION_SUBJECT_MISMATCH")
    need(claims.audience == request["audience"], "RUNTIME_VERIFICATION_AUDIENCE_MISMATCH")
    issued, not_before, valid_until = (core.safe_parse_time(value) for value in
                                      (claims.issued_at, claims.not_before, claims.valid_until))
    need(issued is not None and not_before is not None and valid_until is not None
         and issued <= valid_until and not_before <= valid_until, "INVALID_RUNTIME_EVIDENCE_WINDOW")
    need(issued <= now and not_before <= now <= valid_until, "RUNTIME_EVIDENCE_OUTSIDE_WINDOW")
    need(now - issued <= freshness_window, "RUNTIME_EVIDENCE_STALE")
    # Avoid datetime overflow even for a large, otherwise valid max age.
    usable_until = valid_until if freshness_window >= valid_until - issued else issued + freshness_window
    return {"contract": RUNTIME_VERIFICATION, "evidence_ref": copy.deepcopy(ref),
            "admission_request_ref": reference(admission_bytes), "original_ref": reference(original_bytes),
            "context_hash": context.context_hash, "runtime": claims.runtime, "audience": claims.audience,
            "issuer": claims.issuer, "issued_at": claims.issued_at, "not_before": claims.not_before,
            "valid_until": claims.valid_until, "usable_until": core.iso(usable_until),
            "max_age_seconds": adapter.max_age_seconds,
            "verification": {"result": "verified", "checked_at": core.iso(now), "method": adapter.method}}


@dataclass(frozen=True)
class BoundAdmission:
    """Immutable bytes retained alongside the receiver's assessment."""

    original: bytes
    request: bytes
    core_result: bytes
    receipt: bytes
    effective: bytes | None
    assessment: bytes
    runtime_evidence: bytes | None = None
    runtime_verification: bytes | None = None


@dataclass
class _BoundaryState:
    lock: Any = field(default_factory=RLock)
    active: bool = False
    clock_high: datetime | None = None


@dataclass(frozen=True)
class DispatchBoundary:
    """Application-selected synchronous callback, clock and update order.

    All writers of trust/configuration read by dispatch must use update().
    The guard orders cooperating local updates; it cannot lock a remote issuer.
    The callback receives only the admitted effective bytes and check record.
    """

    execute: Callable[[bytes, bytes], Any]
    clock: Callable[[], datetime] = core.utc_now
    _state: _BoundaryState = field(default_factory=_BoundaryState, init=False, repr=False, compare=False)

    @contextmanager
    def update(self):
        """Serialize a local trust/configuration update with dispatch."""
        with self._state.lock:
            need(not self._state.active, "DISPATCH_REENTRANT_UPDATE")
            yield

    def _now(self) -> datetime:
        try:
            now = self.clock()
            need(isinstance(now, datetime) and now.tzinfo is not None and now.utcoffset() is not None,
                 "INVALID_DISPATCH_TIME")
            # Same-zone datetime comparison ignores fold/offset changes. Use
            # UTC instants so DST transitions cannot hide a clock rollback.
            now = now.astimezone(timezone.utc)
        except Invalid:
            raise
        except Exception:
            raise Invalid("DISPATCH_CLOCK_UNAVAILABLE") from None
        need(self._state.clock_high is None or now >= self._state.clock_high, "DISPATCH_CLOCK_ROLLBACK")
        self._state.clock_high = now
        return now


@dataclass(frozen=True)
class DispatchResult:
    """Local pre-dispatch checks and the callback's unverified return value."""

    checkpoint: bytes
    value: Any


class DispatchAttemptError(RuntimeError):
    """Attempt consumed; callback entry and operation outcome are not established."""

    def __init__(self, checkpoint: bytes) -> None:
        super().__init__("DISPATCH_OUTCOME_UNCONFIRMED")
        self.checkpoint = checkpoint


@dataclass
class _DispatchEntry:
    bound: BoundAdmission
    values: tuple
    policy: bytes
    adapter: RuntimeEvidenceVerifier
    boundary: DispatchBoundary
    verifier_id: str
    fail_closed: bool
    store: Any = None
    store_configuration: bytes | None = None
    attempted: bool = False


def durable_state_module() -> Any:
    """Load the optional installed store only when selected by the application."""
    path = Path(__file__).with_name("durable_state.py").resolve()
    existing = sys.modules.get("durable_state")
    if existing is not None:
        need(Path(getattr(existing, "__file__", "")).resolve() == path, "STATE_MODULE_CHANGED")
        return existing
    spec = importlib.util.spec_from_file_location("durable_state", path)
    need(spec is not None and spec.loader is not None, "STATE_MODULE_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    sys.modules["durable_state"] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop("durable_state", None)
        raise
    return module


def _store_call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except durable_state_module().StateError as exc:
        raise Invalid(exc.cause) from None


def _selected_store(verifier: Any) -> Any:
    store = verifier.state_store
    need(type(store) is durable_state_module().DurableStateStore
         and store.verifier_id == verifier.verifier_id, "STATE_CONFIGURATION_INVALID")
    return store


def _store_configuration(verifier: Any) -> bytes:
    store = _selected_store(verifier)
    adapter = verifier.runtime_evidence_verifier
    _dispatch_configuration(verifier.dispatch_boundary, adapter)
    need(vars(type(verifier)).get("_loaded_source_path") == Path(core.__file__).resolve()
         and vars(type(verifier)).get("_loaded_source_sha256") == core.LOADED_SOURCE_SHA256,
         "STATE_IMPLEMENTATION_CHANGED")
    sources = {}
    for module, relative in ((sys.modules[__name__], "reference/request-binding/request_binding.py"),
                             (core, "reference/vate-verifier-core/vate_verifier_core.py"),
                             (durable_state_module(), "reference/request-binding/durable_state.py")):
        need(hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest() == module.LOADED_SOURCE_SHA256,
             "STATE_IMPLEMENTATION_CHANGED")
        sources[relative] = module.LOADED_SOURCE_SHA256
    return encode({"contract": "vate-durable-admission-configuration-v1", "scope": store.scope,
        "verifier_id": verifier.verifier_id, "policy": verifier.policy, "fail_closed": verifier.fail_closed,
        "runtime_verifier": {"method": adapter.method, "media_type": adapter.media_type,
            "max_age_seconds": adapter.max_age_seconds, "protocol_hint": adapter.protocol_hint}, "sources": sources})


@dataclass(frozen=True)
class StoredDispatchStatus:
    state: str
    record: bytes
    checkpoint: bytes | None


def dispatch_status(verifier: Any, request_id: str) -> StoredDispatchStatus:
    store = _selected_store(verifier)
    saved = _store_call(store.read, request_id)
    checkpoint = saved["checkpoint"]
    record = {"contract": "vate-durable-dispatch-status-v1", "store_anchor_digest": digest(store.anchor),
        "scope": store.scope, "request_id": request_id, "operation_id": saved["operation_id"],
        "state": saved["state"], "attempt_request_id": saved["attempt_request_id"],
        "admission_request_ref": reference(saved["values"][1]), "receipt_ref": reference(saved["values"][3]),
        "checkpoint_ref": reference(checkpoint) if checkpoint is not None else None}
    return StoredDispatchStatus(saved["state"], encode(record), checkpoint)


def restore_admission(verifier: Any, request_id: str) -> BoundAdmission:
    store = _selected_store(verifier)
    configuration = _store_configuration(verifier)
    boundary = verifier.dispatch_boundary
    with boundary._state.lock:
        need(not boundary._state.active, "DISPATCH_REENTRANT")
        saved = _store_call(store.read, request_id)
        need(saved["executable"], "DISPATCH_NOT_EXECUTABLE")
        need(saved["state"] == "ready", "DURABLE_OPERATION_ALREADY_ATTEMPTED")
        need(saved["configuration"] == configuration, "STATE_CONFIGURATION_CHANGED")
        bound = BoundAdmission(*saved["values"])
        request = decode(bound.request)
        need(request["request_id"] == request_id and request["transaction_id"] == saved["operation_id"],
             "STATE_RECORD_CHANGED")
        artifacts = {reference(raw)["uri"]: raw for raw in (bound.original, bound.request, bound.effective)}
        assessment = assess_request_binding(bound.receipt, artifacts,
            expected_admission_request_ref=reference(bound.request))
        need(assessment["binding_requirement_met"] and assessment["decision_allows_immediate_execution"],
             "DISPATCH_NOT_EXECUTABLE")
        need(_store_configuration(verifier) == configuration, "STATE_CONFIGURATION_CHANGED")
        with verifier._replay_lock:
            verifier._seen_request_ids.add(request_id)
            _register_dispatch(verifier, bound, verifier.policy, verifier.runtime_evidence_verifier,
                               boundary, store_configuration=configuration)
        return bound


def _dispatch_configuration(boundary: Any, adapter: Any) -> None:
    need(type(boundary) is DispatchBoundary and callable(boundary.execute) and callable(boundary.clock),
         "INVALID_DISPATCH_BOUNDARY")
    need(type(adapter) is RuntimeEvidenceVerifier, "DISPATCH_REQUIRES_RUNTIME_VERIFIER")
    for function in (boundary.execute, getattr(boundary.execute, "__call__", None)):
        need(not any(check(function) for check in (inspect.iscoroutinefunction,
                 inspect.isgeneratorfunction, inspect.isasyncgenfunction)), "DISPATCH_CALLBACK_NOT_SYNCHRONOUS")


def _bound_values(bound: BoundAdmission) -> tuple:
    return tuple(getattr(bound, item.name) for item in fields(BoundAdmission))


def _register_dispatch(verifier: Any, bound: BoundAdmission, policy: dict,
                       adapter: Any, boundary: Any, *, store_configuration: bytes | None = None) -> None:
    # Called only at the end of successful issuance, inside the replay lock.
    if boundary is None or not decode(bound.assessment)["decision_allows_immediate_execution"]:
        return
    verifier._dispatch_entries[id(bound)] = _DispatchEntry(
        bound, _bound_values(bound), encode(policy), adapter, boundary, verifier.verifier_id, verifier.fail_closed,
        verifier.state_store, store_configuration)


def dispatch_bound(verifier: Any, bound: BoundAdmission) -> DispatchResult:
    """Reauthenticate immediately before invoking the configured callback once.

    Only an admission issued or restored by this verifier is eligible. No caller
    evaluation time, substitute operation, received verification result, or
    new callback can be supplied to this entry point.
    """
    boundary = verifier.dispatch_boundary
    _dispatch_configuration(boundary, verifier.runtime_evidence_verifier)
    need(type(bound) is BoundAdmission, "DISPATCH_ADMISSION_NOT_ISSUED")
    with boundary._state.lock:
        need(not boundary._state.active, "DISPATCH_REENTRANT")
        boundary._state.active = True
        try:
            with verifier._replay_lock:
                entry = verifier._dispatch_entries.get(id(bound))
                need(entry is not None and entry.bound is bound, "DISPATCH_ADMISSION_NOT_ISSUED")
                need(not entry.attempted, "DISPATCH_ALREADY_ATTEMPTED")
            need(_bound_values(bound) == entry.values, "DISPATCH_ADMISSION_CHANGED")

            def configuration_unchanged() -> None:
                need(verifier.dispatch_boundary is entry.boundary
                     and verifier.runtime_evidence_verifier is entry.adapter
                     and verifier.state_store is entry.store
                     and verifier.verifier_id == entry.verifier_id
                     and verifier.fail_closed == entry.fail_closed
                     and encode(verifier.policy) == entry.policy, "DISPATCH_CONFIGURATION_CHANGED")
                if entry.store is not None:
                    need(_store_configuration(verifier) == entry.store_configuration, "STATE_CONFIGURATION_CHANGED")

            def current_time() -> datetime:
                return (boundary._now() if entry.store is None else
                        _store_call(entry.store.observe_clock, boundary._now))

            configuration_unchanged()
            artifacts = {reference(raw)["uri"]: raw for raw in (bound.request, bound.original, bound.effective)}
            assessment = assess_request_binding(bound.receipt, artifacts,
                expected_admission_request_ref=reference(bound.request))
            need(assessment["binding_requirement_met"] and assessment["decision_allows_immediate_execution"],
                 "DISPATCH_NOT_EXECUTABLE")
            request, receipt = decode(bound.request), decode(bound.receipt)
            start, end = core.parse_time(receipt["issued_at"]), core.parse_time(receipt["expires_at"])

            def in_window(instant: datetime, deadline: datetime) -> None:
                need(start <= instant <= deadline, "DISPATCH_OUTSIDE_WINDOW")

            now = current_time()
            in_window(now, end)
            ref, = (item for item in request["evidence_refs"] if item["type"] == "runtime_attestation")
            verified = _verify_runtime_evidence(entry.adapter, ref, bound.runtime_evidence, request,
                bound.request, bound.original, now)
            configuration_unchanged()
            deadline = min(end, core.parse_time(verified["usable_until"]))
            checked_at = current_time()
            in_window(checked_at, deadline)
            checkpoint = encode({"contract": PRE_DISPATCH, "checked_at": core.iso(checked_at),
                "usable_until": core.iso(deadline), "receipt_ref": reference(bound.receipt),
                "admission_request_ref": reference(bound.request), "original_ref": reference(bound.original),
                "effective_ref": reference(bound.effective), "runtime_verification": verified})
            # Include verification and record construction time, not merely the
            # time at entry. The final read also follows replay-lock contention
            # with another admission; waiting must not bypass the deadline.
            configuration_unchanged()
            stored_digest = None
            with verifier._replay_lock:
                need(not entry.attempted, "DISPATCH_ALREADY_ATTEMPTED")
                if entry.store is None:
                    in_window(boundary._now(), deadline)
                else:
                    stored_digest = durable_state_module().record_digest(request["request_id"], request["transaction_id"],
                        entry.store_configuration, entry.values, True)
                    try:
                        entry.store.claim(request["request_id"], entry.store_configuration, stored_digest,
                            checkpoint, boundary._now, lambda instant: in_window(instant, deadline))
                    except durable_state_module().StateError as exc:
                        # A failed COMMIT may have persisted the claim. Never
                        # treat this object's local state as retry authority.
                        entry.attempted = True
                        raise Invalid(exc.cause) from None
                entry.attempted = True
            # Never roll this state back: a raised callback can have effects.
            # A callback return is not independently observed execution proof.
            try:
                if entry.store is not None:
                    # Durable commit itself can outlive validity. Consumption
                    # remains durable even when this final check stops entry.
                    in_window(boundary._now(), deadline)
                value = boundary.execute(bound.effective, checkpoint)
                if inspect.iscoroutine(value):
                    value.close()
                need(not (inspect.isawaitable(value) or inspect.isgenerator(value) or inspect.isasyncgen(value)),
                     "DISPATCH_DEFERRED_RESULT")
                if entry.store is not None:
                    entry.store.finish(request["request_id"], stored_digest, returned=True)
                return DispatchResult(checkpoint, value)
            except Exception:
                # Distinguish an entered callback (including one raising
                # Invalid) from a failed precheck, without exposing its data.
                # BaseException interrupts still propagate with state consumed.
                if entry.store is not None:
                    try:
                        entry.store.finish(request["request_id"], stored_digest, returned=False)
                    except Exception:
                        pass  # The already committed consumed fence remains.
                raise DispatchAttemptError(checkpoint) from None
        finally:
            boundary._state.active = False


def admit_bound(verifier: Any, admission_request_bytes: bytes, original_bytes: bytes, *,
                now: datetime, require_new_permit: bool = False,
                evidence_artifacts: Mapping[str, bytes] | None = None) -> BoundAdmission:
    """Evaluate policy/replay once, then bind the original and effective objects.

    Malformed or mismatched preimages raise Invalid before core admission. A
    valid purchase that cannot meet the effective cap receives a denial.
    """
    need(type(require_new_permit) is bool, "SCHEMA_INVALID")
    need(isinstance(now, datetime) and now.tzinfo is not None and now.utcoffset() is not None,
         "INVALID_EVALUATION_TIME")
    original, request = decode(original_bytes), decode(admission_request_bytes)
    validate_operation(original)
    validate_admission(request, original)
    # The new entry accepts only the policy fields actually evaluated here.
    policy = decode(encode(verifier.policy))
    exact(policy, set(), {"policy_id", "policy_version", "policy_ref", "allowed_actions", "max_amount"})
    for key in ("policy_id", "policy_version", "policy_ref"):
        if key in policy:
            text(policy[key])
    if "max_amount" in policy:
        money(policy["max_amount"])
    if "allowed_actions" in policy:
        need(type(policy["allowed_actions"]) is list and bool(policy["allowed_actions"])
             and all(isinstance(action, str) and action for action in policy["allowed_actions"]), "SCHEMA_INVALID")
    refs = request["evidence_refs"]
    policy_refs = [ref for ref in refs if ref["type"] == "local_policy"]
    runtime_refs = [ref for ref in refs if ref["type"] == "runtime_attestation"]
    adapter = verifier.runtime_evidence_verifier
    boundary = verifier.dispatch_boundary
    store = verifier.state_store
    store_configuration = _store_configuration(verifier) if store is not None else None
    if boundary is not None:
        _dispatch_configuration(boundary, adapter)
    if adapter is None:
        need(len(refs) == len(policy_refs) == 1, "UNSUPPORTED_ADMISSION_EVIDENCE")
    else:
        # Configuring runtime verification makes the proof mandatory. Removing
        # it must not downgrade this call to local-policy-only admission.
        need(len(refs) == 2 and len(policy_refs) == len(runtime_refs) == 1,
             "RUNTIME_EVIDENCE_REQUIRED")
    policy_ref = policy_refs[0]
    need(policy_ref["uri"] == policy.get("policy_ref", "local")
         and policy_ref["media_type"] == "application/json"
         and policy_ref["digest"] == digest(encode(policy)), "LOCAL_POLICY_REFERENCE_MISMATCH")
    need(evidence_artifacts is None or isinstance(evidence_artifacts, Mapping), "INVALID_EVIDENCE_ARTIFACTS")
    artifacts = dict(evidence_artifacts) if evidence_artifacts is not None else {}
    expected_uris = {ref["uri"] for ref in runtime_refs}
    need(set(artifacts) == expected_uris, "EVIDENCE_ARTIFACT_SET_MISMATCH")
    runtime_raw = artifacts[runtime_refs[0]["uri"]] if runtime_refs else None
    runtime_verification = (_verify_runtime_evidence(adapter, runtime_refs[0], runtime_raw, request,
                            admission_request_bytes, original_bytes, now) if runtime_refs else None)
    with verifier._replay_transaction(request["request_id"]):
        # Detect configuration changes made during an adapter call before the
        # policy primitive can evaluate a policy different from the checked one.
        # Concurrent configuration writes remain unsupported by this API.
        need(_same_json(decode(encode(verifier.policy)), policy)
             and verifier.runtime_evidence_verifier is adapter and verifier.dispatch_boundary is boundary
             and verifier.state_store is store,
             "ADMISSION_CONFIGURATION_CHANGED")
        def issue() -> BoundAdmission:
            if store is not None:
                need(_store_configuration(verifier) == store_configuration, "STATE_CONFIGURATION_CHANGED")
            return _issue_bound(verifier, original, request, original_bytes, admission_request_bytes,
                now=now, require_new_permit=require_new_permit, runtime_raw=runtime_raw,
                runtime_verification=runtime_verification)

        if store is None:
            bound = issue()
        else:
            produced = []
            def produce():
                bound = issue()
                produced.append(bound)
                return _bound_values(bound), decode(bound.assessment)["decision_allows_immediate_execution"]
            _store_call(store.issue, request["request_id"], request["transaction_id"], store_configuration, produce)
            bound, = produced
        _register_dispatch(verifier, bound, policy, adapter, boundary, store_configuration=store_configuration)
        return bound


def _issue_bound(verifier: Any, original: dict, request: dict, original_bytes: bytes,
                 admission_request_bytes: bytes, *, now: datetime, require_new_permit: bool,
                 runtime_raw: bytes | None, runtime_verification: dict | None) -> BoundAdmission:
    """Construct and validate every returned artifact inside the replay transaction."""
    core_result = verifier._evaluate_policy(request, now=now)
    receipt = copy.deepcopy(core_result["admission_receipt"])
    decision = receipt["decision"]["outcome"]
    effective = None
    if decision in ("allow", "attenuate"):
        effective = copy.deepcopy(original)
        if decision == "attenuate":
            attenuation = receipt["attenuation"]
            effective["constraints"] = copy.deepcopy(attenuation["effective_constraints"])
            attenuation["original_request_hash"] = object_hash(original)
            attenuation["effective_request_hash"] = object_hash(effective)
            attenuation["changes"][0]["from"] = original["constraints"]["max_amount"]["value"]
            attenuation["require_new_permit"] = require_new_permit
            attenuation["mode"] = "require_new_permit" if require_new_permit else "narrow"
        if (not payload_within_constraints(original) or not payload_within_constraints(effective)
                or decision == "allow" and require_new_permit):
            receipt = verifier._make_receipt(request, now=now, outcome="deny", reason_codes=["POLICY_DENIED"])
            effective = None
    receipt["proof"] = {"format": "none"}
    for item in receipt["evidence"]:
        item["verification"] = ({"result": "verified", "checked_at": receipt["issued_at"],
                                 "method": "vate-local-policy-content-v1"}
                                if item["type"] == "local_policy" else
                                copy.deepcopy(runtime_verification["verification"]))
    if runtime_verification is not None and receipt["decision"]["outcome"] != "deny":
        deadline = runtime_verification["usable_until"]
        if core.parse_time(deadline) < core.parse_time(receipt["expires_at"]):
            receipt["expires_at"] = deadline
    receipt["request"]["constraints"] = copy.deepcopy(request["constraints"])
    binding = {"contract": CONTRACT, "preimage_profile": PREIMAGE_PROFILE,
               "canonicalization": CANONICALIZATION, "transformation_profile": TRANSFORMATION_PROFILE,
               "admission_request_ref": reference(admission_request_bytes), "original_ref": reference(original_bytes)}
    artifacts = {reference(raw)["uri"]: raw for raw in (original_bytes, admission_request_bytes)}
    effective_bytes = None
    if effective is not None:
        effective_bytes = encode(effective)
        binding["effective_ref"] = reference(effective_bytes)
        artifacts[binding["effective_ref"]["uri"]] = effective_bytes
        receipt["request"]["action_binding"] = action_binding(effective)
    receipt["request_binding"] = binding
    receipt_bytes = encode(receipt)
    assessment = assess_request_binding(receipt_bytes, artifacts,
                                        expected_admission_request_ref=reference(admission_request_bytes))
    need(assessment["binding_requirement_met"], "GENERATED_BINDING_FAILED")
    return BoundAdmission(original_bytes, admission_request_bytes, encode(core_result), receipt_bytes,
                          effective_bytes, encode(assessment), runtime_raw,
                          encode(runtime_verification) if runtime_verification is not None else None)
