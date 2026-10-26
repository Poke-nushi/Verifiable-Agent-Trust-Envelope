#!/usr/bin/env python3
"""Assess two locally supplied receipts with pinned, existing VATE checks."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
from itertools import chain
from decimal import Decimal, InvalidOperation
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker

HERE = Path(__file__).resolve().parent
ROOT = next((parent for parent in HERE.parents
             if (parent / "reference/vate-verifier-core/vate_verifier_core.py").is_file()), None)
MAX_INPUT_BYTES = 1024 * 1024  # Local example bound, not a VATE requirement.
NOT_CHECKED = [
    "signatures_and_issuer_authority",
    "request_hash_preimages",
    "constraints_other_than_reported_max_amount_tool_allowlist_and_policy_violations",
    "completeness_of_reported_side_effects",
    "actual_or_independently_observed_execution",
    "current_permission_to_execute",
]


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON property")
        value[key] = item
    return value


def finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("number outside this example's finite numeric range")
    # Keep the existing JSON/digest representation, but do not accept a number
    # whose decimal value changes before the reference checks see it.
    try:
        unchanged = Decimal(text) == Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError("number outside this example's decimal range") from exc
    if not unchanged:
        raise ValueError("JSON number would lose decimal precision; use a decimal string for money")
    return value


def reject_constant(text: str) -> None:
    raise ValueError("non-JSON numeric constant")


def parse_receipt(raw: bytes) -> dict:
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("input exceeds the local 1 MiB bound")
    value = json.loads(raw, object_pairs_hook=unique_object,
                       parse_float=finite_float, parse_constant=reject_constant)
    if not isinstance(value, dict):
        raise ValueError("receipt must be a JSON object")
    return value


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module



# Local diagnostic presentation limits; receipt/schema semantics are unchanged.
DIAGNOSTIC_LIMITS = {"items": 32, "detail_characters": 512, "path_components": 16,
                     "path_component_characters": 128, "list_json_bytes": 32768}


class DiagnosticBudget:
    """Collect incrementally; never count omitted errors by exhausting a source."""
    def __init__(self):
        self.items = []
        self.json_bytes = 2  # The list's opening and closing brackets.
        self.found = False
        self.text_omitted = False
        self.collection_stopped = False

    def _text(self, value, limit):
        if len(value) > limit:
            self.text_omitted = True
            return value[:limit]
        return value

    def add(self, value):
        self.found = True  # Evidence of invalidity survives a full display budget.
        if self.collection_stopped:
            return False
        if isinstance(value, dict):
            value = dict(value)
            if "detail" in value:
                old = value["detail"]
                value["detail"] = self._text(old, DIAGNOSTIC_LIMITS["detail_characters"])
                if old != value["detail"]:
                    value["detail_truncated"] = True
            if "path" in value:
                path = value["path"]
                kept = [self._text(p, DIAGNOSTIC_LIMITS["path_component_characters"])
                        if isinstance(p, str) else p
                        for p in path[:DIAGNOSTIC_LIMITS["path_components"]]]
                if kept != path:
                    self.text_omitted = True
                    value["path_truncated"] = True
                value["path"] = kept
        else:
            value = self._text(value, DIAGNOSTIC_LIMITS["detail_characters"])
        size = len(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii"))
        next_size = self.json_bytes + bool(self.items) + size
        if next_size > DIAGNOSTIC_LIMITS["list_json_bytes"]:
            self.collection_stopped = True
            return False
        self.items.append(value)
        self.json_bytes = next_size
        if len(self.items) >= DIAGNOSTIC_LIMITS["items"] or self.json_bytes >= DIAGNOSTIC_LIMITS["list_json_bytes"]:
            self.collection_stopped = True
        return not self.collection_stopped

    def consume(self, values):
        if self.collection_stopped:
            return
        for value in values:
            if not self.add(value):
                break

    def attach(self, result, field):
        result[field] = self.items
        if self.text_omitted or self.collection_stopped:
            result.setdefault("diagnostic_truncation", {})[field] = {
                "text_omitted": self.text_omitted,
                "collection_stopped_at_limit": self.collection_stopped,
                "total_errors": None,
                "limits": dict(DIAGNOSTIC_LIMITS),
            }


class RecipientExample:
    def __init__(self) -> None:
        if ROOT is None:
            raise ValueError("keep this example inside the supplied VATE repository tree")
        self.sources = json.loads((HERE / "SOURCE-PINS.json").read_text())
        for relative, expected in self.sources["files"].items():
            if digest((ROOT / relative).read_bytes()) != expected:
                raise ValueError("reference source changed: " + relative)
        self.core = load_module("local_recipient_core", ROOT / "reference/vate-verifier-core/vate_verifier_core.py")
        self.runner = load_module("local_recipient_runner", ROOT / "scripts/vate_conformance.py")
        self.verifier = self.core.VateVerifier(verifier_id="urn:vate:local-receipt-review")
        format_checker = FormatChecker()

        # jsonschema's optional date-time plugin is not part of requirements-dev.
        # Use the same explicit checker as the repository's strict validation.
        @format_checker.checks("date-time")
        def is_supported_rfc3339_date_time(value: object) -> bool:
            return self.runner.try_parse_time(value) is not None

        self.validators = {
            role: Draft202012Validator(
                json.loads((ROOT / f"schemas/{schema}.schema.json").read_text()),
                format_checker=format_checker,
            )
            for role, schema in (("admission", "admission-receipt"), ("post", "post-execution-receipt"))
        }
        definitions = self.validators["admission"].schema["$defs"]
        self.amount_validator = Draft202012Validator(definitions["moneyAmount"])
        tool_schema = definitions["effectiveConstraints"]["properties"]["tool_allowlist"]
        self.tool_allowlist_validator = Draft202012Validator(tool_schema)
        self.tool_name_validator = Draft202012Validator(tool_schema["items"])

    def reference_input_issues(self, admission: dict, post: dict):
        """Local preconditions for values this example asks the core to interpret."""

        def validate(role, path, value, validator):
            for error in validator.iter_errors(value):
                yield ({"input": role, "kind": "semantic_input_invalid",
                               "path": path + list(error.absolute_path), "detail": error.message})

        def validate_amount(role, path, amount):
            yield from validate(role, path, amount, self.amount_validator)
            if not isinstance(amount, dict):
                return
            for failure in self.runner.decimal_amount_failures(amount.get("value"), label="amount.value"):
                yield ({"input": role, "kind": "semantic_input_invalid",
                               "path": path + ["value"], "detail": failure})
            if self.core.safe_decimal_amount(amount.get("value")) is None:
                yield ({"input": role, "kind": "unsupported_amount",
                               "path": path + ["value"],
                               "detail": "amount exceeds reference-core input bounds (64 characters, 18 integer digits, 8 fractional digits)"})
            # Match the existing runner's three-letter currency condition as well
            # as its schema: a regex '$' alone may accept a final newline.
            currency = amount.get("currency")
            if isinstance(currency, str) and (len(currency) != 3 or not all("A" <= c <= "Z" for c in currency)):
                yield ({"input": role, "kind": "semantic_input_invalid",
                               "path": path + ["currency"], "detail": "currency must be a 3-letter uppercase code"})

        constraints = self.core.admitted_effective_constraints(admission)
        constraint_path = (["attenuation", "effective_constraints"] if "attenuation" in admission
                           else ["request", "constraints"])
        # Issued receipts use canonical names. Do not silently drop an old
        # constraint or normalize the supplied original at the recipient.
        for legacy, canonical in (("max_amount_usd", "max_amount"), ("resource", "target_resource")):
            if legacy in constraints:
                yield ({"input": "admission", "kind": "semantic_input_invalid",
                               "path": constraint_path + [legacy],
                               "detail": f"issued AL2 receipt contains legacy constraint {legacy}; expected {canonical}"})
        if isinstance(constraints.get("approval"), str):
            yield ({"input": "admission", "kind": "semantic_input_invalid",
                           "path": constraint_path + ["approval"],
                           "detail": "issued AL2 receipt contains string-valued approval; expected an approval object"})
        if "max_amount" in constraints:
            yield from validate_amount("admission", constraint_path + ["max_amount"], constraints["max_amount"])
            for index, effect in enumerate(post["result"]["side_effects"]):
                if "amount" in effect:
                    yield from validate_amount("post", ["result", "side_effects", index, "amount"], effect["amount"])
        if "tool_allowlist" in constraints:
            yield from validate("admission", constraint_path + ["tool_allowlist"],
                     constraints["tool_allowlist"], self.tool_allowlist_validator)
            for index, effect in enumerate(post["result"]["side_effects"]):
                # These aliases and their precedence come from the pinned reference core.
                aliases = [key for key in ("tool", "tool_id", "name") if key in effect]
                if aliases:
                    selected = next((key for key in aliases if effect[key]), aliases[0])
                    yield from validate("post", ["result", "side_effects", index, selected],
                             effect[selected], self.tool_name_validator)
        return

    def declared_field_issues(self, role: str, receipt: dict):
        """Check known typed fields, leaving extension/annotation objects alone."""
        hashes = ([["request", "input_hash"], ["attenuation", "original_request_hash"],
                   ["attenuation", "effective_request_hash"]] if role == "admission" else
                  [["execution", "effective_request_hash"], ["result", "output_hash"]])
        descriptors = (chain([["request", "action_binding", "digest"],
                          ["policy", "policy_snapshot", "digest"]],
                         (["evidence", i, "digest"] for i in range(len(receipt.get("evidence", [])))))
                       if role == "admission" else
                       [["admission", "digest"], ["execution", "action_binding", "digest"]])
        times = ([["issued_at"], ["expires_at"]] if role == "admission" else
                 [["issued_at"], ["execution", "started_at"], ["execution", "finished_at"]])
        for paths, check, detail in (
            (hashes, self.core.is_profile_hash, "expected an exact VATE profile hash"),
            (descriptors, self.core.is_digest_descriptor, "expected an exact SHA-256 digest descriptor"),
            (times, lambda value: self.core.safe_parse_time(value) is not None,
             "expected a supported RFC3339 timestamp with at most six fractional-second digits"),
        ):
            for path in paths:
                value = receipt
                try:
                    for key in path:
                        value = value[key]
                except (KeyError, IndexError, TypeError):
                    continue  # Required fields and shapes were checked by the schema.
                if not check(value):
                    yield ({"input": role, "kind": "semantic_input_invalid",
                                   "path": path, "detail": detail})
        return

    def assess(self, admission_raw: bytes | None, post_raw: bytes | None) -> dict:
        """Missing bytes mean not supplied, never that execution did not occur."""
        result = {
            "record_linkage": "not_assessed",
            "assessment_scope": "receipt relationships and reference-core constraints only",
            "source_files": self.sources["files"],
            "digest_basis": "VATE v0.3 fixture json-sorted-no-whitespace",
            "inputs": {role: {"supplied": raw is not None,
                              "raw_file_sha256": digest(raw) if raw is not None else None}
                       for role, raw in (("admission", admission_raw), ("post", post_raw))},
            "input_issues": [],
            "linkage_checks_run": [],
            "core_result": None,
            "side_effect_check_failures": [],
            "not_checked": list(NOT_CHECKED),
        }
        issues = DiagnosticBudget()
        receipts = {}

        def semantic_issues(role, receipt):
            shape_check = (self.runner.iter_generated_admission_receipt_shape_failures
                           if role == "admission" else self.runner.generated_post_execution_receipt_shape_failures)
            yield from shape_check(receipt, role)
            yield from self.runner.generated_receipt_identity_failures(
                receipt, role, "admission" if role == "admission" else "post_execution")
            if role == "admission":
                yield from self.runner.reason_code_order_failures(
                    receipt["decision"]["reason_codes"], receipt["decision"]["outcome"], label="admission.decision")
                yield from self.runner.iter_evaluate_evidence_vocabulary_checks(None, receipt)

        for role, raw in (("admission", admission_raw), ("post", post_raw)):
            if issues.collection_stopped:
                break  # Both original hashes are already retained above.
            if raw is None:
                issues.add({"input": role, "kind": "not_supplied"})
                continue
            try:
                receipt = parse_receipt(raw)
                schema_invalid = False
                for error in self.validators[role].iter_errors(receipt):
                    schema_invalid = True
                    if not issues.add({"input": role, "kind": "schema_invalid",
                                       "path": list(error.absolute_path), "detail": error.message}):
                        break
            except (ValueError, UnicodeError, RecursionError) as exc:
                issues.add({"input": role, "kind": "invalid_input", "detail": str(exc)})
                continue
            if schema_invalid:
                continue
            semantic_invalid = False
            for error in semantic_issues(role, receipt):
                semantic_invalid = True
                if not issues.add({"input": role, "kind": "semantic_input_invalid", "detail": error}):
                    break
            if semantic_invalid:
                continue
            issues.consume(self.declared_field_issues(role, receipt))
            receipts[role] = receipt
        if issues.found:
            issues.attach(result, "input_issues")
            return result
        issues.consume(self.reference_input_issues(receipts["admission"], receipts["post"]))
        if issues.found:
            issues.attach(result, "input_issues")
            return result
        result["linkage_checks_run"] = [
            "receipt_id_and_admission_object_digest",
            "admission_decision_and_fresh_permit_requirement",
            "transaction_runtime_and_effective_request_hash_fields",
            "execution_times_within_admission_window",
            "reference_reported_constraint_and_policy_validation",
        ]
        result["core_result"] = self.verifier.validate_post_execution_linkage(receipts["admission"], receipts["post"])
        constraints = self.core.admitted_effective_constraints(receipts["admission"])
        side_effects = DiagnosticBudget()
        if "max_amount" in constraints:
            side_effects.consume(self.runner.iter_post_execution_side_effect_failures(
                receipts["admission"], receipts["post"]))
            side_effects.attach(result, "side_effect_check_failures")
            result["linkage_checks_run"].append("runner_reported_amount_validation")
        else:
            result["not_checked"].append("reported_amounts_without_max_amount_constraint")
        if "tool_allowlist" not in constraints:
            result["not_checked"].append("reported_tools_without_tool_allowlist_constraint")
        matched = result["core_result"]["outcome"] == "success" and not side_effects.found
        result["record_linkage"] = "matched" if matched else "mismatch"
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admission", type=Path, help="Local admission JSON; omit if not supplied")
    parser.add_argument("--post", type=Path, help="Local post-execution JSON; omit if not supplied")
    args = parser.parse_args()
    try:
        reviewer = RecipientExample()
        raw, io_issues, file_status = {}, [], {}
        for role, path in (("admission", args.admission), ("post", args.post)):
            raw[role] = None
            file_status[role] = "not_specified"
            if path is not None:
                try:
                    if not path.is_file():
                        raise OSError("expected a regular local file")
                    with path.open("rb") as handle:
                        raw[role] = handle.read(MAX_INPUT_BYTES + 1)
                    if len(raw[role]) > MAX_INPUT_BYTES:
                        raw[role] = None
                        file_status[role] = "too_large"
                        io_issues.append({"input": role, "kind": "input_too_large", "detail": "local 1 MiB bound"})
                    else:
                        file_status[role] = "read"
                except OSError as exc:
                    raw[role] = None
                    file_status[role] = "unreadable"
                    io_issues.append({"input": role, "kind": "unreadable_file", "detail": str(exc)})
        result = reviewer.assess(raw["admission"], raw["post"])
        for role, status in file_status.items():
            result["inputs"][role]["file_status"] = status
        unreadable = {issue["input"] for issue in io_issues}
        previous = result.get("diagnostic_truncation", {}).get("input_issues")
        issues = DiagnosticBudget()
        issues.consume(chain((issue for issue in result["input_issues"] if issue["input"] not in unreadable), io_issues))
        issues.attach(result, "input_issues")
        if previous:
            current = result.setdefault("diagnostic_truncation", {}).get("input_issues", {})
            result["diagnostic_truncation"]["input_issues"] = {
                **previous,
                "text_omitted": previous["text_omitted"] or current.get("text_omitted", False),
                "collection_stopped_at_limit": previous["collection_stopped_at_limit"] or current.get("collection_stopped_at_limit", False),
            }
    except (OSError, ValueError) as exc:
        print(json.dumps({"record_linkage": "not_assessed", "tool_error": str(exc)}))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return {"matched": 0, "mismatch": 1, "not_assessed": 2}[result["record_linkage"]]


if __name__ == "__main__":
    raise SystemExit(main())
