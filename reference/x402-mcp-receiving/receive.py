"""Read a bounded local x402 SDK export; never call a tool or payment API."""
from __future__ import annotations

import argparse
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

PROFILE = "vate-local-x402-mcp-receiving-v1"
EXPORT = "local-x402-python-mcp-export-v1"
SDK = {"package": "x402", "version": "2.27.0",
       "source_commit": "2ef9f3872fbc0cfc93b1143f26ed668d13a7725e"}
MAX_BYTES = 1024 * 1024
MAX_DEPTH = 48
KEY = "x402/payment-response"
CANCEL_UNKNOWN = "Payment cancellation outcome unknown"
HEX = re.compile(r"[0-9a-f]{64}\Z")
NOT_ASSESSED = (
    "capture_authenticity_and_issuer", "operation_and_attempt_authenticity",
    "settlement_native_verification", "cancellation_or_refund_outcome",
    "tool_execution_outcome", "admission_linkage", "execution_permission",
    "retry_permission", "previous_result_identity",
)


class InputError(ValueError):
    def __init__(self, code, label):
        super().__init__(code)
        self.code, self.label = code, label


def need(condition, code, label):
    if not condition:
        raise InputError(code, label)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


try:
    _READER_SOURCE = Path(__file__).read_bytes()
    # A timestamp-valid cache can contain code from different source bytes.
    _READER_CODE_MATCH = compile(_READER_SOURCE, __file__, "exec", dont_inherit=True,
                                 optimize=sys.flags.optimize) == sys._getframe().f_code
except (OSError, ValueError, SyntaxError):
    _READER_SOURCE, _READER_CODE_MATCH = b"", False
READER_SHA256 = sha(_READER_SOURCE)


def encoded(value):
    """Local report encoding; not a protocol canonicalization or receipt digest."""
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True,
                       allow_nan=False) + "\n").encode("utf-8")


def raw_ref(raw):
    return {"digest_basis": "raw_file_sha256", "digest": {"alg": "sha-256", "value": sha(raw)},
            "byte_length": len(raw)}


def parse(raw, label):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "input_size_or_type", label)

    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate_json_key", label)
            result[key] = value
        return result

    def number(token):
        need(len(token) <= 128, "number_token_limit", label)
        return Decimal(token)  # Preserve numerical values; no binary64 rounding.

    def constant(_):
        raise InputError("non_json_number", label)

    def inspect(value, depth=0):
        need(depth <= MAX_DEPTH, "json_depth_limit", label)
        if type(value) is str:
            value.encode("utf-8", errors="strict")
        elif type(value) is dict:
            for key, item in value.items():
                inspect(key, depth + 1)
                inspect(item, depth + 1)
        elif type(value) is list:
            for item in value:
                inspect(item, depth + 1)
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs,
                           parse_int=number, parse_float=number, parse_constant=constant)
        inspect(value)
        need(type(value) is dict, "expected_json_object", label)
        return value
    except InputError:
        raise
    except (UnicodeError, ValueError, RecursionError, ArithmeticError):
        raise InputError("invalid_json", label) from None


def same(left, right):
    """Compare JSON values without conflating booleans and numbers."""
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(same(left[k], right[k]) for k in left)
    if type(left) is list:
        return len(left) == len(right) and all(same(a, b) for a, b in zip(left, right))
    return left == right


def shape(value, keys, label):
    need(type(value) is dict and set(value) == set(keys), "unsupported_object_shape", label)


def identifier(value, label):
    need(type(value) is str and 1 <= len(value) <= 256 and
         all(32 < ord(c) < 127 for c in value), "invalid_identifier", label)


def context(value, label):
    shape(value, ("server_id", "operation_id", "attempt_id"), label)
    for item in value.values():
        identifier(item, label)


def digest_field(value, label):
    need(type(value) is str and HEX.fullmatch(value) is not None, "invalid_digest", label)


def content(value, label):
    need(type(value) is list and len(value) <= 128, "content_shape_or_limit", label)
    for item in value:
        need(type(item) is dict and type(item.get("type")) is str, "invalid_content_block", label)
        if item["type"] == "text":
            need(type(item.get("text")) is str, "invalid_text_block", label)


def receipt_views(result):
    raw = result["raw_result"]
    candidates, diagnostics = [], []
    if result["payment_response"] is not None:
        candidates.append(("/result/payment_response", "sdk_summary", result["payment_response"]))
    for location, obj, surface in (
        ("/result/raw_result/meta", raw["meta"], "metadata"),
        ("/result/raw_result/structured_content", raw["structured_content"], "error_body"),
    ):
        if obj is not None and KEY in obj:
            candidates.append((location + "/x402~1payment-response", surface, obj[KEY]))
    for index, item in enumerate(raw["content"]):
        if item["type"] != "text":
            continue
        text = item["text"]
        # Plain error text is not a JSON envelope. JSON-looking but invalid text
        # remains raw evidence and an explicit diagnostic, never a receipt.
        if not text.lstrip().startswith("{"):
            continue
        pointer = f"/result/raw_result/content/{index}/text"
        try:
            obj = parse(text.encode("utf-8"), "embedded_text")
        except InputError:
            diagnostics.append({"source_pointer": pointer, "reason": "unreadable_json_text"})
            continue
        if KEY in obj:
            candidates.append((pointer, "error_body_json_text", obj[KEY]))
    unique, observations = [], []
    for pointer, surface, obj in candidates:
        recognized = (type(obj) is dict and type(obj.get("success")) is bool
                      and type(obj.get("transaction")) is str
                      and type(obj.get("network")) is str and bool(obj["network"]))
        if recognized:
            for key in ("amount", "payer", "errorReason", "errorMessage"):
                if key in obj and obj[key] is not None and type(obj[key]) is not str:
                    recognized = False
        if not any(same(obj, previous) for previous in unique):
            unique.append(obj)
        body = surface.startswith("error_body")
        observations.append({
            "source_pointer": pointer, "surface": surface,
            "shape": "recognized_header_subset" if recognized else "unrecognized",
            "reported_success": obj["success"] if recognized else None,
            "header_subset_location_match": bool(recognized and
                (surface == "metadata" or (body and raw["is_error"] and obj["success"] is False))),
        })
    return {"sdk_summary_present": result["payment_response"] is not None,
            "views": observations, "distinct_values": len(unique), "diagnostics": diagnostics,
            "selection": "none_all_views_retained"}


def assess(*, selection: bytes, request: bytes, capture: bytes):
    need(_READER_CODE_MATCH, "reader_source_mismatch", "reader")
    try:
        current_source = Path(__file__).read_bytes()
    except (OSError, ValueError):
        raise InputError("reader_source_changed", "reader") from None
    need(sha(current_source) == READER_SHA256, "reader_source_changed", "reader")
    inputs = {"selection": selection, "request": request, "capture": capture}
    s, q, c = (parse(inputs[name], name) for name in ("selection", "request", "capture"))
    shape(s, ("profile", "context", "request_sha256", "capture_sha256"), "selection")
    context(s["context"], "selection")
    for field in ("request_sha256", "capture_sha256"):
        digest_field(s[field], "selection")
    report = {"document_type": "x402_mcp_receiving_report", "profile": PROFILE,
              "reader_sha256": READER_SHA256, "source_profile": dict(SDK),
              "inputs": {k: raw_ref(v) for k, v in inputs.items()}, "status": "not_assessed",
              "checks": {k: {"status": "not_assessed"} for k in NOT_ASSESSED},
              "observations": None, "is_execution_ticket": False,
              "reader_action": "retain_and_inspect_only"}
    matches = {name: sha(inputs[name]) == s[name + "_sha256"] for name in ("request", "capture")}
    report["checks"]["receiver_selected_bytes"] = {
        "status": "matched" if all(matches.values()) else "mismatched", "matches": matches,
        "scope": "receiver_selected_raw_bytes_only"}
    if s["profile"] != PROFILE:
        report["reason"] = "unsupported_receiver_profile"
        return report
    if not all(matches.values()):
        report["reason"] = "receiver_selected_bytes_mismatch"
        return report
    shape(q, ("name", "arguments"), "request")
    identifier(q["name"], "request")
    need(type(q["arguments"]) is dict, "arguments_not_object", "request")
    shape(c, ("export_profile", "sdk", "client_kind", "origin", "context", "request_sha256",
              "carrier", "exception_type", "result", "local_observations"), "capture")
    context(c["context"], "capture")
    digest_field(c["request_sha256"], "capture")
    if c["export_profile"] != EXPORT or c["sdk"] != SDK:
        report["reason"] = "unsupported_export_or_sdk_pin"
        return report
    binding = c["context"] == s["context"] and c["request_sha256"] == sha(request)
    report["checks"]["declared_context"] = {
        "status": "matched" if binding else "mismatched", "scope": "exporter_labels_only"}
    if not binding:
        report["reason"] = "request_or_declared_context_mismatch"
        return report
    need(c["origin"] in ("synthetic_fixture", "retained_sdk_export", "unknown"), "capture_origin", "capture")
    need(c["client_kind"] in ("sync", "async", "session"), "client_kind", "capture")
    need(c["carrier"] in ("return", "exception.result", "exception.mcp_result"), "result_carrier", "capture")
    if c["carrier"] == "return":
        need(c["exception_type"] is None, "carrier_exception_conflict", "capture")
    else:
        identifier(c["exception_type"], "capture")
    result = c["result"]
    shape(result, ("content", "is_error", "payment_made", "payment_response", "raw_result"), "result")
    content(result["content"], "result")
    need(type(result["is_error"]) is bool and type(result["payment_made"]) is bool, "result_flags", "result")
    raw = result["raw_result"]
    shape(raw, ("content", "is_error", "meta", "structured_content"), "raw_result")
    content(raw["content"], "raw_result")
    need(type(raw["is_error"]) is bool and type(raw["meta"]) is dict and
         (raw["structured_content"] is None or type(raw["structured_content"]) is dict),
         "raw_result_shape", "raw_result")
    local = c["local_observations"]
    shape(local, ("payment_phase", "reapproval", "client_recovered"), "local_observations")
    need(local["payment_phase"] in ("before_handler", "unknown") and
         local["reapproval"] in ("denied", "not_recorded") and
         (local["client_recovered"] is None or type(local["client_recovered"]) is bool),
         "local_observation_shape", "local_observations")
    markers = [f"/result/raw_result/content/{i}/text" for i, item in enumerate(raw["content"])
               if item["type"] == "text" and item["text"] == CANCEL_UNKNOWN]
    receipts = receipt_views(result)
    report.update(status="inspected", reason=None, observations={
        "origin_claim": c["origin"], "client_kind_claim": c["client_kind"],
        "result_carrier": c["carrier"], "result_retained_in_capture": True,
        "sdk_payment_made_claim": result["payment_made"],
        "tool_result": {"sdk_is_error": result["is_error"], "raw_is_error": raw["is_error"],
                        "content_views_equal": same(result["content"], raw["content"])},
        "cancellation": {"observation": "reported_unknown" if markers else "not_reported",
                         "source_pointers": markers, "basis": "unverified_error_text"},
        "receipts": receipts,
        "exporter_claims": {**local, "basis": "unverified_local_observations"},
        "claimed_upfront_success_with_unknown_cancellation": bool(markers and
            local["payment_phase"] == "before_handler" and any(
                view["surface"] == "metadata" and view["reported_success"] is True
                for view in receipts["views"])),
    })
    return report


def read_file(path, label):
    fd = None
    try:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except (TypeError, ValueError):  # Includes UnicodeError from path encoding.
            raise InputError("invalid_file_path", label) from None
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode), "not_regular_file", label)
        need(before.st_size <= MAX_BYTES, "input_size_or_type", label)
        with os.fdopen(fd, "rb") as stream:
            fd = None
            raw = stream.read(MAX_BYTES + 1)
            after = os.fstat(stream.fileno())
        need(len(raw) <= MAX_BYTES, "input_size_or_type", label)
        need((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "input_changed_during_read", label)
        return raw
    except OSError:
        raise InputError("unreadable_or_linked_file", label) from None
    finally:
        if fd is not None:
            os.close(fd)


def save_bundle(output, inputs, report):
    """Create one new bundle; a final manifest marks a completed write."""
    fd = None
    try:
        try:
            os.mkdir(output, 0o700)
            fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except (TypeError, ValueError):
            raise InputError("invalid_file_path", "output") from None
        files = {name + ".json": raw for name, raw in inputs.items()}
        files["report.json"] = encoded(report)
        manifest = {"profile": PROFILE, "reader_sha256": report["reader_sha256"],
                    "files": {name: raw_ref(raw) for name, raw in files.items()},
                    "is_execution_ticket": False}
        files["MANIFEST.json"] = encoded(manifest)
        for name, raw in files.items():
            handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(handle, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
    except FileExistsError:
        raise InputError("output_exists", "output") from None
    except OSError:
        raise InputError("output_write_failed", "output") from None
    finally:
        if fd is not None:
            os.close(fd)


def receive_files(*, selection, request, capture, output):
    inputs = {k: read_file(p, k) for k, p in (
        ("selection", selection), ("request", request), ("capture", capture))}
    report = assess(**inputs)
    save_bundle(output, inputs, report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("selection", "request", "capture"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = receive_files(selection=args.selection, request=args.request,
                               capture=args.capture, output=args.out)
        sys.stdout.buffer.write(encoded(report))
        return 0
    except InputError as exc:
        sys.stdout.buffer.write(encoded({"status": "input_error", "reason": exc.code,
                                         "input": exc.label, "is_execution_ticket": False}))
        return 64
    except Exception:
        sys.stdout.buffer.write(encoded({"status": "internal_error", "is_execution_ticket": False}))
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
