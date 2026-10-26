"""Shared byte and file contracts for this local demonstration, not VATE core."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
# Required provenance snapshot of this reference package, including tests/docs;
# this is not an inventory of Python runtime imports or producer-selected files.
REQUIRED_SOURCE_FILES = (
    "reference/execution-evidence-demo/CASE-CONTRACT.md",
    "reference/execution-evidence-demo/README.md",
    "reference/execution-evidence-demo/admission.py",
    "reference/execution-evidence-demo/demo_contract.py",
    "reference/execution-evidence-demo/provider.py",
    "reference/execution-evidence-demo/run_demo.py",
    "reference/execution-evidence-demo/test_execution_demo.py",
    "reference/execution-evidence-demo/verify_evidence.py",
    "reference/vate-verifier-core/vate_verifier_core.py",
    "schemas/admission-receipt.schema.json",
    "schemas/admission-request.schema.json",
    "schemas/post-execution-receipt.schema.json",
)
CONTRACT = "vate-demo-file-set-v1"
ACTION = "demo.create_file_set"
RUNTIME = "urn:vate:demo:file-provider"
VERIFIER = "urn:vate:demo:admission-verifier"
BYTE_BASIS = "vate-v0.3-fixture-json;ascii-escaped;sorted;compact;no-floats"
MAX_ARTIFACT = 2 * 1024 * 1024
MAX_SAFE_INTEGER = 9007199254740991
MAX_OUTPUT_BYTES = 4096
ID_RE = re.compile(r"[a-z][a-z0-9-]{0,79}\Z")
FILE_RE = re.compile(r"[a-z][a-z0-9_-]{0,63}\.txt\Z")


class Invalid(ValueError):
    """A required demo contract or observation did not hold."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise Invalid(message)


def load_core() -> Any:
    path = ROOT / "reference/vate-verifier-core/vate_verifier_core.py"
    spec = importlib.util.spec_from_file_location("execution_demo_vate_core", path)
    if spec is None or spec.loader is None:
        raise Invalid("verifier core unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


core = load_core()


def encode(value: Any) -> bytes:
    # The accepted demo domain has strings, booleans, null and safe integers.
    try:
        return json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
    except RecursionError as exc:
        raise Invalid("JSON nesting exceeds this runtime's encoding limit") from exc


def decode(raw: bytes) -> Any:
    need(len(raw) <= MAX_ARTIFACT, "artifact exceeds demo size bound")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            need(key not in result, "duplicate JSON member")
            result[key] = value
        return result

    def no_float(_: str) -> Any:
        raise Invalid("floating-point JSON tokens are outside the demo contract")

    def integer(value: str) -> int:
        number = int(value)
        need(abs(number) <= MAX_SAFE_INTEGER, "unsafe JSON integer")
        return number

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_float=no_float,
                          parse_constant=no_float, parse_int=integer)
    except RecursionError as exc:
        raise Invalid("JSON nesting exceeds this runtime's decoding limit") from exc


def digest(raw: bytes) -> dict[str, str]:
    return {"alg": "sha-256", "value": hashlib.sha256(raw).hexdigest()}


def object_hash(value: Any) -> str:
    return "sha-256:" + digest(encode(value))["value"]


def action_binding(operation: dict[str, Any]) -> dict[str, Any]:
    return {"type": "profile_defined_digest", "preimage_profile": CONTRACT,
            "canonicalization": BYTE_BASIS, "digest": digest(encode(operation))}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def time_value(value: str) -> datetime:
    need(isinstance(value, str) and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value) is not None,
        "invalid demo UTC timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def exact(value: Any, fields: set[str], label: str) -> None:
    need(isinstance(value, dict) and set(value) == fields, f"{label}: missing or unknown field")


def identifier(value: Any) -> None:
    need(isinstance(value, str) and ID_RE.fullmatch(value) is not None, "invalid local identifier")


def check_child_pid(pid: Any, controller_pid: int, label: str) -> None:
    check_integer(pid, f"{label} PID", minimum=1)
    need(pid != controller_pid, f"{label} PID equals controller PID")


def check_integer(value: Any, label: str, *, minimum: int = 0, maximum: int = MAX_SAFE_INTEGER) -> None:
    need(type(value) is int and minimum <= value <= maximum, f"invalid {label}: expected an integer in {minimum}..{maximum}")


def check_size(value: Any, label: str, *, maximum: int = MAX_ARTIFACT) -> None:
    check_integer(value, label + " size", maximum=maximum)


def check_digest(value: Any, label: str) -> None:
    exact(value, {"alg", "value"}, label + " digest")
    need(value["alg"] == "sha-256", label + " digest algorithm must be sha-256")
    need(isinstance(value["value"], str) and re.fullmatch(r"[0-9a-f]{64}", value["value"]) is not None,
         label + " digest value must be 64 lowercase hexadecimal characters")


def check_output_inventory(files: Any, label: str) -> None:
    need(isinstance(files, list), label + " must be a list")
    names = []
    for entry in files:
        exact(entry, {"name", "size", "digest"}, label + " entry")
        need(isinstance(entry["name"], str) and FILE_RE.fullmatch(entry["name"]) is not None,
             label + " contains an invalid file name")
        names.append(entry["name"])
        check_size(entry["size"], label, maximum=MAX_OUTPUT_BYTES)
        check_digest(entry["digest"], label)
    need(names == sorted(set(names)), label + " file names must be unique and sorted")


def check_native_structure(native: Any, label: str = "native") -> None:
    """The same local native format applies to current and retained executions."""
    exact(native, {"contract", "operation_key", "authorization_key", "attempt_key", "runtime", "pid", "resource",
                   "received_digest", "input_hash", "admission_digest", "started_at", "finished_at", "outcome", "files"}, label)
    need(native["contract"] == CONTRACT and native["runtime"] == RUNTIME, label + " contract/runtime mismatch")
    for key in ("operation_key", "authorization_key", "attempt_key"):
        identifier(native[key])
    need(isinstance(native["resource"], str), label + " resource must be a string")
    check_integer(native["pid"], label + " PID", minimum=1)
    for key in ("started_at", "finished_at"):
        time_value(native[key])
    for key in ("received_digest", "admission_digest"):
        check_digest(native[key], label + " " + key)
    need(isinstance(native["input_hash"], str) and re.fullmatch(r"sha-256:[0-9a-f]{64}", native["input_hash"]) is not None,
         label + " input_hash must be a sha-256 hash string")
    check_output_inventory(native["files"], label + " files")
    need(1 <= len(native["files"]) <= 8, label + " files must contain 1..8 entries")
    need(isinstance(native["outcome"], str) and native["outcome"] == "success", label + " outcome must be success")


def check_snapshot(snapshot: Any, label: str) -> None:
    exact(snapshot, {"provider", "sandbox"}, label)
    for namespace, entries in snapshot.items():
        need(isinstance(entries, dict), label + " namespace must be an object")
        for entry in entries.values():
            exact(entry, {"size", "digest"}, label + " entry")
            check_size(entry["size"], label + " " + namespace,
                       maximum=MAX_OUTPUT_BYTES if namespace == "sandbox" else MAX_ARTIFACT)


def check_transport_record(transport: Any, command: str, raw: bytes, stderr: bytes, controller_pid: int) -> None:
    exact(transport, {"command", "returned_at", "returncode", "pid", "stdout_digest", "stderr_digest"}, "transport")
    time_value(transport["returned_at"])
    code = transport["returncode"]
    if code is not None:
        check_integer(code, "transport returncode", minimum=-MAX_SAFE_INTEGER)
    if code is not None or transport["pid"] is not None:
        check_child_pid(transport["pid"], controller_pid, f"{command} transport")
    need(transport["command"] == command and transport["stdout_digest"] == digest(raw)
         and transport["stderr_digest"] == digest(stderr), "transport observation mismatch")


def check_execute_response(raw: bytes, transport: dict, native_raw: bytes) -> None:
    """Response acceptance, separate from process exit and native validity."""
    need(transport["returncode"] == 0 and bool(raw), "no usable provider response")
    need(raw == native_raw, "response/native original mismatch")


def check_query_response(raw: bytes, transport: dict, keys: dict, *, received: bytes,
                         native_raw: bytes, files: list) -> None:
    """A query must return the original evidence and the current file inventory.

    Callers separately validate transport records and native originals. A failure
    here rejects only the response; it does not erase or validate those originals.
    """
    need(transport["returncode"] == 0, "query did not return usable evidence")
    try:
        reply = decode(raw)
    except ValueError as exc:
        raise Invalid("query response is not contract JSON") from exc
    need(isinstance(reply, dict), "query response must be an object")
    need(reply.get("status") == "observed", "provider evidence unavailable; outcome remains unknown")
    exact(reply, {"status", "operation_key", "attempt_key", "native_base64", "received_base64", "current_files"},
          "query response")
    for key in ("operation_key", "attempt_key"):
        need(reply[key] == keys[key], f"query {key} mismatch")
    try:
        native_returned = base64.b64decode(reply["native_base64"], validate=True)
        received_returned = base64.b64decode(reply["received_base64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise Invalid("query returned invalid base64 evidence") from exc
    need(received_returned == received, "query received bytes mismatch")
    need(native_returned == native_raw, "response/native original mismatch")
    check_output_inventory(reply["current_files"], "query current_files")
    need(reply["current_files"] == files, "query file inventory mismatch")


def check_execution_pids(native_pid: Any, transport_pid: Any, journal: list,
                         controller_pid: int) -> None:
    check_child_pid(native_pid, controller_pid, "native")
    check_child_pid(transport_pid, controller_pid, "execute transport")
    need(native_pid == transport_pid, "provider process observation mismatch")
    need(len(journal) == 2, "provider invocation journal mismatch")
    for event in journal:
        check_child_pid(event["pid"], controller_pid, "journal")
        need(event["pid"] == native_pid, "journal PID differs from execute PID")


def validate_operation(operation: Any, resource: str) -> None:
    exact(operation, {"contract", "operation_key", "action", "target"}, "operation")
    need(operation["contract"] == CONTRACT and operation["action"] == ACTION, "unsupported operation")
    identifier(operation["operation_key"])
    exact(operation["target"], {"resource", "files"}, "target")
    need(operation["target"]["resource"] == resource, "sandbox resource mismatch")
    files = operation["target"]["files"]
    need(isinstance(files, list) and 1 <= len(files) <= 8, "file set must contain 1..8 files")
    names = []
    for item in files:
        exact(item, {"name", "text"}, "file")
        name = item["name"]
        need(isinstance(name, str) and FILE_RE.fullmatch(name) is not None, "unsafe file name")
        need(isinstance(item["text"], str), "file text must be a string")
        need(len(item["text"].encode("utf-8")) <= MAX_OUTPUT_BYTES, "file text exceeds 4096 UTF-8 bytes")
        names.append(name)
    need(names == sorted(set(names)), "file names must be unique and sorted")


def read_raw(path: Path) -> bytes:
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, f"not a single regular file: {path.name}")
    need(info.st_size <= MAX_ARTIFACT, f"artifact too large: {path.name}")
    return path.read_bytes()


def source_digests() -> dict[str, dict[str, str]]:
    """Read every required source; missing or unsafe files cannot shrink the set."""
    return {name: digest(read_raw(ROOT / name)) for name in REQUIRED_SOURCE_FILES}


def read_json(path: Path) -> Any:
    return decode(read_raw(path))


def write_raw(path: Path, raw: bytes) -> None:
    # Run directories are newly allocated. Evidence snapshots are never replaced.
    with path.open("xb") as handle:
        handle.write(raw)


def write_json(path: Path, value: Any) -> None:
    write_raw(path, encode(value))


def tree(path: Path, *, flat: bool = False) -> dict[str, Any]:
    info = path.lstat()  # Missing evidence stays FileNotFoundError, distinct from an unsafe object.
    need(not stat.S_ISLNK(info.st_mode), f"symlink in evidence: {path.name}")
    need(stat.S_ISDIR(info.st_mode), f"not a directory: {path.name}")
    result = {}
    for child in sorted(path.iterdir()):
        need(not child.is_symlink(), f"symlink in evidence: {child.name}")
        if child.is_dir():
            need(not flat, f"directory in flat evidence namespace: {path.name}/{child.name}")
            for name, entry in tree(child).items():
                result[child.name + "/" + name] = entry
        else:
            raw = read_raw(child)
            result[child.name] = {"size": len(raw), "digest": digest(raw)}
    return result


def provider_snapshot(case: Path) -> dict[str, Any]:
    return {"provider": tree(case / "provider", flat=True), "sandbox": tree(case / "sandbox", flat=True)}


def observe_files(case: Path) -> list[dict[str, Any]]:
    result = []
    for name, entry in tree(case / "sandbox", flat=True).items():
        need(FILE_RE.fullmatch(name) is not None, "unexpected output path")
        result.append({"name": name, **entry})
    return result


def check_effect(case: Path, operation: dict[str, Any], native: dict[str, Any]) -> list[dict[str, Any]]:
    """Read actual files; never accept a producer's success flag as effect proof."""
    check_output_inventory(native["files"], "native files")
    observed = observe_files(case)
    files = operation["target"]["files"]
    need([f["name"] for f in observed] == [f["name"] for f in files], "actual output set mismatch")
    for item in files:
        need(read_raw(case / "sandbox" / item["name"]) == item["text"].encode("utf-8"),
             "actual output content differs from admitted text")
    need(native["files"] == observed, "native result differs from actual files")
    need(native["outcome"] == "success", "native result is not a terminal success")
    return observed


def eligible(receipt: dict[str, Any]) -> bool:
    outcome = receipt["decision"]["outcome"]
    return outcome == "allow" or (outcome == "attenuate" and
                                  receipt["attenuation"]["require_new_permit"] is False)


def effective_hash(receipt: dict[str, Any]) -> str:
    if receipt["decision"]["outcome"] == "attenuate":
        return receipt["attenuation"]["effective_request_hash"]
    return receipt["request"]["input_hash"]


def check_native_execution(case: Path, auth: Any, context: dict, *, dispatch: bytes, received: bytes,
                           native_raw: bytes, gate: dict, start: dict, transport: dict,
                           journal_raw: bytes, observed_at: str) -> tuple[dict, list]:
    """Success evidence available during dispatch and reconciliation, also used offline.

    The caller has checked the admission capsule. Later snapshots, reconciliation
    records and the post receipt are deliberately outside this shared boundary.
    """
    receipt = decode(auth.receipt)
    need(eligible(receipt), "admission cannot execute")
    payload, native = decode(dispatch), decode(native_raw)
    need(native_raw == encode(native), "non-contract native JSON bytes")
    identifier(start["attempt_key"])
    keys = {"operation_key": context["operation_key"], "authorization_key": decode(auth.permit)["authorization_key"],
            "attempt_key": start["attempt_key"]}
    need(dispatch == received == encode(payload), "adapter/provider wire bytes mismatch")
    need(payload == {"contract": CONTRACT, "operation": decode(auth.effective),
        "authorization_key": keys["authorization_key"], "attempt_key": keys["attempt_key"],
        "admission_digest": digest(auth.receipt), "effective_input_hash": effective_hash(receipt), "runtime": RUNTIME},
        "provider input differs from the admitted effective input")
    need(start == {**keys, "state": "indeterminate", "dispatch_started_at": start["dispatch_started_at"],
                   "dispatch_digest": digest(dispatch), "admission_digest": digest(auth.receipt)}, "attempt start binding mismatch")
    check_native_structure(native)
    need(native["contract"] == CONTRACT and all(native[k] == v for k, v in keys.items()), "native key linkage mismatch")
    need(native["runtime"] == RUNTIME and native["resource"] == context["resource"], "native runtime/target mismatch")
    journal = [decode(line) for line in journal_raw.splitlines()]
    check_execution_pids(native["pid"], transport["pid"], journal, context["controller_pid"])
    need(journal_raw == b"".join(encode(event) + b"\n" for event in journal), "non-contract journal JSON bytes")
    need(native["received_digest"] == digest(received) and native["input_hash"] == object_hash(payload["operation"])
         and native["admission_digest"] == digest(auth.receipt), "native input/admission digest mismatch")
    need(time_value(gate["checked_at"]) <= time_value(start["dispatch_started_at"]) <= time_value(native["started_at"])
         <= time_value(native["finished_at"]) <= time_value(transport["returned_at"]) <= time_value(observed_at),
         "execution observation time ordering mismatch")
    need(time_value(receipt["issued_at"]) <= time_value(native["started_at"])
         <= time_value(native["finished_at"]) <= time_value(receipt["expires_at"]),
         "native execution falls outside the admission window")
    need(journal[0] == {"event": "execute_received", "at": native["started_at"], "pid": native["pid"],
         "attempt_key": keys["attempt_key"], "received_digest": digest(received)}, "provider invocation journal mismatch")
    need(journal[1] == {"event": "completed", "at": journal[1]["at"], "pid": native["pid"],
         "attempt_key": keys["attempt_key"], "native_digest": digest(native_raw)}, "provider completion journal mismatch")
    need(time_value(native["finished_at"]) <= time_value(journal[1]["at"]) <= time_value(transport["returned_at"]),
         "journal completion time mismatch")
    return native, check_effect(case, payload["operation"], native)
