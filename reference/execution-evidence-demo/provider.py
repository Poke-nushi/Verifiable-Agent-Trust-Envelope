#!/usr/bin/env python3
"""One-shot local file provider. No arbitrary commands, paths, or network calls."""

from __future__ import annotations

import argparse
import base64
import os
import stat
import sys
from pathlib import Path

from demo_contract import (
    CONTRACT, MAX_ARTIFACT, RUNTIME, decode, digest, encode, exact, identifier,
    need, now, object_hash, observe_files, provider_snapshot, read_json, read_raw, validate_operation,
    write_raw,
)


def append_event(case: Path, event: dict) -> None:
    path = case / "provider/invocations.jsonl"
    read_raw(path)  # Reject missing files, links, FIFOs and non-regular files.
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
    with os.fdopen(fd, "ab") as handle:
        info = os.fstat(handle.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "unsafe invocation journal")
        handle.write(encode(event) + b"\n")


def execute(case: Path, raw: bytes, *, drop_response: bool = False) -> bytes:
    provider_snapshot(case)  # Reject pre-existing unsafe provider/output trees.
    need(read_raw(case / "provider/invocations.jsonl") == b"", "invocation journal is not empty; reconcile instead of retry")
    context = read_json(case / "context.json")
    payload = decode(raw)
    exact(payload, {"contract", "operation", "authorization_key", "attempt_key",
                    "admission_digest", "effective_input_hash", "runtime"}, "dispatch")
    need(payload["contract"] == CONTRACT and payload["runtime"] == RUNTIME, "unsupported dispatch")
    need(raw == encode(payload), "dispatch must use exact demo JSON bytes")
    for key in ("authorization_key", "attempt_key"):
        identifier(payload[key])
    operation = payload["operation"]
    validate_operation(operation, context["resource"])
    need(operation["operation_key"] == context["operation_key"], "operation key mismatch")
    need(payload["effective_input_hash"] == object_hash(operation), "dispatch input hash mismatch")
    need((case / "provider").is_dir() and not (case / "provider").is_symlink(), "unsafe provider directory")
    need(observe_files(case) == [], "sandbox is not empty; no overwrite or retry")
    # Record the received wire bytes before any effect. Exclusive creation also
    # prevents a second sequential dispatch from replacing the first record.
    write_raw(case / "provider/received.bin", raw)
    started = now()
    append_event(case, {"event": "execute_received", "at": started, "pid": os.getpid(),
                        "attempt_key": payload["attempt_key"], "received_digest": digest(raw)})
    for item in operation["target"]["files"]:
        write_raw(case / "sandbox" / item["name"], item["text"].encode("utf-8"))
    observed = observe_files(case)
    native = {
        "contract": CONTRACT, "operation_key": operation["operation_key"],
        "authorization_key": payload["authorization_key"], "attempt_key": payload["attempt_key"],
        "runtime": RUNTIME, "pid": os.getpid(), "resource": context["resource"],
        "received_digest": digest(raw), "input_hash": object_hash(operation),
        "admission_digest": payload["admission_digest"], "started_at": started,
        "finished_at": now(), "outcome": "success", "files": observed,
    }
    native_raw = encode(native)
    write_raw(case / "provider/native-result.json", native_raw)
    append_event(case, {"event": "completed", "at": now(), "pid": os.getpid(),
                        "attempt_key": payload["attempt_key"], "native_digest": digest(native_raw)})
    # Controlled response loss occurs after both the files and native record exist.
    return b"" if drop_response else native_raw


def query(case: Path, raw: bytes) -> bytes:
    """Read-only lookup; deliberately does not append an invocation or create files."""
    provider_snapshot(case)
    payload = decode(raw)
    exact(payload, {"operation_key", "attempt_key"}, "query")
    for value in payload.values():
        identifier(value)
    context = read_json(case / "context.json")
    need(payload["operation_key"] == context["operation_key"], "query operation mismatch")
    received_path = case / "provider/received.bin"
    native_path = case / "provider/native-result.json"
    if not received_path.exists() or not native_path.exists():
        return encode({"status": "unknown", "reason": "required_provider_evidence_missing", **payload})
    received_raw = read_raw(received_path)
    native_raw = read_raw(native_path)
    received, native = decode(received_raw), decode(native_raw)
    need(received["attempt_key"] == payload["attempt_key"] == native["attempt_key"], "query attempt mismatch")
    need(received["operation"]["operation_key"] == payload["operation_key"] == native["operation_key"],
         "query record operation mismatch")
    return encode({
        "status": "observed", **payload,
        "received_base64": base64.b64encode(received_raw).decode("ascii"),
        "native_base64": base64.b64encode(native_raw).decode("ascii"),
        "current_files": observe_files(case),
    })


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("execute", "query"))
    parser.add_argument("--case-dir", required=True, type=Path)
    parser.add_argument("--drop-response", action="store_true")
    args = parser.parse_args()
    try:
        need(not args.case_dir.is_symlink(), "unsafe case directory")
        case = args.case_dir.resolve(strict=True)
        raw = sys.stdin.buffer.read(MAX_ARTIFACT + 1)
        if args.command == "execute":
            output = execute(case, raw, drop_response=args.drop_response)
        else:
            need(not args.drop_response, "response-loss control is execute-only")
            output = query(case, raw)
        sys.stdout.buffer.write(output)
        return 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        # An error here is not proof that no effect occurred. The caller keeps
        # the attempt indeterminate and must reconcile.
        sys.stderr.write(f"provider diagnostic: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
