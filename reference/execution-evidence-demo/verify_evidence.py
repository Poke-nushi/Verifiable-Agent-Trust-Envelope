#!/usr/bin/env python3
"""Read-only verification of this demo's captured bytes and local file effects."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path, PureWindowsPath

from admission import Authorization, assert_authorization
from demo_contract import (
    ACTION, CONTRACT, Invalid, MAX_OUTPUT_BYTES, ROOT, RUNTIME, action_binding, check_execute_response, check_native_execution,
    check_integer, check_native_structure, check_query_response, check_size, check_snapshot, check_transport_record, core, decode, digest,
    effective_hash, eligible, encode, exact, identifier, need, object_hash, provider_snapshot, read_raw,
    source_digests, time_value, tree, validate_operation,
)


QUERY_EVIDENCE_FILES = frozenset({
    "adapter/query-request.json", "adapter/query-stdout.bin", "adapter/query-stderr.bin",
    "adapter/query-transport.json", "adapter/before-query-snapshot.json",
    "adapter/after-query-snapshot.json", "adapter/reconciliation.json",
})


class Reader:
    def __init__(self, case: Path):
        need(not case.is_symlink(), "case directory is a symlink")
        self.case = case.resolve(strict=True)
        self.used: set[str] = set()

    def raw(self, path: str) -> bytes:
        self.used.add(path)
        return read_raw(self.case / path)

    def get(self, path: str):
        raw = self.raw(path)
        value = decode(raw)
        need(raw == encode(value), f"non-contract JSON bytes: {path}")
        return value


def check_gate(gate: dict, auth: Authorization, candidate: bytes, prior: dict | None, initial: dict) -> None:
    receipt, permit = decode(auth.receipt), decode(auth.permit)
    exact(gate, {"contract", "checked_at", "authorization_key", "operation_key", "admission_digest",
                 "candidate_digest", "eligible_by_receipt", "handoff", "reason", "checks", "prior_attempt_key",
                 "provider_snapshot"}, "gate")
    check_snapshot(gate["provider_snapshot"], "gate snapshot")
    need(gate["contract"] == CONTRACT and gate["authorization_key"] == permit["authorization_key"]
         and gate["operation_key"] == permit["operation_key"], "gate identity mismatch")
    need(gate["admission_digest"] == digest(auth.receipt) and gate["candidate_digest"] == digest(candidate),
         "gate digest mismatch")
    need(gate["eligible_by_receipt"] is eligible(receipt), "gate misstates immediate eligibility")
    need(time_value(gate["checked_at"]) >= time_value(decode(auth.record)["evaluated_at"]), "gate predates evaluation")
    names = ["admission_preimages"]
    reason = "READY"
    if not eligible(receipt):
        reason = "REQUIRE_NEW_PERMIT" if receipt["decision"]["outcome"] == "attenuate" else "ADMISSION_DENIED"
    else:
        names.append("immediate_eligibility")
        if not (time_value(receipt["issued_at"]) <= time_value(gate["checked_at"]) <= time_value(receipt["expires_at"])):
            reason = "ADMISSION_WINDOW_INVALID"
        else:
            names.append("current_admission_window")
            try:
                operation = decode(candidate)
                validate_operation(operation, decode(auth.original)["target"]["resource"])
                need(candidate == auth.effective == encode(operation), "candidate mismatch")
                need(object_hash(operation) == effective_hash(receipt), "candidate hash mismatch")
                need(receipt["request"]["action_binding"] == action_binding(operation), "action binding mismatch")
            except (ValueError, KeyError, TypeError):
                reason = "EXECUTION_INPUT_MISMATCH"
            else:
                names.append("exact_execution_input")
                if prior is not None:
                    reason = "OPERATION_INDETERMINATE" if prior["state"] == "indeterminate" else "OPERATION_ALREADY_DISPATCHED"
                else:
                    names.append("operation_retry_guard")
                    if gate["provider_snapshot"] == initial:
                        names.append("fresh_local_provider_state")
                    else:
                        reason = "UNEXPECTED_PROVIDER_STATE"
    expected = [(name, True) for name in names]
    if reason != "READY":
        expected.append((reason, False))
    need(isinstance(gate["checks"], list) and all(type(c.get("pass")) is bool for c in gate["checks"]),
         "missing or malformed gate evaluations")
    need([(c["name"], c["pass"]) for c in gate["checks"]] == expected, "gate evaluation coverage mismatch")
    need(gate["reason"] == reason and gate["handoff"] is (reason == "READY"), "gate outcome mismatch")
    need(gate["prior_attempt_key"] == (prior["attempt_key"] if prior else None), "retry attempt linkage mismatch")


def check_transport(reader: Reader, command: str, controller_pid: int) -> tuple[bytes, dict]:
    raw, stderr = reader.raw(f"adapter/{command}-stdout.bin"), reader.raw(f"adapter/{command}-stderr.bin")
    transport = reader.get(f"adapter/{command}-transport.json")
    check_transport_record(transport, command, raw, stderr, controller_pid)
    return raw, transport


def response_rejection(check, *args, **kwargs) -> str | None:
    # Only response acceptance failures become an unknown observation. Missing
    # or invalid originals, transport records and snapshots are checked outside.
    try:
        check(*args, **kwargs)
    except (ValueError, KeyError, TypeError) as exc:
        return str(exc)
    return None


class _RecognitionPairs(list):
    """Retain duplicate object members without confusing objects with arrays."""


def recognition_document(raw: bytes, label: str) -> str | None:
    """Use the stdlib byte-decoding rules; recovery is only an uncertainty cue."""
    encoding = json.detect_encoding(raw)
    try:
        return raw.decode(encoding, "surrogatepass")
    except UnicodeDecodeError as exc:
        uncertain = raw.decode(encoding, "replace")
        if re.match(r"[\s\ufeff]*\{", uncertain):
            raise Invalid(f"cannot classify {label} object: invalid JSON encoding") from exc
        return None  # Opaque non-object bytes remain ordinary retained data.


def recognition_json(raw: bytes, label: str):
    """Find content cues without accepting a record as contract JSON.

    Numbers are irrelevant to recognition and need no conversion. Object pairs
    preserve every event member, including one a duplicate would overwrite.
    """
    document = recognition_document(raw, label)
    if document is None:
        return None
    try:
        return json.loads(document, object_pairs_hook=_RecognitionPairs,
                          parse_int=lambda _: None, parse_float=lambda _: None,
                          parse_constant=lambda _: None)
    except RecursionError as exc:
        raise Invalid(f"cannot classify {label}: JSON nesting exceeds this runtime's limit") from exc
    except ValueError as exc:
        if re.match(r"[\s\ufeff]*\{", document):
            raise Invalid(f"cannot classify {label} object: invalid JSON") from exc
        return None  # Ordinary non-JSON log text is not an execution record.


def recognition_members(value, key: str) -> list:
    return [item for name, item in value if name == key] if isinstance(value, _RecognitionPairs) else []


def recognition_match(value, expected) -> bool:
    """Only compare the shallow string/digest cues supplied by this reader.

    Matching any duplicate member is enough to require strict validation, never
    enough to accept the record or authenticate the referenced operation.
    """
    if isinstance(expected, dict):
        return isinstance(value, _RecognitionPairs) and all(
            any(recognition_match(item, child) for item in recognition_members(value, key))
            for key, child in expected.items())
    return type(value) is type(expected) and value == expected


def recognize_execution_event(raw: bytes) -> bool:
    value = recognition_json(raw, "retained journal")
    return any(isinstance(item, str) and item in ("execute_received", "completed")
               for item in recognition_members(value, "event"))


def recognition_journal_lines(raw: bytes):
    """Keep original bytes while finding CR/LF at the detected code-unit width."""
    encoding = json.detect_encoding(raw)
    if encoding in ("utf-8", "utf-8-sig"):
        yield from raw.splitlines()
        return
    width = 2 if encoding.startswith("utf-16") else 4
    order = "little" if encoding.endswith("-le") or raw.startswith(b"\xff\xfe") else "big"
    separators = tuple(number.to_bytes(width, order) for number in (13, 10))
    start = 0
    for offset in range(0, len(raw), width):
        if raw[offset:offset + width] in separators:
            yield raw[start:offset]
            start = offset + width
    if start < len(raw):
        yield raw[start:]


def recognize_execution_journal(raw: bytes) -> bool:
    return any(recognize_execution_event(line) for line in recognition_journal_lines(raw))


def check_closed_provider_records(reader: Reader, context: dict, auth: Authorization, gate: dict,
                                  journal_raw: bytes) -> None:
    """Attribute retained demo execution records before claiming this operation unused.

    Ordinary pre-existing bytes remain opaque. Recognizable demo records need
    their companion originals; an unassignable execution journal is not zero calls.
    This checks captured consistency, not authenticity of the earlier execution.
    """
    def contract_record(raw, label):
        try:
            return decode(raw)
        except ValueError as exc:
            raise Invalid(label + " is not contract JSON") from exc

    retained = gate["provider_snapshot"]["provider"]
    received_raw = reader.raw("provider/received.bin") if "received.bin" in retained else None
    native_raw = reader.raw("provider/native-result.json") if "native-result.json" in retained else None
    received_view = recognition_json(received_raw, "retained received record") if received_raw is not None else None
    native_view = recognition_json(native_raw, "retained native record") if native_raw is not None else None
    journal_lines = journal_raw.splitlines()
    permit, receipt = decode(auth.permit), decode(auth.receipt)
    current = {"operation_key": context["operation_key"], "authorization_key": permit["authorization_key"],
               "admission_digest": digest(auth.receipt), "resource": context["resource"],
               "input_hash": effective_hash(receipt), "effective_input_hash": effective_hash(receipt)}
    operations = recognition_members(received_view, "operation")
    objects = [received_view, native_view, *operations]
    objects.extend(target for operation in operations for target in recognition_members(operation, "target"))
    matches_current = any(recognition_match(item, expected) for value in objects for key, expected in current.items()
                          for item in recognition_members(value, key))
    # Recognition must not depend on the fields whose absence makes an event
    # incomplete. Removing attribution evidence cannot establish non-execution.
    recognizable = matches_current or any(recognition_match(item, CONTRACT) for value in objects
                                         for item in recognition_members(value, "contract")) or recognize_execution_journal(journal_raw)
    if not recognizable:
        return
    if received_raw is None:
        reader.raw("provider/received.bin")  # Missing attribution evidence remains incomplete.
    if native_raw is None:
        reader.raw("provider/native-result.json")
    received = contract_record(received_raw, "retained received record")
    native = contract_record(native_raw, "retained native record")
    exact(received, {"contract", "operation", "attempt_key", "authorization_key", "admission_digest",
                     "effective_input_hash", "runtime"}, "retained received record")
    check_native_structure(native, "retained native record")
    need(received_raw == encode(received) and native_raw == encode(native), "non-contract retained provider JSON bytes")
    need(received["contract"] == native["contract"] == CONTRACT, "retained provider contract mismatch")
    operation = received["operation"]
    validate_operation(operation, native["resource"])
    for key in ("attempt_key", "authorization_key"):
        identifier(native[key])
        need(native[key] == received[key], "retained provider identity mismatch")
    need(native["operation_key"] == operation["operation_key"] and native["runtime"] == received["runtime"] == RUNTIME,
         "retained provider operation/runtime mismatch")
    need(native["received_digest"] == digest(received_raw) and native["admission_digest"] == received["admission_digest"]
         and native["input_hash"] == received["effective_input_hash"] == object_hash(operation),
         "retained provider input/admission binding mismatch")
    expected_files = []
    for item in operation["target"]["files"]:
        raw = item["text"].encode("utf-8")
        expected_files.append({"name": item["name"], "size": len(raw), "digest": digest(raw)})
    need(native["files"] == expected_files, "retained provider outputs differ from received operation text")
    check_integer(native["pid"], "retained native PID", minimum=1)
    events = [contract_record(line, "retained provider journal") for line in journal_lines]
    need(len(events) == 2 and isinstance(events[1], dict), "retained provider journal is incomplete or inconsistent")
    need(events == [
        {"event": "execute_received", "at": native["started_at"], "pid": native["pid"],
         "attempt_key": native["attempt_key"], "received_digest": digest(received_raw)},
        {"event": "completed", "at": events[1]["at"], "pid": native["pid"],
         "attempt_key": native["attempt_key"], "native_digest": digest(native_raw)}], "retained provider journal binding mismatch")
    for event in events:
        check_integer(event["pid"], "retained journal PID", minimum=1)
    need(journal_raw == b"".join(encode(event) + b"\n" for event in events), "non-contract retained journal bytes")
    need(not matches_current, "closed gate conflicts with retained execution evidence for the current operation/admission")
    need(time_value(native["started_at"]) <= time_value(native["finished_at"]) <= time_value(events[1]["at"])
         <= time_value(gate["checked_at"]), "retained execution postdates the claimed pre-gate snapshot")


def check_post(reader: Reader, auth: Authorization, native_raw: bytes, files: list, *, observed_at: str) -> dict:
    native = decode(native_raw)
    post = reader.get("adapter/post-execution-receipt.json")
    receipt = decode(auth.receipt)
    exact(post, {"version", "profile", "receipt_type", "receipt_id", "issued_at", "issuer", "admission",
                 "execution", "result", "proof", "demo_evidence"}, "post receipt")
    need(post["version"] == core.VERSION and post["profile"] == core.PROFILE and post["receipt_type"] == "post_execution",
         "post receipt version/phase mismatch")
    need(post["receipt_id"] == "post-" + native["attempt_key"] and post["proof"] == {"format": "none"}, "post identity/proof mismatch")
    need(post["issuer"] == {"id": "urn:vate:demo:observing-adapter", "role": "broker"}, "post issuer mismatch")
    need(eligible(receipt), "non-executable admission cannot produce a success receipt")
    need(post["admission"] == {"receipt_id": receipt["receipt_id"], "uri": "local:admission-1/receipt.json",
                              "digest": digest(auth.receipt), "decision": receipt["decision"]["outcome"]},
         "post admission content link mismatch")
    need(post["execution"] == {"transaction_id": native["operation_key"], "runtime": RUNTIME,
        "started_at": native["started_at"], "finished_at": native["finished_at"],
        "effective_request_hash": native["input_hash"], "action_binding": action_binding(decode(auth.effective))},
        "post execution differs from observed provider execution")
    need(isinstance(post["result"]["side_effects"], list), "post side_effects must be a list")
    for effect in post["result"]["side_effects"]:
        check_size(effect["size"], "post side_effects", maximum=MAX_OUTPUT_BYTES)
    need(post["result"] == {"outcome": "success", "output_hash": object_hash({"files": files}),
        "side_effects": [{"tool": ACTION, "resource": native["resource"], **f} for f in files], "policy_violations": []},
        "post result differs from actual file effects")
    need(post["demo_evidence"] == {"contract": CONTRACT, "operation_key": native["operation_key"],
        "authorization_key": native["authorization_key"], "attempt_key": native["attempt_key"],
        "native_result": {"path": "provider/native-result.json", "digest": digest(native_raw)},
        "received_input": {"path": "provider/received.bin", "digest": native["received_digest"]}},
        "post native evidence link mismatch")
    need(time_value(post["issued_at"]) >= time_value(native["finished_at"]), "post predates completion")
    need(time_value(post["issued_at"]) >= time_value(observed_at), "post predates response observation")
    linkage = core.VateVerifier(verifier_id="demo-auditor").validate_post_execution_linkage(receipt, post)
    need(linkage["outcome"] == "success", "core post linkage failed: " + ",".join(linkage["reason_codes"]))
    return post


def verify(case: Path) -> dict:
    report = {"contract": CONTRACT, "verdict": "invalid", "effect_state": "unknown",
              "controller_observer_state": "unknown", "provider_execution_count": None,
              "provider_files_observed": None, "checks": [], "issues": [],
              "provenance": {"source_content": "not_checked", "producer_claims": {"status": "unverified", "fields": None}},
              "scope": "one local sequential run; unsigned artifacts and a trusted local controller/provider"}
    try:
        reader = Reader(case)
        provider_snapshot(reader.case)  # Reject directories, including empty ones, before inventory checks.
        manifest = reader.get("manifest.json")
        exact(manifest, {"contract", "digest_basis", "artifacts"}, "manifest")
        need(manifest["contract"] == CONTRACT and manifest["digest_basis"] == "raw-file-sha256", "manifest basis mismatch")
        actual = tree(reader.case)
        actual = {k: v for k, v in actual.items() if k not in ("manifest.json", "verification.json")}
        declared = manifest["artifacts"]
        need(isinstance(declared, dict), "manifest artifacts must be an object")
        for path, entry in declared.items():
            # Retained diagnostic names are not restricted to operation output names.
            need(isinstance(path, str) and "\\" not in path and "\x00" not in path
                 and not PureWindowsPath(path).drive
                 and all(part not in ("", ".", "..") for part in path.split("/")), "unsafe manifest path")
            exact(entry, {"size", "digest", "role"}, "manifest entry")
            check_size(entry["size"], "manifest entry")
            role = ("provider_original" if path.startswith("provider/") else "actual_output" if path.startswith("sandbox/")
                    else "admission_artifact" if path.startswith("admission-") else "adapter_record" if path.startswith("adapter/")
                    else "scenario_input_or_provenance")
            need(entry["role"] == role, "artifact role mismatch")
            if path not in actual:
                report["issues"].append({"kind": "missing", "path": path})
            elif actual[path] != {"size": entry["size"], "digest": entry["digest"]}:
                report["issues"].append({"kind": "modified", "path": path})
        for path in set(actual) - set(declared):
            report["issues"].append({"kind": "undeclared", "path": path})
        if report["issues"]:
            report["verdict"] = "incomplete" if all(i["kind"] == "missing" for i in report["issues"]) else "invalid"
            return report
        report["checks"].append("raw_artifact_inventory_and_digests")
        context, policy, source = reader.get("context.json"), reader.get("policy.json"), reader.get("source.json")
        exact(context, {"contract", "scenario", "operation_key", "resource", "controller_pid"}, "context")
        need(context["contract"] == CONTRACT, "context contract mismatch")
        identifier(context["operation_key"])
        need(context["resource"] == "urn:vate:demo:sandbox:" + context["operation_key"].removeprefix("op-"), "resource allocation mismatch")
        need(type(context["controller_pid"]) is int and context["controller_pid"] > 0, "invalid controller process")
        need(source["contract"] == CONTRACT, "source contract mismatch")
        source_match = source["files"] == source_digests()
        report["provenance"] = {"source_content": "matched_current_source_bytes" if source_match else "mismatch",
                                "producer_claims": {"status": "unverified", "fields": sorted(set(source) - {"contract", "files"})}}
        need(source_match, "source bytes differ from the recorded run; use its exact source snapshot")
        original = reader.raw("inputs/original-operation.json")
        validate_operation(decode(original), context["resource"])
        need(decode(original)["operation_key"] == context["operation_key"], "original operation mismatch")
        auths = []
        for index in (1, 2):
            prefix = f"admission-{index}/"
            if index == 2 and not any(path.startswith(prefix) for path in declared):
                break
            request, permit = reader.raw(prefix + "request.json"), reader.raw(prefix + "permit.json")
            receipt, core_raw = reader.raw(prefix + "receipt.json"), reader.raw(prefix + "core-result.json")
            record = reader.raw(prefix + "decision-record.json")
            effective = None if decode(receipt)["decision"]["outcome"] == "deny" else reader.raw(prefix + "effective-operation.json")
            auth = Authorization(original, permit, request, core_raw, receipt, effective, record)
            assert_authorization(auth, policy, context["resource"], f"local:admission-{index}/permit.json")
            auths.append(auth)
        auth = auths[0]
        receipt = decode(auth.receipt)
        report.update(admission_decision=receipt["decision"]["outcome"], immediate_eligibility=eligible(receipt))
        report["checks"].append("original_effective_preimages_permit_policy_and_core_decision")
        initial = reader.get("adapter/initial-snapshot.json")
        check_snapshot(initial, "initial snapshot")
        need(initial == {"provider": {"invocations.jsonl": {"size": 0, "digest": digest(b"")}}, "sandbox": {}},
             "initial local observation is not an empty initialized provider")
        candidate, gate = reader.raw("adapter/candidate-1.json"), reader.get("adapter/gate-1.json")
        check_gate(gate, auth, candidate, None, initial)
        final = reader.get("adapter/final-state.json")
        journal_raw = reader.raw("provider/invocations.jsonl")  # Required even for a refusal; missing is not zero calls.
        after = reader.get("adapter/after-dispatch-snapshot.json")
        if not gate["handoff"]:
            check_snapshot(after, "after-dispatch snapshot")
            need(after == provider_snapshot(reader.case), "provider capture snapshot mismatch")
            need(after == gate["provider_snapshot"], "provider or sandbox changed after a closed gate")
            # These bytes were present before the refusal. Inventory roles name
            # their location; they do not attribute them to this operation.
            for namespace, entries in after.items():
                for name in entries:
                    reader.raw(namespace + "/" + name)
            check_closed_provider_records(reader, context, auth, gate, journal_raw)
            need(final == {"operation_key": context["operation_key"], "attempt_key": None, "state": "not_dispatched"},
                 "non-dispatched final state mismatch")
            report.update(verdict="verified", effect_state="not_started", controller_observer_state="not_dispatched",
                          provider_execution_count=0,
                          provider_files_observed=[{"name": name, **entry} for name, entry in after["sandbox"].items()])
            report["checks"].append("closed_gate_preserved_pre_dispatch_bytes")
        else:
            dispatch = reader.raw("adapter/dispatch.json")
            start = reader.get("adapter/attempt-start.json")
            observation = reader.get("adapter/attempt-observation.json")
            native_raw = reader.raw("provider/native-result.json")
            received = reader.raw("provider/received.bin")
            response, transport = check_transport(reader, "execute", context["controller_pid"])
            keys = {"operation_key": context["operation_key"], "authorization_key": decode(auth.permit)["authorization_key"],
                    "attempt_key": start["attempt_key"]}
            native, files = check_native_execution(reader.case, auth, context, dispatch=dispatch, received=received,
                native_raw=native_raw, gate=gate, start=start, transport=transport, journal_raw=journal_raw,
                observed_at=observation["observed_at"])
            for item in files:
                reader.used.add("sandbox/" + item["name"])
            check_snapshot(after, "after-dispatch snapshot")
            need(after == provider_snapshot(reader.case), "provider capture snapshot mismatch")
            need(all(observation[k] == v for k, v in keys.items()), "attempt observation identity mismatch")
            state = observation["state"]
            common = {**keys, "state": state, "observed_at": observation["observed_at"]}
            rejected = response_rejection(check_execute_response, response, transport, native_raw)
            if state == "confirmed_success":
                need(rejected is None, "success lacks the exact provider response: " + str(rejected))
                post = check_post(reader, auth, native_raw, files, observed_at=observation["observed_at"])
                need(observation == {**common, "observer_state": "terminal_observed", "effect_state": "created",
                     "receipt_state": "emitted", "post_receipt_digest": digest(encode(post))}, "success observation differs from post receipt")
            else:
                need(state == "indeterminate", "unknown attempt state")
                need(rejected is not None, "indeterminate record conflicts with a valid response")
                need(observation == {**common, "observer_state": "indeterminate", "effect_state": "unknown",
                     "receipt_state": "not_emitted", "reason": rejected},
                     "indeterminate attempt must not fabricate terminal fields")
            if len(auths) == 2:
                need(decode(auths[1].permit)["authorization_key"] != keys["authorization_key"], "fresh permit reused the authorization key")
                retry = reader.get("adapter/gate-2.json")
                check_gate(retry, auths[1], reader.raw("adapter/candidate-2.json"), observation, initial)
                need(retry["provider_snapshot"] == after, "retry gate provider snapshot mismatch")
                need(time_value(observation["observed_at"]) <= time_value(decode(auths[1].record)["evaluated_at"]),
                     "fresh authorization predates original observation")
                need(not retry["handoff"], "retry reopened the original operation")
                report["retry_gate_reason"] = retry["reason"]
            # A missing request must not hide the remaining reconciliation evidence.
            if QUERY_EVIDENCE_FILES.intersection(declared):
                need(state == "indeterminate", "reconciliation did not start from an unresolved attempt")
                query = reader.get("adapter/query-request.json")
                need(query == {"operation_key": keys["operation_key"], "attempt_key": keys["attempt_key"]}, "query key mismatch")
                before_query, after_query = reader.get("adapter/before-query-snapshot.json"), reader.get("adapter/after-query-snapshot.json")
                check_snapshot(before_query, "before-query snapshot")
                check_snapshot(after_query, "after-query snapshot")
                need(before_query == after_query == after, "query changed the provider or effect artifacts")
                query_raw, query_transport = check_transport(reader, "query", context["controller_pid"])
                reconciliation = reader.get("adapter/reconciliation.json")
                need(reconciliation["read_only_snapshot_match"] is True, "read_only_snapshot_match must be boolean true")
                need(time_value(observation["observed_at"]) <= time_value(query_transport["returned_at"]),
                     "query predates original unknown observation")
                if len(auths) == 2:
                    need(time_value(retry["checked_at"]) <= time_value(query_transport["returned_at"]),
                         "query predates retry gate")
                need(time_value(query_transport["returned_at"]) <= time_value(reconciliation["observed_at"]),
                     "reconciliation predates query")
                common_query = {"contract": CONTRACT, **keys, "observed_at": reconciliation["observed_at"],
                                "read_only_snapshot_match": True}
                rejected = response_rejection(check_query_response, query_raw, query_transport, keys,
                                              received=received, native_raw=native_raw, files=files)
                if reconciliation["state"] == "confirmed_success":
                    need(rejected is None, "reconciliation lacks an accepted query response: " + str(rejected))
                    post = check_post(reader, auth, native_raw, files, observed_at=reconciliation["observed_at"])
                    need(reconciliation == {**common_query, "state": "confirmed_success", "effect_state": "created",
                        "observer_state": "terminal_observed", "post_receipt_digest": digest(encode(post))},
                        "reconciliation projection mismatch")
                    state = "confirmed_success"
                else:
                    need(rejected is not None, "indeterminate reconciliation conflicts with a valid query response")
                    need(reconciliation == {**common_query, "state": "indeterminate", "effect_state": "unknown",
                        "observer_state": "indeterminate", "reason": rejected}, "failed query must preserve the unknown attempt")
                report["checks"].append("read_only_reconciliation_to_original_attempt")
            need(final == {**keys, "state": state}, "final operation state mismatch")
            if state == "indeterminate":
                need("adapter/post-execution-receipt.json" not in declared, "unresolved attempt has a fabricated terminal receipt")
            report.update(verdict="verified" if state == "confirmed_success" else "indeterminate",
                          effect_state="created" if state == "confirmed_success" else "unknown",
                          controller_observer_state="terminal_observed" if state == "confirmed_success" else "indeterminate",
                          provider_execution_count=1, provider_files_observed=files)
            report["checks"].append("provider_wire_native_records_and_actual_file_bytes")
        if "fault-injection.json" in declared:
            reader.get("fault-injection.json")  # Provenance only, never an expected result or pass condition.
        need(reader.used - {"manifest.json"} == set(declared), "unexpected or unconsumed evidence artifact")
        report["checks"].append("gate_coverage_and_operation_state")
    except FileNotFoundError as exc:
        report.update(verdict="incomplete", effect_state="unknown", controller_observer_state="unknown",
                      provider_execution_count=None, provider_files_observed=None)
        report["issues"].append({"kind": "missing_required_evidence", "detail": str(exc)})
    except (ValueError, OSError, KeyError, TypeError, IndexError, AttributeError) as exc:
        report.update(verdict="invalid", effect_state="unknown", controller_observer_state="unknown",
                      provider_execution_count=None, provider_files_observed=None)
        report["issues"].append({"kind": "invalid_evidence", "detail": str(exc)})
    return report


def validate_schemas(case: Path) -> None:
    """Optional existing development dependency; the demo itself uses stdlib."""
    from jsonschema import Draft202012Validator, FormatChecker
    provider_snapshot(case)
    tree(case)  # Reject unsafe paths before optional schema reads as well.
    pairs = [(path, "admission-request.schema.json") for path in case.glob("admission-*/request.json")]
    pairs += [(path, "admission-receipt.schema.json") for path in case.glob("admission-*/receipt.json")]
    post = case / "adapter/post-execution-receipt.json"
    if post.exists():
        pairs.append((post, "post-execution-receipt.schema.json"))
    for path, name in pairs:
        schema = decode(read_raw(ROOT / "schemas" / name))
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(decode(read_raw(path)))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case_dir", type=Path)
    parser.add_argument("--strict-schema", action="store_true")
    args = parser.parse_args()
    report = verify(args.case_dir)
    if args.strict_schema:
        try:
            validate_schemas(args.case_dir)
            report["checks"].append("strict_existing_vate_schemas")
        except FileNotFoundError as exc:
            # A missing namespace is incomplete even with optional schema checks.
            # Do not downgrade an independently established invalid verdict.
            if report["verdict"] != "invalid":
                report.update(verdict="incomplete", effect_state="unknown", controller_observer_state="unknown",
                              provider_execution_count=None, provider_files_observed=None)
            report["issues"].append({"kind": "schema_evidence_missing", "detail": str(exc)})
        except Exception as exc:
            report.update(verdict="invalid", effect_state="unknown")
            report["issues"].append({"kind": "schema_validation", "detail": str(exc)})
    # Unverified metadata and filesystem errors can contain lone surrogates.
    print(json.dumps(report, indent=2, ensure_ascii=True))
    return 0 if report["verdict"] == "verified" else 2 if report["verdict"] in ("indeterminate", "incomplete") else 1


if __name__ == "__main__":
    raise SystemExit(main())
