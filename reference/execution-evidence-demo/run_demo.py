#!/usr/bin/env python3
"""Run bounded local file effects and save role-separated execution evidence."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import uuid
from pathlib import Path

from admission import Authorization, assert_authorization, evaluate, make_permit, make_policy
from demo_contract import (
    ACTION, CONTRACT, HERE, ROOT, RUNTIME, Invalid, action_binding, check_execute_response, check_native_execution,
    check_query_response, check_snapshot, check_transport_record, core, decode,
    digest, effective_hash, eligible, encode, identifier, need, now, object_hash, observe_files, provider_snapshot,
    read_json, read_raw, source_digests, time_value, tree, validate_operation, write_json, write_raw,
)

SCENARIOS = ("allow", "deny", "attenuate", "swap-content", "swap-destination", "require-new-permit",
             "response-loss", "response-loss-reconciled", "missing-evidence", "tampered-evidence")


def source_record() -> dict:
    files = source_digests()
    base_commit = None
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False)
        if head.returncode == 0:
            base_commit = head.stdout.strip() or None
    except OSError:
        pass  # Git is optional producer metadata, not an execution dependency.
    return {"contract": CONTRACT, "base_commit": base_commit,
            "python": sys.version,
            "files": files}


class Controller:
    """One live, sequential controller. Its operation slot is not a durable store."""

    def __init__(self, case: Path, scenario: str):
        need(scenario in SCENARIOS, "unknown scenario")
        case.mkdir()  # Refuse to reuse or overwrite an existing run directory.
        self.case = case.resolve()
        for name in ("inputs", "adapter", "provider", "sandbox"):
            (self.case / name).mkdir()
        suffix = uuid.uuid4().hex
        self.context = {"contract": CONTRACT, "scenario": scenario,
                        "operation_key": "op-" + suffix, "resource": "urn:vate:demo:sandbox:" + suffix,
                        "controller_pid": os.getpid()}
        self.policy = make_policy(require_new_permit=scenario == "require-new-permit")
        files = [{"name": "summary.txt", "text": "Local execution evidence.\n観測したファイルです。\n"}]
        if scenario in ("attenuate", "require-new-permit"):
            files.insert(0, {"name": "details.txt", "text": "An additional requested output.\n"})
        self.original = {"contract": CONTRACT, "operation_key": self.context["operation_key"],
                         "action": ACTION, "target": {"resource": self.context["resource"], "files": files}}
        write_json(self.case / "context.json", self.context)
        write_json(self.case / "policy.json", self.policy)
        write_json(self.case / "source.json", source_record())
        write_json(self.case / "inputs/original-operation.json", self.original)
        write_raw(self.case / "provider/invocations.jsonl", b"")
        self.initial = provider_snapshot(self.case)
        write_json(self.case / "adapter/initial-snapshot.json", self.initial)
        self.slot: dict | None = None
        self.auths: list[Authorization] = []

    def authorize(self, *, revoked: bool = False) -> Authorization:
        index = len(self.auths) + 1
        directory = self.case / f"admission-{index}"
        directory.mkdir()
        permit = make_permit(self.original, "auth-" + uuid.uuid4().hex, issued_at=core.iso(core.utc_now()),
                             status="revoked" if revoked else "active")
        auth = evaluate(self.original, permit, self.policy, resource=self.context["resource"],
                        permit_uri=f"local:admission-{index}/permit.json", evaluated_at=now())
        for filename, raw in (("permit.json", auth.permit), ("request.json", auth.request),
                              ("core-result.json", auth.core_result), ("receipt.json", auth.receipt),
                              ("decision-record.json", auth.record), ("effective-operation.json", auth.effective)):
            if raw is not None:
                write_raw(directory / filename, raw)
        self.auths.append(auth)
        return auth

    def gate(self, auth: Authorization, candidate: bytes, *, checked_at: str | None = None) -> dict:
        index = self.auths.index(auth) + 1
        receipt = decode(auth.receipt)
        # Observe even an early denial, before any attempt or provider call.
        snapshot, snapshot_error = None, None
        try:
            snapshot = provider_snapshot(self.case)
        except (ValueError, OSError) as exc:
            snapshot_error = str(exc)
        stamp = checked_at or now()
        checks = []
        reason = "READY"
        try:
            reason = "ADMISSION_BINDING_INVALID"
            assert_authorization(auth, self.policy, self.context["resource"], f"local:admission-{index}/permit.json")
            checks.append({"name": "admission_preimages", "pass": True})
            reason = "REQUIRE_NEW_PERMIT" if receipt["decision"]["outcome"] == "attenuate" else "ADMISSION_DENIED"
            need(eligible(receipt), reason)
            checks.append({"name": "immediate_eligibility", "pass": True})
            reason = "ADMISSION_WINDOW_INVALID"
            need(time_value(receipt["issued_at"]) <= time_value(stamp) <= time_value(receipt["expires_at"]), reason)
            checks.append({"name": "current_admission_window", "pass": True})
            reason = "EXECUTION_INPUT_MISMATCH"
            operation = decode(candidate)
            validate_operation(operation, self.context["resource"])
            need(candidate == encode(operation) == auth.effective, reason)
            need(object_hash(operation) == effective_hash(receipt), reason)
            need(receipt["request"]["action_binding"] == action_binding(operation), reason)
            checks.append({"name": "exact_execution_input", "pass": True})
            reason = "OPERATION_INDETERMINATE" if self.slot and self.slot["state"] == "indeterminate" else "OPERATION_ALREADY_DISPATCHED"
            need(self.slot is None, reason)
            checks.append({"name": "operation_retry_guard", "pass": True})
            reason = "UNEXPECTED_PROVIDER_STATE"
            check_snapshot(self.initial, "initial snapshot")
            need(snapshot is not None, snapshot_error or "provider state unavailable")
            check_snapshot(snapshot, "gate snapshot")
            need(snapshot == self.initial, reason)
            checks.append({"name": "fresh_local_provider_state", "pass": True})
            reason = "READY"
        except (ValueError, OSError, KeyError, TypeError) as exc:
            checks.append({"name": reason, "pass": False, "detail": str(exc)})
        return {"contract": CONTRACT, "checked_at": stamp, "authorization_key": decode(auth.permit)["authorization_key"],
                "operation_key": self.context["operation_key"], "admission_digest": digest(auth.receipt),
                "candidate_digest": digest(candidate), "eligible_by_receipt": eligible(receipt),
                "handoff": reason == "READY", "reason": reason, "checks": checks,
                "prior_attempt_key": self.slot["attempt_key"] if self.slot else None,
                "provider_snapshot": snapshot}

    def provider_call(self, command: str, payload: bytes, *, drop_response: bool = False) -> tuple[bytes, dict]:
        argv = [sys.executable, "-B", str(HERE / "provider.py"), command, "--case-dir", str(self.case)]
        if drop_response:
            argv.append("--drop-response")
        pid = None
        try:
            with subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
                pid = child.pid
                try:
                    raw, error = child.communicate(payload, timeout=15)
                    code = child.returncode
                except subprocess.TimeoutExpired:
                    child.kill()
                    raw, error = child.communicate()
                    code = None
        except OSError as exc:
            raw, error, code = b"", str(exc).encode("utf-8"), None
        write_raw(self.case / f"adapter/{command}-stdout.bin", raw)
        write_raw(self.case / f"adapter/{command}-stderr.bin", error)
        transport = {"command": command, "returned_at": now(), "returncode": code,
                     "pid": pid, "stdout_digest": digest(raw), "stderr_digest": digest(error)}
        write_json(self.case / f"adapter/{command}-transport.json", transport)
        return raw, transport

    def accept_native(self, auth: Authorization, dispatch: bytes, raw: bytes, *, observed_at: str,
                      execution_observed_at: str | None = None) -> dict:
        receipt = decode(auth.receipt)
        need(raw == read_raw(self.case / "provider/native-result.json"), "response/native original mismatch")
        transport = read_json(self.case / "adapter/execute-transport.json")
        check_transport_record(transport, "execute", read_raw(self.case / "adapter/execute-stdout.bin"),
                               read_raw(self.case / "adapter/execute-stderr.bin"), self.context["controller_pid"])
        check_native_execution(self.case, auth, self.context, dispatch=dispatch,
            received=read_raw(self.case / "provider/received.bin"), native_raw=raw,
            gate=read_json(self.case / "adapter/gate-1.json"), start=read_json(self.case / "adapter/attempt-start.json"),
            transport=transport, journal_raw=read_raw(self.case / "provider/invocations.jsonl"),
            observed_at=execution_observed_at if execution_observed_at is not None else observed_at)
        post = build_post(auth, raw, observed_at=observed_at)
        need(eligible(receipt), "admission cannot execute")
        result = core.VateVerifier(verifier_id="demo-post-check").validate_post_execution_linkage(receipt, post)
        need(result["outcome"] == "success", "core post linkage: " + ",".join(result["reason_codes"]))
        write_json(self.case / "adapter/post-execution-receipt.json", post)
        return post

    def dispatch(self, auth: Authorization, candidate: bytes, *, drop_response: bool = False) -> dict:
        gate = self.gate(auth, candidate)
        write_raw(self.case / "adapter/candidate-1.json", candidate)
        write_json(self.case / "adapter/gate-1.json", gate)
        if not gate["handoff"]:
            # Unsafe/missing namespaces cannot produce a complete capture, but
            # keep their gate rejection without allocating an attempt.
            if gate["provider_snapshot"] is not None:
                write_json(self.case / "adapter/after-dispatch-snapshot.json", provider_snapshot(self.case))
            return gate
        attempt_key = "attempt-" + uuid.uuid4().hex
        self.slot = {"operation_key": self.context["operation_key"], "attempt_key": attempt_key,
                     "authorization_key": decode(auth.permit)["authorization_key"], "state": "indeterminate"}
        payload = {"contract": CONTRACT, "operation": decode(candidate), "attempt_key": attempt_key,
                   "authorization_key": self.slot["authorization_key"], "admission_digest": digest(auth.receipt),
                   "effective_input_hash": effective_hash(decode(auth.receipt)), "runtime": RUNTIME}
        dispatch = encode(payload)
        write_raw(self.case / "adapter/dispatch.json", dispatch)
        write_json(self.case / "adapter/attempt-start.json", {**self.slot, "dispatch_started_at": now(),
                   "dispatch_digest": digest(dispatch), "admission_digest": digest(auth.receipt)})
        raw, transport = self.provider_call("execute", dispatch, drop_response=drop_response)
        # observed_at is the start of response processing, before post issuance.
        observation = {**self.slot, "observed_at": now(), "observer_state": "indeterminate",
                       "effect_state": "unknown", "receipt_state": "not_emitted"}
        try:
            check_transport_record(transport, "execute", raw, read_raw(self.case / "adapter/execute-stderr.bin"),
                                   self.context["controller_pid"])
            need(transport["returncode"] == 0 and bool(raw), "no usable provider response")
            check_execute_response(raw, transport, read_raw(self.case / "provider/native-result.json"))
            post = self.accept_native(auth, dispatch, raw, observed_at=observation["observed_at"])
            self.slot["state"] = "confirmed_success"
            observation.update(state="confirmed_success", observer_state="terminal_observed", effect_state="created",
                               receipt_state="emitted", post_receipt_digest=digest(encode(post)))
        except (ValueError, OSError, KeyError, TypeError) as exc:
            observation["reason"] = str(exc)
        write_json(self.case / "adapter/attempt-observation.json", observation)
        write_json(self.case / "adapter/after-dispatch-snapshot.json", provider_snapshot(self.case))
        return gate

    def try_fresh_authorization(self) -> dict:
        auth = self.authorize()
        candidate = auth.effective if auth.effective is not None else auth.original
        gate = self.gate(auth, candidate)
        write_raw(self.case / "adapter/candidate-2.json", candidate)
        write_json(self.case / "adapter/gate-2.json", gate)
        # This probe deliberately has no dispatch path. Its gate must reject it.
        need(not gate["handoff"], "fresh authorization unexpectedly reopened an attempted operation")
        return gate

    def reconcile(self) -> dict:
        need(self.slot is not None and self.slot["state"] == "indeterminate", "no unresolved attempt")
        payload = encode({"operation_key": self.slot["operation_key"], "attempt_key": self.slot["attempt_key"]})
        write_raw(self.case / "adapter/query-request.json", payload)
        before = provider_snapshot(self.case)
        write_json(self.case / "adapter/before-query-snapshot.json", before)
        raw, transport = self.provider_call("query", payload)
        after = provider_snapshot(self.case)
        write_json(self.case / "adapter/after-query-snapshot.json", after)
        # Preserve the same response-processing timestamp semantics as dispatch.
        record = {"contract": CONTRACT, "observed_at": now(), **self.slot, "effect_state": "unknown",
                  "read_only_snapshot_match": before == after, "observer_state": "indeterminate"}
        try:
            check_snapshot(before, "before-query snapshot")
            check_snapshot(after, "after-query snapshot")
            need(before == after, "query changed provider or output bytes")
            check_transport_record(transport, "query", raw, read_raw(self.case / "adapter/query-stderr.bin"),
                                   self.context["controller_pid"])
            need(transport["returncode"] == 0, "query did not return usable evidence")
            native_raw = read_raw(self.case / "provider/native-result.json")
            received_raw = read_raw(self.case / "adapter/dispatch.json")
            check_query_response(raw, transport, self.slot, received=received_raw,
                                 native_raw=native_raw, files=observe_files(self.case))
            post = self.accept_native(self.auths[0], received_raw, native_raw, observed_at=record["observed_at"],
                                      execution_observed_at=read_json(self.case / "adapter/attempt-observation.json")["observed_at"])
            self.slot["state"] = "confirmed_success"
            record.update(state="confirmed_success", observer_state="terminal_observed", effect_state="created",
                          post_receipt_digest=digest(encode(post)))
        except (ValueError, OSError, KeyError, TypeError) as exc:
            record["reason"] = str(exc)
        write_json(self.case / "adapter/reconciliation.json", record)
        return record

    def finish(self) -> None:
        write_json(self.case / "adapter/final-state.json", self.slot or {
            "operation_key": self.context["operation_key"], "attempt_key": None, "state": "not_dispatched"})
        write_json(self.case / "manifest.json", make_manifest(self.case))


def build_post(auth: Authorization, native_raw: bytes, *, observed_at: str) -> dict:
    native = decode(native_raw)
    need(native_raw == encode(native), "non-contract native JSON bytes")
    receipt = decode(auth.receipt)
    operation = decode(auth.effective)
    issued_at = now()
    need(time_value(native["finished_at"]) <= time_value(observed_at) <= time_value(issued_at),
         "post issuance time ordering mismatch")
    return {
        "version": core.VERSION, "profile": core.PROFILE, "receipt_type": "post_execution",
        "receipt_id": "post-" + native["attempt_key"], "issued_at": issued_at,
        "issuer": {"id": "urn:vate:demo:observing-adapter", "role": "broker"},
        "admission": {"receipt_id": receipt["receipt_id"], "uri": "local:admission-1/receipt.json",
                      "digest": digest(auth.receipt), "decision": receipt["decision"]["outcome"]},
        "execution": {"transaction_id": native["operation_key"], "runtime": native["runtime"],
                      "started_at": native["started_at"], "finished_at": native["finished_at"],
                      "effective_request_hash": native["input_hash"], "action_binding": action_binding(operation)},
        "result": {"outcome": native["outcome"], "output_hash": object_hash({"files": native["files"]}),
                   "side_effects": [{"tool": ACTION, "resource": native["resource"], **f} for f in native["files"]],
                   "policy_violations": []}, "proof": {"format": "none"},
        "demo_evidence": {"contract": CONTRACT, "operation_key": native["operation_key"],
                          "authorization_key": native["authorization_key"], "attempt_key": native["attempt_key"],
                          "native_result": {"path": "provider/native-result.json", "digest": digest(native_raw)},
                          "received_input": {"path": "provider/received.bin", "digest": native["received_digest"]}},
    }


def artifact_role(path: str) -> str:
    if path.startswith("provider/"):
        return "provider_original"
    if path.startswith("sandbox/"):
        return "actual_output"
    if path.startswith("admission-"):
        return "admission_artifact"
    if path.startswith("adapter/"):
        return "adapter_record"
    return "scenario_input_or_provenance"


def make_manifest(case: Path) -> dict:
    provider_snapshot(case)  # Empty directories must not disappear from the inventory.
    return {"contract": CONTRACT, "digest_basis": "raw-file-sha256", "artifacts": {
        path: {**entry, "role": artifact_role(path)} for path, entry in tree(case).items()
        if path not in ("manifest.json", "verification.json")}}


def run_case(case: Path, scenario: str) -> dict:
    controller = Controller(case, scenario)
    auth = controller.authorize(revoked=scenario == "deny")
    candidate = auth.effective if auth.effective is not None else auth.original
    if scenario.startswith("swap-"):
        modified = decode(candidate)
        if scenario == "swap-content":
            modified["target"]["files"][0]["text"] = "Changed after admission.\n"
        else:
            modified["target"]["files"][0]["name"] = "redirected.txt"
        candidate = encode(modified)
    controller.dispatch(auth, candidate, drop_response=scenario.startswith("response-loss"))
    if scenario.startswith("response-loss"):
        controller.try_fresh_authorization()
        if scenario == "response-loss-reconciled":
            controller.reconcile()
    if scenario in ("missing-evidence", "tampered-evidence"):
        write_json(case / "fault-injection.json", {"fault": scenario, "phase": "after_capture_and_manifest"})
    controller.finish()
    if scenario == "missing-evidence":
        (case / "provider/native-result.json").unlink()
    elif scenario == "tampered-evidence":
        (case / "sandbox/summary.txt").write_bytes(b"Altered after evidence capture.\n")
    from verify_evidence import verify
    result = verify(case)
    write_json(case / "verification.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=SCENARIOS)
    parser.add_argument("--output-name", help="new directory name under this demo's ignored generated directory")
    args = parser.parse_args()
    name = args.output_name or "run-" + uuid.uuid4().hex
    try:
        identifier(name)
        generated = HERE / "generated"
        need(not generated.is_symlink(), "generated directory must not be a symlink")
        generated.mkdir(exist_ok=True)
        output = generated / name
        output.mkdir()
        print(f"Local execution evidence: {output}")
        for scenario in (args.case,) if args.case else SCENARIOS:
            result = run_case(output / scenario, scenario)
            print(f"{scenario}: {result['verdict']} / effect={result['effect_state']}")
        print("Local observation only; no independent implementation or production claim.")
        return 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f"demo error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
