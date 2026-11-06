"""Verify fixed SDK captures through the unchanged VATE reader and Inbox.

Run with the existing VATE environment; this process never imports the SDK.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import closing
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
READER = HERE
sys.path.insert(0, str(READER))

from receive import NOT_ASSESSED, PROFILE, SDK, assess, encoded, sha
from inbox_connection import retain


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def save(path, value):
    raw = value if type(value) is bytes else encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)


CASES = ("01-cancel-unknown", "02-upfront-and-unknown", "03-reapproval-return", "04-success-control")
CASE_FILES = ("request.json", "receiver-plan.json", "native-sdk-result.json",
              "native-tool-results.json", "capture.json", "TRACE.json")


def checked_capture_manifest(root, expected_cases):
    """Check a saved test inventory; its hashes do not authenticate an exporter."""
    manifest = json.loads((root / "CAPTURE-MANIFEST.json").read_bytes())
    require(manifest["source_commit"] == SDK["source_commit"] and
            manifest["sdk_source_commit"] == SDK["source_commit"], "SDK capture pin mismatch")
    require([row["case"] for row in manifest["cases"]] == list(expected_cases),
            "unexpected or repeated capture cases")
    expected_paths = {case + "/" + name for case in expected_cases for name in CASE_FILES}
    require(set(manifest["files"]) == expected_paths, "saved capture inventory mismatch")
    for name in sorted(expected_paths):
        raw = (root / name).read_bytes()
        require(manifest["files"][name] == {"sha256": sha(raw), "bytes": len(raw)},
                "saved capture file changed")
    require(manifest["capture_script_sha256"] == sha((HERE / "sdk/capture_sdk.py").read_bytes()),
            "capture harness differs from saved run")
    pins = json.loads((HERE / "sdk/SOURCE.json").read_bytes())
    expected_modules = {p["path"].removeprefix("python/"): p["sha256"]
                        for p in pins["files"] if p["path"].startswith("python/")}
    modules = manifest["imported_sdk_modules"]
    require(bool(modules) and len({m["module"] for m in modules}) == len(modules),
            "missing or repeated SDK module inventory")
    require(all(expected_modules.get(m["path"]) == m["sha256"] for m in modules),
            "saved SDK module differs from source inventory")
    require(manifest["origin"] == "real_pinned_sdk_with_local_test_doubles" and
            manifest["external_service_or_payment"] is False and
            manifest["network_guard_attempts"] == [], "unexpected saved experiment scope")
    return manifest


def check_sdk_path(case, capture, trace, raw_returns):
    events = trace["events"]
    count = Counter(e["kind"] for e in events)
    require(count["in_process_tool_call"] == 2 and count["test_payload_created"] == 1,
            "unexpected SDK dispatch/payload count")
    paid = [e["payment_present"] for e in events if e["kind"] == "in_process_tool_call"]
    require(paid == [False, True], "expected one probe and one payload submission")
    result = capture["result"]
    require(result["payment_made"] is True and result["raw_result"] == raw_returns[-1],
            "paid SDK output not preserved")
    require(len(raw_returns) == 2, "missing native tool result")
    require(trace["sdk_result_type"] == "x402.mcp.client.MCPToolCallResult", "unexpected result type")
    require(trace["sdk_raw_result_type"] == "x402.mcp.types.MCPToolResult", "unexpected raw result type")
    require(count["local_handler_called"] == (1 if case == "04-success-control" else 0),
            "unexpected local handler execution")
    approvals = [e["allowed"] for e in events if e["kind"] == "application_approval"]
    require(approvals == ([True, False] if case == "03-reapproval-return" else [True]),
            "unexpected approval sequence")
    require(count["cancellation_fault_injected"] == (1 if case.startswith(("01", "02")) else 0),
            "wrong cancellation fault coverage")
    require(count["facilitator_settle"] == (1 if case.startswith(("02", "04")) else 0),
            "unexpected test settlement count")
    require(result["is_error"] is (case != "04-success-control"), "unexpected SDK error status")
    return dict(count)


def check_observation(case, report):
    require(report["status"] == "inspected" and report["is_execution_ticket"] is False,
            "not an inspected non-executable observation")
    require(all(report["checks"][name]["status"] == "not_assessed" for name in NOT_ASSESSED),
            "unintended validation claim")
    o = report["observations"]
    require(o["origin_claim"] == "retained_sdk_export", "SDK origin lost")
    require(o["result_carrier"] == "return" and o["result_retained_in_capture"], "SDK result lost")
    require(o["cancellation"]["observation"] == (
        "reported_unknown" if case.startswith(("01", "02")) else "not_reported"), "cancellation meaning changed")
    require(o["claimed_upfront_success_with_unknown_cancellation"] is (case.startswith("02")),
            "upfront/unknown coexistence changed")
    require(o["exporter_claims"]["reapproval"] == (
        "denied" if case.startswith("03") else "not_recorded"), "approval observation changed")
    require(o["tool_result"]["content_views_equal"] is True, "SDK/raw content mismatch")


def negative_controls(inputs):
    original = json.loads(inputs["capture"])
    controls = []
    for name, mutation, reselect, expected in (
        ("changed_bytes_old_selection", lambda c: c["result"].update(payment_made=False), False,
         "receiver_selected_bytes_mismatch"),
        ("wrong_attempt", lambda c: c["context"].update(attempt_id="different-attempt"), True,
         "request_or_declared_context_mismatch"),
        ("wrong_request_reference", lambda c: c.update(request_sha256="0" * 64), True,
         "request_or_declared_context_mismatch"),
        ("different_sdk_commit", lambda c: c["sdk"].update(source_commit="0" * 40), True,
         "unsupported_export_or_sdk_pin"),
    ):
        changed = deepcopy(original)
        mutation(changed)
        trial = {**inputs, "capture": encoded(changed)}
        if reselect:
            selection = json.loads(trial["selection"])
            selection["capture_sha256"] = sha(trial["capture"])
            trial["selection"] = encoded(selection)
        report = assess(**trial)
        require(report["reason"] == expected and report["is_execution_ticket"] is False,
                "negative control incorrectly inspected")
        require(all(report["checks"][k]["status"] == "not_assessed" for k in NOT_ASSESSED),
                "negative control gained authority")
        controls.append({"control": name, "reason": report["reason"], "is_execution_ticket": False})
    return controls


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--inbox-source-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    root = args.inbox_source_root.resolve(strict=True)
    sys.path.insert(0, str(root / "reference/recipient-inbox"))
    from recipient_inbox import Engine, Inbox
    manifest = checked_capture_manifest(args.capture, CASES)
    args.out.mkdir(mode=0o700)
    (args.out / "inputs").mkdir(mode=0o700)
    (args.out / "bundles").mkdir(mode=0o700)
    records, preserved_inputs, controls = [], {}, []
    db = args.out / "inbox.sqlite3"
    with closing(Inbox(db, Engine(root), create=True)) as inbox:
        for row in manifest["cases"]:
            case = row["case"]
            # This replay accepts the four documented local SDK scenarios.
            require(case in CASES,
                    "unexpected local capture case")
            directory = args.capture / case
            request = (directory / "request.json").read_bytes()
            capture = (directory / "capture.json").read_bytes()
            native = (directory / "native-sdk-result.json").read_bytes()
            require(sha(capture) == row["capture"]["sha256"] and sha(native) == row["result"]["sha256"],
                    "capture changed after SDK execution")
            c = json.loads(capture)
            require(c["result"] == json.loads(native), "export modified SDK result")
            plan = json.loads((directory / "receiver-plan.json").read_bytes())
            require(sha(request) == plan["request_sha256"] and plan["profile"] == PROFILE,
                    "application request changed")
            trace = json.loads((directory / "TRACE.json").read_bytes())
            counts = check_sdk_path(case, c, trace, json.loads((directory / "native-tool-results.json").read_bytes()))
            for e in trace["events"]:
                if e["kind"] == "in_process_tool_call":
                    require(e["request_sha256"] == sha(request), "transport used another request")
            selection = encoded({**plan, "capture_sha256": row["capture"]["sha256"]})
            inputs = {"selection": selection, "request": request, "capture": capture}
            src = args.out / "inputs" / case
            src.mkdir(mode=0o700)
            for name, raw in inputs.items():
                save(src / (name + ".json"), raw)
            command = [sys.executable, "-B", str(READER / "receive.py")]
            for name in inputs:
                command.extend(["--" + name, str(src / (name + ".json"))])
            command.extend(["--out", str(args.out / "bundles" / case)])
            process = subprocess.run(command, capture_output=True, timeout=30)
            save(args.out / (case + ".stdout.json"), process.stdout)
            save(args.out / (case + ".stderr.log"), process.stderr)
            require(process.returncode == 0 and process.stderr == b"", "reader CLI failed")
            report = json.loads(process.stdout)
            check_observation(case, report)
            require(report == assess(**inputs), "reader CLI/API mismatch")
            for name, raw in inputs.items():
                require((args.out / "bundles" / case / (name + ".json")).read_bytes() == raw,
                        "reader bundle changed original bytes")
            stored = retain(inbox, **inputs)
            duplicate = retain(inbox, **inputs)
            require(not stored["registration"]["duplicate"] and duplicate["registration"]["duplicate"],
                    "Inbox idempotency mismatch")
            require(json.loads(inbox.get(stored["originals"]["inspection"])) == report,
                    "Inbox changed report")
            preserved_inputs[case] = inputs
            records.append({"case": case, "record": stored, "sdk_event_counts": counts,
                            "observations": report["observations"], "reader_exit": process.returncode})
            controls.extend({"case": case, **r} for r in negative_controls(inputs))
        require(inbox.db.execute("SELECT count(*) FROM deliveries").fetchone()[0] == 4, "unexpected delivery count")
        require(inbox.db.execute("SELECT count(*) FROM runs").fetchone()[0] == 0, "unexpected native execution record")

    # Reopen: checks storage persistence, not just objects cached by this process.
    with closing(Inbox(db, Engine(root), create=False)) as inbox:
        for row in records:
            case = row["case"]
            inputs = preserved_inputs[case]
            refs = row["record"]["originals"]
            for name, raw in inputs.items():
                require(inbox.get(refs[name]) == raw, "reopened Inbox changed original")
            require(inbox.get(refs["inspection"]) == encoded(assess(**inputs)), "reopened Inbox changed assessment")
            require(retain(inbox, **inputs)["registration"]["duplicate"], "reopened duplicate not recognized")

    require(not any(n == "x402" or n.startswith("x402.") for n in sys.modules), "SDK leaked into VATE process")
    result = {"cases": records, "negative_controls": controls, "passed": True,
        "sdk_and_vate_separate_processes": True,
        "reopened_originals_and_reports_preserved": True, "idempotency_after_reopen": True,
        "inbox_deliveries": 4, "inbox_native_runs": 0, "is_execution_ticket": False,
        "not_measured": ["MCP wire transport", "real payment/cancellation", "signature and issuer",
                         "real external side effects", "external adoption", "native Inbox prepare/run"]}
    save(args.out / "SUMMARY.json", result)
    print(json.dumps({"passed": True, "sdk_cases_received": len(records), "negative_controls": len(controls),
        "inbox_deliveries": 4, "inbox_native_runs": 0, "sdk_imported_in_vate": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
