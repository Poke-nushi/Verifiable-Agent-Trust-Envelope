"""Retain a second real SDK test attempt without replacing the first attempt."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import sys

from run_sdk_examples import (assess, check_observation, checked_capture_manifest,
                           check_sdk_path, encoded, require, retain, save, sha)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first-intake", type=Path, required=True)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inbox-source-root", type=Path, required=True)
    args = parser.parse_args()
    root_repo = args.inbox_source_root.resolve(strict=True)
    sys.path.insert(0, str(root_repo / "reference/recipient-inbox"))
    from recipient_inbox import Engine, Inbox
    output = args.out
    output.mkdir(mode=0o700)
    original_summary = json.loads((args.first_intake / "SUMMARY.json").read_bytes())
    old = next(r for r in original_summary["cases"] if r["case"] == "03-reapproval-return")
    source_db = args.first_intake / "inbox.sqlite3"
    db = output / "inbox.sqlite3"
    with closing(sqlite3.connect(source_db.resolve().as_uri() + "?mode=ro", uri=True)) as src:
        with closing(sqlite3.connect(db)) as dst:
            src.backup(dst)
    os.chmod(db, 0o600)
    root = args.capture
    manifest = checked_capture_manifest(root, ("03-reapproval-return",))
    require(len(manifest["cases"]) == 1, "expected one additional SDK run")
    row = manifest["cases"][0]
    case = row["case"]
    require(case == "03-reapproval-return", "unexpected SDK case")
    directory = root / case
    request = (directory / "request.json").read_bytes()
    capture = (directory / "capture.json").read_bytes()
    native = (directory / "native-sdk-result.json").read_bytes()
    require(sha(capture) == row["capture"]["sha256"] and sha(native) == row["result"]["sha256"],
            "second capture changed")
    c = json.loads(capture)
    require(c["result"] == json.loads(native), "second export changed SDK output")
    plan = json.loads((directory / "receiver-plan.json").read_bytes())
    require(plan["request_sha256"] == sha(request), "second request changed")
    inputs = {"request": request, "capture": capture,
              "selection": encoded({**plan, "capture_sha256": sha(capture)})}
    trace = json.loads((directory / "TRACE.json").read_bytes())
    check_sdk_path(case, c, trace, json.loads((directory / "native-tool-results.json").read_bytes()))
    report = assess(**inputs)
    check_observation(case, report)
    with closing(Inbox(db, Engine(root_repo), create=False)) as inbox:
        oldrefs = old["record"]["originals"]
        oldcapture = json.loads(inbox.get(oldrefs["capture"]))
        require(request == inbox.get(oldrefs["request"]), "not the same application request")
        require(c["result"] == oldcapture["result"], "SDK result differs beyond attempt")
        require(c["context"]["attempt_id"] != oldcapture["context"]["attempt_id"], "attempt did not change")
        stored = retain(inbox, **inputs)
        require(stored["delivery"]["source_namespace"] == old["record"]["delivery"]["source_namespace"],
                "different operation namespace")
        require(stored["delivery"]["entry_id"] != old["record"]["delivery"]["entry_id"],
                "second attempt collapsed into first")
        require(not stored["registration"]["duplicate"], "second attempt treated as duplicate")
        require(retain(inbox, **inputs)["registration"]["duplicate"], "second attempt not idempotent")
        require(inbox.db.execute("SELECT count(*) FROM deliveries").fetchone()[0] == 5, "delivery count")
        require(inbox.db.execute("SELECT count(*) FROM runs").fetchone()[0] == 0, "unexpected execution")
    with closing(Inbox(db, Engine(root_repo), create=False)) as inbox:
        for prior in original_summary["cases"]:
            directory = args.first_intake / "inputs" / prior["case"]
            previous = {n: (directory / (n + ".json")).read_bytes() for n in ("selection", "request", "capture")}
            for name, raw in {**previous, "inspection": encoded(assess(**previous))}.items():
                require(inbox.get(prior["record"]["originals"][name]) == raw, "prior record replaced")
        for name, raw in {**inputs, "inspection": encoded(report)}.items():
            require(inbox.get(stored["originals"][name]) == raw, "second attempt storage mismatch")
    save(output / "SUMMARY.json", {"passed": True, "same_request_and_sdk_result": True,
        "same_operation_different_attempt": True, "separate_entries": True,
        "prior_entries_preserved": 4, "reopened_all_originals_and_reports_preserved": True,
        "deliveries": 5, "native_runs": 0, "second_record": stored, "is_execution_ticket": False})
    print(json.dumps({"passed": True, "same_operation_distinct_attempts": 2,
                      "old_entries_preserved": 4, "deliveries": 5, "native_runs": 0}))


if __name__ == "__main__":
    main()
