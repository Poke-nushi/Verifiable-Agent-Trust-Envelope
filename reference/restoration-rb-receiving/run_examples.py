"""Generate three synthetic inputs, and optionally retain two readings in Inbox."""
from datetime import datetime, timezone
import argparse
import json
from pathlib import Path
import sys
import tempfile

from example_inputs import inputs
from rb_receiving import assess, encode, identity, receive

HERE = Path(__file__).resolve().parent


def store_history(destination, case, source_root):
    root = Path(source_root).resolve()
    if not (root / "reference/recipient-inbox/recipient_inbox.py").is_file():
        raise ValueError("a trusted VATE source tree is required")
    sys.path.insert(0, str(root / "reference/recipient-inbox"))
    from recipient_inbox import Engine, Inbox, DELIVERY, PLAN
    engine = Engine(root)
    reports = [encode(assess(case["statement"], case["selection"], test_plan=case["test_plan"])),
               encode(assess(**case))]
    with tempfile.TemporaryDirectory(prefix="vate-rb-inbox-") as temporary:
        box = Inbox(Path(temporary) / "inbox.sqlite3", engine, create=True)
        try:
            basis = box.put(b"Synthetic local RB storage/history example. Receiver arrival times unknown. Empty requirement set.\n", "text/plain")
            now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            namespace = "urn:example:rb-storage"
            plan = {"document_type": PLAN, "version": 1, "receiver_id": namespace,
                "review_set": {"document_type": "receiver_review_set_design", "design_revision": 2,
                    "review_set_id": "rb-storage-history", "revision": 1, "namespace": namespace,
                    "population_basis_refs": [basis], "collection_scope": "receiver_selected_set_only", "requirements": []},
                "review_set_selected_at": now, "assessment_cutoff": now, "assessment_time": now,
                "inventory_state": "partial", "collection_basis_ref": basis, "selection_basis_ref": basis,
                "revision_basis_ref": basis, "native_policy_refs": {"s3": None, "signature": None}}
            retained = [*case.values(), *reports]
            previous = None
            destination.mkdir(parents=True, exist_ok=False)
            for stage, report in enumerate(reports, 1):
                originals = {k: v for k, v in case.items() if stage == 2 or k != "observation"}
                originals["reader_report"] = report
                delivery = {"document_type": DELIVERY, "version": 1, "event_id": f"rb-reading-{stage}",
                    "entry_id": f"rb-reading-{stage}", "source_namespace": namespace,
                    "native_input_kind": "restoration-rb-opaque-reading", "received_at": None,
                    "receipt_basis_ref": basis, "originals": {k: box.put(v) for k, v in originals.items()}}
                box.receive(encode(delivery))
                for k, ref in delivery["originals"].items():
                    if box.get(ref) != originals[k]:
                        raise ValueError("original readback differs")
                state = box.run(box.prepare(encode(plan))["run_id"])
                if state["status"] != "completed":
                    raise ValueError("inbox evaluation did not complete")
                storage_raw = box.get(state["report_ref"])
                storage = json.loads(storage_raw)
                if storage["review_set_status"] != "selected_empty" or storage["native_calls"]:
                    raise ValueError("unexpected native assessment in storage example")
                if previous and (state["previous_id"] != previous[0]["run_id"] or box.get(previous[0]["report_ref"]) != previous[1]):
                    raise ValueError("earlier storage report was not retained")
                (destination / f"reader-report-{stage}.json").write_bytes(report)
                (destination / f"storage-report-{stage}.json").write_bytes(storage_raw)
                previous = state, storage_raw
            box.export(state["run_id"], destination / "inbox-export")
            exported = [p.read_bytes() for p in (destination / "inbox-export/objects").iterdir()]
            if not all(raw in exported for raw in retained):
                raise ValueError("export omitted selected originals or reports")
            summary = {"originals_and_both_readings_retained": True, "previous_storage_report_preserved": True,
                       "storage_revision": state["revision"], "storage_scope": "empty_set_history_only",
                       "native_rb_in_required_records": False, "report_refs": [identity(r) for r in reports]}
            (destination / "SUMMARY.json").write_bytes(encode(summary) + b"\n")
            return summary
        finally:
            box.close()


def run(destination, with_inbox=False, source_root=None):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    summaries = []
    for scenario in ("no_commit", "commit_observed", "not_established"):
        case = inputs(scenario)
        report = receive(destination / scenario, **case)
        summaries.append({"scenario": scenario, "record_check": report["record_check"],
                          "receiver_binding": report["receiver_binding"]["status"],
                          "observation_check": report["observation_check"]})
    result = {"sample_kind": "synthetic", "results": summaries}
    if with_inbox:
        result["inbox"] = store_history(destination / "inbox-history", inputs("commit_observed"), source_root or HERE.parents[1])
    (destination / "SUMMARY.json").write_bytes(encode(result) + b"\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--with-inbox", action="store_true")
    parser.add_argument("--source-root", type=Path, help="trusted VATE source for optional Inbox")
    args = parser.parse_args()
    print(json.dumps(run(args.out, args.with_inbox, args.source_root)))
