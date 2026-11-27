"""Run the purchase-A late-arrival trial using the existing Recipient Inbox."""

import argparse
from contextlib import closing
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
for module_dir in ("recipient-inbox", "request-binding"):
    sys.path.insert(0, str(ROOT / "reference" / module_dir))

from recipient_inbox import CONTRACT, DELIVERY, PLAN, PROCESS_ENV, Engine, Inbox, encoded, raw_ref, read_file, sha
from request_binding import LOADED_SOURCE_SHA256, assess_request_binding, core, reference

NAMESPACE = "urn:example:receiver:purchase-A"
FILES = ("admission-request.json", "original.json", "effective.json")
MANIFEST_SHA = "fc62455a82283c8eb29edf4a0270063ade130112c50f892e2a6a93fe4e469e76"
DAY = "2026-11-12T00:"
SELECTED, ADMISSION, EARLY, LATE, FINAL = (DAY+t+"Z" for t in (
    "00:00", "00:02", "01:00", "02:00", "03:00"))


def check(condition, detail):
    if not condition:
        raise ValueError(detail)


def read_json(path):
    return json.loads(path.read_bytes())


def save(path, value):
    with path.open("xb") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False).encode() + b"\n")


def original(relpath):
    directory = ROOT / "reference/request-binding/receiver-selection"
    manifest = (directory / "SHA256SUMS").read_bytes()
    check(sha(manifest) == MANIFEST_SHA, "unrecognized purchase vector set")
    pins = {name: digest for digest, name in (line.split("  ", 1) for line in manifest.decode().splitlines())}
    data = (directory / relpath).read_bytes()
    check(sha(data) == pins[relpath], "fixture bytes differ: " + relpath)
    return data


def binding_reader():
    check(LOADED_SOURCE_SHA256 == sha((ROOT/"reference/request-binding/request_binding.py").read_bytes()),
          "loaded purchase reader differs from selected files")
    check(core.LOADED_SOURCE_SHA256 == sha((ROOT/"reference/vate-verifier-core/vate_verifier_core.py").read_bytes()),
          "loaded verifier core differs from selected files")
    return {"fixture_manifest_sha256": MANIFEST_SHA, "purchase_reader_sha256": LOADED_SOURCE_SHA256,
            "verifier_core_sha256": core.LOADED_SOURCE_SHA256, "trial_sha256": sha(Path(__file__).read_bytes())}


def choose(box):
    saved = box.put(original("receiver/A.json"))
    choice = box.put(encoded({"selected_request_ref": saved, "reader": binding_reader(),
        "reason": "Receiver selected its saved purchase A before receiving the admission."}))
    collection = box.put(b"Only the events registered in this local synthetic intake are observed.\n", "text/plain")
    return {"document_type": PLAN, "version": 1, "receiver_id": "purchase-example-receiver",
            "review_set": {"document_type": "receiver_review_set_design", "design_revision": 2,
                "review_set_id": "purchase-A-receipts", "revision": 1, "namespace": NAMESPACE,
                "population_basis_refs": [saved], "collection_scope": "receiver_selected_set_only",
                "requirements": []},
            "review_set_selected_at": SELECTED, "assessment_cutoff": EARLY, "assessment_time": EARLY,
            "inventory_state": "partial", "selection_basis_ref": choice, "collection_basis_ref": collection,
            "native_policy_refs": {"s3": None, "signature": None}, "revision_basis_ref": None}


def receive(box, plan, event_id, entry_id, kind, when, parts):
    refs = {key: box.put(value) for key, value in parts.items()}
    event = {"document_type": DELIVERY, "version": 1, "source_namespace": NAMESPACE,
             "event_id": event_id, "entry_id": entry_id, "native_input_kind": kind,
             "received_at": when, "receipt_basis_ref": plan["collection_basis_ref"], "originals": refs}
    return box.receive(encoded(event))


def receive_approval(box, plan):
    receive(box, plan, "purchase-inputs", "sender-inputs", "local_purchase_input_bytes", ADMISSION,
            {name: original(f"deliveries/A/{name}") for name in FILES})
    receive(box, plan, "admitted", "purchase-receipts", "receipt_pair", ADMISSION,
            {"admission": original("deliveries/A/admission-receipt.json")})


def receive_result(box, plan, post):
    receive(box, plan, "result-arrived", "purchase-receipts", "receipt_pair", LATE,
            {"post": original(f"deliveries/{post}/post-execution.json")})


def purchase_decision(report, get):
    selection = report["selection"]
    choice = json.loads(get(selection["selection_basis_ref"]))
    check(choice["reader"] == binding_reader(), "purchase reader or receiving procedure changed")
    review = json.loads(get(selection["review_set_ref"]))
    check(review["population_basis_refs"] == [choice["selected_request_ref"]], "saved request selection changed")
    snapshot = json.loads(get(selection["submission_snapshot_ref"]))
    entries = {entry["entry_id"]: entry for entry in snapshot["entries"]}
    pair = entries["purchase-receipts"]["originals"]
    inputs = entries["sender-inputs"]["originals"]
    check(set(inputs) == set(FILES) and all(e["cutoff_membership"] == "included" for e in inputs.values()),
          "missing purchase preimages at the selected cutoff")
    check(pair["admission"]["cutoff_membership"] == "included", "admission unavailable")
    payloads = [get(inputs[key]["ref"]) for key in FILES]
    binding = assess_request_binding(get(pair["admission"]["ref"]), {reference(b)["uri"]: b for b in payloads},
        expected_admission_request_ref=reference(get(choice["selected_request_ref"])))

    check(report["review_set_status"] == "selected_empty" and report["requirements"] == []
          and report["invocation_errors"] is False, "unexpected inventory review")
    call, = report["native_calls"]
    receipt_entry = next(e for e in report["entries"] if e["entry"]["entry_id"] == "purchase-receipts")
    check(call["kind"] == "receipt" and receipt_entry["native_result_refs"] == [call["call_id"]],
          "wrong report for receipt pair")
    for name, event in pair.items():
        included = event is not None and event["cutoff_membership"] == "included"
        identity = call["result"]["inputs"][name]
        check(identity["supplied"] is included and identity["raw_sha256"] ==
              (sha(get(event["ref"])) if included else None), "receipt call used the wrong original")
    native = call["result"]["native_result"]
    return {"cutoff": selection["assessment_cutoff"], "saved_request": choice["selected_request_ref"],
            "admission": pair["admission"], "post": pair["post"], "record_linkage": native["record_linkage"],
            "receipt_input_issues": native["input_issues"], "binding": binding}


def capture(work, post=None):
    first = post is None
    if first:
        work.mkdir(parents=True, exist_ok=False)
    stage = "before" if first else "after"
    folder = work / stage
    folder.mkdir(exist_ok=False)
    engine = Engine(ROOT)
    with closing(Inbox(work / "inbox.sqlite3", engine, create=first)) as box:
        if first:
            plan = choose(box)
            receive_approval(box, plan)
        else:
            old = read_json(work / "before/status.json")
            old_chain = read_json(work / "before/export/runs.json")
            old_job = json.loads(box.get(old_chain["runs"][0]["job_ref"]))
            check(old_job["run_id"] == old["run_id"] and box.status(old["run_id"]) == old,
                  "before revision was not the stored head")
            plan = json.loads(box.get(old_job["plan_ref"]))
            receive_result(box, plan, post)
            plan.update(assessment_cutoff=FINAL, assessment_time=FINAL,
                        revision_basis_ref=box.put(b"One post receipt arrived after the first cutoff.\n", "text/plain"))
        state = box.run(box.prepare(encoded(plan))["run_id"])
        check(state["status"] == "completed" and state["revision"] == (1 if first else 2), state)
        check(state["head"] == state["run_id"] and state["max_delivery_sequence"] == (2 if first else 3),
              "unexpected history or delivery count")
        report = json.loads(box.get(state["report_ref"]))
        decision = purchase_decision(report, box.get)
        if not first:
            check(state["previous_id"] == old["run_id"] and report["previous"]["previous_report_ref"] == old["report_ref"],
                  "revision 2 does not reference revision 1")
            check(box.get(old["report_ref"]) == (work/"before/export/report.json").read_bytes(),
                  "first report bytes changed after arrival")
        save(folder / "status.json", state)
        save(folder / "purchase-decision.json", decision)
        box.export(state["run_id"], folder / "export")
        print(stage, state["revision"], decision["record_linkage"], decision["binding"]["pass"])


def detached(directory, output):
    check(directory.is_dir() and not directory.is_symlink(), "expected a local export directory")
    objects = directory / "objects"
    check(objects.is_dir() and not objects.is_symlink(), "expected local export objects")
    names = {p.name for p in directory.iterdir()}
    check(names == {"MANIFEST.json", "selection.json", "report.json", "runs.json", "objects"},
          "unexpected export layout")
    envelope = json.loads(read_file(directory / "MANIFEST.json"))
    check(envelope["contract"] == CONTRACT, "unknown export contract")
    manifest = envelope["files"]
    actual = names - {"objects"}
    for path in objects.iterdir():
        check(path.is_file() and not path.is_symlink() and len(path.name) == 64
              and all(c in "0123456789abcdef" for c in path.name), "unexpected export object")
        actual.add(f"objects/{path.name}")
    check(actual == set(manifest) | {"MANIFEST.json"}, "export file inventory differs")
    check("MANIFEST.json" not in manifest, "manifest cannot list itself")
    for name, recorded in manifest.items():
        raw = read_file(directory / name)
        check(recorded == {"raw_sha256": sha(raw), "byte_length": len(raw)}, "export file differs: " + name)
        if name.startswith("objects/"):
            check(name == "objects/" + sha(raw), "export object name differs from its digest")

    def get(ref):
        name = ref["path"]
        check(name in manifest, "missing export object")
        data = read_file(directory / name)
        check(ref == raw_ref(data, ref["media_type"]), "reference does not match its bytes")
        return data

    chain = json.loads(read_file(directory / "runs.json"))
    check(chain["contract"] == CONTRACT and len(chain["runs"]) == 2
          and chain["selected"] == chain["runs"][0]["run_id"], "expected two revisions")
    output.mkdir(parents=True, exist_ok=False)
    identity = Engine(ROOT).identity
    previous = None
    for revision, item in enumerate(reversed(chain["runs"]), start=1):
        job = json.loads(get(item["job_ref"]))
        result = json.loads(get(item["result_ref"]))
        check(job["engine_identity"] == identity and item["run_id"] == job["run_id"], "wrong evaluator or job")
        check(item["status"] == result["status"] == "completed" and job["revision"] == revision, "unexpected stored state")
        check(job["previous_id"] == (previous["run_id"] if previous else None), "history link differs")
        selection_raw = get(job["selection_ref"])
        report_raw = get(result["report_ref"])
        old = json.loads(report_raw)
        if previous:
            check(old["previous"]["previous_report_ref"] == previous["report_ref"]
                  and old["previous"]["previous_review_set_ref"] == previous["review_set_ref"], "broken history refs")
            check(selection_raw == read_file(directory / "selection.json")
                  and report_raw == read_file(directory / "report.json"), "top-level export differs")
        compare_to = output / f"revision-{revision}-inbox-report.json"
        subprocess.run([sys.executable, "-B", str(ROOT/"reference/required-records/required_records.py"),
                        "--selection", str(directory/job["selection_ref"]["path"]), "--base", "inbox="+str(directory),
                        "--source-root", str(ROOT), "--output", str(compare_to)], env=PROCESS_ENV, check=True)
        current = read_json(compare_to)
        decision = purchase_decision(current, get)
        save(output/f"revision-{revision}-purchase-decision.json", decision)
        # These purchase receipts have no file paths or measurements other than elapsed time that vary per run.
        times = [v["usage"].pop("elapsed_milliseconds") for v in (old, current)]
        check(all(type(t) is int and t >= 0 for t in times) and encoded(old) == encoded(current),
              "recomputed Inbox report differs beyond elapsed time")
        print(revision, decision["record_linkage"], decision["binding"]["pass"])
        previous = {"run_id": item["run_id"], "report_ref": result["report_ref"], "review_set_ref": job["review_set_ref"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="stage", required=True)
    subs.add_parser("before", help="record the approval before the result arrives").add_argument("work", type=Path)
    after = subs.add_parser("after", help="deliver a result and reassess")
    after.add_argument("work", type=Path)
    after.add_argument("--post", required=True, choices=("A", "B"))
    replay = subs.add_parser("replay", help="recompute both revisions from the latest local export")
    replay.add_argument("export", type=Path)
    replay.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.stage == "replay":
        detached(args.export, args.output)
    else:
        capture(args.work, getattr(args, "post", None))


if __name__ == "__main__":
    main()
