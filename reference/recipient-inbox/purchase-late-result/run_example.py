"""Capture two purchase histories and replay each from its latest Inbox export."""

import argparse
from contextlib import closing
import json
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import trial


def run_stage(*args):
    subprocess.run([sys.executable, "-IB", str(HERE / "trial.py"), *args], check=True)


def purchase_history(output, post, case):
    history = output / ("purchase-" + post)
    run_stage("before", history)
    run_stage("after", history, "--post", post)
    # Give the replay process only the latest export as its evidence input.
    export = output / ("export-" + post)
    shutil.copytree(history / "after/export", export)
    replay = output / ("replay-" + post)
    run_stage("replay", export, replay)

    expected = json.loads(trial.original("expected.json"))["cases"][case]
    chosen = trial.raw_ref(trial.original("receiver/A.json"))
    expected_post = trial.raw_ref(trial.original(f"deliveries/{post}/post-execution.json"))
    admission = trial.raw_ref(trial.original("deliveries/A/admission-receipt.json"))
    rows = []
    for revision, stage in enumerate(("before", "after"), 1):
        folder = history / stage
        recorded = (folder / "purchase-decision.json").read_bytes()
        rebuilt = (replay / f"revision-{revision}-purchase-decision.json").read_bytes()
        trial.check(recorded == rebuilt, f"{case}/{stage}: purchase decision changed on replay")
        decision = json.loads(rebuilt)
        first = stage == "before"
        expected_link = "not_assessed" if first else expected["record_linkage"]
        actual_post = decision["post"]["ref"] if decision["post"] else None
        trial.check(decision["saved_request"] == chosen and decision["admission"]["ref"] == admission,
                    f"{case}/{stage}: selected request or admission changed")
        trial.check(decision["binding"]["pass"] is True and decision["binding"]["binding_requirement_met"] is True,
                    f"{case}/{stage}: request and admission did not match")
        trial.check(actual_post == (None if first else expected_post) and decision["record_linkage"] == expected_link,
                    f"{case}/{stage}: wrong result receipt or linkage")
        if first:
            trial.check(decision["receipt_input_issues"] == [{"input": "post", "kind": "not_supplied"}],
                        f"{case}: missing result was not recorded")
            for other in ("A", "B"):
                ref = trial.raw_ref(trial.original(f"deliveries/{other}/post-execution.json"))
                trial.check(not (folder / "export" / ref["path"]).exists(), "first export contains a result")
        rows.append({"revision": revision, "at": decision["cutoff"],
                     "selected_request_matches_admission": decision["binding"]["pass"],
                     "record_linkage": decision["record_linkage"], "replayed_decision_sha256": trial.sha(rebuilt)})
    return rows


def cutoff_control(output):
    """Register all deliveries first and vary only the cutoff at one assessment time."""
    output.mkdir()
    rows = []
    with closing(trial.Inbox(output / "inbox.sqlite3", trial.Engine(trial.ROOT), create=True)) as box:
        plan = trial.choose(box)
        trial.receive_approval(box, plan)
        trial.receive_result(box, plan, "A")
        plan["assessment_time"] = trial.FINAL
        for cutoff, membership, linkage in [(trial.EARLY, "after", "not_assessed"),
                                           (trial.FINAL, "included", "matched")]:
            plan["assessment_cutoff"] = cutoff
            if rows:
                plan["revision_basis_ref"] = box.put(b"Extend the cutoff to the result delivery.\n", "text/plain")
            state = box.run(box.prepare(trial.encoded(plan))["run_id"])
            trial.check(state["status"] == "completed" and state["max_delivery_sequence"] == 3,
                        "cutoff control changed the intake")
            report = json.loads(box.get(state["report_ref"]))
            decision = trial.purchase_decision(report, box.get)
            post = decision["post"]
            trial.check(post["cutoff_membership"] == membership and decision["record_linkage"] == linkage,
                        "cutoff control produced an unexpected result")
            rows.append({"assessment_time": plan["assessment_time"], "cutoff": cutoff,
                         "membership": post["cutoff_membership"], "record_linkage": decision["record_linkage"],
                         "post_ref": post["ref"]})
        trial.check(rows[0]["post_ref"] == rows[1]["post_ref"], "cutoff control used different results")
        box.export(state["run_id"], output / "export")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="new directory for databases, exports and decisions")
    output = parser.parse_args().output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    histories = {
        "A": purchase_history(output, "A", "select-a-receive-a"),
        "B": purchase_history(output, "B", "select-a-receive-a-with-b-result"),
    }
    trial.check(histories["A"][0] == histories["B"][0], "the pre-result purchase decisions differ")
    summary = {"histories": histories, "same_inventory_cutoff": cutoff_control(output / "cutoff")}
    trial.save(output / "SUMMARY.json", summary)
    for post, rows in histories.items():
        print(f"Result {post}: {rows[0]['record_linkage']} -> {rows[1]['record_linkage']}")
    print("Saved both revisions and the cutoff control in", output / "SUMMARY.json")


if __name__ == "__main__":
    main()
