"""Exercise six synthetic file-set histories through the existing Recipient Inbox."""
import argparse
import importlib.util
from pathlib import Path
from bridge import Receiver, CONTRACT, encode, b64, replay_export, SAMPLE
spec = importlib.util.spec_from_file_location("handoff_inbox_capture", SAMPLE / "run_demo.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
capture = module.run
from fixture import BASE
from handoff_contract import iso

EARLY = iso(BASE + 800)
LATE = iso(BASE + 1000)
FIRST_CUTOFF = iso(BASE + 950)
FINAL_CUTOFF = iso(BASE + 1100)
ASSESSED = iso(BASE + 1200)


def choose(folder, runtime):
    # Explicit fixture receiver choice, made before reading incoming bundle bytes.
    return encode({"contract": CONTRACT, "receiver_id": "local-handoff-recipient",
        "namespace": "urn:vate:local:handoff-inbox", "selected_at": iso(BASE - 100),
        "context_b64": b64((folder / "context.json").read_bytes()),
        "operation_b64": b64((folder / "operation.json").read_bytes()),
        "requirements": [{"id": "expected-post", "runtime": runtime, "record_kind": "post_execution",
                          "due_at": iso(BASE + 900)}]})


def run(destination):
    destination.mkdir(parents=True, exist_ok=False)
    capture(destination / "synthetic-inputs")
    summaries = {}
    for folder in sorted((destination / "synthetic-inputs").iterdir()):
        if not folder.is_dir():
            continue
        selected = choose(folder, "runtime-b" if folder.name == "b-after-unaccepted-a" else "runtime-a")
        work = destination / folder.name
        work.mkdir()
        (work / "receiver-selection.json").write_bytes(selected)
        receiver = Receiver(work / "inbox.sqlite3", selected, create=True)
        try:
            first = receiver.receive("before", (folder / "before-handoff.json").read_bytes(), EARLY)
            frozen = receiver.prepare(FIRST_CUTOFF, ASSESSED)
            final = receiver.receive("after", (folder / "bundle.json").read_bytes(), LATE)
            earlier = receiver.run(frozen["run_id"])
            later = receiver.run(receiver.prepare(FINAL_CUTOFF, ASSESSED)["run_id"])
            receiver.export(later["inbox"]["run_id"], work / "export")
            replayed = replay_export(selected, work / "export")
            result = {"first_intake": first, "later_intake": final,
                      "frozen": earlier, "latest": later, "replay": replayed}
            (work / "RESULT.json").write_bytes(encode(result))
            summaries[folder.name] = {"first_effect": earlier["handoff"]["effect_state"],
                "latest_effect": later["handoff"]["effect_state"], "first_coverage": earlier["record_coverage"],
                "latest_coverage": later["record_coverage"], "linkage": later["handoff"]["linkage"],
                "replay": replayed}
        finally:
            receiver.close()
    (destination / "SUMMARY.json").write_bytes(encode(summaries))
    return summaries


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    print(encode(run(args.out)).decode())
