"""Replay fixed synthetic exports, preserve originals, optionally register in Inbox."""
import argparse
import json
from pathlib import Path
import sys

from fixture_data import CASE_IDS
from receive import NOT_ASSESSED, assess, encoded, raw_ref, read_file, receive_files, sha
from inbox_connection import retain

HERE = Path(__file__).resolve().parent


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inbox-source-root", type=Path)
    args = parser.parse_args(argv)
    args.out.mkdir(mode=0o700)  # Existing outputs are never overwritten.
    manifest = json.loads((HERE / "fixtures/MANIFEST.json").read_bytes())
    pins = json.loads((HERE / "SOURCE-MANIFEST.json").read_bytes())
    inbox = None
    summary = {"fixture_origin": "synthetic_not_native_sdk_capture", "cases": [],
               "documented_upstream_commit": pins["ref"]}
    try:
        if args.inbox_source_root:
            root = args.inbox_source_root.resolve(strict=True)
            module = root / "reference/recipient-inbox/recipient_inbox.py"
            if "recipient_inbox" in sys.modules:
                require(Path(sys.modules["recipient_inbox"].__file__).resolve() == module,
                        "conflicting_inbox_module")
            sys.path.insert(0, str(module.parent))
            from recipient_inbox import Engine, Inbox
            inbox = Inbox(args.out / "inbox.sqlite3", Engine(root), create=True)
        for case_id in CASE_IDS:
            source = HERE / "fixtures" / case_id
            inputs = {name: read_file(source / (name + ".json"), name)
                      for name in ("selection", "request", "capture")}
            require({k: raw_ref(v) for k, v in inputs.items()} == manifest["cases"][case_id],
                    "fixture_hash_mismatch")
            report = receive_files(**{k: source / (k + ".json") for k in inputs},
                                   output=args.out / case_id)
            retained = {name: read_file(args.out / case_id / (name + ".json"), name) for name in inputs}
            require(retained == inputs, "bundle_original_mismatch")
            require(assess(**retained) == report, "reassessment_mismatch")
            require(report["status"] == "inspected", "example_not_inspected")
            require(all(report["checks"][k]["status"] == "not_assessed" for k in NOT_ASSESSED),
                    "unexpected_verification_claim")
            row = {"case": case_id, "report": raw_ref(encoded(report)),
                   "original_bytes_preserved": True, "reassessment_equal": True,
                   "observations": report["observations"], "is_execution_ticket": False}
            if inbox:
                stored = retain(inbox, **inputs)
                duplicate = retain(inbox, **inputs)
                require(not stored["registration"]["duplicate"] and duplicate["registration"]["duplicate"],
                        "inbox_idempotency")
                require(assess(**{k: inbox.get(stored["originals"][k]) for k in inputs}) == report,
                        "inbox_reassessment")
                row["inbox"] = stored
            summary["cases"].append(row)
        (args.out / "SUMMARY.json").write_bytes(encoded(summary))
        print(encoded({"cases": len(summary["cases"]), "originals_and_reassessment": "passed",
                       "inbox_registered": inbox is not None, "is_execution_ticket": False}).decode(), end="")
    finally:
        if inbox is not None:
            inbox.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
