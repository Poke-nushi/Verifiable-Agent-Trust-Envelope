"""Replay the independent reader against fixed inputs and saved native readings."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from receive import assess, load_key

HERE = Path(__file__).resolve().parent


def check_inventory():
    inventory = json.loads((HERE / "samples/SOURCES.json").read_text(encoding="utf-8"))
    for item in inventory["files"]:
        data = (HERE / item["path"]).read_bytes()
        if len(data) != item["bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError("sample inventory mismatch")


def run():
    check_inventory()
    saved = json.loads((HERE / "samples/native-replay.json").read_text(encoding="utf-8"))
    rows = []
    equivalent = {"PASS": "matched", "FAIL": "mismatched", "INCONCLUSIVE": "not_assessed"}
    for row in saved["cases"]:
        group = "published" if row["origin"] == "published" else "regenerated"
        package = HERE / "samples" / group / (row["case"] + ".uibc")
        actual_files = {str(p.relative_to(package)): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in sorted(package.rglob("*")) if p.is_file()}
        if actual_files != row["inputs"]:
            raise ValueError("saved native result input mismatch")
        key = (load_key(package.parent / "DISPOSABLE-TEST-KEY.hex", package)
               if row["mode"] == "strict" else None)
        received = assess(package, key=key)
        native = {c["id"]: c["result"] for c in row["native"]["checks"]}
        comparison = {name: check["status"] == equivalent[native[check["upstream_check"]]]
                      for name, check in received["checks"].items()}
        if not all(comparison.values()):
            raise ValueError("independent reader diverged on a selected check")
        rows.append({"origin": row["origin"], "case": row["case"], "mode": row["mode"],
                     "native_saved_result": row["native"], "vate": received,
                     "selected_check_agreement": comparison})
    return {"kind": "uibc-selected-check-comparison", "cases": rows,
            "native_execution": "saved_replay_only", "vate_execution": "rerun_on_pinned_sample_bytes",
            "compared_checks": ["S4", "S5", "S6"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="new JSON file; existing files are not overwritten")
    args = parser.parse_args()
    report = run()
    if args.output:
        with args.output.open("x", encoding="utf-8") as output:
            output.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    for row in report["cases"]:
        print(row["origin"], row["case"], row["mode"],
              {n: c["status"] for n, c in row["vate"]["checks"].items()})
    return 0


if __name__ == "__main__":
    sys.exit(main())
