"""Generate synthetic local file-set originals and an A/C package for an A/B/C inventory."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from package_intake import encoded, save, sha

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reference/runtime-support"))
from file_set_fixture import capture_cases, operation_context, receipt_pair, tree_hashes

CASES = {"A": "allow", "B": "response-loss-reconciled", "C": "attenuate"}


def generate(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    producer = output / "producer"
    reports = capture_cases(ROOT, producer)
    originals = tree_hashes(producer)
    jobs = []
    for label, scenario in CASES.items():
        admission, _ = receipt_pair(producer / scenario)
        context = operation_context(admission)
        jobs.append({"job_label": label, "operation_id": context["transaction_id"],
                     "expected_context": context, "expected_record_kind": "post_execution"})
    inventory = {"kind": "local_lab_dispatch_inventory", "version": 1,
                 "namespace": "local-package-example",
                 "provenance": "Synthetic same-maintainer requirements from producer admission originals, "
                               "selected before package membership; no external arrival observation.",
                 "jobs": jobs}
    inventory_raw = encoded(inventory)
    save(output / "inventory.json", inventory_raw, raw=True)
    package = output / "package"
    package.mkdir()
    membership = {"kind": "local_selected_receipt_package", "version": 1,
                  "namespace": inventory["namespace"], "inventory_sha256": sha(inventory_raw),
                  "files": [], "deliveries": []}
    # B remains required even though its originals are excluded from this package.
    for label in ("A", "C"):
        slots = {}
        for slot, raw in zip(("admission", "post"), receipt_pair(producer / CASES[label])):
            name = label + "-" + slot + ".json"
            save(package / name, raw, raw=True)
            slots[slot] = name
            membership["files"].append({"path": name, "bytes": len(raw), "sha256": sha(raw)})
        membership["deliveries"].append({"entry_id": "entry-" + label, "originals": slots})
    save(output / "membership.json", membership)
    if tree_hashes(producer) != originals:
        raise ValueError("producer originals changed while selecting the package")
    save(output / "PROVENANCE.json", {
        "kind": "synthetic_local_package_example", "version": 1,
        "producer": "repository execution-evidence-demo, local file-set scenarios",
        "cases": CASES, "required_jobs": list(CASES), "selected_package_jobs": ["A", "C"],
        "producer_files_sha256": originals, "native_reports": reports,
        "inventory_sha256": sha(inventory_raw), "membership_sha256": sha(encoded(membership)),
        "arrival_meaning": "The intake command records its own local import time.",
        "not_established": ["external adoption", "independent inventory authority", "external arrival times"]})
    return {"output": str(output), "required_jobs": list(CASES), "selected_package_jobs": ["A", "C"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(generate(args.output), sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"error_type": type(exc).__name__, "detail": str(exc)[:512]}))
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
