#!/usr/bin/env python3
"""Run four local examples; preserve their originals and any existing report."""
import argparse
import json
from pathlib import Path

from recipient_example import HERE, RecipientExample, digest


def run_examples() -> dict:
    provenance = json.loads((HERE / "INPUT-PROVENANCE.json").read_text())
    for entry in provenance["inputs"]:
        if "path" in entry:
            if digest((HERE / entry["path"]).read_bytes()) != entry["raw_file_sha256"]:
                raise ValueError("example input changed: " + entry["path"])
    reviewer = RecipientExample()
    results = []
    for name, admission_path, post_path, expected in (
        ("R17", "inputs/R17/admission.json", "inputs/R17/post.json", "matched"),
        ("R86", "inputs/R86/admission.json", "inputs/R86/post.json", "matched"),
        ("R52", "inputs/R52/admission.json", None, "not_assessed"),
        ("synthetic_runtime_mismatch", "inputs/R17/admission.json", "inputs/synthetic-runtime-mismatch.json", "mismatch"),
    ):
        result = reviewer.assess((HERE / admission_path).read_bytes(),
                                 (HERE / post_path).read_bytes() if post_path else None)
        results.append({"example": name, "synthetic": name == "synthetic_runtime_mismatch",
                        "expected_local_assessment": expected, "assessment": result})
    return {
        "scope": "local reuse of existing receipt checks; no original action or external SUT executed",
        "all_expected_assessments_observed": all(r["assessment"]["record_linkage"] == r["expected_local_assessment"] for r in results),
        "examples": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="New JSON report path; existing files are never overwritten")
    args = parser.parse_args()
    result = run_examples()
    encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        with args.output.open("x") as handle:
            handle.write(encoded)
    print(json.dumps({"all_expected_assessments_observed": result["all_expected_assessments_observed"],
                      "examples": [{"example": r["example"], "record_linkage": r["assessment"]["record_linkage"]}
                                   for r in result["examples"]]}, ensure_ascii=False))
    return 0 if result["all_expected_assessments_observed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
