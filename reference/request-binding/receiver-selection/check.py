#!/usr/bin/env python3
"""Replay purchase receiver-selection vectors or compare another reader's results."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
MANIFEST_SHA256 = "fc62455a82283c8eb29edf4a0270063ade130112c50f892e2a6a93fe4e469e76"


def read_inputs(directory: Path) -> dict[str, bytes]:
    manifest = (directory / "SHA256SUMS").read_bytes()
    if hashlib.sha256(manifest).hexdigest() != MANIFEST_SHA256:
        raise ValueError("SHA256SUMS differs from the fixed vector set")
    inputs = {}
    for line in manifest.decode("ascii").splitlines():
        digest, path = line.split("  ", 1)
        raw = (directory / path).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError(f"SHA-256 mismatch for {path}")
        inputs[path] = raw
    return inputs


def unique_keys(pairs: list[tuple]) -> dict:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def reference_results(vectors: dict, inputs: dict[str, bytes]) -> dict:
    # In the standalone ZIP, the reference tree is next to this script.
    root = HERE if (HERE / "reference").is_dir() else HERE.parents[2]
    sys.path.insert(0, str(root / "reference/recipient-assessment"))
    sys.path.insert(0, str(root / "reference/request-binding"))
    from request_binding import assess_request_binding, reference
    from vate_recipient import AssessmentError, RecipientAssessor

    recipient = RecipientAssessor(expected_api_contract="vate-recipient-assessment-api-v1")
    results = {}
    for case_id, case in vectors["cases"].items():
        delivery = "deliveries/" + case["delivery"] + "/"
        admission = inputs[delivery + "admission-receipt.json"]
        post_delivery = case.get("post_delivery", case["delivery"])
        post = inputs[f"deliveries/{post_delivery}/post-execution.json"]
        try:
            pair = recipient.assess_receipts(admission, post, requested_checks=("receipt_linkage",))
        except AssessmentError as exc:
            raise ValueError(f"{case_id}: {exc}") from exc

        artifacts = {}
        for filename in ("admission-request.json", "original.json", "effective.json"):
            raw = inputs[delivery + filename]
            artifacts[reference(raw)["uri"]] = raw
        selected = case["receiver_request"]
        expected_ref = None if selected is None else reference(inputs[f"receiver/{selected}.json"])
        binding = assess_request_binding(admission, artifacts, expected_admission_request_ref=expected_ref)
        selection = next((check for check in binding["checks"]
                          if check["name"] == "receiver.admission_request"), None)
        if selection is None:
            raise ValueError(f"{case_id}: binding report has no receiver.admission_request check")
        results[case_id] = {
            "record_linkage": pair["native_result"]["record_linkage"],
            "request_binding": {
                "status": binding["status"],
                "pass": binding["pass"],
                "binding_requirement_met": binding["binding_requirement_met"],
                "selection_cause": selection.get("cause"),
            },
        }
    return {"vector_set": vectors["vector_set"], "cases": results}


def compare(actual: object, expected: dict) -> None:
    if not isinstance(actual, dict) or actual.keys() != expected.keys():
        raise ValueError("expected a results object with vector_set and cases")
    if actual["vector_set"] != expected["vector_set"]:
        raise ValueError(f"this package compares reports for {expected['vector_set']}")
    cases = actual["cases"]
    if not isinstance(cases, dict) or cases.keys() != expected["cases"].keys():
        raise ValueError("case IDs must match vectors.json exactly")
    for case_id, want in expected["cases"].items():
        # JSON booleans and numbers are distinct even when Python considers them equal.
        if json.dumps(cases[case_id], sort_keys=True, allow_nan=False) != json.dumps(want, sort_keys=True):
            raise ValueError(f"{case_id}: result differs from expected.json")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compare", metavar="RESULTS.json", type=Path,
                        help="compare your reader's saved results using only the Python standard library")
    args = parser.parse_args()
    try:
        inputs = read_inputs(HERE)
        vectors = json.loads(inputs["vectors.json"])
        if args.compare is None:
            actual = reference_results(vectors, inputs)
            print(json.dumps(actual, indent=2))
        else:
            actual = json.loads(args.compare.read_bytes(), object_pairs_hook=unique_keys)
        compare(actual, json.loads(inputs["expected.json"]))
    except (ImportError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"{len(vectors['cases'])} receiver-selection cases matched", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
