#!/usr/bin/env python3
"""Replay JSON vectors against the local API; no original captures are changed."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import sys

from vate_recipient import API_CONTRACT, AssessmentError, RecipientAssessor

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "reference/runtime-support"))
from historical import historical_api


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def read_ref(root, ref):
    raw = (root / ref["path"]).read_bytes()
    if len(raw) != ref["byte_length"] or hashlib.sha256(raw).hexdigest() != ref["raw_sha256"]:
        raise ValueError("vector source changed: " + ref["path"])
    return raw


def at(value, path):
    for part in path:
        value = value[part]
    return value


def edit_raw(raw, edits):
    value = json.loads(raw)
    for edit in edits:
        parent = at(value, edit["path"][:-1])
        parent[edit["path"][-1]] = edit["value"]
    return encode(value)


def assess_vector(assessor, root, vector, temporary):
    inputs = vector["inputs"]
    edits = vector.get("synthetic_json_edits", {})
    if vector["evaluator"] == "receipt_pair":
        raw = {name: read_ref(root, inputs[name]) if inputs[name] is not None else None
               for name in ("admission", "post")}
        for name, mutations in edits.items():
            raw[name] = edit_raw(raw[name], mutations)
        return assessor.assess_receipts(raw["admission"], raw["post"], requested_checks=vector.get("requested_checks", []))
    bundle_ref = inputs["bundle"]
    original = root / bundle_ref["path"]
    # These hashes identify vector source files, not a runtime assessment snapshot.
    expected_names = {Path(ref["path"]).name for ref in bundle_ref["files"]}
    if {p.name for p in original.iterdir()} != expected_names:
        raise ValueError("vector bundle inventory changed")
    for ref in bundle_ref["files"]:
        read_ref(root, ref)
    policy = read_ref(root, inputs["receiver_policy"])
    selected = original
    if edits:
        selected = temporary / vector["id"]
        shutil.copytree(original, selected)
        for name, mutations in edits.items():
            if name == "receiver_policy":
                policy = edit_raw(policy, mutations)
            else:
                path = selected / name
                path.write_bytes(edit_raw(path.read_bytes(), mutations))
        # Synthetic controls update the existing local inventory after changing a
        # disclosed member. Source pins and native captures are never resealed.
        manifest = json.loads((selected / "manifest.json").read_bytes())
        for name, ref in manifest["artifacts"].items():
            raw = (selected / name).read_bytes()
            ref.update(digest={"alg": "sha-256", "value": hashlib.sha256(raw).hexdigest()}, byte_length=len(raw))
        (selected / "manifest.json").write_bytes(encode(manifest))
    return assessor.assess_s3(selected, policy, requested_checks=vector.get("requested_checks", []))


def verify_result(root, vector, result):
    expected = vector["expected"]
    if "native_result_ref" in expected:
        ref = expected["native_result_ref"]
        native = at(json.loads(read_ref(root, ref)), ref["value_path"])
        if encode(result["native_result"]) != encode(native):
            raise AssertionError("complete native result differs")
    for item in expected.get("native_values", []):
        if encode(at(result["native_result"], item["path"])) != encode(item["value"]):
            raise AssertionError("native value differs: " + repr(item["path"]))
    if result["requested_checks"]["unsupported"] != expected.get("unsupported_checks", []):
        raise AssertionError("unsupported requested checks differ")


def run_vectors(root=None, vectors_path=None):
    historical, frozen = historical_api(ROOT)
    root = Path(root) if root is not None else frozen
    vectors_path = Path(vectors_path) if vectors_path is not None else root / "reference/recipient-assessment/vectors.json"
    document = json.loads(vectors_path.read_bytes())
    if document["vector_contract"] != "vate-recipient-assessment-vectors-v1":
        raise ValueError("unknown vector contract")
    assessor = historical.RecipientAssessor(expected_api_contract=document["api_contract"], source_root=root)
    records = []
    with tempfile.TemporaryDirectory(prefix="vate-recipient-vectors-") as directory:
        for vector in document["vectors"]:
            record = {"id": vector["id"], "basis": vector["basis"], "verification": "matched"}
            try:
                result = assess_vector(assessor, root, vector, Path(directory))
                verify_result(root, vector, result)
            except (historical.AssessmentError, AssertionError, OSError, ValueError, KeyError) as exc:
                record.update(verification="different_or_unavailable", detail=str(exc))
            records.append(record)
    return {"api_contract": API_CONTRACT, "scope": "historical API vector replay at e845a6a8", "vectors": records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, help="Explicit copy of the fixed historical runtime and vector inputs")
    args = parser.parse_args()
    report = run_vectors(args.source_root)
    print(json.dumps(report, indent=2))
    return 0 if all(r["verification"] == "matched" for r in report["vectors"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
