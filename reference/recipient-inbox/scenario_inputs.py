"""Synthetic receiver choices over the repository's unchanged saved S3 originals."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

from recipient_inbox import DELIVERY, PLAN, REF_FIELDS, encoded

HERE = Path(__file__).resolve().parent
ROOT = next(path for path in HERE.parents if (path / "reference/required-records/required_records.py").is_file())
SAVED = ROOT / "reference/s3-observation-example/inputs/seaweedfs-4.48/instance"
BUNDLE = SAVED / "bundles/supported"
EXAMPLE = ROOT / "reference/required-records/examples/operation-B-missing"
NAMESPACE = "urn:example:receiver:archive-intake"
EARLY = "2026-10-20T10:00:00Z"
LATE = "2026-10-20T13:30:00Z"


def plan_for(inbox, *, s3_instance=SAVED):
    def relocate(value):
        if type(value) is dict and set(value) == REF_FIELDS:
            root = {"inputs": EXAMPLE, "repository": ROOT}[value["path_base"]]
            raw = (root / value["path"]).read_bytes()
            if len(raw) != value["byte_length"] or hashlib.sha256(raw).hexdigest() != value["digest"]["value"]:
                raise ValueError("saved example input does not match its published raw identity")
            return inbox.put(raw, value["media_type"])
        if type(value) is dict:
            return {key: relocate(item) for key, item in value.items()}
        if type(value) is list:
            return [relocate(item) for item in value]
        return value
    review = relocate(json.loads((EXAMPLE / "review-set.json").read_bytes()))
    basis = inbox.put(b"Synthetic receiver intake, requirements and arrival assertions. Saved S3 originals; no live service.\n",
                      "text/plain")
    return {"document_type": PLAN, "version": 1, "receiver_id": "urn:example:durable-receiver",
            "review_set": review, "review_set_selected_at": "2026-10-20T09:00:00Z",
            "assessment_cutoff": "2026-10-20T13:00:00Z", "assessment_time": "2026-10-20T14:00:00Z",
            "inventory_state": "closed", "collection_basis_ref": basis, "selection_basis_ref": basis,
            "native_policy_refs": {"s3": inbox.put((s3_instance / "receiver-policy.json").read_bytes()), "signature": None},
            "revision_basis_ref": basis}


def delivery(inbox, plan, event_id, originals, *, entry_id="A", received=EARLY, proofs=None,
             kind="receipt_pair", namespace=NAMESPACE):
    value = {"document_type": DELIVERY, "version": 1, "event_id": event_id, "entry_id": entry_id,
             "source_namespace": namespace, "native_input_kind": kind, "received_at": received,
             "receipt_basis_ref": plan["collection_basis_ref"],
             "originals": {name: inbox.put(raw, "application/octet-stream") for name, raw in originals.items()}}
    if proofs is not None:
        value["detached_proofs"] = {name: inbox.put(raw) for name, raw in proofs.items()}
    return encoded(value)


def next_plan(plan, *, later=True):
    value = deepcopy(plan)
    if later:
        value.update(assessment_cutoff="2026-10-20T15:00:00Z", assessment_time="2026-10-20T16:00:00Z")
    return value


def signature_fixture(openssl):
    sys.path.insert(0, str(ROOT / "reference/recipient-signature-authority"))
    from trial_fixtures import Fixtures
    return Fixtures(openssl)


def coverage(report):
    return {row["requirement_id"]: row["record_coverage"] for row in report["requirements"]}


def timings(report):
    return {row["requirement_id"]: row["timeliness"] for row in report["requirements"]}
