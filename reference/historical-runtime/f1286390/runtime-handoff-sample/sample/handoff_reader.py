"""Read-only evidence assessment. Does not import the provider or execute effects."""
import argparse
from pathlib import Path

from handoff_contract import (Context, PROFILE, ZERO, MAX_EVENTS, MAX_JOURNAL_BYTES, RESERVED_EVENT_BYTES,
                              encode, decode, need, exact, integer)
from handoff_contract import unb64, effect_state, linkage, post_receipt, iso, sha, reserved_event_count
from handoff_model import replay, validate_inventory
from dependencies import crypto


def assess(context_raw, expected_operation_raw, bundle_raw):
    context = Context(context_raw)
    expected_operation = context.operation(decode(expected_operation_raw))
    need(expected_operation_raw == encode(expected_operation), "noncanonical expected operation")
    bundle = decode(bundle_raw)
    exact(bundle, {"profile", "context_sha256", "store", "operation_id", "records", "head", "inventory", "observed_at",
                   "is_execution_ticket"})
    need(bundle["profile"] == PROFILE and bundle["context_sha256"] == context.digest and
         bundle["store"] == context.data["store"] and bundle["is_execution_ticket"] is False, "selected bundle context")
    records = bundle["records"]
    need(isinstance(records, list) and len(records) <= MAX_EVENTS and
         sum(len(unb64(r["raw"])) for r in records) <= MAX_JOURNAL_BYTES, "bundle capacity")
    need(bundle["head"] == (records[-1]["sha256"] if records else ZERO), "bundle head")
    state = replay(context, records)
    reserved = reserved_event_count(state)
    need(len(records) + reserved <= MAX_EVENTS and sum(len(unb64(r["raw"])) for r in records) +
         reserved * RESERVED_EVENT_BYTES <= MAX_JOURNAL_BYTES, "reservation capacity mismatch")
    need(bundle["operation_id"] == expected_operation["operation_key"], "selected operation mismatch")
    op = state["operations"][bundle["operation_id"]]
    need(op["operation"] == expected_operation, "operation originals mismatch")
    need(integer(bundle["observed_at"]) >= state["clock_high"], "observation before recorded history")
    validate_inventory(bundle["inventory"])
    return {"profile": PROFILE, "bundle_sha256": sha(bundle_raw), "operation_id": bundle["operation_id"],
            "generation": op["generation"], "revision": op["revision"], "runtime": op["runtime"],
            "effect_state": effect_state(op, bundle["inventory"]), "acceptance_count": int(op["accepted"] is not None),
            "accepted": op["accepted"], "unknown": op["unknown"], "handoffs": op["handoff_results"],
            "later_observations": op["observations"], "linkage": linkage(op),
            "post_execution_receipt": post_receipt(op, iso(bundle["observed_at"])), "clock_uncertain": state["clock_bad"],
            "subjects": state["subjects"], "as_of_observation": bundle["observed_at"], "is_execution_ticket": False,
            "evidence_boundary": "selected context and submitted history; provider-reported effects/exclusion; no independent completeness proof"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--operation", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    args = parser.parse_args()
    result = assess(crypto.safe_read(args.context), crypto.safe_read(args.operation), crypto.safe_read(args.bundle))
    print(encode(result).decode())
