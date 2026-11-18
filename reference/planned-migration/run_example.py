#!/usr/bin/env python3
"""Record a fixed old-program to new-program migration with disposable keys."""
import argparse
import base64
import json
from pathlib import Path
import tempfile

from fixture_support import Fixture, ROOT, b, s
from migration import PlannedMigration, authority, d, source_program


def prepare(fixture, directory):
    selected = s.SnapshotVerifier(expected_profile=s.PROFILE, selection=fixture.selection,
        node=fixture.node, node_sha256=fixture.node_sha)
    stores = {role: authority.AuthorityStore(fixture.old / role, verifier=selected,
        expected_anchor=b.encode(fixture.anchors[role]), clock=lambda: fixture.now) for role in ("publisher", "recipient")}
    state = d.DurableStateStore(fixture.old / "dispatch", expected_anchor=b.encode(fixture.anchors["dispatch"]))
    return PlannedMigration.prepare(directory, source_root=fixture.source,
        dispatch=state, new_selection=fixture.new_selection, **stores)


def set_target(fixture, move, result):
    fixture.target_base = {**fixture.base, "directory": str(move.directory),
                          "anchors": result["anchors"], "selection": result["selection"]}


def save(path, value):
    with path.open("xb") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True).encode() + b"\n")


def run(args):
    source_program(args.source_root)
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    observations = []
    def check(name, observed, expected):
        matched = b.encode(observed) == b.encode(expected)
        observations.append({"case": name, "observed": observed, "expected": expected, "matched": matched})
        if not matched:
            raise RuntimeError("Migration fixture mismatch: " + name)
    with Fixture(output, source_root=args.source_root) as f:
        move = prepare(f, output / "moved")
        save(output / "JOURNAL-ANCHOR.json", json.loads(move.anchor))
        save(output / "OLD-ANCHORS.json", f.anchors)
        result = move.run(old_signer=f.old_signer, new_signer=f.new_signer, clock=lambda: f.now)
        save(output / "MIGRATION.json", result)
        set_target(f, move, result)
        for name, before in f.history.items():
            status = f.worker({"action": "status", "request_id": before["request_id"]}, target=True)["status"]
            check("retained-state-" + name, status["state"], before["state"])
            check("retained-receipt-" + name, status["receipt_ref"]["digest"]["value"], before["receipt_sha256"])
        check("old-program-restart", f.worker({"action": "status", "request_id": f.history["pending"]["request_id"]}, succeeds=False),
              "AUTHORITY_SCHEMA_CHANGED")
        check("fresh-authority-required", f.worker({**f.purchase("-new"), "action": "admit"}, target=True, succeeds=False),
              "AUTHORITY_NOT_AVAILABLE")
        old_key_error = f.install(f.last_snapshot, target=True, succeeds=False)
        check("old-key-rejected", old_key_error, "AUTHORITY_HEADER_INVALID")
        minimum = result["selection"]["minimum_revision"]
        f.install(f.snapshot(minimum, revoked=True, new=True), target=True)
        confirmation = base64.b64decode(result["key_confirmations"]["new"]["token_base64"], validate=True)
        check("key-confirmation-below-live-revision", f.install(confirmation, target=True, succeeds=False), "AUTHORITY_REVISION_INVALID")
        check("revoked-grant-still-denied", f.worker({**f.purchase("-revoked"), "action": "admit"}, target=True, succeeds=False), "CALLER_AUTHORIZATION_FAILED")
        f.install(f.snapshot(minimum + 1, new=True), target=True)
        check("old-pending-permit-requires-new-admission", f.worker({"action": "restore", "request_id": f.history["pending"]["request_id"]},
            target=True, succeeds=False), "STATE_CONFIGURATION_CHANGED")
        for name in ("returned", "unknown"):
            check("consumed-operation-" + name, f.worker({**f.purchase("-" + name, request_suffix="-new"), "action": "admit"},
                target=True, succeeds=False), "DURABLE_OPERATION_ALREADY_ATTEMPTED")
        new = f.worker({**f.purchase("-pending", request_suffix="-new"), "action": "admit", "dispatch": True}, target=True)
        check("new-admission-returned", new["state"], "callback_returned")
        check("new-callback-count", len(new["calls"]), 1)
        check("completed-retry-same-result", move.run(old_signer=None, new_signer=None, clock=None) == result, True)
        check("completed-retry-keeps-new-attempt", f.worker({"action": "status", "request_id": new["request_id"]}, target=True)["status"]["state"],
              "callback_returned")
        save(output / "RUN.json", {"contract": "vate-planned-migration-example-v1", "evidence_kind": "local-recording-callback",
            "source_commit": result["source_commit"], "source_runtime": source_program(args.source_root),
            "target_runtime": result["target_program"], "observations": observations,
            "all_matched": all(item["matched"] for item in observations), "old_key_error": old_key_error,
            "limits": ["synthetic-keys-and-authority", "no-external-resource-effect", "no-power-loss-test"]})
    return {"observations": len(observations), "all_matched": True, "output": str(output)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    print(json.dumps(run(parser.parse_args()), sort_keys=True))
