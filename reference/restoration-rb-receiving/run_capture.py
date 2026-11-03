"""Capture a declared file fsync boundary using the existing VATE revocation sample.

Runs local synthetic operations with disposable keys and a controlled clock.
"""
import argparse
import json
from pathlib import Path
import sys
import tempfile

from example_inputs import BASE as EXAMPLE_BASE, inputs, timestamp
from rb_receiving import digest, encode, receive

HERE = Path(__file__).resolve().parent


def run(destination, source_root=None):
    root = Path(source_root).resolve() if source_root else HERE.parents[1]
    sample = root / "reference/post-admission-revocation-sample/sample"
    if not (sample / "fixture.py").is_file():
        raise ValueError("a trusted VATE source tree with the revocation sample is required")
    sys.path.insert(0, str(sample))
    from fixture import BASE, Case, Keys
    from provider import Provider
    from read_evidence import verify
    if BASE != int(EXAMPLE_BASE.timestamp()):
        raise ValueError("revocation sample clock differs from the selected capture profile")
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    results = []
    with tempfile.TemporaryDirectory(prefix="vate-rb-disposable-keys-") as temporary:
        keys = Keys(Path(temporary))
        for scenario in ("no_commit", "commit_observed", "not_established"):
            case = Case(destination / (scenario + "-provider"), keys)
            observer = Provider(case.path, clock=case.clock)
            trace = []
            at = "after_pull" if scenario == "no_commit" else "before_effect"

            def hook(point):
                if point == at:
                    case.clock.value = BASE + 1
                    status = case.signed_status(sequence=2, state="revoked", generated_at=case.clock(), last_changed_at=case.clock())
                    if observer.notify(status)["status"] != "stored":
                        raise ValueError("synthetic revocation was not stored")
                    trace.append({"event": "revocation_stored", "at": timestamp(1)})
                    case.clock.value = BASE + 2
                if point == "after_file_1":
                    trace.append({"event": "first_file_fsync_returned", "at": timestamp(case.clock() - BASE)})

            case.provider.hook = hook
            began = timestamp(case.clock() - BASE)
            trace.append({"event": "attempt_started", "at": began})
            submission = case.submit()
            finished = timestamp(case.clock() - BASE)
            trace.append({"event": "attempt_finished", "at": finished})
            revocations = [e for e in trace if e["event"] == "revocation_stored"]
            if revocations != [{"event": "revocation_stored", "at": timestamp(1)}]:
                raise ValueError("capture did not store the selected revocation exactly once")
            if scenario == "no_commit":
                if (submission.get("status"), submission.get("reason")) != ("denied_before_acceptance", "revoked"):
                    raise ValueError("capture did not deny submission because of revocation")
            elif submission.get("status") != "effect_observed":
                raise ValueError("capture did not report the expected submission effect")
            case.clock.value = BASE + 3
            query = observer.query()
            expected = ("not_accepted", False, 0) if scenario == "no_commit" else ("effect_observed", True, 2)
            if (type(query) is not dict or query.get("status") != expected[0]
                    or query.get("accepted") is not expected[1]
                    or type(query.get("files")) is not list or len(query["files"]) != expected[2]):
                raise ValueError("capture query did not establish the expected native outcome")
            observer.export(case.path / "evidence.json")
            native_raw = (case.path / "evidence.json").read_bytes()
            native = verify(native_raw, case.selection_raw, observer.anchor_raw)
            if native["verified"] is not True:
                raise ValueError("existing VATE evidence did not verify")
            # The native verifier checks inventory shape, order and file bytes.
            # JSON comparison also distinguishes integer sizes from bool/float.
            try:
                files_match = encode(query["files"]) == encode(json.loads(native_raw)["observation"]["files"])
            except (TypeError, ValueError, RecursionError):
                files_match = False
            if not files_match:
                raise ValueError("capture query did not establish the expected native outcome")
            commit_seen = any(e["event"] == "first_file_fsync_returned" for e in trace)
            if commit_seen != (scenario != "no_commit"):
                raise ValueError("capture did not reach the expected boundary")
            data = inputs(scenario)
            # Attempt times come from submit, before advancing the query clock.
            # The third case intentionally supplies a partial observation while
            # retaining the full harness trace separately; no zero is substituted.
            observed = json.loads(data["observation"])
            a = observed["attempts"][0]
            a.update(started_at=began, finished_at=finished)
            if scenario != "not_established":
                a["commit_state"] = "committed" if commit_seen else "not_committed"
                a["committed_at"] = next((e["at"] for e in trace if e["event"] == "first_file_fsync_returned"), None)
            data["observation"] = encode(observed) + b"\n"
            report = receive(destination / scenario, **data)
            provenance = {"profile": "vate-rb-controlled-capture-v1", "scenario": scenario,
                "clock": "fixed synthetic seconds; not independent time", "harness_trace": trace,
                "query_at": timestamp(case.clock() - BASE),
                "supplied_observation": "intentionally partial" if scenario == "not_established" else "local harness assertions",
                "credential_mapping": {"opaque_id": "urn:example:credential:runtime-key-1",
                    "selected_runtime": case.selection["runtime"], "selection_raw_sha256": digest(case.selection_raw)},
                "native_evidence_raw_sha256": digest(native_raw),
                "native_reader": native, "submission_status": submission["status"],
                "source_sha256": {str(p.relative_to(root)): digest(p.read_bytes()) for p in sorted(sample.glob("*.py"))}}
            (destination / scenario / "CAPTURE.json").write_bytes(encode(provenance) + b"\n")
            results.append({"scenario": scenario, "native_outcome": query["status"],
                            "observed_files": len(query["files"]), "record_check": report["record_check"],
                            "observation_check": report["observation_check"]["status"]})
    result = {"test_keys_deleted": True, "sample_kind": "controlled_local_capture", "results": results}
    (destination / "SUMMARY.json").write_bytes(encode(result) + b"\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, help="trusted VATE source tree")
    args = parser.parse_args()
    print(json.dumps(run(args.out, args.source_root)))
