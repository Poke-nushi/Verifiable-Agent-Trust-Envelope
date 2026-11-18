"""Produce six synthetic, local histories and independently read their saved exports."""
import argparse
from pathlib import Path
import tempfile

from fixture import Case, Keys, BASE
from handoff_contract import encode, sha
from handoff_reader import assess


def run(output):
    output.mkdir(parents=True, exist_ok=False)
    summary = {}
    with tempfile.TemporaryDirectory(prefix="vate-handoff-demo-test-keys-") as temporary:
        keys = Keys(Path(temporary))
        scenarios = {"b-after-unaccepted-a": "accept_before_commit", "a-completed-response-lost": "native_after_commit",
                     "accepted-zero-effects": "accepted_before_effect", "accepted-partial-effects": "after_file_1",
                     "effect-completed-outside-admission": "late", "completed-then-observed-later": "later"}
        for name, fault in scenarios.items():
            folder = output / name
            folder.mkdir()
            entries = []
            def hook(point):
                if point == "effect_entry":
                    entries.append(point)
                if fault == "late" and point == "accepted_before_effect":
                    case.clock.value = BASE + 601
                if point == fault:
                    raise RuntimeError("synthetic interruption at " + point)
            case = Case(folder / "store", keys, hook=hook)
            (folder / "context.json").write_bytes(case.context_raw)
            operation_raw = encode(case.operation)
            (folder / "operation.json").write_bytes(operation_raw)
            ticket, proof = case.attempt()
            response = case.provider.submit("operation-one", ticket["attempt_id"], proof)
            case.unknown(ticket)  # explicit synthetic caller report; never fabricated by recovery
            initial = case.provider.export("operation-one")
            (folder / "before-handoff.json").write_bytes(initial)
            case.reopen()
            case.provider.observe(case.owner, "operation-one")
            handoff = case.handoff()
            if name == "b-after-unaccepted-a":
                case.provider.hook = lambda p: entries.append(p) if p == "effect_entry" else None
                final_response = case.submit("runtime-b")
                assert final_response["status"] == "completed"
            if fault == "later":
                case.clock.value = BASE + 700
            bundle = case.provider.export("operation-one", folder / "bundle.json")
            result = assess((folder / "context.json").read_bytes(), operation_raw, (folder / "bundle.json").read_bytes())
            (folder / "assessment.json").write_bytes(encode(result))
            summary[name] = {"effect_state": result["effect_state"], "linkage": result["linkage"],
                             "acceptance_count": result["acceptance_count"], "effect_entries": len(entries),
                             "executing_runtime": result["accepted"]["runtime"] if result["accepted"] else None,
                             "unknown_observations": len(result["unknown"]), "initial_response_status": response["status"],
                             "handoff_effect_state": handoff["result"]["effect_state"], "bundle_sha256": sha(bundle)}
    (output / "SUMMARY.json").write_bytes(encode(summary))
    manifest = {str(p.relative_to(output)): {"sha256": sha(p.read_bytes()), "bytes": p.stat().st_size}
                for p in sorted(output.rglob("*.json"))}
    (output / "MANIFEST.json").write_bytes(encode(manifest))
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path, help="new private directory; must not already exist")
    args = parser.parse_args()
    print(encode(run(args.out)).decode())
