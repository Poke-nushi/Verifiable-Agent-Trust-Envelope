#!/usr/bin/env python3
"""Capture synthetic local-provider inputs in a new folder; never use real keys."""
from __future__ import annotations

import argparse
import multiprocessing as mp
from pathlib import Path
import tempfile

from vector_contract import (CASES, FORMAT, SOURCE, SAMPLE, case_index, check_assessment,
                             data_paths, encode, expected_pep, load_reader, need, sha, verify)


def save(path, value):
    path.write_bytes(encode(value))


def blocked_worker(sample, store, ticket, proof, pipe):
    """A rendezvous at the worker lock makes the busy case independent of timing."""
    try:
        load_reader(sample)
        from fixture import Clock
        from handoff_provider import Provider

        def hook(point):
            if point == "submit_locked":
                pipe.send({"at": point})
                if not pipe.poll(30):
                    raise RuntimeError("worker rendezvous timeout")
                pipe.recv()

        provider = Provider(store, clock=Clock(), hook=hook, owner_capability=object())
        pipe.send({"result": provider.submit("operation-one", ticket["attempt_id"], proof)})
    except Exception as error:
        pipe.send({"error": type(error).__name__ + ": " + str(error)})
    finally:
        pipe.close()


def capture_variant(folder, store, keys, case_name, variant, sample, reader):
    from fixture import Case
    from handoff_contract import b64, decode

    phases = CASES[case_name][2][variant]
    folder.mkdir(parents=True)
    store.parent.mkdir(parents=True, exist_ok=True)
    fault = None
    if case_name == "01-lost-response-recovery":
        fault = "native_after_commit"
    elif case_name == "02-accepted-interrupted":
        fault = "accepted_before_effect" if variant == "zero-effects" else "after_file_1"
    elif case_name == "04-new-permit-does-not-reopen" and variant == "unresolved":
        fault = "accepted_before_effect"

    def hook(point):
        if point == fault:
            raise RuntimeError("synthetic interruption at " + point)

    c = Case(store, keys, hook=hook)
    (folder / "context.json").write_bytes(c.context_raw)
    operation = encode(c.operation)
    (folder / "operation.json").write_bytes(operation)
    interactions, assessments, receipts = [], {}, {}

    def call(identifier, method, request, function):
        try:
            result = function()
        except ValueError as error:
            result = {"status": "rejected", "error_type": "ValueError", "reason": str(error)}
        interactions.append({"id": identifier, "method": method, "request": request, "response": result})
        return result

    def snapshot(label):
        raw = c.provider.export("operation-one")
        (folder / (label + "-history.json")).write_bytes(raw)
        result = reader.assess(c.context_raw, operation, raw)
        check_assessment(result, decode(raw), phases[label])
        assessments[label] = result
        receipts[label] = result["post_execution_receipt"]

    def handoff(authorization=None):
        request = c.request(authorization=authorization)
        return call("handoff", "provider.handoff", {"raw_base64": b64(request)},
                    lambda: c.provider.handoff(c.owner, request))

    def reject_b():
        return call("repeat-ticket", "provider.ticket", {"operation_id": "operation-one", "runtime": "runtime-b"},
                    lambda: c.provider.ticket("operation-one", "runtime-b"))

    ticket, proof = c.attempt()
    interactions.append({"id": "first-ticket", "method": "fixture.attempt", "request": {"runtime": "runtime-a"},
                         "response": {"ticket": ticket, "proof_base64": b64(proof)}})
    submit_request = {"operation_id": "operation-one", "attempt_id": ticket["attempt_id"], "proof_base64": b64(proof)}
    if case_name == "03-confirmed-nonexecution-handoff":
        snapshot("pending")
        if variant == "live-worker":
            parent, child = mp.get_context("spawn").Pipe()
            process = mp.get_context("spawn").Process(target=blocked_worker,
                         args=(str(sample), str(store), ticket, proof, child))
            process.start()
            child.close()
            try:
                need(parent.poll(30) and parent.recv() == {"at": "submit_locked"}, "worker did not reach lock")
                need(handoff()["status"] == "busy", "handoff did not observe live worker")
                parent.send("continue")
                need(parent.poll(30), "worker did not complete")
                result = parent.recv()
                process.join(5)
                need(process.exitcode == 0 and "result" in result, "worker failed")
                interactions.append({"id": "first-submit", "method": "provider.submit",
                                     "request": submit_request, "response": result["result"]})
            finally:
                if process.is_alive():
                    process.terminate()
                process.join(5)
                parent.close()
                need(not process.is_alive(), "worker cleanup failed")
            snapshot("completed")
        else:
            handoff()
            snapshot("fenced")
            call("late-a", "provider.submit", submit_request,
                 lambda: c.provider.submit("operation-one", ticket["attempt_id"], proof))
            b_ticket, b_proof = c.attempt("runtime-b")
            call("b-submit", "provider.submit", {"operation_id": "operation-one", "ticket": b_ticket,
                 "proof_base64": b64(b_proof)},
                 lambda: c.provider.submit("operation-one", b_ticket["attempt_id"], b_proof))
            snapshot("completed")
    else:
        if case_name == "01-lost-response-recovery":
            snapshot("pending")
        call("first-submit", "provider.submit", submit_request,
             lambda: c.provider.submit("operation-one", ticket["attempt_id"], proof))
        c.reopen()
        if variant != "without-prior-receipt" and not (case_name == "04-new-permit-does-not-reopen" and variant == "completed"):
            raw = c.unknown(ticket)
            interactions.append({"id": "caller-unknown", "method": "provider.record_unknown",
                                 "request": {"raw_base64": b64(raw)}, "response": None})
        if case_name == "01-lost-response-recovery":
            c.provider.observe(c.owner, "operation-one")
            handoff()
            reject_b()
            snapshot("recovered")
        elif case_name == "02-accepted-interrupted":
            snapshot("interrupted")
            handoff()
            reject_b()
            snapshot("after-handoff")
        else:
            snapshot("original")
            new_admission = c.authorization("runtime-b", "permit-b-new")
            handoff(new_admission)
            reject_b()
            snapshot("new-admission")

    save(folder / "input-history.json", {"case": case_name, "variant": variant, "snapshots": list(phases),
         "history_basis": "original_provider_export_bytes", "clock": "fixed_fixture_clock"})
    save(folder / "interactions.json", interactions)
    save(folder / "expected-assessments.json", assessments)
    save(folder / "expected-receipts.json", receipts)
    save(folder / "expected-pep-decision.json", expected_pep(case_name, variant))


def capture(output, sample=SAMPLE):
    output, sample = Path(output).absolute(), Path(sample).absolute()
    need(not output.exists(), "output must be a new directory")
    reader = load_reader(sample)
    from fixture import Keys
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="vate-authzen-vectors-") as temporary:
        private = Path(temporary)
        keys = Keys(private / "keys")
        for case, (_, _, variants) in CASES.items():
            for variant in variants:
                capture_variant(output / "cases" / case / variant, private / case / variant,
                                keys, case, variant, sample, reader)
            save(output / "cases" / case / "case.json", case_index(case))
    save(output / "VECTORS.json", {"format": FORMAT, "source": SOURCE, "cases": list(CASES),
         "provenance": "synthetic_local_provider_capture", "is_execution_ticket": False})
    files = {name: {"sha256": sha((output / name).read_bytes()), "bytes": (output / name).stat().st_size}
             for name in sorted(data_paths())}
    save(output / "MANIFEST.json", {"format": FORMAT, "files": files})
    return verify(output, sample)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--sample", type=Path, default=SAMPLE)
    args = parser.parse_args()
    print(encode(capture(args.out, args.sample)).decode())
