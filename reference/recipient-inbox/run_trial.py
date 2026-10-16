"""Save a receiver restart/late-arrival trial using historical S3 inputs and public test keys."""
import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys

from recipient_inbox import Engine, Inbox, encoded, sha
from scenario_inputs import ROOT, HERE, BUNDLE, LATE, plan_for, delivery, next_plan, signature_fixture, coverage, timings


def expect(condition, detail):
    if not condition:
        raise AssertionError(detail)


def compare_replay(old, new):
    """Retain both raw reports; compare all fields except three measured runtime fields."""
    a, b = deepcopy(old), deepcopy(new)
    differences = []
    for report in (a, b):
        expect(type(report["usage"]["elapsed_milliseconds"]) is int and
               report["usage"]["elapsed_milliseconds"] >= 0, "invalid elapsed measurement")
        measured_size = sum(len(encoded(call["result"])) for call in report["native_calls"])
        expect(report["usage"]["native_result_bytes"] == measured_size, "native result size counter differs from retained results")
    differences.append({"path": "/usage/elapsed_milliseconds", "old": a["usage"].pop("elapsed_milliseconds"),
                        "new": b["usage"].pop("elapsed_milliseconds")})
    expect(len(a["native_calls"]) == len(b["native_calls"]), "native call count differs")
    for index, (left, right) in enumerate(zip(a["native_calls"], b["native_calls"])):
        left_bundle = left["result"].get("inputs", {}).get("bundle")
        right_bundle = right["result"].get("inputs", {}).get("bundle")
        if isinstance(left_bundle, dict) and "selected_path" in left_bundle:
            expect(isinstance(right_bundle, dict) and "selected_path" in right_bundle, "missing bundle path")
            x, y = left_bundle["selected_path"], right_bundle["selected_path"]
            expect(isinstance(x, str) and isinstance(y, str) and Path(x).is_absolute() and Path(y).is_absolute(),
                   "expected the native evaluator's temporary absolute bundle paths")
            differences.append({"path": f"/native_calls/{index}/result/inputs/bundle/selected_path", "old": x, "new": y})
            left_bundle["selected_path"] = right_bundle["selected_path"] = "<native temporary snapshot>"
    differences.append({"path": "/usage/native_result_bytes", "old": a["usage"]["native_result_bytes"],
                        "new": b["usage"]["native_result_bytes"], "both_checked_against_retained_results": True})
    for report in (a, b):
        report["usage"]["native_result_bytes"] = sum(len(encoded(call["result"])) for call in report["native_calls"])
    expect(a == b, "exported evaluation differs beyond listed runtime fields")
    return differences


def generate(destination, openssl, expected_sha256):
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError("output must be a new directory")
    openssl = Path(openssl).resolve(strict=True)
    if sha(openssl.read_bytes()) != expected_sha256:
        raise ValueError("selected OpenSSL does not match the expected SHA-256")
    destination.mkdir(parents=True, exist_ok=False)
    sig = signature_fixture(openssl)
    expect(sig.binary_sha256 == expected_sha256, "selected OpenSSL changed during fixture generation")
    engine = Engine(ROOT, openssl, expected_sha256)
    (destination / "ENGINE.json").write_bytes(encoded(engine.identity) + b"\n")
    (destination / "FIXTURE-BASIS.json").write_bytes(encoded({
        "originals": {name: {"raw_sha256": sha((BUNDLE / name).read_bytes()), "byte_length": (BUNDLE / name).stat().st_size}
                      for name in sorted(engine.validation.MEMBERS)},
        "receiver_inputs": "synthetic requirements, arrival and collection assertions",
        "signatures": "created now with existing public test scalars; not original-operation signatures",
        "signature_policy_evaluation_time": sig.policy["evaluation_time"],
        "required_record_cutoff": "synthetic 2026-10-20, separate from signature policy time",
        "live_S3": False, "independent_receiver": False}) + b"\n")
    summaries = []

    def finish(box, plan, name, expected, *, signature=False):
        db_path = box.path
        prepared = box.prepare(encoded(plan))
        box.close()
        cmd = [sys.executable, "-B", str(HERE / "recipient_inbox.py"), "--db", str(db_path), "--source-root", str(ROOT)]
        if signature:
            cmd += ["--openssl", str(sig.openssl), "--openssl-sha256", sig.binary_sha256]
        process = subprocess.Popen([*cmd, "run", prepared["run_id"]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = process.communicate(timeout=100)
        except BaseException:
            if process.poll() is None:
                process.kill(); process.wait()
            raise
        (destination / (name + ".stdout.json")).write_bytes(stdout)
        (destination / (name + ".stderr.txt")).write_bytes(stderr)
        expect(process.returncode == 0, name + " CLI failed: " + stdout.decode(errors="replace"))
        state = json.loads(stdout)
        box = Inbox(db_path, engine if signature else Engine(ROOT))
        report_raw = box.get(state["report_ref"])
        report = json.loads(report_raw)
        expect(coverage(report) == expected, name + " coverage differs")
        expect(not report["invocation_errors"], name + " has invocation errors")
        summaries.append({"case": name, "child_pid": process.pid, "revision": state["revision"],
                          "status": state["status"], "run_id": state["run_id"],
                          "coverage": coverage(report), "timeliness": timings(report),
                          "report_sha256": sha(report_raw), "report_ref": state["report_ref"]})
        return box, state, report

    box = Inbox(destination / "signed-intake.sqlite3", engine, create=True)
    plan = plan_for(box)
    plan["native_policy_refs"]["signature"] = box.put(encoded(sig.policy))
    plan["review_set"]["requirements"][0]["requested_native_checks"].append("signatures_and_issuer_authority")
    box.receive(delivery(box, plan, "signed-admission", {"admission": sig.admission}, proofs={"admission": sig.admission_proof}))
    box, first, _ = finish(box, plan, "01-signed-incomplete", {"A": "missing", "B": "missing"}, signature=True)
    first_raw = box.get(first["report_ref"])
    box.receive(delivery(box, plan, "late-signed-post", {"post": sig.post}, received=LATE, proofs={"post": sig.post_proof}))
    box, second, report2 = finish(box, next_plan(plan), "02-signed-late", {"A": "present", "B": "missing"}, signature=True)
    second_raw = box.get(second["report_ref"])
    result2 = next(call["result"] for call in report2["native_calls"] if "signatures" in call["result"])
    expect(timings(report2)["A"] == "late", "late receipt was relabeled on time")
    expect(result2["signatures"]["post_execution"]["status"] == "verified", "signature check missing")
    expect(result2["issuer_authority"]["post_execution"]["status"] == "authorized_under_policy", "policy result differs")
    changed = next_plan(plan); policy = deepcopy(sig.policy); policy["grants"] = []
    changed["native_policy_refs"]["signature"] = box.put(encoded(policy))
    box, third, report3 = finish(box, changed, "03-policy-update", {"A": "present", "B": "missing"}, signature=True)
    result3 = next(call["result"] for call in report3["native_calls"] if "signatures" in call["result"])
    expect(result3["signatures"]["post_execution"]["status"] == "verified", "signature result changed unexpectedly")
    expect(result3["issuer_authority"]["post_execution"]["status"] == "denied", "authority denial lost")
    expect(result3["receipt_assessment"]["native_result"]["record_linkage"] == "matched", "linkage result changed")
    expect(box.get(first["report_ref"]) == first_raw and box.get(second["report_ref"]) == second_raw, "previous report changed")
    signed_export = destination / "signed-export"
    box.export(third["run_id"], signed_export)
    expect(box.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "signed DB integrity failure")
    box.close()

    sys.path.insert(0, str(ROOT / "reference/runtime-support"))
    from synthetic_s3 import synthetic_current_instance
    synthetic = synthetic_current_instance(ROOT, destination / "synthetic-current-s3")
    bundle = synthetic / "bundles/supported"
    box = Inbox(destination / "s3-intake.sqlite3", Engine(ROOT), create=True)
    plan = plan_for(box, s3_instance=synthetic)
    plan["review_set"]["requirements"] = plan["review_set"]["requirements"][:1]
    row = plan["review_set"]["requirements"][0]
    row["subject"].update(kind="attempt", attempt_id=json.loads((bundle / "attempt.json").read_bytes())["attempt_id"])
    row["binding_profile"] = "vate_s3_attempt_context"
    row["requested_native_checks"].append("s3_observation_binding")
    originals = {name: (bundle / name).read_bytes() for name in engine.validation.MEMBERS if name != "get-body.bin"}
    box.receive(delivery(box, plan, "partial-bundle", originals, kind="s3_bundle"))
    box, first, _ = finish(box, plan, "04-s3-incomplete", {"A": "unresolved"})
    box.receive(delivery(box, plan, "late-readback", {"get-body.bin": (bundle / "get-body.bin").read_bytes()},
                         received=LATE, kind="s3_bundle"))
    box, second, _ = finish(box, plan, "05-s3-old-cutoff", {"A": "unresolved"})
    box, third, report = finish(box, next_plan(plan), "06-s3-later-cutoff", {"A": "present"})
    expect(timings(report)["A"] == "on_time", "post receipt arrival must remain distinct from later supporting body")
    expect(b'"retry_authorized":false' in encoded(report), "native no-retry result lost")
    s3_export = destination / "s3-export"
    box.export(third["run_id"], s3_export)
    expect(box.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "S3 DB integrity failure")
    box.close()

    replay_results = []
    for folder, use_signature in ((signed_export, True), (s3_export, False)):
        output = destination / (folder.name + "-replayed.json")
        cmd = [sys.executable, "-B", str(ROOT / "reference/required-records/required_records.py"),
               "--selection", str(folder / "selection.json"), "--base", "inbox=" + str(folder),
               "--source-root", str(ROOT), "--output", str(output)]
        if use_signature:
            cmd += ["--openssl", str(sig.openssl), "--openssl-sha256", sig.binary_sha256]
        run = subprocess.run(cmd, capture_output=True, timeout=90)
        expect(run.returncode == 0, "export replay failed")
        old, new = json.loads((folder / "report.json").read_bytes()), json.loads(output.read_bytes())
        differences = compare_replay(old, new)
        replay_results.append({"export": folder.name, "returncode": run.returncode,
                               "complete_JSON_equal_except_listed_runtime_fields": True,
                               "runtime_fields": differences,
                               "replayed_sha256": sha(output.read_bytes())})
    summary = {"completed_at": datetime.now(timezone.utc).isoformat(), "python": sys.version,
               "platform": platform.platform(), "sqlite": sqlite3.sqlite_version,
               "cases": summaries, "export_replays": replay_results,
               "all_expectations_matched": True, "previous_reports_unchanged": True,
               "scope": "Same-owner local receiving application; saved receipt bytes, synthetic current-source S3 derivatives and policies/times; no live S3 or external adoption."}
    (destination / "SUMMARY.json").write_bytes(encoded(summary) + b"\n")
    manifest = {str(path.relative_to(destination)): {"raw_sha256": sha(path.read_bytes()), "byte_length": path.stat().st_size}
                for path in sorted(destination.rglob("*")) if path.is_file()}
    (destination / "FILES-SHA256.json").write_bytes(encoded({"files": manifest}) + b"\n")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, required=True)
    parser.add_argument("--openssl-sha256", required=True)
    args = parser.parse_args()
    result = generate(args.output, args.openssl, args.openssl_sha256)
    print(json.dumps({"summary": str(args.output / "SUMMARY.json"), "cases": len(result["cases"]),
                      "all_expectations_matched": result["all_expectations_matched"]}))
