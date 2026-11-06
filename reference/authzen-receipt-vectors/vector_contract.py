"""Fixed comparison cases and read-only replay of local VATE histories."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import types

ROOT = Path(__file__).resolve().parent
SAMPLE = ROOT.parent / "runtime-handoff-sample"
PIN = "f1286390445bb55b92865dc21737e6e0696cee15"
SOURCE = {
    "repository": "https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope",
    "commit": PIN,
    "directory": "reference/runtime-handoff-sample",
    "manifest_sha256": "20ce91dd6e2bf6b1fd73161adb4b7d8e236b1282e9e2e7c4ce02494c91e26b5d",
}
FORMAT = "vate-authzen795-comparison-v1"
MAX_FILE = 2 * 1024 * 1024
PACKAGE_FILES = {"README.md", "VALIDATION.md", "vector_contract.py", "capture.py", "verify.py", "test_vectors.py"}
NOT_CHECKED = ["fresh_pdp_evaluation", "pep_atomic_check_and_reserve", "signed_receipt_registration"]

# Expected states are written independently of captured reader output.
# Each state is (effect, acceptance count, executing runtime, unknown observations, output files).
CASES = {
    "01-lost-response-recovery": ("Recover the original result after response loss", [3, 5], {
        "with-unknown-observation": {
            "pending": ("unresolved", 0, None, 0, 0),
            "recovered": ("completed", 1, "runtime-a", 1, 2)},
        "without-prior-receipt": {
            "pending": ("unresolved", 0, None, 0, 0),
            "recovered": ("completed", 1, "runtime-a", 0, 2)}}),
    "02-accepted-interrupted": ("Keep accepted but interrupted work unresolved", [1, 6], {
        "zero-effects": {
            "interrupted": ("unresolved", 1, "runtime-a", 1, 0),
            "after-handoff": ("unresolved", 1, "runtime-a", 1, 0)},
        "partial-effects": {
            "interrupted": ("unresolved", 1, "runtime-a", 1, 1),
            "after-handoff": ("unresolved", 1, "runtime-a", 1, 1)}}),
    "03-confirmed-nonexecution-handoff": ("Require nonexecution confirmation and exclusion", [6], {
        "live-worker": {
            "pending": ("unresolved", 0, None, 0, 0),
            "completed": ("completed", 1, "runtime-a", 0, 2)},
        "fenced-handoff": {
            "pending": ("unresolved", 0, None, 0, 0),
            "fenced": ("confirmed_unexecuted", 0, None, 0, 0),
            "completed": ("completed", 1, "runtime-b", 0, 2)}}),
    "04-new-permit-does-not-reopen": ("A new permit does not reopen the same effect", [6], {
        "unresolved": {
            "original": ("unresolved", 1, "runtime-a", 1, 0),
            "new-admission": ("unresolved", 1, "runtime-a", 1, 0)},
        "completed": {
            "original": ("completed", 1, "runtime-a", 0, 2),
            "new-admission": ("completed", 1, "runtime-a", 0, 2)}}),
}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def encode(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False).encode("utf-8")
    except RecursionError as error:
        raise ValueError("JSON nesting too deep") from error


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def same(left, right):
    return encode(left) == encode(right)


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    except RecursionError as error:
        raise ValueError("JSON nesting too deep") from error


def read(root, name):
    relative = PurePosixPath(name)
    need(name and str(relative) == name and not relative.is_absolute()
         and all(p not in (".", "..") for p in relative.parts), "invalid input path")
    path = Path(root)
    need(not path.is_symlink(), "symlink input root")
    for part in relative.parts:
        path = path / part
        need(not path.is_symlink(), "symlink input path")
    info = path.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE, "invalid input file")
    raw = path.read_bytes()
    need(len(raw) <= MAX_FILE, "input file too large")
    return raw


def load_reader(sample=SAMPLE):
    """Check the frozen source distribution before importing its modules."""
    sample = Path(sample).absolute()
    raw = read(sample, "SOURCE-MANIFEST.json")
    need(sha(raw) == SOURCE["manifest_sha256"], "runtime sample manifest pin mismatch")
    manifest = decode(raw)
    sources = {name: read(sample, name) for name in manifest["files"]}
    for name, digest in manifest["files"].items():
        need(sha(sources[name]) == digest, "runtime sample source mismatch: " + name)
    # Execute exactly the checked source bytes. A normal loader can prefer a
    # timestamp-valid .pyc before the checker gets to reject unlisted files.
    checker = types.ModuleType("_authzen_vector_source_check")
    checker.__file__ = str(sample / "check_environment.py")
    exec(compile(sources["check_environment.py"], checker.__file__, "exec"), checker.__dict__)
    checker.verify_sources(sample)
    for name in ("dependencies", "fixture", "handoff_contract", "handoff_model", "handoff_reader"):
        old = sys.modules.get(name)
        if old is not None:
            need(Path(old.__file__).resolve().parent == (sample / "sample").resolve(),
                 "mixed runtime sample modules")
    sys.path.insert(0, str(sample / "sample"))
    import handoff_reader
    return handoff_reader


def variant_paths():
    for case, (_, _, variants) in CASES.items():
        for variant, phases in variants.items():
            yield case, variant, phases


def case_index(case):
    title, items, variants = CASES[case]
    return {"case": case, "title": title, "authzen795_items": items, "variants": list(variants)}


def data_paths():
    paths = {"VECTORS.json"}
    for case in CASES:
        paths.add("cases/" + case + "/case.json")
    for case, variant, phases in variant_paths():
        prefix = "cases/" + case + "/" + variant + "/"
        names = ["context.json", "operation.json", "interactions.json", "input-history.json",
                 "expected-assessments.json", "expected-receipts.json", "expected-pep-decision.json"]
        names.extend(phase + "-history.json" for phase in phases)
        paths.update(prefix + name for name in names)
    return paths


def expected_pep(case, variant):
    phases = CASES[case][2][variant]
    decisions = {}
    for phase, (effect, *_rest) in phases.items():
        if effect == "confirmed_unexecuted":
            decisions[phase] = {
                "comparison_expectation": "conditional_continuation",
                "reason": "Nonexecution and old-attempt exclusion are established under the local provider contract.",
                "additional_requirements": NOT_CHECKED,
            }
        else:
            decisions[phase] = {
                "comparison_expectation": "hold_same_logical_effect",
                "reason": "The earlier effect is completed." if effect == "completed" else
                          "The earlier attempt remains unresolved.",
            }
    return {"kind": "expected_pep_comparison_conditions", "is_execution_ticket": False,
            "actual_authzen_pep_execution": "not_run", "not_checked": NOT_CHECKED, "phases": decisions}


def check_assessment(result, bundle, expected):
    effect, count, runtime, unknown_count, files = expected
    need(result["effect_state"] == effect, "unexpected effect state")
    need(result["acceptance_count"] == count, "unexpected acceptance count")
    actual_runtime = result["accepted"]["runtime"] if result["accepted"] else None
    need(actual_runtime == runtime, "unexpected executing runtime")
    need(len(result["unknown"]) == unknown_count, "unexpected unknown observations")
    need(len(bundle["inventory"]) == files, "unexpected effect inventory")
    need(result["is_execution_ticket"] is False, "assessment must not authorize execution")
    receipt = result["post_execution_receipt"]
    if effect == "completed":
        need(receipt is not None and receipt["proof"] == {"format": "none"}, "derived receipt proof")
        need(receipt["execution"]["runtime"] == runtime, "receipt runtime mismatch")
        need(receipt["admission"]["digest"]["value"] == result["accepted"]["admission_sha256"],
             "receipt original admission mismatch")
        need(receipt["receipt_id"] == "post-" + result["accepted"]["attempt_id"], "receipt attempt mismatch")
        need(result["linkage"]["outcome"] == "success", "receipt linkage mismatch")
    else:
        need(receipt is None, "unexpected completed receipt")


def check_interactions(case, variant, interactions, context, operation, bundle, assessment, reader):
    """Bind captured harness observations to the already verified journal."""
    from handoff_contract import unb64, Context
    from handoff_model import check_handoff_request

    need(isinstance(interactions, list) and len(interactions) <= 16, "invalid interaction list")
    live = case == "03-confirmed-nonexecution-handoff" and variant == "live-worker"
    fenced = case == "03-confirmed-nonexecution-handoff" and variant == "fenced-handoff"
    has_unknown = CASES[case][2][variant][list(CASES[case][2][variant])[-1]][3] == 1
    if live or fenced:
        order = ["first-ticket", "handoff"] + (["first-submit"] if live else ["late-a", "b-submit"])
    else:
        order = ["first-ticket", "first-submit"] + (["caller-unknown"] if has_unknown else []) + ["handoff", "repeat-ticket"]
    need(all(isinstance(c, dict) and set(c) == {"id", "method", "request", "response"} for c in interactions),
         "invalid interaction shape")
    need([c["id"] for c in interactions] == order, "interaction sequence mismatch")
    calls = {c["id"]: c for c in interactions}
    methods = {"first-ticket": "fixture.attempt", "first-submit": "provider.submit",
               "late-a": "provider.submit", "b-submit": "provider.submit", "handoff": "provider.handoff",
               "caller-unknown": "provider.record_unknown", "repeat-ticket": "provider.ticket"}
    need(all(c["method"] == methods[c["id"]] for c in interactions), "interaction method mismatch")
    events = [decode(unb64(r["raw"])) for r in bundle["records"]]
    bodies = lambda kind: [e["body"] for e in events if e["kind"] == kind]
    ticket = bodies("ticket")[0]
    first = calls["first-ticket"]
    need(same(first["request"], {"runtime": "runtime-a"}) and isinstance(first["response"], dict)
         and set(first["response"]) == {"ticket", "proof_base64"}
         and same(first["response"]["ticket"], ticket), "first ticket mismatch")
    attempt = next(b for b in bodies("accepted") + bodies("denied") if b["attempt_id"] == ticket["attempt_id"])
    proof = attempt["proof"]
    need(first["response"]["proof_base64"] == proof, "first attempt proof mismatch")
    first_submit = calls["late-a" if fenced else "first-submit"]
    need(same(first_submit["request"], {"operation_id": bundle["operation_id"],
             "attempt_id": ticket["attempt_id"], "proof_base64": proof}), "submit request mismatch")
    if fenced:
        need(same(first_submit["response"], {"status": "denied", "reason": "old_generation"}),
             "old attempt must be fenced")
        accepted = bodies("accepted")[0]
        need(same(calls["b-submit"]["request"], {"operation_id": bundle["operation_id"],
                 "ticket": bodies("ticket")[1], "proof_base64": accepted["proof"]}), "B submit request mismatch")
        need(same(calls["b-submit"]["response"], {"status": "completed", "native": bodies("native")[0]}),
             "B local completion mismatch")
    elif live or (case == "04-new-permit-does-not-reopen" and variant == "completed"):
        need(same(first_submit["response"], {"status": "completed", "native": bodies("native")[0]}),
             "first completion mismatch")
    else:
        # Reconstruct only the journal prefix observed by the first submit's
        # diagnostic query. This is comparison, not provider re-execution.
        end = next(i for i, event in enumerate(events) if event["kind"] in ("unknown", "observed", "handoff"))
        prefix = {**bundle, "records": bundle["records"][:end], "head": bundle["records"][end - 1]["sha256"]}
        replayed = reader.assess(context, operation, encode(prefix))
        keys = ("operation_id", "generation", "revision", "runtime", "effect_state", "accepted", "unknown",
                "linkage", "clock_uncertain", "is_execution_ticket")
        saved = {key: replayed[key] for key in keys}
        saved["inventory"] = bundle["inventory"]
        need(same(first_submit["response"], {"status": "unknown", "next": "query", "saved": saved}),
             "unknown submit observation mismatch")
    if has_unknown:
        need(same(calls["caller-unknown"]["request"], {"raw_base64": bodies("unknown")[0]["raw"]})
             and calls["caller-unknown"]["response"] is None, "caller unknown observation mismatch")
    handoff = calls["handoff"]
    need(isinstance(handoff["request"], dict) and set(handoff["request"]) == {"raw_base64"}, "handoff request shape")
    request = decode(unb64(handoff["request"]["raw_base64"]))
    check_handoff_request(Context(context), request)
    if live:
        need(request["operation_id"] == bundle["operation_id"] and request["old_runtime"] == "runtime-a"
             and request["expected_generation"] == ticket["generation"]
             and request["read_attempts"] == [ticket["attempt_id"]], "busy handoff request mismatch")
        need(same(handoff["response"], {"status": "busy", "next": "query_same_request"}), "live worker must block handoff")
    else:
        need(handoff["request"]["raw_base64"] == bodies("handoff")[0]["request_raw"], "handoff original mismatch")
        need(len(assessment["handoffs"]) == 1 and assessment["handoffs"][0]["request_id"] == request["request_id"],
             "handoff request identity mismatch")
        need(same(handoff["response"], {"status": "committed", "result": assessment["handoffs"][0]}),
             "handoff response mismatch")
    if not live and not fenced:
        need(same(calls["repeat-ticket"]["request"], {"operation_id": bundle["operation_id"], "runtime": "runtime-b"}),
             "repeat ticket request mismatch")
        need(same(calls["repeat-ticket"]["response"],
                  {"status": "rejected", "error_type": "ValueError", "reason": "no new ticket"}), "repeat ticket must be rejected")


def verify(data=ROOT, sample=SAMPLE):
    data = Path(data).absolute()
    for path in data.iterdir():
        need(not path.is_symlink(), "symlink at fixture root")
        need(path.name in PACKAGE_FILES | {"cases", "MANIFEST.json", "VECTORS.json"}, "unexpected fixture root entry")
        need(path.is_dir() if path.name == "cases" else path.is_file(), "invalid fixture root entry")
    manifest = decode(read(data, "MANIFEST.json"))
    need(isinstance(manifest, dict) and set(manifest) == {"format", "files"}
         and manifest["format"] == FORMAT and isinstance(manifest["files"], dict), "manifest shape")
    need(set(manifest["files"]) == data_paths(), "fixture manifest inventory")
    actual = {p.relative_to(data).as_posix() for p in (data / "cases").rglob("*") if p.is_file() or p.is_symlink()}
    need(actual == data_paths() - {"VECTORS.json"}, "fixture tree inventory")
    for name, entry in manifest["files"].items():
        raw = read(data, name)
        need(entry == {"sha256": sha(raw), "bytes": len(raw)}, "fixture digest mismatch: " + name)
        need(not re.search(rb"/Users/|/home/|BEGIN (?:EC |RSA |OPENSSH )?PRIVATE KEY", raw),
             "private material in published fixture")
    index = decode(read(data, "VECTORS.json"))
    need(same(index, {"format": FORMAT, "source": SOURCE, "cases": list(CASES),
                   "provenance": "synthetic_local_provider_capture", "is_execution_ticket": False}), "vector index")
    reader = load_reader(sample)
    verified = []
    for case in CASES:
        need(same(decode(read(data, "cases/" + case + "/case.json")), case_index(case)), "case index")
    for case, variant, phases in variant_paths():
        prefix = "cases/" + case + "/" + variant + "/"
        get = lambda name: read(data, prefix + name)
        context, operation = get("context.json"), get("operation.json")
        expected = decode(get("expected-assessments.json"))
        receipts = decode(get("expected-receipts.json"))
        history = decode(get("input-history.json"))
        need(same(history, {"case": case, "variant": variant, "snapshots": list(phases),
                         "history_basis": "original_provider_export_bytes", "clock": "fixed_fixture_clock"}), "history index")
        need(set(expected) == set(receipts) == set(phases), "expected snapshot set")
        previous = []
        for phase, state in phases.items():
            raw = get(phase + "-history.json")
            bundle = decode(raw)
            need(bundle["records"][:len(previous)] == previous, "earlier records were not retained")
            previous = bundle["records"]
            actual_result = reader.assess(context, operation, raw)
            need(same(actual_result, expected[phase]), "assessment replay mismatch: " + prefix + phase)
            need(same(actual_result["post_execution_receipt"], receipts[phase]), "receipt replay mismatch")
            check_assessment(actual_result, bundle, state)
        need(same(decode(get("expected-pep-decision.json")), expected_pep(case, variant)), "PEP comparison mismatch")
        check_interactions(case, variant, decode(get("interactions.json")), context, operation, bundle, actual_result, reader)
        verified.append({"case": case, "variant": variant, "snapshots": len(phases)})
    return {"status": "matched", "cases": 4, "variants": verified,
            "snapshots_replayed": sum(v["snapshots"] for v in verified),
            "is_execution_ticket": False, "not_checked": NOT_CHECKED,
            "scope": "fixed local histories and comparison expectations; no AuthZEN PEP or PDP execution"}
