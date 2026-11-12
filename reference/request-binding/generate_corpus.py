#!/usr/bin/env python3
"""Regenerate the isolated request-binding corpus and its two SUT examples."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import example
import request_binding as b
from runner_binding import MANIFEST_CONTRACT

ROOT = b.ROOT
CORPUS = ROOT / "conformance/request-binding-v1"
SUT = ROOT / "examples/conformance/request-binding"


def write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n")


def generate() -> None:
    for name, options in (("allow", {"cap": "25.00"}), ("attenuate", {}),
                          ("new-permit", {}), ("deny-over-cap", {"purchase": "120.00"})):
        original, request, policy = example.inputs(**options)
        original["operation_id"] = "op-bound-" + name
        request["transaction_id"] = original["operation_id"]
        request["request_id"] = "areq-bound-" + name
        request["input_hash"] = b.object_hash(original)
        verifier = b.core.VateVerifier(verifier_id="did:web:verifier.example", policy=policy)
        result = verifier.admit(b.encode(request), original=b.encode(original),
                              now=b.core.parse_time(example.EVALUATED_AT), require_new_permit=name == "new-permit")
        files = {"original.json": result.original, "admission-request.json": result.request,
                 "admission-receipt.json": result.receipt}
        if result.effective is not None:
            files["effective.json"] = result.effective
        references = {}
        for filename in ("original.json", "admission-request.json", "effective.json"):
            if filename in files:
                ref = b.reference(files[filename])
                references.setdefault(ref["uri"], {**ref, "path": filename})
        files["binding-manifest.json"] = b.encode({"contract": MANIFEST_CONTRACT, "artifacts": list(references.values())})
        directory = CORPUS / "fixtures" / name
        directory.mkdir(parents=True, exist_ok=True)
        submitted = SUT / name
        submitted.mkdir(parents=True, exist_ok=True)
        for filename, raw in files.items():
            (directory / filename).write_bytes(raw)
            (submitted / filename).write_bytes(raw)
        receipt = b.decode(result.receipt)
        artifacts = {"admission_request": (directory / "admission-request.json").relative_to(ROOT).as_posix(),
                     "admission_receipt": (directory / "admission-receipt.json").relative_to(ROOT).as_posix(),
                     "request_binding_manifest": (directory / "binding-manifest.json").relative_to(ROOT).as_posix()}
        if name in ("allow", "attenuate"):
            post = example.synthetic_post(receipt)
            post["admission"]["uri"] = name + "/admission-receipt.json"
            raw = b.encode(post)
            (directory / "post-execution.json").write_bytes(raw)
            (submitted / "post-execution.json").write_bytes(raw)
            artifacts["post_execution_receipt"] = (directory / "post-execution.json").relative_to(ROOT).as_posix()
        case = {"version": "vate-conformance-0.3", "profile": b.core.PROFILE,
                "case_id": "request-binding-" + name, "title": "Request binding: " + name,
                "category": "negative" if name == "deny-over-cap" else "positive",
                "purpose": "Check the selected purchase operation, admission context and effective constraints from raw preimages.",
                "artifacts": artifacts, "request_binding": {"required_contract": b.CONTRACT},
                "expected": {"admission_decision": receipt["decision"]["outcome"],
                             "should_execute": b.decode(result.assessment)["decision_allows_immediate_execution"],
                             "reason_codes": receipt["decision"]["reason_codes"],
                             "checks": []}}
        if name in ("allow", "attenuate"):
            case["linkage_checks"] = [
                {"kind": "admission_digest", "artifact": "admission_receipt",
                 "post_execution_path": "admission.digest", "expect_match": True,
                 "reason_code": "POST_EXEC_ADMISSION_DIGEST_MISMATCH"},
                {"kind": "admission_receipt_id", "expect_match": True, "reason_code": "POST_EXEC_LINKAGE_MISMATCH"},
                {"kind": "admission_decision", "expect_match": True, "reason_code": "POST_EXEC_LINKAGE_MISMATCH"},
                {"kind": "admission_executable", "expect_valid": True, "reason_code": "POST_EXEC_ADMISSION_DENIED"},
                {"kind": "transaction_id", "admission_path": "request.transaction_id",
                 "post_execution_path": "execution.transaction_id", "expect_match": True,
                 "reason_code": "POST_EXEC_TRANSACTION_MISMATCH"},
                {"kind": "runtime", "admission_path": "subject.runtime",
                 "post_execution_path": "execution.runtime", "expect_match": True,
                 "reason_code": "POST_EXEC_RUNTIME_MISMATCH"},
                {"kind": "effective_request_hash",
                 "admission_path": "attenuation.effective_request_hash" if name == "attenuate" else "request.input_hash",
                 "post_execution_path": "execution.effective_request_hash", "expect_match": True,
                 "reason_code": "POST_EXEC_EFFECTIVE_REQUEST_HASH_MISMATCH"},
                {"kind": "admission_time_window", "expect_valid": True, "reason_code": "POST_EXEC_ADMISSION_EXPIRED"},
                {"kind": "effective_constraints", "expect_valid": True,
                 "reason_code": "POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED"},
            ]
        write(CORPUS / "cases" / (name + ".json"), case)

    base = json.loads((ROOT / "conformance/al2-vate-v0.3/conformance-case.schema.json").read_text())
    # A self-contained overlay adds the binding requirement and its input
    # paths. The legacy schema and its extension points stay untouched.
    base.pop("$id", None)
    base.pop("$schema", None)
    schema = {"$schema": "https://json-schema.org/draft/2020-12/schema",
              "$id": "urn:vate:conformance:request-binding-v1:case", **base}
    schema["title"] = "VATE request-binding case"
    schema["required"] = list(base["required"]) + ["request_binding"]
    schema["properties"]["request_binding"] = {"type": "object", "required": ["required_contract"],
        "properties": {"required_contract": {"const": b.CONTRACT}}, "additionalProperties": False}
    schema["properties"]["artifacts"]["properties"]["request_binding_manifest"] = {"type": "string", "minLength": 1}
    schema["properties"]["artifacts"]["required"] = ["admission_request", "admission_receipt", "request_binding_manifest"]
    write(CORPUS / "conformance-case.schema.json", schema)

    spec = importlib.util.spec_from_file_location("binding_corpus_runner", ROOT / "scripts/vate_conformance.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("runner unavailable")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    index = runner.make_corpus_index(CORPUS)
    write(CORPUS / "corpus.json", index)
    for mode, filename in ((runner.SUT_ARTIFACT_MODE_CORPUS, "sut-results-fixtures.json"),
                           (runner.SUT_ARTIFACT_MODE_GENERATED, "sut-results-generated.json")):
        results = []
        for expected in runner.load_case_expectations(CORPUS):
            case = expected["case"]
            name = case["case_id"].removeprefix("request-binding-")
            artifacts = {}
            generated = {}
            for kind in ("admission_receipt", "post_execution_receipt"):
                if kind in case["artifacts"]:
                    source = ROOT / case["artifacts"][kind]
                    ref = {"uri": case["artifacts"][kind],
                           "media_type": "application/vate-" + kind.replace("_", "-") + "+json",
                           "digest": b.digest(source.read_bytes())}
                    artifacts[kind] = ref
                    generated[kind] = {**ref, "uri": name + "/" + source.name, "local_path": name + "/" + source.name}
            manifest_path = name + "/binding-manifest.json"
            result = {"case_id": case["case_id"], "status": "completed", "outcome": expected["expected_outcome"],
                      "should_execute": expected["expected_should_execute"],
                      "reason_codes": expected["expected_reason_codes"], "checks": [], "artifacts": artifacts,
                      "request_binding_artifacts": {"uri": manifest_path, "media_type": "application/json",
                                                    "digest": b.digest((SUT / manifest_path).read_bytes())}}
            if mode == runner.SUT_ARTIFACT_MODE_GENERATED:
                result["generated_artifacts"] = generated
            results.append(result)
        write(SUT / filename, {"version": runner.SUT_RESULTS_VERSION, "profile": runner.PROFILE,
            "generated_at": example.EVALUATED_AT, "artifact_mode": mode,
            "implementation": {"name": "VATE bound-request reference sample", "type": "reference", "version": "1", "language": "Python"},
            "corpus": {"profile": runner.PROFILE, "digest": index["digest"]}, "results": results})


if __name__ == "__main__":
    generate()
