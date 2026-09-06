"""Project the saved native N1 output into VATE; this script runs no verifier."""

import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reference(name):
    return {
        "uri": name,
        "media_type": "application/json",
        "digest": {"alg": "sha-256", "value": digest(HERE / name)},
    }


def project():
    replay = json.loads((HERE / "replay.json").read_text())
    require(replay["status"] == "native_results_reproduced", "Replay is not complete")
    for run in [replay["harness_execution"], *replay["wrapper_captures"]]:
        require(run["exit_code"] == 0 and not run["timed_out"], "Native execution failed")
        for stream in ("stdout", "stderr"):
            require(digest(HERE / run[stream]) == run[f"{stream}_sha256"],
                    f"Saved {stream} changed for {run['id']}")
    require(digest(HERE / "input-packet.json") == replay["input_packet_sha256"],
            "Input packet changed")
    require(digest(HERE / "issued-mandate.json") == replay["issued_mandate_sha256"],
            "Issued mandate changed")
    require(digest(HERE / "native-report.json") == replay["native_report"]["sha256"],
            "Native report changed")
    for name, expected in replay["script_hashes"].items():
        require(digest(HERE / name) == expected, f"Saved script changed: {name}")

    packet = json.loads((HERE / "input-packet.json").read_text())
    issued = json.loads((HERE / "issued-mandate.json").read_text())
    native_report = json.loads((HERE / "native-report.json").read_text())
    stdout_report = json.loads((HERE / replay["harness_execution"]["stdout"]).read_text())
    require(native_report == stdout_report, "Report differs from saved harness stdout")
    require(native_report["packet_id"] == packet["packet_id"], "Packet ID differs")
    require([row["id"] for row in native_report["runs"]] == ["P", "N1", "N2"],
            "Expected exactly three recorded inputs")
    for row, context in zip(native_report["runs"], packet["request_contexts"]):
        request = json.loads((HERE / f"request-{row['id']}.json").read_text())
        require(row["id"] == context["id"] and row["request"] == context["request"],
                "Native request differs from packet context")
        require(request == {**packet["evc_common"], "bundle": issued["presentation"],
                            "request": context["request"]},
                "Wrapper request differs from the shared presentation and packet")
        wrapper_verdict = json.loads((HERE / f"wrapper-{row['id']}.stdout.txt").read_text())
        require(wrapper_verdict == row["native"], "Direct and wrapper verdicts differ")

    selected = native_report["runs"][1]
    native = selected["native"]
    host = selected["host"]
    require(host["decision"] == native["verdict"] == "deny", "Selected verdict is not deny")
    require(host.get("code") == native["code"], "Host and native denial codes differ")
    profile = "VATE-AL2-Verifier-Admission-v0.3"
    return {
        "version": "vate-sut-results-2026-09",
        "profile": profile,
        "generated_at": replay["verified_at"],
        "artifact_mode": "corpus-fixture-validation",
        "implementation": {
            "name": "Bolyra verifyClassical via x402 runEvcVerifier",
            "type": "reviewer-native-run-vate-side-projection",
            "version": "@bolyra/mpp 0.4.0; x402 source 992f78e",
            "language": "TypeScript",
            "source": "https://github.com/bolyra/bolyra",
            "commit": packet["pins"]["bolyra"],
            "host_source": "https://github.com/saneGuy/x402",
            "host_commit": packet["pins"]["x402"],
            "candidate_execution_report": replay["candidate_report"]["url"],
            "reviewer_execution_record": "replay.json",
            "formatted_by": "VATE maintainer",
            "provenance_status": "VATE-maintainer replay of unchanged candidate scripts; values parsed from saved reviewer stdout",
        },
        "corpus": {
            "profile": profile,
            "digest": {"alg": "sha-256", "value": packet["vate_corpus_digest"]},
        },
        "results": [{
            "case_id": packet["vate_case_id"],
            "status": "completed",
            "outcome": host["decision"],
            "should_execute": host["decision"] == "allow",
            "reason_codes": [native["code"]],
            "artifacts": {},
            "native_evidence": {
                "report": reference("native-report.json"),
                "request": reference("request-N1.json"),
                "verdict": reference("wrapper-N1.stdout.txt"),
                "input_packet": reference("input-packet.json"),
                "report_selector": "/runs/1",
                "native_failed_field": native["detail"]["field"],
                "artifact_role": "Captured test inputs and outputs; not application receipts or evaluated VATE receipt fixtures",
            },
            "limitations": [
                "N1 is one partial audience-mismatch evaluation. P and N2 are auxiliary controls, not additional VATE corpus cases.",
                "Fixed base /target/audience maps to signed project_key; mutated base /audience maps to request.project_key. This does not equate VATE audience with x402 payee semantics.",
                "The native request_mismatch reason is retained. No VATE reason code or named check is synthesized.",
                "The legacy case expects an admission-receipt fixture reference. That fixture was not evaluated and no application decision receipt was issued, so no receipt reference is submitted.",
                "Agent, model, program, capability tier, fixed clock, nonce and disposable operator key are native scaffolding. Other VATE request fields, payment routing, settlement and post-execution linkage are not evaluated.",
                "The command host retains decision and code. Detail, message and kind remain in captured native output; no application retention path was used.",
                "Reviewer Node 24.19.0 differs from candidate Node 24.13.0. Both use macOS arm64 and tsx 4.23.13; Bolyra dependencies follow the same committed lockfile. Candidate esbuild version was not supplied.",
            ],
        }],
        "limitations": [
            "Only one partial corpus case is submitted. The other 75 cases were not executed. Interpret whole-corpus failure counts with that distinction.",
            "The generated implementation report omits custom native evidence and detailed limitations; read it with this SUT result and replay.json.",
        ],
    }


if __name__ == "__main__":
    (HERE / "sut-results.json").write_text(json.dumps(project(), indent=2) + "\n")
