"""Project the saved Vaara reviewer output; this script does not run Vaara."""

import hashlib
import json
from pathlib import Path
import re


HERE = Path(__file__).resolve().parent


def project():
    replay = json.loads((HERE / "replay.json").read_text())
    for run in replay["runs"]:
        for stream in ("stdout", "stderr"):
            path = HERE / run[stream]
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != run[f"{stream}_sha256"]:
                raise ValueError(f"Saved output changed: {path.name}")
        if run["exit_code"] != 0 or run["failed_assertions"] != 0:
            raise ValueError("The saved native execution did not complete successfully")

    native = (HERE / "freshness_admission.stdout.txt").read_text()
    matches = re.findall(
        r"^\s*bound 300s, registry 301s old \(the case\)\s+"
        r"-> ok=(True|False),\s+reason='([^']+)'\s*$",
        native,
        re.MULTILINE,
    )
    if len(matches) != 1:
        raise ValueError("Expected exactly one selected native verdict")
    native_ok, native_reason = matches[0]
    allows = native_ok == "True"
    profile = "VATE-AL2-Verifier-Admission-v0.3"
    return {
        "version": "vate-sut-results-2026-09",
        "profile": profile,
        "generated_at": replay["projection_generated_at"],
        "artifact_mode": "corpus-fixture-validation",
        "implementation": {
            "name": "Vaara",
            "type": "reviewer-native-run-vate-side-projection",
            "version": replay["candidate_version"],
            "language": "Python",
            "source": "https://github.com/vaaraio/vaara",
            "commit": replay["candidate_commit"],
            "candidate_execution_report": replay["candidate_report"]["candidate_report_url"],
            "reviewer_execution_record": "replay.json",
            "formatted_by": "VATE maintainer",
            "provenance_status": "VATE-maintainer replay of unchanged candidate scripts; values parsed from saved reviewer stdout",
        },
        "corpus": {
            "profile": profile,
            "digest": {"alg": "sha-256", "value": replay["corpus_digest"]},
        },
        "results": [{
            "case_id": replay["case_id"],
            "status": "completed",
            "outcome": "allow" if allows else "deny",
            "should_execute": allows,
            "reason_codes": [native_reason],
            "artifacts": {"input_artifacts": [{
                "case_artifact": "status_context",
                "role": "status_evidence",
                "uri": replay["fixture_path"],
                "media_type": "application/json",
                "digest": {"alg": "sha-256", "value": replay["fixture_sha256"]},
            }]},
            "limitations": [
                "One partial evaluation at Vaara 4459c46; the earlier a8b0705 run observed registry freshness without evaluating admission.",
                "The native admission verdict is projected using the candidate's stated mapping. The native reason is retained without adding VATE reason codes or unperformed named checks.",
                "source_issued_at determines registry as_of, grant iat and the fixed credential clock; checked_at sets revocation_now; max_age_seconds sets the freshness bound and test grant lifetime. The split clocks isolate registry freshness from credential TTL.",
                "The HS256 test key, matching tool/tenant/arguments and supplied known binding digest are non-VATE scaffolding. Grant timing fields are derived from the VATE input. No VATE receipt or named VATE check was evaluated.",
                "required is unmapped; availability and artifact status:active are not evaluated. The relation between the status-source subject/authority and the credential issuer/key remains unresolved.",
                "TTL, registry and real-clock Gateway controls are auxiliary observations, not additional VATE corpus case executions. The Gateway controls do not reproduce the exact 300/301-second boundary or execute an upstream tool.",
                "Reviewer runtime: CPython 3.12.14/macOS arm64. Candidate-reported runtime: CPython 3.12.13/Linux aarch64; exact candidate optional-dependency versions and full original stdout/stderr are unavailable.",
            ],
        }],
        "limitations": [
            "Only one partial corpus case is submitted; the remaining 75 cases were not executed. Read README.md, replay.json and this SUT result with the generated implementation report, which omits the custom provenance and detailed limitations."
        ],
    }


if __name__ == "__main__":
    (HERE / "sut-results.json").write_text(json.dumps(project(), indent=2) + "\n")
