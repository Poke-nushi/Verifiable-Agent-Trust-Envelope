#!/usr/bin/env python3
"""Runnable VATE AL2 v0.2 conformance corpus checker.

This runner intentionally uses only the Python standard library.
It validates the machine-readable behavior that matters for early interop:
decision outcomes, reason codes, attenuation shape, digest-bound references,
trust-bundle lookups, and post-execution linkage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "VATE-AL2-Verifier-Admission-v0.2"
CONFORMANCE_REPORT_VERSION = "vate-conformance-report-2026-07"
IMPLEMENTATION_REPORT_VERSION = "vate-implementation-report-2026-07"


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_value(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def resolve_artifact_path(case: dict[str, Any], key_or_path: str) -> Path:
    artifacts = case.get("artifacts", {})
    rel = artifacts.get(key_or_path, key_or_path)
    path = Path(rel)
    if path.is_absolute():
        return path
    return ROOT / path


def load_artifact(case: dict[str, Any], key: str) -> dict[str, Any] | None:
    rel = case.get("artifacts", {}).get(key)
    if not rel:
        return None
    return read_json(resolve_artifact_path(case, key))


def referenced_paths(case: dict[str, Any]) -> list[Path]:
    paths: list[Path] = []
    for key, value in case.get("artifacts", {}).items():
        if isinstance(value, str):
            paths.append(resolve_artifact_path(case, key))
    for check in case.get("integrity_checks", []):
        paths.append(resolve_artifact_path(case, check["artifact"]))
    for check in case.get("trust_checks", []):
        paths.append(resolve_artifact_path(case, check["trust_bundle"]))
    for check in case.get("policy_snapshot_checks", []):
        paths.append(resolve_artifact_path(case, check["artifact"]))
    return paths


def corpus_manifest(corpus_root: Path) -> tuple[list[dict[str, str]], dict[str, str]]:
    paths: set[Path] = set(path.resolve() for path in corpus_root.rglob("*.json"))
    for case_path in sorted((corpus_root / "cases").glob("*.json")):
        case = read_json(case_path)
        for path in referenced_paths(case):
            if path.exists():
                paths.add(path.resolve())

    manifest = [
        {
            "path": display_path(path),
            "sha256": sha256_file(path),
        }
        for path in sorted(paths, key=display_path)
    ]
    return manifest, {"alg": "sha-256", "value": sha256_value(manifest)}


def get_path(value: Any, dotted_path: str) -> Any:
    current = value
    for raw_part in dotted_path.split("."):
        part = raw_part
        if "[" in part and part.endswith("]"):
            name, index = part[:-1].split("[", 1)
            if name:
                current = current[name]
            current = current[int(index)]
            continue
        current = current[part]
    return current


def has_path(value: Any, dotted_path: str) -> bool:
    try:
        get_path(value, dotted_path)
        return True
    except (KeyError, IndexError, TypeError, ValueError):
        return False


def actual_decision(admission_receipt: dict[str, Any] | None) -> str:
    if admission_receipt is None:
        return "missing"
    return str(admission_receipt.get("decision", {}).get("outcome", "missing"))


def actual_reason_codes(admission_receipt: dict[str, Any] | None) -> list[str]:
    if admission_receipt is None:
        return []
    codes = admission_receipt.get("decision", {}).get("reason_codes", [])
    return [str(code) for code in codes]


def actual_linkage_reason_codes(
    admission_receipt: dict[str, Any] | None,
    post_execution_receipt: dict[str, Any] | None,
) -> list[str]:
    if admission_receipt is None or post_execution_receipt is None:
        return []

    receipt_id_matches = post_execution_receipt.get("admission", {}).get("receipt_id") == admission_receipt.get("receipt_id")

    effective_hash = admission_receipt.get("attenuation", {}).get(
        "effective_request_hash",
        admission_receipt.get("request", {}).get("input_hash"),
    )
    effective_hash_matches = post_execution_receipt.get("execution", {}).get("effective_request_hash") == effective_hash

    if not receipt_id_matches or not effective_hash_matches:
        return ["POST_EXEC_LINKAGE_MISMATCH"]

    codes = ["ADMISSION_RECEIPT_LINKED", "EFFECTIVE_REQUEST_HASH_MATCH"]
    if post_execution_receipt.get("result", {}).get("policy_violations") == []:
        codes.append("NO_POLICY_VIOLATIONS")
    return codes


def expected_outcome(case: dict[str, Any]) -> str:
    expected = case["expected"]
    if case["category"] == "linkage":
        return str(expected.get("post_execution_outcome", "missing"))
    return str(expected.get("admission_decision", expected.get("post_execution_outcome", "missing")))


def observed_outcome(case: dict[str, Any], admission: dict[str, Any] | None, post_execution: dict[str, Any] | None) -> str:
    if case["category"] == "linkage":
        if post_execution is None:
            return "missing"
        return str(post_execution.get("result", {}).get("outcome", "missing"))
    if "admission_decision" in case["expected"]:
        return actual_decision(admission)
    if post_execution is None:
        return "missing"
    return str(post_execution.get("result", {}).get("outcome", "missing"))


def bool_for_named_check(
    *,
    name: str,
    admission: dict[str, Any] | None,
    post_execution: dict[str, Any] | None,
    a2a_metadata: dict[str, Any] | None,
) -> bool:
    if name == "decision.outcome":
        return admission is not None and actual_decision(admission) in {"allow", "attenuate"}
    if name == "evidence.verification.result":
        if admission is None:
            return False
        return all(item.get("verification", {}).get("result") == "verified" for item in admission.get("evidence", []))
    if name == "evidence.verification.failure_reason":
        if admission is None:
            return False
        return any(has_path(item, "verification.failure_reason") for item in admission.get("evidence", []))
    if name == "policy.policy_version":
        return admission is not None and has_path(admission, "policy.policy_version")
    if name == "post_execution_receipt":
        return post_execution is not None
    if name in {"request.audience", "target.audience"}:
        if admission is None:
            return False
        request = admission.get("request", {})
        return request.get("audience") == request.get("target_audience")
    if name == "result.policy_violations":
        if post_execution is None:
            return False
        return post_execution.get("result", {}).get("policy_violations") == []

    artifact: dict[str, Any] | None
    dotted = name
    if name.startswith("a2a_metadata."):
        artifact = a2a_metadata
        dotted = name.removeprefix("a2a_metadata.")
    elif name.startswith("post_execution."):
        artifact = post_execution
        dotted = name.removeprefix("post_execution.")
    elif name.startswith("admission_receipt."):
        artifact = admission
        dotted = name.removeprefix("admission_receipt.")
    else:
        artifact = admission
    return artifact is not None and has_path(artifact, dotted)


def evaluate_expected_check(
    *,
    name: str,
    expected: str,
    admission: dict[str, Any] | None,
    post_execution: dict[str, Any] | None,
    a2a_metadata: dict[str, Any] | None,
) -> bool:
    value = bool_for_named_check(
        name=name,
        admission=admission,
        post_execution=post_execution,
        a2a_metadata=a2a_metadata,
    )
    if expected == "pass":
        return value
    if expected == "fail":
        return not value
    if expected == "present":
        return value
    if expected == "absent":
        return not value
    return False


def evaluate_integrity_checks(case: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for check in case.get("integrity_checks", []):
        artifact = read_json(resolve_artifact_path(case, check["artifact"]))
        actual = sha256_value(artifact)
        expected_digest = check["expected_digest"]["value"]
        expect_match = bool(check.get("expect_match", True))
        matched = actual == expected_digest
        if matched != expect_match:
            failures.append(
                f"integrity {check['artifact']}: expected match={expect_match} actual match={matched}"
            )
    return failures


def evaluate_trust_checks(case: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for check in case.get("trust_checks", []):
        bundle = read_json(resolve_artifact_path(case, check["trust_bundle"]))
        trusted = False
        for issuer in bundle.get("issuers", []):
            if issuer.get("issuer_id") != check["issuer_id"]:
                continue
            if issuer.get("kid") != check["kid"]:
                continue
            if check["evidence_type"] not in issuer.get("allowed_evidence_types", []):
                continue
            trusted = True
            break
        expect_trusted = bool(check.get("expect_trusted", True))
        if trusted != expect_trusted:
            failures.append(
                f"trust {check['issuer_id']} {check['kid']}: expected trusted={expect_trusted} actual trusted={trusted}"
            )
    return failures


def evaluate_linkage_checks(
    case: dict[str, Any],
    admission: dict[str, Any] | None,
    post_execution: dict[str, Any] | None,
) -> list[str]:
    failures: list[str] = []
    for check in case.get("linkage_checks", []):
        if admission is None or post_execution is None:
            failures.append("linkage: admission or post-execution artifact missing")
            continue
        left = get_path(admission, check["admission_path"])
        right = get_path(post_execution, check["post_execution_path"])
        matched = left == right
        expect_match = bool(check.get("expect_match", True))
        if matched != expect_match:
            failures.append(f"linkage: expected match={expect_match} actual match={matched}")
    return failures


def evaluate_policy_snapshot_checks(
    case: dict[str, Any],
    admission: dict[str, Any] | None,
    a2a_metadata: dict[str, Any] | None,
) -> list[str]:
    failures: list[str] = []
    for check in case.get("policy_snapshot_checks", []):
        artifact = read_json(resolve_artifact_path(case, check["artifact"]))
        artifact_digest = {
            "alg": "sha-256",
            "value": sha256_value(artifact),
        }
        expect_match = bool(check.get("expect_match", True))
        reference_paths = check.get(
            "reference_paths",
            [
                {
                    "artifact": "admission_receipt",
                    "path": "policy.policy_snapshot",
                }
            ],
        )

        references: list[tuple[str, dict[str, Any]]] = []
        for reference in reference_paths:
            artifact_name = reference["artifact"]
            if artifact_name == "admission_receipt":
                source = admission
            elif artifact_name == "a2a_metadata":
                source = a2a_metadata
            else:
                failures.append(f"policy_snapshot {artifact_name}: unsupported reference artifact")
                continue
            if source is None:
                failures.append(f"policy_snapshot {artifact_name}: artifact missing")
                continue
            try:
                snapshot_ref = get_path(source, reference["path"])
            except (KeyError, IndexError, TypeError, ValueError):
                failures.append(f"policy_snapshot {artifact_name}: reference path missing")
                continue
            references.append((artifact_name, snapshot_ref))

            digest_matches = snapshot_ref.get("digest") == artifact_digest
            if digest_matches != expect_match:
                failures.append(
                    f"policy_snapshot {artifact_name}: expected digest match={expect_match} actual match={digest_matches}"
                )

        if len(references) < 2:
            continue

        first_name, first_ref = references[0]
        for name, snapshot_ref in references[1:]:
            for field in check.get("compare_fields", ["uri", "media_type", "digest"]):
                if first_ref.get(field) != snapshot_ref.get(field):
                    failures.append(f"policy_snapshot {first_name}/{name}: field {field} mismatch")
    return failures


def evaluate_case(case_path: Path) -> dict[str, Any]:
    case = read_json(case_path)
    admission = load_artifact(case, "admission_receipt")
    post_execution = load_artifact(case, "post_execution_receipt")
    a2a_metadata = load_artifact(case, "a2a_metadata")

    expected_codes = [str(code) for code in case["expected"]["reason_codes"]]
    if case["category"] == "linkage":
        actual_codes = actual_linkage_reason_codes(admission, post_execution)
    else:
        actual_codes = actual_reason_codes(admission)
    expected = expected_outcome(case)
    actual = observed_outcome(case, admission, post_execution)

    failures: list[str] = []
    if actual != expected:
        failures.append(f"outcome: expected {expected} actual {actual}")
    if actual_codes != expected_codes:
        failures.append(f"reason_codes: expected {expected_codes} actual {actual_codes}")

    for check in case["expected"].get("checks", []):
        if not evaluate_expected_check(
            name=check["name"],
            expected=check["expected"],
            admission=admission,
            post_execution=post_execution,
            a2a_metadata=a2a_metadata,
        ):
            failures.append(f"check {check['name']}: expected {check['expected']}")

    failures.extend(evaluate_integrity_checks(case))
    failures.extend(evaluate_trust_checks(case))
    failures.extend(evaluate_linkage_checks(case, admission, post_execution))
    failures.extend(evaluate_policy_snapshot_checks(case, admission, a2a_metadata))

    return {
        "case_id": case["case_id"],
        "category": case["category"],
        "expected_outcome": expected,
        "actual_outcome": actual,
        "expected_reason_codes": expected_codes,
        "actual_reason_codes": actual_codes,
        "pass": not failures,
        "failures": failures,
    }


def run_corpus(corpus_root: Path) -> dict[str, Any]:
    case_paths = sorted((corpus_root / "cases").glob("*.json"))
    cases = [evaluate_case(path) for path in case_paths]
    failed = sum(1 for item in cases if not item["pass"])
    report = {
        "version": CONFORMANCE_REPORT_VERSION,
        "profile": PROFILE,
        "checked_at": iso_now(),
        "summary": {
            "total": len(cases),
            "passed": len(cases) - failed,
            "failed": failed,
            "skipped": 0,
        },
        "cases": cases,
    }
    if not case_paths:
        report["fatal_errors"] = ["no conformance case files found"]
    return report


def make_implementation_report(args: argparse.Namespace, conformance_report: dict[str, Any]) -> dict[str, Any]:
    corpus_root = Path(args.corpus_root)
    manifest, digest = corpus_manifest(corpus_root)
    implementation = {
        "name": args.implementation_name,
        "type": args.implementation_type,
        "version": args.implementation_version,
        "language": args.implementation_language,
    }
    if args.implementation_repo:
        implementation["source"] = args.implementation_repo
    if args.implementation_commit:
        implementation["commit"] = args.implementation_commit
    if args.environment:
        implementation["environment"] = args.environment

    failed = bool(conformance_report.get("fatal_errors") or conformance_report["summary"]["failed"])
    return {
        "version": IMPLEMENTATION_REPORT_VERSION,
        "profile": PROFILE,
        "generated_at": conformance_report["checked_at"],
        "status": "fail" if failed else "pass",
        "implementation": implementation,
        "corpus": {
            "name": corpus_root.name,
            "root": display_path(corpus_root.resolve()),
            "case_count": conformance_report["summary"]["total"],
            "artifact_count": len(manifest),
            "digest": digest,
            "manifest": manifest,
        },
        "conformance_report": {
            "uri": args.conformance_report_uri or str(Path(args.report)),
            "media_type": "application/vate-conformance-report+json",
            "digest": {
                "alg": "sha-256",
                "value": sha256_value(conformance_report),
            },
        },
        "summary": conformance_report["summary"],
        "case_results": [
            {
                "case_id": case["case_id"],
                "expected_outcome": case["expected_outcome"],
                "actual_outcome": case["actual_outcome"],
                "pass": case["pass"],
            }
            for case in conformance_report["cases"]
        ],
        "limitations": [
            "This report records one implementation run against one corpus snapshot.",
            "Passing cases do not imply production readiness or endorsement.",
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the VATE AL2 v0.2 conformance corpus")
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run", help="run a conformance corpus")
    run.add_argument("--corpus-root", required=True, help="corpus root containing cases/")
    run.add_argument("--report", required=True, help="path to write the machine-readable report")
    run.add_argument("--implementation-report", help="optional path to write an implementation report")
    run.add_argument("--implementation-name", default="VATE reference artifact checker")
    run.add_argument("--implementation-type", default="reference-artifact-checker")
    run.add_argument("--implementation-version", default="0.2")
    run.add_argument("--implementation-language", default="Python 3 standard library")
    run.add_argument("--implementation-repo")
    run.add_argument("--implementation-commit")
    run.add_argument("--environment")
    run.add_argument("--conformance-report-uri")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "run":
        report = run_corpus(Path(args.corpus_root))
        write_json(Path(args.report), report)
        if args.implementation_report:
            write_json(Path(args.implementation_report), make_implementation_report(args, report))
        if report.get("fatal_errors") or report["summary"]["failed"]:
            return 1
        return 0
    raise RuntimeError(f"unsupported command {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
