#!/usr/bin/env python3
"""Narrate a small VATE admission-receipt demo from committed fixtures."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_ROOT = REPO_ROOT / "conformance" / "al2-vate-v0.3"
CORPUS_PATH = CORPUS_ROOT / "corpus.json"
DEFAULT_CASES = (
    ("allow", "allow-valid-admission"),
    ("attenuate", "attenuate-max-amount"),
    ("deny", "deny-digest-mismatch-before-policy"),
)
CLAIM_BOUNDARY = (
    "This is a discussion draft demo. No certification, endorsement, or\n"
    "production approval is implied. See docs/public-claim-boundary.md"
)


class DemoError(Exception):
    """Raised when committed demo inputs cannot be loaded."""


def read_json(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise DemoError(f"could not read {path.relative_to(REPO_ROOT)}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise DemoError(f"invalid JSON in {path.relative_to(REPO_ROOT)}: {exc}") from exc
    if not isinstance(data, dict):
        raise DemoError(f"expected JSON object in {path.relative_to(REPO_ROOT)}")
    return data


def load_corpus() -> dict[str, dict[str, Any]]:
    corpus = read_json(CORPUS_PATH)
    cases = corpus.get("cases")
    if not isinstance(cases, list):
        raise DemoError("corpus.json does not contain a cases array")

    index: dict[str, dict[str, Any]] = {}
    for entry in cases:
        if not isinstance(entry, dict):
            continue
        case_id = entry.get("case_id")
        if isinstance(case_id, str):
            index[case_id] = entry
    return index


def relative(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def artifact_ref(case: dict[str, Any]) -> tuple[str, Path]:
    artifacts = case.get("artifacts")
    if not isinstance(artifacts, dict):
        raise DemoError(f"{case.get('case_id', '<unknown>')} has no artifacts object")

    artifact_kind = "post_execution_receipt"
    artifact = artifacts.get(artifact_kind)
    if not isinstance(artifact, str):
        artifact_kind = "admission_receipt"
        artifact = artifacts.get(artifact_kind)
    if not isinstance(artifact, str):
        json_artifacts = [
            (key, value) for key, value in artifacts.items() if isinstance(value, str)
        ]
        if not json_artifacts:
            raise DemoError(f"{case.get('case_id', '<unknown>')} has no readable artifact path")
        artifact_kind, artifact = json_artifacts[0]
    return artifact_kind, REPO_ROOT / artifact


def load_case(case_id: str, corpus: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any], str, Path]:
    case = corpus.get(case_id)
    if not case:
        raise DemoError(f"unknown case_id: {case_id}")
    artifact_kind, artifact = artifact_ref(case)
    return case, read_json(artifact), artifact_kind, artifact


def decision(receipt: dict[str, Any]) -> dict[str, Any]:
    value = receipt.get("decision")
    if not isinstance(value, dict):
        return {}
    return value


def request(receipt: dict[str, Any]) -> dict[str, Any]:
    value = receipt.get("request")
    if not isinstance(value, dict):
        return {}
    return value


def attenuation(receipt: dict[str, Any]) -> dict[str, Any]:
    value = receipt.get("attenuation")
    if not isinstance(value, dict):
        return {}
    return value


def result_block(receipt: dict[str, Any]) -> dict[str, Any]:
    value = receipt.get("result")
    if not isinstance(value, dict):
        return {}
    return value


def outcome(receipt: dict[str, Any], case: dict[str, Any]) -> str:
    value = decision(receipt).get("outcome")
    if not isinstance(value, str):
        value = result_block(receipt).get("outcome")
    if not isinstance(value, str):
        value = case.get("expected_outcome", "unknown")
    return str(value).upper()


def action_summary(receipt: dict[str, Any]) -> str:
    action = request(receipt).get("action")
    if isinstance(action, str):
        return action
    side_effects = result_block(receipt).get("side_effects")
    if isinstance(side_effects, list) and side_effects and isinstance(side_effects[0], dict):
        effect_type = side_effects[0].get("type")
        if isinstance(effect_type, str):
            return effect_type
    return "external action"


def reason_codes(receipt: dict[str, Any], case: dict[str, Any]) -> list[str]:
    raw = decision(receipt).get("reason_codes")
    if not isinstance(raw, list):
        raw = case.get("expected_reason_codes")
    return [item for item in raw or [] if isinstance(item, str)]


def summarize_reason_codes(codes: list[str]) -> str:
    return "[" + ", ".join(codes) + "]"


def artifact_line(artifact_kind: str, artifact: Path) -> str:
    return f"Artifact shown: {artifact_kind} -> {relative(artifact)}"


def render_allow(scene_index: int, total: int, case: dict[str, Any], receipt: dict[str, Any], artifact_kind: str, artifact: Path) -> list[str]:
    title = case.get("title", "Committed corpus case")
    return [
        f"=== Scene {scene_index}/{total}: allow ===",
        f"Case          : {case['case_id']}",
        f"Agent requests: {action_summary(receipt)} ({title})",
        f"Decision      : {outcome(receipt, case)}",
        "Receipt       : admission receipt issued before execution",
        f"reason_codes  : {summarize_reason_codes(reason_codes(receipt, case))}",
        artifact_line(artifact_kind, artifact),
    ]


def render_attenuate(scene_index: int, total: int, case: dict[str, Any], receipt: dict[str, Any], artifact_kind: str, artifact: Path) -> list[str]:
    req = request(receipt)
    att = attenuation(receipt)
    changes = att.get("changes")
    change = changes[0] if isinstance(changes, list) and changes and isinstance(changes[0], dict) else {}
    constraints = att.get("effective_constraints")
    if not isinstance(constraints, dict):
        constraints = {}
    max_amount = constraints.get("max_amount")
    if not isinstance(max_amount, dict):
        max_amount = {}

    currency = str(max_amount.get("currency", ""))
    requested = str(change.get("from", "unknown"))
    effective = str(max_amount.get("value", change.get("to", "unknown")))
    reason = str(change.get("reason_code", case.get("expected_primary_reason_code", "")))
    expires = str(constraints.get("expires_at", receipt.get("expires_at", "unknown")))

    return [
        f"=== Scene {scene_index}/{total}: attenuate ===",
        f"Case          : {case['case_id']}",
        f"Agent requests: {req.get('action', 'external action')}, max_amount {currency} {requested}",
        f"Decision      : {outcome(receipt, case)} (narrowed, not rejected)",
        f"  requested   : {currency} {requested}",
        f"  effective   : {currency} {effective} ({reason})",
        f"  expires     : {expires}",
        f"  original_request_hash  : {att.get('original_request_hash', 'missing')}",
        f"  effective_request_hash : {att.get('effective_request_hash', 'missing')}",
        "Why two hashes: post-execution evidence is checked against the",
        "                effective narrowed authority, not the original request.",
        f"reason_codes  : {summarize_reason_codes(reason_codes(receipt, case))}",
        artifact_line(artifact_kind, artifact),
    ]


def render_deny(scene_index: int, total: int, case: dict[str, Any], receipt: dict[str, Any], artifact_kind: str, artifact: Path) -> list[str]:
    return [
        f"=== Scene {scene_index}/{total}: deny ===",
        f"Case          : {case['case_id']}",
        f"Agent requests: {action_summary(receipt)}, but a digest-bound artifact does not match",
        f"Decision      : {outcome(receipt, case)} (digest checked before policy evaluation)",
        f"reason_codes  : {summarize_reason_codes(reason_codes(receipt, case))}",
        artifact_line(artifact_kind, artifact),
    ]


def render_generic(scene_name: str, scene_index: int, total: int, case: dict[str, Any], receipt: dict[str, Any], artifact_kind: str, artifact: Path) -> list[str]:
    return [
        f"=== Scene {scene_index}/{total}: {scene_name} ===",
        f"Case          : {case['case_id']}",
        f"Title         : {case.get('title', 'Committed corpus case')}",
        f"Agent requests: {action_summary(receipt)}",
        f"Decision      : {outcome(receipt, case)}",
        f"reason_codes  : {summarize_reason_codes(reason_codes(receipt, case))}",
        artifact_line(artifact_kind, artifact),
    ]


def render_scene(scene_name: str, scene_index: int, total: int, case: dict[str, Any], receipt: dict[str, Any], artifact_kind: str, artifact: Path) -> str:
    if scene_name == "allow":
        lines = render_allow(scene_index, total, case, receipt, artifact_kind, artifact)
    elif scene_name == "attenuate":
        lines = render_attenuate(scene_index, total, case, receipt, artifact_kind, artifact)
    elif scene_name == "deny":
        lines = render_deny(scene_index, total, case, receipt, artifact_kind, artifact)
    else:
        lines = render_generic(scene_name, scene_index, total, case, receipt, artifact_kind, artifact)
    return "\n".join(lines)


def render_default(corpus: dict[str, dict[str, Any]]) -> str:
    scenes: list[str] = []
    total = len(DEFAULT_CASES)
    for index, (scene_name, case_id) in enumerate(DEFAULT_CASES, start=1):
        case, receipt, artifact_kind, artifact = load_case(case_id, corpus)
        scenes.append(render_scene(scene_name, index, total, case, receipt, artifact_kind, artifact))
    return "\n\n".join(scenes) + "\n\n" + CLAIM_BOUNDARY + "\n"


def render_one(case_id: str, corpus: dict[str, dict[str, Any]]) -> str:
    case, receipt, artifact_kind, artifact = load_case(case_id, corpus)
    scene_name = next(
        (name for name, default_case_id in DEFAULT_CASES if default_case_id == case_id),
        "case",
    )
    return render_scene(scene_name, 1, 1, case, receipt, artifact_kind, artifact) + "\n\n" + CLAIM_BOUNDARY + "\n"


def list_cases(corpus: dict[str, dict[str, Any]]) -> str:
    return "\n".join(sorted(corpus)) + "\n"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Narrate committed VATE v0.3 corpus cases as a 60-second demo."
    )
    parser.add_argument("--case", dest="case_id", help="Render one corpus case by case_id.")
    parser.add_argument("--json", action="store_true", help="Print the selected case artifact JSON.")
    parser.add_argument("--list", action="store_true", help="List available corpus case IDs.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        corpus = load_corpus()
        if args.list:
            sys.stdout.write(list_cases(corpus))
            return 0

        if args.json:
            if not args.case_id:
                raise DemoError("--json requires --case <case_id>")
            _, receipt, _, _ = load_case(args.case_id, corpus)
            json.dump(receipt, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
            return 0

        if args.case_id:
            sys.stdout.write(render_one(args.case_id, corpus))
            return 0

        sys.stdout.write(render_default(corpus))
        return 0
    except DemoError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
