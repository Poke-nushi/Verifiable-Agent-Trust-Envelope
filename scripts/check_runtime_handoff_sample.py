"""Check the standalone handoff sample from a fresh, unrelated source folder.

Install the sample's requirements.lock in the selected Python environment first.
This checker installs nothing and uses synthetic keys and local files only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

SAMPLE = Path(__file__).resolve().parents[1] / "reference/runtime-handoff-sample"
SUITES = (
    ("provider", "sample/test_handoff.py", 52),
    ("receiver", "inbox/test_bridge.py", 32),
    ("distribution", "test_distribution.py", 8),
)
# First effect, latest effect, first coverage, latest coverage, linkage outcome.
EXPECTED = {
    "a-completed-response-lost": ("completed", "completed", "present", "present", "success"),
    "accepted-zero-effects": ("unresolved", "unresolved", "missing", "missing", "unassessable"),
    "accepted-partial-effects": ("unresolved", "unresolved", "missing", "missing", "unassessable"),
    "b-after-unaccepted-a": ("unresolved", "completed", "missing", "present", "success"),
    "completed-then-observed-later": ("completed", "completed", "present", "present", "success"),
    "effect-completed-outside-admission": ("completed", "completed", "present", "present", "failed"),
}
SUCCESS_REASONS = [
    "ADMISSION_RECEIPT_LINKED", "ADMISSION_DIGEST_MATCH", "ADMISSION_DECISION_EXECUTABLE",
    "TRANSACTION_MATCH", "RUNTIME_MATCH", "ADMISSION_WINDOW_VALID", "EFFECTIVE_REQUEST_HASH_MATCH",
    "EFFECTIVE_CONSTRAINTS_OBSERVED", "NO_POLICY_VIOLATIONS",
]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def snapshot(root):
    files = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), f"unexpected symlink: {path}")
        if path.is_dir():
            continue
        require(path.is_file(), f"unexpected non-file: {path}")
        files[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return files


def verify_inventory(source):
    before = snapshot(source)
    manifest = json.loads((source / "SOURCE-MANIFEST.json").read_bytes())
    require(len(before) == 49, "expected the complete 49-file distribution")
    require({k: v for k, v in before.items() if k != "SOURCE-MANIFEST.json"} == manifest["files"],
            "source inventory or hashes differ from the distribution manifest")
    return before


def test_count(stderr, minimum):
    matches = re.findall(r"^Ran (\d+) tests? in ", stderr, re.MULTILINE)
    require(len(matches) == 1 and stderr.rstrip().endswith("OK"), "missing successful unittest summary")
    count = int(matches[0])
    require(count >= minimum, f"test inventory fell below {minimum}")
    return count


def verify_scenarios(summary):
    require(isinstance(summary, dict) and set(summary) == set(EXPECTED), "scenario inventory differs")
    for name, expected in EXPECTED.items():
        row = summary[name]
        actual = (row["first_effect"], row["latest_effect"], row["first_coverage"]["expected-post"],
                  row["latest_coverage"]["expected-post"], row["linkage"]["outcome"])
        require(actual == expected, f"unexpected scenario result: {name}: {actual}")
        replay = row["replay"]
        require(replay["is_execution_ticket"] is False and replay["required_records_replayed"] is True
                and type(replay["capsules_reassessed"]) is int and replay["capsules_reassessed"] == 2,
                f"incomplete or unsafe replay: {name}")
        reasons = row["linkage"]["reason_codes"]
        require(isinstance(reasons, list) and bool(reasons), f"missing linkage reasons: {name}")
        if name == "effect-completed-outside-admission":
            require(reasons == ["POST_EXEC_ADMISSION_EXPIRED"], "outside-admission effect lost its failure")
        elif row["latest_effect"] == "unresolved":
            require(reasons == ["ACTUAL_EXECUTION_TIMES_UNAVAILABLE"], "unknown effect lost its reason")
        else:
            require(reasons == SUCCESS_REASONS, "successful linkage reasons differ: " + name)


def check(source, integrity_only=False):
    before = verify_inventory(source)
    prefix = [sys.executable, "-E", "-s", "-B"]
    with tempfile.TemporaryDirectory(prefix="vate handoff check ") as directory:
        work = Path(directory).resolve()
        copied = work / "separate source folder"
        shutil.copytree(source, copied)

        def call(label, arguments):
            print(f"Runtime handoff: {label}", file=sys.stderr, flush=True)
            result = subprocess.run(prefix + list(map(str, arguments)), cwd=work,
                                    capture_output=True, text=True, timeout=3600)
            require(result.returncode == 0,
                    f"{label} failed (exit {result.returncode})\n{result.stdout}\n{result.stderr}")
            return result

        environment_args = [copied / "check_environment.py"]
        if integrity_only:
            environment_args.append("--sources-only")
        environment = json.loads(call("environment", environment_args).stdout)
        require(environment["status"] == "ok" and environment["source_files_verified"] == 48,
                "environment or source verification failed")
        if integrity_only:
            require(before == snapshot(copied) == snapshot(source), "source files changed")
            return {"status": "pass", "source_files": len(before), "scope": "inventory and hashes only"}

        counts = {}
        for label, path, minimum in SUITES:
            result = call(label + " tests", [copied / path, "-v"])
            counts[label] = test_count(result.stderr, minimum)
            print(result.stderr, file=sys.stderr, end="", flush=True)

        demo = work / "demo"
        summary = json.loads(call("six histories", [copied / "inbox/demo_connection.py", "--out", demo]).stdout)
        verify_scenarios(summary)
        selection = demo / "a-completed-response-lost/receiver-selection.json"
        bundle = demo / "synthetic-inputs/a-completed-response-lost/bundle.json"
        database = work / "receiver.sqlite3"
        cli = [copied / "inbox/receive_handoff.py", "--selection", selection, "--db", database]
        call("init", [*cli, "init"])
        call("receive", [*cli, "receive", "--event", "received-final", "--bundle", bundle,
                         "--received-at", "2026-10-25T00:16:40Z"])
        prepared = json.loads(call("prepare", [*cli, "prepare", "--cutoff", "2026-10-25T00:18:20Z",
                                               "--assessed-at", "2026-10-25T00:20:00Z"]).stdout)
        run_id = prepared["run_id"]
        assessed = json.loads(call("run", [*cli, "run", run_id]).stdout)
        require(assessed["inbox"]["status"] == "completed" and assessed["handoff"]["effect_state"] == "completed"
                and assessed["is_execution_ticket"] is False, "CLI assessment did not complete safely")
        require(json.loads(call("status", [*cli, "status", run_id]).stdout) == assessed,
                "saved assessment differs from run output")
        exported = work / "export"
        call("export", [*cli, "export", run_id, exported])
        saved = snapshot(exported)
        moved = work / "moved evidence"
        exported.rename(moved)
        # The command below has no database argument and only uses the moved evidence.
        replay = json.loads(call("replay", [copied / "inbox/receive_handoff.py", "--selection", selection,
                                            "replay", moved]).stdout)
        require(replay["is_execution_ticket"] is False and replay["required_records_replayed"] is True,
                "CLI replay did not verify the saved assessment")
        require(saved == snapshot(moved), "replay changed exported evidence")
        require(before == snapshot(copied) == snapshot(source), "source files changed during verification")
        return {"status": "pass", "environment": environment, "tests": counts, "scenarios": summary,
                "cli_chain_passed": True, "source_unchanged": True, "export_unchanged": True,
                "source_folder_contains_spaces": True, "source_sha256": before,
                "scope": "local synthetic provider and receiver; no external deployment or general PKI proof"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample-root", type=Path, default=SAMPLE,
                        help="complete standalone sample, including one extracted from a source archive")
    parser.add_argument("--integrity-only", action="store_true", help="check inventory and hashes without dependencies")
    args = parser.parse_args()
    print(json.dumps(check(args.sample_root.resolve(), args.integrity_only), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
