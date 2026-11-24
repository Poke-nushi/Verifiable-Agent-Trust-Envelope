"""Read the published RB captures again with this reader and compare.

The three captures from run_capture.py at eaa47be4 are published in the
agent-evidence-vectors package as the recorded set vate-rb-receiving-captures.
This script checks three things for each case:

1. the retained bytes still match the digest list the set pins
   (agent-evidence-vectors recorded check);
2. this reader, run on the retained inputs, writes the retained report: the
   same fields, JSON types and values in every member. Only the digest and
   length inside reader_source may differ, because they change with any edit
   here; reader_source itself must still be present with the same shape;
3. a second RB reader written separately from the same draft text
   (agent-evidence-verify, restoration rules) gives the same record verdict.

Exit 0 when all three hold for every case, 1 when one does not, 2 when the
check could not run. Install the pinned packages first:
python -m pip install -r reference/restoration-rb-receiving/requirements-recorded.txt
"""

from __future__ import annotations

import json
import subprocess
import sys
from importlib import resources
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import rb_receiving  # noqa: E402

SET_NAME = "vate-rb-receiving-captures"
CASES = ("no_commit", "commit_observed", "not_established")
# A passed record check here is an accept there, with the same reason code.
VERDICT_OF_STATUS = {"passed": "accept", "failed": "reject"}
# The reader's own digest and length change with any edit to it, so only their
# values are left out of the comparison; their presence and type are compared.
SOURCE_VALUES = ("reader_source.sha256", "reader_source.byte_length")
JSON_NAME = {bool: "boolean", int: "integer", float: "number", str: "string",
             type(None): "null", list: "array", dict: "object"}
SHOWN = 8


def set_root() -> Path:
    package = resources.files("agent_evidence_vectors")
    root = Path(str(package)) / "corpora" / "vectors-recorded" / "sets" / SET_NAME / "bytes"
    if not (root / "SHA256SUMS").is_file():
        raise FileNotFoundError(f"{root}/SHA256SUMS")
    return root


def digests_hold(root: Path) -> bool:
    command = [sys.executable, "-m", "agent_evidence_vectors.recorded", "check",
               str(root), "--member", SET_NAME, "--json"]
    done = subprocess.run(command, capture_output=True, text=True, check=False)
    if done.returncode not in (0, 1):
        raise RuntimeError(done.stderr.strip() or f"recorded check exited {done.returncode}")
    answer = json.loads(done.stdout)
    print(f"digest list: {answer['verdict']} {answer['codes']}")
    return answer["verdict"] == "verified"


def read_case(case: Path) -> dict:
    return rb_receiving.assess(
        (case / "statement.json").read_bytes(),
        (case / "selection.json").read_bytes(),
        test_plan=(case / "test_plan.json").read_bytes(),
        observation=(case / "observation.json").read_bytes(),
    )


def json_name(value) -> str:
    return JSON_NAME.get(type(value), type(value).__name__)


def differences(retained, fresh, path: str = "") -> list[str]:
    """Name each place two decoded JSON values differ in type, presence or value.

    Python's == hides what the JSON text shows: 0 equals false, 1 equals true,
    0 equals 0.0, and dict.get gives None for a field that is absent. So types
    are compared exactly, an object's fields by presence and an array by length.
    """
    where = path or "report"
    if type(retained) is not type(fresh):
        return [f"{where}: {json_name(retained)} in retained, {json_name(fresh)} in fresh"]
    if type(retained) is dict:
        found: list[str] = []
        for key in sorted(retained.keys() | fresh.keys()):
            below = f"{path}.{key}" if path else key
            if key not in retained or key not in fresh:
                found.append(f"{below}: absent in {'retained' if key not in retained else 'fresh'}")
            else:
                found.extend(differences(retained[key], fresh[key], below))
        return found
    if type(retained) is list:
        if len(retained) != len(fresh):
            return [f"{where}: {len(retained)} items in retained, {len(fresh)} in fresh"]
        return [line for index, pair in enumerate(zip(retained, fresh))
                for line in differences(*pair, f"{path}[{index}]")]
    if path in SOURCE_VALUES or retained == fresh:
        return []
    return [f"{where}: value differs"]


def load_report(case: Path):
    """The retained report, read with this reader's own strict JSON decoder.

    It refuses duplicate keys, which json.loads would collapse to the last one,
    and every number that is not an integer.
    """
    return rb_receiving.decode((case / "report.json").read_bytes(), "report")


def same_source(retained, fresh: dict) -> bool:
    return (type(retained) is dict and "reader_source" in retained
            and rb_receiving.encode(retained["reader_source"])
            == rb_receiving.encode(fresh["reader_source"]))


def compare_case(name: str, case: Path, second_reader) -> bool:
    fresh = read_case(case)
    try:
        retained = load_report(case)
    except rb_receiving.InputError as error:
        retained, found = None, [f"report.json: unreadable ({error.code})"]
    else:
        found = differences(retained, fresh)
    verdict, reason = second_reader((case / "statement.json").read_bytes())
    record = fresh["record_check"]
    agrees = (VERDICT_OF_STATUS.get(record["status"]) == verdict
              and record["reason"] == reason)
    shown = "; ".join(found[:SHOWN]) + (f"; and {len(found) - SHOWN} more" if len(found) > SHOWN else "")
    print(f"{name}: report {'same' if not found else 'differs: ' + shown}"
          f" (reader source {'unchanged' if same_source(retained, fresh) else 'changed'});"
          f" record {record['status']} {record['reason']};"
          f" second reader {verdict} {reason}")
    return not found and agrees


def main() -> int:
    try:
        from agent_evidence_verify.adapters.restoration import check_record_bytes
        root = set_root()
        held = digests_hold(root)
        results = [compare_case(name, root / name, check_record_bytes) for name in CASES]
    except (ImportError, OSError, RuntimeError, ValueError, KeyError) as error:
        print(f"could not run: {error}", file=sys.stderr)
        return 2
    passed = sum(results)
    print(f"{passed} of {len(CASES)} cases reproduce and agree")
    return 0 if held and passed == len(CASES) else 1


if __name__ == "__main__":
    sys.exit(main())
