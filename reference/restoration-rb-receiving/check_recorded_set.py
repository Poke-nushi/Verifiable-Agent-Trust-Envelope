"""Read the published RB captures again with this reader and compare.

The three captures from run_capture.py at eaa47be4 are published in the
agent-evidence-vectors package as the recorded set vate-rb-receiving-captures.
This script checks three things for each case:

1. the retained bytes still match the digest list the set pins
   (agent-evidence-vectors recorded check);
2. this reader, run on the retained inputs, writes the retained report, every
   member except reader_source, whose digest changes with any edit here;
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


def compare_case(name: str, case: Path, second_reader) -> bool:
    retained = json.loads((case / "report.json").read_text(encoding="utf-8"))
    fresh = read_case(case)
    differing = sorted(key for key in set(retained) | set(fresh)
                       if key != "reader_source" and retained.get(key) != fresh.get(key))
    same_source = retained.get("reader_source") == fresh.get("reader_source")
    verdict, reason = second_reader((case / "statement.json").read_bytes())
    record = fresh["record_check"]
    agrees = (VERDICT_OF_STATUS.get(record["status"]) == verdict
              and record["reason"] == reason)
    print(f"{name}: report {'same' if not differing else 'differs in ' + ', '.join(differing)}"
          f" (reader source {'unchanged' if same_source else 'changed'});"
          f" record {record['status']} {record['reason']};"
          f" second reader {verdict} {reason}")
    return not differing and agrees


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
