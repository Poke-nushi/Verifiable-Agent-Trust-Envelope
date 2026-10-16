"""Fresh local file-set originals for receiver regression tests; no network."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

SCENARIOS = ("allow", "attenuate", "require-new-permit", "response-loss-reconciled", "response-loss")


def capture_cases(root, output):
    output = Path(output)
    output.mkdir()
    # Isolate the demo's imports from the receiver's evaluator modules.
    code = """
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from run_demo import run_case
from verify_evidence import validate_schemas
reports = {}
for name in sys.argv[3:]:
    case = Path(sys.argv[2]) / name
    reports[name] = run_case(case, name)
    validate_schemas(case)
print(json.dumps(reports))
"""
    result = subprocess.run([sys.executable, "-B", "-c", code,
                             str(Path(root) / "reference/execution-evidence-demo"),
                             str(output), *SCENARIOS], capture_output=True, timeout=120)
    if result.returncode:
        raise RuntimeError("file-set fixture capture failed: " + result.stderr.decode(errors="replace"))
    reports = json.loads(result.stdout)
    for name, report in reports.items():
        expected = "indeterminate" if name == "response-loss" else "verified"
        executions = 0 if name == "require-new-permit" else 1
        if report["verdict"] != expected or report["provider_execution_count"] != executions:
            raise ValueError("unexpected native file-set evidence: " + json.dumps(report))
    return reports


def receipt_pair(case):
    case = Path(case)
    post = case / "adapter/post-execution-receipt.json"
    return ((case / "admission-1/receipt.json").read_bytes(),
            post.read_bytes() if post.is_file() else None)


def operation_context(admission):
    """Select the subject from producer originals, without the checker parser."""
    doc = json.loads(admission)
    return {"transaction_id": doc["request"]["transaction_id"],
            "runtime": doc["subject"]["runtime"],
            "effective_request_hash": "sha-256:" + doc["request"]["action_binding"]["digest"]["value"],
            "action_binding": deepcopy(doc["request"]["action_binding"])}


def tree_hashes(folder):
    return {str(path.relative_to(folder)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(Path(folder).rglob("*")) if path.is_file()}
