"""Run full and production npm audits for the TypeScript reference workspace."""

import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
LEVELS = ("info", "low", "moderate", "high", "critical")
BLOCKING = {"moderate", "high", "critical"}


def has_blocking_findings(report, exit_code):
    if not isinstance(report, dict) or report.get("auditReportVersion") != 2 or "error" in report:
        raise ValueError("npm did not return a complete version 2 audit report")
    entries = report.get("vulnerabilities")
    metadata = report.get("metadata")
    counts = metadata.get("vulnerabilities") if isinstance(metadata, dict) else None
    if not isinstance(entries, dict) or not isinstance(counts, dict):
        raise ValueError("npm audit findings or counts are missing")
    observed = dict.fromkeys(LEVELS, 0)
    for name, item in entries.items():
        if not isinstance(item, dict) or item.get("name") != name or item.get("severity") not in LEVELS:
            raise ValueError("invalid npm audit finding")
        severity = item["severity"]
        observed[severity] += 1
    observed["total"] = len(entries)
    if counts != observed or any(type(n) is not int for n in counts.values()):
        raise ValueError("npm audit counts do not match its findings")
    blocking = any(observed[level] for level in BLOCKING)
    if exit_code != int(blocking):
        raise ValueError(f"npm audit exit status {exit_code} disagrees with its findings")
    return blocking


def run_audit(scope):
    command = ["npm", "audit", "--json", "--audit-level=moderate", scope]
    print(" ".join(command), flush=True)
    result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE)
    print(result.stdout, flush=True)
    return has_blocking_findings(json.loads(result.stdout), result.returncode)


def main():
    full = run_audit("--include=dev")
    production = run_audit("--omit=dev")
    if full or production:
        raise ValueError("npm reported dependency findings at moderate severity or higher")
    print("Both npm audits passed the moderate threshold.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        sys.exit(f"Dependency audit failed: {error}")
