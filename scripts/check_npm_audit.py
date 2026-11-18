"""Run full and production npm audits for the TypeScript reference workspace."""

import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
LEVELS = ("info", "low", "moderate", "high", "critical")
BLOCKING = {"moderate", "high", "critical"}
ADVISORY = "https://github.com/advisories/GHSA-fc5q-39xc-vjpf"
# Direct causes reported for each affected development dependency at review.
REVIEWED_VIA = {
    "fdir": {"picomatch"},
    "tinyglobby": {"fdir", "picomatch"},
    "vite": {"picomatch", "tinyglobby"},
    "vitest": {"picomatch", "tinyglobby"},
}


def blocking_findings(report, exit_code):
    if not isinstance(report, dict) or report.get("auditReportVersion") != 2 or "error" in report:
        raise ValueError("npm did not return a complete version 2 audit report")
    entries = report.get("vulnerabilities")
    metadata = report.get("metadata")
    counts = metadata.get("vulnerabilities") if isinstance(metadata, dict) else None
    if not isinstance(entries, dict) or not isinstance(counts, dict):
        raise ValueError("npm audit findings or counts are missing")
    observed = dict.fromkeys(LEVELS, 0)
    blocking = {}
    for name, item in entries.items():
        if not isinstance(item, dict) or item.get("name") != name or item.get("severity") not in LEVELS:
            raise ValueError("invalid npm audit finding")
        severity = item["severity"]
        observed[severity] += 1
        if severity in BLOCKING:
            blocking[name] = item
    observed["total"] = len(entries)
    if counts != observed or any(type(n) is not int for n in counts.values()):
        raise ValueError("npm audit counts do not match its findings")
    if exit_code != int(bool(blocking)):
        raise ValueError(f"npm audit exit status {exit_code} disagrees with its findings")
    return blocking


def run_audit(scope):
    command = ["npm", "audit", "--json", "--audit-level=moderate", scope]
    print(" ".join(command), flush=True)
    result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE)
    print(result.stdout, flush=True)
    return blocking_findings(json.loads(result.stdout), result.returncode)


def covered_by_review(findings, packages):
    if "picomatch" not in findings:
        return False
    for name, finding in findings.items():
        path = f"node_modules/{name}"
        package = packages.get(path, {})
        if finding["severity"] != "high" or finding.get("nodes") != [path] or package.get("dev") is not True:
            return False
        causes = finding.get("via")
        if not isinstance(causes, list) or not causes:
            return False
        if name == "picomatch":
            if len(causes) != 1 or not isinstance(causes[0], dict):
                return False
            advisory = causes[0]
            if (package.get("version") != "4.0.7" or advisory.get("url") != ADVISORY
                    or advisory.get("name") != name or advisory.get("dependency") != name
                    or advisory.get("severity") != "high" or advisory.get("range") != "<=4.0.7"):
                return False
        elif (name not in REVIEWED_VIA or not all(isinstance(cause, str) for cause in causes)
              or set(causes) != REVIEWED_VIA[name] or not set(causes).issubset(findings)):
            return False
    return True


def main():
    full = run_audit("--include=dev")
    production = run_audit("--omit=dev")
    if production:
        raise ValueError("production dependency audit has blocking findings")
    if not full:
        print("Both npm audits passed the moderate threshold.")
        return

    reviewed = os.environ.get("VATE_REVIEWED_NPM_TREE")
    if not reviewed:
        raise ValueError("full dependency audit has blocking findings and no active review")
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip()
    if tree != reviewed:
        raise ValueError("full dependency audit has blocking findings outside the reviewed source tree")
    subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=ROOT, check=True)
    if subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=ROOT):
        raise ValueError("the checkout contains unreviewed files")
    lock = json.loads((ROOT / "package-lock.json").read_text(encoding="utf-8"))
    if not covered_by_review(full, lock["packages"]):
        raise ValueError("full dependency audit has findings outside the reviewed development dependency paths")
    print(f"Full audit reported {len(full)} affected development packages covered by {ADVISORY}.")
    print("Production dependency audit passed the moderate threshold.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        sys.exit(f"Dependency audit failed: {error}")
