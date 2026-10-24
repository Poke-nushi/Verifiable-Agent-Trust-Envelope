"""Check the standalone revocation sample in a fresh folder and pip-free venv.

Uses existing Python and OpenSSL only. No installs, network calls, operational
keys, or original repository imports are needed by the copied sample.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile

SAMPLE = Path(__file__).resolve().parents[1] / "reference/post-admission-revocation-sample"
EXPECTED = {
    "active": ("effect_observed", True, 2),
    "revoked-before": ("not_accepted", False, 0),
    "revoke-after-pull": ("not_accepted", False, 0),
    "revoke-after-accept": ("effect_observed", True, 2),
    "partial-effect": ("unknown", True, 1),
    "lost-response": ("effect_observed", True, 2),
    "expired-conflict": ("not_accepted", False, 0),
    "same-input-resigned": ("effect_observed", True, 2),
}


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


def check(source):
    before = snapshot(source)
    manifest = json.loads((source / "SOURCE-MANIFEST.json").read_bytes())
    require(len(before) == 17, "expected the complete 17-file distribution")
    require({k: v for k, v in before.items() if k != "SOURCE-MANIFEST.json"} == manifest["files"],
            "source inventory or hashes differ from the distribution manifest")
    with tempfile.TemporaryDirectory(prefix="vate revocation check ") as directory:
        work = Path(directory).resolve()
        copied = work / "separate source folder"
        shutil.copytree(source, copied)

        def call(arguments, expected=0):
            result = subprocess.run(arguments, cwd=work, capture_output=True, text=True, timeout=600)
            require(result.returncode == expected,
                    f"command failed: {arguments}\n{result.stdout}\n{result.stderr}")
            return result

        call([sys.executable, "-E", "-s", "-B", "-m", "venv", "--without-pip", str(work / "venv")])
        prefix = [str(work / "venv/bin/python"), "-E", "-s", "-B"]
        environment = json.loads(call(prefix + [str(copied / "check_environment.py")]).stdout)
        require(environment["status"] == "ok" and environment["source_files_verified"] == 16,
                "environment or source verification failed")
        test_counts = {}
        for name, path, minimum in (("behavior_tests", "sample/test_revocation.py", 69),
                                    ("distribution_tests", "test_environment.py", 7)):
            result = call(prefix + [str(copied / path)])
            match = re.search(r"^Ran (\d+) tests? in ", result.stderr, re.MULTILINE)
            require(match is not None and result.stderr.rstrip().endswith("OK"),
                    f"missing successful unittest summary: {path}\n{result.stderr}")
            test_counts[name] = int(match.group(1))
            require(test_counts[name] >= minimum, f"test inventory fell below {minimum}: {path}")

        run = work / "new run"
        call(prefix + [str(copied / "sample/run_demo.py"), "run", "--out", str(run)])
        summary = json.loads((run / "SUMMARY.json").read_bytes())
        require(len(summary["results"]) == 8 and summary["test_keys_deleted"] is True,
                "demo did not complete all scenarios and remove test keys")
        require({row["scenario"] for row in summary["results"]} == set(EXPECTED),
                "scenario inventory differs")
        for row in summary["results"]:
            require((row["outcome"], row["accepted"], row["observed_files"]) == EXPECTED[row["scenario"]]
                    and row["reader_verified"] is True, f"unexpected scenario result: {row}")
        require(len(summary["source_sha256"]) == 10 and
                all(manifest["files"][k] == v for k, v in summary["source_sha256"].items()),
                "demo source correspondence failed")

        recovery = {}
        for name in ("lost-response", "partial-effect", "revoked-before"):
            case = run / name

            def state():
                # Read/export housekeeping may change; acceptance and effects must not.
                with sqlite3.connect((case / "provider.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
                    rows = {t: db.execute("SELECT COUNT(*) FROM " + t).fetchone()[0]
                            for t in ("accepted", "native")}
                return {"files": snapshot(case / "sandbox"), "rows": rows}

            initial = state()
            query = json.loads(call(prefix + [str(copied / "sample/run_demo.py"), "query", str(case)],
                                    expected=2 if name == "partial-effect" else 0).stdout)
            require(query["status"] == EXPECTED[name][0] and query["accepted"] is EXPECTED[name][1],
                    f"unexpected recovery query: {name}")
            if name == "partial-effect":
                require(query["retry_effect"] is False, "unknown must never request effect replay")
            exported = work / (name + "-reexport.json")
            call(prefix + [str(copied / "sample/run_demo.py"), "export", str(case), "--out", str(exported)])
            portable = work / ("portable evidence " + name)
            portable.mkdir()
            for original in (exported, case / "selection.json", case / "anchor.json"):
                shutil.copyfile(original, portable / original.name)
            reader = json.loads(call(prefix + [str(copied / "sample/read_evidence.py"),
                                    str(portable / exported.name), "--selection", str(portable / "selection.json"),
                                    "--anchor", str(portable / "anchor.json")]).stdout)
            require(reader["verified"] is True and reader["outcome"] == EXPECTED[name][0],
                    f"unexpected portable reader result: {name}")
            require(initial == state(), f"recovery changed acceptance or effects: {name}")
            recovery[name] = {"outcome": reader["outcome"], "effects_unchanged": True}
        require(before == snapshot(copied) == snapshot(source), "source files changed during verification")
        return {"status": "pass", "environment": environment, **test_counts,
                "cli_scenarios": len(summary["results"]), "recovery": recovery,
                "source_sha256": before, "source_unchanged": True,
                "fresh_venv_without_pip": True, "source_folder_contains_spaces": True,
                "scope": "synthetic single-provider sample; no external operator or general PKI verification"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample-root", type=Path, default=SAMPLE,
                        help="complete sample folder, including one extracted from a source archive")
    args = parser.parse_args()
    print(json.dumps(check(args.sample_root.resolve()), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
