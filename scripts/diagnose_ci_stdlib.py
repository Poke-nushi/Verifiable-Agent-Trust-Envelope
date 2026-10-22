#!/usr/bin/env python3
"""One-off hosted-runner diagnosis; not part of the required CI workflow."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import sysconfig
import tempfile
import time

from prepare_ci_stdlib import stdlib_sources

ROOT = Path(__file__).resolve().parents[1]
STDLIB = Path(sysconfig.get_path("stdlib")).resolve()
SAMPLES = 7


def digest(paths):
    result = {}
    for path in sorted(set(paths)):
        if path.is_file() and not path.is_symlink():
            result[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def protected_files():
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    paths = [ROOT / p for p in tracked if p]
    paths.extend(ROOT.rglob("*.pyc"))
    for kind in ("purelib", "platlib"):
        folder = Path(sysconfig.get_path(kind))
        paths.extend(folder.rglob("*.py"))
        paths.extend(folder.rglob("*.pyc"))
    paths.extend(stdlib_sources(STDLIB))
    return digest(paths)


def cache_state():
    sources = list(stdlib_sources(STDLIB))
    present = 0
    timestamp_valid = 0
    selected = {}
    for source in sources:
        cache = Path(importlib.util.cache_from_source(str(source), optimization=""))
        exists = cache.is_file()
        present += exists
        valid = False
        if exists:
            header = cache.read_bytes()[:16]
            stat = source.stat()
            valid = (len(header) == 16 and header[:4] == importlib.util.MAGIC_NUMBER
                     and int.from_bytes(header[4:8], "little") == 0
                     and int.from_bytes(header[8:12], "little") == int(stat.st_mtime) & 0xffffffff
                     and int.from_bytes(header[12:16], "little") == stat.st_size & 0xffffffff)
            timestamp_valid += valid
        if source.name in ("argparse.py", "subprocess.py", "tempfile.py", "uuid.py"):
            selected[str(source.relative_to(STDLIB))] = {"present": exists, "timestamp_valid": valid}
    return {"sources": len(sources), "present": present,
            "timestamp_valid": timestamp_valid, "selected": selected}


def micro(prefix):
    cases = {
        "pass": [sys.executable, "-B", "-c", "pass"],
        "stdlib": [sys.executable, "-B", "-c",
                   "import argparse,json,pathlib,subprocess,tempfile,uuid,hashlib,datetime"],
        "jsonschema": [sys.executable, "-B", "-c", "import jsonschema"],
        "isolated_stdlib": [sys.executable, "-I", "-B", "-X", "pycache_prefix=" + str(prefix),
                            "-c", "import argparse,json,pathlib,subprocess,tempfile,uuid,hashlib,datetime"],
    }
    samples = {name: [] for name in cases}
    for _ in range(SAMPLES):
        for name, command in cases.items():
            started = time.perf_counter()
            result = subprocess.run(command, cwd=ROOT, capture_output=True, check=True)
            assert not result.stdout and not result.stderr, (name, result)
            samples[name].append(time.perf_counter() - started)
    assert not list(prefix.rglob("*.pyc")), "isolated empty prefix must stay empty"
    return {name: {"samples_seconds": times, "median_seconds": statistics.median(times)}
            for name, times in samples.items()}


def suite(label):
    command = [sys.executable, "-B", "-m", "unittest", "discover", "-s",
               "reference/execution-evidence-demo", "-p", "test_*.py", "-v"]
    started = time.perf_counter()
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=1200)
    seconds = time.perf_counter() - started
    output = result.stdout + result.stderr
    print("::group::Execution evidence " + label, flush=True)
    print(output, flush=True)
    print("::endgroup::", flush=True)
    assert result.returncode == 0, label
    tests = re.findall(r"^test_.+ \.\.\. (?:ok|skipped .+)$", output, re.MULTILINE)
    count = re.search(r"Ran (\d+) tests in ([\d.]+)s", output)
    assert count and int(count[1]) == 112 and len(tests) == 112, (label, len(tests))
    return {"seconds": seconds, "reported_seconds": float(count[2]), "tests": tests,
            "returncode": result.returncode, "command": command}


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Run only on the disposable diagnostic Actions runner.")
    assert sys.dont_write_bytecode and sys.pycache_prefix is None
    metadata = {"python": sys.version, "executable": sys.executable,
                "platform": platform.platform(), "cpu_count": os.cpu_count(),
                "image_os": os.environ.get("ImageOS"), "image_version": os.environ.get("ImageVersion"),
                "run_id": os.environ.get("GITHUB_RUN_ID"), "sha": os.environ.get("GITHUB_SHA"),
                "repetition": os.environ.get("PROBE_REPETITION")}
    with tempfile.TemporaryDirectory() as directory:
        prefix = Path(directory)
        before_cache = cache_state()
        before_micro = micro(prefix)
        before_suite = suite("before preparation")
        protected_before = protected_files()
        started = time.perf_counter()
        prepared = subprocess.run([sys.executable, "-B", "scripts/prepare_ci_stdlib.py"],
                                  cwd=ROOT, capture_output=True, text=True, check=True)
        preparation_wall = time.perf_counter() - started
        preparation = json.loads(prepared.stdout)
        assert not prepared.stderr, prepared.stderr
        protected_after = protected_files()
        assert protected_before == protected_after, "preparation changed protected files"
        after_cache = cache_state()
        after_micro = micro(prefix)
        after_suite = suite("after preparation")
        assert before_suite["tests"] == after_suite["tests"], "test outcomes or skips changed"
        assert not list(prefix.rglob("*.pyc"))
        report = {"metadata": metadata, "before_cache": before_cache, "after_cache": after_cache,
                  "preparation": preparation, "preparation_wall_seconds": preparation_wall,
                  "before_micro": before_micro, "after_micro": after_micro,
                  "before_suite": before_suite, "after_suite": after_suite,
                  "protected_files_unchanged": True, "protected_file_count": len(protected_before),
                  "test_outcomes_identical": True, "isolated_prefix_stayed_empty": True}
        print("STDLIB_PROBE_RESULT_JSON=" + json.dumps(report, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
