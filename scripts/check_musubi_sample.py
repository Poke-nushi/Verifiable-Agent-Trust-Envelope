"""Check the published MUSUBI sample; portable tests substitute native replay.

No native dependencies are installed. The temporary runtime is a test fixture
using the caller's existing validation dependencies, not a prepared evaluator.
Actual sandboxed native replay has a separate macOS validation record.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import venv

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "reference/musubi-set2-receiving-sample"
RECORD = ROOT / "docs/interop/horizon51-set2-replay"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_manifest(root):
    listed = {}
    for line in (root / "SHA256SUMS").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        require(match is not None, f"invalid manifest line in {root}")
        digest, name = match.groups()
        path = Path(name)
        require(not path.is_absolute() and ".." not in path.parts and name not in listed,
                f"unsafe or duplicate manifest path: {name}")
        listed[name] = digest
    actual = {}
    for path in root.rglob("*"):
        require(not path.is_symlink(), f"symlink in published material: {path}")
        if path.is_file() and path != root / "SHA256SUMS":
            actual[path.relative_to(root).as_posix()] = sha(path.read_bytes())
    require(actual == listed, f"manifest differs from published files: {root}")
    return len(listed)


def check_integrity():
    counts = {"sample_files": check_manifest(SAMPLE), "record_files": check_manifest(RECORD)}
    pin = json.loads((SAMPLE / "vate-source.json").read_bytes())
    for row in pin["files"]:
        raw = (ROOT / row["path"]).read_bytes()
        require(sha(raw) == row["sha256"] and len(raw) == row["bytes"],
                f"VATE source differs from sample pin: {row['path']}")
    execution = json.loads((RECORD / "native-execution.json").read_bytes())
    stdout = (RECORD / execution["stdout_file"]).read_bytes()
    selection = json.loads((SAMPLE / "sample/selection.json").read_bytes())
    reference = (SAMPLE / "sample/originals" / selection["reference_output"]["path"]).read_bytes()
    require(sha(stdout) == execution["stdout_sha256"] and stdout == reference + b"\n",
            "historical native stdout differs from the sample reference")
    return counts


def test_runtime(environment):
    """Build a disposable descriptor fixture, never a native-ready environment."""
    runtime = environment / "venv"
    venv.EnvBuilder(with_pip=False, system_site_packages=True).create(runtime)
    python = runtime / "bin/python"
    # A nested venv does not inherit its parent's installed validation packages.
    # Point this test fixture at the same dependencies used to launch the check.
    purelib = subprocess.check_output(
        [str(python), "-I", "-B", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
        text=True, timeout=30).strip()
    (Path(purelib) / "vate-test-dependencies.pth").write_text(sysconfig.get_path("purelib") + "\n")
    config = json.loads((SAMPLE / "evaluator-template.json").read_bytes())
    files, links = [], {}
    for path in sorted(runtime.rglob("*")):
        name = path.relative_to(runtime).as_posix()
        if path.is_symlink():
            links[name] = str(path.resolve(strict=True))
        elif path.is_file():
            require(path.suffix not in (".pyc", ".pyo"), "bytecode in test runtime")
            raw = path.read_bytes()
            files.append({"path": name, "sha256": sha(raw), "bytes": len(raw)})
    config.update(runtime_files=files, runtime_links=links, runtime_executables=[],
                  interpreter_sha256=sha(python.resolve(strict=True).read_bytes()),
                  test_fixture="native replay substituted; packages are expectations, not installation evidence")
    shutil.copyfile(SAMPLE / "requirements.lock", environment / "requirements.lock")
    (environment / "evaluator.json").write_text(json.dumps(config, sort_keys=True))
    return python


def run_portable():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    with tempfile.TemporaryDirectory(prefix="vate-musubi-portable-") as directory:
        root = Path(directory).resolve()
        environment = root / "environment"
        python = test_runtime(environment)
        subprocess.run([str(python), "-I", "-B", "-c", "import jsonschema"],
                       check=True, env=env, timeout=30)
        subprocess.run([str(python), "-B", str(SAMPLE / "verify.py"),
                        "--sample", str(SAMPLE / "sample")], check=True, env=env, timeout=120)
        counts = {}
        for name in ("cli", "recovery"):
            output = root / name
            subprocess.run([str(python), "-B", str(SAMPLE / f"verify_{name}.py"),
                            "--environment", str(environment), "--vate-root", str(ROOT),
                            "--output", str(output)], check=True, env=env, timeout=240)
            result = json.loads((output / "RESULT.json").read_bytes())
            require(result["status"] == "pass", f"{name} checks failed")
            counts[name] = len(result["cases"])
        return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--integrity-only", action="store_true")
    args = parser.parse_args()
    try:
        result = check_integrity()
        if not args.integrity_only:
            result.update(run_portable())
        print(json.dumps({"status": "pass", **result,
                          "scope": "file integrity and portable tests; no native replay"}))
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        print(f"MUSUBI sample check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
