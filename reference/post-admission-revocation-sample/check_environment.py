#!/usr/bin/env python3
"""Check the unpacked sample and existing tools without installing anything."""
from __future__ import annotations

import hashlib
from importlib.machinery import all_suffixes
import json
import platform
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
REQUIRED = {
    "sample/contract.py", "sample/provider.py", "sample/read_evidence.py", "sample/fixture.py",
    "sample/run_demo.py", "sample/test_revocation.py", "check_environment.py", "test_environment.py",
    "reference/execution-evidence-demo/admission.py", "reference/execution-evidence-demo/demo_contract.py",
    "reference/vate-verifier-core/vate_verifier_core.py", "reference/minimal-al2-demo/trust_envelope_demo.py",
    "README.md", "CONTRACT.md", "VALIDATION.md", "LICENSE",
}


def regular_bytes(root, name):
    relative = PurePosixPath(name)
    if relative.is_absolute() or str(relative) != name or any(p in (".", "..") for p in relative.parts):
        raise ValueError("invalid manifest path")
    path = root
    for part in relative.parts:
        path = path / part
        if path.is_symlink():
            raise ValueError("symlink in source path: " + name)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 2 * 1024 * 1024:
        raise ValueError("invalid source file: " + name)
    return path.read_bytes()


def verify_sources(root=ROOT):
    manifest = json.loads(regular_bytes(root, "SOURCE-MANIFEST.json"))
    if not isinstance(manifest, dict) or manifest.get("format") != "vate-local-sample-files-1":
        raise ValueError("invalid source manifest")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != REQUIRED:
        raise ValueError("source manifest inventory mismatch")
    for name, expected in files.items():
        actual = hashlib.sha256(regular_bytes(root, name)).hexdigest()
        if type(expected) is not str or actual != expected:
            raise ValueError("source digest mismatch: " + name)
    # Refuse stale modules, packages, and bytecode left by an earlier extraction.
    # Non-importable notes/OS metadata do not affect the selected source inventory.
    suffixes = tuple(all_suffixes())
    for path in root.rglob("*"):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError("symlink in distribution: " + name)
        if path.is_file() and path.name.endswith(suffixes) and name not in REQUIRED:
            raise ValueError("unlisted importable file; extract into a fresh folder: " + name)
    return len(files)


def check():
    if not (3, 11) <= sys.version_info[:2] <= (3, 14) or sys.platform not in ("darwin", "linux"):
        raise ValueError("use CPython 3.11-3.14 on macOS or Linux; see VALIDATION.md")
    if platform.python_implementation() != "CPython":
        raise ValueError("this sample targets CPython")
    import fcntl  # Required by the provider's local worker lock.
    del fcntl
    count = verify_sources()
    executable = shutil.which("openssl")
    if not executable:
        raise ValueError("OpenSSL executable missing from PATH")
    result = subprocess.run([executable, "version"], capture_output=True, text=True, timeout=10)
    if result.returncode or not result.stdout.startswith("OpenSSL "):
        raise ValueError("OpenSSL version check failed")
    return {"status": "ok", "python": platform.python_version(), "os": platform.system(),
            "machine": platform.machine(), "sqlite": sqlite3.sqlite_version,
            "openssl": result.stdout.strip(), "source_files_verified": count,
            "scope": "local prerequisites and file hashes; execute tests to verify behavior"}


def main():
    try:
        result = check()
    except (ValueError, OSError, ImportError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
