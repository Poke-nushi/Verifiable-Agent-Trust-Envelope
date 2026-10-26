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
REQUIRED = frozenset(['CONTRACT.md', 'LICENSE', 'README.md', 'UPSTREAM-SOURCES.json', 'VALIDATION.md', 'check_environment.py', 'inbox/bridge.py', 'inbox/demo_connection.py', 'inbox/receive_handoff.py', 'inbox/test_bridge.py', 'reference/execution-evidence-demo/admission.py', 'reference/execution-evidence-demo/demo_contract.py', 'reference/minimal-al2-demo/trust_envelope_demo.py', 'reference/post-admission-revocation-sample/sample/contract.py', 'reference/receipt-linkage-example/SOURCE-PINS.json', 'reference/receipt-linkage-example/recipient_example.py', 'reference/recipient-assessment/EVALUATOR-SOURCES.json', 'reference/recipient-assessment/_worker.py', 'reference/recipient-assessment/vate_recipient.py', 'reference/recipient-inbox/recipient_inbox.py', 'reference/recipient-signature-authority/recipient_trial.py', 'reference/required-records/NATIVE-SOURCES.json', 'reference/required-records/native_bridge.py', 'reference/required-records/required_records.py', 'reference/s3-observation-example/SEAWEEDFS-PIN.json', 'reference/s3-observation-example/assess_observation.py', 'reference/s3-observation-example/capture_s3.py', 'reference/s3-observation-example/contract.py', 'reference/s3-observation-example/native_fixture.py', 'reference/s3-observation-example/run_trial.py', 'reference/s3-observation-example/sandbox_macos.py', 'reference/vate-verifier-core/vate_verifier_core.py', 'registries/evidence-vocabulary.v0.3.json', 'requirements.lock', 'sample/SOURCE-PINS.json', 'sample/dependencies.py', 'sample/fixture.py', 'sample/handoff_contract.py', 'sample/handoff_model.py', 'sample/handoff_provider.py', 'sample/handoff_reader.py', 'sample/run_demo.py', 'sample/test_handoff.py', 'schemas/admission-receipt.schema.json', 'schemas/admission-request.schema.json', 'schemas/post-execution-receipt.schema.json', 'scripts/vate_conformance.py', 'test_distribution.py'])


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


def check(sources_only=False):
    count = verify_sources()
    if sources_only:
        return {"status": "ok", "source_files_verified": count, "scope": "file inventory and hashes only"}
    if not (3, 11) <= sys.version_info[:2] <= (3, 14) or sys.platform not in ("darwin", "linux"):
        raise ValueError("use CPython 3.11-3.14 on macOS or Linux; see VALIDATION.md")
    if platform.python_implementation() != "CPython":
        raise ValueError("this sample targets CPython")
    import fcntl  # Required by the provider's local worker lock.
    del fcntl
    from importlib.metadata import version
    expected = {"attrs": "26.1.0", "jsonschema": "4.26.0", "jsonschema-specifications": "2025.9.1",
                "referencing": "0.37.0", "rpds-py": "0.30.0"}
    if sys.version_info[:2] < (3, 13):
        expected["typing-extensions"] = "4.15.0"
    for name, wanted in expected.items():
        if version(name) != wanted:
            raise ValueError("dependency version mismatch: " + name)
    import jsonschema, referencing, rpds
    del jsonschema, referencing, rpds
    executable = shutil.which("openssl")
    if not executable:
        raise ValueError("OpenSSL executable missing from PATH")
    result = subprocess.run([executable, "version"], capture_output=True, text=True, timeout=10)
    if result.returncode or not result.stdout.startswith("OpenSSL "):
        raise ValueError("OpenSSL version check failed")
    return {"status": "ok", "python": platform.python_version(), "os": platform.system(),
            "machine": platform.machine(), "sqlite": sqlite3.sqlite_version,
            "openssl": result.stdout.strip(), "dependencies": expected, "source_files_verified": count,
            "scope": "local prerequisites and file hashes; execute tests to verify behavior"}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources-only", action="store_true")
    args = parser.parse_args()
    try:
        result = check(args.sources_only)
    except (ValueError, OSError, ImportError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
