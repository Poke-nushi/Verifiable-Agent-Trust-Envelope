"""Local artifact-manifest adapter for the ordinary VATE runner.

The selected corpus case, rather than a SUT's declarations, requires binding.
No URI is fetched. Manifest members name regular files beside the manifest.
"""

from __future__ import annotations

import importlib.util
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("vate_binding_runner_contract", HERE / "request_binding.py")
if spec is None or spec.loader is None:
    raise RuntimeError("request-binding checker unavailable")
binding = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = binding
spec.loader.exec_module(binding)

MANIFEST_CONTRACT = "vate-request-binding-artifact-manifest-v1"
FILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,119}\.json\Z")


def read_raw(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        binding.need(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "NOT_A_REGULAR_FILE")
        raw = stream.read(binding.MAX_BYTES + 1)
    binding.need(len(raw) <= binding.MAX_BYTES, "ARTIFACT_TOO_LARGE")
    return raw


def load_manifest(path: Path, expected_digest: dict | None = None) -> dict[str, bytes]:
    raw = read_raw(path)
    if expected_digest is not None:
        binding.need(binding.digest(raw) == expected_digest, "MANIFEST_DIGEST_MISMATCH")
    manifest = binding.decode(raw)
    binding.exact(manifest, {"contract", "artifacts"})
    binding.need(manifest["contract"] == MANIFEST_CONTRACT, "UNSUPPORTED_ARTIFACT_MANIFEST")
    entries = manifest["artifacts"]
    binding.need(type(entries) is list and 0 < len(entries) <= 16, "SCHEMA_INVALID")
    result = {}
    for entry in entries:
        binding.exact(entry, {"uri", "media_type", "digest", "path"})
        ref = {key: entry[key] for key in ("uri", "media_type", "digest")}
        binding.validate_reference(ref)
        binding.need(isinstance(entry["path"], str) and FILE_RE.fullmatch(entry["path"]) is not None,
                     "UNSAFE_ARTIFACT_PATH")
        binding.need(ref["uri"] not in result, "DUPLICATE_ARTIFACT_URI")
        content = read_raw(path.parent / entry["path"])
        binding.need(binding.digest(content) == ref["digest"], "ARTIFACT_DIGEST_MISMATCH")
        result[ref["uri"]] = content
    return result


def assess(*, required_contract: str, receipt_path: Path, admission_path: Path, manifest_path: Path,
           receipt_digest: dict | None = None, manifest_digest: dict | None = None) -> dict[str, Any]:
    receipt = read_raw(receipt_path)
    if receipt_digest is not None:
        binding.need(binding.digest(receipt) == receipt_digest, "RECEIPT_DIGEST_MISMATCH")
    admission = read_raw(admission_path)
    artifacts = load_manifest(manifest_path, manifest_digest)
    report = binding.assess_request_binding(receipt, artifacts, required_contract=required_contract,
                                            expected_admission_request_ref=binding.reference(admission))
    return report
