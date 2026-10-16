"""Offline test inputs derived from saved captures, with current source declarations.

These copies are synthetic fixtures, never new captures or replacements for the
saved originals. Runtime assessors do not call this helper.
"""
from copy import deepcopy
import hashlib
import types
import json
from pathlib import Path
import shutil


def synthetic_current_instance(repository, destination):
    repository, destination = Path(repository), Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError("synthetic fixture destination must be new")
    original = repository / "reference/s3-observation-example/inputs/seaweedfs-4.48/instance"
    path = repository / "reference/s3-observation-example/contract.py"
    contract = types.ModuleType("_vate_synthetic_s3_contract")
    contract.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), "exec", dont_inherit=True), contract.__dict__)
    source_hashes = contract.sources()
    destination.mkdir(parents=True)
    before = {}
    for name in ("supported", "actual-403", "actual-404", "historical-v1"):
        source = original / "bundles" / name
        target = destination / "bundles" / name
        shutil.copytree(source, target)
        for path in source.iterdir():
            before[str(path.relative_to(original))] = hashlib.sha256(path.read_bytes()).hexdigest()
        (target / "sources.json").write_bytes(contract.encode(source_hashes))
        (target / "manifest.json").unlink()
        contract.seal(target)
    policy_path = original / "receiver-policy.json"
    before["receiver-policy.json"] = hashlib.sha256(policy_path.read_bytes()).hexdigest()
    policy = json.loads(policy_path.read_bytes())
    policy["source_hashes"] = source_hashes
    (destination / "receiver-policy.json").write_bytes(contract.encode(policy))
    # Derive the expected output from the archived result by changing only the
    # independently verified code identity. Never use the assessor as the oracle.
    expected = deepcopy(json.loads((original / "ASSESSMENTS.json").read_bytes()))
    receipt_sources = json.loads((repository / "reference/receipt-linkage-example/SOURCE-PINS.json").read_bytes())["files"]
    for result in expected.values():
        if result.get("receipt_check") is not None:
            result["receipt_check"]["source_files"] = receipt_sources
    (destination / "EXPECTED-SYNTHETIC.json").write_bytes(contract.encode(expected))
    provenance = {
        "basis": "offline synthetic derivative; no new S3 operation or capture",
        "original_instance": str(original.relative_to(repository)),
        "original_files_sha256": before,
        "changed_bundle_members": ["sources.json", "manifest.json"],
        "changed_policy_field": "source_hashes",
        "expected_result_change": "receipt_check.source_files only",
        "current_source_hashes": source_hashes,
    }
    (destination / "SYNTHETIC-PROVENANCE.json").write_bytes(contract.encode(provenance))
    for name, expected_hash in before.items():
        if hashlib.sha256((original / name).read_bytes()).hexdigest() != expected_hash:
            raise ValueError("saved original changed during synthetic fixture generation")
    return destination
