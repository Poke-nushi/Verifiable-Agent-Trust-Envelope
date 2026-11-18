"""Copy current shared sources into the handoff package, or check for drift.

Run after refreshing the repository's evaluator source pins. No dependency
installation, Git changes, historical store migration, or publication occurs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "reference/runtime-handoff-sample"
INVENTORY_NAME = "scripts/runtime_handoff_inventory.json"
# This repository-owned contract is independent of the candidate distribution.
# Its historical hashes were checked against the original upstream Git blobs.
INVENTORY = json.loads((ROOT / INVENTORY_NAME).read_bytes())
ORIGINAL = INVENTORY["original_files"]
ADDED = tuple(INVENTORY["added_files"])
PACKAGE_FILES = frozenset(INVENTORY["package_files"])
DISTRIBUTION_FILES = frozenset(ORIGINAL) | frozenset(ADDED) | PACKAGE_FILES


def encoded(value):
    return (json.dumps(value, indent=2) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def expected_files(sample=SAMPLE):
    """Build the selected bytes without mutating the source or distribution."""
    upstream = json.loads((sample / "UPSTREAM-SOURCES.json").read_bytes())
    unchanged, patched = upstream.get("unchanged_files"), upstream.get("patched_files")
    if (not isinstance(unchanged, dict) or not isinstance(patched, dict)
            or set(unchanged) & set(patched)
            or any(not isinstance(entry, dict) or set(entry) != {"upstream_sha256", "sha256"}
                   for entry in patched.values())):
        raise ValueError("unexpected historical upstream inventory")
    original = {**unchanged, **{name: entry["upstream_sha256"] for name, entry in patched.items()}}
    if original != ORIGINAL or upstream.get("upstream_commit") != INVENTORY["upstream_commit"]:
        raise ValueError("unexpected historical upstream inventory")
    manifest = json.loads((sample / "SOURCE-MANIFEST.json").read_bytes())
    names = set(manifest["files"])
    # Newly selected shared files can be introduced by sync. Other omissions or
    # additions are a contract error, not an invitation to repin arbitrary paths.
    if names - DISTRIBUTION_FILES or DISTRIBUTION_FILES - names - set(ADDED):
        raise ValueError("unexpected distribution inventory")
    selected = {}
    for name in sorted(set(ORIGINAL) | set(ADDED)):
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or (name not in manifest["files"] and name not in ADDED):
            raise ValueError("invalid selected source path: " + name)
        selected[name] = (ROOT / path).read_bytes()
    unchanged, patched = {}, {}
    for name, old in ORIGINAL.items():
        current = digest(selected[name])
        if current == old:
            unchanged[name] = old
        else:
            patched[name] = {"upstream_sha256": old, "sha256": current}
    selected["UPSTREAM-SOURCES.json"] = encoded({"upstream_commit": INVENTORY["upstream_commit"],
        "unchanged_files": unchanged, "patched_files": patched,
        "added_files": {name: digest(selected[name]) for name in ADDED}})
    pins = json.loads((sample / "sample/SOURCE-PINS.json").read_bytes())
    selected["sample/SOURCE-PINS.json"] = encoded({name: digest((sample / "sample" / name).read_bytes()) for name in pins})
    manifest["files"] = {name: digest(selected[name] if name in selected else (sample / name).read_bytes())
                         for name in sorted(DISTRIBUTION_FILES)}
    selected["SOURCE-MANIFEST.json"] = encoded(manifest)
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="report drift without writing files")
    args = parser.parse_args()
    expected = expected_files()
    changed = [name for name, raw in expected.items() if not (SAMPLE / name).is_file() or (SAMPLE / name).read_bytes() != raw]
    if not args.check:
        for name in changed:
            path = SAMPLE / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(expected[name])
    print(json.dumps({"status": "drift" if args.check and changed else "ok", "mode": "check" if args.check else "sync", "changed": changed}))
    return 1 if args.check and changed else 0


if __name__ == "__main__":
    raise SystemExit(main())
