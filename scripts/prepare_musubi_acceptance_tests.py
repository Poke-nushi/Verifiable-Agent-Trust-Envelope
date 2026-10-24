"""Fetch the fixed public inputs for portable MUSUBI acceptance tests.

This preparation step uses HTTPS and checks every raw SHA-256 before writing
the new evidence directory. It does not execute the fetched verifier, install
packages, select live trust roots or create signatures. The test commands use
these saved inputs separately.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "reference/musubi-set2-receiving-sample"
sys.path.insert(0, str(SAMPLE))
from verify_acceptance import PINS  # noqa: E402
from acceptance_checks import WAR_SOURCE_COMMIT, WAR_SOURCE_SHA256  # noqa: E402

MAX_BYTES = 1024 * 1024
ACCEPTANCE_BASE = (
    "https://raw.githubusercontent.com/babyblueviper1/"
    "preaction-governance-conformance/235aaabc45ebe6fa36dd02ca2cd6a44a69297d93/"
    "examples/hs51-acceptance-set/"
)
WAR_BASE = (
    "https://raw.githubusercontent.com/maximusrufus/work-acceptance-record/"
    + WAR_SOURCE_COMMIT + "/"
)
LOCAL = {
    "sources/context/bundle.json": SAMPLE / "sample/originals/workers/hs-ledger/"
    "nenrin/musubi-v0/ca2a-companion-v0/pilot51/set2/bundle.json",
    "sources/context/audit-selection.json": SAMPLE / "sample/audit-selection.json",
}


def fetch(url):
    with urlopen(url, timeout=30) as response:
        if response.geturl() != url:
            raise ValueError("unexpected redirect for pinned test input")
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("test input exceeds size limit")
    return raw


def prepare(output):
    if output.exists() or output.is_symlink():
        raise ValueError("evidence output must be a new directory")
    pins = dict(PINS, **{"sources/war/verifier/war_verify.py": WAR_SOURCE_SHA256})
    files = {}
    for name, expected in pins.items():
        if name in LOCAL:
            raw = LOCAL[name].read_bytes()
        elif name.startswith("sources/acceptance/"):
            raw = fetch(ACCEPTANCE_BASE + name.removeprefix("sources/acceptance/"))
        elif name.startswith("sources/war/"):
            raw = fetch(WAR_BASE + name.removeprefix("sources/war/"))
        else:
            raise ValueError("unmapped test input: " + name)
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("test input hash mismatch: " + name)
        files[name] = raw
    output.mkdir(parents=True, exist_ok=False)
    for name, raw in files.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    return len(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        count = prepare(args.output)
        print(f"Prepared {count} hash-verified test inputs; no verifier executed.")
    except (OSError, ValueError) as exc:
        print(f"Acceptance test preparation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
