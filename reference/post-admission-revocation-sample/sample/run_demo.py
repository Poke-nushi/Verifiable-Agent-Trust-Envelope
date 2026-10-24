#!/usr/bin/env python3
"""Run synthetic local cases, or query/export an existing case without repeating effects."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import sqlite3
import sys
import tempfile

from contract import ROOT, VerificationUnavailable, decode, encode, exclusive_write, openssl, safe_read, sha
from fixture import BASE, Case, Keys
from provider import Provider
from read_evidence import verify

SCENARIOS = ("active", "revoked-before", "revoke-after-pull", "revoke-after-accept",
             "partial-effect", "lost-response", "expired-conflict", "same-input-resigned")


def one(path, keys, scenario):
    c = Case(path, keys)
    if scenario == "revoked-before":
        c.provider.notify(c.signed_status(sequence=2, state="revoked"))
    elif scenario in ("revoke-after-pull", "revoke-after-accept"):
        observer = Provider(path, clock=c.clock)
        wanted = "after_pull" if scenario == "revoke-after-pull" else "before_effect"
        def revoke(point):
            if point == wanted:
                observer.notify(c.signed_status(sequence=2, state="revoked"))
        c.provider.hook = revoke
    elif scenario in ("partial-effect", "lost-response"):
        wanted = "after_file_1" if scenario == "partial-effect" else "after_native"
        def fault(point):
            if point == wanted:
                raise RuntimeError("controlled synthetic fault")
        c.provider.hook = fault
    elif scenario == "expired-conflict":
        c.submit(input_sha256="wrong-test-binding")
        c.clock.value = BASE + 51
        c.provider.notify(c.signed_status(next_update_at=BASE + 50))
        c.clock.value = BASE + 52
    elif scenario == "same-input-resigned":
        c.provider.notify(c.signed_status())
        c.set_status()  # New ECDSA signature, identical protected header/payload.
    result = c.submit()
    observer = Provider(path, clock=c.clock)
    query = observer.query()
    exported = observer.export(path / "evidence.json")
    checked = verify(safe_read(path / "evidence.json"), c.selection_raw, observer.anchor_raw)
    report = {"scenario": scenario, "submission": result, "query": query, "reader": checked,
              "export_sha256": exported["raw_sha256"], "scope": "synthetic local keys, single operation/provider"}
    exclusive_write(path / "RESULT.json", encode(report))
    return {"scenario": scenario, "submission": result["status"], "outcome": query["status"],
            "accepted": query["accepted"], "observed_files": len(query["files"]),
            "reader_verified": checked["verified"], "export_sha256": exported["raw_sha256"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="create new synthetic cases with disposable test keys")
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--scenario", choices=(*SCENARIOS, "all"), default="all")
    query = sub.add_parser("query", help="read an existing case; never repeat effects")
    query.add_argument("case", type=Path)
    export = sub.add_parser("export", help="re-export an existing case; never repeat effects")
    export.add_argument("case", type=Path)
    export.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.command in ("query", "export"):
        try:
            provider = Provider(args.case)
            result = provider.query() if args.command == "query" else provider.export(args.out)
        except (ValueError, VerificationUnavailable, OSError, sqlite3.Error):
            result = {"status": "unknown", "error": "local_evidence_unavailable",
                      "accepted": None, "files": None, "native": None}
        if result.get("status") == "unknown":
            result.update(next="inspect_local_store", retry_effect=False)
        print(encode(result).decode())
        return 2 if result.get("status") == "unknown" else 0
    args.out.mkdir(mode=0o700, exist_ok=False)
    scenarios = SCENARIOS if args.scenario == "all" else (args.scenario,)
    with tempfile.TemporaryDirectory(prefix="vate-disposable-demo-keys-") as td:
        keys = Keys(Path(td))
        results = [one(args.out / scenario, keys, scenario) for scenario in scenarios]
    source_paths = [p for p in Path(__file__).resolve().parent.glob("*.py")]
    source_paths += [ROOT / path for path in (
        "reference/execution-evidence-demo/admission.py", "reference/execution-evidence-demo/demo_contract.py",
        "reference/vate-verifier-core/vate_verifier_core.py", "reference/minimal-al2-demo/trust_envelope_demo.py")]
    summary = {"results": results, "test_keys_deleted": True,
               "environment": {"python": sys.version, "sqlite": sqlite3.sqlite_version,
                               "openssl": openssl("version").stdout.decode().strip(),
                               "os": platform.system(), "machine": platform.machine(), "journal": "WAL"},
               "source_sha256": {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in sorted(source_paths)}}
    exclusive_write(args.out / "SUMMARY.json", encode(summary))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    sys.exit(main())
