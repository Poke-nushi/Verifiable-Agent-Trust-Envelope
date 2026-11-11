"""Replay one engine on immutable inputs; never overwrite an existing report."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent


def inventory(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file() and "__pycache__" not in p.parts}


def run(engine):
    for row in json.loads((ROOT / "SOURCE.json").read_text())["files"]:
        data = (ROOT / "source" / row["path"]).read_bytes()
        if len(data) != row["bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise ValueError("upstream source changed")
    saved = json.loads((ROOT / "validation/native.json").read_text())
    if inventory(ROOT / "inputs") != saved["inputs"]:
        raise ValueError("saved native input mismatch")
    if engine == "native":
        sys.path.insert(0, str(ROOT / "source"))
        from uibc_core.verify import verify
    else:
        sys.path.insert(0, str(ROOT / "reader"))
        from receive_v03 import assess
    equivalent = {"PASS": "matched", "FAIL": "mismatched", "INCONCLUSIVE": "not_assessed"}
    rows = []
    for case in saved["cases"]:
        package = ROOT / "inputs" / case["package"]
        if inventory(package) != case["inputs"]:
            raise ValueError("per-case input mismatch")
        key = bytes.fromhex((ROOT / "inputs" / case["hmac_key_file"]).read_text()) if case["hmac_key_file"] else None
        pub = bytes.fromhex((ROOT / "inputs" / case["public_key_file"]).read_text()) if case["public_key_file"] else None
        if engine == "native":
            report = verify(str(package), key=key, pubkey=pub)
            if report != case["native"]:
                raise ValueError("native replay changed")
        else:
            report = assess(package, key=key, public_key=pub)
            native = {c["id"]: c["result"] for c in case["native"]["checks"]}
            if any(c["status"] != equivalent[native[c["upstream_check"]]]
                   for c in report["checks"].values()):
                raise ValueError(f"selected-check divergence: {case['case']}")
            if report["receiver_checks_status"] != case["expected_receiver_status"]:
                raise ValueError(f"receiving expectation failed: {case['case']}")
            if any(k == "uibc_core" or k.startswith("uibc_core.") for k in sys.modules):
                raise ValueError("VATE reader imported upstream")
        rows.append({"case": case["case"], "report": report})
    if inventory(ROOT / "inputs") != saved["inputs"]:
        raise ValueError("replay mutated inputs")
    return {"engine": engine, "python": sys.version, "cases": rows,
            "selected_check_comparisons": len(rows) * 3 if engine == "vate" else None,
            "full_native_replays": len(rows) if engine == "native" else None,
            "reader_sha256": inventory(ROOT / "reader") if engine == "vate" else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("native", "vate"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.engine)
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"{args.engine}: {len(report['cases'])} conditions passed")


if __name__ == "__main__":
    main()
