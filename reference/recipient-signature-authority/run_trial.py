#!/usr/bin/env python3
"""Create synthetic fixtures and retain complete local trial control reports."""
import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import sys

import recipient_trial as trial
from trial_fixtures import Fixtures


def run(output, openssl, expected_sha):
    if output.exists() or output.is_symlink():
        raise ValueError("output must be a new local directory")
    if trial.sha(openssl.read_bytes()) != expected_sha:
        raise ValueError("selected runtime differs from explicit expected hash")
    fixtures = Fixtures(openssl)
    if fixtures.binary_sha256 != expected_sha:
        raise ValueError("selected runtime changed during fixture setup")
    assessor = fixtures.assessor()
    output.mkdir(parents=True)
    fixtures.save(output / "fixtures")
    originals = fixtures.arguments()
    controls = [("matching", {}, ("verified", "authorized_under_policy", "matched")),
                ("raw-byte-tamper", {"post": fixtures.post + b"\n"}, ("invalid", "not_assessed", "matched")),
                ("missing-proof", {"post_proof": None}, ("not_assessed", "not_assessed", "matched")),
                ("missing-post", {"post": None}, ("not_assessed", "not_assessed", "not_assessed"))]
    post = json.loads(fixtures.post)
    post["issuer"]["id"] = "urn:test:unauthorized-issuer"
    raw = trial.encoded(post)
    controls.append(("unauthorized-issuer", {"post": raw, "post_proof": fixtures.sign("post_execution", raw, 1)},
                     ("verified", "denied", "matched")))
    post = json.loads(fixtures.post)
    post["admission"]["digest"]["value"] = "0" * 64
    raw = trial.encoded(post)
    controls.append(("linkage-mismatch", {"post": raw, "post_proof": fixtures.sign("post_execution", raw, 1)},
                     ("verified", "authorized_under_policy", "mismatch")))
    for name, edit in (("wrong-scope", {"transaction_id": "different-transaction"}),
                       ("expired-authority", {"valid_until": "2026-10-13T00:00:00Z"}),
                       ("rotated-old-key", {"key_sha256": fixtures.keys[2]["key_sha256"]})):
        policy = deepcopy(fixtures.policy)
        policy["grants"][1].update(edit)
        controls.append((name, {"receiver_policy": trial.encoded(policy)}, ("verified", "denied", "matched")))
    controls.append(("rotated-new-key", {"receiver_policy": trial.encoded(policy),
                     "post_proof": fixtures.sign("post_execution", fixtures.post, 2)},
                    ("verified", "authorized_under_policy", "matched")))
    reports = []
    for name, changes, expected in controls:
        selected = {**originals, **changes}
        folder = output / name
        folder.mkdir()
        refs = {}
        for field, raw in selected.items():
            if raw is not None:
                (folder / (field + ".json")).write_bytes(raw)
            refs[field] = trial.identity(raw)
        result = assessor.assess(**selected)
        raw_result = trial.encoded(result) + b"\n"
        (folder / "RESULT.json").write_bytes(raw_result)
        actual = (result["signatures"]["post_execution"]["status"], result["issuer_authority"]["post_execution"]["status"],
                  result["receipt_assessment"]["native_result"]["record_linkage"])
        if actual != expected:
            raise AssertionError((name, expected, actual))
        reports.append({"case": name, "inputs": refs, "result": trial.identity(raw_result),
                        "post_axes": list(actual), "expectation_matched": True})
    before = json.loads((trial.HERE / "BASELINE.json").read_bytes())
    matching = json.loads((output / "matching/RESULT.json").read_bytes())
    if trial.encoded(before["receipt_pair"]) != trial.encoded(matching["receipt_assessment"]):
        raise AssertionError("pre-extension complete v1 response changed")
    for name, expected in before["protected_files"].items():
        if trial.sha((trial.ROOT / name).read_bytes()) != expected:
            raise AssertionError("protected source changed: " + name)
    record = {"contract": trial.CONTRACT, "created_at": datetime.now(timezone.utc).isoformat(),
              "runtime": {"python": sys.version, "executable": sys.executable, "platform": platform.platform(),
                          "openssl": assessor.verifier_identity}, "cases": reports,
              "previous_api_response_preserved": True, "protected_files_unchanged": len(before["protected_files"]),
              "implementation_files": {name: trial.identity((trial.HERE / name).read_bytes())
                 for name in ("recipient_trial.py", "trial_fixtures.py", "run_trial.py")},
              "synthetic_signatures": True, "new_s3_execution": False}
    (output / "RUN.json").write_bytes(trial.encoded(record) + b"\n")
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", required=True, type=Path)
    parser.add_argument("--openssl-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    record = run(args.output, args.openssl, args.openssl_sha256)
    print(json.dumps({"report": str(args.output / "RUN.json"), "controls": len(record["cases"]),
                      "previous_api_response_preserved": record["previous_api_response_preserved"]}))


if __name__ == "__main__":
    main()
