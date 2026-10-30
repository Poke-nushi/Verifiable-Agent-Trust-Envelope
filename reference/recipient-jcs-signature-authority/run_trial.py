#!/usr/bin/env python3
"""Create local public-key test material and report distinct assessment results."""
import argparse
from copy import deepcopy
import json
from pathlib import Path

import jcs_recipient_trial as trial
from jcs_trial_fixtures import Fixtures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new directory for synthetic controls and results")
    args = parser.parse_args()
    fixtures = Fixtures()
    assessor = fixtures.assessor()
    manifest = fixtures.save(args.output)
    controls = {}

    def check(name, changes, signature, authority, linkage):
        inputs = {**fixtures.arguments(), **changes}
        result = assessor.assess(**inputs)
        observed = {"signature": result["signatures"]["post_execution"]["status"],
                    "issuer_authority": result["issuer_authority"]["post_execution"]["status"],
                    "receipt_linkage": result["receipt_assessment"]["native_result"]["record_linkage"]}
        expected = {"signature": signature, "issuer_authority": authority, "receipt_linkage": linkage}
        for field, value in expected.items():
            if observed[field] != value:
                raise RuntimeError(f"{name}: unexpected {field} result")
        folder = args.output / name
        folder.mkdir()
        for field, raw in inputs.items():
            if raw is not None:
                (folder / (field + (".jws" if field.endswith("proof") else ".json"))).write_bytes(raw)
        (folder / "result.json").write_bytes(trial.encoded(result) + b"\n")
        controls[name] = observed

    check("supported", {}, "verified", "authorized_under_policy", "matched")
    check("whitespace", {"post": fixtures.post + b"\n"}, "verified", "authorized_under_policy", "matched")
    changed = json.loads(fixtures.post)
    changed["issuer"]["id"] = "urn:vate:local:ungranted-issuer"
    raw = trial.encoded(changed)
    check("tampered", {"post": raw}, "invalid", "not_assessed", "matched")
    check("ungranted-issuer", {"post": raw, "post_proof": fixtures.sign("post_execution", raw, 1)}, "verified", "denied", "matched")
    expired = deepcopy(fixtures.policy)
    expired["evaluation_time"] = "2026-10-15T00:00:00Z"
    check("expired-grant", {"receiver_policy": trial.encoded(expired)}, "verified", "denied", "matched")
    check("missing-proof", {"post_proof": None}, "not_assessed", "not_assessed", "matched")
    check("unknown-key", {"post_proof": fixtures.sign("post_execution", fixtures.post, 2),
                          "receiver_policy": trial.encoded({**fixtures.policy, "verification_keys": fixtures.policy["verification_keys"][:2]})},
          "not_assessed", "not_assessed", "matched")
    # Keep issuance authority but break the independent admission linkage.
    changed = json.loads(fixtures.post)
    changed["admission"]["digest"]["value"] = "0" * 64
    raw = trial.encoded(changed)
    check("linkage-mismatch", {"post": raw, "post_proof": fixtures.sign("post_execution", raw, 1)}, "verified", "authorized_under_policy", "mismatch")
    summary = {"trial_contract": trial.CONTRACT, "controls": controls, "fixture_manifest": manifest,
               "no_external_implementation_run": True, "no_execution_authorization": True}
    (args.output / "SUMMARY.json").write_bytes(trial.encoded(summary) + b"\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
