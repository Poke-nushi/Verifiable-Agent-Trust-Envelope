"""Read an exported local record against a separately selected receiver contract.

Does not import Provider, open its DB, or perform file effects. A producer's event
history is local evidence, not independent timestamping or a tamper-proof audit log.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re

from contract import (PROFILE, VERIFICATION_ERRORS, Selection, b64, decode, encode, exact,
                      integer, need, safe_read, sha, unb64)


def verify(raw: bytes, selected_raw: bytes, anchor_raw: bytes) -> dict:
    selected = Selection(selected_raw)
    anchor = decode(anchor_raw)
    exact(anchor, {"store_id", "selection_sha256", "db_dev", "db_ino"})
    need(anchor["selection_sha256"] == sha(selected_raw), "anchor selection mismatch")
    bundle = decode(raw)
    exact(bundle, {"profile", "store_id", "selection", "selection_sha256", "events", "acceptance", "native",
                   "observation", "worker_fenced", "file_bytes"})
    need(bundle["profile"] == PROFILE and unb64(bundle["selection"]) == selected_raw and
         bundle["selection_sha256"] == sha(selected_raw), "selection substitution")
    need(bundle["worker_fenced"] is True, "unfenced observation")
    need(type(bundle["store_id"]) is str and bundle["store_id"], "missing store identity")
    need(bundle["store_id"] == anchor["store_id"], "store substitution")
    events = bundle["events"]
    need(isinstance(events, list) and events, "missing event history")
    maximum = 0
    signed_identities = {}
    revoked = conflict = False
    challenges = {}
    consumed, decisions, used_nonces = set(), set(), set()
    unavailable_count = 0
    accepted = native = None
    status_pulls = {}
    last_time = 0
    clock_bad = False
    def inventory(value):
        need(isinstance(value, list) and len(value) <= 8, "invalid file inventory")
        names = []
        allowed = {x["name"] for x in selected.operation["target"]["files"]}
        for item in value:
            exact(item, {"name", "sha256", "size"})
            need(type(item["name"]) is str and item["name"] in allowed and
                 type(item["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None and
                 type(item["size"]) is int and 0 <= item["size"] <= 4096, "invalid file observation")
            names.append(item["name"])
        need(names == sorted(set(names)), "repeated/unordered file inventory")
    for expected_id, event in enumerate(events, 1):
        exact(event, {"id", "kind", "body"})
        need(type(event["id"]) is int and event["id"] == expected_id, "missing/reordered events")
        kind, body = event["kind"], event["body"]
        if "checked_at" in body or "created" in body:
            at = integer(body.get("checked_at", body.get("created")))
            clock_bad |= at < last_time
            last_time = max(at, last_time)
        if kind == "initialized":
            exact(body, {"store_id", "selection_sha256"})
            need(expected_id == 1 and body["store_id"] == bundle["store_id"] and
                 body["selection_sha256"] == sha(selected_raw), "initialization binding mismatch")
        elif kind == "clock":
            exact(body, {"checked_at", "clock_high", "clock_bad"})
            need(type(body["clock_high"]) is int and body["clock_high"] == last_time and
                 type(body["clock_bad"]) is bool and body["clock_bad"] == clock_bad, "clock history mismatch")
        elif kind == "challenge":
            exact(body, {"attempt_id", "nonce", "created"})
            need(type(body["attempt_id"]) is str and body["attempt_id"] not in challenges and
                 type(body["nonce"]) is str and body["nonce"] not in used_nonces, "repeated challenge")
            challenges[body["attempt_id"]] = body
            used_nonces.add(body["nonce"])
        elif kind == "consumed":
            exact(body, {"attempt_id"})
            a = body["attempt_id"]
            need(a in challenges and a not in consumed, "reused/missing attempt")
            consumed.add(a)
        elif kind == "status":
            exact(body, {"raw", "raw_sha256", "signing_input_sha256", "checked_at", "source", "revoked", "conflict"})
            raw_status = unb64(body["raw"])
            v = selected.status(raw_status, body["checked_at"])
            need(v.raw_sha256 == body["raw_sha256"] and v.signing_input_sha256 == body["signing_input_sha256"],
                 "status digest mismatch")
            s = v.payload
            version = s["sequence"]
            if version in signed_identities and v.signing_input_sha256 != signed_identities[version]:
                conflict = True
            signed_identities.setdefault(version, v.signing_input_sha256)
            maximum = max(maximum, version)
            revoked |= s["state"] == "revoked"
            need(type(body["revoked"]) is bool and body["revoked"] == revoked and
                 type(body["conflict"]) is bool and body["conflict"] == conflict, "terminal state mismatch")
            need(type(body["source"]) is str, "invalid status source")
            if body["source"].startswith("pull:"):
                a = body["source"][5:]
                need(a in consumed and a not in decisions and a not in status_pulls, "unbound/repeated pull")
                status_pulls[a] = (v, body["checked_at"])
            else:
                need(body["source"] == "notification", "unknown status source")
        elif kind in ("decision", "verification_unavailable"):
            extra = {"unavailable_checks"} if kind == "verification_unavailable" else {"reason", "output_before_acceptance"}
            exact(body, {*selected.binding(), "attempt_id", "nonce", "checked_at", "proof",
                         "proof_sha256", "pull", "pull_sha256", "pull_outcome", "status_sequence", "store_id", *extra})
            a = body["attempt_id"]
            need(a in consumed and a not in decisions, "unbound/repeated decision")
            decisions.add(a)
            need(body["nonce"] == challenges[a]["nonce"] and body["store_id"] == bundle["store_id"] and
                 all(body[k] == value for k, value in selected.binding().items()), "decision binding mismatch")
            proof_raw = unb64(body["proof"])
            need(sha(proof_raw) == body["proof_sha256"], "proof original digest mismatch")
            pull_raw = unb64(body["pull"]) if body["pull"] is not None else None
            need(body["pull_sha256"] == (sha(pull_raw) if pull_raw is not None else None), "pull original digest mismatch")
            need(body["pull_outcome"] == ("received" if pull_raw is not None else "unavailable"), "pull observation mismatch")
            need(type(body["status_sequence"]) is int and body["status_sequence"] == maximum, "state version mismatch")
            now = body["checked_at"]
            unavailable = body.get("unavailable_checks", {})
            if kind == "verification_unavailable":
                need(isinstance(unavailable, dict) and 0 < len(unavailable) <= 2 and
                     set(unavailable) <= {"status", "proof"} and
                     all(type(v) is str and v in VERIFICATION_ERRORS for v in unavailable.values()),
                     "invalid verifier availability observation")
            if "status" in unavailable:
                need(pull_raw is not None, "status verifier observation without original")
                pulled = None  # This record makes no status-authentication assertion.
            else:
                try:
                    pulled = selected.status(pull_raw, now) if pull_raw is not None else None
                except ValueError:
                    pulled = None
            need((a in status_pulls) == (pulled is not None), "missing or invented authenticated pull event")
            if pulled is not None:
                v, checked = status_pulls[a]
                need(v.raw == pull_raw and checked == now, "substituted pull")
            if kind == "verification_unavailable":
                # The historical outage is a provider assertion. Its originals
                # are bound, but neither proof validity nor refusal is claimed.
                unavailable_count += 1
                continue
            try:
                selected.proof(proof_raw, challenges[a], now)
                proof_valid = True
            except ValueError:
                proof_valid = False
            expected_reason = "accepted"
            if accepted is not None:
                expected_reason = "already_accepted"
            elif clock_bad:
                expected_reason = "clock_uncertain"
            elif not proof_valid:
                expected_reason = "proof_invalid"
            elif not selected.admission_current(now):
                expected_reason = "admission_expired"
            elif not challenges[a]["created"] <= now < challenges[a]["created"] + 60:
                expected_reason = "attempt_expired"
            elif conflict:
                expected_reason = "authority_conflict"
            elif revoked:
                expected_reason = "revoked"
            elif pulled is None:
                expected_reason = "status_unavailable"
            elif pulled.payload["sequence"] != maximum:
                expected_reason = "status_rollback"
            elif not selected.fresh(pulled.payload, now):
                expected_reason = "status_stale"
            elif pulled.payload["state"] != "active":
                expected_reason = "status_not_active"
            if expected_reason == "accepted":
                inventory(body["output_before_acceptance"])
                if body["output_before_acceptance"]:
                    expected_reason = "output_not_empty"
            else:
                need(body["output_before_acceptance"] is None, "unreached output observation")
            need(body["reason"] == expected_reason, "decision reason inconsistent with bound evidence")
            if expected_reason == "accepted":
                accepted = {"event_id": event["id"], "body": body}
        elif kind == "native":
            need(accepted is not None and native is None, "native result missing acceptance or duplicated")
            exact(body, {"operation_key", "attempt_id", "admission_sha256", "input_sha256", "proof_sha256",
                         "pull_sha256", "acceptance_event_id", "files", "outcome"})
            need(body["acceptance_event_id"] == accepted["event_id"] and all(body[k] == accepted["body"][k]
                 for k in ("operation_key", "attempt_id", "admission_sha256", "input_sha256", "proof_sha256", "pull_sha256")),
                 "native result binding mismatch")
            need(body["outcome"] == "success", "unsupported native result")
            integer(body["acceptance_event_id"])
            inventory(body["files"])
            native = body
        else:
            raise ValueError("unknown event kind")
    if bundle["acceptance"] is not None:
        exact(bundle["acceptance"], {"event_id", "body"})
        integer(bundle["acceptance"]["event_id"])
    need(bundle["acceptance"] == accepted and bundle["native"] == native, "summary differs from event originals")
    observation = bundle["observation"]
    exact(observation, {"status", "accepted", "files", "native"})
    need(type(observation["accepted"]) is bool and observation["accepted"] == (accepted is not None) and
         observation["native"] == native, "acceptance/native observation mismatch")
    operation_files = {x["name"]: x["text"].encode("utf-8") for x in selected.operation["target"]["files"]}
    need(isinstance(bundle["file_bytes"], dict) and set(bundle["file_bytes"]) <= set(operation_files), "unexpected output")
    files = [{"name": name, "sha256": sha(unb64(data)), "size": len(unb64(data))}
             for name, data in sorted(bundle["file_bytes"].items())]
    inventory(observation["files"])
    need(files == observation["files"], "observed file bytes/digest mismatch")
    expected = [{"name": name, "sha256": sha(data), "size": len(data)} for name, data in sorted(operation_files.items())]
    status = "unknown"
    if accepted is None and native is None and files == []:
        status = "not_accepted"
    elif accepted is not None and native is not None and native["files"] == files == expected:
        status = "effect_observed"
    need(observation["status"] == status, "overstated outcome")
    return {"verified": True, "outcome": status, "accepted": accepted is not None,
            "observed_files": len(files), "decisions": len(decisions) - unavailable_count,
            "verification_unavailable": unavailable_count,
            "raw_sha256": sha(raw), "boundary": "local evidence consistency; clock, verifier/fetch availability and file observations are provider-local assertions, not independent timestamp or completeness proof"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--selection", required=True, type=Path)
    parser.add_argument("--anchor", required=True, type=Path, help="separately selected store identity")
    args = parser.parse_args()
    print(encode(verify(safe_read(args.bundle), safe_read(args.selection), safe_read(args.anchor))).decode())


if __name__ == "__main__":
    main()
