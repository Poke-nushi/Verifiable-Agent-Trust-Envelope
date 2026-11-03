"""Self-authored synthetic RB inputs; receiver choices here are fixture choices."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone

from rb_receiving import (COMMIT, NO_COMMIT, UNKNOWN, OBSERVATION, SELECTION, REGISTRY,
                          RB_TYPE, context, digest, encode)

BASE = datetime(2026, 10, 23, tzinfo=timezone.utc)


def timestamp(seconds):
    return (BASE + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def inputs(scenario="no_commit"):
    if scenario not in ("no_commit", "commit_observed", "not_established", "replay_only", "time_tie"):
        raise ValueError("unknown example scenario")
    sink = {"id": "urn:example:rb:first-file", "kind": "filesystem",
            "commitBoundary": "successful return of fsync for first.txt; directory durability is not assessed"}
    window = {"start": timestamp(0), "end": timestamp(5)}
    plan = encode({"sink": sink, "window": window}) + b"\n"
    positive = scenario in ("commit_observed", "not_established")
    counts = {"attempts": 1, "inFlightAtRevocation": 1, "postRevocationCommits": int(positive),
              "replaysAttempted": int(scenario == "replay_only"), "replaysCommitted": int(scenario == "replay_only")}
    result = UNKNOWN if scenario in ("not_established", "time_tie") else COMMIT if positive or scenario == "replay_only" else NO_COMMIT
    statement = {"_type": "https://in-toto.io/Statement/v1", "predicateType": RB_TYPE,
                 "subject": [{"name": "local example plan", "digest": {"sha256": digest(plan)}}],
                 "predicate": {"incident": {"issuer": "https://example.org/incidents", "id": "synthetic-" + scenario},
                    "producer": {"id": "https://example.org/rb-producer"}, "issuedAt": timestamp(6),
                    "registryDigest": {"sha256": REGISTRY},
                    "doesNotAssert": ["Independent time, signer authority, or production operation."],
                    "sink": sink, "window": window, "observer": {"id": "urn:example:local-harness", "vantage": "sink_side"},
                    "revocation": {"credential": "urn:example:credential:runtime-key-1", "effectiveAt": timestamp(1),
                                   "timeSource": "urn:example:controlled-seconds"},
                    "counts": counts, "exclusions": [], "result": result}}
    raw = encode(statement) + b"\n"
    selection = {"profile": SELECTION, "receiver_id": "urn:example:rb-receiver", "expected": deepcopy(context(statement))}
    committed = scenario in ("commit_observed", "not_established", "time_tie")
    attempt = {"id": "task-1", "kind": "initial", "replay_of": None, "started_at": timestamp(0),
               "finished_at": timestamp(3), "commit_state": "committed" if committed else "not_committed",
               "committed_at": timestamp(1 if scenario == "time_tie" else 2) if committed else None}
    observation = {"profile": OBSERVATION, "statement_sha256": digest(raw), "context": context(statement),
                   "collection": "closed", "attempts": [attempt], "exclusions": []}
    if scenario == "not_established":
        observation["collection"] = "partial"
        attempt.update(commit_state="unknown", committed_at=None)
    if scenario == "replay_only":
        observation["attempts"].append({"id": "task-1-replay", "kind": "replay", "replay_of": "task-1",
            "started_at": timestamp(2), "finished_at": timestamp(4), "commit_state": "committed", "committed_at": timestamp(3)})
    return {"statement": raw, "selection": encode(selection) + b"\n", "test_plan": plan,
            "observation": encode(observation) + b"\n"}
