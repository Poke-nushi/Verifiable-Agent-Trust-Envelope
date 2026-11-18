"""Pure replay of the bounded local journal. No filesystem writes or provider calls."""
from __future__ import annotations

from handoff_contract import (PROFILE, OBS_TYP, PROOF_TYP, ZERO, MAX_COUNTER, MAX_EVENTS, MAX_JOURNAL_BYTES,
                              RESERVED_EVENT_BYTES, encode, decode, sha, unb64, iso,
                              exact, integer, need, binding, effect_state, expected_inventory,
                              reserved_event_count, validate_event_size)
from dependencies import demo


def initial():
    return {"operations": {}, "subjects": {}, "handoffs": {}, "clock_high": 0, "clock_bad": False,
            "last_status": None}


def merge_status(state, verified):
    p = verified.payload
    subject = state["subjects"].setdefault(p["runtime"],
        {"sequence": 0, "identities": {}, "latest": None, "revoked": False, "conflict": False})
    seq = str(p["sequence"])
    if seq in subject["identities"] and subject["identities"][seq] != verified.signing_input_sha256:
        subject["conflict"] = True
    subject["identities"].setdefault(seq, verified.signing_input_sha256)
    subject["revoked"] |= p["state"] == "revoked"
    if p["sequence"] > subject["sequence"]:
        subject["sequence"], subject["latest"] = p["sequence"], p


def admission_reason(context, state, op, ticket, status, inventory, at):
    if state["clock_bad"]:
        return "clock_uncertain"
    if op["accepted"] is not None:
        return "already_accepted"
    if ticket["generation"] != op["generation"] or ticket["runtime"] != op["runtime"]:
        return "old_generation"
    if ticket["authorization_sha256"] != op["authorization_sha256"]:
        return "old_authorization"
    if inventory or op["native"] is not None:
        return "effect_evidence_unresolved"
    if any(o["attempt_id"] in op["tickets"] and op["tickets"][o["attempt_id"]]["generation"] == op["generation"]
           for o in op["unknown"]):
        return "unresolved_current_attempt"
    if op["generation"] > 1 and (not op["handoff_results"] or
                                  op["handoff_results"][-1]["effect_state"] != "confirmed_unexecuted"):
        return "no_unexecuted_confirmation"
    auth = op["authorizations"][op["authorization_sha256"]]
    if not context.admission_current(op["operation"], auth, at):
        return "admission_expired"
    if not ticket["issued_at"] <= at < ticket["expires_at"]:
        return "ticket_expired"
    s = state["subjects"].get(ticket["runtime"])
    if not s or s["conflict"]:
        return "status_conflict"
    if s["revoked"]:
        return "status_revoked"
    if status["sequence"] != s["sequence"]:
        return "status_stale_version"
    if status["state"] != "active":
        return "status_not_active"
    if not (status["generated_at"] <= at < status["next_update_at"] and at - status["generated_at"] <= 60):
        return "status_expired"
    return None


def validate_inventory(value):
    need(isinstance(value, dict) and len(value) <= 8, "inventory shape")
    for name, item in value.items():
        need(isinstance(name, str) and demo.FILE_RE.fullmatch(name), "inventory name")
        exact(item, {"size", "sha256"})
        need(integer(item["size"]) <= 4096, "inventory size")
        demo.check_digest({"alg": "sha-256", "value": item["sha256"]}, "inventory")


def apply(context, state, event):
    """Validate before modifying the caller-owned replay state."""
    exact(event, {"index", "previous", "context_sha256", "at", "kind", "operation_id", "body"})
    need(integer(event["index"]) >= 1, "event index")
    need(event["context_sha256"] == context.digest, "event context")
    at, kind, operation_id, b = integer(event["at"]), event["kind"], event["operation_id"], event["body"]
    state["clock_bad"] |= at < state["clock_high"]
    state["clock_high"] = max(state["clock_high"], at)
    if kind == "clock":
        need(operation_id is None and b == {}, "clock shape")
        return
    if kind == "status":
        need(operation_id is None, "global status event")
        exact(b, {"raw", "raw_sha256", "signing_input_sha256"})
        raw = unb64(b["raw"])
        v = context.status(raw, at)
        need(b["raw_sha256"] == sha(raw) and b["signing_input_sha256"] == v.signing_input_sha256, "status digest")
        merge_status(state, v)
        state["last_status"] = {"event_index": event["index"], "at": at, "runtime": v.payload["runtime"],
                                "raw_sha256": v.raw_sha256, "signing_input_sha256": v.signing_input_sha256}
        return
    demo.identifier(operation_id)
    if kind == "registered":
        exact(b, {"operation", "authorization"})
        op = context.operation(b["operation"])
        need(op["operation_key"] == operation_id and operation_id not in state["operations"], "duplicate operation")
        need(not state["clock_bad"], "clock_uncertain")
        need(all(x["operation"]["target"]["resource"] != op["target"]["resource"] for x in state["operations"].values()),
             "resource already assigned")
        context.authorization(op, b["authorization"])
        h = sha(encode(b["authorization"]))
        state["operations"][operation_id] = {
            "operation": op, "runtime": b["authorization"]["runtime"], "generation": 1, "revision": 1,
            "authorization_sha256": h, "authorizations": {h: b["authorization"]}, "tickets": {},
            "unknown": [], "accepted": None, "native": None, "handoff_results": [], "observations": [],
            "execution_clocks": {}, "reserved_events": 0,
        }
        return
    need(operation_id in state["operations"], "unregistered operation")
    op = state["operations"][operation_id]
    need(op["revision"] < MAX_COUNTER, "revision capacity")
    if kind == "ticket":
        base = binding(context, op)
        exact(b, {*base, "attempt_id", "nonce", "issued_at", "expires_at"})
        need(not state["clock_bad"] and op["accepted"] is None, "no new ticket")
        need(encode({k: b[k] for k in base}) == encode(base), "ticket binding")
        demo.identifier(b["attempt_id"]); demo.identifier(b["nonce"])
        need(all(b["attempt_id"] not in x["tickets"] and
                 all(t["nonce"] != b["nonce"] for t in x["tickets"].values()) for x in state["operations"].values()),
             "duplicate ticket/nonce")
        need(integer(b["issued_at"]) == at and integer(b["expires_at"]) - at == 60, "ticket interval")
        op["tickets"][b["attempt_id"]] = b
    elif kind == "unknown":
        exact(b, {"attempt_id", "runtime", "raw"})
        need(b["attempt_id"] in op["tickets"], "unknown nonexistent ticket")
        ticket = op["tickets"][b["attempt_id"]]
        need(b["runtime"] == ticket["runtime"], "observation actor")
        p = context.verify_actor(unb64(b["raw"]), b["runtime"], OBS_TYP).payload
        exact(p, {"profile", "context_sha256", "operation_id", "attempt_id", "runtime", "observed_at", "outcome"})
        need(p["profile"] == PROFILE and p["context_sha256"] == context.digest and
             p["operation_id"] == operation_id and p["attempt_id"] == b["attempt_id"] and
             p["runtime"] == b["runtime"] and p["outcome"] == "unknown", "observation binding")
        need(ticket["issued_at"] <= integer(p["observed_at"]) <= at, "observation time")
        op["unknown"].append({**p, "recorded_at": at, "event_index": event["index"]})
    elif kind in ("accepted", "denied"):
        exact(b, {"attempt_id", "proof", "status", "inventory", "reason", "worker_excluded"})
        need(b["attempt_id"] in op["tickets"] and b["worker_excluded"] is True, "submit ticket/worker")
        validate_inventory(b["inventory"])
        ticket = op["tickets"][b["attempt_id"]]
        # Signed contents are always exact; freshness belongs to the decision below.
        p = context.verify_actor(unb64(b["proof"]), ticket["runtime"], PROOF_TYP).payload
        need(encode(p) == encode(ticket), "proof binding mismatch")
        v = context.status(unb64(b["status"]), at)
        need(v.payload["runtime"] == ticket["runtime"], "pull subject mismatch")
        # The transaction records the exact pull immediately before its decision.
        # Sequence existence alone does not bind the two authenticated originals.
        expected_pull = {"event_index": event["index"] - 1, "at": at, "runtime": v.payload["runtime"],
                         "raw_sha256": v.raw_sha256, "signing_input_sha256": v.signing_input_sha256}
        need(state["last_status"] == expected_pull, "decision pull original mismatch")
        reason = admission_reason(context, state, op, ticket, v.payload, b["inventory"], at)
        need(reason == b["reason"] and (kind == "accepted") == (reason is None), "incorrect acceptance decision")
        if kind == "accepted":
            need(op["accepted"] is None, "duplicate acceptance")
            op["accepted"] = {"attempt_id": b["attempt_id"], "event_index": event["index"],
                              "admission_checked_at": at, "runtime": ticket["runtime"],
                              "generation": ticket["generation"], "admission_sha256": ticket["admission_sha256"]}
            op["reserved_events"] = 3
    elif kind == "execution_clock":
        exact(b, {"phase", "sampled_at"})
        need(op["accepted"] is not None and op["native"] is None and b["phase"] in ("start", "finish"),
             "execution clock without pending acceptance")
        need(b["phase"] not in op["execution_clocks"] and op["reserved_events"] > 1, "repeated execution clock")
        if b["phase"] == "finish":
            need("start" in op["execution_clocks"], "finish clock before start")
        sampled = integer(b["sampled_at"])
        prior = (op["accepted"]["admission_checked_at"] if b["phase"] == "start" else
                 op["execution_clocks"]["start"]["recorded_at"])
        # A later status may have committed while this sample waited for the DB.
        # Compare actual samples with their own preceding boundary, not with that
        # unrelated later event; global recorded time is checked above separately.
        state["clock_bad"] |= sampled < prior or sampled > at
        op["execution_clocks"][b["phase"]] = {"sampled_at": sampled, "recorded_at": at}
        op["reserved_events"] -= 1
    elif kind == "clock_fault":
        need(b == {} and state["clock_bad"] and op["accepted"] is not None and op["native"] is None and
             op["reserved_events"] >= 1, "unbound clock fault")
        op["reserved_events"] -= 1
    elif kind == "native":
        exact(b, {"attempt_id", "runtime", "admission_sha256", "input_sha256", "started_at", "finished_at", "outputs"})
        need(op["accepted"] is not None and op["native"] is None, "unbound/duplicate native")
        accepted = op["accepted"]
        ticket = op["tickets"][accepted["attempt_id"]]
        for k in ("attempt_id", "runtime", "admission_sha256", "input_sha256"):
            need(b[k] == ticket[k], "native binding")
        validate_inventory(b["outputs"])
        need(b["outputs"] == expected_inventory(op["operation"]), "native outputs")
        # Missing actual times is explicitly unassessable, never substituted with checked_at.
        for k in ("started_at", "finished_at"):
            if b[k] is not None:
                demo.time_value(b[k])
        if b["started_at"] is not None and b["finished_at"] is not None:
            need(set(op["execution_clocks"]) == {"start", "finish"} and not state["clock_bad"], "missing/uncertain actual clock")
            need(b["started_at"] == iso(op["execution_clocks"]["start"]["sampled_at"]) and
                 b["finished_at"] == iso(op["execution_clocks"]["finish"]["sampled_at"]), "native clock originals mismatch")
            need(demo.time_value(iso(accepted["admission_checked_at"])) <= demo.time_value(b["started_at"]) <=
                 demo.time_value(b["finished_at"]) <= demo.time_value(iso(at)), "native actual time order")
        op["native"] = b
        op["reserved_events"] = 0
    elif kind == "handoff":
        exact(b, {"request_raw", "inventory", "retained_attempts", "effect_state", "worker_excluded"})
        request_raw = unb64(b["request_raw"])
        request = decode(request_raw)
        check_handoff_request(context, request)
        need(request_raw == encode(request), "handoff canonical bytes")
        need(request["request_id"] not in state["handoffs"], "reapplied handoff")
        need(request["operation_id"] == operation_id and request["old_runtime"] == op["runtime"], "old assignment mismatch")
        need(request["expected_generation"] == op["generation"] and request["expected_revision"] == op["revision"], "stale")
        need(op["generation"] < MAX_COUNTER and not state["clock_bad"], "generation capacity/clock")
        auth = request["authorization"]
        context.authorization(op["operation"], auth)
        need(auth["runtime"] != op["runtime"], "handoff requires the other actor")
        validate_inventory(b["inventory"])
        need(b["worker_excluded"] is True and b["retained_attempts"] == sorted(op["tickets"]), "handoff history/worker")
        need(set(request["read_attempts"]).issubset(op["tickets"]), "unknown submitted history reference")
        need(b["effect_state"] == effect_state(op, b["inventory"], fenced=True), "handoff classification")
        op["generation"] += 1
        op["runtime"] = auth["runtime"]
        h = sha(encode(auth))
        op["authorization_sha256"] = h
        op["authorizations"].setdefault(h, auth)
        result = {"request_id": request["request_id"], "generation": op["generation"], "revision": op["revision"] + 1,
                  "effect_state": b["effect_state"], "retained_attempts": b["retained_attempts"],
                  "event_index": event["index"], "is_execution_ticket": False}
        op["handoff_results"].append(result)
        state["handoffs"][request["request_id"]] = {"request_raw": b["request_raw"], "result": result}
    elif kind == "observed":
        exact(b, {"inventory", "effect_state", "worker_excluded"})
        validate_inventory(b["inventory"])
        need(b["worker_excluded"] is True and b["effect_state"] == effect_state(op, b["inventory"]), "observation mismatch")
        op["observations"].append({**b, "observed_at": at, "event_index": event["index"]})
    else:
        raise ValueError("unknown event kind")
    op["revision"] += 1
    need(op["revision"] + op["reserved_events"] <= MAX_COUNTER, "revision reserve capacity")


def check_handoff_request(context, request):
    exact(request, {"context_sha256", "request_id", "operation_id", "expected_generation", "expected_revision",
                    "old_runtime", "authorization", "read_attempts"})
    need(request["context_sha256"] == context.digest, "handoff selected context")
    for k in ("request_id", "operation_id", "old_runtime"):
        demo.identifier(request[k])
    need(integer(request["expected_generation"]) >= 1 and integer(request["expected_revision"]) >= 1, "handoff version")
    need(isinstance(request["read_attempts"], list) and request["read_attempts"] == sorted(set(request["read_attempts"])),
         "handoff history refs")


def replay(context, records):
    state, previous, total_bytes = initial(), ZERO, 0
    for i, record in enumerate(records, 1):
        exact(record, {"raw", "sha256"})
        raw = unb64(record["raw"])
        event = decode(raw)
        validate_event_size(raw, event["kind"])
        need(raw == encode(event) and sha(raw) == record["sha256"], "event original hash")
        need(event["index"] == i and event["previous"] == previous, "event chain discontinuity")
        apply(context, state, event)
        total_bytes += len(raw)
        reserved = reserved_event_count(state)
        need(i + reserved <= MAX_EVENTS and total_bytes + reserved * RESERVED_EVENT_BYTES <= MAX_JOURNAL_BYTES,
             "historical reservation capacity")
        previous = record["sha256"]
    return state
