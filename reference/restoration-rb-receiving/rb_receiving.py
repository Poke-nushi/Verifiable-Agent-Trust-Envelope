"""Read a bounded Restoration Evidence RB Statement against receiver choices.

No network, dynamic verifier, signature validation, or permission decision.
The optional observation contract describes local assertions, not trusted time.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from itertools import combinations
import json
import os
from pathlib import Path
import re
import stat
import sys

PROFILE = "vate-local-restoration-rb-receiving-v1"
SELECTION = "vate-local-rb-selection-v1"
OBSERVATION = "vate-local-rb-observation-v1"
PLAN = "vate-local-rb-plan-raw-v1"
TYPE_PREFIX = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/"
PREDICATES = {TYPE_PREFIX + name for name in (
    "incident-action-authorization", "revocation-sweep", "re-enable-decision",
    "joint-authority", "revocation-boundary")}
RB_TYPE = TYPE_PREFIX + "revocation-boundary"
REGISTRY = "1c5ff80bd97237a603afc402db692ffe5abe15e4a7f9eca13f20068ada347fdc"
RULESET = "draft-gilda-audit-restoration-evidence-00;rb;local-bounded-reader-v1"
COUNTS = ("attempts", "inFlightAtRevocation", "postRevocationCommits", "replaysAttempted", "replaysCommitted")
NO_COMMIT = "no_post_revocation_commit_observed"
COMMIT = "post_revocation_commit_observed"
UNKNOWN = "not_established"
MAX_BYTES = 1024 * 1024
MAX_INTEGER = 9007199254740991
MAX_ITEMS = 256
COMMON = {"incident", "producer", "issuedAt", "registryDigest", "doesNotAssert"}
# Use the pinned checker's ECMAScript whitespace set, not Python's broader \s.
HTTPS_RE = re.compile("https://[^\\t\\n\\v\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f"
                      "\\u205f\\u3000\\ufeff]+")
try:
    _SOURCE_RAW = Path(__file__).read_bytes()
    _SOURCE_VALID = compile(_SOURCE_RAW, __file__, "exec", dont_inherit=True,
                            optimize=sys.flags.optimize) == sys._getframe().f_code
except (OSError, SyntaxError, ValueError):
    _SOURCE_RAW, _SOURCE_VALID = b"", False


class InputError(ValueError):
    def __init__(self, code, source):
        self.code, self.source = code, source
        super().__init__(code)


def need(ok, code, source):
    if not ok:
        raise InputError(code, source)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def identity(raw):
    if raw is None:
        return None
    return {"digest_basis": "raw_file_sha256", "sha256": digest(raw), "byte_length": len(raw)}


def decode(raw, source):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "INPUT_SIZE_OR_TYPE", source)

    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "DUPLICATE_JSON_KEY", source)
            result[key] = value
        return result

    def number(token):
        need(len(token) <= 17, "INTEGER_OUT_OF_RANGE", source)
        value = int(token)
        need(abs(value) <= MAX_INTEGER, "INTEGER_OUT_OF_RANGE", source)
        return value

    def no_number(_):
        raise InputError("NONINTEGER_NUMBER", source)

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_int=number,
                           parse_float=no_number, parse_constant=no_number)
        todo = [(value, 0)]
        nodes = 0
        while todo:
            item, depth = todo.pop()
            nodes += 1
            need(depth <= 24 and nodes <= 20000, "JSON_COMPLEXITY", source)
            if type(item) is dict:
                todo.extend((v, depth + 1) for pair in item.items() for v in pair)
            elif type(item) is list:
                need(len(item) <= MAX_ITEMS, "ARRAY_LIMIT", source)
                todo.extend((v, depth + 1) for v in item)
            elif type(item) is str:
                item.encode("utf-8")
        return value
    except InputError:
        raise
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise InputError("INVALID_JSON", source) from None


def read_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        need(stat.S_ISREG(os.fstat(fd).st_mode), "NOT_REGULAR_FILE", "file")
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        need(0 < len(raw) <= MAX_BYTES, "INPUT_SIZE_OR_TYPE", "file")
        return raw
    finally:
        os.close(fd)


def exact(value, required, optional=()):
    return type(value) is dict and set(required) <= set(value) <= set(required) | set(optional)


def text(value):
    return type(value) is str and bool(value)


def https(value):
    return text(value) and HTTPS_RE.fullmatch(value) is not None


def sha(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def sha_object(value):
    return exact(value, ("sha256",)) and sha(value["sha256"])


def count(value):
    return type(value) is int and 0 <= value <= MAX_INTEGER


def instant(value):
    if type(value) is not str or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value) is None:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def sequence(value, predicate, minimum=0):
    return type(value) is list and minimum <= len(value) <= MAX_ITEMS and all(predicate(v) for v in value)


def incident_ref(value):
    return exact(value, ("issuer", "id")) and https(value["issuer"]) and text(value["id"])


def sink_shape(value):
    return (exact(value, ("id", "kind", "commitBoundary")) and text(value["id"])
            and type(value["kind"]) is str and value["kind"] in
            ("database", "filesystem", "http_endpoint", "subprocess", "queue", "other")
            and text(value["commitBoundary"]))


def observer_shape(value):
    return (exact(value, ("id", "vantage")) and text(value["id"])
            and type(value["vantage"]) is str and value["vantage"] in ("sink_side", "agent_side"))


def revocation_shape(value):
    return (exact(value, ("credential", "effectiveAt", "timeSource")) and text(value["credential"])
            and instant(value["effectiveAt"]) is not None and text(value["timeSource"]))


def window_shape(value):
    return exact(value, ("start", "end")) and all(instant(value[k]) is not None for k in ("start", "end"))


def exclusions_shape(value):
    return sequence(value, lambda e: exact(e, ("count", "reason")) and count(e["count"]) and text(e["reason"]))


def statement_check(value):
    fail = lambda code: {"status": "failed", "reason": code}
    if not exact(value, ("_type", "subject", "predicateType", "predicate")):
        return fail("statement-malformed")
    if value["_type"] != "https://in-toto.io/Statement/v1" or value["predicateType"] != RB_TYPE:
        return fail("statement-malformed")
    subject = value["subject"]
    if not (sequence(subject, lambda s: exact(s, ("digest",), ("name",)) and sha_object(s["digest"])
                     and ("name" not in s or text(s["name"])), 1) and len(subject) == 1
            and type(value["predicate"]) is dict):
        return fail("statement-malformed")
    p = value["predicate"]
    keys = COMMON | {"sink", "observer", "revocation", "window", "counts", "exclusions", "result"}
    if not exact(p, keys, ("predecessors",)):
        return fail("predicate-malformed")
    inc = p["incident"]
    good = (exact(inc, ("issuer", "id"), ("related",)) and https(inc["issuer"]) and text(inc["id"])
            and ("related" not in inc or sequence(inc["related"], incident_ref))
            and exact(p["producer"], ("id",)) and https(p["producer"]["id"])
            and instant(p["issuedAt"]) is not None and sha_object(p["registryDigest"])
            and sequence(p["doesNotAssert"], text) and sink_shape(p["sink"])
            and observer_shape(p["observer"]) and revocation_shape(p["revocation"])
            and window_shape(p["window"]) and exact(p["counts"], COUNTS)
            and all(count(p["counts"][k]) for k in COUNTS) and exclusions_shape(p["exclusions"])
            and type(p["result"]) is str and p["result"] in (NO_COMMIT, COMMIT, UNKNOWN)
            and ("predecessors" not in p or sequence(p["predecessors"], lambda r:
                exact(r, ("predicateType", "digest")) and type(r["predicateType"]) is str
                and r["predicateType"] in PREDICATES and sha_object(r["digest"]), 1)))
    if not good:
        return fail("predicate-malformed")
    # The pinned profile places RB's document-defined closed values in rule 2.
    # RB has no registry-valued field for common rule 3.
    if not instant(p["window"]["start"]) <= instant(p["revocation"]["effectiveAt"]) <= instant(p["window"]["end"]):
        return fail("revocation-outside-window")
    c = p["counts"]
    if not (c["inFlightAtRevocation"] <= c["attempts"] and c["postRevocationCommits"] <= c["inFlightAtRevocation"]
            and c["replaysCommitted"] <= c["replaysAttempted"]):
        return fail("counts-inconsistent")
    positive = c["postRevocationCommits"] > 0 or c["replaysCommitted"] > 0
    if p["result"] != UNKNOWN and (p["result"] == COMMIT) != positive:
        return fail("result-contradicts-counts")
    if p["result"] == NO_COMMIT and p["observer"]["vantage"] != "sink_side":
        return fail("observer-not-at-sink")
    return {"status": "passed", "reason": "boundary-recorded"}


def context(value):
    p = value["predicate"]
    return {"incident": {k: p["incident"][k] for k in ("issuer", "id")},
            "producer": p["producer"], "sink": p["sink"], "observer": p["observer"],
            "revocation": p["revocation"], "window": p["window"],
            "test_plan_sha256": value["subject"][0]["digest"]["sha256"],
            "registry_sha256": p["registryDigest"]["sha256"]}


def selection_check(raw):
    selected = decode(raw, "selection")
    need(exact(selected, ("profile", "receiver_id", "expected")) and selected["profile"] == SELECTION
         and text(selected["receiver_id"]), "INVALID_SELECTION", "selection")
    e = selected["expected"]
    need(exact(e, ("incident", "producer", "sink", "observer", "revocation", "window", "test_plan_sha256", "registry_sha256")),
         "INVALID_SELECTION", "selection")
    need(incident_ref(e["incident"]) and exact(e["producer"], ("id",)) and https(e["producer"]["id"])
         and sink_shape(e["sink"]) and observer_shape(e["observer"]) and revocation_shape(e["revocation"])
         and window_shape(e["window"]) and sha(e["test_plan_sha256"]) and e["registry_sha256"] == REGISTRY,
         "INVALID_SELECTION", "selection")
    need(instant(e["window"]["start"]) <= instant(e["revocation"]["effectiveAt"]) <= instant(e["window"]["end"]),
         "INVALID_SELECTION_WINDOW", "selection")
    return selected


def plan_check(raw, c):
    if raw is None:
        return {"status": "not_assessed", "reason": "TEST_PLAN_ABSENT"}
    if digest(raw) != c["test_plan_sha256"]:
        return {"status": "mismatch", "reason": "TEST_PLAN_DIGEST_MISMATCH"}
    try:
        plan = decode(raw, "test_plan")
    except InputError as exc:
        return {"status": "not_assessed", "reason": exc.code}
    if not exact(plan, ("sink", "window")):
        return {"status": "not_assessed", "reason": "UNSUPPORTED_TEST_PLAN_SHAPE"}
    if plan != {k: c[k] for k in ("sink", "window")}:
        return {"status": "mismatch", "reason": "TEST_PLAN_CONTEXT_MISMATCH"}
    return {"status": "matched_under_local_profile", "profile": PLAN}


def _partition_fits(possible_groups, capacities):
    """Can every observed attempt occupy one of its allowed count categories?

    For every subset of categories, attempts restricted to that subset must
    fit its declared capacity. There are only three initial categories and
    two replay categories, so this checks at most seven subsets per group.
    Spare capacity is allowed for unobserved attempts in a partial collection;
    the separate total-count check requires equality for a closed collection.
    """
    for size in range(1, len(capacities) + 1):
        for selected in combinations(range(len(capacities)), size):
            subset = set(selected)
            required = sum(options <= subset for options in possible_groups)
            if required > sum(capacities[i] for i in selected):
                return False
    return True


def observation_check(raw, statement_raw, value):
    answer = {"status": "not_assessed", "reason": "OBSERVATION_ABSENT", "derived_counts": None,
              "derived_result": None, "observed_positive": None,
              "trust_basis": "unverified_local_observer_assertions"}
    if raw is None:
        return answer
    try:
        o = decode(raw, "observation")
    except InputError as exc:
        return {**answer, "reason": exc.code}
    if not (exact(o, ("profile", "statement_sha256", "context", "collection", "attempts", "exclusions"))
            and o["profile"] == OBSERVATION and sha(o["statement_sha256"])
            and type(o["collection"]) is str and o["collection"] in ("closed", "partial")
            and sequence(o["attempts"], lambda a: type(a) is dict)
            and exclusions_shape(o["exclusions"])):
        return {**answer, "reason": "INVALID_OBSERVATION"}
    if o["statement_sha256"] != digest(statement_raw) or o["context"] != context(value):
        return {**answer, "status": "mismatch", "reason": "OBSERVATION_BINDING_MISMATCH"}
    p = value["predicate"]
    rev = instant(p["revocation"]["effectiveAt"])
    start, end = (instant(p["window"][k]) for k in ("start", "end"))
    rows, ids = [], set()
    unknown = ["PARTIAL_COLLECTION"] if o["collection"] == "partial" else []
    for a in o["attempts"]:
        if not (exact(a, ("id", "kind", "replay_of", "started_at", "finished_at", "commit_state", "committed_at"))
                and text(a["id"]) and a["id"] not in ids and type(a["kind"]) is str
                and a["kind"] in ("initial", "replay") and type(a["commit_state"]) is str
                and a["commit_state"] in ("committed", "not_committed", "unknown")):
            return {**answer, "reason": "INVALID_OBSERVATION_ATTEMPT"}
        ids.add(a["id"])
        began, finished, committed = (instant(a[k]) for k in ("started_at", "finished_at", "committed_at"))
        if (began is None or not start <= began <= end
                or (a["finished_at"] is not None and (finished is None or not began <= finished <= end))
                or (a["commit_state"] == "committed" and (committed is None or finished is None
                    or not began <= committed <= finished))
                or (a["commit_state"] != "committed" and a["committed_at"] is not None)
                or (a["commit_state"] == "not_committed" and finished is None)):
            return {**answer, "reason": "INVALID_OBSERVATION_TIME"}
        if a["kind"] == "initial":
            if a["replay_of"] is not None:
                return {**answer, "reason": "INVALID_REPLAY_REFERENCE"}
            if began >= rev:
                unknown.append("INITIAL_NOT_BEFORE_REVOCATION")
            if began == rev or finished == rev:
                unknown.append("REVOCATION_TIME_TIE")
        else:
            if not text(a["replay_of"]) or began < rev:
                return {**answer, "reason": "INVALID_REPLAY_REFERENCE_OR_TIME"}
        if committed == rev:
            unknown.append("REVOCATION_TIME_TIE")
        if a["commit_state"] == "unknown":
            unknown.append("COMMIT_OBSERVATION_UNKNOWN")
        rows.append((a, began, finished, committed))
    initial_starts = {a["id"]: began for a, began, _, _ in rows if a["kind"] == "initial"}
    for a, began, _, _ in rows:
        if a["kind"] == "replay":
            if a["replay_of"] not in initial_starts:
                return {**answer, "reason": "INVALID_REPLAY_REFERENCE"}
            if began < initial_starts[a["replay_of"]]:
                return {**answer, "reason": "REPLAY_BEFORE_INITIAL"}

    # Bounds retain what is known for each count without turning missing effects
    # or finish times into zero. Only a closed collection bounds the full total.
    lower = {k: 0 for k in COUNTS}
    upper = {k: 0 for k in COUNTS}
    initial_groups, replay_groups = [], []

    def add(key, minimum, maximum):
        lower[key] += minimum
        upper[key] += maximum

    for a, began, finished, committed in rows:
        if a["kind"] == "initial":
            add("attempts", 1, 1)
            definitely_in_flight = int(began < rev and finished is not None and finished > rev)
            possibly_in_flight = int(began <= rev and (finished is None or finished >= rev))
            add("inFlightAtRevocation", definitely_in_flight, possibly_in_flight)
            if a["commit_state"] == "unknown" or committed == rev:
                add("postRevocationCommits", 0, possibly_in_flight)
            elif committed is not None and committed > rev:
                add("postRevocationCommits", definitely_in_flight, possibly_in_flight)
            # Disjoint categories: outside in-flight, in-flight without a
            # post-revocation commit, in-flight with a post-revocation commit.
            options = set()
            if not definitely_in_flight:
                options.add(0)
            if possibly_in_flight:
                if committed is None or committed <= rev:
                    options.add(1)
                if a["commit_state"] == "unknown" or committed is not None and committed >= rev:
                    options.add(2)
            initial_groups.append(options)
        else:
            add("replaysAttempted", 1, 1)
            if a["commit_state"] == "unknown" or committed == rev:
                add("replaysCommitted", 0, 1)
                replay_groups.append({0, 1})
            elif committed is not None and committed > rev:
                add("replaysCommitted", 1, 1)
                replay_groups.append({1})
            else:
                replay_groups.append({0})
    positive = lower["postRevocationCommits"] > 0 or lower["replaysCommitted"] > 0
    answer["observed_positive"] = positive
    if not positive and p["observer"]["vantage"] != "sink_side":
        unknown.append("NO_SINK_SIDE_OBSERVATION")
    c = p["counts"]
    differing = {k for k in COUNTS if lower[k] > c[k]
                 or o["collection"] == "closed" and c[k] > upper[k]}
    if not differing.intersection(COUNTS[:3]) and not _partition_fits(
            initial_groups, (c["attempts"] - c["inFlightAtRevocation"],
                c["inFlightAtRevocation"] - c["postRevocationCommits"], c["postRevocationCommits"])):
        differing.update(COUNTS[:3])
    if not differing.intersection(COUNTS[3:]) and not _partition_fits(
            replay_groups, (c["replaysAttempted"] - c["replaysCommitted"], c["replaysCommitted"])):
        differing.update(COUNTS[3:])
    # Even unobserved replays need an initial parent in this local population.
    # One initial can have many replays; this is not a bound on their number.
    if c["replaysAttempted"] > 0 and c["attempts"] == 0:
        differing.update(("attempts", "replaysAttempted"))
    differing = [k for k in COUNTS if k in differing]
    if (lower["postRevocationCommits"] > p["counts"]["postRevocationCommits"]
            or lower["replaysCommitted"] > p["counts"]["replaysCommitted"]
            or positive and p["result"] == NO_COMMIT):
        return {**answer, "status": "contradiction", "reason": "OBSERVED_COMMIT_EXCEEDS_DECLARATION",
                "derived_counts": None if unknown else lower, "derived_result": COMMIT,
                "different_fields": differing,
                "gaps": sorted(set(unknown))}
    if differing:
        return {**answer, "status": "contradiction", "reason": "OBSERVATION_DISAGREES_WITH_RECORD",
                "different_fields": differing, "derived_counts": None if unknown else lower,
                "derived_result": COMMIT if positive else UNKNOWN if unknown else NO_COMMIT,
                "gaps": sorted(set(unknown))}
    if unknown:
        return {**answer, "status": "not_established", "reason": "INCOMPLETE_OBSERVATION",
                "gaps": sorted(set(unknown)), "derived_result": COMMIT if positive else UNKNOWN}
    outcome = COMMIT if positive else NO_COMMIT
    compatible = p["result"] in (outcome, UNKNOWN)
    if o["exclusions"] != p["exclusions"] or not compatible:
        return {**answer, "status": "contradiction", "reason": "OBSERVATION_DISAGREES_WITH_RECORD",
                "derived_counts": lower, "derived_result": outcome}
    return {**answer, "status": "consistent_under_local_assumptions", "reason": "COUNTS_AND_RESULT_COMPATIBLE",
            "derived_counts": lower, "derived_result": outcome}


def assess(statement, selection=None, *, test_plan=None, observation=None):
    need(_SOURCE_VALID and Path(__file__).read_bytes() == _SOURCE_RAW, "READER_SOURCE_CHANGED", "reader")
    raws = {"statement": statement, "selection": selection, "test_plan": test_plan, "observation": observation}
    for name, raw in raws.items():
        need(raw is None or type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "INPUT_SIZE_OR_TYPE", name)
    selected = selection_check(selection) if selection is not None else None
    report = {"profile": PROFILE, "ruleset": RULESET,
              "reader_source": identity(_SOURCE_RAW),
              "inputs": {k: identity(v) for k, v in raws.items()},
              "record_check": {"status": "not_assessed", "reason": "STATEMENT_ABSENT"},
              "receiver_binding": {"status": "not_assessed",
                                   "reason": "RECORD_NOT_CHECKED" if selected is not None else "SELECTION_ABSENT"},
              "test_plan_binding": {"status": "not_assessed", "reason": "RECORD_NOT_CHECKED"},
              "observation_check": {"status": "not_assessed", "reason": "RECORD_NOT_CHECKED"},
              "signature_verification": {"status": "not_assessed", "reason": "DSSE_NOT_EVALUATED"},
              "issuer_authority": {"status": "not_assessed", "reason": "ISSUER_AUTHORITY_NOT_EVALUATED"},
              "evidence_sufficiency": {"status": "not_assessed", "reason": "RECEIVER_SUFFICIENCY_POLICY_NOT_EVALUATED"},
              "permission_to_resume": {"status": "not_assessed", "reason": "RECEIVER_POLICY_NOT_EVALUATED"}}
    if statement is None:
        return report
    try:
        value = decode(statement, "statement")
    except InputError as exc:
        report["record_check"] = {"status": "not_assessed", "reason": exc.code}
        return report
    report["record_check"] = statement_check(value)
    if report["record_check"]["status"] != "passed":
        return report
    c = context(value)
    report["declared"] = {"context": c, "result": value["predicate"]["result"], "counts": value["predicate"]["counts"]}
    report["test_plan_binding"] = plan_check(test_plan, c)
    report["observation_check"] = observation_check(observation, statement, value)
    if selected is not None:
        differences = sorted(k for k in c if c[k] != selected["expected"][k])
        report["receiver_binding"] = {"status": "mismatch" if differences else "matched",
                                      "different_fields": differences, "basis": "receiver_selected_claim_values",
                                      "receiver_id": selected["receiver_id"]}
    return report


def receive(destination, statement, selection, *, test_plan=None, observation=None):
    report = assess(statement, selection, test_plan=test_plan, observation=observation)
    originals = {"statement": statement, "selection": selection, "test_plan": test_plan, "observation": observation}
    destination = Path(destination)
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    manifest = {}
    for name, raw in {**originals, "report": encode(report) + b"\n"}.items():
        if raw is not None:
            filename = name + ".json"
            with (destination / filename).open("xb") as stream:
                stream.write(raw)
            manifest[filename] = identity(raw)
    with (destination / "MANIFEST.json").open("xb") as stream:
        stream.write(encode({"profile": PROFILE, "files": manifest}) + b"\n")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--statement", required=True, type=Path)
    parser.add_argument("--selection", required=True, type=Path, help="receiver-owned choices; do not copy an untrusted sender's choices")
    parser.add_argument("--test-plan", type=Path)
    parser.add_argument("--observation", type=Path)
    parser.add_argument("--out", required=True, type=Path, help="new directory retaining originals and report")
    args = parser.parse_args(argv)
    try:
        report = receive(args.out, read_file(args.statement), read_file(args.selection),
                         test_plan=read_file(args.test_plan) if args.test_plan else None,
                         observation=read_file(args.observation) if args.observation else None)
        print(encode(report).decode())
        return 0
    except (InputError, OSError) as exc:
        print(json.dumps({"error": getattr(exc, "code", "LOCAL_IO_ERROR"),
                          "input": getattr(exc, "source", None)}), file=sys.stderr)
        return 64


if __name__ == "__main__":
    sys.exit(main())
