"""Local, read-only handoff receipt intake using the existing Recipient Inbox."""
from contextlib import contextmanager
from copy import deepcopy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
SAMPLE = HERE.parent / "sample"
ROOT = HERE.parent
PINS = json.loads((SAMPLE / "SOURCE-PINS.json").read_bytes())


def check_sample():
    for name, digest in PINS.items():
        if hashlib.sha256((SAMPLE / name).read_bytes()).hexdigest() != digest:
            raise RuntimeError("selected handoff source changed: " + name)


check_sample()
# Reject an unrelated same-named module rather than silently composing with it.
for name in ("dependencies", "handoff_contract", "handoff_model", "handoff_reader"):
    if name in sys.modules and Path(sys.modules[name].__file__).resolve() != SAMPLE / (name + ".py"):
        raise RuntimeError("conflicting handoff module: " + name)
sys.path.insert(0, str(SAMPLE))
sys.path.insert(0, str(ROOT / "reference/recipient-inbox"))
from handoff_contract import Context, b64, unb64, decode, encode, sha, post_receipt
from handoff_model import replay
from handoff_reader import assess
from dependencies import demo
from recipient_inbox import Engine, Inbox, InboxError, DELIVERY, PLAN, encoded, read_file, raw_ref

CONTRACT = "local-handoff-inbox-connection-v1"
CAPSULE = CONTRACT + ":evidence"
MAX_BUNDLE = 384 * 1024
MAX_SELECTION = 64 * 1024
MAX_CAPSULE = 1024 * 1024
MAX_INTAKES = 8
MAX_AUTHORIZATIONS = 4
SOURCE_RAW = Path(__file__).read_bytes()


def need(ok, code):
    if not ok:
        raise InboxError(code, code)


def selection(raw):
    need(type(raw) is bytes and len(raw) <= MAX_SELECTION, "SELECTION_BOUND")
    value = decode(raw)
    need(set(value) == {"contract", "receiver_id", "namespace", "selected_at", "context_b64",
                       "operation_b64", "requirements"} and value["contract"] == CONTRACT, "SELECTION_SHAPE")
    context_raw, operation_raw = unb64(value["context_b64"]), unb64(value["operation_b64"])
    context = Context(context_raw)
    operation = context.operation(decode(operation_raw))
    need(encode(operation) == operation_raw and raw == encode(value), "SELECTION_CANONICAL")
    for name in ("receiver_id", "namespace"):
        need(type(value[name]) is str and 1 <= len(value[name]) <= 128 and
             all(32 < ord(c) < 127 for c in value[name]), "RECEIVER_IDENTIFIER")
    rows = value["requirements"]
    need(type(rows) is list and 1 <= len(rows) <= 4, "REQUIREMENT_BOUND")
    names = set()
    for row in rows:
        need(type(row) is dict and set(row) == {"id", "runtime", "record_kind", "due_at"}, "REQUIREMENT_SHAPE")
        demo.identifier(row["id"])
        need(row["id"] not in names and row["runtime"] in context.data["actors"] and
             row["record_kind"] in ("admission", "post_execution"), "REQUIREMENT_BINDING")
        names.add(row["id"])
    return value, context, operation


def evaluate(selected_raw, bundle_raw):
    """Input failures have no projection; environmental failures remain distinct."""
    s, context, operation = selection(selected_raw)
    result = assess(context.raw, unb64(s["operation_b64"]), bundle_raw)
    bundle = decode(bundle_raw)
    op = replay(context, bundle["records"])["operations"][operation["operation_key"]]
    need(1 <= len(op["authorizations"]) <= MAX_AUTHORIZATIONS, "PROJECTION_BOUND")
    # Stable derivation from actual native times. Observation time is not a new
    # receipt identity, and neither receipt is represented as producer-signed.
    post = post_receipt(op)
    accepted_hash = (op["tickets"][op["accepted"]["attempt_id"]]["authorization_sha256"]
                     if op["accepted"] is not None else None)
    projection = []
    for digest, authorization in sorted(op["authorizations"].items()):
        item = {"authorization_sha256": digest, "admission_b64": authorization["receipt"], "post_b64": None}
        if digest == accepted_hash and post is not None:
            item["post_b64"] = b64(encode(post))
        projection.append(item)
    return {"status": "assessed", "reason": None, "handoff": result, "projection": projection}


def verify_capsule(selected_raw, raw):
    """Receiver selection must be supplied separately, never adopted from evidence."""
    c = decode(raw)
    need(type(c) is dict and set(c) == {"contract", "event_id", "received_at", "selection_b64", "bundle_b64",
         "previous_accepted_capsule", "evaluation", "is_execution_ticket", "reader_sources"} and
         c["is_execution_ticket"] is False, "CAPSULE_SHAPE")
    need(c["contract"] == CAPSULE and unb64(c["selection_b64"]) == selected_raw, "CAPSULE_SELECTION")
    need(c["reader_sources"] == reader_sources(), "CAPSULE_READER_VERSION")
    need(c["evaluation"]["status"] == "assessed", "CAPSULE_UNASSESSABLE")
    fresh = evaluate(selected_raw, unb64(c["bundle_b64"]))
    need(encode(fresh) == encode(c["evaluation"]), "CAPSULE_REASSESSMENT_MISMATCH")
    return fresh


def reader_sources():
    return {"handoff_candidate": PINS, "bridge_sha256": sha(SOURCE_RAW)}


def requirements(s, operation, basis):
    return [{"requirement_id": row["id"], "obligation": "required", "record_kind": row["record_kind"],
        "binding_profile": "vate_receipt_operation_context", "due_at": row["due_at"], "basis_refs": [basis],
        "requested_native_checks": ["receipt_linkage"],
        "subject": {"kind": "operation", "operation_id": "handoff-" + sha(encode(
            [operation["operation_key"], row["runtime"]])),
            "native_context": {"transaction_id": operation["operation_key"], "runtime": row["runtime"],
                "effective_request_hash": demo.object_hash(operation), "action_binding": demo.action_binding(operation)}}}
        for row in s["requirements"]]


def observation_basis(capsules, selection_ref, cutoff, stamp):
    """Select one observation from the accepted chain, independent of input order."""
    cutoff_time = stamp(cutoff)
    children = {}
    for digest, capsule in capsules.items():
        previous = capsule["previous_accepted_capsule"]
        need(previous is None or previous in capsules, "OBSERVATION_HISTORY_MISSING")
        need(previous not in children, "OBSERVATION_HISTORY_FORK")
        children[previous] = digest
    basis, visited = selection_ref, set()
    current = children.get(None)
    while current is not None:
        need(current not in visited, "OBSERVATION_HISTORY_CYCLE")
        visited.add(current)
        capsule = capsules[current]
        if capsule["received_at"] is not None and stamp(capsule["received_at"]) <= cutoff_time:
            basis = raw_ref(encode(capsule))
        current = children.get(current)
    need(len(visited) == len(capsules), "OBSERVATION_HISTORY_DISCONNECTED")
    return basis


def check_projection(entries, capsules, read, namespace):
    """Bind stored receipt bytes and arrival assertions to the verified derivation."""
    expected = {}
    for digest, capsule in capsules.items():
        for index, item in enumerate(capsule["evaluation"]["projection"]):
            event = "projection-" + sha(encode([digest, index]))
            expected[event] = (digest, capsule, item)
    need(len(entries) == len(expected) and {e["entry_id"] for e in entries} == set(expected), "PROJECTION_ENTRIES")
    for entry in entries:
        digest, capsule, item = expected[entry["entry_id"]]
        need(entry["native_input_kind"] == "receipt_pair" and entry["source_namespace"] == namespace and
             set(entry["originals"]) == {"admission", "post"} and "detached_proofs" not in entry, "PROJECTION_KIND")
        for slot in ("admission", "post"):
            record = entry["originals"][slot]
            raw64 = item[slot + "_b64"]
            if raw64 is None:
                need(record is None, "PROJECTION_UNEXPECTED_POST")
            else:
                need(record is not None and read(record["ref"]) == unb64(raw64) and
                     record["received_at"] == capsule["received_at"] and
                     record["receipt_basis_ref"] == raw_ref(encode(capsule)) and
                     digest == sha(encode(capsule)), "PROJECTION_BINDING")
                # This connection derives cutoff membership only from arrival
                # time; it never accepts an independent membership assertion.
                need(record["received_at"] is not None or record["cutoff_membership"] == "unknown",
                     "PROJECTION_CUTOFF_MEMBERSHIP")


def compare_replay(old, new):
    """Compare frozen reports, normalizing only three measured runtime fields.

    Kept in this pinned reader instead of importing the scenario trial runner.
    The raw reports remain unchanged, including on a comparison failure.
    """
    a, b = deepcopy(old), deepcopy(new)
    differences = []
    for report in (a, b):
        need(type(report["usage"]["elapsed_milliseconds"]) is int and
             report["usage"]["elapsed_milliseconds"] >= 0, "REPLAY_REPORT_MISMATCH")
        measured_size = sum(len(encoded(call["result"])) for call in report["native_calls"])
        need(type(report["usage"]["native_result_bytes"]) is int and
             report["usage"]["native_result_bytes"] == measured_size, "REPLAY_REPORT_MISMATCH")
    differences.append({"path": "/usage/elapsed_milliseconds", "old": a["usage"].pop("elapsed_milliseconds"),
                        "new": b["usage"].pop("elapsed_milliseconds")})
    need(len(a["native_calls"]) == len(b["native_calls"]), "REPLAY_REPORT_MISMATCH")
    for index, (left, right) in enumerate(zip(a["native_calls"], b["native_calls"])):
        left_bundle = left["result"].get("inputs", {}).get("bundle")
        right_bundle = right["result"].get("inputs", {}).get("bundle")
        if isinstance(left_bundle, dict) and "selected_path" in left_bundle:
            need(isinstance(right_bundle, dict) and "selected_path" in right_bundle, "REPLAY_REPORT_MISMATCH")
            x, y = left_bundle["selected_path"], right_bundle["selected_path"]
            need(isinstance(x, str) and isinstance(y, str) and Path(x).is_absolute() and Path(y).is_absolute(),
                 "REPLAY_REPORT_MISMATCH")
            differences.append({"path": f"/native_calls/{index}/result/inputs/bundle/selected_path", "old": x, "new": y})
            left_bundle["selected_path"] = right_bundle["selected_path"] = "<native temporary snapshot>"
    differences.append({"path": "/usage/native_result_bytes", "old": a["usage"]["native_result_bytes"],
                        "new": b["usage"]["native_result_bytes"], "both_checked_against_retained_results": True})
    for report in (a, b):
        report["usage"]["native_result_bytes"] = sum(len(encoded(call["result"])) for call in report["native_calls"])
    need(encoded(a) == encoded(b), "REPLAY_REPORT_MISMATCH")
    return differences


class Receiver:
    def __init__(self, path, selected_raw, *, create=False):
        check_sample()
        self.path, self.selected_raw = Path(path), selected_raw
        self.s, self.context, self.operation = selection(selected_raw)
        self.box = Inbox(path, Engine(ROOT), create=create)
        try:
            self.box.v.stamp(self.s["selected_at"])
            for row in self.s["requirements"]:
                self.box.v.stamp(row["due_at"])
            with self.box.transaction():
                self.box.db.execute("INSERT OR IGNORE INTO meta VALUES (?,?)", (CONTRACT, sha(selected_raw)))
                found = self.box.db.execute("SELECT value FROM meta WHERE key=?", (CONTRACT,)).fetchone()[0]
                need(found == sha(selected_raw), "DATABASE_SELECTION_MISMATCH")
            self.selection_ref = self.box.put(selected_raw)
        except BaseException:
            self.box.close()
            raise

    def close(self):
        self.box.close()

    def check(self):
        check_sample()
        need(Path(__file__).read_bytes() == SOURCE_RAW, "BRIDGE_SOURCE_CHANGED")
        self.box.engine.check()

    @contextmanager
    def lock(self):
        fd = os.open(str(self.path) + ".handoff-lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            need(stat.S_ISREG(os.fstat(fd).st_mode), "LOCK_TYPE")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.check()
            yield
        finally:
            os.close(fd)

    def capsules(self):
        rows = self.box.db.execute("SELECT s.ref FROM slots s JOIN deliveries d ON s.event_id=d.event_id "
            "WHERE s.namespace=? AND s.role='originals' AND s.name='capsule' ORDER BY d.seq",
            (self.s["namespace"] + ":source",)).fetchall()
        values = [(json.loads(row[0]), decode(self.box.get(json.loads(row[0])))) for row in rows]
        for _, capsule in values:
            need(capsule["contract"] == CAPSULE and unb64(capsule["selection_b64"]) == self.selected_raw,
                 "STORED_SELECTION_MISMATCH")
            need(capsule["reader_sources"] == reader_sources(), "STORED_READER_VERSION")
        return values

    def _deliver(self, event, entry, kind, originals, basis, received, namespace):
        value = {"document_type": DELIVERY, "version": 1, "event_id": event, "entry_id": entry,
                 "source_namespace": namespace, "native_input_kind": kind, "received_at": received,
                 "receipt_basis_ref": basis, "originals": originals}
        return self.box.receive(encode(value))

    def _project(self, ref, capsule):
        if capsule["evaluation"]["status"] != "assessed":
            return
        for index, item in enumerate(capsule["evaluation"]["projection"]):
            event = "projection-" + sha(encode([ref["digest"]["value"], index]))
            originals = {"admission": self.box.put(unb64(item["admission_b64"]))}
            if item["post_b64"] is not None:
                originals["post"] = self.box.put(unb64(item["post_b64"]))
            self._deliver(event, event, "receipt_pair", originals, ref, capsule["received_at"], self.s["namespace"])

    def receive(self, event_id, bundle_raw, received_at):
        self.box.v.label(event_id)
        need(type(bundle_raw) is bytes and len(bundle_raw) <= MAX_BUNDLE, "BUNDLE_BOUND")
        if received_at is not None:
            self.box.v.stamp(received_at)
        with self.lock():
            previous = self.capsules()
            for ref, c in previous:
                # Safe crash recovery only replays local storage, never provider execution.
                self._project(ref, c)
                if c["event_id"] == event_id:
                    need(unb64(c["bundle_b64"]) == bundle_raw and c["received_at"] == received_at,
                         "EVENT_ID_CONFLICT")
                    return self._answer(ref, c, duplicate=True)
            need(len(previous) < MAX_INTAKES, "INTAKE_CAPACITY")
            prior = next(((ref, c) for ref, c in reversed(previous)
                          if c["evaluation"]["status"] == "assessed"), None)
            try:
                evaluation = evaluate(self.selected_raw, bundle_raw)
                if prior:
                    old = decode(unb64(prior[1]["bundle_b64"]))
                    new = decode(bundle_raw)
                    need(new["records"][:len(old["records"])] == old["records"] and
                         new["observed_at"] >= old["observed_at"], "HISTORY_NOT_EXTENSION")
                self.check()
            except (ValueError, KeyError, TypeError, IndexError, OverflowError, RecursionError) as exc:
                evaluation = {"status": "unassessable", "reason": getattr(exc, "code", "INVALID_HANDOFF_INPUT"),
                              "handoff": None, "projection": []}
            # OSError, busy, subprocess failures and source changes are not input verdicts.
            self.check()
            capsule = {"contract": CAPSULE, "event_id": event_id, "received_at": received_at,
                       "selection_b64": b64(self.selected_raw), "bundle_b64": b64(bundle_raw),
                       "reader_sources": reader_sources(),
                       "previous_accepted_capsule": prior[0]["digest"]["value"] if prior else None,
                       "evaluation": evaluation, "is_execution_ticket": False}
            raw = encode(capsule)
            need(len(raw) <= MAX_CAPSULE, "CAPSULE_BOUND")
            ref = self.box.put(raw)
            source_event = "source-" + sha(encode([sha(self.selected_raw), event_id]))
            self._deliver(source_event, source_event, "local_handoff_evidence", {"capsule": ref},
                          self.selection_ref, received_at, self.s["namespace"] + ":source")
            self._project(ref, capsule)
            return self._answer(ref, capsule, duplicate=False)

    @staticmethod
    def _answer(ref, c, *, duplicate):
        return {"contract": CONTRACT, "event_id": c["event_id"], "capsule_ref": ref,
                "duplicate": duplicate, "status": c["evaluation"]["status"], "reason": c["evaluation"]["reason"],
                "effect_state": (c["evaluation"]["handoff"]["effect_state"] if c["evaluation"]["handoff"] else None),
                "is_execution_ticket": False}

    def prepare(self, cutoff, assessed_at):
        with self.lock():
            accepted = {}
            for ref, c in self.capsules():
                self._project(ref, c)
                if c["evaluation"]["status"] == "assessed":
                    accepted[ref["digest"]["value"]] = c
            basis = observation_basis(accepted, self.selection_ref, cutoff, self.box.v.stamp)
            entries, _, _ = self.box._snapshot(self.s["namespace"])
            check_projection(entries, accepted, self.box.get, self.s["namespace"])
            review = {"document_type": "receiver_review_set_design", "design_revision": 2,
                      "namespace": self.s["namespace"], "review_set_id": "handoff-required-receipts", "revision": 1,
                      "collection_scope": "receiver_selected_set_only", "population_basis_refs": [self.selection_ref],
                      "requirements": requirements(self.s, self.operation, self.selection_ref)}
            plan = {"document_type": PLAN, "version": 1, "receiver_id": self.s["receiver_id"],
                    "review_set": review, "review_set_selected_at": self.s["selected_at"],
                    "assessment_cutoff": cutoff, "assessment_time": assessed_at, "inventory_state": "closed",
                    "collection_basis_ref": basis, "selection_basis_ref": self.selection_ref,
                    "revision_basis_ref": self.selection_ref, "native_policy_refs": {"s3": None, "signature": None}}
            return self.box.prepare(encode(plan))

    def run(self, run_id):
        with self.lock():
            self._selected_job(run_id)
            state = self.box.run(run_id)
            return self.report(state)

    def _selected_job(self, run_id):
        _, job = self.box._run(run_id)
        plan = decode(self.box.get(job["plan_ref"]))
        review = decode(self.box.get(job["review_set_ref"]))
        need(plan["selection_basis_ref"] == self.selection_ref and
             plan["receiver_id"] == self.s["receiver_id"] and plan["review_set_selected_at"] == self.s["selected_at"],
             "RUN_SELECTION_MISMATCH")
        need(review["requirements"] == requirements(self.s, self.operation, self.selection_ref) and
             review["namespace"] == self.s["namespace"] and review["review_set_id"] == "handoff-required-receipts" and
             review["population_basis_refs"] == [self.selection_ref] and
             review["collection_scope"] == "receiver_selected_set_only", "RUN_REQUIREMENTS_CHANGED")
        snapshot = decode(self.box.get(job["snapshot_ref"]))
        capsules = {}
        for entry in snapshot["entries"]:
            for record in entry["originals"].values():
                if record is None:
                    continue
                ref = record["receipt_basis_ref"]
                c = decode(self.box.get(ref))
                need(c.get("contract") == CAPSULE and c.get("reader_sources") == reader_sources() and
                     unb64(c["selection_b64"]) == self.selected_raw and c["evaluation"]["status"] == "assessed",
                     "RUN_CAPSULE_BINDING")
                capsules[ref["digest"]["value"]] = c
        check_projection(snapshot["entries"], capsules, self.box.get, self.s["namespace"])
        basis = observation_basis(capsules, self.selection_ref, plan["assessment_cutoff"], self.box.v.stamp)
        need(plan["collection_basis_ref"] == basis, "RUN_OBSERVATION_BASIS")
        return plan

    def report(self, state):
        # Read the frozen job's basis, not the current/latest delivery.
        plan = self._selected_job(state["run_id"])
        basis = decode(self.box.get(plan["collection_basis_ref"]))
        handoff = basis["evaluation"]["handoff"] if basis.get("contract") == CAPSULE else None
        report = decode(self.box.get(state["report_ref"])) if state["report_ref"] else None
        return {"contract": CONTRACT, "inbox": state, "handoff": handoff,
                "record_coverage": ({r["requirement_id"]: r["record_coverage"] for r in report["requirements"]}
                                    if report else None),
                "is_execution_ticket": False, "not_checked": ["current_permission_to_execute", "remote_provider_effects"]}

    def export(self, run_id, destination):
        with self.lock():
            self._selected_job(run_id)
            return self.box.export(run_id, destination)


def replay_export(selected_raw, folder):
    """Recheck frozen handoff evidence and the unchanged required-record selection."""
    check_sample()
    folder = Path(folder)
    s, _, operation = selection(selected_raw)
    need((folder / "objects").is_dir() and not (folder / "objects").is_symlink(), "EXPORT_OBJECT_DIRECTORY")
    manifest = decode(read_file(folder / "MANIFEST.json"))
    need(type(manifest) is dict and type(manifest.get("files")) is dict and
         len(manifest["files"]) <= 4096, "EXPORT_MANIFEST")
    for name, expected in manifest["files"].items():
        relative = Path(name)
        need(name in {"selection.json", "report.json", "runs.json"} or
             (len(relative.parts) == 2 and relative.parts[0] == "objects" and
              len(relative.parts[1]) == 64 and all(c in "0123456789abcdef" for c in relative.parts[1])), "EXPORT_PATH")
        raw = read_file(folder / relative)
        need(sha(raw) == expected["raw_sha256"] and len(raw) == expected["byte_length"], "EXPORT_HASH")
    frozen = decode(read_file(folder / "selection.json"))
    def read(ref):
        need(type(ref) is dict and ref.get("path") == "objects/" + ref.get("digest", {}).get("value", "") and
             ref["path"] in manifest["files"], "EXPORT_REFERENCE")
        raw = read_file(folder / ref["path"])
        need(ref == raw_ref(raw, ref.get("media_type")), "EXPORT_REFERENCE_HASH")
        return raw
    basis = frozen["selection_basis_ref"]
    need(read(basis) == selected_raw and frozen["receiver_id"] == s["receiver_id"] and
         frozen["review_set_selected_at"] == s["selected_at"], "EXPORT_RECEIVER_SELECTION")
    review = decode(read(frozen["review_set_ref"]))
    need(review["requirements"] == requirements(s, operation, raw_ref(selected_raw)) and
         review["namespace"] == s["namespace"] and review["review_set_id"] == "handoff-required-receipts" and
         review["population_basis_refs"] == [raw_ref(selected_raw)] and
         review["collection_scope"] == "receiver_selected_set_only", "EXPORT_REQUIREMENTS_CHANGED")
    capsules = {}
    for name in manifest["files"]:
        if not name.startswith("objects/"):
            continue
        path = folder / name
        raw = read_file(path)
        need(path.name == sha(raw), "EXPORT_OBJECT_HASH")
        try:
            value = decode(raw)
        except (ValueError, TypeError):
            continue
        if type(value) is dict and value.get("contract") == CAPSULE:
            verify_capsule(selected_raw, raw)
            capsules[sha(raw)] = value
    for c in capsules.values():
        predecessor = c["previous_accepted_capsule"]
        if predecessor is not None:
            need(predecessor in capsules, "EXPORT_HISTORY_MISSING")
            old = decode(unb64(capsules[predecessor]["bundle_b64"]))
            new = decode(unb64(c["bundle_b64"]))
            need(new["records"][:len(old["records"])] == old["records"] and
                 new["observed_at"] >= old["observed_at"], "EXPORT_HISTORY_FORK")
    snapshot = decode(read(frozen["submission_snapshot_ref"]))
    check_projection(snapshot["entries"], capsules, read, s["namespace"])
    basis = observation_basis(capsules, raw_ref(selected_raw), frozen["assessment_cutoff"],
                              Engine(ROOT).validation.stamp)
    need(snapshot["collection_basis_ref"] == basis, "EXPORT_OBSERVATION_BASIS")
    with tempfile.TemporaryDirectory(prefix="vate-handoff-inbox-replay-") as directory:
        output = Path(directory) / "report.json"
        run = subprocess.run([sys.executable, "-E", "-s", "-B",
            str(ROOT / "reference/required-records/required_records.py"),
            "--selection", str(folder / "selection.json"), "--base", "inbox=" + str(folder),
            "--source-root", str(ROOT), "--output", str(output)], capture_output=True, timeout=120)
        need(run.returncode == 0 and output.is_file(), "REPLAY_FAILED")
        compare_replay(decode(read_file(folder / "report.json")), decode(read_file(output)))
    return {"capsules_reassessed": len(capsules), "required_records_replayed": True,
            "is_execution_ticket": False}
