"""Import a selected local receipt package into Recipient Inbox and assess its records."""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

MIB = 1024 * 1024
MAX_FILES, MAX_DELIVERIES, MAX_TOTAL = 64, 32, 8 * MIB


class ClockError(ValueError):
    """A run-wide invalid clock must never be reduced to one member's error."""


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value, *, raw=False):
    with path.open("xb") as stream:
        stream.write(value if raw else encoded(value))
        stream.flush()
        os.fsync(stream.fileno())


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def exact(value, keys):
    need(type(value) is dict and set(value) == set(keys), "unexpected input fields")


def label(value):
    need(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,95}", value), "invalid label")


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def decode(raw):
    def bad_constant(value):
        raise ValueError("nonfinite JSON value")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad_constant)


def signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_regular(path, *, directory=None, maximum=MIB):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, "not a bounded regular file or byte budget exhausted")
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(maximum + 1)
        need(len(raw) <= maximum and signature(before) == signature(os.fstat(fd)), "file changed while reading")
        return raw
    finally:
        os.close(fd)


def validate(inventory, manifest, inventory_raw):
    need(type(inventory) is dict, "inventory must be an object")
    label(inventory.get("namespace"))
    jobs = inventory.get("jobs")
    need(type(jobs) is list and 0 < len(jobs) <= 64, "invalid receiver job set")
    names = set()
    for job in jobs:
        need(type(job) is dict, "invalid receiver job")
        label(job.get("job_label")); label(job.get("operation_id"))
        need(job["job_label"] not in names, "duplicate receiver job label")
        names.add(job["job_label"])
        need(job.get("expected_record_kind") == "post_execution" and type(job.get("expected_context")) is dict,
             "this example requires operation post records")
    exact(manifest, ("kind", "version", "namespace", "inventory_sha256", "files", "deliveries"))
    need(manifest["kind"] == "local_selected_receipt_package" and type(manifest["version"]) is int
         and manifest["version"] == 1, "unknown local package format")
    need(manifest["namespace"] == inventory["namespace"] and manifest["inventory_sha256"] == sha(inventory_raw),
         "package and receiver selection differ")
    files, deliveries = manifest["files"], manifest["deliveries"]
    need(type(files) is list and len(files) <= MAX_FILES, "file count limit")
    need(type(deliveries) is list and len(deliveries) <= MAX_DELIVERIES, "delivery count limit")
    by_name = {}
    for entry in files:
        exact(entry, ("path", "bytes", "sha256"))
        name = entry["path"]
        need(type(name) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name), "unsafe file name")
        need(name not in by_name, "duplicate file path")
        need(type(entry["bytes"]) is int and 0 <= entry["bytes"] <= MIB, "file size limit")
        need(type(entry["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]), "invalid digest")
        by_name[name] = entry
    need(sum(f["bytes"] for f in files) <= MAX_TOTAL, "package size limit")
    used, entry_ids = [], set()
    for delivery in deliveries:
        exact(delivery, ("entry_id", "originals")); label(delivery["entry_id"])
        need(delivery["entry_id"] not in entry_ids, "duplicate entry id")
        entry_ids.add(delivery["entry_id"])
        originals = delivery["originals"]
        need(type(originals) is dict and 0 < len(originals) <= 2 and set(originals) <= {"admission", "post"},
             "unsupported or empty delivery")
        for name in originals.values():
            need(type(name) is str and name in by_name, "unlisted original")
            used.append(name)
    need(len(used) == len(set(used)) and set(used) == set(by_name), "every file must have exactly one slot")


class Clock:
    def __init__(self):
        self.last = None

    def now(self):
        value = datetime.now(timezone.utc)
        if self.last is not None and value < self.last:
            raise ClockError("local clock moved backwards; start a fresh run")
        self.last = value
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


class Journal:
    def __init__(self, output, clock):
        self.output, self.clock, self.events = output, clock, []

    def add(self, phase, **data):
        event = {"seq": len(self.events) + 1, "at": self.clock.now(), "phase": phase, **data}
        self.events.append(event)
        with (self.output / "EVENTS.jsonl").open("ab") as stream:
            stream.write(json.dumps(event, sort_keys=True, allow_nan=False).encode() + b"\n")
            stream.flush(); os.fsync(stream.fileno())


def scan(fd):
    names = set()
    with os.scandir(fd) as entries:
        for entry in entries:
            names.add(entry.name)
            need(len(names) <= MAX_FILES, "directory count limit")
    return names


def collect(package, manifest, box, output, journal, refs):
    """State is derived only here, from the actual selected read/registration attempt."""
    errors, originals, registered = [], {}, []
    acquired_bytes = 0
    opened, fd = False, None
    expected = {f["path"]: f for f in manifest["files"]}

    def issue(phase, exc, **data):
        item = {"stage": phase, "error_type": type(exc).__name__,
                "code": getattr(exc, "code", None), "detail": str(exc)[:512], **data}
        errors.append(item); journal.add("issue", **item)

    try:
        try:
            fd = os.open(package, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            root_stat = os.fstat(fd)
            names = scan(fd)
            opened = True
            journal.add("enumerated", names=sorted(names))
            if names != set(expected):
                issue("membership", ValueError("directory differs from selected membership"),
                      missing=sorted(set(expected) - names), extra=sorted(names - set(expected)))
        except ClockError:
            raise
        except OSError as exc:
            issue("open_or_enumerate", exc)
        except ValueError as exc:
            issue("enumerate", exc)
        if opened:
            for name, expected_file in expected.items():
                try:
                    raw = read_regular(name, directory=fd, maximum=min(MIB, MAX_TOTAL - acquired_bytes))
                    acquired_bytes += len(raw)
                    save(output / "observed" / name, raw, raw=True)
                    journal.add("read", path=name, bytes=len(raw), sha256=sha(raw))
                    ref = box.put(raw, "application/json")
                    need(box.get(ref) == raw, "Inbox stored bytes differ")
                    journal.add("stored", path=name, ref=ref)
                    need(len(raw) == expected_file["bytes"] and sha(raw) == expected_file["sha256"],
                         "raw identity differs from selected member")
                    originals[name] = ref
                except ClockError:
                    raise
                except Exception as exc:
                    issue("read_store_identity", exc, path=name)
            for index, item in enumerate(manifest["deliveries"]):
                available = {slot: originals[name] for slot, name in item["originals"].items() if name in originals}
                if not available:
                    journal.add("registration_skipped", entry_id=item["entry_id"], reason="no acquired member")
                    continue
                try:
                    at = journal.clock.now()
                    basis = {"kind": "local_package_arrival", "at": at, "entry_id": item["entry_id"],
                             "clock_meaning": "this application's import time, not provider execution or external arrival",
                             "selection_refs": refs, "originals": available}
                    basis_ref = box.put(encoded(basis))
                    delivery = {"document_type": "recipient_inbox_delivery", "version": 1,
                                "event_id": "package-" + str(index), "entry_id": item["entry_id"],
                                "source_namespace": manifest["namespace"], "native_input_kind": "receipt_pair",
                                "received_at": at, "receipt_basis_ref": basis_ref, "originals": available}
                    save(output / "submitted" / ("delivery-" + str(index) + ".json"), delivery)
                    response = box.receive(encoded(delivery))
                    journal.add("registered", entry_id=item["entry_id"], response=response, received_at=at)
                    registered.append(item["entry_id"])
                except ClockError:
                    raise
                except Exception as exc:
                    issue("register", exc, entry_id=item["entry_id"])
            try:
                need(scan(fd) == set(expected), "directory membership changed or differs")
                current = os.stat(package, follow_symlinks=False)
                need((root_stat.st_dev, root_stat.st_ino) == (current.st_dev, current.st_ino)
                     and stat.S_ISDIR(current.st_mode), "package root changed")
                for name, expected_file in expected.items():
                    raw = read_regular(name, directory=fd)
                    need(len(raw) == expected_file["bytes"] and sha(raw) == expected_file["sha256"],
                         "member changed or differs at final check")
                journal.add("rechecked", files=len(expected))
            except ClockError:
                raise
            except Exception as exc:
                issue("final_check", exc)
    finally:
        if fd is not None:
            os.close(fd)
    state = "unavailable" if not opened else "partial" if errors else "closed"
    need(state != "closed" or len(registered) == len(manifest["deliveries"]), "unregistered selected delivery")
    finished = journal.clock.now()
    return {"kind": "local_selected_package_collection", "inventory_state": state,
            "scope": "only this selected finite package; no claim about all external arrivals or execution",
            "namespace": manifest["namespace"], "selection_refs": refs,
            "started_at": journal.events[0]["at"], "finished_at": finished, "assessment_cutoff": finished,
            "errors": errors, "acquired_bytes": acquired_bytes, "registered_entries": registered, "events": journal.events}


def review_set(inventory, refs, due_at):
    # Requirements come from the receiver inventory, independently of the received subset.
    return {"document_type": "receiver_review_set_design", "design_revision": 2,
            "review_set_id": inventory["namespace"] + ":required-posts", "revision": 1,
            "namespace": inventory["namespace"], "population_basis_refs": [refs["inventory"]],
            "collection_scope": "receiver_selected_set_only", "requirements": [
                {"requirement_id": job["job_label"] + "-post", "subject": {"kind": "operation",
                  "operation_id": job["operation_id"], "native_context": copy.deepcopy(job["expected_context"])},
                 "record_kind": "post_execution", "binding_profile": "vate_receipt_operation_context",
                 "obligation": "required", "basis_refs": [refs["inventory"], refs["policy"]],
                 "requested_native_checks": ["receipt_linkage"], "due_at": due_at} for job in inventory["jobs"]]}


def execute(source, inventory_path, manifest_path, package, output, due_at, Engine, Inbox):
    output.mkdir(parents=True, exist_ok=False)
    for name in ("observed", "submitted"):
        (output / name).mkdir()
    clock = Clock(); journal = Journal(output, clock); box = None
    save(output / "STARTED.json", {"run_id": str(uuid.uuid4()), "state": "in_progress", "at": clock.now()})
    try:
        journal.add("started")
        inv_raw, manifest_raw = read_regular(inventory_path), read_regular(manifest_path)
        save(output / "inventory.json", inv_raw, raw=True); save(output / "membership.json", manifest_raw, raw=True)
        inventory, manifest = decode(inv_raw), decode(manifest_raw)
        validate(inventory, manifest, inv_raw)
        engine = Engine(source)
        box = Inbox(output / "inbox.sqlite3", engine, create=True)
        refs = {"inventory": box.put(inv_raw), "membership": box.put(manifest_raw),
                "policy": box.put(encoded({"due_at": due_at, "arrival_clock": "local import", "scope": "selected package"}))}
        review = review_set(inventory, refs, due_at)
        engine.validation.review_shape(review)
        collection = collect(package, manifest, box, output, journal, refs)
        save(output / "COLLECTION.json", collection)
        basis = box.put(encoded(collection))
        plan = {"document_type": "recipient_inbox_plan", "version": 1, "receiver_id": "local-package-receiver",
                "review_set": review, "review_set_selected_at": collection["started_at"],
                "assessment_cutoff": collection["assessment_cutoff"], "assessment_time": collection["finished_at"],
                "inventory_state": collection["inventory_state"], "collection_basis_ref": basis,
                "selection_basis_ref": refs["membership"], "revision_basis_ref": refs["policy"],
                "native_policy_refs": {"s3": None, "signature": None}}
        save(output / "submitted/plan.json", plan)
        prepared = box.prepare(encoded(plan)); save(output / "PREPARED.json", prepared)
        result = box.run(prepared["run_id"]); save(output / "RUN.json", result)
        status = box.status(prepared["run_id"]); save(output / "STATUS.json", status)
        need(status["status"] == "completed" and status["report_ref"] is not None, "assessment handling did not complete")
        raw = box.get(status["report_ref"]); save(output / "report.json", raw, raw=True)
        export = box.export(prepared["run_id"], output / "export"); save(output / "EXPORT.json", export)
        need((output / "export/report.json").read_bytes() == raw, "exported report differs")
        report = decode(raw)
        summary = {"handling_status": status["status"], "inventory_state": collection["inventory_state"],
                   "collection_errors": len(collection["errors"]), "report_path": "report.json",
                   "requirements": [{"id": row["requirement_id"], "coverage": row["record_coverage"],
                                     "timeliness": row["timeliness"]} for row in report["requirements"]],
                   "meaning": "handling, collection, record coverage and native results are separate; no retry permission"}
        save(output / "SUMMARY.json", summary)
        return summary
    except BaseException as exc:
        save(output / "FAILURE.json", {"state": "failed_or_interrupted", "error_type": type(exc).__name__,
                                      "code": getattr(exc, "code", None), "detail": str(exc)[:512]})
        raise
    finally:
        if box is not None:
            box.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source-root", "inventory", "membership", "package", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--due-at", required=True)
    args = parser.parse_args()
    try:
        source = args.source_root.resolve(strict=True)
        module_dir = source / "reference/recipient-inbox"
        if not (module_dir / "recipient_inbox.py").is_file():
            raise ModuleNotFoundError("selected source has no Recipient Inbox module")
        sys.path.insert(0, str(module_dir))
        from recipient_inbox import Engine, Inbox
        summary = execute(source, args.inventory, args.membership, args.package, args.output, args.due_at, Engine, Inbox)
        print(json.dumps(summary, sort_keys=True))
        return 0 if summary["inventory_state"] == "closed" else 2
    except Exception as exc:
        print(json.dumps({"handling_status": "failed", "error_type": type(exc).__name__, "detail": str(exc)[:512]}))
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
