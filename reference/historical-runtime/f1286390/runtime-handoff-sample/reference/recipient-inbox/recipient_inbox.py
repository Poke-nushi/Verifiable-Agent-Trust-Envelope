"""Local durable intake for the existing required-record reviewer; no execution gate."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import types
import uuid

CONTRACT = "vate-recipient-inbox-local-v1"
PLAN = "recipient_inbox_plan"
DELIVERY = "recipient_inbox_delivery"
BASE = "inbox"
MIB = 1024 * 1024
MAX_OBJECT = 128 * MIB
SNAPSHOT_HEADER_RESERVE = 4096
READ_METADATA_RESERVE = 4 * MIB
PROCESS_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
REF_FIELDS = {"path_base", "path", "media_type", "digest_basis", "digest", "byte_length"}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def metadata_bytes(value, name):
    raw = encoded(value)
    require(len(raw) <= MIB, "METADATA_BOUND", name + " exceeds the evaluator's 1 MiB input bound")
    return raw


class InboxError(ValueError):
    def __init__(self, code, detail):
        self.code = code
        super().__init__(detail)


def require(condition, code, detail):
    if not condition:
        raise InboxError(code, detail)


def read_file(path, maximum=MAX_OBJECT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "FILE_TYPE", "expected a regular file")
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(maximum + 1)
        require(len(raw) <= maximum, "SIZE_LIMIT", "file exceeds byte bound")
        return raw
    finally:
        os.close(fd)


def raw_ref(raw, media_type="application/json"):
    digest = sha(raw)
    return {"path_base": BASE, "path": "objects/" + digest, "media_type": media_type,
            "digest_basis": "raw_file_sha256", "digest": {"alg": "sha-256", "value": digest},
            "byte_length": len(raw)}


try:
    _SELF_RAW = read_file(__file__)
    _SELF_VALID = compile(_SELF_RAW, __file__, "exec", dont_inherit=True,
                          optimize=sys.flags.optimize) == sys._getframe().f_code
except (OSError, ValueError, SyntaxError):
    _SELF_RAW, _SELF_VALID = b"", False


class Engine:
    """Trusted source/runtime selection, separate from submitted records."""

    def __init__(self, source_root, openssl=None, openssl_sha256=None):
        self.root = Path(source_root).resolve(strict=True)
        self.openssl = str(Path(openssl).resolve(strict=True)) if openssl else None
        self.openssl_sha256 = openssl_sha256
        require(bool(self.openssl) == bool(openssl_sha256), "CONFIGURATION",
                "OpenSSL path and expected digest must be selected together")
        self.identity = self.current_identity()
        path = self.root / "reference/required-records/required_records.py"
        raw = read_file(path, MIB)
        require(sha(raw) == self.identity["sources"]["reference/required-records/required_records.py"],
                "SOURCE_CHANGED", "reviewer changed while loading its input validators")
        self.validation = types.ModuleType("_inbox_required_record_contract")
        self.validation.__file__ = str(path)
        exec(compile(raw, str(path), "exec", dont_inherit=True), self.validation.__dict__)

    def current_identity(self):
        require(_SELF_VALID and read_file(__file__) == _SELF_RAW, "SOURCE_CHANGED",
                "restart after changing the inbox implementation")
        manifest_name = "reference/required-records/NATIVE-SOURCES.json"
        manifest_raw = read_file(self.root / manifest_name, MIB)
        manifest = json.loads(manifest_raw)
        require(type(manifest) is dict, "SOURCE_MANIFEST", "source manifest must be an object")
        names = set(manifest) | {manifest_name, "reference/required-records/required_records.py",
                                 "reference/required-records/native_bridge.py"}
        sources = {}
        for name in sorted(names):
            require(type(name) is str and not name.startswith("/")
                    and all(p not in ("", ".", "..") for p in name.split("/"))
                    and "\\" not in name, "SOURCE_PATH", "unsafe source manifest path")
            sources[name] = sha(read_file(self.root / name, 8 * MIB))
        require(sources[manifest_name] == sha(manifest_raw), "SOURCE_CHANGED", "source manifest changed")
        if self.openssl:
            require(sha(read_file(self.openssl)) == self.openssl_sha256, "OPENSSL_CHANGED",
                    "selected OpenSSL does not match its expected digest")
        # Native workers use isolated Python. Record that environment, rather than
        # caller-only sys.path/PYTHONPATH overlays that the worker cannot see.
        interpreter = Path(sys.executable).resolve(strict=True)
        interpreter_sha256 = sha(read_file(interpreter))
        try:
            runtime = subprocess.run([sys.executable, "-I", "-B", "-c",
                "import importlib.metadata,json,sys; print(json.dumps({'python':sys.version,"
                "'interpreter':sys.executable,'jsonschema_version':importlib.metadata.version('jsonschema')}))"],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=20, env=PROCESS_ENV, check=True)
            runtime_identity = json.loads(runtime.stdout)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise InboxError("RUNTIME_UNAVAILABLE", "cannot identify the isolated evaluator runtime") from exc
        require(Path(sys.executable).resolve(strict=True) == interpreter and
                sha(read_file(interpreter)) == interpreter_sha256,
                "PYTHON_CHANGED", "selected Python changed while identifying the runtime")
        return {"inbox_source_sha256": sha(_SELF_RAW), "sources": sources,
                **runtime_identity,
                "interpreter_realpath": str(interpreter), "interpreter_sha256": interpreter_sha256,
                "openssl": self.openssl, "openssl_sha256": self.openssl_sha256}

    def check(self):
        require(self.current_identity() == self.identity, "SOURCE_CHANGED",
                "source/runtime selection changed; create a fresh Engine")


SCHEMA = (
    "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE objects (digest TEXT PRIMARY KEY, raw BLOB NOT NULL)",
    "CREATE TABLE entries (namespace TEXT NOT NULL, entry_id TEXT NOT NULL, kind TEXT NOT NULL, "
    "PRIMARY KEY(namespace,entry_id))",
    "CREATE TABLE deliveries (seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL, "
    "raw_ref TEXT NOT NULL)",
    "CREATE TABLE slots (namespace TEXT NOT NULL, entry_id TEXT NOT NULL, role TEXT NOT NULL, "
    "name TEXT NOT NULL, event_id TEXT NOT NULL REFERENCES deliveries(event_id), "
    "ref TEXT NOT NULL, received_at TEXT, basis TEXT NOT NULL, "
    "PRIMARY KEY(namespace,entry_id,role,name), "
    "FOREIGN KEY(namespace,entry_id) REFERENCES entries(namespace,entry_id))",
    "CREATE TABLE runs (run_id TEXT PRIMARY KEY, stream_id TEXT NOT NULL, previous_id TEXT, "
    "status TEXT NOT NULL, job_ref TEXT NOT NULL, result_ref TEXT)",
    "CREATE TABLE heads (stream_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id))",
)


class Inbox:
    """One trusted local receiver. Each public mutation is a SQLite transaction."""

    def __init__(self, path, engine, *, create=False):
        self.path = Path(path)
        self.engine, self.v = engine, engine.validation
        if create:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        require(self.path.is_file() and not self.path.is_symlink(), "DATABASE_PATH",
                "database must be an existing regular file, or explicitly initialized")
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA synchronous=FULL")
        try:
            if create:
                with self.transaction():
                    for statement in SCHEMA:
                        self.db.execute(statement)
                    self.db.execute("INSERT INTO meta VALUES ('contract',?)", (CONTRACT,))
            found = self.db.execute("SELECT value FROM meta WHERE key='contract'").fetchone()
            require(found and found[0] == CONTRACT, "DATABASE_CONTRACT", "unknown database contract")
        except Exception:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def _put(self, raw, media_type="application/json"):
        require(type(raw) is bytes and len(raw) <= MAX_OBJECT, "OBJECT_BOUND", "expected bounded raw bytes")
        self.v.label(media_type)
        ref = raw_ref(raw, media_type)
        self.db.execute("INSERT OR IGNORE INTO objects VALUES (?,?)", (sha(raw), raw))
        require(self.get(ref) == raw, "OBJECT_CORRUPT", "stored bytes differ")
        return ref

    def put(self, raw, media_type="application/json"):
        with self.transaction():
            return self._put(raw, media_type)

    def get(self, ref):
        self.v.ref_shape(ref, MAX_OBJECT)
        digest = ref["digest"]["value"]
        require(ref["path_base"] == BASE and ref["path"] == "objects/" + digest,
                "FOREIGN_REF", "reference must name this inbox's content-addressed object")
        row = self.db.execute("SELECT raw FROM objects WHERE digest=?", (digest,)).fetchone()
        require(row is not None, "OBJECT_UNAVAILABLE", "referenced object is absent")
        raw = bytes(row[0])
        require(sha(raw) == digest and len(raw) == ref["byte_length"], "OBJECT_CORRUPT",
                "stored object does not match its raw-byte identity")
        return raw

    def _refs(self, value):
        refs = []
        if type(value) is dict:
            if set(value) == REF_FIELDS:
                self.get(value)
                refs.append(value)
            else:
                for item in value.values():
                    refs.extend(self._refs(item))
        elif type(value) is list:
            for item in value:
                refs.extend(self._refs(item))
        return refs

    def _json(self, ref):
        return self.v.decode(self.get(ref), 64)

    def receive(self, delivery_raw):
        require(type(delivery_raw) is bytes and len(delivery_raw) <= MIB, "DELIVERY_BOUND", "delivery exceeds bound")
        item = self.v.decode(delivery_raw)
        self.v.exact(item, ("document_type", "version", "event_id", "entry_id", "source_namespace",
                           "native_input_kind", "received_at", "receipt_basis_ref", "originals"),
                     ("detached_proofs",))
        require(item["document_type"] == DELIVERY and type(item["version"]) is int and item["version"] == 1,
                "DELIVERY_CONTRACT", "unknown delivery contract")
        for key in ("event_id", "entry_id", "source_namespace", "native_input_kind"):
            self.v.label(item[key])
        if item["received_at"] is not None:
            self.v.stamp(item["received_at"])
        kind = item["native_input_kind"]
        allowed = {"receipt_pair": {"admission", "post"}, "s3_bundle": self.v.MEMBERS}.get(kind)
        parts = []
        for role in ("originals", "detached_proofs"):
            values = item.get(role, {})
            require(type(values) is dict and len(values) <= (18 if role == "originals" else 2),
                    "DELIVERY_SHAPE", "invalid slot map")
            for name, ref in values.items():
                self.v.label(name)
                permitted = allowed if role == "originals" else {"admission", "post"}
                require(permitted is None or name in permitted, "DELIVERY_SLOT", "unsupported slot name")
                self.v.ref_shape(ref, 4096 if role == "detached_proofs" else 256 * 1024 if kind == "s3_bundle" else MIB)
                parts.append((role, name, ref))
        require(parts, "EMPTY_DELIVERY", "delivery must contain an acquired original or proof")
        self.v.ref_shape(item["receipt_basis_ref"])
        namespace, entry_id = item["source_namespace"], item["entry_id"]
        with self.transaction():
            self._refs(item)
            prior = self.db.execute("SELECT seq,raw_ref FROM deliveries WHERE event_id=?", (item["event_id"],)).fetchone()
            if prior:
                require(self.get(json.loads(prior["raw_ref"])) == delivery_raw, "EVENT_ID_CONFLICT",
                        "event ID already identifies different raw delivery metadata")
                return {"event_id": item["event_id"], "sequence": prior["seq"], "duplicate": True}
            entry = self.db.execute("SELECT kind FROM entries WHERE namespace=? AND entry_id=?", (namespace, entry_id)).fetchone()
            require(not entry or entry[0] == kind, "ENTRY_KIND_CONFLICT", "entry input kind cannot change")
            self.db.execute("INSERT OR IGNORE INTO entries VALUES (?,?,?)", (namespace, entry_id, kind))
            ref = self._put(delivery_raw)
            seq = self.db.execute("INSERT INTO deliveries(event_id,raw_ref) VALUES (?,?)",
                                  (item["event_id"], encoded(ref).decode())).lastrowid
            for role, name, original_ref in parts:
                exists = self.db.execute("SELECT 1 FROM slots WHERE namespace=? AND entry_id=? AND role=? AND name=?",
                                         (namespace, entry_id, role, name)).fetchone()
                require(not exists, "SLOT_ALREADY_RECEIVED", "use a distinct entry for another receipt event; never replace a slot")
                self.db.execute("INSERT INTO slots VALUES (?,?,?,?,?,?,?,?)",
                                (namespace, entry_id, role, name, item["event_id"], encoded(original_ref).decode(),
                                 item["received_at"], encoded(item["receipt_basis_ref"]).decode()))
            # Check cumulative capacity before committing the delivery. Reserve
            # space for the bounded snapshot header; never omit received entries.
            entries, _, _ = self._snapshot(namespace)
            self._check_capacity(entries)
            return {"event_id": item["event_id"], "sequence": seq, "duplicate": False}

    def _check_capacity(self, entries):
        require(len(entries) <= 256, "ENTRY_LIMIT", "namespace exceeds the existing snapshot limit")
        require(all(len(entry["originals"]) <= 18 for entry in entries),
                "SLOT_LIMIT", "entry exceeds the cumulative 18-original limit")
        require(len(encoded(entries)) <= MIB - SNAPSHOT_HEADER_RESERVE, "SNAPSHOT_CAPACITY",
                "namespace exceeds the snapshot metadata capacity")
        # Current evaluator contract: signature then receipt fallback, plus S3.
        # Do not depend on equal-byte caching, the policy, or a future cutoff.
        calls = sum({"receipt_pair": 2, "s3_bundle": 3}.get(entry["native_input_kind"], 0)
                    for entry in entries)
        require(calls <= self.v.DEFAULT_LIMITS["native_calls"], "NATIVE_CAPACITY",
                "namespace exceeds the conservative native-call capacity")
        self._check_read_capacity(self._refs(entries),
                                  self.v.DEFAULT_LIMITS["bytes"] - READ_METADATA_RESERVE)

    def _check_read_capacity(self, refs, maximum):
        # Reader caches the entire reference, including media_type, not digest alone.
        unique = {encoded(ref): ref for ref in refs}
        require(sum(ref["byte_length"] for ref in unique.values()) <= maximum,
                "READ_CAPACITY", "selected originals and metadata exceed the input byte budget")

    def _snapshot(self, namespace, cutoff=None, assessed=None):
        # Without times, measure capacity using the longest possible membership
        # string. This form is never used as an assessment input.
        capacity = cutoff is None and assessed is None
        entries, delivery_refs = {}, {}
        maximum_seq = 0
        for row in self.db.execute("SELECT s.*,e.kind,d.seq,d.raw_ref FROM slots s "
                                   "JOIN entries e USING(namespace,entry_id) JOIN deliveries d USING(event_id) "
                                   "WHERE namespace=? ORDER BY d.seq,s.role,s.name", (namespace,)):
            maximum_seq = max(maximum_seq, row["seq"])
            delivery_refs[row["event_id"]] = json.loads(row["raw_ref"])
            if row["entry_id"] not in entries:
                names = {"receipt_pair": {"admission", "post"}, "s3_bundle": self.v.MEMBERS}.get(row["kind"], ())
                entries[row["entry_id"]] = {"entry_id": row["entry_id"], "source_namespace": namespace,
                    "native_input_kind": row["kind"], "originals": {name: None for name in sorted(names)}}
            entry = entries[row["entry_id"]]
            if row["role"] == "detached_proofs":
                entry.setdefault("detached_proofs", {"admission": None, "post": None})
            received = self.v.stamp(row["received_at"]) if row["received_at"] else None
            require(capacity or received is None or received <= assessed, "RECEIPT_TIME_IN_FUTURE",
                    "assessment time precedes a stored receiver arrival assertion")
            entry[row["role"]][row["name"]] = {"ref": json.loads(row["ref"]), "received_at": row["received_at"],
                "cutoff_membership": "unknown" if received is None else "included" if capacity or received <= cutoff else "after",
                "receipt_basis_ref": json.loads(row["basis"])}
        return list(entries.values()), maximum_seq, list(delivery_refs.values())

    def _head(self, stream):
        row = self.db.execute("SELECT run_id FROM heads WHERE stream_id=?", (stream,)).fetchone()
        return row[0] if row else None

    def _run(self, run_id):
        row = self.db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        require(row is not None, "RUN_UNAVAILABLE", "unknown prepared run")
        return row, self._json(json.loads(row["job_ref"]))

    def prepare(self, plan_raw):
        self.engine.check()
        require(type(plan_raw) is bytes and len(plan_raw) <= MIB, "PLAN_BOUND", "plan exceeds bound")
        plan = self.v.decode(plan_raw)
        self.v.exact(plan, ("document_type", "version", "receiver_id", "review_set", "review_set_selected_at",
                           "assessment_cutoff", "assessment_time", "inventory_state", "collection_basis_ref",
                           "selection_basis_ref", "native_policy_refs", "revision_basis_ref"))
        require(plan["document_type"] == PLAN and type(plan["version"]) is int and plan["version"] == 1,
                "PLAN_CONTRACT", "unknown plan contract")
        self.v.label(plan["receiver_id"])
        self.v.review_shape(plan["review_set"])
        require(plan["review_set"]["revision"] == 1, "PLAN_REVISION", "supply a revision-1 template; history is linked by the inbox")
        cutoff, assessed = self.v.stamp(plan["assessment_cutoff"]), self.v.stamp(plan["assessment_time"])
        require(cutoff <= assessed and self.v.stamp(plan["review_set_selected_at"]) <= assessed,
                "PLAN_TIME", "selection time order is invalid")
        require(plan["inventory_state"] in ("closed", "partial", "unavailable"), "PLAN_INVENTORY", "choose the inventory state explicitly")
        self.v.exact(plan["native_policy_refs"], ("s3", "signature"))
        for ref in (plan["collection_basis_ref"], plan["selection_basis_ref"], plan["revision_basis_ref"],
                    *plan["native_policy_refs"].values()):
            if ref is not None:
                self.v.ref_shape(ref)
        require(plan["collection_basis_ref"] is not None and plan["selection_basis_ref"] is not None,
                "PLAN_BASIS", "collection and selection basis are required")
        review = plan["review_set"].copy()
        stream = sha(encoded([plan["receiver_id"], review["namespace"], review["review_set_id"]]))
        run_id = str(uuid.uuid4())
        with self.transaction():
            assets = self._refs(plan)
            previous_id = self._head(stream)
            if previous_id:
                prior_row, prior = self._run(previous_id)
                result = self._json(json.loads(prior_row["result_ref"]))
                require(plan["revision_basis_ref"] is not None, "REVISION_BASIS", "revision requires a receiver-selected basis")
                review.update(revision=prior["revision"] + 1, previous_review_set_ref=prior["review_set_ref"],
                              previous_report_ref=result["report_ref"], revision_basis_ref=plan["revision_basis_ref"])
                # Reuse the existing one-step revision validator, not a second semantic implementation.
                class LocalReader:
                    def read(_, ref, *args, **kwargs):
                        return self.get(ref)
                self.v.Reviewer._prior(review, {}, LocalReader(), cutoff)
                assets.extend(self._refs({k: review[k] for k in ("previous_review_set_ref", "previous_report_ref")}))
            entries, sequence, deliveries = self._snapshot(review["namespace"], cutoff, assessed)
            self._check_capacity(entries)
            snapshot = {"document_type": "submission_snapshot_design", "design_revision": 2,
                        "snapshot_id": run_id, "as_of": plan["assessment_cutoff"], "inventory_state": plan["inventory_state"],
                        "collection_basis_ref": plan["collection_basis_ref"], "entries": entries}
            self.v.snapshot_shape(snapshot, cutoff, assessed)
            assets.extend(self._refs(snapshot)); assets.extend(deliveries)
            review_raw = metadata_bytes(review, "review set")
            snapshot_raw = metadata_bytes(snapshot, "snapshot")
            review_ref, snapshot_ref = self._put(review_raw), self._put(snapshot_raw)
            selection = {"document_type": "receiver_selection_design", "design_revision": 2,
                "receiver_id": plan["receiver_id"], "review_set_selected_at": plan["review_set_selected_at"],
                "snapshot_selected_at": plan["assessment_time"], "assessment_time": plan["assessment_time"],
                "assessment_cutoff": plan["assessment_cutoff"], "review_set_ref": review_ref,
                "submission_snapshot_ref": snapshot_ref, "selection_basis_ref": plan["selection_basis_ref"],
                "native_policy_refs": plan["native_policy_refs"]}
            selection_ref, plan_ref = self._put(metadata_bytes(selection, "selection")), self._put(plan_raw)
            # The CLI receives selection bytes directly. It reads these references
            # through Reader; previous_report_ref alone uses the separate history budget.
            normal_review = {key: value for key, value in review.items() if key != "previous_report_ref"}
            self._check_read_capacity(self._refs([selection, snapshot, normal_review]),
                                      self.v.DEFAULT_LIMITS["bytes"])
            assets.extend((review_ref, snapshot_ref, selection_ref, plan_ref))
            job = {"contract": CONTRACT, "run_id": run_id, "stream_id": stream, "previous_id": previous_id,
                   "revision": review["revision"], "receiver_id": plan["receiver_id"], "namespace": review["namespace"],
                   "max_delivery_sequence": sequence, "plan_ref": plan_ref, "review_set_ref": review_ref,
                   "snapshot_ref": snapshot_ref, "selection_ref": selection_ref,
                   "source_root": str(self.engine.root), "engine_identity": self.engine.identity,
                   "assets": list({r["digest"]["value"]: r for r in assets}.values())}
            job_ref = self._put(encoded(job))
            self.db.execute("INSERT INTO runs VALUES (?,?,?,?,?,NULL)",
                            (run_id, stream, previous_id, "prepared", encoded(job_ref).decode()))
        return self.status(run_id)

    def status(self, run_id):
        row, job = self._run(run_id)
        result = self._json(json.loads(row["result_ref"])) if row["result_ref"] else None
        return {"contract": CONTRACT, "run_id": run_id, "status": row["status"], "revision": job["revision"],
                "previous_id": job["previous_id"], "max_delivery_sequence": job["max_delivery_sequence"],
                "report_ref": result["report_ref"] if result else None,
                "head": self._head(job["stream_id"]), "errors": result["errors"] if result else []}

    def run(self, run_id):
        row, job = self._run(run_id)
        if row["status"] != "prepared":
            return self.status(run_id)
        self.engine.check()
        require(self.engine.identity == job["engine_identity"], "RESUME_SOURCE_CHANGED",
                "prepared inputs require the same evaluator/runtime; prepare a new run for an update")
        originals = [(ref, self.get(ref)) for ref in job["assets"]]
        report_raw, stdout, stderr, returncode, errors = None, b"", b"", None, []
        try:
            with tempfile.TemporaryDirectory(prefix="vate-recipient-inbox-") as directory:
                folder = Path(directory); (folder / "objects").mkdir()
                for ref, raw in originals:
                    (folder / ref["path"]).write_bytes(raw)
                selection = folder / job["selection_ref"]["path"]
                command = [sys.executable, "-B", str(self.engine.root / "reference/required-records/required_records.py"),
                           "--selection", str(selection), "--base", BASE + "=" + str(folder),
                           "--source-root", str(self.engine.root), "--output", str(folder / "report.json")]
                if self.engine.openssl:
                    command += ["--openssl", self.engine.openssl, "--openssl-sha256", self.engine.openssl_sha256]
                with (folder / "stdout").open("xb") as out, (folder / "stderr").open("xb") as err:
                    process = None
                    try:
                        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                            env=PROCESS_ENV, start_new_session=True)
                        returncode = process.wait(timeout=90)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL); process.wait()
                        errors.append({"code": "EVALUATOR_TIMEOUT", "detail": "stopped this evaluation process group"})
                    except OSError as exc:
                        errors.append({"code": "EVALUATOR_START" if process is None else "EVALUATOR_IO_ERROR", "detail": str(exc)})
                        if process is not None and process.poll() is None:
                            os.killpg(process.pid, signal.SIGKILL); process.wait()
                    except BaseException:
                        if process is not None and process.poll() is None:
                            os.killpg(process.pid, signal.SIGKILL); process.wait()
                        raise
                if (folder / "report.json").exists():
                    try:
                        report_raw = read_file(folder / "report.json")
                    except (OSError, InboxError) as exc:
                        errors.append({"code": "OUTPUT_ERROR", "detail": "report.json: " + str(exc)})
                else:
                    errors.append({"code": "REPORT_ABSENT", "detail": "evaluator did not create a report"})
                outputs = {"stdout": b"", "stderr": b""}
                for name in outputs:
                    try:
                        outputs[name] = read_file(folder / name, MIB)
                    except (OSError, InboxError) as exc:
                        errors.append({"code": "OUTPUT_ERROR", "detail": name + ": " + str(exc)})
                stdout, stderr = outputs["stdout"], outputs["stderr"]
        except OSError as exc:
            errors.append({"code": "EVALUATOR_IO_ERROR", "detail": str(exc)})
        try:
            self.engine.check()
        except (ValueError, OSError, importlib.metadata.PackageNotFoundError) as exc:
            errors.append({"code": "SOURCE_CHANGED", "detail": str(exc)})
        report = None
        if report_raw is not None:
            try:
                report = self.v.decode(report_raw, 64)
                require(report.get("contract") == self.v.CONTRACT and
                        report.get("selection_identity") == self.v.identity(self.get(job["selection_ref"])),
                        "REPORT_BINDING", "report does not identify the selected input bytes")
                if report.get("review_set_status") in ("selected", "selected_empty") and report.get("invocation_errors") is False:
                    names = ("required_records.py", "native_bridge.py", "NATIVE-SOURCES.json")
                    sources = job["engine_identity"]["sources"]
                    composers = {name: sources["reference/required-records/" + name] for name in names}
                    expected_source = {"python": job["engine_identity"]["python"], "composer_sources": composers,
                        "native_sources": {name: digest for name, digest in sources.items()
                                           if name not in {"reference/required-records/" + n for n in names}}}
                    require(report.get("source_identity") == expected_source, "REPORT_SOURCE_BINDING",
                            "report source/runtime differs from the prepared evaluator identity")
            except (ValueError, self.v.Problem) as exc:
                errors.append({"code": getattr(exc, "code", "REPORT_BINDING"), "detail": str(exc)}); report = None
        eligible = (not errors and returncode == 0 and report is not None
                    and report.get("review_set_status") in ("selected", "selected_empty")
                    and report.get("invocation_errors") is False)
        with self.transaction():
            current, _ = self._run(run_id)
            if current["status"] != "prepared":
                return self.status(run_id)
            state = "completed" if eligible else "assessment_error"
            if eligible and self._head(job["stream_id"]) != job["previous_id"]:
                state = "stale_history"
                errors.append({"code": "HISTORY_CONFLICT", "detail": "another report advanced this review history"})
            result = {"status": state, "report_ref": self._put(report_raw) if report_raw is not None else None,
                      "stdout_ref": self._put(stdout, "application/octet-stream"),
                      "stderr_ref": self._put(stderr, "application/octet-stream"),
                      "returncode": returncode, "errors": errors}
            result_ref = self._put(encoded(result))
            self.db.execute("UPDATE runs SET status=?,result_ref=? WHERE run_id=?",
                            (state, encoded(result_ref).decode(), run_id))
            if state == "completed":
                self.db.execute("INSERT INTO heads VALUES (?,?) ON CONFLICT(stream_id) DO UPDATE SET run_id=excluded.run_id",
                                (job["stream_id"], run_id))
        return self.status(run_id)

    def export(self, run_id, destination):
        # Gather and validate first; write only to a newly created directory.
        refs, chain, cursor, visited = {}, [], run_id, set()
        with self.transaction():
            while cursor:
                require(cursor not in visited and len(visited) < 256, "HISTORY_LIMIT", "history cycle or export exceeds 256 revisions")
                visited.add(cursor)
                row, job = self._run(cursor)
                chain.append({"run_id": cursor, "status": row["status"], "job_ref": json.loads(row["job_ref"]),
                              "result_ref": json.loads(row["result_ref"]) if row["result_ref"] else None})
                selected = [*job["assets"], json.loads(row["job_ref"])]
                if row["result_ref"]:
                    result_ref = json.loads(row["result_ref"])
                    selected.extend([result_ref, *self._refs(self._json(result_ref))])
                for ref in selected:
                    refs[ref["path"]] = self.get(ref)
                cursor = job["previous_id"]
            _, job = self._run(run_id)
            state = self.status(run_id)
            refs["selection.json"] = self.get(job["selection_ref"])
            if state["report_ref"]:
                refs["report.json"] = self.get(state["report_ref"])
            refs["runs.json"] = encoded({"contract": CONTRACT, "runs": chain, "selected": run_id})
        destination = Path(destination)
        destination.mkdir(parents=True, exist_ok=False)
        (destination / "objects").mkdir()
        manifest = {}
        for name, raw in sorted(refs.items()):
            with (destination / name).open("xb") as stream:
                stream.write(raw)
            require(read_file(destination / name) == raw, "EXPORT_MISMATCH", "exported bytes differ")
            manifest[name] = {"raw_sha256": sha(raw), "byte_length": len(raw)}
        with (destination / "MANIFEST.json").open("xb") as stream:
            stream.write(encoded({"contract": CONTRACT, "files": manifest}) + b"\n")
        return {"directory": str(destination), "files": len(manifest), "run_id": run_id, "status": state["status"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--openssl"); parser.add_argument("--openssl-sha256")
    subs = parser.add_subparsers(dest="command", required=True)
    subs.add_parser("init")
    put = subs.add_parser("put"); put.add_argument("file", type=Path); put.add_argument("--media-type", default="application/json")
    receive = subs.add_parser("receive"); receive.add_argument("file", type=Path)
    prepare = subs.add_parser("prepare"); prepare.add_argument("file", type=Path)
    for name in ("run", "status", "export"):
        sub = subs.add_parser(name); sub.add_argument("run_id")
        if name == "export":
            sub.add_argument("directory", type=Path)
    args = parser.parse_args()
    inbox = None
    try:
        engine = Engine(args.source_root, args.openssl, args.openssl_sha256)
        inbox = Inbox(args.db, engine, create=args.command == "init")
        if args.command == "init":
            value = {"contract": CONTRACT, "database": str(args.db)}
        elif args.command == "put":
            value = inbox.put(read_file(args.file), args.media_type)
        elif args.command == "receive":
            value = inbox.receive(read_file(args.file, MIB))
        elif args.command == "prepare":
            value = inbox.prepare(read_file(args.file, MIB))
        elif args.command == "export":
            value = inbox.export(args.run_id, args.directory)
        else:
            value = getattr(inbox, args.command)(args.run_id)
        print(json.dumps(value, ensure_ascii=True))
        return 64 if args.command == "run" and value["status"] != "completed" else 0
    except (ValueError, OSError, sqlite3.Error, importlib.metadata.PackageNotFoundError) as exc:
        print(json.dumps({"contract": CONTRACT, "error": {"code": getattr(exc, "code", type(exc).__name__), "detail": str(exc)}}))
        return 64
    finally:
        if inbox is not None:
            inbox.close()


if __name__ == "__main__":
    raise SystemExit(main())
