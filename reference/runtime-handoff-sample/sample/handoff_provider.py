"""One trusted local provider/store; submit is the only effect-producing method."""
from __future__ import annotations

from contextlib import contextmanager
import copy
import fcntl
import os
from pathlib import Path
import sqlite3
import stat
import time
import uuid

from dependencies import crypto, demo
from handoff_contract import (Context, PROFILE, OBS_TYP, ZERO, MAX_EVENTS, MAX_JOURNAL_BYTES, RESERVED_EVENT_BYTES, iso,
                              encode, decode, sha, b64, unb64, need, exact, integer, binding, effect_state, linkage,
                              reserved_event_count, validate_event_size)
from handoff_model import initial, apply, replay, admission_reason, check_handoff_request

APPLICATION_ID = 1447121990


def directory(path):
    need(stat.S_ISDIR(path.lstat().st_mode), "unsafe/missing directory")


def initialize(path, context_raw, *, journal="WAL"):
    """NEW private case only. Recovery never initializes or replaces a store."""
    context = Context(context_raw)
    need(journal in ("WAL", "DELETE"), "unsupported journal")
    path.mkdir(mode=0o700)
    for child in ("locks", "resources", "authority"):
        (path / child).mkdir(mode=0o700)
    crypto.exclusive_write(path / "context.json", context_raw)
    db = path / "provider.sqlite3"
    c = sqlite3.connect(db, isolation_level=None)
    try:
        c.execute(f"PRAGMA journal_mode={journal}")
        c.execute("PRAGMA synchronous=FULL")
        c.execute(f"PRAGMA application_id={APPLICATION_ID}")
        c.executescript("""
          CREATE TABLE metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            store_id TEXT NOT NULL, context_sha256 TEXT NOT NULL, count INTEGER NOT NULL,
            head TEXT NOT NULL, journal_bytes INTEGER NOT NULL, projection BLOB NOT NULL);
          CREATE TABLE events (id INTEGER PRIMARY KEY, raw BLOB NOT NULL, sha256 TEXT NOT NULL);
          CREATE TABLE accepted (operation_id TEXT PRIMARY KEY, attempt_id TEXT UNIQUE NOT NULL,
            event_id INTEGER UNIQUE NOT NULL);
        """)
        c.execute("INSERT INTO metadata VALUES (1,?,?,0,?,0,?)",
                  (context.data["store"], context.digest, ZERO, encode(initial())))
    finally:
        c.close()
    info = db.stat()
    crypto.exclusive_write(path / "anchor.json", encode({"store": context.data["store"], "context_sha256": context.digest,
        "db_dev": info.st_dev, "db_ino": info.st_ino}))


class Provider:
    def __init__(self, path, *, clock=None, hook=None, owner_capability=None, timeout=0.5):
        self.path = Path(path).absolute()
        self.context = Context(crypto.safe_read(self.path / "context.json"))
        self.anchor_raw = crypto.safe_read(self.path / "anchor.json")
        self.anchor = decode(self.anchor_raw)
        exact(self.anchor, {"store", "context_sha256", "db_dev", "db_ino"})
        need(self.anchor["store"] == self.context.data["store"] and
             self.anchor["context_sha256"] == self.context.digest, "wrong selected anchor")
        self.clock = clock or (lambda: int(time.time()))
        self.hook = hook or (lambda point: None)  # deterministic tests only; not a runtime parameter
        self.owner_capability = owner_capability
        self.timeout = timeout
        with self.connection() as c:
            self.load(c)

    def owner(self, capability):
        # This is a trusted local composition boundary, not OS isolation or network authentication.
        need(self.owner_capability is not None and capability is self.owner_capability, "owner control required")

    def anchor_check(self):
        for p in (self.path, self.path / "resources", self.path / "locks"):
            directory(p)
        need(crypto.safe_read(self.path / "context.json") == self.context.raw and
             crypto.safe_read(self.path / "anchor.json") == self.anchor_raw, "context/anchor changed")
        db = self.path / "provider.sqlite3"
        s = db.lstat()
        need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and
             (s.st_dev, s.st_ino) == (self.anchor["db_dev"], self.anchor["db_ino"]), "DB missing/replaced/unsafe")
        for ext in ("-wal", "-shm", "-journal"):
            p = Path(str(db) + ext)
            if os.path.lexists(p):
                s = p.lstat()
                need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, "unsafe SQLite sidecar")
        return db

    @contextmanager
    def connection(self, *, write=False):
        db = self.anchor_check()
        c = sqlite3.connect(db.as_uri() + ("?mode=rw" if write else "?mode=ro"), uri=True,
                            isolation_level=None, timeout=self.timeout)
        c.row_factory = sqlite3.Row
        try:
            if write:
                c.execute("PRAGMA synchronous=FULL")
            c.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            need(c.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID, "wrong DB application")
            need(c.execute("PRAGMA quick_check").fetchone()[0] == "ok", "corrupt DB")
            yield c
        finally:
            try:
                if c.in_transaction:
                    c.rollback()
            finally:
                c.close()  # also close when rollback itself fails

    def load(self, c):
        rows = c.execute("SELECT * FROM metadata").fetchall()
        need(len(rows) == 1 and rows[0]["context_sha256"] == self.context.digest and
             rows[0]["store_id"] == self.context.data["store"], "DB identity")
        meta = rows[0]
        records = [{"raw": b64(row["raw"]), "sha256": row["sha256"]}
                   for row in c.execute("SELECT * FROM events ORDER BY id")]
        raw_rows = c.execute("SELECT id,raw FROM events ORDER BY id").fetchall()
        need([x["id"] for x in raw_rows] == list(range(1, len(records) + 1)), "journal row gap")
        need(len(records) == meta["count"] <= MAX_EVENTS and
             sum(len(r["raw"]) for r in raw_rows) == meta["journal_bytes"] <= MAX_JOURNAL_BYTES and
             meta["head"] == (records[-1]["sha256"] if records else ZERO), "journal incomplete/capacity")
        state = replay(self.context, records)
        need(encode(state) == meta["projection"], "journal/projection mismatch")
        reserved = reserved_event_count(state)
        need(len(records) + reserved <= MAX_EVENTS and meta["journal_bytes"] + reserved * RESERVED_EVENT_BYTES <=
             MAX_JOURNAL_BYTES, "reservation capacity mismatch")
        accepted = sorted((opid, op["accepted"]["attempt_id"], op["accepted"]["event_index"])
                          for opid, op in state["operations"].items() if op["accepted"] is not None)
        actual = sorted(tuple(r) for r in c.execute("SELECT operation_id,attempt_id,event_id FROM accepted"))
        need(actual == accepted, "acceptance/history mismatch")
        return state, records

    def append(self, c, state, records, kind, opid, body, at):
        event = {"index": len(records) + 1, "previous": records[-1]["sha256"] if records else ZERO,
                 "context_sha256": self.context.digest, "at": integer(at), "kind": kind,
                 "operation_id": opid, "body": body}
        raw = encode(event)
        need(len(records) < MAX_EVENTS, "journal event capacity")
        validate_event_size(raw, kind)
        meta = c.execute("SELECT journal_bytes FROM metadata").fetchone()
        need(meta[0] + len(raw) <= MAX_JOURNAL_BYTES, "journal byte capacity")
        # Validate the complete event before inserting anything; the outer transaction covers all events.
        candidate = copy.deepcopy(state)
        apply(self.context, candidate, event)
        reserved = reserved_event_count(candidate)
        need(len(records) + 1 + reserved <= MAX_EVENTS and
             meta[0] + len(raw) + reserved * RESERVED_EVENT_BYTES <= MAX_JOURNAL_BYTES, "reserved result capacity")
        digest = sha(raw)
        c.execute("INSERT INTO events VALUES (?,?,?)", (event["index"], raw, digest))
        if kind == "accepted":
            c.execute("INSERT INTO accepted VALUES (?,?,?)", (opid, body["attempt_id"], event["index"]))
        c.execute("UPDATE metadata SET count=?,head=?,journal_bytes=journal_bytes+?,projection=?",
                  (event["index"], digest, len(raw), encode(candidate)))
        state.clear(); state.update(candidate)
        records.append({"raw": b64(raw), "sha256": digest})
        return event

    def clock_check(self, c, state, records, now):
        need(not state["clock_bad"], "clock_uncertain")
        if now < state["clock_high"]:
            self.append(c, state, records, "clock", None, {}, now)
            c.commit()
            raise ValueError("clock_uncertain")

    @contextmanager
    def worker(self, operation_id):
        demo.identifier(operation_id)
        self.anchor_check()
        fd = os.open(self.path / "locks" / operation_id, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            s = os.fstat(fd)
            need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, "unsafe worker lock")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def resource_path(self, operation):
        self.context.operation(operation)
        return self.path / "resources" / operation["target"]["resource"].rsplit(":", 1)[1]

    def inventory(self, operation):
        directory(self.resource_path(operation))
        entries = list(self.resource_path(operation).iterdir())
        need(len(entries) <= 8, "unexpected resource entries")
        result = {}
        for p in sorted(entries):
            need(demo.FILE_RE.fullmatch(p.name), "unexpected resource entry")
            raw = crypto.safe_read(p, limit=4096)
            result[p.name] = {"sha256": sha(raw), "size": len(raw)}
        return result

    def prepare_operation(self, capability, operation_id, files):
        self.owner(capability)
        demo.identifier(operation_id)
        return self.context.operation({"contract": demo.CONTRACT, "operation_key": operation_id, "action": demo.ACTION,
            "target": {"resource": "urn:vate:handoff:" + self.context.data["store"] + ":resource-" + uuid.uuid4().hex,
                       "files": files}})

    def register(self, capability, operation, authorization):
        self.owner(capability)
        self.context.operation(operation)
        self.context.authorization(operation, authorization)
        with self.connection(write=True) as c:
            state, records = self.load(c)
            now = integer(self.clock())
            self.clock_check(c, state, records, now)
            event = self.append(c, state, records, "registered", operation["operation_key"],
                                {"operation": operation, "authorization": authorization}, now)
            # Newly allocated paths only. A failed registration can leave an empty orphan,
            # which is never re-used or mistaken for a recovered operation.
            self.resource_path(operation).mkdir(mode=0o700)
            crypto.exclusive_write(self.path / "locks" / operation["operation_key"], b"")
            c.commit()
            return event

    def ticket(self, operation_id, runtime):
        with self.worker(operation_id), self.connection(write=True) as c:
            state, records = self.load(c)
            now = integer(self.clock())
            self.clock_check(c, state, records, now)
            op = state["operations"][operation_id]
            need(runtime == op["runtime"], "not current runtime")
            ticket = {**binding(self.context, op), "attempt_id": "attempt-" + uuid.uuid4().hex,
                      "nonce": "nonce-" + uuid.uuid4().hex, "issued_at": now, "expires_at": now + 60}
            self.append(c, state, records, "ticket", operation_id, ticket, now)
            self.hook("ticket_before_commit")
            c.commit()
            self.hook("ticket_after_commit")
            return ticket

    def notify(self, raw):
        v = self.context.verify_status(raw)
        with self.connection(write=True) as c:
            state, records = self.load(c)
            now = integer(self.clock())
            self.clock_check(c, state, records, now)
            self.context.status(raw, now)
            self.append_status(c, state, records, v, now)
            c.commit()

    def append_status(self, c, state, records, verified, now):
        self.append(c, state, records, "status", None,
                    {"raw": b64(verified.raw), "raw_sha256": verified.raw_sha256,
                     "signing_input_sha256": verified.signing_input_sha256}, now)

    def record_unknown(self, operation_id, attempt_id, runtime, raw):
        # Caller-signed observation, not an assertion by the provider that an effect failed.
        with self.worker(operation_id), self.connection(write=True) as c:
            state, records = self.load(c)
            now = integer(self.clock())
            # Commit the first clock fault before an invalid observation can roll it back.
            # Already-faulted stores may still collect otherwise-valid late observations.
            if not state["clock_bad"] and now < state["clock_high"]:
                self.clock_check(c, state, records, now)
            self.append(c, state, records, "unknown", operation_id,
                        {"attempt_id": attempt_id, "runtime": runtime, "raw": b64(raw)}, now)
            c.commit()

    def submit(self, operation_id, attempt_id, proof_raw):
        """Pull from the fixed owner-controlled local authority path, never a caller URL."""
        try:
            with self.worker(operation_id):
                self.hook("submit_locked")
                return self._submit(operation_id, attempt_id, proof_raw)
        except BlockingIOError:
            return {"status": "busy", "next": "query"}
        except ValueError as error:
            # A local validation failure never states that the original operation had no effect.
            return {"status": "rejected", "reason": str(error), "next": "query"}
        except (KeyError, OSError, sqlite3.Error, RuntimeError):
            # Any uncertain acceptance commit ends this invocation before effect_entry.
            # Context managers have closed the old connection and released the worker lock.
            try:
                saved = self.query(operation_id)
            except (ValueError, KeyError, OSError, sqlite3.Error, RuntimeError):
                saved = None
            return {"status": "unknown", "next": "query", "saved": saved}

    def _submit(self, operation_id, attempt_id, proof_raw):
        with self.connection() as c:
            state, _ = self.load(c)
            ticket = state["operations"][operation_id]["tickets"][attempt_id]
        verified = self.context.verify_actor(proof_raw, ticket["runtime"], "vate-local-handoff-attempt+jws")
        need(encode(verified.payload) == encode(ticket), "proof binding mismatch")
        directory(self.path / "authority")
        status_raw = crypto.safe_read(self.path / "authority" / (ticket["runtime"] + ".jws"), limit=65536)
        status = self.context.verify_status(status_raw)
        self.hook("submit_after_crypto")
        with self.connection(write=True) as c:
            state, records = self.load(c)
            now = integer(self.clock())
            self.clock_check(c, state, records, now)
            self.context.status(status_raw, now)
            need(status.payload["runtime"] == ticket["runtime"], "wrong pull subject")
            self.append_status(c, state, records, status, now)
            op = state["operations"][operation_id]
            inventory = self.inventory(op["operation"])
            reason = admission_reason(self.context, state, op, ticket, status.payload, inventory, now)
            self.append(c, state, records, "denied" if reason else "accepted", operation_id,
                        {"attempt_id": attempt_id, "proof": b64(proof_raw), "status": b64(status_raw),
                         "inventory": inventory, "reason": reason, "worker_excluded": True}, now)
            self.hook("accept_before_commit")
            c.commit()
            self.hook("accept_commit_return")
            if reason:
                return {"status": "denied", "reason": reason}
            operation = copy.deepcopy(op["operation"])
        try:
            return self._execute_accepted(operation_id, attempt_id, ticket, operation)
        except (ValueError, KeyError, OSError, sqlite3.Error, RuntimeError) as error:
            raise RuntimeError("accepted execution result uncertain") from error

    def execution_clock(self, operation_id, phase):
        # Persist observations separately from native validation: a rejected native
        # transaction must not erase an observed backwards clock.
        sampled = integer(self.clock())
        self.hook("execution_clock_sampled_" + phase)
        with self.connection(write=True) as c:
            state, records = self.load(c)
            now = integer(self.clock())
            need(not state["clock_bad"], "clock_uncertain")
            self.append(c, state, records, "execution_clock", operation_id,
                        {"phase": phase, "sampled_at": sampled}, now)
            c.commit()
            need(not state["clock_bad"], "clock_uncertain")
            return sampled

    def _execute_accepted(self, operation_id, attempt_id, ticket, operation):
        self.hook("accepted_before_effect")
        started_at = iso(self.execution_clock(operation_id, "start"))
        self.hook("effect_entry")  # tests count actual entries, not merely surviving output files
        for i, entry in enumerate(operation["target"]["files"]):
            crypto.exclusive_write(self.resource_path(operation) / entry["name"], entry["text"].encode("utf-8"))
            self.hook("after_file_" + str(i + 1))
        # Ensure the directory entries are durable before recording a complete native result.
        fd = os.open(self.resource_path(operation), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        finished_at = iso(self.execution_clock(operation_id, "finish"))
        native = {"attempt_id": attempt_id, "runtime": ticket["runtime"], "admission_sha256": ticket["admission_sha256"],
                  "input_sha256": ticket["input_sha256"], "started_at": started_at, "finished_at": finished_at,
                  "outputs": self.inventory(operation)}
        with self.connection(write=True) as c:
            state, records = self.load(c)
            now = integer(self.clock())
            if state["clock_bad"] or now < state["clock_high"]:
                # Use this accepted operation's reserved native slot for the fatal
                # clock observation if no ordinary journal slots remain.
                self.append(c, state, records, "clock_fault", operation_id, {}, now)
                c.commit()
                raise ValueError("clock_uncertain")
            self.append(c, state, records, "native", operation_id, native, now)
            c.commit()
        self.hook("native_after_commit")
        return {"status": "completed", "native": native}

    def handoff(self, capability, request_raw):
        self.owner(capability)
        request = decode(request_raw)
        check_handoff_request(self.context, request)
        need(request_raw == encode(request), "handoff must preserve canonical original bytes")
        opid, reqid = request["operation_id"], request["request_id"]
        try:
            with self.worker(opid):
                self.hook("handoff_locked")
                with self.connection(write=True) as c:
                    state, records = self.load(c)
                    saved = state["handoffs"].get(reqid)
                    if saved is not None:  # strictly BEFORE current CAS, status or authorization checks
                        need(unb64(saved["request_raw"]) == request_raw, "handoff ID reused with different bytes")
                        return {"status": "committed", "result": saved["result"]}
                    now = integer(self.clock())
                    self.clock_check(c, state, records, now)
                    op = state["operations"][opid]
                    inventory = self.inventory(op["operation"])
                    self.append(c, state, records, "handoff", opid,
                                {"request_raw": b64(request_raw), "inventory": inventory,
                                 "retained_attempts": sorted(op["tickets"]),
                                 "effect_state": effect_state(op, inventory, fenced=True), "worker_excluded": True}, now)
                    self.hook("handoff_before_commit")
                    c.commit()
                    self.hook("handoff_commit_return")
                    return {"status": "committed", "result": state["handoffs"][reqid]["result"]}
        except BlockingIOError:
            return {"status": "busy", "next": "query_same_request"}
        except (OSError, sqlite3.Error, RuntimeError):
            # No effect and no new request ID. The old transaction is closed before this new read.
            try:
                return self.handoff_result(reqid, request_raw)
            except (ValueError, OSError, sqlite3.Error, RuntimeError):
                return {"status": "unknown", "next": "query_same_request"}

    def handoff_result(self, request_id, request_raw):
        with self.connection() as c:
            state, _ = self.load(c)
            saved = state["handoffs"].get(request_id)
            if saved is None:
                return {"status": "not_committed", "is_execution_ticket": False}
            need(unb64(saved["request_raw"]) == request_raw, "handoff original mismatch")
            return {"status": "committed", "result": saved["result"]}

    def query(self, operation_id):
        with self.worker(operation_id), self.connection() as c:
            state, _ = self.load(c)
            op = state["operations"][operation_id]
            inventory = self.inventory(op["operation"])
            return {"operation_id": operation_id, "generation": op["generation"], "revision": op["revision"],
                    "runtime": op["runtime"], "effect_state": effect_state(op, inventory), "accepted": op["accepted"],
                    "inventory": inventory, "unknown": op["unknown"], "linkage": linkage(op),
                    "clock_uncertain": state["clock_bad"],
                    "is_execution_ticket": False}

    def observe(self, capability, operation_id):
        """Append a later read-only filesystem observation. No execution or handoff."""
        self.owner(capability)
        with self.worker(operation_id), self.connection(write=True) as c:
            state, records = self.load(c)
            op = state["operations"][operation_id]
            inventory = self.inventory(op["operation"])
            self.append(c, state, records, "observed", operation_id,
                        {"inventory": inventory, "effect_state": effect_state(op, inventory), "worker_excluded": True},
                        integer(self.clock()))
            c.commit()

    def export(self, operation_id, output=None):
        # Per-operation lock also makes the resource inventory stable across the DB snapshot.
        with self.worker(operation_id), self.connection() as c:
            state, records = self.load(c)
            op = state["operations"][operation_id]
            inventory = self.inventory(op["operation"])
            bundle = {"profile": PROFILE, "context_sha256": self.context.digest, "store": self.context.data["store"],
                      "operation_id": operation_id, "records": records,
                      "head": records[-1]["sha256"] if records else ZERO, "inventory": inventory,
                      "observed_at": integer(self.clock()), "is_execution_ticket": False}
            raw = encode(bundle)
            need(len(raw) <= crypto.MAX, "export capacity")
        if output is not None:
            crypto.exclusive_write(Path(output), raw)
        return raw
