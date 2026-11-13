"""Optional local SQLite state for admission replay and consumed dispatch attempts.

The store is trusted application state, not a received receipt or an effect log.
Only explicit create() initializes a new directory. Reopen requires its retained
anchor. See DURABLE-STATE.md for the filesystem, scope and recovery contract.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import uuid

CONTRACT = "vate-local-dispatch-state-v1"
APPLICATION_ID = 1447121988
VERSION = 1
MAX_BYTES = 2 * 1024 * 1024
VALUE_NAMES = ("original", "request", "core_result", "receipt", "effective", "assessment",
               "runtime_evidence", "runtime_verification")
# Bind the source digest to executed code, including when import uses a .pyc.
_source = Path(__file__).read_bytes()
LOADED_SOURCE_SHA256 = (hashlib.sha256(_source).hexdigest() if hasattr(sys, "_getframe")
    and sys._getframe().f_code == compile(_source, sys._getframe().f_code.co_filename,
        "exec", dont_inherit=True, optimize=sys.flags.optimize) else None)
del _source
TABLES = {
    "identity": """CREATE TABLE identity (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), store_id TEXT NOT NULL,
        scope TEXT NOT NULL, verifier_id TEXT NOT NULL, clock_high TEXT)""",
    "admissions": """CREATE TABLE admissions (
        request_id TEXT PRIMARY KEY NOT NULL, operation_id TEXT NOT NULL,
        configuration BLOB NOT NULL, record_sha256 TEXT NOT NULL,
        executable INTEGER NOT NULL CHECK(executable IN (0,1)),
        original BLOB NOT NULL, request BLOB NOT NULL, core_result BLOB NOT NULL,
        receipt BLOB NOT NULL, effective BLOB, assessment BLOB NOT NULL,
        runtime_evidence BLOB, runtime_verification BLOB)""",
    "operations": """CREATE TABLE operations (
        operation_id TEXT PRIMARY KEY NOT NULL, request_id TEXT UNIQUE NOT NULL
        REFERENCES admissions(request_id), record_sha256 TEXT NOT NULL,
        checkpoint BLOB NOT NULL, checkpoint_sha256 TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('attempt_consumed','callback_returned','outcome_unknown')),
        checked_at TEXT NOT NULL)""",
}


class StateError(ValueError):
    def __init__(self, cause: str):
        self.cause = cause
        super().__init__(cause)


def require(ok: bool, cause: str) -> None:
    if not ok:
        raise StateError(cause)


def identifier(value: object) -> None:
    require(type(value) is str and 0 < len(value) <= 1024
            and not any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value),
            "STATE_IDENTIFIER_INVALID")


def raw_bytes(raw: object) -> None:
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "STATE_BYTES_INVALID")


def encode(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def instant(value: datetime) -> datetime:
    require(isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None,
            "STATE_CLOCK_INVALID")
    return value.astimezone(timezone.utc)


def timestamp(value: datetime) -> str:
    return instant(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    require(type(value) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", value) is not None,
            "STATE_CORRUPT")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise StateError("STATE_CORRUPT") from None


def record_digest(request_id: str, operation_id: str, configuration: bytes,
                  values: tuple, executable: bool) -> str:
    identifier(request_id)
    identifier(operation_id)
    raw_bytes(configuration)
    require(type(values) is tuple and len(values) == len(VALUE_NAMES) and type(executable) is bool,
            "STATE_RECORD_INVALID")
    for i, value in enumerate(values):
        if value is None:
            require(i in (4, 6, 7), "STATE_RECORD_INVALID")
        else:
            raw_bytes(value)
    require(not executable or all(values[i] is not None for i in (4, 6, 7)), "STATE_RECORD_INVALID")
    return sha(encode({"contract": CONTRACT, "request_id": request_id, "operation_id": operation_id,
        "configuration_sha256": sha(configuration), "executable": executable,
        "artifacts": {name: sha(raw) if raw is not None else None for name, raw in zip(VALUE_NAMES, values)}}))


class DurableStateStore:
    def __init__(self, directory: str | Path, *, expected_anchor: bytes, timeout: float = 2.0):
        require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 30,
                "STATE_CONFIGURATION_INVALID")
        require(type(expected_anchor) is bytes and len(expected_anchor) <= 16384, "STATE_ANCHOR_INVALID")
        try:
            anchor = json.loads(expected_anchor)
        except (ValueError, UnicodeError):
            raise StateError("STATE_ANCHOR_INVALID") from None
        require(type(anchor) is dict and set(anchor) == {"contract", "store_id", "scope", "verifier_id",
                "directory_device", "directory_inode", "db_device", "db_inode"}
                and encode(anchor) == expected_anchor and anchor["contract"] == CONTRACT,
                "STATE_ANCHOR_INVALID")
        for key in ("store_id", "scope", "verifier_id"):
            identifier(anchor[key])
        require(all(type(anchor[key]) is int and anchor[key] >= 0 for key in
                    ("directory_device", "directory_inode", "db_device", "db_inode")), "STATE_ANCHOR_INVALID")
        self.directory = Path(directory).absolute()
        self.anchor = expected_anchor
        self._anchor = anchor
        self.scope, self.verifier_id = anchor["scope"], anchor["verifier_id"]
        self.timeout = timeout
        with self._connection():
            pass

    @classmethod
    def create(cls, directory: str | Path, *, scope: str, verifier_id: str, timeout: float = 2.0):
        """Explicit initialization only; an existing directory is never reused."""
        identifier(scope)
        identifier(verifier_id)
        require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 30,
                "STATE_CONFIGURATION_INVALID")
        directory = Path(directory).absolute()
        directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        db = directory / "state.sqlite3"
        fd = os.open(db, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        connection = sqlite3.connect(db.as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=timeout)
        store_id = str(uuid.uuid4())
        try:
            require(connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete", "STATE_MODE_INVALID")
            connection.execute("PRAGMA synchronous=EXTRA")
            connection.execute("BEGIN IMMEDIATE")
            for sql in TABLES.values():
                connection.execute(sql)
            connection.execute("INSERT INTO identity VALUES (1,?,?,?,NULL)", (store_id, scope, verifier_id))
            connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version={VERSION}")
            connection.execute("COMMIT")
        finally:
            connection.close()
        directory_stat, db_stat = directory.lstat(), db.lstat()
        anchor = encode({"contract": CONTRACT, "store_id": store_id, "scope": scope, "verifier_id": verifier_id,
            "directory_device": directory_stat.st_dev, "directory_inode": directory_stat.st_ino,
            "db_device": db_stat.st_dev, "db_inode": db_stat.st_ino})
        return cls(directory, expected_anchor=anchor, timeout=timeout)

    def _files(self) -> Path:
        info = self.directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) ==
                (self._anchor["directory_device"], self._anchor["directory_inode"]), "STATE_STORE_REPLACED")
        db = self.directory / "state.sqlite3"
        info = db.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and (info.st_dev, info.st_ino) ==
                (self._anchor["db_device"], self._anchor["db_inode"]), "STATE_STORE_REPLACED")
        for suffix in ("-journal", "-wal", "-shm"):
            path = Path(str(db) + suffix)
            if os.path.lexists(path):
                item = path.lstat()
                require(stat.S_ISREG(item.st_mode) and item.st_nlink == 1, "STATE_SIDECAR_INVALID")
        return db

    @contextmanager
    def _connection(self):
        connection = None
        try:
            db = self._files()
            connection = sqlite3.connect(db.as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=self.timeout)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA synchronous=EXTRA")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            require(connection.execute("PRAGMA synchronous").fetchone()[0] == 3
                    and connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
                    and connection.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
                    and connection.execute("PRAGMA user_version").fetchone()[0] == VERSION, "STATE_MODE_INVALID")
            schema = {row["name"]: " ".join(row["sql"].split()) for row in connection.execute(
                "SELECT name,sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'")}
            require(schema == {name: " ".join(sql.split()) for name, sql in TABLES.items()}, "STATE_SCHEMA_CHANGED")
            identity = connection.execute("SELECT * FROM identity").fetchall()
            require(len(identity) == 1 and identity[0]["singleton"] == 1
                    and all(identity[0][key] == self._anchor[key] for key in ("store_id", "scope", "verifier_id")),
                    "STATE_IDENTITY_MISMATCH")
            if identity[0]["clock_high"] is not None:
                parse_time(identity[0]["clock_high"])
            require(connection.execute("PRAGMA quick_check").fetchone()[0] == "ok", "STATE_CORRUPT")
            self._files()
            yield connection
        except (sqlite3.Error, OSError):
            raise StateError("STATE_UNAVAILABLE") from None
        finally:
            if connection is not None:
                try:
                    if connection.in_transaction:
                        connection.rollback()
                except sqlite3.Error:
                    raise StateError("STATE_UNAVAILABLE") from None
                finally:
                    try:
                        connection.close()
                    except sqlite3.Error:
                        raise StateError("STATE_UNAVAILABLE") from None

    def _commit(self, connection) -> None:
        # No COMMIT retry: an error is an uncertain write, never callback authority.
        connection.execute("COMMIT")

    def issue(self, request_id: str, operation_id: str, configuration: bytes, producer) -> None:
        identifier(request_id)
        identifier(operation_id)
        raw_bytes(configuration)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            require(connection.execute("SELECT 1 FROM admissions WHERE request_id=?", (request_id,)).fetchone() is None,
                    "DURABLE_REPLAY_DETECTED")
            require(connection.execute("SELECT 1 FROM operations WHERE operation_id=?", (operation_id,)).fetchone() is None,
                    "DURABLE_OPERATION_ALREADY_ATTEMPTED")
            values, executable = producer()
            digest = record_digest(request_id, operation_id, configuration, values, executable)
            connection.execute("INSERT INTO admissions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (request_id, operation_id, configuration, digest, int(executable), *values))
            self._commit(connection)

    def _read(self, connection, request_id: str) -> dict:
        row = connection.execute("SELECT * FROM admissions WHERE request_id=?", (request_id,)).fetchone()
        require(row is not None, "STATE_ADMISSION_NOT_FOUND")
        require(type(row["executable"]) is int and row["executable"] in (0, 1), "STATE_CORRUPT")
        values = tuple(row[name] for name in VALUE_NAMES)
        digest = record_digest(row["request_id"], row["operation_id"], row["configuration"], values, bool(row["executable"]))
        require(digest == row["record_sha256"], "STATE_RECORD_CHANGED")
        operation = connection.execute("SELECT * FROM operations WHERE operation_id=?", (row["operation_id"],)).fetchone()
        state = "ready" if row["executable"] else "not_executable"
        checkpoint, owner = None, None
        if operation is not None:
            owner = operation["request_id"]
            selected = connection.execute("SELECT operation_id,record_sha256 FROM admissions WHERE request_id=?", (owner,)).fetchone()
            require(selected is not None and selected["operation_id"] == row["operation_id"]
                    and selected["record_sha256"] == operation["record_sha256"]
                    and operation["state"] in ("attempt_consumed", "callback_returned", "outcome_unknown"), "STATE_CORRUPT")
            raw_bytes(operation["checkpoint"])
            require(sha(operation["checkpoint"]) == operation["checkpoint_sha256"], "STATE_RECORD_CHANGED")
            parse_time(operation["checked_at"])
            state = operation["state"] if owner == request_id else "operation_already_attempted"
            checkpoint = operation["checkpoint"]
        return {"request_id": request_id, "operation_id": row["operation_id"], "configuration": row["configuration"],
            "record_sha256": digest, "values": values, "executable": bool(row["executable"]),
            "state": state, "checkpoint": checkpoint, "attempt_request_id": owner}

    def read(self, request_id: str) -> dict:
        identifier(request_id)
        with self._connection() as connection:
            connection.execute("BEGIN")
            return self._read(connection, request_id)

    def _clock(self, connection, clock) -> datetime:
        now = instant(clock())  # After acquisition of the SQLite write lock.
        high = connection.execute("SELECT clock_high FROM identity WHERE singleton=1").fetchone()[0]
        require(high is None or now >= parse_time(high), "DURABLE_CLOCK_ROLLBACK")
        connection.execute("UPDATE identity SET clock_high=? WHERE singleton=1", (timestamp(now),))
        return now

    def observe_clock(self, clock) -> datetime:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            now = self._clock(connection, clock)
            self._commit(connection)
            return now

    def claim(self, request_id: str, configuration: bytes, digest: str, checkpoint: bytes, clock, validate) -> None:
        raw_bytes(checkpoint)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            record = self._read(connection, request_id)
            require(record["configuration"] == configuration and record["record_sha256"] == digest,
                    "STATE_RECORD_CHANGED")
            require(record["executable"] and record["state"] == "ready", "DURABLE_OPERATION_ALREADY_ATTEMPTED")
            now = self._clock(connection, clock)
            try:
                validate(now)
            except Exception:
                self._commit(connection)  # Retain an observed deadline failure's clock high-water.
                raise
            connection.execute("INSERT INTO operations VALUES (?,?,?,?,?,?,?)", (record["operation_id"],
                request_id, digest, checkpoint, sha(checkpoint), "attempt_consumed", timestamp(now)))
            self._commit(connection)

    def finish(self, request_id: str, digest: str, *, returned: bool) -> None:
        require(type(returned) is bool, "STATE_RECORD_INVALID")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            record = self._read(connection, request_id)
            require(record["record_sha256"] == digest and record["state"] == "attempt_consumed"
                    and record["attempt_request_id"] == request_id, "STATE_ATTEMPT_MISMATCH")
            connection.execute("UPDATE operations SET state=? WHERE operation_id=?", (
                "callback_returned" if returned else "outcome_unknown", record["operation_id"]))
            self._commit(connection)
