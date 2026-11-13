"""Anchored local authority state; updates and complete dispatch leases share a lock."""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import sys
from threading import Lock, RLock, local
import uuid

import snapshot as s

b, jwt = s.b, s.jwt
CONTRACT = "vate-authority-state-v1"
APPLICATION_ID = 1447121990
TABLES = {
    "identity": "CREATE TABLE identity (singleton INTEGER PRIMARY KEY CHECK(singleton=1), store_id TEXT NOT NULL, selection BLOB NOT NULL)",
    "state": "CREATE TABLE state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision INTEGER NOT NULL, issued_at INTEGER NOT NULL, raw BLOB, raw_sha256 TEXT, payload_sha256 TEXT, conflict INTEGER NOT NULL CHECK(conflict IN (0,1)), unavailable INTEGER NOT NULL CHECK(unavailable IN (0,1)), clock_high TEXT)"
}
_source = None
try:
    _source = Path(__file__).read_bytes()
    LOADED_SOURCE_SHA256 = (hashlib.sha256(_source).hexdigest() if hasattr(sys, "_getframe")
        and sys._getframe().f_code == compile(_source, sys._getframe().f_code.co_filename,
            "exec", dont_inherit=True, optimize=sys.flags.optimize) else None)
except (OSError, SyntaxError, ValueError):
    # Import remains available; identity-dependent entry points reject None.
    LOADED_SOURCE_SHA256 = None
del _source

def _fd_registry():
    guard, descriptors = Lock(), set()
    def child_cleanup():
        # Capture this generation's registry: a later module reload must not
        # redirect an old hook to a new set and strand an inherited descriptor.
        try:
            for fd in tuple(descriptors):
                try:
                    os.close(fd)
                except OSError:
                    pass
            descriptors.clear()
        finally:
            guard.release()
    # Opening/registering and closing/unregistering are indivisible with fork.
    # Close only child references; LOCK_UN would release the parent's lease.
    os.register_at_fork(before=guard.acquire, after_in_parent=guard.release,
                        after_in_child=child_cleanup)
    return guard, descriptors


_FD_GUARD, _ACTIVE_FDS = _fd_registry()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class AuthorityStore:
    _loaded_source_path = Path(__file__).resolve()
    _loaded_source_sha256 = LOADED_SOURCE_SHA256

    @classmethod
    def create(cls, directory, *, verifier, clock=b.core.utc_now):
        s.need(type(verifier) is s.SnapshotVerifier and callable(clock), "AUTHORITY_CONFIGURATION_INVALID")
        verifier.configuration_id()
        directory = Path(directory).absolute()
        directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        for name in ("authority.sqlite3", "authority.lock"):
            fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        store_id = str(uuid.uuid4())
        selection = b.encode(verifier.selection.descriptor())
        connection = sqlite3.connect(directory / "authority.sqlite3", isolation_level=None)
        try:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=EXTRA")
            connection.execute("BEGIN IMMEDIATE")
            for sql in TABLES.values():
                connection.execute(sql)
            connection.execute("INSERT INTO identity VALUES (1,?,?)", (store_id, selection))
            connection.execute("INSERT INTO state VALUES (1,0,0,NULL,NULL,NULL,0,1,NULL)")
            connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
            connection.execute("PRAGMA user_version=1")
            connection.commit()
        finally:
            connection.close()
        anchor = {"contract": CONTRACT, "store_id": store_id, "selection_sha256": sha(selection)}
        for name, path in (("directory", directory), ("db", directory / "authority.sqlite3"),
                           ("lock", directory / "authority.lock")):
            info = path.lstat()
            anchor[name + "_device"], anchor[name + "_inode"] = info.st_dev, info.st_ino
        return cls(directory, verifier=verifier, expected_anchor=b.encode(anchor), clock=clock)

    def __init__(self, directory, *, verifier, expected_anchor: bytes, clock=b.core.utc_now):
        s.need(type(verifier) is s.SnapshotVerifier and callable(clock), "AUTHORITY_CONFIGURATION_INVALID")
        s.need(type(expected_anchor) is bytes and len(expected_anchor) <= 16384, "AUTHORITY_ANCHOR_INVALID")
        anchor = b.decode(expected_anchor)
        names = {"contract", "store_id", "selection_sha256", "directory_device", "directory_inode",
                 "db_device", "db_inode", "lock_device", "lock_inode"}
        s.need(type(anchor) is dict and set(anchor) == names and anchor["contract"] == CONTRACT
             and jwt.text(anchor["store_id"]) and anchor["selection_sha256"] == sha(b.encode(verifier.selection.descriptor()))
             and all(type(anchor[key]) is int and anchor[key] >= 0 for key in names if key.endswith(("_device", "_inode"))),
             "AUTHORITY_ANCHOR_INVALID")
        self.directory, self.verifier, self.anchor = Path(directory).absolute(), verifier, expected_anchor
        self._anchor, self.clock = anchor, clock
        self._pid, self._lock, self._local = os.getpid(), RLock(), local()
        self._configuration = self.configuration_id()
        with self._gate(), self._connection() as connection:
            self._row(connection)

    def configuration_id(self):
        s.need(os.getpid() == self._pid, "AUTHORITY_FORK_REOPEN_REQUIRED")
        s.class_identity(self, sys.modules[__name__])
        return b.object_hash({"contract": CONTRACT, "anchor": b.digest(self.anchor),
            "verifier": self.verifier.configuration_id(), "source": s.module_identity(sys.modules[__name__])})

    def _files(self):
        for name, path in (("directory", self.directory), ("db", self.directory / "authority.sqlite3"),
                           ("lock", self.directory / "authority.lock")):
            info = path.lstat()
            kind = stat.S_ISDIR(info.st_mode) if name == "directory" else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            s.need(kind and (info.st_dev, info.st_ino) == (self._anchor[name + "_device"], self._anchor[name + "_inode"]),
                   "AUTHORITY_STORE_REPLACED")
        for suffix in ("-journal", "-wal", "-shm"):
            path = self.directory / ("authority.sqlite3" + suffix)
            if os.path.lexists(path):
                info = path.lstat()
                s.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "AUTHORITY_SIDECAR_INVALID")

    @contextmanager
    def _gate(self):
        s.need(self.configuration_id() == self._configuration, "AUTHORITY_CONFIGURATION_CHANGED")
        s.need(not getattr(self._local, "active", False), "AUTHORITY_REENTRANT")
        s.need(self._lock.acquire(blocking=False), "AUTHORITY_BUSY")
        fd = None
        fd_guard, active_fds = _FD_GUARD, _ACTIVE_FDS
        try:
            try:
                self._files()
                with fd_guard:
                    fd = os.open(self.directory / "authority.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                    active_fds.add(fd)
                info = os.fstat(fd)
                s.need((info.st_dev, info.st_ino) == (self._anchor["lock_device"], self._anchor["lock_inode"]),
                       "AUTHORITY_STORE_REPLACED")
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise s.AuthorityError("AUTHORITY_BUSY") from None
                self._files()
            except OSError:
                raise s.AuthorityError("AUTHORITY_STORE_UNAVAILABLE") from None
            self._local.active = True
            yield
        finally:
            if os.getpid() == self._pid:
                self._local.active = False
                try:
                    if fd is not None:
                        with fd_guard:
                            active_fds.discard(fd)
                            os.close(fd)
                finally:
                    self._lock.release()

    @contextmanager
    def _connection(self):
        connection = None
        try:
            self._files()
            connection = sqlite3.connect((self.directory / "authority.sqlite3").as_uri() + "?mode=rw",
                uri=True, isolation_level=None, timeout=2.0)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA synchronous=EXTRA")
            connection.execute("PRAGMA trusted_schema=OFF")
            s.need(connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
                 and connection.execute("PRAGMA synchronous").fetchone()[0] == 3
                 and connection.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
                 and connection.execute("PRAGMA user_version").fetchone()[0] == 1, "AUTHORITY_DB_MODE_INVALID")
            schema = {row["name"]: " ".join(row["sql"].split()) for row in connection.execute(
                "SELECT name,sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'")}
            s.need(schema == TABLES, "AUTHORITY_SCHEMA_CHANGED")
            identity = connection.execute("SELECT * FROM identity").fetchall()
            s.need(len(identity) == 1 and identity[0]["singleton"] == 1
                 and identity[0]["store_id"] == self._anchor["store_id"]
                 and identity[0]["selection"] == b.encode(self.verifier.selection.descriptor()), "AUTHORITY_IDENTITY_CHANGED")
            s.need(connection.execute("PRAGMA quick_check").fetchone()[0] == "ok", "AUTHORITY_STATE_CORRUPT")
            yield connection
        except (sqlite3.Error, OSError):
            raise s.AuthorityError("AUTHORITY_STORE_UNAVAILABLE") from None
        finally:
            if connection is not None:
                if connection.in_transaction:
                    connection.rollback()
                connection.close()

    def _row(self, connection):
        rows = connection.execute("SELECT * FROM state").fetchall()
        s.need(len(rows) == 1 and rows[0]["singleton"] == 1, "AUTHORITY_STATE_CORRUPT")
        row = rows[0]
        s.need(type(row["revision"]) is int and 0 <= row["revision"] <= s.MAX_REVISION
             and type(row["issued_at"]) is int and 0 <= row["issued_at"] <= jwt.MAX_NUMERIC_DATE
             and row["conflict"] in (0, 1) and row["unavailable"] in (0, 1), "AUTHORITY_STATE_CORRUPT")
        if row["clock_high"] is None:
            s.need(row["revision"] == 0, "AUTHORITY_STATE_CORRUPT")
        else:
            high = b.core.safe_parse_time(row["clock_high"])
            s.need(high is not None and b.core.iso(high) == row["clock_high"]
                 and (row["revision"] == 0 or high >= jwt.numeric_date(row["issued_at"])),
                 "AUTHORITY_STATE_CORRUPT")
        if row["revision"] == 0:
            s.need(all(row[key] is None for key in ("raw", "raw_sha256", "payload_sha256"))
                 and row["issued_at"] == 0 and row["unavailable"] == 1 and row["conflict"] == 0,
                 "AUTHORITY_STATE_CORRUPT")
        else:
            s.need(type(row["raw"]) is bytes and 0 < len(row["raw"]) <= jwt.MAX_TOKEN_BYTES
                 and row["raw_sha256"] == sha(row["raw"])
                 and type(row["payload_sha256"]) is str and len(row["payload_sha256"]) == 64,
                 "AUTHORITY_STATE_CORRUPT")
            try:
                parts = row["raw"].split(b".")
                s.need(len(parts) == 3, "AUTHORITY_STATE_CORRUPT")
                payload = b.decode(jwt.decode_segment(parts[1], jwt.MAX_TOKEN_BYTES))
                s.need(type(payload) is dict and set(payload) == s.CLAIMS
                     and type(payload["revision"]) is int and payload["revision"] == row["revision"]
                     and type(payload["iat"]) is int and payload["iat"] == row["issued_at"]
                     and sha(b.encode(payload)) == row["payload_sha256"], "AUTHORITY_STATE_CORRUPT")
            except (b.Invalid, jwt.RuntimeJwtError):
                raise s.AuthorityError("AUTHORITY_STATE_CORRUPT") from None
        return row

    def _observe(self):
        try:
            now = self.clock()
            s.need(isinstance(now, datetime) and now.tzinfo is not None and now.utcoffset() is not None,
                   "AUTHORITY_CLOCK_INVALID")
            now = now.astimezone(timezone.utc)
        except Exception:
            raise s.AuthorityError("AUTHORITY_CLOCK_INVALID") from None
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._row(connection)
            if row["clock_high"] is not None:
                high = b.core.safe_parse_time(row["clock_high"])
                s.need(high is not None, "AUTHORITY_STATE_CORRUPT")
                s.need(now >= high, "AUTHORITY_CLOCK_ROLLBACK")
            connection.execute("UPDATE state SET clock_high=? WHERE singleton=1", (b.core.iso(now),))
            connection.commit()
        return now

    def accept(self, raw: bytes):
        with self._gate():
            checked = self.verifier.verify(raw, self._observe())
            self.verifier.check_window(checked, self._observe())
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                previous = self._row(connection)
                s.need(checked.revision >= previous["revision"], "AUTHORITY_ROLLBACK")
                payload_sha = sha(checked.payload)
                if checked.revision == previous["revision"] and payload_sha != previous["payload_sha256"]:
                    connection.execute("UPDATE state SET conflict=1,unavailable=1 WHERE singleton=1")
                    connection.commit()
                    raise s.AuthorityError("AUTHORITY_REVISION_CONFLICT")
                s.need(checked.issued_at >= previous["issued_at"], "AUTHORITY_ISSUANCE_ROLLBACK")
                s.need(not previous["conflict"] or checked.revision > previous["revision"], "AUTHORITY_REVISION_CONFLICT")
                connection.execute("UPDATE state SET revision=?,issued_at=?,raw=?,raw_sha256=?,payload_sha256=?,conflict=0,unavailable=0 WHERE singleton=1",
                    (checked.revision, checked.issued_at, raw, sha(raw), payload_sha))
                connection.commit()
            return {"revision": checked.revision, "payload_digest": b.digest(checked.payload)}

    def mark_unavailable(self):
        with self._gate():
            self._observe()
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._row(connection)
                connection.execute("UPDATE state SET unavailable=1 WHERE singleton=1")
                connection.commit()

    def refresh(self, fetch):
        s.need(callable(fetch), "AUTHORITY_FETCH_INVALID")
        try:
            raw = fetch()
            return self.accept(raw)
        except Exception:
            try:
                self.mark_unavailable()
            except s.AuthorityError:
                # A busy/inaccessible store cannot acknowledge an update.
                # The original refresh still fails; no success is reported.
                pass
            raise s.AuthorityError("AUTHORITY_REFRESH_FAILED") from None

    @contextmanager
    def lease(self):
        with self._gate():
            now = self._observe()
            with self._connection() as connection:
                row = self._row(connection)
            s.need(not row["conflict"] and not row["unavailable"] and row["raw"] is not None,
                   "AUTHORITY_NOT_AVAILABLE")
            checked = self.verifier.verify(row["raw"], now)
            s.need(checked.revision == row["revision"] and checked.issued_at == row["issued_at"]
                 and sha(checked.payload) == row["payload_sha256"], "AUTHORITY_STATE_CORRUPT")
            self.verifier.check_window(checked, self._observe())
            self._local.snapshot = checked
            try:
                yield
            finally:
                del self._local.snapshot

    def _current(self):
        s.need(self.configuration_id() == self._configuration, "AUTHORITY_CONFIGURATION_CHANGED")
        checked = getattr(self._local, "snapshot", None)
        s.need(getattr(self._local, "active", False) and checked is not None, "AUTHORITY_LEASE_REQUIRED")
        self.verifier.check_window(checked, self._observe())
        return checked

    def runtime_policy(self):
        return self._current().runtime_policy

    def authority_policy(self):
        return self._current().authority_policy

    def now(self):
        self._current()
        return self._observe()

    def status(self):
        with self._gate(), self._connection() as connection:
            row = self._row(connection)
            return {"revision": row["revision"], "conflict": bool(row["conflict"]),
                    "unavailable": bool(row["unavailable"]), "clock_high": row["clock_high"],
                    "snapshot_sha256": row["raw_sha256"]}
