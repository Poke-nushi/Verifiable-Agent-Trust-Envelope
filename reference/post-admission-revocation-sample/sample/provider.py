"""Local provider: verified status and acceptance share one SQLite write order.

Only submit can create effects. No listener, credential lookup, or automatic retry.
Trusted local code/configuration/OS and an intact DB are explicit prerequisites.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import sqlite3
import stat
import time
import uuid

from contract import (MAX, PROFILE, Selection, VerificationUnavailable, b64, decode, encode, exact, exclusive_write,
                      integer, need, safe_read, sha, unb64, unurl64)

APPLICATION_ID = 1447121989


def _directory(path):
    need(stat.S_ISDIR(path.lstat().st_mode), "unsafe directory")


def initialize(case: Path, selection_raw: bytes, *, journal="WAL"):
    """Explicit initialization of a NEW private test case only; never recovery."""
    Selection(selection_raw)
    need(journal in ("WAL", "DELETE"), "unsupported journal mode")
    case.mkdir(mode=0o700, parents=False, exist_ok=False)
    (case / "sandbox").mkdir(mode=0o700)
    exclusive_write(case / "selection.json", selection_raw)
    exclusive_write(case / "worker.lock", b"")
    db = case / "provider.sqlite3"
    c = sqlite3.connect(db, isolation_level=None)
    store_id = str(uuid.uuid4())
    try:
        c.execute(f"PRAGMA journal_mode={journal}")
        c.execute("PRAGMA synchronous=FULL")
        c.execute(f"PRAGMA application_id={APPLICATION_ID}")
        c.executescript("""
          CREATE TABLE identity (store_id TEXT PRIMARY KEY, selection_sha256 TEXT NOT NULL);
          CREATE TABLE state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), sequence INTEGER,
            raw BLOB, signing_input_sha256 TEXT, revoked INTEGER NOT NULL,
            conflict INTEGER NOT NULL, clock_high INTEGER NOT NULL, clock_bad INTEGER NOT NULL);
          INSERT INTO state VALUES (1,0,NULL,NULL,0,0,0,0);
          CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, body BLOB NOT NULL);
          CREATE TABLE attempts (attempt_id TEXT PRIMARY KEY, boot TEXT NOT NULL, nonce TEXT UNIQUE NOT NULL,
            created INTEGER NOT NULL, state TEXT NOT NULL, decision BLOB);
          CREATE TABLE accepted (operation_key TEXT PRIMARY KEY, nonce TEXT UNIQUE NOT NULL,
            attempt_id TEXT UNIQUE NOT NULL, event_id INTEGER UNIQUE NOT NULL, body BLOB NOT NULL);
          CREATE TABLE native (operation_key TEXT PRIMARY KEY, body BLOB NOT NULL);
        """)
        c.execute("INSERT INTO identity VALUES (?,?)", (store_id, sha(selection_raw)))
        c.execute("INSERT INTO events(kind,body) VALUES (?,?)", ("initialized", encode({
            "store_id": store_id, "selection_sha256": sha(selection_raw)})))
    finally:
        c.close()
    info = db.stat()
    exclusive_write(case / "anchor.json", encode({"store_id": store_id, "selection_sha256": sha(selection_raw),
                                                   "db_dev": info.st_dev, "db_ino": info.st_ino}))


class Provider:
    def __init__(self, case: Path, *, clock=None, hook=None, timeout=2.0):
        self.case = case.absolute()
        _directory(self.case)
        self.selection = Selection(safe_read(self.case / "selection.json"))
        self.anchor_raw = safe_read(self.case / "anchor.json")
        self.anchor = decode(self.anchor_raw)
        exact(self.anchor, {"store_id", "selection_sha256", "db_dev", "db_ino"})
        need(type(self.anchor["store_id"]) is str and bool(self.anchor["store_id"]), "invalid store identity")
        need(self.anchor["selection_sha256"] == sha(self.selection.raw), "anchor selection mismatch")
        need(all(type(self.anchor[key]) is int and self.anchor[key] >= 0 for key in ("db_dev", "db_ino")),
             "invalid DB identity")
        self.boot = str(uuid.uuid4())
        self.clock = clock or (lambda: int(time.time()))
        # Private deterministic test seam, absent from the CLI: exceptions/delays at named boundaries.
        self.hook = hook or (lambda point: None)
        self.timeout = timeout
        with self.connect():
            pass

    @contextmanager
    def connect(self):
        _directory(self.case); _directory(self.case / "sandbox")
        need(safe_read(self.case / "selection.json") == self.selection.raw and
             safe_read(self.case / "anchor.json") == self.anchor_raw, "selection/anchor changed")
        db = self.case / "provider.sqlite3"
        info = db.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
             (info.st_dev, info.st_ino) == (self.anchor["db_dev"], self.anchor["db_ino"]),
             "DB missing/replaced/unsafe")
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(db) + suffix)
            if os.path.lexists(sidecar):
                meta = sidecar.lstat()
                need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1, "unsafe SQLite sidecar")
        c = sqlite3.connect(db.as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=self.timeout)
        c.row_factory = sqlite3.Row
        try:
            c.execute("PRAGMA synchronous=FULL")
            need(c.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID, "wrong DB application")
            identity = c.execute("SELECT * FROM identity").fetchall()
            need(len(identity) == 1 and identity[0]["store_id"] == self.anchor["store_id"] and
                 identity[0]["selection_sha256"] == sha(self.selection.raw), "wrong DB identity")
            need(c.execute("PRAGMA quick_check").fetchone()[0] == "ok", "DB integrity failed")
            need(c.execute("SELECT count(*) FROM state").fetchone()[0] == 1, "missing state")
            yield c
        finally:
            # COMMIT busy can leave a live writer. Never return it to callers or retry COMMIT.
            if c.in_transaction:
                c.rollback()
            c.close()

    @contextmanager
    def worker(self, *, shared=False):
        fd = os.open(self.case / "worker.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "unsafe worker lock")
            fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)  # Releases this worker's flock; process death does so too.

    @staticmethod
    def event(c, kind, body):
        return c.execute("INSERT INTO events(kind,body) VALUES (?,?)", (kind, encode(body))).lastrowid

    def clock_check(self, c, now):
        integer(now)
        s = c.execute("SELECT * FROM state").fetchone()
        bad = bool(s["clock_bad"] or now < s["clock_high"])
        c.execute("UPDATE state SET clock_high=?,clock_bad=?", (max(now, s["clock_high"]), int(bad)))
        self.event(c, "clock", {"checked_at": now, "clock_high": max(now, s["clock_high"]), "clock_bad": bad})
        return not bad

    def merge_status(self, c, verified, now, source):
        """Called only on cryptographically verified, authority/target-valid originals."""
        s = verified.payload
        current = c.execute("SELECT * FROM state").fetchone()
        seq, conflict = s["sequence"], bool(current["conflict"])
        revoked = bool(current["revoked"] or s["state"] == "revoked")
        # The latest version selects current state; it cannot replace conflict
        # evidence for older versions. Replay the authenticated event history
        # inside this write transaction, including after a provider restart.
        identities = {seq: verified.signing_input_sha256}
        if not conflict:
            for row in c.execute("SELECT body FROM events WHERE kind='status' ORDER BY id"):
                previous = decode(row["body"])
                original = unb64(previous["raw"]).decode("ascii").split(".")
                version = decode(unurl64(original[1]))["sequence"]
                identity = previous["signing_input_sha256"]
                if version in identities and identities[version] != identity:
                    conflict = True
                    break
                identities[version] = identity
        if seq > current["sequence"]:
            c.execute("UPDATE state SET sequence=?,raw=?,signing_input_sha256=?",
                      (seq, verified.raw, verified.signing_input_sha256))
        c.execute("UPDATE state SET revoked=?,conflict=?", (int(revoked), int(conflict)))
        self.event(c, "status", {"raw": b64(verified.raw), "raw_sha256": verified.raw_sha256,
                    "signing_input_sha256": verified.signing_input_sha256, "checked_at": now,
                    "source": source, "revoked": revoked, "conflict": conflict})

    def notify(self, raw: bytes):
        """Authenticated notification may stop execution; it never creates a pull ticket."""
        try:
            authenticated = self.selection.authenticate_status(raw)
            with self.connect() as c:
                c.execute("BEGIN IMMEDIATE")
                now = integer(self.clock())
                verified = self.selection.status_at(authenticated, now)
                self.clock_check(c, now)
                self.merge_status(c, verified, now, "notification")
                c.commit()
            return {"status": "stored"}
        except (ValueError, VerificationUnavailable, OSError, sqlite3.Error):
            return {"status": "not_stored"}  # No false revocation assertion.

    def challenge(self):
        """Receiver-generated attempt and nonce. Old-instance attempts cannot be submitted."""
        with self.worker(), self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            now = integer(self.clock())
            okay = self.clock_check(c, now)
            attempt = {"attempt_id": str(uuid.uuid4()), "nonce": str(uuid.uuid4()), "created": now}
            if not okay:
                c.commit()
                raise ValueError("clock_uncertain")
            c.execute("INSERT INTO attempts VALUES (?,?,?,?,?,NULL)",
                      (attempt["attempt_id"], self.boot, attempt["nonce"], now, "pending"))
            self.event(c, "challenge", attempt)
            c.commit()
            return attempt

    def submit(self, attempt_id: str, proof_raw: bytes):
        """One fresh local pull, one acceptance transaction, then at most one file effect."""
        try:
            with self.worker():
                return self._submit(attempt_id, proof_raw)
        except (ValueError, OSError, sqlite3.Error, RuntimeError):
            # This is NEVER an automatic retry or a statement that no effect occurred.
            return {"status": "unknown", "next": "query", "operation_key": self.selection.operation["operation_key"]}

    def _submit(self, attempt_id, proof_raw):
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            need(row is not None and row["boot"] == self.boot and row["state"] == "pending",
                 "attempt unavailable or already consumed")
            attempt = dict(row)
            c.execute("UPDATE attempts SET state='consumed' WHERE attempt_id=?", (attempt_id,))
            self.event(c, "consumed", {"attempt_id": attempt_id})
            c.commit()  # Every attempted submission consumes its ticket, even on invalid proof/pull.
        need(type(proof_raw) is bytes and len(proof_raw) <= 65536, "invalid proof bytes")
        pull = None
        try:
            pull = safe_read(self.case / "authority-status.jws", 65536)
        except (ValueError, OSError):
            pass  # Preserve an invalid original for the refusal record; never trust it as status.
        authenticated_status = authenticated_proof = None
        unavailable = {}
        # Cryptography runs before the acceptance write lock. Time/binding checks use the
        # freshly selected clock after verification AND lock acquisition below.
        if pull is not None:
            try:
                authenticated_status = self.selection.authenticate_status(pull)
            except VerificationUnavailable as exc:
                unavailable["status"] = exc.code
            except ValueError:
                pass
        try:
            authenticated_proof = self.selection.authenticate_proof(proof_raw)
        except VerificationUnavailable as exc:
            unavailable["proof"] = exc.code
        except ValueError:
            pass
        self.hook("after_pull")
        with self.connect() as c:
            self.hook("before_accept_lock")
            c.execute("BEGIN IMMEDIATE")
            now = integer(self.clock())  # Re-read after lock acquisition, never the pre-gate clock.
            clock_ok = self.clock_check(c, now)
            verified = None
            if authenticated_status is not None:
                try:
                    verified = self.selection.status_at(authenticated_status, now)
                    self.merge_status(c, verified, now, "pull:" + attempt_id)
                except ValueError:
                    pass
            try:
                need(authenticated_proof is not None, "proof not authenticated")
                self.selection.proof_at(authenticated_proof, attempt, now)
                proof_ok = True
            except ValueError:
                proof_ok = False
            state = c.execute("SELECT * FROM state").fetchone()
            original = {**self.selection.binding(), "attempt_id": attempt_id, "nonce": attempt["nonce"],
                        "checked_at": now, "proof": b64(proof_raw), "proof_sha256": sha(proof_raw),
                        "pull": b64(pull) if pull is not None else None,
                        "pull_sha256": sha(pull) if pull is not None else None,
                        "pull_outcome": "received" if pull is not None else "unavailable",
                        "status_sequence": state["sequence"], "store_id": self.anchor["store_id"]}
            if unavailable:
                # Keep any authenticated status/clock update. This observation
                # is about the verifier, not a refusal inferred from signed input.
                self.event(c, "verification_unavailable", {**original, "unavailable_checks": unavailable})
                self.hook("before_commit")
                c.commit()
                self.hook("after_commit")
                return {"status": "unknown", "next": "query", "operation_key": original["operation_key"]}
            old = c.execute("SELECT body FROM accepted WHERE operation_key=?",
                            (self.selection.operation["operation_key"],)).fetchone()
            reason = "accepted"
            output_before = None
            if old:
                reason = "already_accepted"
            elif not clock_ok:
                reason = "clock_uncertain"
            elif not proof_ok:
                reason = "proof_invalid"
            elif not self.selection.admission_current(now):
                reason = "admission_expired"
            elif now < attempt["created"] or now - attempt["created"] >= 60:
                reason = "attempt_expired"
            elif state["conflict"]:
                reason = "authority_conflict"
            elif state["revoked"]:
                reason = "revoked"
            elif verified is None:
                reason = "status_unavailable"
            elif verified.payload["sequence"] != state["sequence"]:
                reason = "status_rollback"
            elif not self.selection.fresh(verified.payload, now):
                reason = "status_stale"
            elif verified.payload["state"] != "active":
                reason = "status_not_active"
            else:
                output_before = self.observe()
                if output_before:
                    reason = "output_not_empty"
            decision = {**original, "reason": reason, "output_before_acceptance": output_before}
            event_id = self.event(c, "decision", decision)
            c.execute("UPDATE attempts SET state='decided',decision=? WHERE attempt_id=?", (encode(decision), attempt_id))
            if reason == "accepted":
                c.execute("INSERT INTO accepted VALUES (?,?,?,?,?)", (self.selection.operation["operation_key"],
                          attempt["nonce"], attempt_id, event_id, encode(decision)))
            self.hook("before_commit")
            c.commit()
            self.hook("after_commit")  # Simulate loss before the caller learns commit succeeded.
        if reason != "accepted":
            next_step = "query" if old else ("stop" if reason in {"revoked", "authority_conflict", "clock_uncertain"} else "new_attempt")
            return {"status": "denied_before_acceptance", "reason": reason, "next": next_step}
        self.hook("before_effect")
        # The worker flock remains held from before consumption through native-result storage.
        # No other public method or command dispatches a file effect or resumes this block.
        fd = os.open(self.case / "sandbox", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for i, item in enumerate(self.selection.operation["target"]["files"]):
                out = os.open(item["name"], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=fd)
                with os.fdopen(out, "wb") as f:
                    f.write(item["text"].encode("utf-8")); f.flush(); os.fsync(f.fileno())
                self.hook("after_file_" + str(i + 1))
            os.fsync(fd)
        finally:
            os.close(fd)
        native = {"operation_key": decision["operation_key"], "attempt_id": attempt_id,
                  "admission_sha256": decision["admission_sha256"], "input_sha256": decision["input_sha256"],
                  "proof_sha256": decision["proof_sha256"], "pull_sha256": decision["pull_sha256"],
                  "acceptance_event_id": event_id, "files": self.observe(), "outcome": "success"}
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("INSERT INTO native VALUES (?,?)", (decision["operation_key"], encode(native)))
            self.event(c, "native", native)
            c.commit()
        self.hook("after_native")
        return {"status": "effect_observed", "native": native}

    def observe(self):
        _directory(self.case / "sandbox")
        allowed = {x["name"] for x in self.selection.operation["target"]["files"]}
        files = []
        for path in sorted((self.case / "sandbox").iterdir()):
            need(path.name in allowed, "unexpected output")
            raw = safe_read(path, 4096)
            files.append({"name": path.name, "sha256": sha(raw), "size": len(raw)})
        return files

    def _snapshot(self):
        # Called with shared/exclusive worker flock: no effect worker is alive during observation.
        with self.connect() as c:
            c.execute("BEGIN")  # Always a new connection/snapshot, including WAL.
            events = [{"id": r["id"], "kind": r["kind"], "body": decode(r["body"])}
                      for r in c.execute("SELECT * FROM events ORDER BY id")]
            accepted = c.execute("SELECT * FROM accepted").fetchall()
            native = c.execute("SELECT body FROM native").fetchall()
            need(len(accepted) <= 1 and len(native) <= 1, "unexpected operation inventory")
            a = None if not accepted else {"event_id": accepted[0]["event_id"], "body": decode(accepted[0]["body"])}
            n = None if not native else decode(native[0]["body"])
            files = self.observe()
            result = {"status": "unknown", "accepted": a is not None, "files": files, "native": n}
            if a is None and n is None and files == []:
                result["status"] = "not_accepted"
            elif a is not None and n is not None:
                body = a["body"]
                need(n["acceptance_event_id"] == a["event_id"] and all(n[k] == body[k] for k in
                     ("operation_key", "attempt_id", "admission_sha256", "input_sha256", "proof_sha256", "pull_sha256")),
                     "native acceptance binding mismatch")
                expected = [{"name": x["name"], "sha256": sha(x["text"].encode()), "size": len(x["text"].encode())}
                            for x in self.selection.operation["target"]["files"]]
                if n["outcome"] == "success" and n["files"] == files == expected:
                    result["status"] = "effect_observed"
            return {"profile": PROFILE, "store_id": self.anchor["store_id"], "selection": b64(self.selection.raw),
                    "selection_sha256": sha(self.selection.raw), "events": events, "acceptance": a,
                    "native": n, "observation": result, "worker_fenced": True}

    def query(self):
        try:
            with self.worker(shared=True):
                return self._snapshot()["observation"]
        except (ValueError, OSError, sqlite3.Error):
            return {"status": "unknown", "accepted": None, "files": None, "native": None}

    def export(self, destination: Path):
        """Read-only re-export is safe; publish the complete file atomically, never re-execute."""
        with self.worker(shared=True):
            bundle = self._snapshot()
            bundle["file_bytes"] = {f["name"]: b64(safe_read(self.case / "sandbox" / f["name"], 4096))
                                    for f in bundle["observation"]["files"]}
            raw = encode(bundle)
            need(len(raw) <= MAX, "export exceeds local demo size bound")
            temporary = destination.with_name("." + destination.name + "." + str(uuid.uuid4()))
            try:
                exclusive_write(temporary, raw)
                self.hook("before_export_publish")
                os.link(temporary, destination, follow_symlinks=False)
            finally:
                temporary.unlink(missing_ok=True)
            return {"path": str(destination), "raw_sha256": sha(raw)}
