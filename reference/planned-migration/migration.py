"""Offline, one-host migration of the selected authority and dispatch stores.

The migration journal and six participating databases commit together. All files
and configuration are trusted operator state. See CONTRACT.md before use.
"""
from contextlib import contextmanager, ExitStack
from dataclasses import replace
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reference/authority-updates"))
import authority_store as authority
import snapshot as s

b, d = s.b, s.b.durable_state_module()
CONTRACT = "vate-local-planned-migration-v1"
ROLES = ("publisher", "recipient", "dispatch")
JOURNAL_TABLE = "CREATE TABLE journal (singleton INTEGER PRIMARY KEY CHECK(singleton=1), plan BLOB NOT NULL, plan_sha256 TEXT NOT NULL, result BLOB, result_sha256 TEXT)"
APPLICATION_ID = 1447121991
BASELINE = "675847669851070728431fd1ebd1415f57ad411e"
_source = Path(__file__).read_bytes()
LOADED_SOURCE_SHA256 = (hashlib.sha256(_source).hexdigest() if hasattr(sys, "_getframe")
    and sys._getframe().f_code == compile(_source, sys._getframe().f_code.co_filename,
        "exec", dont_inherit=True, optimize=sys.flags.optimize) else None)
del _source

# Reuse the authority store's generation-local fork cleanup. A child closes its
# inherited references without unlocking the parent's migration/authority locks.
_FD_GUARD, _ACTIVE_FDS = authority._fd_registry()


class MigrationError(ValueError):
    def __init__(self, cause):
        self.cause = cause
        super().__init__(cause)


def need(condition, cause):
    if not condition:
        raise MigrationError(cause)


def canonical(raw, *, max_bytes=1024 * 1024):
    need(type(raw) is bytes and len(raw) <= max_bytes, "MIGRATION_RECORD_INVALID")
    value = b.decode(raw)
    need(b.encode(value) == raw, "MIGRATION_RECORD_INVALID")
    return value


def program(root=ROOT):
    need(LOADED_SOURCE_SHA256 is not None and d.sha(Path(__file__).read_bytes()) == LOADED_SOURCE_SHA256,
         "MIGRATION_PROGRAM_CHANGED")
    return {name: d.sha((Path(root) / name).read_bytes()) for name in d.MIGRATION_SOURCES}


def source_program(root):
    supported = json.loads(Path(__file__).with_name("supported-source.json").read_bytes())
    need(supported["source_commit"] == BASELINE and set(supported["files"]) == set(d.MIGRATION_SOURCES[:-2]),
         "MIGRATION_SOURCE_UNSUPPORTED")
    need(all(d.sha((Path(root) / name).read_bytes()) == digest for name, digest in supported["files"].items()),
         "MIGRATION_SOURCE_UNSUPPORTED")
    return supported


def selection(value):
    options = dict(value)
    options["public_key_spki"] = s.public_key(options.pop("public_key_spki_base64"))
    result = s.AuthoritySelection(**options)
    result.descriptor()
    return result


def dbname(role):
    return "state.sqlite3" if role == "dispatch" else "authority.sqlite3"


def table_shapes(role):
    return {name: " ".join(sql.split()) for name, sql in
            (d.TABLES if role == "dispatch" else authority.TABLES).items()}


def schema(connection, alias):
    return {row["name"]: " ".join(row["sql"].split()) for row in connection.execute(
        f"SELECT name,sql FROM {alias}.sqlite_master WHERE name NOT GLOB 'sqlite_*'")}


def inspect_files(directory, anchor, *, role=None):
    directory = Path(directory)
    names = [("directory", directory), ("db", directory / (dbname(role) if role else "migration.sqlite3"))]
    if role != "dispatch":
        names.append(("lock", directory / ("authority.lock" if role else "migration.lock")))
    for prefix, path in names:
        info = path.lstat()
        need((stat.S_ISDIR(info.st_mode) if prefix == "directory" else
              stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
             and info.st_uid == os.getuid() and not info.st_mode & 0o077
             and (info.st_dev, info.st_ino) == (anchor[prefix + "_device"], anchor[prefix + "_inode"]),
             "MIGRATION_FILE_IDENTITY_CHANGED")
    db = names[1][1]
    for path in db.parent.glob(db.name + "-*"):
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid(),
             "MIGRATION_SIDECAR_INVALID")
    return db


def physical_anchor(directory, *, role=None):
    names = [("directory", directory), ("db", directory / (dbname(role) if role else "migration.sqlite3"))]
    if role != "dispatch":
        names.append(("lock", directory / ("authority.lock" if role else "migration.lock")))
    result = {}
    for prefix, path in names:
        info = path.lstat()
        result.update({prefix + "_device": info.st_dev, prefix + "_inode": info.st_ino})
    return result


def private_file(path):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    os.close(fd)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def locked(path, expected_device, expected_inode):
    owner = os.getpid()
    fd_guard, active_fds = _FD_GUARD, _ACTIVE_FDS
    with fd_guard:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        active_fds.add(fd)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and (info.st_dev, info.st_ino) == (expected_device, expected_inode), "MIGRATION_LOCK_CHANGED")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise MigrationError("MIGRATION_BUSY") from None
        yield
    finally:
        if os.getpid() == owner:
            with fd_guard:
                active_fds.discard(fd)
                os.close(fd)


def ordered_rows(connection, alias, table):
    # Table/alias identifiers are constants selected by this module, not input.
    order = {"identity": "singleton", "state": "singleton", "admissions": "request_id", "operations": "operation_id"}[table]
    return (dict(row) for row in connection.execute(f"SELECT * FROM {alias}.{table} ORDER BY {order}"))


def rows(connection, alias, table):
    return list(ordered_rows(connection, alias, table))


def history(connection, alias, role):
    # Preserve the original sorted compact JSON byte stream and SHA-256 basis,
    # without applying one external artifact's size limit to the whole store.
    encoder = json.JSONEncoder(allow_nan=False, ensure_ascii=True, sort_keys=True,
                               separators=(",", ":"))
    digest = hashlib.sha256()
    digest.update(b"{")
    for index, table in enumerate(sorted(table_shapes(role))):
        if index:
            digest.update(b",")
        digest.update(encoder.encode(table).encode("ascii") + b":[")
        for position, row in enumerate(ordered_rows(connection, alias, table)):
            if position:
                digest.update(b",")
            value = {key: {"bytes_hex": item.hex()} if type(item) is bytes else item
                     for key, item in row.items()}
            b._json_domain(value)
            for chunk in encoder.iterencode(value):
                digest.update(chunk.encode("ascii"))
        digest.update(b"]")
    digest.update(b"}")
    return digest.hexdigest()


class PlannedMigration:
    @classmethod
    def prepare(cls, directory, *, source_root, publisher, recipient, dispatch, new_selection):
        """Explicit allocation only; source stores are read and never changed here."""
        need(type(publisher) is authority.AuthorityStore and type(recipient) is authority.AuthorityStore
             and type(dispatch) is d.DurableStateStore and type(new_selection) is s.AuthoritySelection,
             "MIGRATION_CONFIGURATION_INVALID")
        source_pins, target_pins = source_program(source_root), program()
        old_selection = publisher.verifier.selection
        recipient_selection = recipient.verifier.selection
        need(replace(old_selection, minimum_revision=recipient_selection.minimum_revision) == recipient_selection,
             "MIGRATION_AUTHORITY_MISMATCH")
        new_selection.descriptor()
        need(all(getattr(old_selection, name) == getattr(new_selection, name)
                 for name in ("issuer", "audience", "scope", "epoch", "max_snapshot_age_seconds"))
             and old_selection.kid != new_selection.kid
             and old_selection.public_key_spki != new_selection.public_key_spki,
             "MIGRATION_AUTHORITY_MISMATCH")
        need(dispatch.verifier_id == old_selection.audience, "MIGRATION_AUTHORITY_MISMATCH")
        directory = Path(directory).absolute()
        need(directory.parent.resolve(strict=True) == directory.parent, "MIGRATION_PATH_INVALID")
        stores = {"publisher": publisher, "recipient": recipient, "dispatch": dispatch}
        entries = {}
        for role, store in stores.items():
            anchor = canonical(store.anchor)
            path = store.directory.resolve(strict=True)
            need(path == store.directory and directory != path and not directory.is_relative_to(path)
                 and not path.is_relative_to(directory), "MIGRATION_PATH_INVALID")
            inspect_files(path, anchor, role=role)
            entries[role] = {"source": str(path), "source_anchor": anchor}
        identities = {(e["source_anchor"]["db_device"], e["source_anchor"]["db_inode"]) for e in entries.values()}
        need(len(identities) == 3 and len({device for device, inode in identities}) == 1
             and directory.parent.stat().st_dev == next(iter(identities))[0], "MIGRATION_FILESYSTEM_UNSUPPORTED")
        publisher.status(); recipient.status()
        with dispatch._connection():
            pass
        directory.mkdir(mode=0o700, exist_ok=False)
        private_file(directory / "migration.sqlite3")
        private_file(directory / "migration.lock")
        migration_id = str(uuid.uuid4())
        for role in ROLES:
            target = directory / role
            target.mkdir(mode=0o700)
            private_file(target / dbname(role))
            if role != "dispatch":
                private_file(target / "authority.lock")
            anchor = physical_anchor(target, role=role)
            entries[role].update(target=str(target), target_physical=anchor)
            connection = sqlite3.connect(target / dbname(role), isolation_level=None)
            try:
                connection.execute("PRAGMA main.journal_mode=DELETE")
                connection.execute("PRAGMA main.synchronous=EXTRA")
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(d.MIGRATION_TABLE)
                connection.execute("INSERT INTO main.migration VALUES(1,?,'prepared',?,?)",
                    (migration_id, b.encode(anchor), b.encode(target_pins)))
                connection.commit()
            finally:
                connection.close()
            sync_directory(target)
        plan = {"contract": CONTRACT, "migration_id": migration_id, "stores": entries,
            "source_root": str(Path(source_root).resolve(strict=True)), "source_program": source_pins,
            "target_program": target_pins, "old_selection": old_selection.descriptor(),
            "recipient_selection": recipient_selection.descriptor(),
            "requested_selection": new_selection.descriptor(), "node": str(publisher.verifier.backend.node),
            "node_sha256": publisher.verifier.backend.node_sha256}
        connection = sqlite3.connect(directory / "migration.sqlite3", isolation_level=None)
        try:
            connection.execute("PRAGMA main.journal_mode=DELETE")
            connection.execute("PRAGMA main.synchronous=EXTRA")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(JOURNAL_TABLE)
            raw = b.encode(plan)
            connection.execute("INSERT INTO main.journal VALUES(1,?,?,NULL,NULL)", (raw, d.sha(raw)))
            connection.execute(f"PRAGMA main.application_id={APPLICATION_ID}")
            connection.execute("PRAGMA main.user_version=1")
            connection.commit()
        finally:
            connection.close()
        sync_directory(directory)
        sync_directory(directory.parent)
        anchor = {"contract": CONTRACT, "migration_id": migration_id, "plan_sha256": d.sha(raw),
                  **physical_anchor(directory)}
        return cls(directory, expected_anchor=b.encode(anchor))

    def __init__(self, directory, *, expected_anchor):
        self.directory = Path(directory).absolute()
        self.anchor = expected_anchor
        self._anchor = canonical(expected_anchor)
        need(type(self._anchor) is dict and set(self._anchor) == {"contract", "migration_id", "plan_sha256",
            "directory_device", "directory_inode", "db_device", "db_inode", "lock_device", "lock_inode"}
             and self._anchor["contract"] == CONTRACT, "MIGRATION_ANCHOR_INVALID")
        self._pid = os.getpid()
        inspect_files(self.directory, self._anchor)

    def _point(self, name):
        """Owned regression probes override this method to interrupt a transaction."""

    def run(self, *, old_signer, new_signer, clock=b.core.utc_now):
        """Commit one move, or read back that same committed move without recopying."""
        need(os.getpid() == self._pid, "MIGRATION_FORK_REOPEN_REQUIRED")
        try:
            return self._run(old_signer, new_signer, clock)
        except MigrationError:
            raise
        except Exception:
            raise MigrationError("MIGRATION_FAILED") from None

    def _run(self, old_signer, new_signer, clock):
        inspect_files(self.directory, self._anchor)
        with ExitStack() as stack:
            stack.enter_context(locked(self.directory / "migration.lock", self._anchor["lock_device"], self._anchor["lock_inode"]))
            connection = sqlite3.connect((self.directory / "migration.sqlite3").as_uri() + "?mode=rw",
                uri=True, isolation_level=None, timeout=2)
            stack.callback(connection.close)
            connection.row_factory = sqlite3.Row
            need(schema(connection, "main") == {"journal": JOURNAL_TABLE}
                 and connection.execute("PRAGMA main.application_id").fetchone()[0] == APPLICATION_ID
                 and connection.execute("PRAGMA main.user_version").fetchone()[0] == 1,
                 "MIGRATION_JOURNAL_INVALID")
            saved = connection.execute("SELECT * FROM main.journal").fetchall()
            need(len(saved) == 1 and saved[0]["singleton"] == 1
                 and d.sha(saved[0]["plan"]) == saved[0]["plan_sha256"] == self._anchor["plan_sha256"],
                 "MIGRATION_JOURNAL_INVALID")
            need((saved[0]["result"] is None and saved[0]["result_sha256"] is None)
                 or (type(saved[0]["result"]) is bytes
                     and d.sha(saved[0]["result"]) == saved[0]["result_sha256"]),
                 "MIGRATION_RESULT_CHANGED")
            plan = canonical(saved[0]["plan"])
            need(plan["contract"] == CONTRACT and plan["migration_id"] == self._anchor["migration_id"]
                 and plan["target_program"] == program()
                 and plan["source_program"] == source_program(plan["source_root"]), "MIGRATION_PROGRAM_CHANGED")
            for role in ("publisher", "recipient"):
                entry, anchor = plan["stores"][role], plan["stores"][role]["source_anchor"]
                inspect_files(entry["source"], anchor, role=role)
                stack.enter_context(locked(Path(entry["source"]) / "authority.lock", anchor["lock_device"], anchor["lock_inode"]))
            aliases = ["main"]
            for role in ROLES:
                entry = plan["stores"][role]
                for prefix, field in (("old", "source_anchor"), ("new", "target_physical")):
                    path = entry["source" if prefix == "old" else "target"]
                    db = inspect_files(path, entry[field], role=role)
                    alias = prefix + "_" + role
                    connection.execute(f"ATTACH DATABASE ? AS {alias}", (db.as_uri() + "?mode=rw",))
                    aliases.append(alias)
            for alias in aliases:
                need(connection.execute(f"PRAGMA {alias}.journal_mode").fetchone()[0] == "delete", "MIGRATION_DB_MODE_INVALID")
                connection.execute(f"PRAGMA {alias}.synchronous=EXTRA")
                connection.execute(f"PRAGMA {alias}.fullfsync=ON")
                need(connection.execute(f"PRAGMA {alias}.synchronous").fetchone()[0] == 3, "MIGRATION_DB_MODE_INVALID")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("BEGIN IMMEDIATE")
            # No data is inspected outside this common write reservation.
            for alias in aliases:
                need(connection.execute(f"PRAGMA {alias}.quick_check").fetchone()[0] == "ok", "MIGRATION_DATA_CORRUPT")
            if saved[0]["result"] is not None:
                result = canonical(saved[0]["result"])
                self._readback(connection, plan, result)
                return result
            self._point("locked")
            old = selection(plan["old_selection"])
            states = {}
            for role in ROLES:
                backend = s.SnapshotVerifier(expected_profile=s.PROFILE,
                    selection=selection(plan["recipient_selection"]) if role == "recipient" else old,
                    node=plan["node"], node_sha256=plan["node_sha256"])
                self._validate_source(connection, plan, role, backend)
                self._marker(connection, "new_" + role, plan, "prepared", b.encode(plan["stores"][role]["target_physical"]), bare=True)
                if role != "dispatch":
                    states[role] = rows(connection, "old_" + role, "state")[0]
            requested = selection(plan["requested_selection"])
            confirmation_revision = max(old.minimum_revision, selection(plan["recipient_selection"]).minimum_revision,
                                        requested.minimum_revision, max(row["revision"] for row in states.values()) + 1)
            need(confirmation_revision < s.MAX_REVISION, "MIGRATION_REVISION_EXHAUSTED")
            confirmation_selection = replace(requested, minimum_revision=confirmation_revision)
            selected = replace(requested, minimum_revision=confirmation_revision + 1)
            now = d.instant(clock())
            highs = [row["clock_high"] for row in states.values()]
            highs.append(rows(connection, "old_dispatch", "identity")[0]["clock_high"])
            need(all(value is None or now >= b.core.parse_time(value) for value in highs), "MIGRATION_CLOCK_ROLLBACK")
            second = int((now - s.jwt.EPOCH).total_seconds())
            confirmations = {}
            for label, chosen, signer in (("old", old, old_signer), ("new", confirmation_selection, new_signer)):
                claims = {"iss": chosen.issuer, "aud": chosen.audience, "scope": chosen.scope,
                    "epoch": chosen.epoch, "revision": confirmation_revision, "iat": second, "nbf": second,
                    "exp": second + min(30, chosen.max_snapshot_age_seconds), "runtime_grants": [], "delegation_grants": []}
                token = signer({"alg": "ES256", "typ": s.TOKEN_TYPE, "kid": chosen.kid}, claims)
                need(os.getpid() == self._pid, "MIGRATION_FORK_REOPEN_REQUIRED")
                check = s.SnapshotVerifier(expected_profile=s.PROFILE, selection=chosen,
                    node=plan["node"], node_sha256=plan["node_sha256"]).verify(token, now)
                need(check.payload == b.encode(claims), "MIGRATION_KEY_CONFIRMATION_FAILED")
                confirmations[label] = {"digest": b.digest(token), "token_base64": base64.b64encode(token).decode("ascii")}
            self._point("keys_confirmed")
            result = {"contract": CONTRACT, "migration_id": plan["migration_id"], "state": "migrated_refresh_required",
                "selection": selected.descriptor(), "target_program": plan["target_program"],
                "source_commit": BASELINE, "key_confirmations": confirmations,
                "source_histories": {}, "anchors": {}, "directories": {}}
            for role in ROLES:
                entry, alias, target = plan["stores"][role], "old_" + role, "new_" + role
                result["source_histories"][role] = history(connection, alias, role)
                connection.execute(f"CREATE TABLE {alias}." + d.MIGRATION_TABLE.removeprefix("CREATE TABLE "))
                connection.execute(f"INSERT INTO {alias}.migration VALUES(1,?,'retired',?,?)",
                    (plan["migration_id"], b.encode(entry["source_anchor"]), b.encode(plan["target_program"])))
                self._point("retired_" + role)
                for name, sql in table_shapes(role).items():
                    connection.execute(f"CREATE TABLE {target}." + sql.removeprefix("CREATE TABLE "))
                    connection.execute(f"INSERT INTO {target}.{name} SELECT * FROM {alias}.{name}")
                target_anchor = {**entry["source_anchor"], **entry["target_physical"]}
                if role != "dispatch":
                    encoded = b.encode(selected.descriptor())
                    target_anchor["selection_sha256"] = d.sha(encoded)
                    connection.execute(f"UPDATE {target}.identity SET selection=? WHERE singleton=1", (encoded,))
                    # Retain the exact old signed original and floors, but never
                    # lease it under the new root or clear a recorded conflict.
                    connection.execute(f"UPDATE {target}.state SET unavailable=1,conflict=CASE WHEN revision=0 THEN 0 ELSE 1 END WHERE singleton=1")
                connection.execute(f"PRAGMA {target}.application_id={d.APPLICATION_ID if role == 'dispatch' else authority.APPLICATION_ID}")
                connection.execute(f"PRAGMA {target}.user_version=1")
                connection.execute(f"UPDATE {target}.migration SET role='target',anchor=? WHERE singleton=1", (b.encode(target_anchor),))
                result["anchors"][role] = target_anchor
                result["directories"][role] = entry["target"]
                self._point("copied_" + role)
            self._readback(connection, plan, result)
            need(program() == plan["target_program"], "MIGRATION_PROGRAM_CHANGED")
            for role, entry in plan["stores"].items():
                inspect_files(entry["source"], entry["source_anchor"], role=role)
                inspect_files(entry["target"], entry["target_physical"], role=role)
            result_raw = b.encode(result)
            connection.execute("UPDATE main.journal SET result=?,result_sha256=? WHERE singleton=1",
                               (result_raw, d.sha(result_raw)))
            self._point("before_commit")
            connection.commit()
            self._point("committed")
            return result

    def _marker(self, connection, alias, plan, role, anchor, *, bare=False):
        kind = alias.split("_", 1)[1]
        expected = {} if bare else table_shapes(kind)
        need(schema(connection, alias) == {**expected, "migration": d.MIGRATION_TABLE}, "MIGRATION_SCHEMA_CHANGED")
        found = connection.execute(f"SELECT * FROM {alias}.migration").fetchall()
        need(len(found) == 1 and dict(found[0]) == {"singleton": 1, "migration_id": plan["migration_id"],
            "role": role, "anchor": anchor, "program": b.encode(plan["target_program"])}, "MIGRATION_MARKER_CHANGED")

    def _header(self, connection, alias, role):
        need(connection.execute(f"PRAGMA {alias}.application_id").fetchone()[0] ==
                 (d.APPLICATION_ID if role == "dispatch" else authority.APPLICATION_ID)
             and connection.execute(f"PRAGMA {alias}.user_version").fetchone()[0] == 1,
             "MIGRATION_DB_MODE_INVALID")
        need(not connection.execute(f"PRAGMA {alias}.foreign_key_check").fetchall(), "MIGRATION_DATA_CORRUPT")

    def _authority_row(self, connection, alias, verifier):
        state = rows(connection, alias, "state")
        need(len(state) == 1 and state[0]["singleton"] == 1, "MIGRATION_DATA_CORRUPT")
        row = state[0]
        need(type(row["revision"]) is int and 0 <= row["revision"] <= s.MAX_REVISION
             and type(row["issued_at"]) is int and 0 <= row["issued_at"] <= s.jwt.MAX_NUMERIC_DATE
             and row["conflict"] in (0, 1) and row["unavailable"] in (0, 1), "MIGRATION_DATA_CORRUPT")
        if row["clock_high"] is not None:
            need(b.core.iso(b.core.parse_time(row["clock_high"])) == row["clock_high"], "MIGRATION_DATA_CORRUPT")
        if row["revision"] == 0:
            need(row["issued_at"] == 0 and row["conflict"] == 0 and row["unavailable"] == 1
                 and all(row[key] is None for key in ("raw", "raw_sha256", "payload_sha256")), "MIGRATION_DATA_CORRUPT")
            return row
        need(type(row["raw"]) is bytes and 0 < len(row["raw"]) <= s.jwt.MAX_TOKEN_BYTES
             and d.sha(row["raw"]) == row["raw_sha256"], "MIGRATION_DATA_CORRUPT")
        payload = b.decode(s.jwt.decode_segment(row["raw"].split(b".")[1], s.jwt.MAX_TOKEN_BYTES))
        # Historical authentication checks retained originals without granting
        # a current policy lease or advancing clocks during readback.
        checked = verifier.verify(row["raw"], s.jwt.numeric_date(max(payload["iat"], payload["nbf"])))
        need(checked.revision == row["revision"] and checked.issued_at == row["issued_at"]
             and d.sha(checked.payload) == row["payload_sha256"]
             and row["clock_high"] is not None
             and b.core.parse_time(row["clock_high"]) >= s.jwt.numeric_date(row["issued_at"]), "MIGRATION_DATA_CORRUPT")
        return row

    def _dispatch_rows(self, connection, alias, anchor, source_options):
        for row in ordered_rows(connection, alias, "admissions"):
            need(row["executable"] in (0, 1) and d.record_digest(row["request_id"], row["operation_id"],
                row["configuration"], tuple(row[name] for name in d.VALUE_NAMES), bool(row["executable"])) == row["record_sha256"],
                "MIGRATION_DATA_CORRUPT")
            config = canonical(row["configuration"], max_bytes=d.MAX_BYTES)
            need(config["scope"] == anchor["scope"] and config["verifier_id"] == anchor["verifier_id"]
                 and any(all(pins.get(path) == digest for path, digest in config["sources"].items())
                         for pins in source_options)
                 and "caller_authorizer" in config, "MIGRATION_ADMISSION_SOURCE_UNSUPPORTED")
        for row in ordered_rows(connection, alias, "operations"):
            owner = connection.execute(f"SELECT operation_id,record_sha256 FROM {alias}.admissions WHERE request_id=?",
                                       (row["request_id"],)).fetchone()
            need(owner is not None and owner["operation_id"] == row["operation_id"]
                 and owner["record_sha256"] == row["record_sha256"] and type(row["checkpoint"]) is bytes
                 and d.sha(row["checkpoint"]) == row["checkpoint_sha256"]
                 and row["state"] in ("attempt_consumed", "callback_returned", "outcome_unknown"), "MIGRATION_DATA_CORRUPT")
            d.parse_time(row["checked_at"])

    def _validate_source(self, connection, plan, role, verifier):
        alias, anchor = "old_" + role, plan["stores"][role]["source_anchor"]
        need(schema(connection, alias) == table_shapes(role), "MIGRATION_SOURCE_UNSUPPORTED")
        self._header(connection, alias, role)
        identities = rows(connection, alias, "identity")
        need(len(identities) == 1 and identities[0]["singleton"] == 1
             and identities[0]["store_id"] == anchor["store_id"], "MIGRATION_IDENTITY_CHANGED")
        if role != "dispatch":
            need(identities[0]["selection"] == b.encode(plan["recipient_selection"] if role == "recipient" else plan["old_selection"]),
                 "MIGRATION_IDENTITY_CHANGED")
            self._authority_row(connection, alias, verifier)
        else:
            need(all(identities[0][key] == anchor[key] for key in ("scope", "verifier_id")), "MIGRATION_IDENTITY_CHANGED")
            if identities[0]["clock_high"] is not None:
                d.parse_time(identities[0]["clock_high"])
            self._dispatch_rows(connection, alias, anchor, (plan["source_program"]["files"],))

    def _readback(self, connection, plan, result):
        need(result["contract"] == CONTRACT and result["migration_id"] == plan["migration_id"]
             and result["target_program"] == plan["target_program"], "MIGRATION_RESULT_CHANGED")
        for role in ROLES:
            entry, alias, target = plan["stores"][role], "old_" + role, "new_" + role
            self._marker(connection, alias, plan, "retired", b.encode(entry["source_anchor"]))
            self._marker(connection, target, plan, "target", b.encode(result["anchors"][role]))
            self._header(connection, alias, role)
            self._header(connection, target, role)
            need(history(connection, alias, role) == result["source_histories"][role], "MIGRATION_HISTORY_CHANGED")
            before_identity, after_identity = rows(connection, alias, "identity"), rows(connection, target, "identity")
            need(len(before_identity) == len(after_identity) == 1, "MIGRATION_IDENTITY_CHANGED")
            identity = dict(before_identity[0])
            if role == "dispatch":
                self._dispatch_rows(connection, target, result["anchors"][role],
                                    (plan["source_program"]["files"], plan["target_program"]))
                identity["clock_high"] = after_identity[0]["clock_high"]
            else:
                identity["selection"] = b.encode(result["selection"])
            need(after_identity[0] == identity, "MIGRATION_IDENTITY_CHANGED")
            if role == "dispatch":
                for table, primary in (("admissions", "request_id"), ("operations", "operation_id")):
                    for row in ordered_rows(connection, alias, table):
                        retained = connection.execute(f"SELECT * FROM {target}.{table} WHERE {primary}=?",
                                                      (row[primary],)).fetchone()
                        need(retained is not None and dict(retained) == row, "MIGRATION_HISTORY_CHANGED")
                old_high = rows(connection, alias, "identity")[0]["clock_high"]
                new_high = rows(connection, target, "identity")[0]["clock_high"]
                # A new store may acquire its first clock floor after an empty
                # source was migrated. Its value still needs independent validation.
                new_time = None if new_high is None else d.parse_time(new_high)
                need(old_high is None or new_time is not None and new_time >= d.parse_time(old_high),
                     "MIGRATION_CLOCK_ROLLBACK")
            else:
                before, after = rows(connection, alias, "state")[0], rows(connection, target, "state")[0]
                need(type(after["revision"]) is int, "MIGRATION_DATA_CORRUPT")
                chosen = (plan["recipient_selection"] if role == "recipient" else plan["old_selection"]) \
                    if after["revision"] == before["revision"] else result["selection"]
                verifier = s.SnapshotVerifier(expected_profile=s.PROFILE, selection=selection(chosen),
                    node=plan["node"], node_sha256=plan["node_sha256"])
                after = self._authority_row(connection, target, verifier)
                need(after["revision"] >= before["revision"] and after["issued_at"] >= before["issued_at"]
                     and (before["clock_high"] is None or after["clock_high"] is not None
                          and b.core.parse_time(after["clock_high"]) >= b.core.parse_time(before["clock_high"])),
                     "MIGRATION_AUTHORITY_ROLLBACK")
                if after["revision"] == before["revision"]:
                    need(all(after[key] == before[key] for key in before if key not in ("conflict", "unavailable", "clock_high"))
                         and after["unavailable"] == 1 and after["conflict"] == int(before["revision"] != 0), "MIGRATION_HISTORY_CHANGED")
