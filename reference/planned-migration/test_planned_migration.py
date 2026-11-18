"""Bounded old-program/new-program migration using disposable local stores."""
import base64
from contextlib import closing, contextmanager
from dataclasses import replace
from datetime import timedelta
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from fixture_support import Fixture, ROOT, b, s, c
from fixture_signer import FixtureSigner
import shutil
import select
from migration import PlannedMigration, MigrationError, authority, d, locked, source_program, history, rows, table_shapes, selection

BASELINE = Path(os.environ["VATE_MIGRATION_BASELINE"]) if os.environ.get("VATE_MIGRATION_BASELINE") else None


class PlannedMigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if BASELINE is None or not BASELINE.is_dir():
            raise RuntimeError("Set VATE_MIGRATION_BASELINE to the pinned 6758476 source tree; migration tests must not be skipped")
        source_program(BASELINE)

    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory(prefix="vate-migration-test-") as directory:
            with Fixture(directory, source_root=BASELINE) as fixture:
                yield fixture

    def prepare(self, f, *, selected=None):
        verifier = s.SnapshotVerifier(expected_profile=s.PROFILE, selection=f.selection,
            node=f.node, node_sha256=f.node_sha)
        stores = {role: authority.AuthorityStore(f.old / role, verifier=verifier,
            expected_anchor=b.encode(f.anchors[role]), clock=lambda: f.now) for role in ("publisher", "recipient")}
        state = d.DurableStateStore(f.old / "dispatch", expected_anchor=b.encode(f.anchors["dispatch"]))
        move = PlannedMigration.prepare(f.root / "moved", source_root=BASELINE,
            dispatch=state, new_selection=selected or f.new_selection, **stores)
        return move

    def migrate(self, f, move=None):
        move = move or self.prepare(f)
        result = move.run(old_signer=f.old_signer, new_signer=f.new_signer, clock=lambda: f.now)
        f.target_base = {**f.base, "directory": str(f.root / "moved"),
                         "anchors": result["anchors"], "selection": result["selection"]}
        return move, result

    def test_old_histories_preserved_new_root_and_new_operation(self):
        with self.fixture() as f:
            move, result = self.migrate(f)
            self.assertEqual(result["selection"]["minimum_revision"], 4)
            for role in f.anchors:
                self.assertNotEqual(result["anchors"][role]["db_inode"], f.anchors[role]["db_inode"])
            for name, old in f.history.items():
                observed = f.worker({"action": "status", "request_id": old["request_id"]}, target=True)
                self.assertEqual(observed["status"]["state"], old["state"])
                self.assertEqual(observed["status"]["receipt_ref"]["digest"]["value"], old["receipt_sha256"])
            self.assertEqual(f.worker({**f.purchase("-new"), "action": "admit"}, target=True, succeeds=False), "AUTHORITY_NOT_AVAILABLE")
            self.assertEqual(f.install(f.last_snapshot, target=True, succeeds=False), "AUTHORITY_HEADER_INVALID")
            f.install(f.snapshot(4, revoked=True, new=True), target=True)
            self.assertEqual(f.worker({**f.purchase("-revoked"), "action": "admit"}, target=True, succeeds=False), "CALLER_AUTHORIZATION_FAILED")
            f.install(f.snapshot(5, new=True), target=True)
            self.assertEqual(f.worker({"action": "restore", "request_id": f.history["pending"]["request_id"]},
                target=True, succeeds=False), "STATE_CONFIGURATION_CHANGED")
            for name in ("returned", "unknown"):
                self.assertEqual(f.worker({**f.purchase("-" + name, request_suffix="-new"), "action": "admit"},
                    target=True, succeeds=False), "DURABLE_OPERATION_ALREADY_ATTEMPTED")
            response = f.worker({**f.purchase("-pending", request_suffix="-new"), "action": "admit", "dispatch": True}, target=True)
            self.assertEqual(response["state"], "callback_returned")
            self.assertEqual(len(response["calls"]), 1)
            self.assertEqual(f.worker({"action": "status", "request_id": f.history["returned"]["request_id"]}, succeeds=False),
                "AUTHORITY_SCHEMA_CHANGED")
            self.assertEqual(move.run(old_signer=None, new_signer=None, clock=None), result)
            self.assertEqual(f.worker({"action": "status", "request_id": response["request_id"]}, target=True)["status"]["state"],
                             "callback_returned")

    def test_committed_result_corruption_is_rejected(self):
        with self.fixture() as f:
            move, result = self.migrate(f)
            with closing(sqlite3.connect(move.directory / "migration.sqlite3")) as connection, connection:
                saved = connection.execute("SELECT result FROM journal").fetchone()[0]
                corrupt = b.decode(saved)
                corrupt["key_confirmations"]["old"]["token_base64"] = base64.b64encode(b"corrupt").decode()
                connection.execute("UPDATE journal SET result=?", (b.encode(corrupt),))
            with self.assertRaisesRegex(MigrationError, "MIGRATION_RESULT_CHANGED"):
                move.run(old_signer=None, new_signer=None, clock=None)
            with closing(sqlite3.connect(move.directory / "migration.sqlite3")) as connection, connection:
                connection.execute("UPDATE journal SET result=?", (saved,))
            self.assertEqual(move.run(old_signer=None, new_signer=None, clock=None), result)

    def test_large_valid_history_preserves_original_digest_basis(self):
        with self.fixture() as f:
            def old_history(connection, role):
                return b.encode({table: [{key: {"bytes_hex": value.hex()} if type(value) is bytes else value
                    for key, value in row.items()} for row in rows(connection, "main", table)]
                    for table in table_shapes(role)})
            for role in f.anchors:
                filename = "state.sqlite3" if role == "dispatch" else "authority.sqlite3"
                with closing(sqlite3.connect(f.old / role / filename)) as connection, connection:
                    connection.row_factory = sqlite3.Row
                    self.assertEqual(history(connection, "main", role), d.sha(old_history(connection, role)))
            f.install(f.snapshot(3))
            purchase = f.purchase("-large", order_padding=1100 * 1024)
            self.assertGreater(len(base64.b64decode(purchase["original"])), b.MAX_BYTES // 2)
            accepted = f.worker({**purchase, "action": "admit"})
            with closing(sqlite3.connect(f.old / "dispatch/state.sqlite3")) as connection, connection:
                connection.row_factory = sqlite3.Row
                with self.assertRaisesRegex(b.Invalid, "ARTIFACT_TOO_LARGE"):
                    old_history(connection, "dispatch")
                before = [tuple(row) for row in connection.execute("SELECT * FROM admissions ORDER BY request_id")]
            move, result = self.migrate(f)
            with closing(sqlite3.connect(move.directory / "dispatch/state.sqlite3")) as connection, connection:
                after = connection.execute("SELECT * FROM admissions ORDER BY request_id").fetchall()
            self.assertEqual(before, after)
            self.assertEqual(f.worker({"action": "status", "request_id": accepted["request_id"]}, target=True)["status"]["state"], "ready")
            self.assertEqual(move.run(old_signer=None, new_signer=None, clock=None), result)

    def test_large_supported_configuration_is_preserved(self):
        with self.fixture() as f:
            f.install(f.snapshot(3))
            purchase = f.purchase("-large-policy", policy_padding=1100 * 1024)
            accepted = f.worker({**purchase, "action": "admit"})
            with closing(sqlite3.connect(f.old / "dispatch/state.sqlite3")) as connection:
                before = connection.execute("SELECT configuration FROM admissions WHERE request_id=?",
                    (accepted["request_id"],)).fetchone()[0]
            self.assertGreater(len(before), 1024 * 1024)
            self.assertLess(len(before), d.MAX_BYTES)
            move, result = self.migrate(f)
            with closing(sqlite3.connect(move.directory / "dispatch/state.sqlite3")) as connection:
                after = connection.execute("SELECT configuration FROM admissions WHERE request_id=?",
                    (accepted["request_id"],)).fetchone()[0]
            self.assertEqual(before, after)
            self.assertEqual(move.run(old_signer=None, new_signer=None, clock=None), result)

    def test_key_confirmation_is_below_every_live_authority_revision(self):
        with self.fixture() as f:
            move, result = self.migrate(f)
            selected = selection(result["selection"])
            confirmation = base64.b64decode(result["key_confirmations"]["new"]["token_base64"], validate=True)
            verifier = s.SnapshotVerifier(expected_profile=s.PROFILE, selection=selected, node=f.node, node_sha256=f.node_sha)
            stores = [authority.AuthorityStore(move.directory / role, verifier=verifier,
                expected_anchor=b.encode(result["anchors"][role]), clock=lambda: f.now)
                for role in ("publisher", "recipient")]
            for installed in (False, True):
                if installed:
                    f.install(f.snapshot(selected.minimum_revision, new=True), target=True)
                for store in stores:
                    before = store.status()
                    with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REVISION_INVALID"):
                        store.accept(confirmation)
                    self.assertEqual(store.status(), before)
            self.assertEqual(f.worker({**f.purchase("-confirmation-control"), "action": "admit", "dispatch": True}, target=True)["state"], "callback_returned")

    def test_committed_readback_checks_every_database_header(self):
        with self.fixture() as f:
            move, result = self.migrate(f)
            for directory in (f.old, move.directory):
                for role in ("publisher", "recipient", "dispatch"):
                    database = directory / role / ("state.sqlite3" if role == "dispatch" else "authority.sqlite3")
                    for field in ("application_id", "user_version"):
                        with self.subTest(directory=directory.name, role=role, field=field):
                            with closing(sqlite3.connect(database)) as connection, connection:
                                original = connection.execute("PRAGMA " + field).fetchone()[0]
                                connection.execute("PRAGMA " + field + "=7")
                            with self.assertRaisesRegex(MigrationError, "MIGRATION_DB_MODE_INVALID"):
                                move.run(old_signer=None, new_signer=None, clock=None)
                            with closing(sqlite3.connect(database)) as connection, connection:
                                connection.execute("PRAGMA " + field + "=" + str(original))
            self.assertEqual(move.run(old_signer=None, new_signer=None, clock=None), result)

    def test_committed_readback_checks_new_authority_originals(self):
        with self.fixture() as f:
            move, result = self.migrate(f)
            f.install(f.snapshot(4, new=True), target=True)
            for role in ("publisher", "recipient"):
                with self.subTest(role=role):
                    database = move.directory / role / "authority.sqlite3"
                    with closing(sqlite3.connect(database)) as connection, connection:
                        original = connection.execute("SELECT raw FROM state").fetchone()[0]
                        connection.execute("UPDATE state SET raw=?", (b"corrupt",))
                    with self.assertRaisesRegex(MigrationError, "MIGRATION_DATA_CORRUPT"):
                        move.run(old_signer=None, new_signer=None, clock=None)
                    with closing(sqlite3.connect(database)) as connection, connection:
                        connection.execute("UPDATE state SET raw=?", (original,))
            self.assertEqual(move.run(old_signer=None, new_signer=None, clock=None), result)

    def test_committed_readback_checks_subsequent_operation_records(self):
        with self.fixture() as f:
            move, result = self.migrate(f)
            f.install(f.snapshot(4, new=True), target=True)
            observed = f.worker({**f.purchase("-later"), "action": "admit", "dispatch": True}, target=True)
            database = move.directory / "dispatch/state.sqlite3"
            for table, field in (("operations", "checkpoint"), ("admissions", "receipt")):
                with self.subTest(table=table):
                    with closing(sqlite3.connect(database)) as connection, connection:
                        original = connection.execute(f"SELECT {field} FROM {table} WHERE request_id=?", (observed["request_id"],)).fetchone()[0]
                        connection.execute(f"UPDATE {table} SET {field}=? WHERE request_id=?", (b"corrupt", observed["request_id"]))
                    with self.assertRaisesRegex(MigrationError, "MIGRATION_DATA_CORRUPT"):
                        move.run(old_signer=None, new_signer=None, clock=None)
                    with closing(sqlite3.connect(database)) as connection, connection:
                        connection.execute(f"UPDATE {table} SET {field}=? WHERE request_id=?", (original, observed["request_id"]))
            self.assertEqual(move.run(old_signer=None, new_signer=None, clock=None), result)

    def test_signer_fork_does_not_leave_inherited_locks(self):
        with self.fixture() as f:
            move = self.prepare(f)
            ready_r, ready_w = os.pipe()
            release_r, release_w = os.pipe()
            child = None
            try:
                def signer(header, claims):
                    nonlocal child
                    raw = f.old_signer(header, claims)
                    child = os.fork()
                    if child == 0:
                        os.close(ready_r); os.close(release_w)
                        os.write(ready_w, b"1")
                        os.read(release_r, 1)
                        os._exit(0)
                    self.assertTrue(select.select([ready_r], [], [], 10)[0])
                    self.assertEqual(os.read(ready_r, 1), b"1")
                    return raw
                result = move.run(old_signer=signer, new_signer=f.new_signer, clock=lambda: f.now)
                self.assertEqual(move.run(old_signer=None, new_signer=None, clock=None), result)
            finally:
                if child:
                    os.write(release_w, b"1")
                    os.waitpid(child, 0)
                for fd in (ready_r, ready_w, release_r, release_w):
                    os.close(fd)

    def test_new_request_requires_new_runtime_evidence(self):
        with self.fixture() as f:
            self.migrate(f)
            f.install(f.snapshot(4, new=True), target=True)
            candidate = f.purchase("-pending", request_suffix="-new")
            valid_candidate = dict(candidate)
            candidate["runtime_token"] = f.purchases["pending"]["runtime_token"]
            request = b.decode(base64.b64decode(candidate["request"]))
            for ref in request["evidence_refs"]:
                if ref["type"] == "runtime_attestation":
                    ref["digest"] = b.digest(base64.b64decode(candidate["runtime_token"]))
            request_raw = b.encode(request)
            candidate["request"] = base64.b64encode(request_raw).decode()
            second = int((f.now - s.jwt.EPOCH).total_seconds())
            proof = f.actor({"alg": "ES256", "kid": "actor-key", "typ": c.TOKEN_TYPE}, {
                "iss": request["actor"], "sub": request["actor"], "aud": request["audience"],
                "iat": second, "nbf": second, "exp": second + 180, "grant_id": "purchase-grant",
                "request_sha256": b.digest(request_raw)["value"],
                "original_sha256": b.digest(base64.b64decode(candidate["original"]))["value"]})
            candidate["proof"] = base64.b64encode(proof).decode()
            self.assertEqual(f.worker({**candidate, "action": "admit", "dispatch": True}, target=True, succeeds=False),
                             "RUNTIME_EVIDENCE_VERIFICATION_FAILED")
            self.assertEqual(f.worker({**valid_candidate, "action": "admit", "dispatch": True}, target=True)["state"], "callback_returned")

    def test_target_runtime_change_detected_from_separate_installed_tree(self):
        with self.fixture() as f:
            _, result = self.migrate(f)
            installed = f.root / "changed-program"
            for name in d.MIGRATION_SOURCES:
                path = installed / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / name).read_bytes())
            selected = installed / "reference/authority-keychain/keychain_bridge.swift"
            selected.write_bytes(selected.read_bytes() + b"\n// fixture change\n")
            script = '''import importlib.util, json, sys
from pathlib import Path
spec=importlib.util.spec_from_file_location("owned_migration_state",sys.argv[1])
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
job=json.load(sys.stdin)
try:
    m.DurableStateStore(job["directory"],expected_anchor=m.encode(job["anchor"]))
except m.StateError as error:
    print(error.cause)
else: raise RuntimeError("Changed program accepted")
'''
            process = subprocess.run([sys.executable, "-I", "-B", "-c", script,
                str(installed / "reference/request-binding/durable_state.py")],
                input=b.encode({"directory": str(f.root / "moved/dispatch"), "anchor": result["anchors"]["dispatch"]}),
                capture_output=True, timeout=10)
            self.assertEqual(process.returncode, 0, process.stderr.decode())
            self.assertEqual(process.stdout.strip(), b"STATE_IMPLEMENTATION_CHANGED")

    def test_wal_participant_is_not_silently_converted(self):
        with self.fixture() as f:
            move = self.prepare(f)
            with closing(sqlite3.connect(f.root / "moved/dispatch/state.sqlite3")) as connection, connection:
                self.assertEqual(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
            with self.assertRaisesRegex(MigrationError, "MIGRATION_DB_MODE_INVALID"):
                self.migrate(f, move)
            with closing(sqlite3.connect(f.root / "moved/dispatch/state.sqlite3")) as connection, connection:
                self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")

    def test_wrong_journal_anchor_refused(self):
        with self.fixture() as f:
            move = self.prepare(f)
            wrong = json.loads(move.anchor)
            wrong["plan_sha256"] = "0" * 64
            reopened = PlannedMigration(move.directory, expected_anchor=b.encode(wrong))
            with self.assertRaisesRegex(MigrationError, "MIGRATION_JOURNAL_INVALID"):
                self.migrate(f, reopened)

    def test_old_handle_and_old_program_cannot_reopen_retired_stores(self):
        with self.fixture() as f:
            old_handle = d.DurableStateStore(f.old / "dispatch", expected_anchor=b.encode(f.anchors["dispatch"]))
            self.migrate(f)
            with self.assertRaisesRegex(d.StateError, "STATE_MIGRATION_INACTIVE"):
                old_handle.read(f.history["pending"]["request_id"])
            self.assertEqual(f.worker({"action": "restore", "request_id": f.history["pending"]["request_id"]}, succeeds=False),
                             "AUTHORITY_SCHEMA_CHANGED")

    def test_prepared_destination_cannot_open_as_empty_store(self):
        with self.fixture() as f:
            self.prepare(f)
            self.assertEqual(f.worker({"action": "status", "request_id": f.history["pending"]["request_id"]})["status"]["state"], "ready")
            with self.assertRaises(d.StateError):
                d.DurableStateStore(f.root / "moved/dispatch", expected_anchor=b.encode(f.anchors["dispatch"]))

    def test_busy_authority_blocks_before_source_changes(self):
        with self.fixture() as f:
            move = self.prepare(f)
            anchor = f.anchors["recipient"]
            with locked(f.old / "recipient/authority.lock", anchor["lock_device"], anchor["lock_inode"]):
                with self.assertRaisesRegex(MigrationError, "MIGRATION_BUSY"):
                    self.migrate(f, move)
            self.assertEqual(f.worker({"action": "status", "request_id": f.history["pending"]["request_id"]})["status"]["state"], "ready")
            self.migrate(f, move)

    @contextmanager
    def parked_worker(self, f, job, expected):
        process = subprocess.Popen([sys.executable, "-I", "-B", str(Path(__file__).with_name("fixture_worker.py")), str(BASELINE)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            process.stdin.write(b.encode({**f.base, **job}) + b"\n"); process.stdin.flush()
            self.assertTrue(select.select([process.stdout], [], [], 15)[0], "Old fixture did not become ready")
            self.assertEqual(json.loads(process.stdout.readline()), {"fixture_ready": expected})
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()

    def test_original_program_retained_managed_handle_refuses_after_cutover(self):
        with self.fixture() as f:
            move = self.prepare(f)
            with self.parked_worker(f, {"action": "park"}, "configured") as child:
                self.migrate(f, move)
                child.stdin.write(b.encode({"action": "restore", "request_id": f.history["pending"]["request_id"]}) + b"\n")
                child.stdin.flush()
                stdout, stderr = child.communicate(timeout=15)
                self.assertEqual(child.returncode, 1, stderr.decode())
                self.assertEqual(json.loads(stdout)["cause"], "AUTHORITY_SCHEMA_CHANGED")

    def test_real_old_managed_callback_holds_drain_barrier(self):
        with self.fixture() as f:
            f.install(f.snapshot(3))
            move = self.prepare(f)
            with self.parked_worker(f, {**f.purchase("-live"), "action": "admit", "dispatch": True, "callback": "park"}, "callback") as child:
                with self.assertRaisesRegex(MigrationError, "MIGRATION_BUSY"):
                    self.migrate(f, move)
                child.stdin.write(b"continue\n"); child.stdin.flush()
                stdout, stderr = child.communicate(timeout=15)
                self.assertEqual(child.returncode, 0, stderr.decode())
                prior = json.loads(stdout)["result"]
                self.assertEqual(prior["state"], "callback_returned")
            self.migrate(f, move)
            observed = f.worker({"action": "status", "request_id": prior["request_id"]}, target=True)
            self.assertEqual(observed["status"]["state"], "callback_returned")

    def test_interrupted_old_claim_stays_consumed_after_migration(self):
        with self.fixture() as f:
            f.install(f.snapshot(3))
            purchase = f.purchase("-claimed")
            request_id = b.decode(base64.b64decode(purchase["request"]))["request_id"]
            with self.parked_worker(f, {**purchase, "action": "admit", "dispatch": True, "callback": "park"}, "callback") as child:
                child.terminate()
                child.wait(timeout=5)
                self.assertLess(child.returncode, 0)
            original = f.worker({"action": "status", "request_id": request_id})
            self.assertEqual(original["status"]["state"], "attempt_consumed")
            self.assertIsNotNone(original["checkpoint"])
            move, result = self.migrate(f)
            migrated = f.worker({"action": "status", "request_id": request_id}, target=True)
            self.assertEqual(migrated["status"]["state"], "attempt_consumed")
            self.assertEqual(migrated["checkpoint"], original["checkpoint"])
            self.assertEqual(migrated["status"]["receipt_ref"], original["status"]["receipt_ref"])
            f.install(f.snapshot(5, new=True), target=True)
            self.assertEqual(f.worker({**f.purchase("-claimed", request_suffix="-new"), "action": "admit"},
                target=True, succeeds=False), "DURABLE_OPERATION_ALREADY_ATTEMPTED")
            self.assertEqual(move.run(old_signer=None, new_signer=None, clock=None), result)
            self.assertEqual(f.worker({"action": "status", "request_id": request_id}, target=True), migrated)

    def test_clock_rollback_preserves_source(self):
        with self.fixture() as f:
            move = self.prepare(f)
            with self.assertRaisesRegex(MigrationError, "MIGRATION_CLOCK_ROLLBACK"):
                move.run(old_signer=f.old_signer, new_signer=f.new_signer, clock=lambda: f.now - timedelta(seconds=1))
            self.migrate(f, move)

    def test_empty_source_readback_validates_first_target_clock(self):
        with self.fixture() as f:
            f.old = f.root / "empty-old"
            f.old.mkdir()
            f.base["directory"] = str(f.old)
            f.anchors = f.worker({"action": "create"})["anchors"]
            f.base["anchors"] = f.anchors
            move, result = self.migrate(f)
            database = move.directory / "dispatch/state.sqlite3"
            with closing(sqlite3.connect(database)) as connection:
                self.assertIsNone(connection.execute("SELECT clock_high FROM identity").fetchone()[0])
            for value in (None, d.timestamp(f.now), "not-a-timestamp", "2026-13-99T99:99:99.000000Z", 123):
                with self.subTest(clock_high=value):
                    with closing(sqlite3.connect(database)) as connection, connection:
                        connection.execute("UPDATE identity SET clock_high=? WHERE singleton=1", (value,))
                    if value is None or value == d.timestamp(f.now):
                        self.assertEqual(move.run(old_signer=None, new_signer=None, clock=None), result)
                    else:
                        with self.assertRaisesRegex(MigrationError, "MIGRATION_FAILED"):
                            move.run(old_signer=None, new_signer=None, clock=None)

    def test_key_confirmation_failure_is_not_a_partial_move(self):
        with self.fixture() as f:
            move = self.prepare(f)
            with self.assertRaises(MigrationError):
                move.run(old_signer=f.new_signer, new_signer=f.new_signer, clock=lambda: f.now)
            self.assertEqual(f.worker({"action": "status", "request_id": f.history["pending"]["request_id"]})["status"]["state"], "ready")
            self.migrate(f, move)

    def test_final_locked_revision_and_selected_floor_are_used(self):
        with self.fixture() as f:
            move = self.prepare(f, selected=replace(f.new_selection, minimum_revision=50))
            f.install(f.snapshot(70, revoked=True))
            _, result = self.migrate(f, move)
            self.assertEqual(result["selection"]["minimum_revision"], 72)
            self.assertEqual(f.install(f.snapshot(70, new=True), target=True, succeeds=False), "AUTHORITY_REVISION_INVALID")
            f.install(f.snapshot(72, revoked=True, new=True), target=True)

    def test_revision_exhaustion_is_refused_without_retirement(self):
        for revision in (s.MAX_REVISION - 1, s.MAX_REVISION):
            with self.subTest(revision=revision), self.fixture() as f:
                f.install(f.snapshot(revision, revoked=True))
                move = self.prepare(f)
                with self.assertRaisesRegex(MigrationError, "MIGRATION_REVISION_EXHAUSTED"):
                    self.migrate(f, move)
                self.assertEqual(f.worker({"action": "status", "request_id": f.history["pending"]["request_id"]})["status"]["state"], "ready")

    def test_last_usable_revision_keeps_confirmation_below_live_floor(self):
        with self.fixture() as f:
            f.install(f.snapshot(s.MAX_REVISION - 2, revoked=True))
            _, result = self.migrate(f)
            self.assertEqual(result["selection"]["minimum_revision"], s.MAX_REVISION)
            f.install(f.snapshot(s.MAX_REVISION, new=True), target=True)
            confirmation = base64.b64decode(result["key_confirmations"]["new"]["token_base64"], validate=True)
            self.assertEqual(f.install(confirmation, target=True, succeeds=False), "AUTHORITY_REVISION_INVALID")

    def test_unpopulated_recipient_preserves_its_higher_configured_minimum(self):
        with tempfile.TemporaryDirectory(prefix="vate-migration-empty-") as directory:
            root = Path(directory).resolve()
            node = Path(shutil.which("node")).resolve(strict=True)
            digest = s.jwt.file_sha(node)
            with FixtureSigner(node, digest) as old_key, FixtureSigner(node, digest) as new_key:
                old = s.AuthoritySelection("issuer", "audience", "scope", "epoch", "old", old_key.public_key, 1, 120)
                def verifier(selected):
                    return s.SnapshotVerifier(expected_profile=s.PROFILE, selection=selected, node=node, node_sha256=digest)
                publisher = authority.AuthorityStore.create(root / "publisher", verifier=verifier(old))
                recipient = authority.AuthorityStore.create(root / "recipient", verifier=verifier(replace(old, minimum_revision=100)))
                dispatch = d.DurableStateStore.create(root / "dispatch", scope="empty", verifier_id="audience")
                move = PlannedMigration.prepare(root / "moved", source_root=BASELINE, publisher=publisher,
                    recipient=recipient, dispatch=dispatch,
                    new_selection=replace(old, kid="new", public_key_spki=new_key.public_key))
                result = move.run(old_signer=old_key, new_signer=new_key)
                self.assertEqual(result["selection"]["minimum_revision"], 101)
                selected = replace(old, kid="new", public_key_spki=new_key.public_key, minimum_revision=101)
                target = authority.AuthorityStore(root / "moved/recipient", verifier=verifier(selected),
                    expected_anchor=b.encode(result["anchors"]["recipient"]))
                self.assertEqual(target.status()["revision"], 0)
                self.assertFalse(target.status()["conflict"])
                self.assertTrue(target.status()["unavailable"])
                self.assertEqual(move.run(old_signer=None, new_signer=None, clock=None), result)

    def test_source_corruption_fails_without_reset(self):
        with self.fixture() as f:
            move = self.prepare(f)
            with closing(sqlite3.connect(f.old / "dispatch/state.sqlite3")) as connection, connection:
                connection.execute("UPDATE admissions SET receipt=? WHERE request_id=?", (b"corrupt", f.history["pending"]["request_id"]))
            with self.assertRaises(MigrationError):
                self.migrate(f, move)
            with closing(sqlite3.connect(f.old / "dispatch/state.sqlite3")) as connection, connection:
                self.assertEqual(connection.execute("SELECT receipt FROM admissions WHERE request_id=?", (f.history["pending"]["request_id"],)).fetchone()[0], b"corrupt")

    def test_destination_identity_replacement_refused(self):
        with self.fixture() as f:
            move = self.prepare(f)
            path = f.root / "moved/dispatch/state.sqlite3"
            path.rename(path.with_suffix(".saved"))
            path.write_bytes(path.with_suffix(".saved").read_bytes())
            with self.assertRaises(MigrationError):
                self.migrate(f, move)

    def test_crash_boundaries_and_idempotent_recovery(self):
        script = '''import base64, json, os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from migration import PlannedMigration, b
job=json.load(sys.stdin)
move=PlannedMigration(job["directory"],expected_anchor=b.encode(job["anchor"]))
def point(name):
    if name == job["point"]: os._exit(86)
move._point=point
move.run(old_signer=lambda *args: base64.b64decode(job["old_token"]),
         new_signer=lambda *args: base64.b64decode(job["new_token"]),
         clock=lambda: b.core.parse_time(job["now"]))
raise RuntimeError("Fault point was not reached")
'''
        points = ("locked", "keys_confirmed", "retired_publisher", "copied_publisher", "retired_recipient",
                  "copied_recipient", "retired_dispatch", "copied_dispatch", "before_commit", "committed")
        for point in points:
            with self.subTest(point=point), self.fixture() as f:
                move = self.prepare(f)
                tokens = []
                second = int((f.now - s.jwt.EPOCH).total_seconds())
                for selected, signer in ((f.selection, f.old_signer), (f.new_selection, f.new_signer)):
                    raw = signer({"alg": "ES256", "typ": s.TOKEN_TYPE, "kid": selected.kid}, {
                        "iss": selected.issuer, "aud": selected.audience, "scope": selected.scope,
                        "epoch": selected.epoch, "revision": 3, "iat": second, "nbf": second, "exp": second + 30,
                        "runtime_grants": [], "delegation_grants": []})
                    tokens.append(base64.b64encode(raw).decode())
                job = {"directory": str(move.directory), "anchor": json.loads(move.anchor), "point": point,
                       "now": b.core.iso(f.now), "old_token": tokens[0], "new_token": tokens[1]}
                process = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(Path(__file__).parent)],
                                         input=b.encode(job), capture_output=True, timeout=30)
                self.assertEqual(process.returncode, 86, process.stderr.decode())
                if point != "committed":
                    self.assertEqual(f.worker({"action": "status", "request_id": f.history["pending"]["request_id"]})["status"]["state"], "ready")
                reopened = PlannedMigration(move.directory, expected_anchor=move.anchor)
                _, result = self.migrate(f, reopened)
                self.assertEqual(result["selection"]["minimum_revision"], 4)
                self.assertEqual(f.worker({"action": "status", "request_id": f.history["unknown"]["request_id"]}, target=True)["status"]["state"], "outcome_unknown")
                self.assertEqual(reopened.run(old_signer=None, new_signer=None, clock=None), result)


if __name__ == "__main__":
    unittest.main()
