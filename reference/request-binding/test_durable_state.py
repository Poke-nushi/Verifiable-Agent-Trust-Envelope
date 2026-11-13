"""Local restart, contention and interruption checks; no external operations."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import timedelta
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

import request_binding as b
import test_runtime_evidence as fixtures

s = b.durable_state_module()


@contextmanager
def database(path, **options):
    connection = sqlite3.connect(path, **options)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def process_worker(directory, anchor, key, mode, marker, ready, start, results):
    """Spawned interpreter reopens stored artifacts with application trust."""
    fixture = fixtures.RuntimeEvidenceTests()
    fixture.setUp()
    fixture.key = key
    fixture.attach()
    store = s.DurableStateStore(directory, expected_anchor=anchor)

    def callback(effective, checkpoint):
        with open(marker, "ab", buffering=0) as output:
            output.write((b.digest(effective)["value"] + "\n").encode())
        if mode == "exit_in_callback":
            os._exit(23)
        return "recorded locally"

    verifier = fixture.verifier
    verifier.state_store = store
    verifier.dispatch_boundary = b.DispatchBoundary(execute=callback, clock=lambda: fixture.now)
    try:
        if mode == "admit":
            ready.put(True)
            if not start.wait(10):
                raise RuntimeError("test start timeout")
            fixture.admit()
            results.put("admitted")
            return
        bound = verifier.restore_admission(fixture.request["request_id"])
        ready.put(True)
        if not start.wait(10):
            raise RuntimeError("test start timeout")
        if mode == "exit_after_claim":
            commit = store._commit
            def interrupted(connection):
                claimed = connection.execute("SELECT count(*) FROM operations").fetchone()[0]
                commit(connection)
                if claimed:
                    os._exit(23)
            store._commit = interrupted
        elif mode == "exit_after_return":
            store.finish = lambda *args, **kwargs: os._exit(23)
        verifier.dispatch(bound)
        results.put("returned")
    except b.Invalid as exc:
        results.put(exc.cause)
    except Exception as exc:
        results.put(type(exc).__name__)


class DurableStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / "state"
        self.fixture = fixtures.RuntimeEvidenceTests()
        self.fixture.setUp()
        self.verifier = self.fixture.verifier
        self.now = self.fixture.now
        self.calls = []
        self.store = s.DurableStateStore.create(self.directory, scope="test purchase scope",
            verifier_id=self.verifier.verifier_id)
        self.configure(self.verifier, self.store)
        self.request_id = self.fixture.request["request_id"]

    def callback(self, *args):
        self.calls.append(args)
        return b"recorded"

    def configure(self, verifier, store):
        verifier.state_store = store
        verifier.dispatch_boundary = b.DispatchBoundary(execute=self.callback, clock=lambda: self.now)
        return verifier

    def reopen(self):
        return self.configure(self.fixture.new_verifier(),
            s.DurableStateStore(self.directory, expected_anchor=self.store.anchor))

    def status(self):
        return self.verifier.dispatch_status(self.request_id)

    def admit(self, **options):
        return self.fixture.admit(**options)

    def rejection(self, function, cause):
        with self.assertRaisesRegex(b.Invalid, "^" + cause + "$"):
            function()

    def change_request_id(self, request_id):
        self.fixture.request["request_id"] = request_id
        self.fixture.claims["context_hash"] = b.runtime_context_hash(
            b.encode(self.fixture.request), b.encode(self.fixture.original))
        self.fixture.attach()

    def test_restart_restores_exact_artifacts_and_reauthenticates(self):
        bound = self.admit()
        restarted = self.reopen()
        restored = restarted.restore_admission(self.request_id)
        self.assertEqual(bound, restored)
        self.assertIsNot(bound, restored)
        self.assertEqual(self.status().state, "ready")
        with patch.object(restarted, "_evaluate_policy", side_effect=AssertionError("must not re-admit")):
            result = restarted.dispatch(restored)
        self.assertEqual(self.calls, [(bound.effective, result.checkpoint)])
        self.assertEqual(len(self.fixture.calls), 2)
        self.assertEqual(self.status().state, "callback_returned")
        self.assertEqual(self.status().checkpoint, result.checkpoint)
        self.rejection(lambda: self.verifier.dispatch(bound), "DURABLE_OPERATION_ALREADY_ATTEMPTED")
        self.rejection(lambda: self.reopen().restore_admission(self.request_id), "DURABLE_OPERATION_ALREADY_ATTEMPTED")
        self.assertEqual(len(self.calls), 1)

    def test_receipt_copy_is_not_restore_authority(self):
        bound = self.admit()
        self.rejection(lambda: self.reopen().dispatch(replace(bound)), "DISPATCH_ADMISSION_NOT_ISSUED")
        self.rejection(lambda: self.reopen().restore_admission("absent"), "STATE_ADMISSION_NOT_FOUND")
        self.assertEqual(self.calls, [])

    def test_admission_replay_survives_restart(self):
        self.admit()
        self.fixture.verifier = self.reopen()
        self.rejection(self.admit, "DURABLE_REPLAY_DETECTED")
        self.assertEqual(self.calls, [])

    def test_operation_id_fences_another_previously_admitted_request(self):
        first = self.admit()
        self.change_request_id("urn:test:second-request")
        second = self.admit()
        self.verifier.dispatch(first)
        self.rejection(lambda: self.verifier.dispatch(second), "DURABLE_OPERATION_ALREADY_ATTEMPTED")
        status = self.verifier.dispatch_status(self.fixture.request["request_id"])
        self.assertEqual(status.state, "operation_already_attempted")
        self.assertEqual(b.decode(status.record)["attempt_request_id"], self.request_id)
        self.assertEqual(len(self.calls), 1)

    def test_new_request_cannot_re_admit_consumed_operation(self):
        self.verifier.dispatch(self.admit())
        self.change_request_id("urn:test:second-request")
        self.fixture.verifier = self.reopen()
        self.rejection(self.admit, "DURABLE_OPERATION_ALREADY_ATTEMPTED")
        self.assertEqual(len(self.calls), 1)

    def test_deny_and_new_permit_are_retained_but_cannot_restore(self):
        for require_permit in (False, True):
            with self.subTest(require_permit=require_permit):
                self.change_request_id("urn:test:decision:" + str(require_permit))
                if not require_permit:
                    self.fixture.policy["allowed_actions"] = ["other"]
                    self.fixture.request["evidence_refs"][0]["digest"] = b.digest(b.encode(self.fixture.policy))
                    self.fixture.claims["context_hash"] = b.runtime_context_hash(
                        b.encode(self.fixture.request), b.encode(self.fixture.original))
                    self.fixture.attach()
                else:
                    self.fixture.policy.pop("allowed_actions")
                    self.fixture.request["evidence_refs"][0]["digest"] = b.digest(b.encode(self.fixture.policy))
                    self.fixture.claims["context_hash"] = b.runtime_context_hash(
                        b.encode(self.fixture.request), b.encode(self.fixture.original))
                    self.fixture.attach()
                self.admit(require_new_permit=require_permit)
                self.assertEqual(self.verifier.dispatch_status(self.fixture.request["request_id"]).state, "not_executable")
                self.rejection(lambda: self.verifier.restore_admission(self.fixture.request["request_id"]),
                               "DISPATCH_NOT_EXECUTABLE")

    def test_revocation_after_restart_stops_callback(self):
        self.admit()
        restarted = self.reopen()
        bound = restarted.restore_admission(self.request_id)
        with patch.object(b, "_verify_runtime_evidence", side_effect=b.Invalid("RUNTIME_EVIDENCE_VERIFICATION_FAILED")):
            self.rejection(lambda: restarted.dispatch(bound), "RUNTIME_EVIDENCE_VERIFICATION_FAILED")
        self.assertEqual(self.status().state, "ready")
        self.assertEqual(self.calls, [])

    def test_expired_restored_admission_remains_unexecuted(self):
        bound = self.admit()
        self.now = b.core.parse_time(b.decode(bound.receipt)["expires_at"]) + timedelta(microseconds=1)
        restarted = self.reopen()
        self.rejection(lambda: restarted.dispatch(restarted.restore_admission(self.request_id)), "DISPATCH_OUTSIDE_WINDOW")
        self.assertEqual(self.status().state, "ready")
        self.assertEqual(self.calls, [])

    def test_clock_high_water_survives_restart(self):
        bound = self.admit()
        self.now += timedelta(seconds=2)
        with patch.object(b, "_verify_runtime_evidence", side_effect=b.Invalid("RUNTIME_EVIDENCE_VERIFICATION_FAILED")):
            self.rejection(lambda: self.verifier.dispatch(bound), "RUNTIME_EVIDENCE_VERIFICATION_FAILED")
        self.now -= timedelta(seconds=1)
        restarted = self.reopen()
        self.rejection(lambda: restarted.dispatch(restarted.restore_admission(self.request_id)), "DURABLE_CLOCK_ROLLBACK")
        self.assertEqual(self.calls, [])

    def test_configuration_change_rejects_restore(self):
        self.admit()
        restarted = self.reopen()
        restarted.policy = {**restarted.policy, "policy_version": "changed"}
        self.rejection(lambda: restarted.restore_admission(self.request_id), "STATE_CONFIGURATION_CHANGED")
        self.assertEqual(self.calls, [])

    def test_loaded_implementation_change_rejects_restore(self):
        self.admit()
        with patch.object(b, "LOADED_SOURCE_SHA256", "0" * 64):
            self.rejection(lambda: self.reopen().restore_admission(self.request_id), "STATE_IMPLEMENTATION_CHANGED")

    def test_subclass_cannot_inherit_reference_implementation_identity(self):
        class AnotherImplementation(type(self.verifier)):
            pass
        self.fixture.verifier = AnotherImplementation(verifier_id=self.verifier.verifier_id,
            policy=self.fixture.policy, runtime_evidence_verifier=self.fixture.adapter,
            dispatch_boundary=self.verifier.dispatch_boundary, state_store=self.store)
        self.rejection(self.admit, "STATE_IMPLEMENTATION_CHANGED")
        self.rejection(self.status, "STATE_ADMISSION_NOT_FOUND")
        self.assertEqual(self.calls, [])

    def test_adapter_descriptor_change_rejects_restore(self):
        self.admit()
        restarted = self.reopen()
        restarted.runtime_evidence_verifier = replace(self.fixture.adapter, max_age_seconds=59)
        self.rejection(lambda: restarted.restore_admission(self.request_id), "STATE_CONFIGURATION_CHANGED")

    def test_store_replacement_on_live_verifier_rejected(self):
        bound = self.admit()
        self.verifier.state_store = self.reopen().state_store
        self.rejection(lambda: self.verifier.dispatch(bound), "DISPATCH_CONFIGURATION_CHANGED")

    def test_status_remains_readable_without_runtime_verification(self):
        self.admit()
        self.verifier.runtime_evidence_verifier = None
        self.verifier.dispatch_boundary = None
        self.assertEqual(self.status().state, "ready")

    def test_status_schema_binds_records_and_state_shape(self):
        try:
            from jsonschema import Draft202012Validator, FormatChecker
        except ImportError:
            self.skipTest("jsonschema is available in the repository venv")
        schema = json.loads((Path(b.__file__).parent / "schemas/durable-dispatch-status.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        bound = self.admit()
        ready = b.decode(self.status().record)
        validator.validate(ready)
        result = self.verifier.dispatch(bound)
        returned = b.decode(self.status().record)
        validator.validate(returned)
        self.assertEqual(returned["checkpoint_ref"], b.reference(result.checkpoint))
        self.assertEqual(returned["store_anchor_digest"], b.digest(self.store.anchor))
        self.assertEqual(returned["receipt_ref"], b.reference(bound.receipt))
        for changed in ({**ready, "checkpoint_ref": returned["checkpoint_ref"]},
                        {**returned, "attempt_request_id": None}, {**returned, "checkpoint_ref": None},
                        {**returned, "state": "executed_successfully"}, {**ready, "permission": True}):
            self.assertFalse(validator.is_valid(changed))

    def test_callback_exception_consumes_across_restart(self):
        def failed(*args):
            self.calls.append(args)
            raise b.Invalid("private application detail")
        self.verifier.dispatch_boundary = b.DispatchBoundary(execute=failed, clock=lambda: self.now)
        bound = self.admit()
        with self.assertRaises(b.DispatchAttemptError) as raised:
            self.verifier.dispatch(bound)
        self.assertEqual(str(raised.exception), "DISPATCH_OUTCOME_UNCONFIRMED")
        self.assertEqual(self.status().state, "outcome_unknown")
        self.assertEqual(self.status().checkpoint, raised.exception.checkpoint)
        self.rejection(lambda: self.reopen().restore_admission(self.request_id), "DURABLE_OPERATION_ALREADY_ATTEMPTED")
        self.assertEqual(len(self.calls), 1)

    def test_base_exception_preserves_consumed_state(self):
        self.verifier.dispatch_boundary = b.DispatchBoundary(
            execute=lambda *args: (_ for _ in ()).throw(KeyboardInterrupt()), clock=lambda: self.now)
        bound = self.admit()
        with self.assertRaises(KeyboardInterrupt):
            self.verifier.dispatch(bound)
        self.assertEqual(self.status().state, "attempt_consumed")
        self.rejection(lambda: self.reopen().restore_admission(self.request_id), "DURABLE_OPERATION_ALREADY_ATTEMPTED")

    def test_failed_admission_write_rolls_back_and_is_retryable(self):
        with patch.object(self.store, "_commit", side_effect=sqlite3.OperationalError("inert write fault")):
            self.rejection(self.admit, "STATE_UNAVAILABLE")
        self.assertEqual(self.verifier._seen_request_ids, set())
        self.rejection(self.status, "STATE_ADMISSION_NOT_FOUND")
        self.admit()
        self.assertEqual(self.status().state, "ready")

    def test_ambiguous_admission_commit_is_not_reissued(self):
        commit = self.store._commit
        def uncertain(connection):
            commit(connection)
            raise sqlite3.OperationalError("inert lost acknowledgement")
        with patch.object(self.store, "_commit", side_effect=uncertain):
            self.rejection(self.admit, "STATE_UNAVAILABLE")
        self.assertEqual(self.status().state, "ready")
        self.rejection(self.admit, "DURABLE_REPLAY_DETECTED")
        self.reopen().restore_admission(self.request_id)

    def test_claim_commit_failure_never_calls_callback(self):
        for committed in (False, True):
            with self.subTest(committed=committed):
                self.change_request_id("urn:test:claim:" + str(committed))
                bound = self.admit()
                commit = self.store._commit
                def uncertain(connection):
                    if connection.execute("SELECT count(*) FROM operations").fetchone()[0]:
                        if committed:
                            commit(connection)
                        raise sqlite3.OperationalError("inert claim fault")
                    commit(connection)
                with patch.object(self.store, "_commit", side_effect=uncertain):
                    self.rejection(lambda: self.verifier.dispatch(bound), "STATE_UNAVAILABLE")
                rid = self.fixture.request["request_id"]
                self.assertEqual(self.verifier.dispatch_status(rid).state, "attempt_consumed" if committed else "ready")
                self.rejection(lambda: self.verifier.dispatch(bound), "DISPATCH_ALREADY_ATTEMPTED")
        self.assertEqual(self.calls, [])

    def test_finish_write_failure_keeps_consumed_fence(self):
        bound = self.admit()
        with patch.object(self.store, "finish", side_effect=s.StateError("STATE_UNAVAILABLE")):
            with self.assertRaises(b.DispatchAttemptError):
                self.verifier.dispatch(bound)
        self.assertEqual(self.status().state, "attempt_consumed")
        self.rejection(lambda: self.reopen().restore_admission(self.request_id), "DURABLE_OPERATION_ALREADY_ATTEMPTED")
        self.assertEqual(len(self.calls), 1)

    def test_commit_duration_cannot_bypass_deadline(self):
        bound = self.admit()
        commit = self.store._commit
        def slow_commit(connection):
            consumed = connection.execute("SELECT count(*) FROM operations").fetchone()[0]
            commit(connection)
            if consumed:
                self.now += timedelta(seconds=100)
        with patch.object(self.store, "_commit", side_effect=slow_commit):
            with self.assertRaises(b.DispatchAttemptError):
                self.verifier.dispatch(bound)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.status().state, "outcome_unknown")

    def test_sqlite_lock_wait_is_included_in_final_deadline(self):
        bound = self.admit()
        claim = self.store.claim
        acquired = threading.Event()
        release = threading.Event()
        def holder():
            with database(self.directory / "state.sqlite3", isolation_level=None) as connection:
                connection.execute("BEGIN IMMEDIATE")
                acquired.set()
                if not release.wait(5):
                    raise RuntimeError("test lock timeout")
                self.now += timedelta(seconds=100)
                connection.execute("COMMIT")
        def waiting(*args):
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(holder)
                self.assertTrue(acquired.wait(5))
                # Release after the store reaches BEGIN IMMEDIATE, not a sleep.
                connect = s.sqlite3.connect
                def connection(*a, **kw):
                    value = connect(*a, **kw)
                    value.set_trace_callback(lambda sql: release.set() if sql == "BEGIN IMMEDIATE" else None)
                    return value
                with patch.object(s.sqlite3, "connect", side_effect=connection):
                    try:
                        return claim(*args)
                    finally:
                        release.set()
                        future.result(timeout=5)
        with patch.object(self.store, "claim", side_effect=waiting):
            self.rejection(lambda: self.verifier.dispatch(bound), "DISPATCH_OUTSIDE_WINDOW")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.status().state, "ready")

    def test_busy_store_fails_closed_and_is_not_recreated(self):
        bound = self.admit()
        self.store.timeout = 0.01
        connection = sqlite3.connect(self.directory / "state.sqlite3", isolation_level=None)
        try:
            connection.execute("BEGIN IMMEDIATE")
            self.rejection(lambda: self.verifier.dispatch(bound), "STATE_UNAVAILABLE")
        finally:
            connection.rollback()
            connection.close()
        self.assertEqual(self.status().state, "ready")
        self.assertEqual(self.calls, [])

    def test_missing_database_fails_closed_without_creation(self):
        bound = self.admit()
        db = self.directory / "state.sqlite3"
        db.unlink()
        self.rejection(lambda: self.verifier.dispatch(bound), "STATE_UNAVAILABLE")
        self.assertFalse(db.exists())
        self.assertEqual(self.calls, [])

    def test_corrupt_database_fails_closed(self):
        self.admit()
        (self.directory / "state.sqlite3").write_bytes(b"inert corrupt database")
        self.rejection(self.status, "STATE_UNAVAILABLE")

    def test_replaced_database_does_not_reset_replay(self):
        self.admit()
        other = s.DurableStateStore.create(Path(self.tmp.name) / "other", scope=self.store.scope,
            verifier_id=self.verifier.verifier_id)
        os.replace(other.directory / "state.sqlite3", self.directory / "state.sqlite3")
        self.rejection(self.status, "STATE_STORE_REPLACED")

    def test_altered_artifact_is_rejected_before_restore(self):
        self.admit()
        with database(self.directory / "state.sqlite3") as connection:
            connection.execute("UPDATE admissions SET effective=?", (b"{}",))
        self.rejection(lambda: self.verifier.restore_admission(self.request_id), "STATE_RECORD_CHANGED")

    def test_changed_schema_or_identity_is_rejected(self):
        with database(self.directory / "state.sqlite3") as connection:
            connection.execute("CREATE TABLE unexpected(x TEXT)")
        self.rejection(self.status, "STATE_SCHEMA_CHANGED")
        with database(self.directory / "state.sqlite3") as connection:
            connection.execute("DROP TABLE unexpected")
            connection.execute("UPDATE identity SET scope='different'")
        self.rejection(self.status, "STATE_IDENTITY_MISMATCH")

    def test_nonreserved_sqlite_like_name_is_not_hidden_from_schema_check(self):
        self.admit()
        with database(self.directory / "state.sqlite3") as connection:
            connection.execute("CREATE TABLE sqliteXunexpected(x TEXT)")
        self.rejection(self.status, "STATE_SCHEMA_CHANGED")

    def test_wrong_anchor_and_existing_create_are_rejected(self):
        changed = json.loads(self.store.anchor)
        changed["store_id"] = "another-store"
        with self.assertRaisesRegex(s.StateError, "STATE_IDENTITY_MISMATCH"):
            s.DurableStateStore(self.directory, expected_anchor=s.encode(changed))
        with self.assertRaises(FileExistsError):
            s.DurableStateStore.create(self.directory, scope="new", verifier_id=self.verifier.verifier_id)
        with self.assertRaisesRegex(s.StateError, "STATE_ANCHOR_INVALID"):
            s.DurableStateStore(self.directory, expected_anchor=self.store.anchor + b" ")

    def test_symlink_database_and_sidecar_rejected(self):
        db = self.directory / "state.sqlite3"
        saved = self.directory / "saved.sqlite3"
        db.rename(saved)
        db.symlink_to(saved)
        self.rejection(self.status, "STATE_STORE_REPLACED")
        db.unlink()
        saved.rename(db)
        sidecar = Path(str(db) + "-journal")
        sidecar.symlink_to(Path(self.tmp.name) / "absent")
        self.rejection(self.status, "STATE_SIDECAR_INVALID")

    def test_two_processes_share_one_admission_replay_decision(self):
        self.run_processes("admit", count=2, expected=["admitted", "DURABLE_REPLAY_DETECTED"])
        self.assertEqual(self.status().state, "ready")

    def test_two_processes_enter_callback_at_most_once(self):
        self.admit()
        marker = self.run_processes("dispatch", count=2, expected=["returned", "DURABLE_OPERATION_ALREADY_ATTEMPTED"])
        self.assertEqual(len(marker.read_bytes().splitlines()), 1)
        self.assertEqual(self.status().state, "callback_returned")

    def test_abrupt_process_exit_preserves_attempt(self):
        for mode, calls in (("exit_after_claim", 0), ("exit_in_callback", 1), ("exit_after_return", 1)):
            with self.subTest(mode=mode):
                # Isolated stores model independent operations; no recovery reset.
                self.store = s.DurableStateStore.create(Path(self.tmp.name) / mode,
                    scope="test purchase scope", verifier_id=self.verifier.verifier_id)
                self.directory = self.store.directory
                self.verifier = self.configure(self.fixture.new_verifier(), self.store)
                self.fixture.verifier = self.verifier
                self.admit()
                marker = self.run_processes(mode, count=1, expected=None)
                self.assertEqual(len(marker.read_bytes().splitlines()) if marker.exists() else 0, calls)
                self.assertEqual(self.status().state, "attempt_consumed")
                self.rejection(lambda: self.reopen().restore_admission(self.request_id), "DURABLE_OPERATION_ALREADY_ATTEMPTED")

    def run_processes(self, mode, count, expected):
        context = multiprocessing.get_context("spawn")
        ready, results, start = context.Queue(), context.Queue(), context.Event()
        marker = Path(self.tmp.name) / (mode + ".calls")
        processes = [context.Process(target=process_worker, args=(self.directory, self.store.anchor,
            self.fixture.key, mode, marker, ready, start, results)) for _ in range(count)]
        try:
            for process in processes:
                process.start()
            for _ in processes:
                self.assertTrue(ready.get(timeout=10))
            start.set()
            if expected is not None:
                self.assertCountEqual([results.get(timeout=10) for _ in processes], expected)
            for process in processes:
                process.join(timeout=10)
                self.assertEqual(process.exitcode, 0 if expected is not None else 23)
            return marker
        finally:
            start.set()
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
                process.close()
            for queue in (ready, results):
                queue.close()
                queue.join_thread()


if __name__ == "__main__":
    unittest.main()
