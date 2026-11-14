"""Refresh ordering and local readiness using signed disposable purchase fixtures."""
import copy
from datetime import timedelta
import multiprocessing
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import PropertyMock, patch

import snapshot as s
from authority_store import AuthorityStore
from managed_verifier import ManagedAuthorityVerifier
from refresh_lifecycle import RefreshingAuthorityVerifier
from supervised_https import SupervisedHttpsSnapshotSource
import test_authority_updates as fixtures
import test_https_intake as https_fixtures

b = s.b


def inherited_controller_process(controller, results):
    observations = []
    for action in (controller.poll, controller.status, controller.close):
        try:
            action(); observations.append("accepted")
        except s.AuthorityError as error:
            observations.append(error.cause)
    results.put(observations)


def reopened_process(options, results):
    """A fresh process has the retained anchors, not a copied controller or ready flag."""
    controller = None
    try:
        selected = s.SnapshotVerifier(expected_profile=s.PROFILE, selection=options["selection"],
            node=options["node"], node_sha256=options["node_sha256"])
        source = AuthorityStore(options["authority_directory"], verifier=selected,
            expected_anchor=options["authority_anchor"], clock=lambda: options["now"])
        state = b.durable_state_module().DurableStateStore(options["dispatch_directory"],
            expected_anchor=options["dispatch_anchor"])
        calls = []
        verifier = ManagedAuthorityVerifier(source=source, verifier_id=options["verifier_id"],
            policy=options["policy"], state_store=state, execute=lambda *args: calls.append(args),
            max_runtime_token_age_seconds=60, max_caller_token_age_seconds=40)
        fetch = SupervisedHttpsSnapshotSource(options["url"], ca_file=options["ca_file"])
        controller = RefreshingAuthorityVerifier(verifier=verifier, fetch=fetch,
            refresh_interval_seconds=5, retry_interval_seconds=2)
        observed = {"initial_phase": controller.status().phase,
            "retained_state": controller.dispatch_status(options["request_id"]).state}
        try:
            restored = controller.restore_admission(options["request_id"])
            observed["receipt_unchanged"] = restored.receipt == options["receipt"]
            controller.dispatch(restored, caller_proof=options["proof"])
            observed["operation"] = "returned"
        except (s.AuthorityError, b.Invalid) as error:
            observed["operation"] = error.cause
        observed.update(calls=len(calls), revision=source.status()["revision"])
        controller.close()
        observed["phase"] = controller.status().phase
        results.put(observed)
    except BaseException as error:
        results.put({"error": getattr(error, "cause", type(error).__name__)})
    finally:
        if controller is not None:
            controller.close()


class RefreshLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.AuthorityUpdateTests.setUpClass()

    def setUp(self):
        self.f = fixtures.AuthorityUpdateTests(); self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        revoked = copy.deepcopy(self.f.claims)
        revoked["revision"] = 2; revoked["delegation_grants"][0]["revoked"] = True
        self.tokens = self.f.setup_source([self.f.claims, revoked, {**self.f.claims, "revision": 3}])
        self.tick = 10.0
        self.fetch = SupervisedHttpsSnapshotSource("https://authority.example.invalid/snapshot")
        self.controller = self.new_controller()
        self.addCleanup(self.controller.close)
        self.body = self.tokens[0]
        acquisition = patch.object(SupervisedHttpsSnapshotSource, "__call__", side_effect=lambda: self.body)
        self.acquisition = acquisition.start()
        self.addCleanup(acquisition.stop)

    def new_controller(self, verifier=None, **options):
        return RefreshingAuthorityVerifier(verifier=verifier or self.f.managed, fetch=self.fetch,
            refresh_interval_seconds=options.pop("refresh_interval_seconds", 5),
            retry_interval_seconds=options.pop("retry_interval_seconds", 2),
            monotonic=options.pop("monotonic", lambda: self.tick), **options)

    def admit(self):
        return self.controller.admit(b.encode(self.f.f.f.request), original=b.encode(self.f.f.f.original),
            evidence_artifacts={"urn:example:jwt": self.f.f.f.raw}, caller_proof=self.f.f.proof)

    def test_first_operation_refreshes_and_idle_polls_keep_schedule(self):
        self.assertEqual(self.controller.status().phase, "refresh_required")
        bound = self.admit()
        self.assertEqual(self.acquisition.call_count, 1)
        self.assertEqual(self.controller.status().next_attempt_in_seconds, 5)
        self.tick = 14.99
        self.assertIsNone(self.controller.poll())
        self.assertEqual(self.acquisition.call_count, 1)
        self.body = self.tokens[1]; self.tick = 15
        self.assertEqual(self.controller.status().phase, "refresh_required")
        with self.assertRaisesRegex(b.Invalid, "CALLER_AUTHORIZATION_FAILED"):
            self.controller.dispatch(bound, caller_proof=self.f.f.proof)
        self.assertEqual(self.acquisition.call_count, 2)
        self.assertEqual(self.controller.status().last_installed_revision, 2)
        self.assertEqual(self.controller.status().phase, "refreshed")
        self.assertEqual(self.f.calls, [])

    def test_busy_store_failure_blocks_this_path_without_claiming_shared_suspension(self):
        bound = self.admit()
        other, _ = self.f.reopen()
        self.tick = 15
        with other.lease(), self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REFRESH_FAILED"):
            self.controller.poll()
        self.assertFalse(self.f.source.status()["unavailable"])
        self.assertEqual(self.f.source.status()["revision"], 1)
        self.assertEqual(self.controller.status().phase, "retry_wait")
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REFRESH_RETRY_WAIT"):
            self.controller.dispatch(bound, caller_proof=self.f.f.proof)
        self.assertIsNone(self.controller.poll())
        self.assertEqual(self.acquisition.call_count, 2)
        self.assertEqual(self.f.calls, [])
        self.tick = 17
        self.controller.dispatch(bound, caller_proof=self.f.f.proof)
        self.assertEqual(len(self.f.calls), 1)

    def test_retry_interval_begins_after_failure_and_does_not_expose_exception_text(self):
        def fail():
            self.tick += 3
            raise OSError("private transport details")
        self.acquisition.side_effect = fail
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REFRESH_FAILED"):
            self.controller.poll()
        self.assertEqual(self.controller.status().next_attempt_in_seconds, 2)
        self.assertEqual(self.controller.status().last_failure, "AUTHORITY_REFRESH_FAILED")
        self.tick = 14.9
        self.assertIsNone(self.controller.poll())
        self.assertEqual(self.acquisition.call_count, 1)
        self.tick = 15; self.acquisition.side_effect = lambda: self.body
        self.assertEqual(self.controller.poll()["revision"], 1)
        self.assertIsNone(self.controller.status().last_failure)

    def test_cleanup_must_finish_before_retry_acquisition(self):
        with patch.object(SupervisedHttpsSnapshotSource, "cleanup_required", new_callable=PropertyMock,
                          return_value=True), patch.object(self.fetch, "cleanup_pending",
                          side_effect=s.AuthorityError("AUTHORITY_FETCH_CLEANUP_FAILED")) as cleanup:
            with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_FETCH_CLEANUP_FAILED"):
                self.controller.poll()
            self.acquisition.assert_not_called()
            self.assertIsNone(self.controller.poll())
            self.assertEqual(cleanup.call_count, 1)
            with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_FETCH_CLEANUP_FAILED"):
                self.controller.close()
            self.assertEqual(self.controller.status().phase, "stop_requested")
        self.controller.close()
        self.assertEqual(self.controller.status().phase, "stopped")

    def test_pending_cleanup_precedes_successful_acquisition(self):
        events = []
        with patch.object(SupervisedHttpsSnapshotSource, "cleanup_required", new_callable=PropertyMock,
                          return_value=True), patch.object(self.fetch, "cleanup_pending",
                          side_effect=lambda: events.append("cleanup")):
            self.acquisition.side_effect = lambda: (events.append("fetch"), self.body)[1]
            self.controller.poll()
        self.assertEqual(events, ["cleanup", "fetch"])

    def test_complete_refresh_blocks_other_calls_and_stop_waits_for_completion(self):
        entered, release = threading.Event(), threading.Event()
        errors = []
        def fetch():
            entered.set()
            if not release.wait(10): raise RuntimeError("fixture release timeout")
            return self.body
        def run():
            try: self.controller.poll()
            except s.AuthorityError as error: errors.append(error.cause)
        self.acquisition.side_effect = fetch
        worker = threading.Thread(target=run)
        worker.start()
        try:
            self.assertTrue(entered.wait(5))
            for action in (self.controller.poll, self.admit, self.controller.close):
                with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REFRESH_BUSY"):
                    action()
            self.assertEqual(self.acquisition.call_count, 1)
        finally:
            release.set(); worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, ["AUTHORITY_REFRESH_STOP_REQUESTED"])
        self.assertEqual(self.f.calls, [])
        self.controller.close()
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REFRESH_STOP_REQUESTED"):
            self.controller.poll()

    def test_stop_during_callback_does_not_claim_remote_cancellation(self):
        entered, release = threading.Event(), threading.Event()
        errors = []
        def execute(*args):
            self.f.calls.append(args); entered.set()
            if not release.wait(10): raise RuntimeError("fixture release timeout")
        self.f.managed = self.f.configure(self.f.source, execute=execute)
        self.controller = self.new_controller()
        self.addCleanup(self.controller.close)
        bound = self.admit()
        def run():
            try: self.controller.dispatch(bound, caller_proof=self.f.f.proof)
            except BaseException as error: errors.append(type(error).__name__)
        worker = threading.Thread(target=run); worker.start()
        try:
            self.assertTrue(entered.wait(5))
            with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REFRESH_BUSY"):
                self.controller.close()
        finally:
            release.set(); worker.join(10)
        self.assertFalse(worker.is_alive()); self.assertEqual(errors, [])
        self.controller.close()
        self.assertEqual(len(self.f.calls), 1)
        self.assertEqual(self.controller.dispatch_status(self.f.f.f.request["request_id"]).state, "callback_returned")
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REFRESH_STOP_REQUESTED"):
            self.controller.dispatch(bound, caller_proof=self.f.f.proof)

    def test_stop_after_managed_entry_does_not_cancel_dispatch(self):
        bound = self.admit()
        dispatch = self.f.managed.dispatch
        def entered(*args, **kwargs):
            self.controller.request_stop()
            return dispatch(*args, **kwargs)
        with patch.object(self.f.managed, "dispatch", side_effect=entered):
            self.controller.dispatch(bound, caller_proof=self.f.f.proof)
        self.assertEqual(self.controller.status().phase, "stop_requested")
        self.controller.close()
        self.assertEqual(self.controller.dispatch_status(self.f.f.f.request["request_id"]).state, "callback_returned")
        self.assertEqual(len(self.f.calls), 1)

    def stop_at_dispatch_boundary(self, method):
        """Fix thread ordering without replacing stop, checks or managed dispatch."""
        bound = self.admit()
        paused, release, stopped = threading.Event(), threading.Event(), threading.Event()
        errors, stop_errors = [], []
        def trace(frame, event, arg):
            if (event == "return" and frame.f_code is method.__code__
                    and frame.f_back.f_code is RefreshingAuthorityVerifier._invoke.__code__):
                paused.set()
                if not release.wait(10): raise RuntimeError("fixture release timeout")
            return trace
        def dispatch():
            sys.settrace(trace)
            try: self.controller.dispatch(bound, caller_proof=self.f.f.proof)
            except BaseException as error: errors.append(getattr(error, "cause", type(error).__name__))
            finally: sys.settrace(None)
        def stop():
            try: self.controller.request_stop()
            except BaseException as error: stop_errors.append(type(error).__name__)
            finally: stopped.set()
        worker = threading.Thread(target=dispatch)
        stopper = threading.Thread(target=stop)
        worker.start()
        try:
            self.assertTrue(paused.wait(5))
            stopper.start()
            self.assertTrue(stopped.wait(5), "stop must not wait for managed execution")
        finally:
            release.set(); worker.join(10)
            if stopper.ident is not None: stopper.join(10)
        self.assertFalse(worker.is_alive()); self.assertFalse(stopper.is_alive())
        self.assertEqual(stop_errors, [])
        return errors

    def test_stop_after_configuration_checks_rejects_unaccepted_dispatch(self):
        errors = self.stop_at_dispatch_boundary(RefreshingAuthorityVerifier._running)
        self.assertEqual(errors, ["AUTHORITY_REFRESH_STOP_REQUESTED"])
        self.assertEqual(self.f.calls, [])
        self.assertEqual(self.controller.dispatch_status(self.f.f.f.request["request_id"]).state, "ready")

    def test_accepted_handoff_may_start_after_stop_returns(self):
        errors = self.stop_at_dispatch_boundary(RefreshingAuthorityVerifier._accept_managed_call)
        self.assertEqual(errors, [])
        self.assertEqual(len(self.f.calls), 1)
        self.assertEqual(self.controller.status().phase, "stop_requested")
        self.controller.close()
        self.assertEqual(self.controller.dispatch_status(self.f.f.f.request["request_id"]).state, "callback_returned")

    def check_installation_record_after_failure(self, *, subsequent, stopped):
        if subsequent:
            self.controller.poll()
            self.tick = 15
            self.body = self.tokens[1]
        def acquire():
            if stopped: self.controller.request_stop()
            else: self.tick = float("nan")
            return self.body
        self.acquisition.side_effect = acquire
        expected = "AUTHORITY_REFRESH_STOP_REQUESTED" if stopped else "AUTHORITY_REFRESH_CLOCK_INVALID"
        with self.assertRaisesRegex(s.AuthorityError, expected): self.controller.poll()
        status = self.controller.status()
        self.assertEqual(status.phase, "stop_requested" if stopped else "clock_failed")
        self.assertEqual(status.last_failure, expected)
        self.assertEqual(status.last_installed_revision, 2 if subsequent else 1)
        self.assertEqual(status.last_installed_revision, self.f.source.status()["revision"])
        self.assertEqual(self.f.calls, [])
        self.controller.close()
        self.assertEqual(self.controller.status().last_installed_revision, status.last_installed_revision)

    def test_initial_installation_is_recorded_before_stop_failure(self):
        self.check_installation_record_after_failure(subsequent=False, stopped=True)

    def test_later_installation_is_recorded_before_stop_failure(self):
        self.check_installation_record_after_failure(subsequent=True, stopped=True)

    def test_initial_installation_is_recorded_before_clock_failure(self):
        self.check_installation_record_after_failure(subsequent=False, stopped=False)

    def test_later_installation_is_recorded_before_clock_failure(self):
        self.check_installation_record_after_failure(subsequent=True, stopped=False)

    def test_preflight_failure_preserves_schedule_and_recovery_rechecks_permissions(self):
        bound = self.admit()
        self.tick = 11
        status = self.controller.status()
        with patch.object(self.f.source, "configuration_id",
                          side_effect=s.AuthorityError("AUTHORITY_IMPLEMENTATION_CHANGED")):
            for action in (self.controller.poll,
                           lambda: self.controller.dispatch(bound, caller_proof=self.f.f.proof)):
                with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_IMPLEMENTATION_CHANGED"):
                    action()
            self.assertEqual(self.controller.status(), status)
        self.assertEqual(self.acquisition.call_count, 1)
        self.assertEqual(self.f.calls, [])
        # Source recovery does not bypass current permissions or force an early fetch.
        self.f.source.accept(self.tokens[1])
        with self.assertRaisesRegex(b.Invalid, "CALLER_AUTHORIZATION_FAILED"):
            self.controller.dispatch(bound, caller_proof=self.f.f.proof)
        self.assertEqual(self.acquisition.call_count, 1)
        self.assertEqual(self.f.calls, [])
        self.f.source.accept(self.tokens[2])
        self.controller.dispatch(bound, caller_proof=self.f.f.proof)
        self.assertEqual(self.acquisition.call_count, 1)
        self.assertEqual(len(self.f.calls), 1)

    def test_due_preflight_failure_preserves_due_refresh_for_recovery(self):
        self.controller.poll(); self.tick = 15
        before = self.controller.status()
        with patch.object(self.f.source, "configuration_id", return_value="changed"):
            with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_CONFIGURATION_CHANGED"):
                self.controller.poll()
            self.assertEqual(self.controller.status(), before)
        self.assertEqual(self.acquisition.call_count, 1)
        self.assertEqual(self.controller.poll()["revision"], 1)
        self.assertEqual(self.acquisition.call_count, 2)
        self.assertEqual(self.controller.status().next_attempt_in_seconds, 5)

    def test_interrupt_requires_explicit_close_and_new_controller(self):
        for failure in (KeyboardInterrupt, SystemExit):
            with self.subTest(failure=failure.__name__):
                controller = self.new_controller()
                self.acquisition.side_effect = failure
                with self.assertRaises(failure): controller.poll()
                self.assertTrue(self.f.source.status()["unavailable"])
                self.assertEqual(controller.status().phase, "stop_requested")
                with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REFRESH_STOP_REQUESTED"):
                    controller.poll()
                controller.close()

    def test_interrupted_callback_retains_attempt_history_when_reopened(self):
        def execute(*args):
            self.f.calls.append(args)
            raise KeyboardInterrupt()
        self.f.managed = self.f.configure(self.f.source, execute=execute)
        self.controller = self.new_controller()
        self.addCleanup(self.controller.close)
        bound = self.admit()
        with self.assertRaises(KeyboardInterrupt):
            self.controller.dispatch(bound, caller_proof=self.f.f.proof)
        self.assertEqual(self.controller.status().phase, "stop_requested")
        request_id = self.f.f.f.request["request_id"]
        self.assertEqual(self.controller.dispatch_status(request_id).state, "attempt_consumed")
        self.controller.close()
        self.f.source, self.f.managed = self.f.reopen()
        reopened = self.new_controller()
        self.addCleanup(reopened.close)
        with self.assertRaisesRegex(b.Invalid, "DURABLE_OPERATION_ALREADY_ATTEMPTED"):
            reopened.restore_admission(request_id)
        self.assertEqual(reopened.dispatch_status(request_id).state, "attempt_consumed")
        self.assertEqual(len(self.f.calls), 1)

    def test_clock_failure_stays_closed_even_if_clock_later_recovers(self):
        for value in (float("nan"), float("inf"), -1, True, "15", 9, 10**400):
            with self.subTest(value_type=type(value).__name__):
                self.tick = 10
                controller = self.new_controller(); controller.poll()
                self.tick = value
                with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REFRESH_CLOCK_INVALID"):
                    controller.poll()
                self.tick = 16
                with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REFRESH_CLOCK_INVALID"):
                    controller.poll()
                self.assertEqual(controller.status().phase, "clock_failed")
                controller.close()

    def test_clock_interrupt_requests_stop_even_before_fetch(self):
        with patch.object(self.controller, "_monotonic", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): self.controller.poll()
        self.assertEqual(self.controller.status().phase, "stop_requested")
        self.acquisition.assert_not_called()

    def test_unrepresentable_deadline_and_invalid_configuration_rejected(self):
        for value in (0, -1, True, float("inf"), float("nan"), "5", 10**400):
            with self.subTest(value_type=type(value).__name__), self.assertRaisesRegex(
                    s.AuthorityError, "AUTHORITY_REFRESH_CONFIGURATION_INVALID"):
                self.new_controller(refresh_interval_seconds=value)
        self.tick = 1e100
        controller = self.new_controller()
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REFRESH_CLOCK_INVALID"):
            controller.poll()
        self.assertEqual(controller.status().phase, "clock_failed")
        controller.close()

    def test_store_expiry_still_rejects_when_refresh_timer_has_not_elapsed(self):
        bound = self.admit()
        self.f.now += timedelta(seconds=31)
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_STALE"):
            self.controller.dispatch(bound, caller_proof=self.f.f.proof)
        self.assertEqual(self.acquisition.call_count, 1)
        self.assertEqual(self.f.calls, [])

    def test_reopen_ignores_old_ready_state_and_keeps_revision_fence(self):
        self.controller.poll(); self.controller.close()
        self.f.source, self.f.managed = self.f.reopen()
        controller = self.new_controller()
        self.assertEqual(controller.status().phase, "refresh_required")
        self.acquisition.side_effect = OSError("offline")
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REFRESH_FAILED"):
            controller.restore_admission(self.f.f.f.request["request_id"])
        self.assertEqual(self.f.source.status()["revision"], 1)
        self.assertEqual(controller.status().phase, "retry_wait")
        controller.close()

    def test_forked_controller_cannot_acquire_or_close_parent_resources(self):
        self.controller.poll()
        context = multiprocessing.get_context("fork")
        results = context.Queue()
        worker = context.Process(target=inherited_controller_process, args=(self.controller, results))
        worker.start()
        try:
            self.assertEqual(results.get(timeout=5), ["AUTHORITY_REFRESH_FORK_REOPEN_REQUIRED"] * 3)
            worker.join(5)
            self.assertFalse(worker.is_alive()); self.assertEqual(worker.exitcode, 0)
        finally:
            if worker.is_alive(): worker.kill(); worker.join(5)
            results.close(); results.join_thread()
        self.assertEqual(self.controller.status().phase, "refreshed")
        self.assertEqual(self.acquisition.call_count, 1)

    def test_changed_configuration_rejected_without_losing_cleanup_access(self):
        self.controller.poll()
        with patch.object(self.f.source, "configuration_id", return_value="changed"):
            with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_CONFIGURATION_CHANGED"):
                self.controller.poll()
            self.controller.close()
        self.assertEqual(self.controller.status().phase, "stopped")
        self.assertEqual(self.acquisition.call_count, 1)


class RefreshLifecycleHttpsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.AuthorityUpdateTests.setUpClass()
        https_fixtures.HttpsIntakeTests.setUpClass.__func__(cls)

    def setUp(self):
        self.http = https_fixtures.HttpsIntakeTests()
        self.http.cert, self.http.key = self.cert, self.key
        self.http.setUp(); self.addCleanup(self.http.doCleanups)
        self.f = fixtures.AuthorityUpdateTests(); self.f.setUp(); self.addCleanup(self.f.doCleanups)
        revoked = copy.deepcopy(self.f.claims); revoked["revision"] = 2
        revoked["delegation_grants"][0]["revoked"] = True
        self.tokens = self.f.setup_source([self.f.claims, revoked, {**self.f.claims, "revision": 3}])
        self.fetch = SupervisedHttpsSnapshotSource(self.http.base + "/ok", ca_file=self.cert)
        self.tick = 10
        self.controller = RefreshingAuthorityVerifier(verifier=self.f.managed, fetch=self.fetch,
            refresh_interval_seconds=5, retry_interval_seconds=2, monotonic=lambda: self.tick)
        self.addCleanup(self.controller.close)

    def child(self, receipt):
        options = {"selection": self.f.selection, "node": self.f.f.f.node, "node_sha256": self.f.f.f.node_sha,
            "authority_directory": self.f.source.directory, "authority_anchor": self.f.source.anchor,
            "dispatch_directory": self.f.f.store.directory, "dispatch_anchor": self.f.f.store.anchor,
            "now": self.f.now, "verifier_id": self.f.f.f.verifier.verifier_id, "policy": self.f.f.f.policy,
            "url": self.http.base + "/ok", "ca_file": self.cert, "request_id": self.f.f.f.request["request_id"],
            "proof": self.f.f.proof, "receipt": receipt}
        context = multiprocessing.get_context("spawn")
        results = context.Queue()
        worker = context.Process(target=reopened_process, args=(options, results))
        worker.start()
        try:
            result = results.get(timeout=20)
            worker.join(10)
            self.assertFalse(worker.is_alive()); self.assertEqual(worker.exitcode, 0)
            return result
        finally:
            if worker.is_alive(): worker.kill(); worker.join(5)
            results.close(); results.join_thread()

    def test_https_failure_process_restart_revocation_recovery_and_dispatch_history(self):
        self.http.body = self.tokens[0]
        self.controller.poll()
        bound = self.controller.admit(b.encode(self.f.f.f.request), original=b.encode(self.f.f.f.original),
            evidence_artifacts={"urn:example:jwt": self.f.f.f.raw}, caller_proof=self.f.f.proof)
        self.http.body = b"invalid.response"; self.tick = 15
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REFRESH_FAILED"):
            self.controller.dispatch(bound, caller_proof=self.f.f.proof)
        self.assertTrue(self.f.source.status()["unavailable"])
        self.assertEqual(self.f.calls, [])
        self.controller.close()
        self.http.body = self.tokens[1]
        self.assertEqual(self.child(bound.receipt), {"initial_phase": "refresh_required", "retained_state": "ready",
            "receipt_unchanged": True, "operation": "CALLER_AUTHORIZATION_FAILED", "calls": 0,
            "revision": 2, "phase": "stopped"})
        self.f.source, self.f.managed = self.f.reopen()
        controller = RefreshingAuthorityVerifier(verifier=self.f.managed,
            fetch=SupervisedHttpsSnapshotSource(self.http.base + "/ok", ca_file=self.cert),
            refresh_interval_seconds=5, retry_interval_seconds=2, monotonic=lambda: self.tick)
        self.addCleanup(controller.close)
        self.http.body = self.tokens[0]
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REFRESH_FAILED"): controller.poll()
        self.assertEqual(self.f.source.status()["revision"], 2)
        self.http.body = self.tokens[2]; self.tick = 17
        restored = controller.restore_admission(self.f.f.f.request["request_id"])
        controller.dispatch(restored, caller_proof=self.f.f.proof)
        self.assertEqual(restored.receipt, bound.receipt)
        self.assertEqual(len(self.f.calls), 1)
        controller.close()
        self.assertEqual(self.child(bound.receipt), {"initial_phase": "refresh_required",
            "retained_state": "callback_returned", "operation": "DURABLE_OPERATION_ALREADY_ATTEMPTED",
            "calls": 0, "revision": 3, "phase": "stopped"})
        self.assertFalse(self.fetch.cleanup_required)


if __name__ == "__main__":
    unittest.main()
