"""Abrupt local-process exit through refresh and durable dispatch; disposable effects."""
import copy
from datetime import timedelta
import multiprocessing
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

import snapshot as s
from authority_store import AuthorityStore
from managed_verifier import ManagedAuthorityVerifier
from refresh_lifecycle import RefreshingAuthorityVerifier
import supervised_https as h
import test_authority_updates as fixtures
import test_https_intake as https_fixtures

b = s.b
CRASH_EXIT = 73


def open_session(options, execute):
    verifier = s.SnapshotVerifier(expected_profile=s.PROFILE, selection=options["selection"],
        node=options["node"], node_sha256=options["node_sha256"])
    source = AuthorityStore(options["authority_directory"], verifier=verifier,
        expected_anchor=options["authority_anchor"], clock=lambda: options["now"])
    state = b.durable_state_module().DurableStateStore(options["dispatch_directory"],
        expected_anchor=options["dispatch_anchor"])
    managed = ManagedAuthorityVerifier(source=source, verifier_id=options["verifier_id"],
        policy=options["policy"], state_store=state, execute=execute,
        max_runtime_token_age_seconds=60, max_caller_token_age_seconds=40)
    fetch = h.SupervisedHttpsSnapshotSource(options["url"], ca_file=options["ca_file"],
        timeout_seconds=options.get("timeout", 5))
    session = RefreshingAuthorityVerifier(verifier=managed, fetch=fetch,
        refresh_interval_seconds=5, retry_interval_seconds=2)
    return session, source, state, fetch


def recovery_process(options, mode, report):
    """Only this test-created process is interrupted; no real external operation."""
    session = None
    observations = {}
    def execute(*args):
        with open(options["marker"], "ab", buffering=0) as marker:
            marker.write(b"local effect\n"); os.fsync(marker.fileno())
        if mode == "in_callback": os._exit(CRASH_EXIT)
    try:
        session, source, state, fetch = open_session(options, execute)
        request_id = options["request_id"]
        observations.update(initial_phase=session.status().phase,
            initial_history=session.dispatch_status(request_id).state)
        if mode in ("before_install", "after_install"):
            accept = source.accept
            def install(raw):
                if mode == "before_install": os._exit(CRASH_EXIT)
                accept(raw)
                os._exit(CRASH_EXIT)
            with patch.object(source, "accept", side_effect=install): session.poll()
        elif mode == "fetch_owner_exit":
            # Exercise the real worker with a local stalled resolver, without DNS traffic.
            code = """import pathlib, runpy, socket, sys, time
worker, marker = sys.argv[1:]
def stalled(*args, **kwargs):
    pathlib.Path(marker).write_text('entered')
    time.sleep(60)
socket.getaddrinfo = stalled
sys.argv = [worker, '--worker']
runpy.run_path(worker, run_name='__main__')
"""
            command = [sys.executable, "-I", "-S", "-B", "-c", code,
                       str(Path(h.__file__).resolve()), str(options["resolver_marker"])]
            popen = subprocess.Popen
            def spawn(*args, **kwargs):
                process = popen(*args, **kwargs)
                report.send({"worker_pid": process.pid})
                return process
            with patch.object(fetch, "_command", return_value=command), \
                    patch.object(h.subprocess, "Popen", side_effect=spawn):
                session.poll()
        else:
            restored = session.restore_admission(request_id)
            observations["receipt_unchanged"] = restored.receipt == options["receipt"]
            if mode == "after_handoff":
                accepted = session._accept_managed_call
                def handoff():
                    accepted(); os._exit(CRASH_EXIT)
                session._accept_managed_call = handoff
            elif mode == "after_claim":
                commit = state._commit
                def claimed(connection):
                    count = connection.execute("SELECT count(*) FROM operations").fetchone()[0]
                    commit(connection)
                    if count: os._exit(CRASH_EXIT)
                state._commit = claimed
            elif mode in ("after_callback", "after_finish"):
                finish = state.finish
                def finished(*args, **kwargs):
                    if mode == "after_finish": finish(*args, **kwargs)
                    os._exit(CRASH_EXIT)
                state.finish = finished
            session.dispatch(restored, caller_proof=options["proof"])
        observations["operation"] = "returned"
    except BaseException as error:
        observations["operation"] = getattr(error, "cause", type(error).__name__)
    finally:
        if session is not None:
            observations.update(revision=source.status()["revision"],
                final_history=session.dispatch_status(options["request_id"]).state)
            session.close()
        report.send(observations)
        report.close()


def process_state(pid):
    result = subprocess.run(["ps", "-p", str(pid), "-o", "stat="], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3)
    return result.stdout.strip()


def process_exited(pid):
    state = process_state(pid)
    # Reaping an orphan belongs to its new OS parent; an exited zombie cannot fetch.
    return not state or state.startswith("Z")


class LifecycleRecoveryTests(unittest.TestCase):
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
        self.http.body = self.tokens[0]
        fetch = h.SupervisedHttpsSnapshotSource(self.http.base + "/ok", ca_file=self.cert)
        session = RefreshingAuthorityVerifier(verifier=self.f.managed, fetch=fetch,
            refresh_interval_seconds=5, retry_interval_seconds=2)
        self.addCleanup(session.close)
        self.bound = session.admit(b.encode(self.f.f.f.request), original=b.encode(self.f.f.f.original),
            evidence_artifacts={"urn:example:jwt": self.f.f.f.raw}, caller_proof=self.f.f.proof)
        session.close()
        self.marker = Path(self.f.tmp.name) / "effects"
        self.options = {"selection": self.f.selection, "node": self.f.f.f.node,
            "node_sha256": self.f.f.f.node_sha, "authority_directory": self.f.source.directory,
            "authority_anchor": self.f.source.anchor, "dispatch_directory": self.f.f.store.directory,
            "dispatch_anchor": self.f.f.store.anchor, "now": self.f.now,
            "verifier_id": self.f.f.f.verifier.verifier_id, "policy": self.f.f.f.policy,
            "url": self.http.base + "/ok", "ca_file": self.cert,
            "request_id": self.f.f.f.request["request_id"], "proof": self.f.f.proof,
            "receipt": self.bound.receipt, "marker": self.marker}
        self.processes, self.workers = [], []
        self.addCleanup(self.cleanup_processes)

    def cleanup_processes(self):
        for process in self.processes:
            if process.is_alive(): process.kill(); process.join(5)
            self.assertFalse(process.is_alive())
        for pid in self.workers:
            if not process_exited(pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.assertTrue(self.wait_for(lambda: process_exited(pid), 5),
                                "fixture worker did not exit during cleanup")

    def wait_for(self, predicate, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate(): return True
            time.sleep(0.05)
        return predicate()

    def spawn(self, mode, **overrides):
        context = multiprocessing.get_context("spawn")
        incoming, outgoing = context.Pipe(duplex=False)
        worker = context.Process(target=recovery_process,
            args=({**self.options, **overrides}, mode, outgoing))
        worker.start(); outgoing.close()
        self.processes.append(worker); self.addCleanup(incoming.close)
        return worker, incoming

    def run_child(self, mode="recover", expected=0, **overrides):
        worker, incoming = self.spawn(mode, **overrides)
        worker.join(25)
        self.assertFalse(worker.is_alive(), "fixture process did not finish")
        self.assertEqual(worker.exitcode, expected)
        if expected == 0:
            self.assertTrue(incoming.poll(3))
            return incoming.recv()

    def effects(self):
        return len(self.marker.read_bytes().splitlines()) if self.marker.exists() else 0

    def assert_original_receipt(self):
        record = self.f.f.store.read(self.options["request_id"])
        self.assertEqual(record["values"][3], self.bound.receipt)

    def check_update_exit(self, mode, revision):
        self.http.body = self.tokens[1]
        now = self.f.now + timedelta(seconds=5)
        self.run_child(mode, expected=CRASH_EXIT, now=now)
        saved = self.f.source.status()
        self.assertEqual(saved["revision"], revision)
        # accept observes UTC before installation; an exit before accept leaves old time.
        self.assertEqual(saved["clock_high"], b.core.iso(now if mode == "after_install" else self.f.now))
        self.assertEqual(self.effects(), 0); self.assert_original_receipt()
        # Restart cannot reuse a still-unexpired cached permit when delivery fails.
        self.http.body = b"invalid.snapshot"
        failed = self.run_child(now=now)
        self.assertEqual(failed["initial_phase"], "refresh_required")
        self.assertEqual(failed["operation"], "AUTHORITY_REFRESH_FAILED")
        self.assertEqual(failed["revision"], revision)
        self.assertEqual(self.effects(), 0)
        self.http.body = self.tokens[1]
        denied = self.run_child(now=now)
        self.assertEqual(denied["operation"], "CALLER_AUTHORIZATION_FAILED")
        self.assertEqual(denied["revision"], 2)
        self.assertEqual(denied["final_history"], "ready")
        self.http.body = self.tokens[0]
        stale = self.run_child(now=now)
        self.assertEqual(stale["operation"], "AUTHORITY_REFRESH_FAILED")
        self.assertEqual(stale["revision"], 2)
        self.http.body = self.tokens[2]
        recovered = self.run_child(now=now)
        self.assertEqual(recovered["operation"], "returned")
        self.assertTrue(recovered["receipt_unchanged"])
        self.assertEqual(recovered["final_history"], "callback_returned")
        self.assertEqual(self.effects(), 1); self.assert_original_receipt()

    def test_exit_before_install_requires_new_verified_refresh(self):
        self.check_update_exit("before_install", 1)

    def test_exit_after_install_preserves_revocation_revision_and_clock(self):
        self.check_update_exit("after_install", 2)

    def check_dispatch_exit(self, mode, calls, history):
        self.run_child(mode, expected=CRASH_EXIT)
        self.assertEqual(self.effects(), calls); self.assert_original_receipt()
        self.assertEqual(self.f.managed.dispatch_status(self.options["request_id"]).state, history)
        self.http.body = self.tokens[2]
        recovered = self.run_child()
        self.assertEqual(recovered["initial_phase"], "refresh_required")
        self.assertEqual(recovered["initial_history"], history)
        self.assertEqual(recovered["revision"], 3)
        if history == "ready":
            self.assertEqual(recovered["operation"], "returned")
            self.assertEqual(self.effects(), 1)
        else:
            self.assertEqual(recovered["operation"], "DURABLE_OPERATION_ALREADY_ATTEMPTED")
            self.assertEqual(self.effects(), calls)
        self.assert_original_receipt()

    def test_exit_after_handoff_before_claim_leaves_operation_unattempted(self):
        self.check_dispatch_exit("after_handoff", 0, "ready")

    def test_exit_after_claim_does_not_retry_unobserved_operation(self):
        self.check_dispatch_exit("after_claim", 0, "attempt_consumed")

    def test_exit_in_callback_does_not_repeat_effect(self):
        self.check_dispatch_exit("in_callback", 1, "attempt_consumed")

    def test_exit_after_callback_retains_uncertain_attempt(self):
        self.check_dispatch_exit("after_callback", 1, "attempt_consumed")

    def test_exit_after_finish_keeps_completed_attempt(self):
        self.check_dispatch_exit("after_finish", 1, "callback_returned")

    def test_owner_exit_during_blocked_dns_bounds_worker_and_requires_refresh(self):
        resolver = Path(self.f.tmp.name) / "resolver-entered"
        owner, reports = self.spawn("fetch_owner_exit", timeout=2, resolver_marker=resolver)
        self.assertTrue(reports.poll(15))
        packet = reports.recv()
        self.assertIn("worker_pid", packet)
        pid = packet["worker_pid"]; self.workers.append(pid)
        self.assertTrue(self.wait_for(resolver.exists, 10))
        owner.kill(); owner.join(5)
        self.assertEqual(owner.exitcode, -signal.SIGKILL)
        self.assertTrue(self.wait_for(lambda: process_exited(pid), 5),
                        "orphaned fetch outlived its own acquisition deadline")
        self.assertEqual(self.f.source.status()["revision"], 1)
        self.assertEqual(self.effects(), 0); self.assert_original_receipt()
        self.http.body = self.tokens[1]
        recovered = self.run_child()
        self.assertEqual(recovered["initial_phase"], "refresh_required")
        self.assertEqual(recovered["operation"], "CALLER_AUTHORIZATION_FAILED")
        self.assertEqual(recovered["revision"], 2)
        self.assertEqual(self.effects(), 0)


if __name__ == "__main__":
    unittest.main()
