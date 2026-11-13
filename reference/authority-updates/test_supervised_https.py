"""Disposable local workers: no external authority, credentials or user Keychain."""
from dataclasses import replace
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
from threading import Event
import time
import unittest
from unittest.mock import patch

import supervised_https as h


class SupervisedProcessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.processes = []
        self.addCleanup(self.clean_processes)
        self.real_popen = subprocess.Popen

    def clean_processes(self):
        for process in self.processes:
            remaining = process.poll() is None
            if remaining:
                process.kill(); process.wait(timeout=3)
            self.assertFalse(remaining, "fetch left its child running")
            self.assertTrue(process.stdin.closed)
            self.assertTrue(process.stdout.closed)

    def spawn(self, *args, **kwargs):
        process = self.real_popen(*args, **kwargs)
        self.processes.append(process)
        return process

    def source(self, timeout=2):
        return h.SupervisedHttpsSnapshotSource("https://localhost.invalid/snapshot", timeout_seconds=timeout)

    def script(self, source, code):
        command = [sys.executable, "-I", "-S", "-B", "-c", code]
        return patch.object(source, "_command", return_value=command)

    def test_complete_bounded_output_is_returned_after_child_exit(self):
        source = self.source()
        with self.script(source, "import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write(b'x'*65536)"), \
                patch.object(h.subprocess, "Popen", side_effect=self.spawn):
            self.assertEqual(source(), b"x" * 65536)
        self.assertEqual(self.processes[0].returncode, 0)

    def test_silent_worker_times_out_and_is_reaped(self):
        source = self.source(0.15)
        start = time.monotonic()
        with self.script(source, "import time; time.sleep(60)"), \
                patch.object(h.subprocess, "Popen", side_effect=self.spawn), \
                self.assertRaisesRegex(h.s.AuthorityError, "AUTHORITY_FETCH_TIMEOUT"):
            source()
        self.assertLess(time.monotonic() - start, 4)

    def test_blocked_dns_is_stopped_by_parent(self):
        source = self.source(2)
        marker = self.root / "resolver-entered"
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
                   str(source._config.worker), str(marker)]
        start = time.monotonic()
        with patch.object(source, "_command", return_value=command), \
                patch.object(h.subprocess, "Popen", side_effect=self.spawn), \
                self.assertRaisesRegex(h.s.AuthorityError, "AUTHORITY_FETCH_TIMEOUT"):
            source()
        self.assertEqual(marker.read_text(), "entered")
        self.assertLess(time.monotonic() - start, 5)

    def test_pipe_eof_without_process_exit_still_times_out(self):
        source = self.source(0.2)
        with self.script(source, "import sys,os,time; sys.stdin.buffer.read(); os.close(1); time.sleep(60)"), \
                patch.object(h.subprocess, "Popen", side_effect=self.spawn), \
                self.assertRaisesRegex(h.s.AuthorityError, "AUTHORITY_FETCH_TIMEOUT"):
            source()

    def test_worker_not_reading_a_full_input_pipe_times_out(self):
        source = self.source(0.2)
        source._config = replace(source._config, request=b"x" * h.MAX_REQUEST_BYTES)
        with self.script(source, "import time; time.sleep(60)"), \
                patch.object(h.subprocess, "Popen", side_effect=self.spawn), \
                self.assertRaisesRegex(h.s.AuthorityError, "AUTHORITY_FETCH_TIMEOUT"):
            source()

    def test_overflow_is_rejected_without_waiting_for_worker(self):
        source = self.source()
        with self.script(source, "import sys,time; sys.stdin.buffer.read(); sys.stdout.buffer.write(b'x'*65537); sys.stdout.buffer.flush(); time.sleep(60)"), \
                patch.object(h.subprocess, "Popen", side_effect=self.spawn), \
                self.assertRaisesRegex(h.s.AuthorityError, "AUTHORITY_FETCH_OUTPUT_INVALID"):
            source()

    def test_empty_and_failed_outputs_are_never_returned(self):
        for code, reason in (
            ("import sys; sys.stdin.buffer.read()", "AUTHORITY_FETCH_OUTPUT_INVALID"),
            ("import sys; sys.stdin.buffer.read(); print('partial'); print('private detail',file=sys.stderr); sys.exit(9)",
             "AUTHORITY_FETCH_WORKER_FAILED"),
        ):
            source = self.source()
            with self.subTest(reason=reason), self.script(source, code), \
                    patch.object(h.subprocess, "Popen", side_effect=self.spawn), \
                    self.assertRaisesRegex(h.s.AuthorityError, reason):
                source()

    def test_environment_is_not_inherited(self):
        source = self.source()
        code = "import json,os,sys; sys.stdin.buffer.read(); print(json.dumps(sorted(os.environ)))"
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://fixture.invalid", "SSL_CERT_FILE": "fixture",
                "SSLKEYLOGFILE": "fixture", "PYTHONPATH": "fixture", "DYLD_INSERT_LIBRARIES": "fixture",
                "PRIVATE_FIXTURE_SETTING": "fixture"}), self.script(source, code), \
                patch.object(h.subprocess, "Popen", side_effect=self.spawn):
            result = json.loads(source())
        # macOS may add its own text encoding setting during process startup.
        self.assertLessEqual(set(result), {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "__CF_USER_TEXT_ENCODING"})

    def test_interruption_reaps_worker_and_propagates(self):
        source = self.source()
        selector = selectors.DefaultSelector()
        with self.script(source, "import time; time.sleep(60)"), \
                patch.object(h.subprocess, "Popen", side_effect=self.spawn), \
                patch.object(h.selectors, "DefaultSelector", return_value=selector), \
                patch.object(selector, "select", side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            source()

    def test_sigint_during_popen_construction_retains_child_until_reaped(self):
        source = self.source()
        execute = self.real_popen._execute_child
        cancelled_before_return = []
        def execute_and_interrupt(process, *args, **kwargs):
            result = execute(process, *args, **kwargs)
            self.processes.append(process)
            # The child exists, but Popen has not returned its handle yet.
            os.kill(os.getpid(), signal.SIGINT)
            cancelled_before_return.append(source._pending_attempt.cancel.wait(1))
            return result
        with self.script(source, "import time; time.sleep(10)"), \
                patch.object(self.real_popen, "_execute_child", new=execute_and_interrupt), \
                self.assertRaises(KeyboardInterrupt):
            source()
        self.assertEqual(cancelled_before_return, [True])
        self.assertFalse(source.cleanup_required)
        self.assertIsNone(source.pending_worker_pid)
        self.assertIsNotNone(self.processes[0].returncode)

    def test_pending_startup_without_pid_blocks_reuse_until_owner_finishes(self):
        source = self.source(0.15)
        release, entered = Event(), Event()
        def delayed_spawn(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("fixture startup was not released")
            return self.spawn(*args, **kwargs)
        try:
            with self.script(source, "import time; time.sleep(10)"), \
                    patch.object(h.subprocess, "Popen", side_effect=delayed_spawn), \
                    patch.object(h, "CLEANUP_SECONDS", 0.05):
                with self.assertRaisesRegex(h.s.AuthorityError, "AUTHORITY_FETCH_CLEANUP_FAILED"):
                    source()
                self.assertTrue(entered.is_set())
                self.assertTrue(source.cleanup_required)
                self.assertIsNone(source.pending_worker_pid)
                with self.assertRaisesRegex(h.s.AuthorityError, "AUTHORITY_FETCH_CLEANUP_REQUIRED"):
                    source()
                attempt = source._pending_attempt
                release.set()
                self.assertTrue(attempt.done.wait(3))
                source.cleanup_pending()
        finally:
            release.set()
            source.cleanup_pending()
        self.assertFalse(source.cleanup_required)
        self.assertIsNotNone(self.processes[0].returncode)
        with self.script(source, "import sys; sys.stdin.buffer.read(); print('recovered')"), \
                patch.object(h.subprocess, "Popen", side_effect=self.spawn):
            self.assertEqual(source(), b"recovered\n")

    def test_failed_thread_creation_does_not_leave_pending_work(self):
        source = self.source()
        with patch.object(h.Thread, "start", side_effect=RuntimeError("fixture start failure")), \
                patch.object(h.subprocess, "Popen") as process, \
                self.assertRaisesRegex(h.s.AuthorityError, "AUTHORITY_FETCH_WORKER_FAILED"):
            source()
        process.assert_not_called()
        self.assertFalse(source.cleanup_required)

    def test_sigint_before_thread_start_allows_cleanup_and_reuse(self):
        source = self.source()
        start_code = h.Thread.start.__code__
        interrupted = []
        def trace(frame, event, arg):
            if event == "call" and frame.f_code is start_code:
                interrupted.append(True)
                sys.settrace(None)
                os.kill(os.getpid(), signal.SIGINT)
            return trace
        try:
            with patch.object(h.subprocess, "Popen") as process:
                sys.settrace(trace)
                with self.assertRaises(KeyboardInterrupt):
                    source()
                process.assert_not_called()
        finally:
            sys.settrace(None)
        self.assertEqual(interrupted, [True])
        source.cleanup_pending()
        self.assertFalse(source.cleanup_required)
        with self.script(source, "import sys; sys.stdin.buffer.read(); print('recovered')"), \
                patch.object(h.subprocess, "Popen", side_effect=self.spawn):
            self.assertEqual(source(), b"recovered\n")

    def test_cancelled_start_gate_prevents_a_late_owner_from_spawning(self):
        source = self.source()
        owners = []
        real_start = h.Thread.start
        def delayed_start(thread):
            owners.append(thread)
            raise KeyboardInterrupt
        with patch.object(h.Thread, "start", new=delayed_start), self.assertRaises(KeyboardInterrupt):
            source()
        self.assertFalse(source.cleanup_required)
        # Even if a native startup were to finish later, its acquisition gate is
        # permanently closed; this must not create a worker or touch a new call.
        with patch.object(h.subprocess, "Popen") as process:
            real_start(owners[0])
            owners[0].join(3)
            self.assertFalse(owners[0].is_alive())
            process.assert_not_called()
        self.assertFalse(source.cleanup_required)

    def test_busy_start_gate_keeps_cleanup_pending_with_bounded_wait(self):
        source = self.source()
        locked = []
        def interrupted_start(thread):
            gate = source._pending_attempt.start_gate
            gate.acquire(); locked.append(gate)
            raise KeyboardInterrupt
        started = time.monotonic()
        try:
            with patch.object(h.Thread, "start", new=interrupted_start), \
                    patch.object(h, "CLEANUP_SECONDS", 0.05), self.assertRaises(KeyboardInterrupt):
                source()
            self.assertLess(time.monotonic() - started, 1)
            self.assertTrue(source.cleanup_required)
        finally:
            for gate in locked:
                gate.release()
            source.cleanup_pending()
        self.assertFalse(source.cleanup_required)

    def test_constructor_does_not_consult_environmental_tls_paths(self):
        keylog = self.root / "keylog"
        for destination in (keylog, self.root):
            env = {"SSLKEYLOGFILE": str(destination), "SSL_CERT_FILE": str(self.root / "missing-ca")}
            with self.subTest(destination=destination.name), patch.dict(os.environ, env):
                self.source()
                for name, value in env.items():
                    self.assertEqual(os.environ[name], value)
        self.assertFalse(keylog.exists())

    def test_cleanup_failure_never_returns_success(self):
        source = self.source()
        def spawn(*args, **kwargs):
            process = self.spawn(*args, **kwargs)
            wait, count = process.wait, 0
            def observed_wait(*args, **kwargs):
                nonlocal count
                count += 1
                if count == 2:
                    raise subprocess.TimeoutExpired("owned fixture", h.CLEANUP_SECONDS)
                return wait(*args, **kwargs)
            process.wait = observed_wait
            return process
        with self.script(source, "import sys; sys.stdin.buffer.read(); print('complete')"), \
                patch.object(h.subprocess, "Popen", side_effect=spawn), \
                self.assertRaisesRegex(h.s.AuthorityError, "AUTHORITY_FETCH_CLEANUP_FAILED"):
            source()
        self.assertEqual(source.pending_worker_pid, self.processes[0].pid)
        with patch.object(h.subprocess, "Popen") as start, \
                self.assertRaisesRegex(h.s.AuthorityError, "AUTHORITY_FETCH_CLEANUP_REQUIRED"):
            source()
        start.assert_not_called()
        source.cleanup_pending()
        self.assertIsNone(source.pending_worker_pid)
        with self.script(source, "import sys; sys.stdin.buffer.read(); print('new attempt')"), \
                patch.object(h.subprocess, "Popen", side_effect=self.spawn):
            self.assertEqual(source(), b"new attempt\n")

    def test_cleanup_ownership_is_retained_if_reaping_fails(self):
        source = self.source()
        def spawn(*args, **kwargs):
            process = self.spawn(*args, **kwargs)
            # A controlled cleanup failure; the original wait is used below.
            original_kill, original_wait = process.kill, process.wait
            def restore_and_cleanup():
                process.kill, process.wait = original_kill, original_wait
                if process.poll() is None:
                    process.kill(); process.wait(timeout=3)
            self.addCleanup(restore_and_cleanup)
            process.fixture_wait = process.wait
            process.kill = lambda: None
            process.wait = lambda **kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired("owned fixture", 3))
            return process
        with self.script(source, "import time; time.sleep(60)"), \
                patch.object(h.subprocess, "Popen", side_effect=spawn), \
                self.assertRaisesRegex(h.s.AuthorityError, "AUTHORITY_FETCH_CLEANUP_FAILED"):
            source._config = replace(source._config, timeout=0.15)
            source()
        process = self.processes[0]
        self.assertIsNone(process.poll())
        self.assertEqual(source.pending_worker_pid, process.pid)
        process.kill = lambda: os.kill(process.pid, 9)
        process.wait = process.fixture_wait
        source.cleanup_pending()
        self.assertIsNone(source.pending_worker_pid)
        self.assertIsNotNone(process.returncode)

    def test_concurrent_and_forked_use_cannot_start_or_reap_another_worker(self):
        source = self.source()
        with source._gate(), patch.object(h.subprocess, "Popen") as start:
            for call in (source, source.cleanup_pending, lambda: source.pending_worker_pid,
                         lambda: source.cleanup_required):
                with self.assertRaisesRegex(h.s.AuthorityError, "AUTHORITY_FETCH_BUSY"):
                    call()
        with patch.object(h.os, "getpid", return_value=source._owner_pid + 1):
            for call in (source, source.cleanup_pending, lambda: source.pending_worker_pid,
                         lambda: source.cleanup_required):
                with self.assertRaisesRegex(h.s.AuthorityError, "AUTHORITY_FETCH_FORK_NEW_SOURCE_REQUIRED"):
                    call()
        start.assert_not_called()

    def test_loaded_sources_cannot_be_relabeled_after_replacement(self):
        import test_authority_source_identity as identity_fixtures
        code = """import importlib,json,sys
from pathlib import Path
root,name,reload = sys.argv[1:]
sys.path.insert(0,str(Path(root)/'reference/authority-updates'))
import supervised_https as h
old=h.SupervisedHttpsSnapshotSource('https://localhost.invalid/')
old._supervise=lambda:b'no network'
module=h if name=='supervised_https.py' else h.https
path=Path(module.__file__); path.write_bytes(path.read_bytes()+b'\\n# replacement fixture\\n')
if reload=='yes':
    importlib.invalidate_caches(); importlib.reload(module)
    h.SupervisedHttpsSnapshotSource('https://localhost.invalid/')
try:
    old()
    cause=None
except h.s.AuthorityError as exc:
    cause=exc.cause
print(json.dumps({'cause':cause}))
"""
        for name in ("supervised_https.py", "https_source.py"):
            for reload in ("yes", "no"):
                with self.subTest(name=name,reload=reload), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    identity_fixtures.AuthoritySourceIdentityTests().copy_sources(root)
                    result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", code,
                        str(root), name, reload], capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("IMPLEMENTATION_CHANGED", json.loads(result.stdout)["cause"])

    def test_worker_rejects_changed_source_or_invalid_pipe_protocol(self):
        source = self.source()
        valid = h.s.b.decode(source._config.request)
        invalid = {**valid, "source_sha256": {name: "0" * 64 for name in valid["source_sha256"]}}
        for raw in (b"{}", b"[", h.s.b.encode(invalid), b"x" * (h.MAX_REQUEST_BYTES + 1)):
            with self.subTest(size=len(raw)):
                result = subprocess.run(source._command(), input=raw, capture_output=True, timeout=5,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, b"")

    def test_invalid_configuration_never_starts_worker(self):
        with patch.object(h.subprocess, "Popen") as process:
            for url in ("http://localhost/", "https://user:password@localhost/", "https://localhost/#x"):
                with self.subTest(url=url), self.assertRaises(h.s.AuthorityError):
                    h.SupervisedHttpsSnapshotSource(url)
            for timeout in (True, 0, -1, 31, float("nan"), float("inf")):
                with self.subTest(timeout=timeout), self.assertRaises(h.s.AuthorityError):
                    self.source(timeout)
            for raw in (b"", b"x" * (h.MAX_CA_BYTES + 1), b"not a certificate"):
                path = self.root / "ca.pem"; path.write_bytes(raw)
                with self.subTest(size=len(raw)), self.assertRaises(h.s.AuthorityError):
                    h.SupervisedHttpsSnapshotSource("https://localhost/", ca_file=path)
            process.assert_not_called()

    def test_changed_runtime_file_prevents_spawn_and_discards_result(self):
        source = self.source()
        selected = self.root / "selected-runtime"; selected.write_bytes(b"selected")
        source._config = replace(source._config, python=selected, python_sha256=h._sha(selected))
        selected.write_bytes(b"changed")
        with patch.object(h.subprocess, "Popen") as process, \
                self.assertRaisesRegex(h.s.AuthorityError, "AUTHORITY_FETCH_IMPLEMENTATION_CHANGED"):
            source()
        process.assert_not_called()
        selected.write_bytes(b"selected")
        def completed():
            selected.write_bytes(b"changed")
            return b"complete"
        with patch.object(source, "_supervise", side_effect=completed), \
                self.assertRaisesRegex(h.s.AuthorityError, "AUTHORITY_FETCH_IMPLEMENTATION_CHANGED"):
            source()


if __name__ == "__main__":
    unittest.main()
