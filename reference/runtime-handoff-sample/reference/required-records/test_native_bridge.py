"""The supervisor owns the whole worker group, even after its leader exits."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from native_bridge import Bridge, CLEANUP_SECONDS, inbox_process_owner

HELPER = """
import json, os, signal, subprocess, sys, time
from pathlib import Path
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(45)'],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
os.kill(child.pid, signal.SIGSTOP)
marker = Path(sys.argv[1])
temporary = marker.with_suffix('.tmp')
temporary.write_text(str(child.pid))
temporary.replace(marker)
mode = sys.argv[2]
if mode == 'success':
    print(json.dumps({'ok': True}), flush=True)
elif mode == 'invalid':
    print('not-json', flush=True)
elif mode == 'error':
    sys.exit(7)
elif mode == 'reported_timeout':
    print(json.dumps({'invocation': {'status': 'error'}, 'error': {'code': 'WORKER_TIMEOUT'}}), flush=True)
elif mode in ('reported_worker_failure', 'reported_worker_protocol'):
    code = 'WORKER_FAILED' if mode == 'reported_worker_failure' else 'WORKER_PROTOCOL_ERROR'
    print(json.dumps({'invocation': {'status': 'error'}, 'error': {'code': code}}), flush=True)
elif mode in ('reported_signature_timeout', 'reported_signature_failure'):
    code = 'VERIFIER_TIMEOUT' if mode == 'reported_signature_timeout' else 'VERIFIER_EXECUTION_ERROR'
    print(json.dumps({'invocation': {'status': 'returned'},
        'signatures': {'admission': {'status': 'error', 'reason': code}}}), flush=True)
else:
    time.sleep(45)
"""


class NativeGroupCleanupTests(unittest.TestCase):
    def exercise(self, mode):
        real_popen, real_sleep = subprocess.Popen, time.sleep
        processes = []
        unrelated = real_popen([sys.executable, '-c', 'import time; time.sleep(45)'],
                               start_new_session=True)
        self.addCleanup(lambda: unrelated.wait(timeout=5))
        self.addCleanup(lambda: unrelated.kill() if unrelated.poll() is None else None)
        with tempfile.TemporaryDirectory(prefix="vate-owned-group-") as directory:
            marker = Path(directory) / "child.pid"

            def spawn(_args, **kwargs):
                process = real_popen([sys.executable, "-c", HELPER, str(marker), mode], **kwargs)
                processes.append(process)
                end = time.monotonic() + 5
                while not marker.exists() and process.poll() is None and time.monotonic() < end:
                    real_sleep(0.005)
                self.assertTrue(marker.exists(), "owned helper did not start")
                return process

            try:
                bridge = Bridge.__new__(Bridge)
                with patch("native_bridge.subprocess.Popen", side_effect=spawn):
                    if mode == "interrupt":
                        interrupted = False
                        def interrupt_once(seconds):
                            nonlocal interrupted
                            if not interrupted:
                                interrupted = True
                                raise KeyboardInterrupt()
                            real_sleep(seconds)
                        with patch("native_bridge.time.sleep", side_effect=interrupt_once), self.assertRaises(KeyboardInterrupt):
                            bridge._run(b"{}", 5)
                    else:
                        result = bridge._run(b"{}", 0.05 if mode == "timeout" else 5)
                        if mode == "success":
                            self.assertEqual(result, {"ok": True})
                        else:
                            self.assertEqual(result["error"]["code"], "EVALUATION_LIMIT" if mode == "timeout" else "NATIVE_PROCESS_ERROR")
                self.assertTrue(processes and all(process.returncode is not None for process in processes))
                self.assertIsNone(unrelated.poll(), 'cleanup touched an unrelated group')
                child = int(marker.read_text())
                end = time.monotonic() + 3
                while True:
                    status = subprocess.run(["ps", "-o", "stat=", "-p", str(child)], capture_output=True, text=True).stdout.strip()
                    if not status or status.startswith("Z"):
                        break
                    self.assertLess(time.monotonic(), end, "owned descendant survived group cleanup: " + status)
                    real_sleep(0.01)
            finally:
                # Also clean up if this regression is run against broken code.
                for process in processes:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)

    def test_cleanup_after_leader_success(self):
        self.exercise("success")

    def test_cleanup_after_leader_error(self):
        self.exercise("error")

    def test_cleanup_after_invalid_response(self):
        self.exercise("invalid")

    def test_cleanup_after_deadline(self):
        self.exercise("timeout")

    def test_cleanup_after_interruption(self):
        self.exercise("interrupt")

    def test_delegation_requires_immediate_session_leader_and_explicit_directory(self):
        environment = {'VATE_INBOX_PROCESS_OWNER': '101',
            'VATE_INBOX_PROCESS_DIRECTORY': '/private/inbox',
            'TMPDIR': '/private/inbox', 'TMP': '/private/inbox', 'TEMP': '/private/inbox'}
        with patch.dict(os.environ, environment, clear=True), \
                patch('native_bridge.os.getpid', return_value=202), \
                patch('native_bridge.os.getppid', return_value=101), \
                patch('native_bridge.os.getpgrp', return_value=202), \
                patch('native_bridge.os.getsid', return_value=202):
            self.assertEqual(inbox_process_owner(), Path('/private/inbox'))
            with patch('native_bridge.os.getppid', return_value=303):
                self.assertIsNone(inbox_process_owner())
            with patch('native_bridge.os.getpid', return_value=303):
                self.assertIsNone(inbox_process_owner())
            with patch('native_bridge.os.getsid', return_value=303):
                self.assertIsNone(inbox_process_owner())
            for key, value in [('VATE_INBOX_PROCESS_OWNER', ''), ('TMPDIR', '/other'),
                               ('VATE_INBOX_PROCESS_DIRECTORY', 'relative')]:
                with patch.dict(os.environ, {key: value}):
                    self.assertIsNone(inbox_process_owner())

    def nested_failure(self, mode):
        # The bridge is the Inbox's delegated session leader. Its native helper
        # creates a stopped grandchild, just as a stuck crypto descendant could.
        # A native failure must kill this entire group before any next call.
        with tempfile.TemporaryDirectory(prefix='vate-nested-group-') as directory:
            folder = Path(directory)
            helper = folder/'helper.py'; helper.write_text(HELPER)
            driver = """
import os, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import native_bridge
root, mode = Path(sys.argv[2]), sys.argv[3]
real_popen, real_sleep = subprocess.Popen, time.sleep
def spawn(_args, **kwargs):
    assert kwargs['start_new_session'] is False
    assert 'VATE_INBOX_PROCESS_OWNER' not in kwargs['env']
    assert 'VATE_INBOX_PROCESS_DIRECTORY' not in kwargs['env']
    process = real_popen([sys.executable, str(root/'helper.py'), str(root/'child.pid'), mode], **kwargs)
    (root/'native.pid').write_text(str(process.pid))
    deadline = time.monotonic()+5
    while not (root/'child.pid').exists() and time.monotonic()<deadline:
        real_sleep(0.005)
    assert (root/'child.pid').exists()
    return process
native_bridge.subprocess.Popen = spawn
if mode == 'interrupt':
    def interrupted(_seconds):
        raise KeyboardInterrupt()
    native_bridge.time.sleep = interrupted
native_bridge.Bridge.__new__(native_bridge.Bridge)._run(b'{}', 0.05 if mode == 'timeout' else 5)
(root/'continued').write_text('a later native call could run')
"""
            env = {**os.environ, 'VATE_INBOX_PROCESS_OWNER': str(os.getpid()),
                   'VATE_INBOX_PROCESS_DIRECTORY': directory,
                   'TMPDIR': directory, 'TMP': directory, 'TEMP': directory}
            proc = subprocess.Popen([sys.executable, '-B', '-c', driver,
                str(Path(__file__).resolve().parent), directory, mode],
                env=env, start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                stdout, stderr = proc.communicate(timeout=10)
                self.assertEqual(proc.returncode, -signal.SIGKILL, (stdout, stderr))
                self.assertFalse((folder/'continued').exists())
                stop = json.loads((folder/'native-stop.json').read_bytes())
                expected = {'timeout': 'EVALUATION_LIMIT', 'interrupt': 'NATIVE_PROCESS_INTERRUPTED',
                    'reported_timeout': 'WORKER_TIMEOUT', 'reported_signature_timeout': 'VERIFIER_TIMEOUT',
                    'reported_worker_failure': 'WORKER_FAILED', 'reported_worker_protocol': 'WORKER_PROTOCOL_ERROR',
                    'reported_signature_failure': 'VERIFIER_EXECUTION_ERROR'}
                self.assertEqual(stop['native_code'], expected.get(mode, 'NATIVE_PROCESS_ERROR'))
                for name in ('native.pid', 'child.pid'):
                    pid = int((folder/name).read_text())
                    end = time.monotonic()+3
                    while True:
                        state = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)],
                            capture_output=True, text=True).stdout.strip()
                        if not state or state.startswith('Z'):
                            break
                        self.assertLess(time.monotonic(), end, name+' survived: '+state)
                        time.sleep(0.01)
            finally:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=5)

    def test_nested_deadline_stops_before_next_call(self):
        self.nested_failure('timeout')

    def test_nested_interrupt_stops_before_next_call(self):
        self.nested_failure('interrupt')

    def test_nested_worker_error_stops_before_next_call(self):
        for mode in ('error', 'reported_timeout', 'reported_worker_failure', 'reported_worker_protocol',
                     'reported_signature_timeout', 'reported_signature_failure'):
            with self.subTest(mode=mode):
                self.nested_failure(mode)

    def test_nested_invalid_response_stops_before_next_call(self):
        self.nested_failure('invalid')


if __name__ == "__main__":
    unittest.main()
