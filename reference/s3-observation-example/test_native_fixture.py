"""Offline cleanup regressions; no binary, sockets or native processes are used."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from contract import Invalid
from native_fixture import LocalSeaweed


class CleanupTests(unittest.TestCase):
    def fixture(self, root):
        fixture = LocalSeaweed.__new__(LocalSeaweed)
        fixture.work = root / 'work'
        fixture.destination = root / 'output'
        fixture.work.mkdir()
        fixture.destination.mkdir()
        (fixture.work / 'credentials.json').write_text('synthetic-secret')
        fixture.credentials = {'observer': ('synthetic-key', 'synthetic-secret')}
        fixture.sockets = []
        fixture.owned_sockets = []
        fixture.log = None
        fixture.lifecycle = {}
        fixture.process = Mock(pid=987654, returncode=0)
        fixture.process.poll.side_effect = [None, 0]
        fixture.process.wait.return_value = 0
        return fixture

    def test_exit_race_still_removes_credentials_and_records_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(Path(temp))
            with patch('native_fixture.os.killpg', side_effect=ProcessLookupError), \
                 patch('native_fixture.subprocess.run', return_value=subprocess.CompletedProcess([], 1, b'', b'')):
                self.assertFalse(fixture.__exit__(None, None, None))
            record = json.loads((fixture.destination / 'instance/LIFECYCLE.json').read_bytes())
            self.assertTrue(record['cleanup_ok'])
            self.assertTrue(record['credentials_file_removed'])
            self.assertEqual(record['cleanup_errors'], [])
            self.assertEqual(fixture.credentials, {})

    def test_stop_error_does_not_skip_secret_cleanup_or_claim_success(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(Path(temp))
            with patch('native_fixture.os.killpg', side_effect=PermissionError):
                with self.assertRaisesRegex(Invalid, 'cleanup incomplete'):
                    fixture.__exit__(None, None, None)
            record = json.loads((fixture.work / 'LIFECYCLE.json').read_bytes())
            self.assertFalse(record['cleanup_ok'])
            self.assertTrue(record['credentials_file_removed'])
            self.assertEqual(record['cleanup_errors'], [{'step': 'graceful_stop', 'error_type': 'PermissionError'},
                                                         {'step': 'stop_process', 'error_type': 'PermissionError'}])
            self.assertEqual(fixture.credentials, {})

    def test_log_error_does_not_skip_secret_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(Path(temp))
            fixture.log = Mock()
            fixture.log.close.side_effect = OSError
            fixture.process.poll.side_effect = [0, 0]
            with patch('native_fixture.subprocess.run', return_value=subprocess.CompletedProcess([], 1, b'', b'')):
                with self.assertRaisesRegex(Invalid, 'cleanup incomplete'):
                    fixture.__exit__(None, None, None)
            record = json.loads((fixture.destination / 'instance/LIFECYCLE.json').read_bytes())
            self.assertTrue(record['credentials_file_removed'])
            self.assertFalse(record['cleanup_ok'])
            self.assertEqual(fixture.credentials, {})

    def test_preexisting_socket_is_not_owned_or_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(Path(temp))
            unrelated = Mock()
            fixture.sockets = [unrelated]
            fixture.process = None
            self.assertFalse(fixture.__exit__(ValueError, ValueError('startup'), None))
            unrelated.unlink.assert_not_called()
            record = json.loads((fixture.destination / 'instance/LIFECYCLE.json').read_bytes())
            self.assertEqual(record['exception_type'], 'ValueError')
            self.assertEqual(record['grpc_sockets'], {})

    def test_cancel_during_wait_forces_stop_and_finishes_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(Path(temp))
            fixture.process.wait.side_effect = [KeyboardInterrupt(), -9]
            fixture.process.returncode = -9
            with patch('native_fixture.os.killpg') as kill, \
                 patch('native_fixture.subprocess.run', return_value=subprocess.CompletedProcess([], 1, b'', b'')):
                with self.assertRaisesRegex(Invalid, 'cleanup incomplete'):
                    fixture.__exit__(None, None, None)
            self.assertEqual(kill.call_count, 2)
            record = json.loads((fixture.destination / 'instance/LIFECYCLE.json').read_bytes())
            self.assertTrue(record['process_stopped'])
            self.assertTrue(record['credentials_file_removed'])
            self.assertFalse(record['cleanup_ok'])
            self.assertEqual(fixture.credentials, {})

    def test_cancel_during_log_close_still_removes_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(Path(temp))
            fixture.process = None
            fixture.log = Mock()
            fixture.log.close.side_effect = KeyboardInterrupt
            with self.assertRaisesRegex(Invalid, 'cleanup incomplete'):
                fixture.__exit__(None, None, None)
            record = json.loads((fixture.destination / 'instance/LIFECYCLE.json').read_bytes())
            self.assertTrue(record['credentials_file_removed'])
            self.assertEqual(record['cleanup_errors'], [{'step': 'close_log', 'error_type': 'KeyboardInterrupt'}])
            self.assertEqual(fixture.credentials, {})


if __name__ == '__main__':
    unittest.main()
