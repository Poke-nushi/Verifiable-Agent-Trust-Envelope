"""Test the pinned-file replay wrapper with self-authored data, without network."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import acs_reader as reader
import check_capture
from test_reader import HERE, inputs


class CaptureCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        data = inputs()
        selection = (HERE/'selection.example.json').read_bytes()
        self.expected = reader.assess(data, selection)
        files = {}
        for key, raw in data.items():
            name = key.replace('_', '-')+'.jsonl'
            (self.folder/name).write_bytes(raw)
            files[key] = {'filename': name, 'raw_sha256': reader.digest(raw), 'byte_length': len(raw)}
        self.meta = {'files': files, 'selection_file': 'published-selection.json',
                     'selection_sha256': reader.digest(selection),
                     'expected_report_sha256': reader.digest(reader.encode(self.expected)+b'\n')}
        (self.folder/'published-selection.json').write_bytes(selection)
        self.save_meta()
        self.patch = patch.object(check_capture, 'HERE', self.folder)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def save_meta(self):
        (self.folder/'PUBLISHED-CAPTURE.json').write_bytes(reader.encode(self.meta))

    def test_matching_bytes_reproduce_report(self):
        self.assertEqual(check_capture.check_capture(self.folder), self.expected)

    def test_whitespace_change_fails_before_reading_later_sources(self):
        first = self.folder/'host-audit.jsonl'
        first.write_bytes(first.read_bytes()+b' ')
        with patch.object(check_capture, 'read_file', wraps=reader.read_file) as reads:
            with self.assertRaises(reader.InputError) as raised:
                check_capture.check_capture(self.folder)
        self.assertEqual(raised.exception.code, 'CAPTURE_DIGEST_MISMATCH')
        self.assertEqual(raised.exception.source, 'host_audit')
        self.assertEqual(len(reads.call_args_list), 2)

    def test_selection_and_expected_report_identity(self):
        for key, code in (('selection_sha256', 'SELECTION_DIGEST_MISMATCH'),
                          ('expected_report_sha256', 'EXPECTED_REPORT_MISMATCH')):
            with self.subTest(key=key):
                original = self.meta[key]
                self.meta[key] = '0'*64
                self.save_meta()
                with self.assertRaises(reader.InputError) as raised:
                    check_capture.check_capture(self.folder)
                self.assertEqual(raised.exception.code, code)
                self.meta[key] = original

    def test_pin_cannot_select_another_local_path(self):
        self.meta['files']['host_audit']['filename'] = '../host-audit.jsonl'
        self.save_meta()
        with self.assertRaises(reader.InputError) as raised:
            check_capture.check_capture(self.folder)
        self.assertEqual(raised.exception.code, 'INVALID_CAPTURE_PINS')

    def test_cli_missing_capture_is_error_not_absence(self):
        missing = self.folder/'not-received'
        run = subprocess.run([sys.executable, '-B', str(HERE/'check_capture.py'),
                              '--directory', str(missing)], capture_output=True)
        self.assertEqual(run.returncode, 64)
        self.assertEqual(json.loads(run.stdout)['reason'], 'FILE_UNAVAILABLE')
        self.assertNotIn(str(missing).encode(), run.stdout+run.stderr)


if __name__ == '__main__':
    unittest.main()
