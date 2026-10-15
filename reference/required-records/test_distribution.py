"""Exercise shipped inputs and the example generator's execution boundaries."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from fixture_inputs import ROOT, HERE
from run_examples import generate


class Distribution(unittest.TestCase):
    def test_saved_example_from_an_unrelated_working_directory(self):
        inputs = HERE / 'examples/operation-B-missing'
        with tempfile.TemporaryDirectory(prefix='vate-required-distribution-') as folder:
            output = Path(folder) / 'report.json'
            result = subprocess.run([
                sys.executable, '-B', str(HERE / 'required_records.py'),
                '--selection', str(inputs / 'selection.json'),
                '--base', 'inputs=' + str(inputs), '--base', 'repository=' + str(ROOT),
                '--source-root', str(ROOT), '--output', str(output),
            ], cwd=folder, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            report = json.loads(output.read_bytes())
            self.assertFalse(report['invocation_errors'])
            self.assertEqual({row['requirement_id']: row['record_coverage']
                              for row in report['requirements']}, {'A': 'present', 'B': 'missing'})
            self.assertTrue(report['native_calls'])
            self.assertTrue(all(call['result'] for call in report['native_calls']))

    def test_generator_rejects_wrong_executable_hash_before_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / 'not-executable'
            binary.write_bytes(b'This file must never be executed.')
            output = Path(folder) / 'controls'
            with patch('run_examples.signatures') as signing:
                with self.assertRaisesRegex(ValueError, 'expected SHA-256'):
                    generate(output, binary, '0' * 64)
                signing.assert_not_called()
            self.assertFalse(output.exists())

    def test_generator_preserves_an_existing_output_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / 'prior-report'
            marker.write_bytes(b'unchanged')
            with patch('run_examples.signatures') as signing:
                with self.assertRaisesRegex(ValueError, 'new directory'):
                    generate(folder, '/not/an/executable', '0' * 64)
                signing.assert_not_called()
            self.assertEqual(marker.read_bytes(), b'unchanged')


if __name__ == '__main__':
    unittest.main()
