"""Offline negative checks for environment preparation and pin enforcement."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

import prepare_environment as preparation
from offline_native import runtime_identity
from receiving import InputError, encoded, sha


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vate-distribution-check-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_unsupported_os_cannot_start_installation(self):
        with patch.object(sys, 'platform', 'linux'), patch.object(preparation.subprocess, 'run') as call:
            with self.assertRaises(InputError):
                preparation.prepare(self.root/'env', VATE, 'uv')
            call.assert_not_called()
        self.assertFalse((self.root/'env').exists())

    def test_unsupported_python_cannot_start_installation(self):
        with patch.object(sys, 'version_info', (3, 10)), patch.object(preparation.subprocess, 'run') as call:
            with self.assertRaises(InputError):
                preparation.prepare(self.root/'env', VATE, 'uv')
            call.assert_not_called()
        self.assertFalse((self.root/'env').exists())

    def test_wrong_vate_source_cannot_start_installation(self):
        with patch.object(preparation.subprocess, 'run') as call:
            with self.assertRaises((ValueError, OSError)):
                preparation.prepare(self.root/'env', self.root/'missing-vate', 'uv')
            call.assert_not_called()
        self.assertFalse((self.root/'env').exists())

    def test_existing_directory_is_preserved(self):
        output = self.root/'existing'; output.mkdir()
        (output/'owner-file').write_bytes(b'keep')
        with patch.object(preparation.subprocess, 'run') as call:
            with self.assertRaisesRegex(InputError, 'already exists'):
                preparation.prepare(output, VATE, 'uv')
            call.assert_not_called()
        self.assertEqual(['owner-file'], [p.name for p in output.iterdir()])
        self.assertEqual(b'keep', (output/'owner-file').read_bytes())

    def test_lock_change_rejected_before_installation(self):
        for name in ('evaluator-template.json', 'requirements.lock'):
            shutil.copyfile(preparation.ROOT/name, self.root/name)
        with (self.root/'requirements.lock').open('ab') as stream:
            stream.write(b'\n# changed\n')
        with patch.object(preparation, 'ROOT', self.root):
            with self.assertRaisesRegex(InputError, 'lock differs'):
                preparation.template()

    def test_source_change_rejected_before_installation(self):
        for name in ('evaluator-template.json', 'requirements.lock'):
            shutil.copyfile(preparation.ROOT/name, self.root/name)
        shutil.copytree(preparation.ROOT/'sample/evaluator-source', self.root/'sample/evaluator-source')
        config = json.loads((self.root/'evaluator-template.json').read_bytes())
        path = self.root/'sample/evaluator-source'/config['entrypoint']
        path.write_bytes(path.read_bytes()+b'\n# changed\n')
        with patch.object(preparation, 'ROOT', self.root), self.assertRaises(InputError):
            preparation.template()

    def test_prepared_descriptor_cannot_select_another_source(self):
        config = json.loads((ENVIRONMENT/'evaluator.json').read_bytes())
        config['source_commit'] = '0'*40
        (self.root/'evaluator.json').write_bytes(encoded(config))
        with self.assertRaisesRegex(InputError, 'source/lock selection'):
            preparation.check_environment(self.root)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vate-pin-check-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'bin').mkdir()
        self.python = Path(sys.executable).resolve()
        (self.root/'bin/python').symlink_to(self.python)
        (self.root/'module.py').write_bytes(b'x = 1\n')
        self.config = {'runtime_files': [{'path': 'module.py', 'sha256': sha(b'x = 1\n'), 'bytes': 6}],
                       'runtime_links': {'bin/python': str(self.python)}, 'runtime_executables': [],
                       'interpreter_sha256': sha(self.python.read_bytes()), 'lock_sha256': '0'*64}
        runtime_identity(self.root, self.config)

    def test_changed_installed_file_is_rejected(self):
        (self.root/'module.py').write_bytes(b'x = 2\n')
        with self.assertRaises(InputError): runtime_identity(self.root, self.config)

    def test_extra_installed_file_is_rejected(self):
        (self.root/'extra.py').write_bytes(b'')
        with self.assertRaises(InputError): runtime_identity(self.root, self.config)

    def test_bytecode_cannot_be_added_even_to_descriptor(self):
        (self.root/'module.pyc').write_bytes(b'bytecode')
        config = copy.deepcopy(self.config)
        config['runtime_files'].append({'path': 'module.pyc', 'sha256': sha(b'bytecode'), 'bytes': 8})
        with self.assertRaisesRegex(InputError, 'bytecode'): runtime_identity(self.root, config)

    def test_extra_symlink_is_rejected(self):
        (self.root/'bin/other').symlink_to(self.python)
        with self.assertRaises(InputError): runtime_identity(self.root, self.config)


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--vate-root', type=Path, required=True)
    ap.add_argument('--environment', type=Path, required=True)
    args = ap.parse_args()
    VATE, ENVIRONMENT = args.vate_root.resolve(), args.environment.resolve()
    preparation.check_vate(VATE)
    preparation.check_environment(ENVIRONMENT)
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls)
                               for cls in (PreparationTests, RuntimeTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
