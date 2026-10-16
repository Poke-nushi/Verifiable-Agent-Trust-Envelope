#!/usr/bin/env python3
"""Offline CLI controls; stored evidence and its source pins remain unchanged."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import assess_cli as cli
import contract as c

HERE = Path(__file__).resolve().parent
CLI = HERE / 'assess_cli.py'
LEGACY = HERE / 'assess_observation.py'
INSTANCE = HERE / 'inputs/seaweedfs-4.48/instance'
POLICY = INSTANCE / 'receiver-policy.json'
sys.path.insert(0, str(HERE.parents[1] / 'reference/runtime-support'))
from synthetic_s3 import synthetic_current_instance


class AssessmentCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global INSTANCE, POLICY
        cls.synthetic = tempfile.TemporaryDirectory(prefix="vate-current-s3-cli-")
        cls.addClassCleanup(cls.synthetic.cleanup)
        INSTANCE = synthetic_current_instance(HERE.parents[1], Path(cls.synthetic.name) / "instance")
        POLICY = INSTANCE / "receiver-policy.json"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vate-s3-cli-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / 'Bundle'
        shutil.copytree(INSTANCE / 'bundles/supported', self.bundle)
        self.policy = self.root / 'receiver-policy.json'
        shutil.copyfile(POLICY, self.policy)

    def invoke(self, bundle=None, policy=None, entry=None):
        result = subprocess.run(
            [sys.executable, '-B', str(entry or CLI), '--bundle', str(bundle or self.bundle),
             '--trust', str(policy or self.policy)],
            capture_output=True, text=True, timeout=30,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        self.assertEqual(result.stderr, '')
        value = json.loads(result.stdout)
        self.assertIs(value['retry_authorized'], False)
        return result.returncode, value

    def assert_configuration_rejection(self, bundle, policy):
        code, value = self.invoke(bundle, policy)
        self.assertEqual(code, 2)
        self.assertEqual(value, {
            'assessment': 'insufficient',
            'diagnostics': [{'kind': 'receiver_configuration',
                             'detail': 'trust policy must be supplied outside the bundle'}],
            'retry_authorized': False})

    def test_stored_assessments_equal_fixed_cli(self):
        for name in ('supported', 'actual-403', 'actual-404', 'historical-v1'):
            with self.subTest(capture=name):
                bundle = INSTANCE / 'bundles' / name
                self.assertEqual(self.invoke(bundle, POLICY), self.invoke(bundle, POLICY, LEGACY))

    def test_leading_hyphen_paths_retain_complete_native_result(self):
        bundle = self.root / '-Bundle'
        policy = self.root / '-receiver-policy.json'
        self.bundle.rename(bundle)
        self.policy.rename(policy)
        arguments = (
            ['--bundle', './' + bundle.name, '--trust', str(policy)],
            ['--bundle', str(bundle), '--trust', './' + policy.name],
            ['--bundle', './' + bundle.name, '--trust', './' + policy.name],
            ['--bundle=' + bundle.name, '--trust=' + policy.name],
        )
        for args in arguments:
            with self.subTest(arguments=args):
                results = []
                for entry in (LEGACY, CLI):
                    result = subprocess.run(
                        [sys.executable, '-B', str(entry), *args], cwd=self.root,
                        capture_output=True, text=True, timeout=30,
                        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, '')
                    value = json.loads(result.stdout)
                    self.assertEqual(value['assessment'], 'supported_under_local_assumptions')
                    self.assertIs(value['retry_authorized'], False)
                    results.append(value)
                self.assertEqual(results[0], results[1])

    def test_stale_assessor_bytecode_does_not_replace_script_source(self):
        source_root = self.root / 'source'
        for relative in c.SOURCE_PATHS:
            target = source_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(c.ROOT / relative, target)
        entry = source_root / CLI.relative_to(c.ROOT)
        shutil.copyfile(CLI, entry)
        native = entry.with_name('assess_observation.py')
        original = native.read_bytes()
        stale = b'raise RuntimeError("stale-assessor-bytecode")\n'
        native.write_bytes(stale + b' ' * (len(original) - len(stale)))
        os.utime(native, (1700000000, 1700000000))
        py_compile.compile(str(native), doraise=True,
                           invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
        native.write_bytes(original)
        os.utime(native, (1700000000, 1700000000))
        control = subprocess.run(
            [sys.executable, '-B', '-c',
             'import sys; sys.path.insert(0, sys.argv[1]); import assess_observation', str(entry.parent)],
            capture_output=True, text=True, timeout=30)
        self.assertNotEqual(control.returncode, 0)
        self.assertIn('stale-assessor-bytecode', control.stderr)
        self.assertEqual(self.invoke(entry=entry)[0], 0)

    def test_contradiction_retains_complete_native_result_and_exit(self):
        post = c.decode((self.bundle / 'post.json').read_bytes())
        post['execution']['runtime'] = 'urn:other:runtime'
        (self.bundle / 'post.json').write_bytes(c.encode(post))
        (self.bundle / 'manifest.json').unlink()
        c.seal(self.bundle)
        actual = self.invoke()
        self.assertEqual(actual, self.invoke(entry=LEGACY))
        self.assertEqual(actual[0], 1)
        self.assertEqual(actual[1]['assessment'], 'contradictory')

    def test_unknown_policy_contract_retains_unsupported_result_and_exit(self):
        trust = c.decode(self.policy.read_bytes())
        trust['contract'] = 'future-contract'
        self.policy.write_bytes(c.encode(trust))
        actual = self.invoke()
        self.assertEqual(actual, self.invoke(entry=LEGACY))
        self.assertEqual(actual[0], 3)

    def test_internal_policy_rejected_before_json_decode(self):
        policy = self.bundle / 'receiver-policy.json'
        policy.write_bytes(b'not JSON')
        self.assert_configuration_rejection(self.bundle, policy)

    def test_nested_internal_policy_rejected(self):
        policy = self.bundle / 'nested' / 'receiver-policy.json'
        policy.parent.mkdir()
        shutil.copyfile(POLICY, policy)
        self.assert_configuration_rejection(self.bundle, policy)

    def check_alias(self, name, alias):
        bundle = self.root / name
        self.bundle.rename(bundle)
        alias_bundle = self.root / alias
        if not alias_bundle.exists() or not alias_bundle.samefile(bundle):
            self.skipTest('filesystem does not equate these directory spellings')
        policy = bundle / 'receiver-policy.json'
        shutil.copyfile(POLICY, policy)
        for selected_bundle, selected_policy in ((bundle, alias_bundle / policy.name),
                                                 (alias_bundle, policy)):
            with self.subTest(bundle=str(selected_bundle), policy=str(selected_policy)):
                self.assert_configuration_rejection(selected_bundle, selected_policy)

    def test_case_alias_is_rejected_in_both_directions(self):
        self.check_alias('CaseBundle', 'casebundle')

    def test_unicode_alias_is_rejected_in_both_directions(self):
        self.check_alias('Caf\u00e9Bundle', 'Cafe\u0301Bundle')

    def test_policy_ancestor_identity_is_rejected_before_evaluation(self):
        bundle_stat = self.bundle.stat()
        original_stat = Path.stat

        def aliased_stat(path, *args, **kwargs):
            if path == self.policy.parent:
                return bundle_stat
            return original_stat(path, *args, **kwargs)

        output = io.StringIO()
        with patch.object(Path, 'resolve', lambda path: path), \
                patch.object(Path, 'stat', aliased_stat), \
                patch.object(cli, '_run_native') as evaluator, redirect_stdout(output):
            code = cli.main(['--bundle', str(self.bundle), '--trust', str(self.policy)])
        self.assertEqual(code, 2)
        evaluator.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())['diagnostics'], [{
            'kind': 'receiver_configuration',
            'detail': 'trust policy must be supplied outside the bundle'}])

    def test_distinct_case_sensitive_directory_is_external(self):
        external = self.root / 'bundle'
        if external.exists():
            self.skipTest('filesystem equates case variants')
        external.mkdir()
        policy = external / 'receiver-policy.json'
        shutil.copyfile(POLICY, policy)
        self.assertEqual(self.invoke(policy=policy)[0], 0)

    def test_sibling_with_shared_name_prefix_is_external(self):
        external = self.root / 'Bundle-extra'
        external.mkdir()
        policy = external / 'receiver-policy.json'
        shutil.copyfile(POLICY, policy)
        self.assertEqual(self.invoke(policy=policy)[0], 0)

    def test_policy_symlink_into_bundle_is_rejected(self):
        inside = self.bundle / 'receiver-policy.json'
        shutil.copyfile(POLICY, inside)
        link = self.root / 'policy-link'
        link.symlink_to(inside)
        self.assert_configuration_rejection(self.bundle, link)

    def test_policy_symlink_to_external_file_stays_usable(self):
        link = self.root / 'policy-link'
        link.symlink_to(self.policy)
        self.assertEqual(self.invoke(policy=link)[0], 0)

    def test_bundle_symlink_still_reaches_native_link_rejection(self):
        link = self.root / 'bundle-link'
        link.symlink_to(self.bundle, target_is_directory=True)
        actual = self.invoke(bundle=link)
        self.assertEqual(actual, self.invoke(bundle=link, entry=LEGACY))
        self.assertEqual(actual[0], 2)
        self.assertEqual(actual[1]['diagnostics'][0]['kind'], 'bundle_invalid')

    def test_missing_bundle_still_reaches_native_insufficient_result(self):
        missing = self.root / 'absent'
        actual = self.invoke(bundle=missing)
        self.assertEqual(actual, self.invoke(bundle=missing, entry=LEGACY))
        self.assertEqual(actual[0], 2)
        self.assertEqual(actual[1]['diagnostics'][0]['kind'], 'bundle_invalid')

    def test_missing_policy_is_configuration_error(self):
        code, value = self.invoke(policy=self.root / 'absent.json')
        self.assertEqual(code, 2)
        self.assertEqual(value['diagnostics'][0]['kind'], 'receiver_configuration')

    def test_stat_failure_is_configuration_error_without_evaluation(self):
        output = io.StringIO()
        with patch.object(Path, 'stat', side_effect=PermissionError('denied')), \
                patch.object(cli, '_run_native') as evaluator, redirect_stdout(output):
            code = cli.main(['--bundle', str(self.bundle), '--trust', str(self.policy)])
        self.assertEqual(code, 2)
        evaluator.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())['diagnostics'][0]['kind'], 'receiver_configuration')

    def test_resolve_failure_is_configuration_error_without_evaluation(self):
        for error in (OSError('unreadable'), RuntimeError('symlink loop')):
            with self.subTest(error=type(error).__name__):
                output = io.StringIO()
                with patch.object(Path, 'resolve', side_effect=error), \
                        patch.object(cli, '_run_native') as evaluator, redirect_stdout(output):
                    code = cli.main(['--bundle', str(self.bundle), '--trust', str(self.policy)])
                self.assertEqual(code, 2)
                evaluator.assert_not_called()
                self.assertEqual(json.loads(output.getvalue())['diagnostics'][0]['kind'], 'receiver_configuration')


if __name__ == '__main__':
    unittest.main()
