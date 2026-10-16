"""Synthetic crosswalk harness, not native execution or newly signed cases.

Uses submitted reports as parser fixtures, not as locally reproduced outputs.
All mutations exist only in memory or TemporaryDirectory and are never signed.
"""
from contextlib import redirect_stderr
import copy
import io
import json
from pathlib import Path
import py_compile
import shutil
import struct
import subprocess
import tempfile
import unittest

import sys
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import compare_records as compare
import crosswalk_core as cw
import replay_vate
import replay_native

TASK = Path(__file__).resolve().parents[1]
REPO = TASK.parents[1]


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(value, indent=2, ensure_ascii=True) + '\n').encode())


def changed(document, change):
    value = copy.deepcopy(document.value)
    change(value)
    return cw.Document(document.path, cw.canonical(value))


class RelationshipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        reader = cw.Reader(TASK)
        try:
            pins, _, _ = compare.verify_public_inputs(reader)
            repo = cw.Reader(REPO, 'repository')
            try:
                sources = compare.repository_source_bytes(repo, pins)
            finally:
                repo.close()
            cls.vate_cases, _, _, cls.policy, _, _ = compare.load_vate(reader, pins, compare.original_case(sources, pins), sources)
            cls.manifest = reader.document(cw.NENRIN_ROOT + '/MANIFEST.json')
            cls.bundles = {case: reader.document(cw.NENRIN_ROOT + '/records/' + case + '/nenrin-bundle.json') for case in cw.CASES}
            cls.native = {case: {engine: reader.document('saved/nenrin/' + engine + '-' + case + '.out')
                                for engine in cw.PACKAGES} for case in cw.CASES}
        finally:
            reader.close()

    def rows(self, case='match', bundle=None, documents=None):
        return {r['id']: r for r in cw.relationship_rows(bundle or self.bundles[case],
            documents or self.vate_cases[cw.CASES[case]], self.policy, self.manifest, self.native[case])}

    def component(self, rows, row_id, name):
        return next(c for c in rows[row_id]['components'] if c['name'] == name)

    def test_matching_static_relationships(self):
        rows = self.rows()
        self.assertEqual(list(rows), [f'CW-{n:02}' for n in range(1, 11)])
        self.assertTrue(all(row['status'] == 'matched' for row in rows.values()))

    def test_two_target_mutations_remain_separate_with_same_body_and_version(self):
        rows = self.rows('target_mismatch')
        for row_id in ('CW-03', 'CW-06'):
            self.assertEqual(rows[row_id]['status'], 'mismatched')
        self.assertEqual(self.component(rows, 'CW-03', 'grant_to_effective')['status'], 'matched')
        self.assertEqual(self.component(rows, 'CW-03', 'receipt_to_grant')['status'], 'mismatched')
        self.assertEqual(self.component(rows, 'CW-06', 'native_versions')['status'], 'matched')
        self.assertEqual(self.component(rows, 'CW-06', 'receipt_to_native_versions')['status'], 'matched')
        self.assertEqual(self.component(rows, 'CW-06', 'get-request_to_effective_target')['status'], 'mismatched')
        self.assertEqual(self.component(rows, 'CW-06', 'put-request_to_effective_target')['status'], 'matched')
        self.assertEqual(rows['CW-05']['status'], 'matched')
        # This is only a projection comparison: native post_observation remains not_assessed.
        self.assertEqual(rows['CW-07']['status'], 'matched')

    def test_missing_receipt_post_not_equal_to_mismatch(self):
        rows = self.rows('missing_receipt')
        self.assertTrue(all(row['status'] == 'not_assessed' for row in rows.values()))
        self.assertEqual(self.component(rows, 'CW-03', 'grant_to_effective')['status'], 'matched')
        self.assertEqual(self.component(rows, 'CW-05', 'put_body_to_effective')['status'], 'matched')
        self.assertEqual(self.component(rows, 'CW-08', 'ordered_put_inside_grant_window')['status'], 'matched')
        self.assertEqual(self.component(rows, 'CW-09', 'grant_content_id')['status'], 'matched')

    def test_missing_does_not_erase_independent_target_mismatch(self):
        docs = dict(self.vate_cases['missing-post'])
        docs['get-request'] = changed(docs['get-request'], lambda d: d.update(key='readable-other.txt'))
        rows = self.rows('missing_receipt', documents=docs)
        self.assertEqual(rows['CW-06']['status'], 'mismatched')
        self.assertEqual(self.component(rows, 'CW-06', 'get-request_to_receipt_target')['status'], 'not_assessed')
        self.assertEqual(rows['CW-07']['status'], 'not_assessed')

    def test_missing_post_does_not_erase_readable_body_mismatch(self):
        docs = dict(self.vate_cases['missing-post'])
        docs['get-body'] = cw.Document(docs['get-body'].path, b'a different raw body', binary=True)
        rows = self.rows('missing_receipt', documents=docs)
        self.assertEqual(rows['CW-05']['status'], 'mismatched')
        self.assertEqual(self.component(rows, 'CW-05', 'receipt_result_to_get_body')['status'], 'not_assessed')
        self.assertEqual(rows['CW-07']['status'], 'not_assessed')

    def test_request_hash_is_full_canonical_object_not_pretty_file(self):
        docs = dict(self.vate_cases['matching'])
        original = docs['effective-request']
        pretty = (json.dumps(original.value, indent=3) + '\n').encode()
        docs['effective-request'] = cw.Document(original.path, pretty)
        self.assertNotEqual(cw.sha(pretty), cw.sha(cw.canonical(original.value)))
        self.assertEqual(self.rows(documents=docs)['CW-04']['status'], 'matched')
        bundle = changed(self.bundles['match'], lambda d: d['grant']['action'].update(args_sha256=cw.sha(pretty)))
        self.assertEqual(self.component(self.rows(bundle=bundle, documents=docs), 'CW-04', 'grant_args_to_full_request')['status'], 'mismatched')

    def test_request_body_structured_result_and_native_action_bases_distinct(self):
        docs = dict(self.vate_cases['matching'])
        body_hash = cw.sha(docs['get-body'].raw)
        docs['post'] = changed(docs['post'], lambda d: d['result'].update(output_hash='sha-256:' + body_hash))
        bundle = changed(self.bundles['match'], lambda d: d['grant']['action_binding']['digest'].update(value=d['grant']['action']['args_sha256']))
        rows = self.rows(bundle=bundle, documents=docs)
        self.assertEqual(self.component(rows, 'CW-07', 'structured_output_hash')['status'], 'mismatched')
        self.assertEqual(self.component(rows, 'CW-09', 'grant_outer_action_binding')['status'], 'mismatched')
        self.assertEqual(rows['CW-04']['status'], 'matched')
        self.assertEqual(rows['CW-05']['status'], 'matched')

    def test_six_digit_timestamp_text_preserved(self):
        rows = self.rows()
        component = self.component(rows, 'CW-08', 'executed_at_exact_finish_text')
        self.assertEqual(component['operands'][0]['value'], '2026-10-12T13:12:32.500049Z')
        for replacement, expected in [('2026-10-12T13:12:32.500048Z', 'mismatched'), ('2026-10-12T13:12:32.500Z', 'not_assessed')]:
            bundle = changed(self.bundles['match'], lambda d: d['receipt'].update(executed_at=replacement))
            self.assertEqual(self.component(self.rows(bundle=bundle), 'CW-08', 'executed_at_exact_finish_text')['status'], expected)

    def test_microsecond_window_includes_start_not_only_receipt_finish(self):
        bundle = changed(self.bundles['match'], lambda d: d['grant'].update(not_before='2026-10-12T13:12:32.274654Z'))
        rows = self.rows(bundle=bundle)
        self.assertEqual(self.component(rows, 'CW-08', 'executed_at_exact_finish_text')['status'], 'matched')
        self.assertEqual(self.component(rows, 'CW-08', 'ordered_put_inside_grant_window')['status'], 'mismatched')
        self.assertEqual(cw.micros('2026-10-12T13:12:32.274654Z') - cw.micros('2026-10-12T13:12:32.274653Z'), 1)

    def test_bool_is_not_an_integer_length(self):
        docs = dict(self.vate_cases['matching'])
        docs['effective-request'] = changed(docs['effective-request'], lambda d: d.update(byte_length=True))
        rows = self.rows(documents=docs)
        self.assertEqual(rows['CW-04']['status'], 'not_assessed')
        self.assertEqual(self.component(rows, 'CW-05', 'put_length_to_effective')['status'], 'not_assessed')
        self.assertEqual(self.component(rows, 'CW-05', 'put_body_to_effective')['status'], 'matched')
        self.assertFalse(cw.same(True, 1))

    def test_unknown_algorithm_is_unassessed(self):
        docs = dict(self.vate_cases['matching'])
        docs['admission'] = changed(docs['admission'], lambda d: d['request'].update(input_hash=d['request']['input_hash'].replace('sha-256:', 'sha256:')))
        docs['effective-request'] = changed(docs['effective-request'], lambda d: d['body_digest'].update(alg='sha-512'))
        rows = self.rows(documents=docs)
        self.assertEqual(self.component(rows, 'CW-04', 'admission:/request/input_hash')['status'], 'not_assessed')
        self.assertEqual(self.component(rows, 'CW-05', 'get_body_to_effective')['status'], 'not_assessed')

    def test_unknown_profiles_not_reinterpreted(self):
        docs = dict(self.vate_cases['matching'])
        docs['effective-request'] = changed(docs['effective-request'], lambda d: d.update(contract='future-profile'))
        self.assertEqual(self.rows(documents=docs)['CW-03']['status'], 'not_assessed')
        docs = dict(self.vate_cases['matching'])
        docs['admission'] = changed(docs['admission'], lambda d: d['request']['action_binding'].update(canonicalization='JCS'))
        self.assertEqual(self.component(self.rows(documents=docs), 'CW-04', 'admission_action_binding')['status'], 'not_assessed')
        bundle = changed(self.bundles['match'], lambda d: d['grant']['action_binding'].update(preimage_profile='future'))
        self.assertEqual(self.component(self.rows(bundle=bundle), 'CW-09', 'grant_outer_action_binding')['status'], 'not_assessed')

    def test_optional_native_binding_absence_is_unassessed(self):
        bundle = changed(self.bundles['match'], lambda d: d['grant'].pop('action_binding'))
        rows = self.rows(bundle=bundle)
        self.assertEqual(self.component(rows, 'CW-09', 'grant_outer_action_binding')['status'], 'not_assessed')
        self.assertEqual(self.component(rows, 'CW-09', 'grant_content_id')['status'], 'matched')

    def test_version_null_cannot_be_equal_target_version(self):
        for value in (None, '', 'null', True, 7):
            bundle = changed(self.bundles['match'], lambda d: d['receipt']['outcome'].update(version_id=value))
            self.assertEqual(self.component(self.rows(bundle=bundle), 'CW-06', 'receipt_to_native_versions')['status'], 'not_assessed')

    def test_native_original_vocabulary_null_arrays_and_bytes_preserved(self):
        native = self.native['missing_receipt']['npm']
        result = cw.report_copy(native)
        self.assertEqual(result['raw_utf8'].encode(), native.raw)
        self.assertTrue(cw.same(result['report'], native.value))
        self.assertEqual(result['report']['refusals'][0]['code'], 'execution_incomplete_pair')
        self.assertIsNone(result['report']['layers']['evidence']['external'])
        self.assertIs(result['report']['signers']['signatures_required'], True)
        self.assertFalse(result['report']['layers']['execution']['complete'])
        self.assertNotIn('receipt_id', result['report']['layers']['execution'])
        self.assertFalse(cw.same({'x': None}, {}))
        self.assertFalse(cw.same(['a', 'b'], ['b', 'a']))

    def test_hand_written_canonical_byte_contrast(self):
        value = {'b': [True, 1], 'a': 'é'}
        self.assertEqual(cw.canonical(value), b'{"a":"\\u00e9","b":[true,1]}')
        self.assertEqual(cw.canonical(value, musubi=True), b'{"a":"\xc3\xa9","b":[true,1]}')
        self.assertNotEqual(cw.sha(cw.canonical(value)), cw.sha(cw.canonical(value, musubi=True)))
        with self.assertRaises(ValueError):
            cw.canonical({'非ASCII': 1}, musubi=True)

    def test_strict_parser_and_bounds(self):
        for raw in (b'{"a":1,"a":2}', b'1.0', b'NaN', b'-0', b'9007199254740992', b'"\\ud800"', b'[' * 45 + b'0' + b']' * 45):
            with self.subTest(raw=raw[:30]), self.assertRaises(cw.InputError):
                cw.decode(raw)


class NativeCustodyTests(unittest.TestCase):
    """Synthetic local-run records; no native invocation or signing occurs."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='nenrin-public-harness-')
        self.root = Path(self.temporary.name).resolve()
        public = cw.Reader(TASK)
        try:
            self.bundles, _ = compare.load_bundles(public)
            self.pins = cw.json_object(public.document('NATIVE-PINS.json'))
            saved = cw.json_object(public.document('saved/nenrin/REPORTS.json'))
            self.runs = {'schema': compare.NATIVE_FRESH, 'evidence_mode': 'fresh_local_run', 'source_commit': cw.NENRIN_COMMIT,
                         'harness_only': True, 'runtime': {
                             'scope': 'synthetic harness, never executed',
                             'node': {'executable': '/synthetic/node', 'executable_sha256': '0' * 64},
                             'python': {'executable': '/synthetic/python', 'executable_sha256': '1' * 64,
                                        'packages': {'nenrin-verify': '0.5.3'}}},
                         'entrypoints': {'npm': '/synthetic/nenrin_verify.mjs', 'pypi': 'nenrin_verify.cli:main'},
                         'source_identity': {engine: self.pins[engine]['files'] for engine in cw.PACKAGES},
                         'python_cache_policy': cw.NATIVE_CACHE_POLICY, 'python_source_checks': [], 'runs': []}
            for phase in ('preflight', 'postflight'):
                cache = cw.native_cache_record(phase)
                (self.root / cache['path']).mkdir(parents=True)
                result = {'source_identity': self.pins['pypi']['files'], 'runtime': {
                    key: value for key, value in self.runs['runtime']['python'].items() if key != 'executable_sha256'}}
                probe = {'phase': phase, 'command': cw.native_python_command('/synthetic/python', cache['path'], cw.NATIVE_PYTHON_PROBE),
                         'cwd': '.', 'started_at': '2026-10-14T00:00:00+00:00', 'finished_at': '2026-10-14T00:00:01+00:00',
                         'exit_code': 0, 'python_cache': cache, 'stdin': cw.fingerprint(cw.canonical(self.pins['pypi']['files']))}
                for role, extension, raw in [('stdout', 'out', cw.canonical(result)), ('stderr', 'err', b'')]:
                    path = 'checks/' + phase + '.' + extension
                    compare.write_new(self.root / path, raw)
                    probe[role] = {'path': path, **cw.fingerprint(raw)}
                self.runs['python_source_checks'].append(probe)
            for case, document in self.bundles.items():
                compare.write_new(self.root / 'inputs' / (case + '.json'), document.raw)
            for record in saved['runs']:
                item = copy.deepcopy(record)
                item.pop('historical_execution')
                item['input']['path'] = 'inputs/' + item['case'] + '.json'
                if item['engine'] == 'npm':
                    command = ['/synthetic/node', '/synthetic/nenrin_verify.mjs', item['input']['path']]
                else:
                    item['python_cache'] = cw.native_cache_record('verify-' + item['case'])
                    (self.root / item['python_cache']['path']).mkdir(parents=True)
                    command = cw.native_python_command('/synthetic/python', item['python_cache']['path'],
                                                       cw.NATIVE_PYTHON_ENTRY, [item['input']['path']])
                item.update(command=command, cwd='.',
                            started_at='2026-10-14T00:00:00+00:00', finished_at='2026-10-14T00:00:01+00:00')
                for role in ('stdout', 'stderr'):
                    raw = public.read(item[role]['path'])
                    item[role]['path'] = item[role]['path'].replace('saved/nenrin/', 'results/')
                    compare.write_new(self.root / item[role]['path'], raw)
                self.runs['runs'].append(item)
        finally:
            public.close()
        self.save()

    def tearDown(self):
        self.temporary.cleanup()

    def save(self):
        write_json(self.root / 'RUN.json', self.runs)

    def load(self):
        self.save()
        reader = cw.Reader(self.root, 'synthetic_native')
        try:
            return compare.load_native(reader, self.bundles, fresh=True, native_pins=self.pins)
        finally:
            reader.close()

    def test_six_bound_synthetic_records_load_without_execution(self):
        reports, records, manifest, mode = self.load()
        self.assertEqual((len(reports), len(records), mode), (6, 6, 'fresh_local_run'))
        self.assertTrue(manifest.value['harness_only'])

    def test_wrong_case_input_valid_hash_refused(self):
        self.runs['runs'][0]['input'] = self.runs['runs'][2]['input']
        with self.assertRaisesRegex(cw.InputError, 'wrong case/artifact path'):
            self.load()

    def test_wrong_case_output_valid_hash_refused(self):
        self.runs['runs'][0]['stdout'] = self.runs['runs'][2]['stdout']
        with self.assertRaisesRegex(cw.InputError, 'wrong case/artifact path'):
            self.load()

    def test_wrong_case_report_copied_and_resealed_refused(self):
        record = self.runs['runs'][0]
        wrong = self.root / self.runs['runs'][2]['stdout']['path']
        (self.root / record['stdout']['path']).write_bytes(wrong.read_bytes())
        record['stdout'].update(cw.fingerprint(wrong.read_bytes()))
        with self.assertRaisesRegex(cw.InputError, 'receipt/input mismatch'):
            self.load()

    def test_raw_report_hash_not_structured_json_hash(self):
        reference = self.runs['runs'][0]['stdout']
        reference['sha256'] = cw.sha(cw.canonical(cw.decode((self.root / reference['path']).read_bytes())))
        with self.assertRaisesRegex(cw.InputError, 'binding mismatch'):
            self.load()

    def test_native_command_input_assignment_refused(self):
        self.runs['runs'][0]['command'][-1] = self.runs['runs'][2]['input']['path']
        with self.assertRaisesRegex(cw.InputError, 'command/input assignment'):
            self.load()

    def test_native_command_wrong_entrypoint_refused(self):
        record = next(r for r in self.runs['runs'] if r['engine'] == 'npm')
        record['command'][1] = '/synthetic/other-checker.mjs'
        with self.assertRaisesRegex(cw.InputError, 'command/input assignment'):
            self.load()

    def test_native_runtime_command_disagreement_refused(self):
        self.runs['runtime']['python']['executable'] = '/synthetic/other-python'
        with self.assertRaisesRegex(cw.InputError, 'source probe command'):
            self.load()

    def test_native_python_command_requires_cache_prefix(self):
        record = next(r for r in self.runs['runs'] if r['engine'] == 'pypi')
        del record['command'][3:5]
        with self.assertRaisesRegex(cw.InputError, 'command/input assignment'):
            self.load()

    def test_native_probe_requires_cache_prefix(self):
        del self.runs['python_source_checks'][0]['command'][3:5]
        with self.assertRaisesRegex(cw.InputError, 'source probe command'):
            self.load()

    def test_native_cache_metadata_and_contents_checked(self):
        record = next(r for r in self.runs['runs'] if r['engine'] == 'pypi')
        record['python_cache']['empty_before'] = 1
        with self.assertRaisesRegex(cw.InputError, 'cache metadata differs'):
            self.load()
        record['python_cache']['empty_before'] = True
        (self.root / record['python_cache']['path'] / 'unexpected.pyc').write_bytes(b'synthetic')
        with self.assertRaisesRegex(cw.InputError, 'cache must remain empty'):
            self.load()

    def test_native_probe_report_identity_is_bound(self):
        record = self.runs['python_source_checks'][1]
        path = self.root / record['stdout']['path']
        value = cw.decode(path.read_bytes())
        value['source_identity']['nenrin_verify/cli.py']['sha256'] = '0' * 64
        write_json(path, value)
        record['stdout'].update(cw.fingerprint(path.read_bytes()))
        with self.assertRaisesRegex(cw.InputError, 'source probe result differs'):
            self.load()

    def test_invocation_time_required_and_ordered(self):
        for value in (None, '2026-10-13T23:59:59+00:00'):
            self.runs['runs'][0]['finished_at'] = value
            with self.assertRaisesRegex(cw.InputError, 'invocation'):
                self.load()

    def test_duplicate_case_engine_refused(self):
        self.runs['runs'][1] = copy.deepcopy(self.runs['runs'][0])
        with self.assertRaisesRegex(cw.InputError, 'duplicate native'):
            self.load()

    def test_duplicate_role_refused(self):
        with self.assertRaisesRegex(cw.InputError, 'duplicate'):
            cw.unique([{'path': 'one'}, {'path': 'one'}], 'path', 'synthetic files')

    def test_missing_receipt_cannot_be_reintroduced(self):
        record = next(r for r in self.runs['runs'] if r['case'] == 'missing_receipt')
        path = self.root / record['input']['path']
        value = cw.decode(path.read_bytes())
        value['receipts'] = [self.bundles['match'].value['receipt']]
        write_json(path, value)
        record['input'].update(cw.fingerprint(path.read_bytes()))
        with self.assertRaisesRegex(cw.InputError, 'input differs from submitted case'):
            self.load()

    def test_bool_length_and_exit_not_integer(self):
        for key in ('byte_length', 'exit_code'):
            original = copy.deepcopy(self.runs)
            if key == 'byte_length':
                self.runs['runs'][0]['stdout'][key] = True
            else:
                self.runs['runs'][0][key] = False
            with self.assertRaises(cw.InputError):
                self.load()
            self.runs = original

    def test_invalid_absolute_traversal_alias_paths(self):
        for path in ('/tmp/file', '../file', 'x/../file', 'x//file', './x/file', 'x\\file'):
            with self.subTest(path=path), self.assertRaises(cw.InputError):
                cw.relative_parts(path)

    def test_symlink_file_and_directory_refused(self):
        path = self.root / self.runs['runs'][0]['stdout']['path']
        real = path.with_suffix('.original')
        path.rename(real)
        path.symlink_to(real)
        with self.assertRaises((OSError, cw.InputError)):
            self.load()
        path.unlink()
        real.rename(path)
        folder = self.root / 'results'
        moved = self.root / 'real-results'
        folder.rename(moved)
        folder.symlink_to(moved, target_is_directory=True)
        with self.assertRaises((OSError, cw.InputError)):
            self.load()

    def test_native_report_bad_shape_refused(self):
        record = self.runs['runs'][0]
        path = self.root / record['stdout']['path']
        value = cw.decode(path.read_bytes())
        value['layers'] = []
        write_json(path, value)
        record['stdout'].update(cw.fingerprint(path.read_bytes()))
        with self.assertRaisesRegex(cw.InputError, 'layers/signers shape'):
            self.load()

    def test_extra_native_fields_and_null_preserved(self):
        record = self.runs['runs'][0]
        path = self.root / record['stdout']['path']
        value = cw.decode(path.read_bytes())
        value['synthetic_extra'] = {'null': None, 'array': [False, 0, 'native_reason', []]}
        write_json(path, value)
        record['stdout'].update(cw.fingerprint(path.read_bytes()))
        report = self.load()[0]['npm', 'match']
        self.assertTrue(cw.same(report.value, value))
        self.assertEqual(cw.report_copy(report)['raw_utf8'].encode(), path.read_bytes())

    def test_source_identity_change_refused(self):
        self.runs['source_identity']['npm'] = {'nenrin_verify.mjs': {'sha256': '0' * 64, 'byte_length': 1}}
        with self.assertRaisesRegex(cw.InputError, 'source identity differs'):
            self.load()

    def test_saved_schema_cannot_be_relabelled_as_fresh(self):
        self.runs['schema'] = compare.NATIVE_SAVED
        with self.assertRaisesRegex(cw.InputError, 'schema or mode'):
            self.load()

    def test_synthetic_record_cannot_emit_final_comparison(self):
        with self.assertRaisesRegex(cw.InputError, 'synthetic harness'):
            compare.build_report(native_run=self.root)

    def test_native_verifier_version_not_removed(self):
        record = self.runs['runs'][0]
        path = self.root / record['stdout']['path']
        value = cw.decode(path.read_bytes())
        value['verifier_version'] = 'future'
        write_json(path, value)
        record['stdout'].update(cw.fingerprint(path.read_bytes()))
        with self.assertRaisesRegex(cw.InputError, 'verifier version'):
            self.load()


class PublicAndVateCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='vate-public-harness-')
        self.root = Path(self.temporary.name).resolve()
        self.public = cw.Reader(TASK)
        self.pins, _, _ = compare.verify_public_inputs(self.public)
        repo = cw.Reader(REPO, 'repository')
        try:
            self.sources = compare.repository_source_bytes(repo, self.pins)
        finally:
            repo.close()
        self.original = compare.original_case(self.sources, self.pins)
        value = copy.deepcopy(cw.json_object(self.public.document('saved/vate/REPORTS.json')))
        value.update(schema=compare.VATE_FRESH, evidence_mode='fresh_local_run', harness_only=True,
                     runtime={'executable': '/synthetic/python', 'executable_sha256': '2' * 64, 'jsonschema_version': '4.26.0'},
                     source_files={path: cw.fingerprint(raw) for path, raw in self.sources.items()})
        self.helper = self.public.read('helpers/build_cases.py')
        compare.write_new(self.root / 'helpers/build_cases.py', self.helper)
        value['producer'] = {'helper': cw.fingerprint(self.helper)}
        value['preparation'] = {'command': ['/synthetic/python', '-I', '-B', '-c', cw.VATE_BOOTSTRAP, 'helpers/build_cases.py'],
                                'cwd': '.', 'started_at': '2026-10-14T00:00:00+00:00',
                                'finished_at': '2026-10-14T00:00:01+00:00', 'exit_code': 0}
        for role, extension, raw in [('stdout', 'out', b'synthetic preparation output\n'), ('stderr', 'err', b'')]:
            path = 'preparation.' + extension
            compare.write_new(self.root / path, raw)
            value['preparation'][role] = {'path': path, **cw.fingerprint(raw)}
        for path, raw in self.sources.items():
            compare.write_new(self.root / 'source' / path, raw)
        for record in value['cases']:
            case = record['case']
            folder = 'cases/' + case
            for name in record['input_files']:
                compare.write_new(self.root / folder / name, self.public.read(record['input_directory'] + '/' + name))
            record['input_directory'] = folder
            record.pop('historical_execution')
            record.update(command=['/synthetic/python', '-I', '-B', '-c', cw.VATE_BOOTSTRAP,
                                  'source/reference/s3-observation-example/assess_observation.py',
                                  '--bundle', folder, '--trust', 'inputs/receiver-policy.json'], cwd='.',
                          started_at='2026-10-14T00:00:00+00:00', finished_at='2026-10-14T00:00:01+00:00')
            for role in ('stdout', 'stderr'):
                raw = self.public.read(record[role]['path'])
                record[role]['path'] = record[role]['path'].replace('saved/vate/', 'results/')
                compare.write_new(self.root / record[role]['path'], raw)
        policy = self.public.read(value['receiver_policy']['path'])
        value['receiver_policy']['path'] = 'inputs/receiver-policy.json'
        compare.write_new(self.root / value['receiver_policy']['path'], policy)
        self.run = value
        self.save()

    def tearDown(self):
        self.public.close()
        self.temporary.cleanup()

    def save(self):
        write_json(self.root / 'RUN.json', self.run)

    def load(self):
        self.save()
        reader = cw.Reader(self.root)
        try:
            return compare.load_vate(reader, self.pins, self.original, self.sources,
                                     fresh=True, expected_helper=self.helper)
        finally:
            reader.close()

    def test_fixed_vate_input_and_results_load(self):
        self.assertEqual(set(self.load()[0]), set(cw.CASES.values()))

    def test_preparation_and_producer_required_objects(self):
        for key in ('preparation', 'producer'):
            original = self.run[key]
            for value in (cw.MISSING, None, [], True, 'invalid'):
                with self.subTest(key=key, value=value):
                    if value is cw.MISSING:
                        self.run.pop(key, None)
                    else:
                        self.run[key] = value
                    with self.assertRaisesRegex(cw.InputError, 'must be an object'):
                        self.load()
            self.run[key] = original

    def test_preparation_command_exact_interpreter_bootstrap_helper_and_arguments(self):
        record = self.run['preparation']
        original = record['command']
        commands = [None, [], 'invalid', original[:-1], original + ['unexpected']]
        for index in range(len(original)):
            changed = list(original)
            changed[index] = 'different'
            commands.append(changed)
        for command in commands:
            with self.subTest(command=command):
                record['command'] = command
                with self.assertRaisesRegex(cw.InputError, 'preparation command/cwd'):
                    self.load()
        record.pop('command')
        with self.assertRaisesRegex(cw.InputError, 'preparation command/cwd'):
            self.load()
        record['command'] = original
        for cwd in (None, '/', './', True):
            with self.subTest(cwd=cwd):
                record['cwd'] = cwd
                with self.assertRaisesRegex(cw.InputError, 'preparation command/cwd'):
                    self.load()
        record.pop('cwd')
        with self.assertRaisesRegex(cw.InputError, 'preparation command/cwd'):
            self.load()

    def test_preparation_requires_integer_zero_exit(self):
        for value in (cw.MISSING, None, False, True, 1, -1, '0'):
            with self.subTest(value=value):
                if value is cw.MISSING:
                    self.run['preparation'].pop('exit_code')
                else:
                    self.run['preparation']['exit_code'] = value
                with self.assertRaisesRegex(cw.InputError, 'preparation failed'):
                    self.load()

    def test_preparation_requires_ordered_utc_times(self):
        record = self.run['preparation']
        for key in ('started_at', 'finished_at'):
            original = record[key]
            for value in (cw.MISSING, None, True, '2026-10-14T00:00:00', 'invalid+00:00'):
                with self.subTest(key=key, value=value):
                    if value is cw.MISSING:
                        record.pop(key, None)
                    else:
                        record[key] = value
                    with self.assertRaises(ValueError):
                        self.load()
            record[key] = original
        record['finished_at'] = '2026-10-13T23:59:59+00:00'
        with self.assertRaisesRegex(cw.InputError, 'finishes before'):
            self.load()

    def test_preparation_utc_suffix_cannot_hide_naive_or_mixed_times(self):
        naive = '2026-10-14+00:00'
        aware = '2026-10-14T00:00:00+00:00'
        for started, finished in ((naive, naive), (naive, aware), (aware, naive)):
            with self.subTest(started=started, finished=finished):
                self.run['preparation'].update(started_at=started, finished_at=finished)
                with self.assertRaisesRegex(cw.InputError, 'requires a timezone-aware UTC'):
                    self.load()

    def test_preparation_preserves_existing_utc_datetime_forms(self):
        for started, finished in (
                ('2026-10-14T00:00:00+00:00', '2026-10-14T00:00:01+00:00'),
                ('2026-10-14T00:00:00.123456+00:00', '2026-10-14T00:00:00.123457+00:00'),
                ('2026-10-14 00:00:00+00:00', '2026-10-14 00:00:00+00:00')):
            with self.subTest(started=started, finished=finished):
                self.run['preparation'].update(started_at=started, finished_at=finished)
                self.assertEqual(set(self.load()[0]), set(cw.CASES.values()))

    def test_preparation_plain_naive_and_non_utc_times_remain_rejected(self):
        valid = '2026-10-14T00:00:00+00:00'
        for invalid in ('2026-10-14T00:00:00', '2026-10-14T00:00:00+09:00'):
            for key in ('started_at', 'finished_at'):
                with self.subTest(key=key, invalid=invalid):
                    self.run['preparation'].update(started_at=valid, finished_at=valid)
                    self.run['preparation'][key] = invalid
                    with self.assertRaisesRegex(cw.InputError, 'requires a UTC'):
                        self.load()

    def test_preparation_both_output_files_required_and_hash_bound(self):
        for role in ('stdout', 'stderr'):
            path = self.root / self.run['preparation'][role]['path']
            raw = path.read_bytes()
            with self.subTest(role=role, change='delete'):
                path.unlink()
                with self.assertRaises(OSError):
                    self.load()
            with self.subTest(role=role, change='alter'):
                path.write_bytes(raw + b'changed')
                with self.assertRaisesRegex(cw.InputError, 'binding mismatch'):
                    self.load()
            path.write_bytes(raw)

    def test_preparation_output_references_require_fixed_path_hash_and_length(self):
        for role in ('stdout', 'stderr'):
            original = self.run['preparation'][role]
            variants = [cw.MISSING, None, {}, {**original, 'path': 'results/matching.out'},
                        {**original, 'sha256': '0' * 64}, {**original, 'byte_length': True},
                        {**original, 'byte_length': original['byte_length'] + 1}]
            for reference in variants:
                with self.subTest(role=role, reference=reference):
                    if reference is cw.MISSING:
                        self.run['preparation'].pop(role, None)
                    else:
                        self.run['preparation'][role] = reference
                    with self.assertRaises(cw.InputError):
                        self.load()
            self.run['preparation'][role] = original

    def test_preparation_helper_required_and_bound_to_declared_and_public_bytes(self):
        path = self.root / 'helpers/build_cases.py'
        path.unlink()
        with self.assertRaises(OSError):
            self.load()
        changed = self.helper + b'\n# synthetic mutation, never executed\n'
        path.write_bytes(changed)
        with self.assertRaisesRegex(cw.InputError, 'binding mismatch'):
            self.load()
        self.run['producer']['helper'] = cw.fingerprint(changed)
        with self.assertRaisesRegex(cw.InputError, 'differs from public example'):
            self.load()
        self.assertNotIn('helpers/build_cases.py', self.run['source_files'])

    def test_preparation_helper_fingerprint_shape_hash_and_length_required(self):
        original = self.run['producer']['helper']
        variants = [cw.MISSING, None, [], {}, {**original, 'path': 'source/helper.py'},
                    {'sha256': original['sha256']}, {'byte_length': original['byte_length']},
                    {**original, 'sha256': '0' * 64}, {**original, 'byte_length': True},
                    {**original, 'byte_length': original['byte_length'] + 1}]
        for helper in variants:
            with self.subTest(helper=helper):
                if helper is cw.MISSING:
                    self.run['producer'].pop('helper', None)
                else:
                    self.run['producer']['helper'] = helper
                with self.assertRaises(cw.InputError):
                    self.load()

    def test_fresh_loader_has_no_missing_expected_helper_bypass(self):
        reader = cw.Reader(self.root)
        try:
            with self.assertRaisesRegex(cw.InputError, 'expected public VATE preparation helper bytes required'):
                compare.load_vate(reader, self.pins, self.original, self.sources, fresh=True)
            for helper in (None, b'', 'not bytes', False):
                with self.subTest(helper=helper):
                    with self.assertRaisesRegex(cw.InputError, 'expected public VATE preparation helper bytes required'):
                        compare.load_vate(reader, self.pins, self.original, self.sources,
                                          fresh=True, expected_helper=helper)
        finally:
            reader.close()

    def test_wrong_vate_command_bundle_refused(self):
        self.run['cases'][0]['command'][-3] = 'cases/missing-post'
        with self.assertRaisesRegex(cw.InputError, 'command/input assignment'):
            self.load()

    def test_vate_wrong_bootstrap_refused(self):
        self.run['cases'][0]['command'][4] = 'print("synthetic wrong program")'
        with self.assertRaisesRegex(cw.InputError, 'command/input assignment'):
            self.load()

    def test_vate_fingerprint_cannot_override_case_path(self):
        self.run['cases'][0]['input_files']['effective-request.json']['path'] = 'cases/missing-post/effective-request.json'
        with self.assertRaisesRegex(cw.InputError, 'fingerprint shape differs'):
            self.load()

    def test_native_changed_source_refused_before_runtime_execution(self):
        package = self.root / 'package'
        package.mkdir()
        (package / 'nenrin_verify.mjs').write_bytes(b'changed native code')
        pins = cw.json_object(self.public.document('NATIVE-PINS.json'))
        with mock.patch('subprocess.run', side_effect=AssertionError('changed source must not execute')):
            with self.assertRaisesRegex(cw.InputError, 'binding mismatch'):
                replay_native.installed_identity(Path('/unused/node'), package / 'nenrin_verify.mjs', Path('/unused/python'), pins,
                                                 root=self.root, phase='preflight')

    def test_reported_vate_source_hash_cannot_disagree_with_fixed_source(self):
        record = self.run['cases'][0]
        path = self.root / record['stdout']['path']
        value = cw.decode(path.read_bytes())
        value['receipt_check']['source_files']['reference/vate-verifier-core/vate_verifier_core.py'] = '0' * 64
        write_json(path, value)
        record['stdout'].update(cw.fingerprint(path.read_bytes()))
        with self.assertRaisesRegex(cw.InputError, 'source_files differ from fixed VATE pins'):
            self.load()

    def test_reported_vate_source_set_and_types_are_exact(self):
        record = self.run['cases'][0]
        path = self.root / record['stdout']['path']
        original = cw.decode(path.read_bytes())
        expected = original['receipt_check']['source_files']
        first = next(iter(expected))
        variants = [None, [], 'source-files', True,
                    {key: value for key, value in expected.items() if key != first},
                    {**expected, 'unrelated.py': '0' * 64}, {**expected, first: 0}]
        for reported in variants:
            with self.subTest(reported=reported):
                value = copy.deepcopy(original)
                value['receipt_check']['source_files'] = reported
                write_json(path, value)
                record['stdout'].update(cw.fingerprint(path.read_bytes()))
                with self.assertRaisesRegex(cw.InputError, 'source_files differ from fixed VATE pins'):
                    self.load()
        value = copy.deepcopy(original)
        del value['receipt_check']['source_files']
        write_json(path, value)
        record['stdout'].update(cw.fingerprint(path.read_bytes()))
        with self.assertRaisesRegex(cw.InputError, 'source_files differ from fixed VATE pins'):
            self.load()

    def test_wrong_vate_case_report_resealed_refused(self):
        first = next(r for r in self.run['cases'] if r['case'] == 'matching')
        other = next(r for r in self.run['cases'] if r['case'] == 'target-mismatch')
        raw = (self.root / other['stdout']['path']).read_bytes()
        (self.root / first['stdout']['path']).write_bytes(raw)
        first['stdout'].update(cw.fingerprint(raw))
        with self.assertRaisesRegex(cw.InputError, 'wrong-case or unexpected'):
            self.load()

    def test_vate_copied_source_tamper_refused(self):
        path = self.root / 'source/reference/s3-observation-example/contract.py'
        path.write_bytes(path.read_bytes() + b'\n# synthetic test mutation\n')
        with self.assertRaisesRegex(cw.InputError, 'binding mismatch'):
            self.load()

    def test_original_repository_source_tamper_refused(self):
        path = self.root / 'source/reference/s3-observation-example/contract.py'
        path.write_bytes(b'changed source')
        reader = cw.Reader(self.root / 'source', 'export_without_git')
        try:
            with self.assertRaisesRegex(cw.InputError, 'binding mismatch'):
                compare.source_bytes(reader, self.pins)
        finally:
            reader.close()

    def test_repository_replay_uses_fixed_archive_and_refuses_its_tampering(self):
        repository = self.root / 'repository'
        for path, raw in self.sources.items():
            compare.write_new(repository / compare.HISTORICAL_PREFIX / path, raw)
        current = repository / 'reference/s3-observation-example/contract.py'
        compare.write_new(current, b'changed current source')
        reader = cw.Reader(repository, 'repository')
        try:
            self.assertEqual(compare.repository_source_bytes(reader, self.pins), self.sources)
        finally:
            reader.close()
        archived = repository / compare.HISTORICAL_PREFIX / 'reference/s3-observation-example/contract.py'
        archived.write_bytes(b'changed historical source')
        reader = cw.Reader(repository, 'repository')
        try:
            with self.assertRaisesRegex(cw.InputError, 'binding mismatch'):
                compare.repository_source_bytes(reader, self.pins)
        finally:
            reader.close()

    def test_post_reintroduced_into_missing_case_refused(self):
        record = next(r for r in self.run['cases'] if r['case'] == 'missing-post')
        compare.write_new(self.root / record['input_directory'] / 'post.json', self.original['post.json'])
        with self.assertRaisesRegex(cw.InputError, 'inventory differs'):
            self.load()

    def test_saved_verification_executes_no_checker(self):
        with mock.patch('subprocess.run', side_effect=AssertionError('saved comparison must never run a process')):
            report = compare.build_report()
        self.assertEqual(report['evidence_modes'], {'nenrin': 'saved', 'vate': 'saved'})
        self.assertIs(report['checker_execution_performed_by_comparison'], False)
        self.assertNotIn('verdict', report)
        for case in report['cases']:
            self.assertEqual(case['evidence_modes'], report['evidence_modes'])
            for saved in [*case['native_reports'].values(), case['vate_report']]:
                self.assertEqual(saved['raw_utf8'].encode(), (TASK / saved['artifact']['path']).read_bytes())
        # The comparison's current date is separate from recorded historical execution times.
        self.assertIn('compared_at', report)
        self.assertIn('historical_execution', report['records']['nenrin']['report']['runs'][0])

    def test_local_replay_output_directory_never_reused(self):
        with mock.patch('subprocess.run', side_effect=AssertionError('existing directory must be refused before execution')):
            with self.assertRaisesRegex(cw.InputError, 'output exists'):
                replay_vate.replay(self.root)
            with self.assertRaisesRegex(cw.InputError, 'output exists'):
                replay_native.replay(self.root, Path('/unused/node'), Path('/unused/nenrin_verify.mjs'), Path('/unused/python'))

    def test_output_file_never_overwritten(self):
        output = self.root / 'keep.json'
        output.write_bytes(b'KEEP')
        with redirect_stderr(io.StringIO()):
            self.assertEqual(compare.main(['--output', str(output)]), 64)
        self.assertEqual(output.read_bytes(), b'KEEP')

    def test_saved_snapshot_digest_tamper_refused(self):
        copied = self.root / 'example'
        shutil.copytree(TASK / 'third_party', copied / 'third_party')
        shutil.copytree(TASK / 'saved', copied / 'saved')
        for name in ('SOURCES.json', 'VATE-PINS.json', 'NATIVE-PINS.json', 'LICENSE'):
            shutil.copyfile(TASK / name, copied / name)
        report = copied / 'saved/nenrin/npm-match.out'
        report.write_bytes(report.read_bytes() + b' ')
        reader = cw.Reader(copied)
        try:
            with self.assertRaisesRegex(cw.InputError, 'binding mismatch'):
                compare.verify_public_inputs(reader)
        finally:
            reader.close()

    def test_archive_inputs_need_neither_git_nor_private_notes(self):
        reader = cw.Reader(self.root / 'source', 'export')
        try:
            self.assertFalse((reader.root / '.git').exists())
            self.assertFalse((reader.root / '.local-notes').exists())
            self.assertEqual(compare.source_bytes(reader, self.pins), self.sources)
        finally:
            reader.close()


class ReplayDiagnosticsTests(unittest.TestCase):
    """Bounded local process probes and synthetic failures; no native verifier run."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='crosswalk-diagnostics-')
        self.root = Path(self.temporary.name).resolve()
        self.python = Path(sys.executable)
        self.env = replay_native.environment(self.python, self.python)

    def tearDown(self):
        self.temporary.cleanup()

    def invoke(self, engine, root, code='pass'):
        if engine == 'vate':
            contract = root / 'source/reference/s3-observation-example/contract.py'
            contract.parent.mkdir(parents=True)
            contract.write_text("from pathlib import Path\nROOT = Path('source').resolve()\n")
            (root / 'probe.py').write_text(code)
            return replay_vate.invoke(root, 'probe.py', [], 'probe')
        _, record = replay_native.invoke_python(root, self.python, 'probe', code, env=self.env, stem='probe')
        return record

    def assert_timeout(self, root, stem, stdout, stderr):
        record = cw.decode((root / (stem + '.timeout.json')).read_bytes())
        self.assertEqual(record['schema'], 'nenrin-vate-replay-timeout-v1')
        self.assertEqual(record['status'], 'timed_out')
        self.assertIsNone(record['exit_code'])
        self.assertGreater(record['timeout_seconds'], 0)
        self.assertEqual(record['cwd'], '.')
        compare.local_times(record)
        for role, extension, raw in [('stdout', 'out', stdout), ('stderr', 'err', stderr)]:
            path = stem + '.' + extension
            self.assertEqual((root / path).read_bytes(), raw)
            self.assertEqual(record[role], {'path': path, **cw.fingerprint(raw)})
        self.assertFalse((root / 'RUN.json').exists())
        return record

    def test_python_timeouts_keep_partial_binary_and_absent_output(self):
        for engine in ('vate', 'native'):
            for index, (stdout, stderr) in enumerate(((b'partial\x00\xff', b'error\xfe'), (None, None), (b'', b''))):
                with self.subTest(engine=engine, stdout=stdout, stderr=stderr):
                    root = self.root / (engine + str(index))
                    root.mkdir()
                    failure = subprocess.TimeoutExpired(['synthetic'], 1, output=stdout, stderr=stderr)
                    with mock.patch('subprocess.run', side_effect=failure):
                        with self.assertRaises(subprocess.TimeoutExpired) as caught:
                            self.invoke(engine, root)
                    self.assertIs(caught.exception, failure)
                    record = self.assert_timeout(root, 'probe', stdout or b'', stderr or b'')
                    self.assertEqual(record['command'][0], sys.executable)
                    if engine == 'native':
                        self.assertEqual(record['python_cache'], {**cw.native_cache_record('probe'), 'empty_after': None})
                        self.assertEqual(list((root / record['python_cache']['path']).iterdir()), [])

    def test_real_python_timeout_output_survives_both_entrypoints(self):
        original_run = subprocess.run
        code = "import os,time; os.write(1, b'partial\\x00\\xff'); os.write(2, b'error\\xfe'); time.sleep(10)"
        def short_timeout(command, **kwargs):
            return original_run(command, **{**kwargs, 'timeout': 1})
        for engine in ('vate', 'native'):
            with self.subTest(engine=engine):
                root = self.root / engine
                root.mkdir()
                probe_code = code
                if engine == 'native':
                    probe_code = "from pathlib import Path; Path('.python-cache/probe/partial').write_bytes(b'partial cache'); " + code
                with mock.patch('subprocess.run', side_effect=short_timeout):
                    with self.assertRaises(subprocess.TimeoutExpired):
                        self.invoke(engine, root, probe_code)
                record = self.assert_timeout(root, 'probe', b'partial\x00\xff', b'error\xfe')
                if engine == 'native':
                    self.assertIsNone(record['python_cache']['empty_after'])
                    self.assertEqual((root / '.python-cache/probe/partial').read_bytes(), b'partial cache')

    def test_python_normal_outputs_and_nonzero_exit_remain_complete(self):
        for engine in ('vate', 'native'):
            for exit_code in (0, 7):
                with self.subTest(engine=engine, exit_code=exit_code):
                    root = self.root / (engine + str(exit_code))
                    root.mkdir()
                    record = self.invoke(engine, root, f"import os; os.write(1, b'complete\\xff'); raise SystemExit({exit_code})")
                    self.assertEqual(record['exit_code'], exit_code)
                    self.assertEqual((root / 'probe.out').read_bytes(), b'complete\xff')
                    self.assertEqual((root / 'probe.err').read_bytes(), b'')
                    self.assertNotIn('status', record)
                    self.assertFalse((root / 'probe.timeout.json').exists())
                    compare.local_times(record)

    def test_timeout_diagnostics_never_overwrite_existing_files(self):
        for existing in ('probe.out', 'probe.err', 'probe.timeout.json'):
            with self.subTest(existing=existing):
                root = self.root / existing
                root.mkdir()
                (root / existing).write_bytes(b'KEEP')
                with mock.patch('subprocess.run', side_effect=subprocess.TimeoutExpired(['synthetic'], 1, output=b'partial')):
                    with self.assertRaises(FileExistsError):
                        self.invoke('vate', root)
                self.assertEqual((root / existing).read_bytes(), b'KEEP')
                self.assertFalse((root / 'RUN.json').exists())

    def test_vate_replay_timeout_and_failed_preparation_never_complete_run(self):
        for timeout in (True, False):
            with self.subTest(timeout=timeout):
                output = self.root / ('timeout' if timeout else 'nonzero')
                failure = subprocess.TimeoutExpired(['synthetic'], 1, output=b'partial', stderr=b'error')
                completed = subprocess.CompletedProcess(['synthetic'], 7, b'partial', b'error')
                with mock.patch.object(replay_vate.importlib.metadata, 'version', return_value='4.26.0'), \
                     mock.patch.object(replay_vate.platform, 'platform', return_value='synthetic harness'), \
                     mock.patch('subprocess.run', side_effect=failure if timeout else None, return_value=completed), \
                     redirect_stderr(io.StringIO()):
                    self.assertEqual(replay_vate.main(['--output', str(output)]), 64)
                self.assertFalse((output / 'RUN.json').exists())
                if timeout:
                    record = self.assert_timeout(output, 'preparation', b'partial', b'error')
                    self.assertEqual(record['command'][-1], 'helpers/build_cases.py')
                else:
                    self.assertEqual((output / 'preparation.err').read_bytes(), b'error')
                    self.assertFalse((output / 'preparation.timeout.json').exists())

    def synthetic_package(self):
        package = self.root / 'package'
        package.mkdir()
        files = {'nenrin_verify.mjs': b'// synthetic fixture, never executed\n',
                 'package.json': cw.canonical({'name': 'nenrin-verify', 'version': '0.5.1'})}
        for path, raw in files.items():
            (package / path).write_bytes(raw)
        return package / 'nenrin_verify.mjs', {'npm': {'files': {path: cw.fingerprint(raw) for path, raw in files.items()}},
                                              'pypi': {'files': {}}}

    def test_node_version_timeout_retains_diagnostics(self):
        entry, pins = self.synthetic_package()
        with mock.patch('subprocess.run', side_effect=subprocess.TimeoutExpired(['synthetic'], 15, output=b'v', stderr=b'error')):
            with self.assertRaises(subprocess.TimeoutExpired):
                replay_native.installed_identity(self.python, entry, self.python, pins, root=self.root, phase='preflight')
        record = self.assert_timeout(self.root, 'checks/node-preflight', b'v', b'error')
        self.assertEqual(record['command'], [str(self.python), '--version'])

    def test_node_version_success_logs_and_identity_stay_consistent(self):
        entry, pins = self.synthetic_package()
        probe = {'source_identity': {}, 'runtime': {'executable': str(self.python), 'packages': {'nenrin-verify': '0.5.3'}}}
        outputs = [subprocess.CompletedProcess([], 0, b'v22.16.0\n', b''),
                   subprocess.CompletedProcess([], 0, cw.canonical(probe), b'')]
        with mock.patch('subprocess.run', side_effect=outputs):
            identity, runtime, record = replay_native.installed_identity(
                self.python, entry, self.python, pins, root=self.root, phase='preflight')
        self.assertEqual(identity, {engine: pins[engine]['files'] for engine in cw.PACKAGES})
        self.assertEqual(runtime['node']['version'], 'v22.16.0')
        self.assertEqual(runtime['python']['executable'], str(self.python))
        self.assertEqual(record['phase'], 'preflight')
        self.assertEqual(record['exit_code'], 0)
        self.assertEqual((self.root / 'checks/node-preflight.out').read_bytes(), b'v22.16.0\n')
        self.assertEqual((self.root / 'checks/node-preflight.err').read_bytes(), b'')
        self.assertEqual((self.root / record['stdout']['path']).read_bytes(), cw.canonical(probe))
        self.assertEqual(list((self.root / record['python_cache']['path']).iterdir()), [])
        self.assertFalse(list(self.root.rglob('*.timeout.json')))

    def test_native_replay_npm_or_python_timeout_never_completes_run(self):
        for engine in ('npm', 'pypi'):
            with self.subTest(engine=engine):
                output = self.root / engine
                def fail_selected(command, **kwargs):
                    if engine == 'pypi' and len(command) == 3:
                        return subprocess.CompletedProcess(command, 0, (TASK / 'saved/nenrin/npm-match.out').read_bytes(), b'')
                    raise subprocess.TimeoutExpired(command, kwargs['timeout'], output=b'partial', stderr=b'error')
                with mock.patch.object(replay_native, 'installed_identity', return_value=({}, {}, {})), \
                     mock.patch('subprocess.run', side_effect=fail_selected), redirect_stderr(io.StringIO()):
                    self.assertEqual(replay_native.main(['--output', str(output), '--node', str(self.python),
                        '--python', str(self.python), '--npm-entry', str(self.root / 'nenrin_verify.mjs')]), 64)
                record = self.assert_timeout(output, f'results/{engine}-match', b'partial', b'error')
                self.assertEqual(record['command'][-1], 'inputs/match.json')
                if engine == 'pypi':
                    self.assertEqual(record['python_cache'], {**cw.native_cache_record('verify-match'), 'empty_after': None})
                    self.assertEqual((output / 'results/npm-match.out').read_bytes(), (TASK / 'saved/nenrin/npm-match.out').read_bytes())


class PythonCacheTests(unittest.TestCase):
    """Finite synthetic module probes; no native packages, network or signing."""
    def test_different_existing_bytecode_is_ignored_without_changing_source(self):
        with tempfile.TemporaryDirectory(prefix='nenrin-synthetic-cache-') as temporary:
            root = Path(temporary).resolve()
            source = root / 'synthetic_cache_subject.py'
            raw = b"VALUE = 'source'\n"
            source.write_bytes(raw)
            code = f'import sys; sys.path.insert(0, {str(root)!r}); import synthetic_cache_subject as s; print(s.VALUE)'
            python = Path(sys.executable)
            env = replay_native.environment(python, python)
            old_command = [str(python), '-I', '-B', '-c', code]
            baseline = subprocess.run(old_command, env=env, cwd=root, capture_output=True, timeout=30)
            self.assertEqual((baseline.returncode, baseline.stdout), (0, b'source\n'))

            alternate = root / 'synthetic_alternate.py'
            alternate.write_bytes(b"VALUE = 'existing-pyc'\n")
            cache = root / '__pycache__' / f'synthetic_cache_subject.{sys.implementation.cache_tag}.pyc'
            cache.parent.mkdir()
            py_compile.compile(str(alternate), cfile=str(cache), dfile=str(source), doraise=True,
                               invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
            compiled = bytearray(cache.read_bytes())
            compiled[8:16] = struct.pack('<II', int(source.stat().st_mtime) & 0xffffffff, len(raw))
            cache.write_bytes(compiled)
            before_cache = cache.read_bytes()
            exposed = subprocess.run(old_command, env=env, cwd=root, capture_output=True, timeout=30)
            self.assertEqual((exposed.returncode, exposed.stdout), (0, b'existing-pyc\n'))

            fixed, record = replay_native.invoke_python(root, python, 'synthetic', code, env=env, stem='synthetic-fixed')
            self.assertEqual((fixed.returncode, fixed.stdout), (0, b'source\n'))
            self.assertEqual(source.read_bytes(), raw)
            self.assertEqual(cache.read_bytes(), before_cache)
            self.assertEqual(list((root / record['python_cache']['path']).iterdir()), [])
            self.assertIn('pycache_prefix=.python-cache/synthetic', record['command'])

    def test_python_cache_prefix_is_exclusive_and_never_reused(self):
        with tempfile.TemporaryDirectory(prefix='nenrin-synthetic-cache-reuse-') as temporary:
            root = Path(temporary).resolve()
            (root / '.python-cache/synthetic').mkdir(parents=True)
            python = Path(sys.executable)
            with mock.patch('subprocess.run', side_effect=AssertionError('existing cache must be refused before Python starts')):
                with self.assertRaises(FileExistsError):
                    replay_native.invoke_python(root, python, 'synthetic', 'print("unused")',
                                                env=replay_native.environment(python, python), stem='unused')


if __name__ == '__main__':
    unittest.main(verbosity=2)
