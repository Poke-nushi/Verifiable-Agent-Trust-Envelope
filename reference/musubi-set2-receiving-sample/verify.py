"""Local verification harness; accepts explicit sample and VATE source directories."""
import argparse
import copy
from pathlib import Path
import platform
import shutil
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from receiving import (InputError, SavedOutputError, assess, canonical, changes, decode, digest, encoded, run,
                       interpret_native, load_inbox, sha, validate_selection, verified_files)

SAMPLE = None


class BindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.selection = decode((SAMPLE / 'selection.json').read_bytes())
        cls.manifest = decode((SAMPLE / 'manifest.json').read_bytes())
        cls.originals = verified_files(SAMPLE / 'originals', cls.manifest['files'])
        cls.bundle = decode(cls.originals[cls.selection['bundle']['path']])
        cls.native = decode(cls.originals[cls.selection['reference_output']['path']])

    def make(self, selection=None, originals=None, bundle=None, native=None, state='evaluated'):
        return assess(selection or self.selection, originals or self.originals,
                      bundle or self.bundle, self.native if native is None else native, {'state': state})

    def test_baseline_states(self):
        r = self.make()
        self.assertEqual('partial', r['overall_evidence_state'])
        self.assertEqual(9, sum(x['binding_status'] == 'bound' for x in r['requirements']))
        self.assertEqual(10, sum(x['binding_status'] == 'not_received' for x in r['requirements']))
        self.assertEqual(2, sum(x['binding_status'] == 'not_selected' for x in r['requirements']))
        self.assertTrue(all(x['accepted'] is None for x in r['native']['output']['pilot']['executions']))

    def test_signed_other_request_receipt_is_not_same_record(self):
        s = copy.deepcopy(self.selection)
        s['requirements'][0]['files'] = s['requirements'][7]['files']
        r = self.make(selection=s)
        self.assertTrue(self.native['companion']['log']['verified'])
        self.assertEqual('contradictory', r['requirements'][0]['binding_status'])

    def test_wrong_occurrence_same_object_digest(self):
        s = copy.deepcopy(self.selection)
        s['cases'][0]['request_sha256'] = s['cases'][1]['request_sha256']
        r = self.make(selection=s)
        self.assertEqual('contradictory', r['cases'][0]['binding_status'])
        self.assertEqual('contradictory', r['requirements'][0]['binding_status'])

    def test_wrong_criteria(self):
        s = copy.deepcopy(self.selection); s['cases'][0]['criteria_sha256'] = '0' * 64
        self.assertEqual('contradictory', self.make(selection=s)['requirements'][2]['binding_status'])

    def test_wrong_checker(self):
        s = copy.deepcopy(self.selection); s['cases'][0]['checker'] = '0' * 64
        self.assertEqual('contradictory', self.make(selection=s)['requirements'][2]['binding_status'])

    def test_wrong_item_digest(self):
        s = copy.deepcopy(self.selection); s['requirements'][0]['item_sha256'] = '0' * 64
        self.assertEqual('contradictory', self.make(selection=s)['requirements'][0]['binding_status'])

    def test_wrong_log(self):
        s = copy.deepcopy(self.selection); s['log_identity']['head'] = '0' * 64
        r = self.make(selection=s)
        self.assertEqual(['selected_log_mismatch'], r['global_findings'])
        self.assertEqual('contradictory', r['requirements'][0]['binding_status'])

    def test_multiple_candidates_remain_ambiguous(self):
        s = copy.deepcopy(self.selection); s['requirements'][0]['files'] *= 2
        self.assertEqual('ambiguous', self.make(selection=s)['requirements'][0]['binding_status'])

    def test_duplicate_occurrence_is_ambiguous(self):
        b = copy.deepcopy(self.bundle); b['requests'].append(b['requests'][0])
        self.assertEqual('ambiguous', self.make(bundle=b)['cases'][0]['binding_status'])

    def test_unknown_original_present_is_unsupported(self):
        s = copy.deepcopy(self.selection); s['requirements'][3]['files'] = s['requirements'][0]['files']
        self.assertEqual('unsupported', self.make(selection=s)['requirements'][3]['binding_status'])

    def test_malformed_candidate_is_contradictory(self):
        originals = dict(self.originals); originals[self.selection['requirements'][0]['files'][0]] = b'[]'
        self.assertEqual('contradictory', self.make(originals=originals)['requirements'][0]['binding_status'])

    def test_evaluator_failure_is_unassessed_not_missing(self):
        r = self.make(state='evaluator_error')
        self.assertEqual('bound', r['requirements'][0]['binding_status'])
        self.assertEqual('unassessed', r['requirements'][0]['semantic_assessment'])
        self.assertEqual('evaluator_error', r['native']['state'])

    def test_no_native_row_and_duplicate_native_row_are_unassessed(self):
        for rows in ([], [self.native['pilot']['executions'][0]] * 2):
            n = copy.deepcopy(self.native); n['pilot']['executions'] = rows
            execution = {'state': 'process_completed', 'exit_code': 0}
            actual = interpret_native(encoded(n), execution)
            self.assertEqual('evaluated', execution['state'])
            self.assertEqual('unassessed', self.make(native=actual)['requirements'][0]['semantic_assessment'])

    def test_budget_arrays_and_acceptance_are_not_flattened(self):
        n = copy.deepcopy(self.native)
        n['pilot']['payments'][0]['budgets'].append({'unit':'other','limit':0,'total':1})
        n['pilot']['executions'][0]['accepted'] = False
        r = self.make(native=n)
        self.assertEqual(n['pilot']['payments'][0], r['requirements'][1]['native_rows'][0])
        self.assertIs(False, r['requirements'][0]['native_rows'][0]['accepted'])

    def test_invalid_json_not_silently_canonicalized(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":1.0}', b'NaN'):
            with self.assertRaises(InputError): decode(raw)
        for obj in ({'a': 2**53}, {'a':'\u00e9'}, {'a':1.2}):
            with self.assertRaises(InputError): canonical(obj)

    def test_manifest_traversal_duplicate_tamper_and_symlink(self):
        for rows in ([{**self.manifest['files'][0], 'path':'../outside'}],
                     [self.manifest['files'][0]] * 2,
                     [{**self.manifest['files'][0], 'sha256':'0'*64}]):
            with self.assertRaises(InputError): verified_files(SAMPLE / 'originals', rows)

    def test_selection_duplicates_and_missing_candidates_fail(self):
        for mode in ('duplicate','missing'):
            s = copy.deepcopy(self.selection)
            if mode == 'duplicate': s['cases'].append(s['cases'][0])
            else: s['requirements'][0]['files'] = ['absent']
            with self.assertRaises(InputError): validate_selection(s, self.originals)

    def test_normal_native_refusals_are_preserved(self):
        for code, payload in ((2, {'companion': {'log': {'verified': False, 'problem': 'anchor_too_shallow'}}}),
                              (3, {'refused': 'unreadable_input'})):
            payload.update(type='musubi.ca2a.pilot-settlement.v0',profile='musubi.ca2a.pilot.v0')
            execution={'state':'process_completed','exit_code':code}
            self.assertEqual(payload, interpret_native(encoded(payload),execution))
            self.assertEqual('refused',execution['state'])

    def test_bad_output_or_inconsistent_exit_is_an_execution_error(self):
        for raw in (b'not-json',encoded({'type':'musubi.ca2a.pilot-settlement.v0','profile':'musubi.ca2a.pilot.v0'}),
                    encoded({'type':'musubi.ca2a.pilot-settlement.v0','profile':'musubi.ca2a.pilot.v0','companion':[]})):
            execution={'state':'process_completed','exit_code':0}
            self.assertIsNone(interpret_native(raw,execution))
            self.assertEqual('evaluator_error',execution['state'])

    def test_native_integer_parse_limit_retains_unassessed_bindings(self):
        limit = sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(4300)
            for prefix in (b'{', encoded(self.native).rstrip()[:-1] + b','):
                with self.subTest(valid_settlement_prefix=prefix != b'{'):
                    raw = prefix + b'"ignored":' + b'9' * 5000 + b'}'
                    execution = {'state': 'process_completed', 'exit_code': 0}
                    actual = interpret_native(raw, execution)
                    self.assertIsNone(actual)
                    self.assertEqual('evaluator_error', execution['state'])
                    self.assertEqual('invalid_native_output_or_exit_contract', execution['error'])
                    report = assess(self.selection, self.originals, self.bundle, actual, execution)
                    self.assertEqual('partial', report['overall_evidence_state'])
                    self.assertEqual(9, sum(x['binding_status'] == 'bound' for x in report['requirements']))
                    self.assertTrue(all(x['semantic_assessment'] == 'unassessed' for x in report['requirements']))
        finally:
            sys.set_int_max_str_digits(limit)

    def test_process_failure_cannot_be_promoted_by_stdout(self):
        execution={'state':'evaluator_error','exit_code':1}
        self.assertIsNone(interpret_native(encoded(self.native),execution))
        self.assertEqual('evaluator_error',execution['state'])

    def test_malformed_success_output_structure_is_evaluator_error(self):
        payloads = []
        for bad in (None, [], True, 1, 'pilot'):
            n = copy.deepcopy(self.native); n['pilot'] = bad; payloads.append(n)
        n = copy.deepcopy(self.native); del n['pilot']; payloads.append(n)
        for key in ('executions', 'payments', 'criteria_commitments'):
            for bad in (None, {}, 'rows', 1, True, [None], [[]], [1], ['row']):
                n = copy.deepcopy(self.native); n['pilot'][key] = bad; payloads.append(n)
            n = copy.deepcopy(self.native); del n['pilot'][key]; payloads.append(n)
        for n in payloads:
            with self.subTest(pilot=n.get('pilot')):
                execution = {'state': 'process_completed', 'exit_code': 0}
                actual = interpret_native(encoded(n), execution)
                self.assertIsNone(actual)
                self.assertEqual('evaluator_error', execution['state'])
                report = assess(self.selection, self.originals, self.bundle, actual, execution)
                self.assertEqual('partial', report['overall_evidence_state'])
                self.assertEqual(9, sum(x['binding_status'] == 'bound' for x in report['requirements']))
                self.assertTrue(all(x['semantic_assessment'] == 'unassessed' for x in report['requirements']))

    def test_malformed_native_row_identity_is_evaluator_error(self):
        for key in ('executions', 'payments', 'criteria_commitments'):
            for field, bad in (('seq', True), ('seq', '1'), ('seq', -1), ('seq', None),
                               ('request_sha256', []), ('request_sha256', 1),
                               ('request_sha256', 'bad'), ('request_sha256', 'A'*64)):
                with self.subTest(key=key, field=field, value=bad):
                    n = copy.deepcopy(self.native); n['pilot'][key][0][field] = bad
                    execution = {'state': 'process_completed', 'exit_code': 0}
                    self.assertIsNone(interpret_native(encoded(n), execution))
                    self.assertEqual('evaluator_error', execution['state'])

    def test_assessment_time_rejects_wrong_type_or_format(self):
        validate_selection(self.selection, self.originals)
        for value in (None, 1, True, [], {}, '', 'todayZ', '2026-10-22T00:00:00+00:00'):
            with self.subTest(value=value):
                s = copy.deepcopy(self.selection); s['assessment_time'] = value
                with self.assertRaises(ValueError):
                    validate_selection(s, self.originals)

    def test_changes_distinguish_json_types(self):
        for before, after in ((True, 1), (False, 0), (1, True), (0, False),
                              ([True], [1]), ([False], [0]),
                              ([{'nested': [True]}], [{'nested': [1]}]),
                              (None, False), ([], {})):
            with self.subTest(before=before, after=after):
                expected = [{'path': '$', 'before': before, 'after': after}]
                self.assertEqual(encoded(expected), encoded(changes(before, after)))
        expected = [{'path': '$.nested', 'before': [False], 'after': [0]}]
        self.assertEqual(encoded(expected), encoded(changes({'nested': [False]}, {'nested': [0]})))

    def test_array_differences_keep_whole_array_representation(self):
        for before, after in (([1, 2], [1, 3]), ([1], [1, 2]),
                              ([{'a': None}], [{}])):
            expected = [{'path': '$', 'before': before, 'after': after}]
            self.assertEqual(encoded(expected), encoded(changes(before, after)))

    def test_unchanged_json_and_object_key_order_have_no_changes(self):
        value = {'a': [True, 1, False, 0, None, {'nested': ['value']}], 'b': []}
        self.assertEqual([], changes(value, copy.deepcopy(value)))
        self.assertEqual([], changes([{'a': 1, 'b': 2}], [{'b': 2, 'a': 1}]))


def integration(sample, vate, output, environment):
    output.mkdir(parents=True, exist_ok=False)
    def execute(name, **kw):
        args = dict(originals=sample/'originals', manifest=sample/'manifest.json',
                    selection=sample/'selection.json', source=sample/'evaluator-source',
                    runtime=environment/'venv', evaluator=environment/'evaluator.json',
                    vate_root=vate, database=output/'inbox.sqlite', output=output/name,
                    view=None, previous=None)
        args.update(kw)
        return run(SimpleNamespace(**args))
    first = execute('baseline')
    assert first['native_state'] == 'evaluated', first
    assert first['comparison']['exact_bytes']
    assert first['comparison']['actual_raw_sha256'] == '18a19f8a1eb62593b857241f34c07b1d96550b93d5c9ea17184b2ac695818fbd'
    first_raw = (output/'baseline/assessment.json').read_bytes()
    second = execute('extended', selection=sample/'extended-selection.json', view=sample/'extended-view.json',
                     previous=output/'baseline/RESULT.json')
    assert second['native_state'] == 'evaluated'
    assert second['comparison']['kind'] == 'changed_conditions'
    assert second['comparison']['output_changes'] == [{'path':'$.companion.log.anchor_depth','before':9,'after':14}]
    assert second['inbox']['previous_id'] == first['inbox']['run_id']
    assert second['inbox']['max_delivery_sequence'] - first['inbox']['max_delivery_sequence'] < 20
    assert (output/'baseline/assessment.json').read_bytes() == first_raw
    assert (output/'extended/export'/first['assessment_ref']['path']).read_bytes() == first_raw
    # Restore exact inputs using saved references; replay without reading the old originals directory.
    restored = output/'restored'; restored.mkdir()
    for name, ref in first['original_refs'].items():
        raw = (output/'extended/export'/ref['path']).read_bytes()
        assert sha(raw) == ref['digest']['value'] and len(raw) == ref['byte_length']
        p = restored/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(raw)
    third = execute('from-export', originals=restored, previous=output/'extended/RESULT.json')
    assert third['comparison']['exact_bytes']
    assert third['inbox']['previous_id'] == second['inbox']['run_id']
    # Independently valid refs from older evaluations must not be relabeled as the latest.
    for name, old in (('mixed-assessment',first),('mixed-selection',second)):
        forged=copy.deepcopy(old); forged['inbox']['run_id']=third['inbox']['run_id']
        previous=output/(name+'.json'); previous.write_bytes(encoded(forged))
        database=output/(name+'.sqlite'); shutil.copyfile(output/'inbox.sqlite',database)
        try:
            execute(name, previous=previous, database=database)
            raise AssertionError('mixed prior references were accepted')
        except InputError as exc:
            assert 'previous references do not belong' in str(exc)
    # Valid signature from another request remains valid upstream; receiver binding must still fail.
    s = decode((sample/'selection.json').read_bytes())
    s['namespace'] += '-swap'; s['requirements'][0]['files'] = s['requirements'][7]['files']
    swapped = output/'swap-selection.json'; swapped.write_bytes(encoded(s))
    fourth = execute('signed-swap', selection=swapped, database=output/'swap.sqlite')
    report = decode((output/'signed-swap/assessment.json').read_bytes())
    assert fourth['comparison']['exact_bytes'] and report['native']['output']['companion']['log']['verified']
    assert report['requirements'][0]['binding_status'] == 'contradictory'
    # A real upstream refusal is a result, not an evaluator crash.
    refused=decode((sample/'selection.json').read_bytes())
    refused['namespace']+='-refusal'; refused['trust']['min_depth']=1000000
    rejected=output/'refusal-selection.json'; rejected.write_bytes(encoded(refused))
    fifth=execute('native-refusal',selection=rejected,database=output/'refusal.sqlite')
    denied=decode((output/'native-refusal/assessment.json').read_bytes())
    assert fifth['status']=='recorded' and fifth['native_state']=='refused'
    assert denied['native']['output']['companion']['log']['problem']=='anchor_too_shallow'
    assert denied['comparison']['output_changes']
    # Real sandboxed native evaluation followed by a simulated export failure.
    from recover_output import recover
    _, Inbox = load_inbox(vate)
    recovery_db = output/'output-failure.sqlite'
    with patch.object(Inbox, 'export', side_effect=OSError('injected after real evaluation')):
        try:
            execute('output-failure', database=recovery_db)
        except SavedOutputError as exc:
            receipt = exc.receipt
        else:
            raise AssertionError('export fault did not fire')
    before = sha(recovery_db.read_bytes())
    with patch('offline_native.replay', side_effect=AssertionError('native ran during output recovery')):
        recovered = recover(vate, recovery_db, receipt, output/'output-recovered')
    assert sha(recovery_db.read_bytes()) == before
    assert recovered['comparison']['exact_bytes'] and recovered['assessment_ref'] == receipt['assessment_ref']
    assert (output/'output-recovered/materials/evaluation/native.stdout').read_bytes() == (output/'output-failure/native.stdout').read_bytes()
    # Keep all exports verifiable, including predecessor files.
    for name in ('baseline','extended','from-export','signed-swap','native-refusal','output-recovered'):
        folder=output/name/'export'; manifest=decode((folder/'MANIFEST.json').read_bytes())
        for filename, desc in manifest['files'].items():
            raw=(folder/filename).read_bytes()
            assert sha(raw)==desc['raw_sha256'] and len(raw)==desc['byte_length']
    summary={'status':'pass','baseline_sha256':first['comparison']['actual_raw_sha256'],
             'header_delta':second['comparison']['output_changes'], 'restored_originals':len(first['original_refs']),
             'prior_assessment_unchanged':True,'valid_signed_other_request_rejected':True,
             'mixed_previous_references_rejected':2,'native_refusal_preserved':True,
             'real_native_output_recovery_without_replay_or_database_change':True,
             'delivery_sequences':[x['inbox']['max_delivery_sequence'] for x in (first,second,third)],
             'core_status':'selected_empty','native_acceptance':'null','overall_evidence_state':'partial',
             'native_platform':platform.system()+' '+platform.machine(), 'all_export_manifests_verified':True}
    (output/'VERIFICATION.json').write_bytes(encoded(summary))
    print(encoded(summary).decode())


if __name__ == '__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--sample',type=Path,required=True)
    ap.add_argument('--vate-root',type=Path)
    ap.add_argument('--output',type=Path)
    ap.add_argument('--environment',type=Path)
    a=ap.parse_args(); SAMPLE=a.sample.resolve()
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(BindingTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful(): raise SystemExit(1)
    if a.output:
        if not a.vate_root or not a.environment: ap.error('--vate-root and --environment required for integration')
        integration(SAMPLE,a.vate_root.resolve(),a.output.resolve(),a.environment.resolve())
