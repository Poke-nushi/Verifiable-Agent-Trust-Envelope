"""Bounded audit linkage regressions; synthetic mutations are never signed."""
from __future__ import annotations

import argparse
import copy
from pathlib import Path
import platform
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from receiving import (AUDIT_PROFILE, InputError, SavedOutputError, assess, canonical,
                       decode, digest, encoded, load_inbox, run, sha, validate_selection,
                       verified_files)

SAMPLE = Path(__file__).resolve().parent / 'sample'


def requirement(selection, case, kind):
    return next(r for r in selection['requirements'] if r['id'] == 'hs51-musubi-2-' + case + ':' + kind)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.s = decode((SAMPLE/'audit-selection.json').read_bytes())
        self.manifest = decode((SAMPLE/'audit-manifest.json').read_bytes())
        self.originals = verified_files(SAMPLE/'originals', self.manifest['files'])
        self.bundle = decode(self.originals[self.s['bundle']['path']])
        self.native = decode(self.originals[self.s['reference_output']['path']])

    def report(self, state='evaluated'):
        validate_selection(self.s, self.originals)
        return assess(self.s, self.originals, self.bundle, self.native, {'state': state})

    def row(self, case='A', kind='audit_original', state='evaluated'):
        return requirement(self.report(state), case, kind)

    def mutated_audit(self, raw):
        # Shape parser probes use unsigned synthetic receipt mutations and never
        # run interpret_native or label the forged receipt authenticated.
        r = requirement(self.s, 'A', 'execution')
        name = r['files'][0]
        old = decode(self.originals[name])
        entry = copy.deepcopy(old)
        entry['item']['outcome']['response_sha256'] = sha(raw)
        self.originals[name] = encoded(entry)
        self.bundle['log']['entries'] = [entry if e == old else e for e in self.bundle['log']['entries']]
        r['item_sha256'] = digest(entry['item'])
        self.originals[requirement(self.s, 'A', 'audit_original')['files'][0]] = raw

    def test_real_shared_audit_keeps_two_request_links_and_partial_state(self):
        r = self.report()
        self.assertEqual('partial', r['overall_evidence_state'])
        self.assertEqual(13, sum(x['binding_status'] == 'bound' for x in r['requirements']))
        self.assertEqual(10, sum(x['binding_status'] == 'not_received' for x in r['requirements']))
        self.assertEqual(1, sum(x['binding_status'] == 'not_selected' for x in r['requirements']))
        a, c = [requirement(r, case, 'audit_original') for case in ('A', 'C')]
        self.assertEqual(a['raw_sha256'], c['raw_sha256'])
        self.assertNotEqual(a['linkage_basis']['request_sha256'], c['linkage_basis']['request_sha256'])
        self.assertNotEqual(a['linkage_basis']['execution_raw_sha256'], c['linkage_basis']['execution_raw_sha256'])
        for case in ('A', 'C'):
            for kind in ('audit_original', 'dataset_original'):
                self.assertEqual('digest_linkage_checked', requirement(r, case, kind)['semantic_assessment'])
        self.assertEqual(self.native, r['native']['output'])
        self.assertTrue(all(x['accepted'] is None for x in self.native['pilot']['executions']))

    def test_non_ascii_is_raw_bytes_and_does_not_extend_canonical_subset(self):
        raw = self.originals[requirement(self.s, 'A', 'audit_original')['files'][0]]
        self.assertFalse(raw.isascii())
        self.assertEqual('bound', self.row()['binding_status'])
        with self.assertRaises(InputError): canonical(decode(raw))

    def test_no_profile_preserves_old_unsupported_behavior(self):
        del self.s['audit_binding_profile']
        r = self.report()
        self.assertNotIn('audit_binding_profile', r)
        self.assertEqual('unsupported', requirement(r, 'A', 'audit_original')['binding_status'])

    def test_unknown_profile_rejected(self):
        self.s['audit_binding_profile'] = AUDIT_PROFILE + '-unknown'
        with self.assertRaises(InputError): self.report()

    def test_prerequisites_must_exist_be_required_and_match_kind_and_occurrence(self):
        original = copy.deepcopy(self.s)
        for value in (None, [], 'absent', 'hs51-musubi-2-C:execution', 'hs51-musubi-2-A:payment'):
            self.s = copy.deepcopy(original)
            requirement(self.s, 'A', 'audit_original')['execution_requirement'] = value
            with self.subTest(value=value), self.assertRaises(InputError): self.report()
        self.s = copy.deepcopy(original)
        requirement(self.s, 'A', 'execution')['required'] = False
        with self.assertRaises(InputError): self.report()
        self.s = copy.deepcopy(original)
        requirement(self.s, 'A', 'dataset_original')['audit_requirement'] = 'hs51-musubi-2-C:audit_original'
        with self.assertRaises(InputError): self.report()

    def test_requirement_order_cannot_bypass_dependencies(self):
        first = self.report()
        self.s['requirements'].reverse()
        second = self.report()
        self.assertEqual({r['id']: r for r in first['requirements']},
                         {r['id']: r for r in second['requirements']})

    def test_valid_signed_receipts_from_B_or_C_do_not_bind_to_A(self):
        for case in ('B', 'C'):
            requirement(self.s, 'A', 'execution')['files'] = requirement(self.s, case, 'execution')['files']
            self.assertEqual('contradictory', self.row(kind='execution')['binding_status'])
            self.assertEqual('unresolved', self.row()['binding_status'])
            self.assertEqual('unresolved', self.row(kind='dataset_original')['binding_status'])

    def test_missing_or_ambiguous_parent_is_unresolved(self):
        parent = requirement(self.s, 'A', 'execution')
        original = parent['files']
        for files in ([], original * 2):
            parent['files'] = files
            self.assertEqual('unresolved', self.row()['binding_status'])
            self.assertEqual('unassessed', self.row(kind='dataset_original')['semantic_assessment'])

    def test_missing_ambiguous_and_not_selected_audit_are_not_promoted(self):
        r = requirement(self.s, 'A', 'audit_original')
        files = r['files']
        for names, required, state in (([], True, 'not_received'), (files*2, True, 'ambiguous')):
            r.update(files=names, required=required)
            self.assertEqual(state, self.row()['binding_status'])
            self.assertEqual('unresolved', self.row(kind='dataset_original')['binding_status'])
        # An optional audit cannot be a selected dataset prerequisite.
        self.s['requirements'] = [x for x in self.s['requirements'] if x['id'] != 'hs51-musubi-2-A:dataset_original']
        r.update(files=files, required=False)
        self.assertEqual('not_selected', self.row()['binding_status'])

    def test_B_cannot_borrow_shared_A_C_audit(self):
        requirement(self.s, 'B', 'audit_original')['files'] = requirement(self.s, 'A', 'audit_original')['files']
        requirement(self.s, 'B', 'dataset_original')['files'] = requirement(self.s, 'A', 'dataset_original')['files']
        self.assertEqual('audit_response_digest_mismatch', self.row('B')['reason'])
        self.assertEqual('unresolved', self.row('B', 'dataset_original')['binding_status'])

    def test_raw_audit_tamper_including_whitespace_is_not_equivalent(self):
        name = requirement(self.s, 'A', 'audit_original')['files'][0]
        self.originals[name] += b'\n'
        self.assertEqual('audit_response_digest_mismatch', self.row()['reason'])
        self.assertEqual('unresolved', self.row(kind='dataset_original')['binding_status'])

    def test_wrong_dataset_cannot_change_audit_link_or_native_judgment(self):
        name = requirement(self.s, 'A', 'dataset_original')['files'][0]
        self.originals[name] = b'{}'
        self.assertEqual('bound', self.row()['binding_status'])
        self.assertEqual('audit_dataset_digest_mismatch', self.row(kind='dataset_original')['reason'])
        self.assertEqual(self.native, self.report()['native']['output'])

    def test_native_refusal_and_failure_do_not_attest_digest_links(self):
        for state in ('refused', 'evaluator_error'):
            self.native = None
            for kind in ('audit_original', 'dataset_original'):
                row = self.row(kind=kind, state=state)
                self.assertEqual('bound', row['binding_status'])
                self.assertEqual('unassessed', row['semantic_assessment'])
            self.assertEqual('partial', self.report(state)['overall_evidence_state'])

    def test_missing_or_ambiguous_native_execution_does_not_check_link(self):
        first = self.native['pilot']['executions'][0]
        for rows in ([], [first, first]):
            self.native['pilot']['executions'] = rows
            self.assertEqual('unassessed', self.row()['semantic_assessment'])
            self.assertEqual('unassessed', self.row(kind='dataset_original')['semantic_assessment'])

    def test_wrong_selected_log_blocks_linkage(self):
        self.s['log_identity']['head'] = '0' * 64
        self.assertEqual('unresolved', self.row()['binding_status'])

    def test_unknown_audit_type_is_unsupported(self):
        self.mutated_audit(b'{"type":"future-audit"}')
        row = self.row(state='evaluator_error')
        self.assertEqual('unsupported', row['binding_status'])
        self.assertEqual('unassessed', row['semantic_assessment'])

    def test_bad_json_and_shapes_are_explicitly_contradictory(self):
        for raw in (b'[]', b'{"type":1,"type":2}', b'{"amount":1.0}', b'NaN', b'\xff', b'{'):
            self.mutated_audit(raw)
            self.assertEqual('invalid_audit_shape', self.row(state='evaluator_error')['reason'])

    def test_audit_dataset_shape_and_bounds(self):
        for lines in (None, [], {}, [None], [{}], [{'dataset_sha256': 'A'*64}],
                      [{'dataset_sha256': 4}], [{'dataset_sha256': '1'*64}]*257):
            self.mutated_audit(encoded({'type': 'horizon-shield.estimate-audit.v0', 'lines': lines}))
            self.assertEqual('invalid_audit_shape', self.row(state='evaluator_error')['reason'])

    def test_integer_digit_limit_is_a_shape_finding_not_an_unhandled_error(self):
        self.mutated_audit(b'{"type":"horizon-shield.estimate-audit.v0","n":' + b'9'*5000 + b'}')
        row = self.row(state='evaluator_error')
        self.assertEqual('contradictory', row['binding_status'])
        self.assertEqual('invalid_audit_shape', row['reason'])
        self.assertEqual('unassessed', row['semantic_assessment'])

    def test_multiple_dataset_digests_stay_unsupported(self):
        self.mutated_audit(encoded({'type': 'horizon-shield.estimate-audit.v0',
                                   'lines': [{'dataset_sha256': c*64} for c in ('0','1')]}))
        self.assertEqual('multiple_dataset_digests_not_supported', self.row(state='evaluator_error')['reason'])

    def test_manifest_identity_and_count_bounds_unchanged(self):
        rows = copy.deepcopy(self.manifest['files'])
        rows[-1]['sha256'] = '0'*64
        with self.assertRaises(InputError): verified_files(SAMPLE/'originals', rows)
        with self.assertRaises(InputError): verified_files(SAMPLE/'originals', [{}]*97)


def integration(vate, environment, output, native_replay=True):
    """Real Inbox; native replay or an explicitly marked portable test double."""
    from run_audit_example import example
    from recover_output import recover
    result = example(vate, environment, output/'example', [])
    def execute(name, selection, database):
        selected = output/(name+'-selection.json'); selected.write_bytes(encoded(selection))
        return run(SimpleNamespace(originals=SAMPLE/'originals', manifest=SAMPLE/'audit-manifest.json',
                   selection=selected, source=SAMPLE/'evaluator-source', runtime=environment/'venv',
                   evaluator=environment/'evaluator.json', vate_root=vate, database=database,
                   output=output/name, view=None, previous=None))
    original = decode((SAMPLE/'audit-selection.json').read_bytes())
    swapped = copy.deepcopy(original)
    requirement(swapped, 'A', 'execution')['files'] = requirement(swapped, 'C', 'execution')['files']
    saved = execute('signed-swap', swapped, output/'swap.sqlite')
    r = decode((output/'signed-swap/assessment.json').read_bytes())
    assert saved['comparison']['exact_bytes'] and r['native']['output']['companion']['log']['verified']
    assert requirement(r, 'A', 'audit_original')['binding_status'] == 'unresolved'
    assert requirement(r, 'C', 'audit_original')['semantic_assessment'] == 'digest_linkage_checked'
    refused = copy.deepcopy(original); refused['trust']['min_depth'] = 1000000
    saved = execute('refusal', refused, output/'refusal.sqlite')
    r = decode((output/'refusal/assessment.json').read_bytes())
    assert saved['native_state'] == 'refused'
    assert r['native']['output']['companion']['log']['problem'] == 'anchor_too_shallow'
    assert all(row['semantic_assessment'] == 'unassessed' for row in r['requirements'])
    # Rebuild an additional-audit output after simulated export failure, without
    # replay or mutations to the retained database.
    _, Inbox = load_inbox(vate)
    database = output/'output-failure.sqlite'
    with patch.object(Inbox, 'export', side_effect=OSError('injected audit export fault')):
        try:
            execute('output-failure', original, database)
        except SavedOutputError as exc:
            receipt = exc.receipt
        else:
            raise AssertionError('export fault did not fire')
    before = sha(database.read_bytes())
    with patch('offline_native.replay', side_effect=AssertionError('replay during recovery')):
        recovered = recover(vate, database, receipt, output/'recovered')
    assert before == sha(database.read_bytes())
    assert recovered['comparison']['exact_bytes'] and recovered['assessment_ref'] == receipt['assessment_ref']
    for name in ('audit-A-C.json', 'souba-db.json'):
        assert (output/'recovered/materials/originals/supplementary'/name).read_bytes() == (SAMPLE/'originals/supplementary'/name).read_bytes()
    for name in ('example/baseline','example/audits','signed-swap','refusal','recovered'):
        folder = output/name/'export'
        for filename, desc in decode((folder/'MANIFEST.json').read_bytes())['files'].items():
            raw = (folder/filename).read_bytes()
            assert sha(raw) == desc['raw_sha256'] and len(raw) == desc['byte_length']
    result.update(status='pass', platform=platform.platform(), python=platform.python_version(),
                  real_native_replays=5 if native_replay else 0,
                  replay_mode='sandboxed_native' if native_replay else 'saved_output_test_double',
                  signed_swap_rejected=True, native_refusal_preserved=True,
                  recovery_without_replay_or_db_change=True, all_export_manifests_verified=True)
    (output/'VERIFICATION.json').write_bytes(encoded(result))
    print(encoded(result).decode(), end='')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vate-root', type=Path)
    parser.add_argument('--environment', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--portable', action='store_true', help='real storage with saved-output replay substitute')
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(AuditTests))
    if not result.wasSuccessful(): raise SystemExit(1)
    if args.output:
        if not args.vate_root or not args.environment: parser.error('native integration requires --vate-root and --environment')
        args.output.mkdir(parents=True, exist_ok=False)
        if args.portable:
            # This switch belongs only to the test harness. The example and
            # production replay retain their native-runtime verification gates.
            config = decode((args.environment/'evaluator.json').read_bytes())
            if not config.get('test_fixture'): parser.error('--portable requires an explicit test runtime fixture')
            def replay(source, runtime, evaluator, raw, out):
                bundle = decode(raw)
                if bundle['trust']['min_depth'] == 1000000:
                    payload = {'type': 'musubi.ca2a.pilot-settlement.v0', 'profile': 'musubi.ca2a.pilot.v0',
                               'companion': {'log': {'verified': False, 'problem': 'anchor_too_shallow'}}}
                    return ({'state': 'process_completed', 'exit_code': 2, 'regression_test_double': True},
                            encoded(payload), b'', {})
                selected = decode((SAMPLE/'selection.json').read_bytes())
                stdout = (SAMPLE/'originals'/selected['reference_output']['path']).read_bytes() + b'\n'
                return ({'state': 'process_completed', 'exit_code': 0, 'regression_test_double': True}, stdout, b'', {})
            with patch('offline_native.replay', side_effect=replay), patch('run_audit_example.check_environment'):
                integration(args.vate_root.resolve(), args.environment.resolve(), args.output.resolve(), False)
        else:
            integration(args.vate_root.resolve(), args.environment.resolve(), args.output.resolve())
