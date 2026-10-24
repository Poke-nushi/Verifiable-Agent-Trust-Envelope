"""Receiver binding regressions using real foreign records and fixed native output.

These portable tests do not replay the native MUSUBI evaluator. Full native
replay is exercised separately by run_acceptance_example.py on macOS.
"""
from __future__ import annotations

import argparse
import base64
import copy
import importlib.util
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import acceptance_adapter as adapter
from acceptance_checks import evaluate
from receiving import InputError, assess, decode, encoded, sha, validate_selection, make_summary
from run_acceptance_example import ROOT, prepare_inputs

EVIDENCE = None


def row(selection, case, kind='acceptance'):
    return next(r for r in selection['requirements'] if r['id'] == 'hs51-musubi-2-' + case + ':' + kind)


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='vate-acceptance-binding-')
        output = Path(cls.temp.name)
        roots = []
        for n in (31, 32):
            vector = decode(next((EVIDENCE/'sources/war/vectors').glob(str(n)+'-*.json')).read_bytes())
            for root in vector['inputs']['tsa_roots_base64']:
                if root not in roots:
                    roots.append(root)
        cls.roots = [base64.b64decode(r, validate=True) for r in roots]
        (output/'roots.json').write_bytes(encoded(roots))
        cls.selection, cls.originals = prepare_inputs(EVIDENCE/'sources/acceptance', output/'roots.json', output/'intake')
        source = EVIDENCE/'sources/war/verifier/war_verify.py'
        raw = source.read_bytes()
        if sha(raw) != adapter.VERIFIER_SHA256:
            raise ValueError('test verifier pin mismatch')
        spec = importlib.util.spec_from_loader('test_war', loader=None)
        cls.war = importlib.util.module_from_spec(spec)
        exec(compile(raw, str(source), 'exec'), cls.war.__dict__)
        cls.verified = cls.verify_records(cls.selection, cls.originals)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def verify_records(cls, selection, originals):
        results = {}
        for case in ('A', 'B'):
            r = row(selection, case)
            expected = adapter.expectations(selection, originals, r)
            value = evaluate(originals[r['files'][0]], expected, cls.roots, cls.war)
            results[r['id']] = dict(value, expected=expected)
        return {'state': 'evaluated', 'profile': adapter.PROFILE, 'results': results}

    def setUp(self):
        self.s, self.o, self.v = copy.deepcopy(self.selection), dict(self.originals), copy.deepcopy(self.verified)
        self.bundle = decode(self.o[self.s['bundle']['path']])
        self.native = decode(self.o[self.s['reference_output']['path']])

    def report(self, state='evaluated'):
        validate_selection(self.s, self.o)
        return assess(self.s, self.o, self.bundle, self.native, {'state': state}, self.v)

    def test_valid_pass_and_fail_remain_distinct_from_native_acceptance(self):
        result = self.report()
        for case, verdict in (('A', 'pass'), ('B', 'fail')):
            r = row(result, case)
            self.assertEqual(('bound', 'foreign_acceptance_verified', verdict),
                             (r['binding_status'], r['semantic_assessment'], r['work_verdict']))
        self.assertEqual('partial', result['overall_evidence_state'])
        self.assertTrue(all(x['accepted'] is None for x in result['native']['output']['pilot']['executions']))
        self.assertEqual('not_received', row(result, 'B', 'audit_original')['binding_status'])
        self.assertEqual('not_selected', row(result, 'C')['binding_status'])

    def test_no_profile_preserves_unsupported_behavior(self):
        del self.s['acceptance_binding_profile']
        self.assertEqual('unsupported', row(self.report(), 'A')['binding_status'])

    def test_profile_and_verifier_are_receiver_selected(self):
        self.s['acceptance_binding_profile'] += '-other'
        with self.assertRaises(InputError): self.report()
        self.s = copy.deepcopy(self.selection)
        self.s['acceptance_verification']['verifier_sha256'] = '0'*64
        with self.assertRaises(InputError): self.report()

    def test_unreceived_ambiguous_and_optional_records_are_not_promoted(self):
        for files, required, expected in (([], True, 'not_received'),
                                         (row(self.s, 'A')['files']*2, True, 'ambiguous'),
                                         (row(self.s, 'A')['files'], False, 'not_selected')):
            with self.subTest(expected=expected):
                row(self.s, 'A').update(files=files, required=required)
                r = row(self.report(), 'A')
                self.assertEqual(expected, r['binding_status'])
                self.assertEqual('unassessed', r['semantic_assessment'])

    def test_prerequisites_cannot_point_to_another_occurrence_or_kind(self):
        for field in ('execution_requirement', 'criteria_requirement'):
            for value in (None, [], 'missing', 'hs51-musubi-2-B:execution', 'hs51-musubi-2-A:payment'):
                self.s = copy.deepcopy(self.selection)
                row(self.s, 'A')[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(InputError): self.report()

    def test_prerequisites_must_be_required(self):
        for kind in ('execution', 'criteria'):
            self.s = copy.deepcopy(self.selection)
            row(self.s, 'A', kind)['required'] = False
            with self.assertRaises(InputError): self.report()

    def test_native_refusal_or_failure_cannot_promote_foreign_binding(self):
        for state in ('refused', 'evaluator_error'):
            r = row(self.report(state), 'A')
            self.assertEqual('unresolved', r['binding_status'])
            self.assertNotIn('work_verdict', r)

    def test_missing_native_parent_row_cannot_promote_foreign_binding(self):
        self.native['pilot']['criteria_commitments'] = []
        self.assertEqual('unresolved', row(self.report(), 'A')['binding_status'])

    def test_wrong_log_or_replaced_execution_cannot_promote_foreign_binding(self):
        self.s['log_identity']['head'] = '0'*64
        self.assertEqual('unresolved', row(self.report(), 'A')['binding_status'])
        self.s = copy.deepcopy(self.selection)
        row(self.s, 'A', 'execution')['files'] = row(self.s, 'B', 'execution')['files']
        self.assertEqual('unresolved', row(self.report(), 'A')['binding_status'])

    def test_foreign_verification_must_match_exact_original_and_expectations(self):
        for mutation in ('raw', 'expected', 'missing', 'malformed'):
            self.v = copy.deepcopy(self.verified)
            item = self.v['results']['hs51-musubi-2-A:acceptance']
            if mutation == 'raw': item['raw_sha256'] = '0'*64
            elif mutation == 'expected': item['expected']['request_sha256'] = '0'*64
            elif mutation == 'missing': del self.v['results']['hs51-musubi-2-A:acceptance']
            else: self.v['results']['hs51-musubi-2-A:acceptance'] = []
            with self.subTest(mutation=mutation):
                self.assertEqual('unresolved', row(self.report(), 'A')['binding_status'])

    def test_fresh_verification_rejects_same_audit_APS_and_A_for_B(self):
        for target, replacement in (('A', 'foreign-acceptance/hs51-aps-A.json'),
                                    ('B', 'foreign-acceptance/hs51-musubi-2-A.json')):
            self.s = copy.deepcopy(self.selection)
            row(self.s, target)['files'] = [replacement]
            self.v = self.verify_records(self.s, self.o)
            self.assertEqual('contradictory', row(self.report(), target)['binding_status'])

    def test_status_separation(self):
        for status, expected in (('unsupported', 'unsupported'), ('unavailable', 'unresolved'), ('rejected', 'contradictory')):
            self.v['results']['hs51-musubi-2-A:acceptance']['status'] = status
            self.assertEqual(expected, row(self.report(), 'A')['binding_status'])

    def test_failed_or_other_profile_worker_does_not_attach_results(self):
        for field, value in (('state', 'evaluator_error'), ('profile', 'unknown')):
            self.v = copy.deepcopy(self.verified)
            self.v[field] = value
            self.assertEqual('unresolved', row(self.report(), 'A')['binding_status'])

    def test_missing_root_is_unavailable_not_verified(self):
        self.s['acceptance_verification']['tsa_roots'] = []
        for case in ('A', 'B'):
            r = row(self.s, case)
            expected = adapter.expectations(self.s, self.o, r)
            self.v['results'][r['id']] = dict(evaluate(self.o[r['files'][0]], expected, [], self.war), expected=expected)
        self.assertEqual('unresolved', row(self.report(), 'A')['binding_status'])

    def test_root_raw_hash_and_duplicate_selection_are_checked(self):
        ref = self.s['acceptance_verification']['tsa_roots'][0]
        self.o[ref['path']] += b'\n'
        with self.assertRaises(InputError): self.report()
        self.o = dict(self.originals)
        self.s['acceptance_verification']['tsa_roots'].append(ref)
        with self.assertRaises(InputError): self.report()

    def test_requirement_order_cannot_choose_dependency_order(self):
        first = self.report()
        self.s['requirements'].reverse()
        self.assertEqual({r['id']: r for r in first['requirements']},
                         {r['id']: r for r in self.report()['requirements']})

    def test_external_source_required_and_hash_checked_before_execution(self):
        with self.assertRaises(InputError): adapter.prepare(self.s, self.o, None)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'war_verify.py'
            p.write_text('raise RuntimeError("not executed")\n')
            with self.assertRaises(InputError): adapter.prepare(self.s, self.o, p)

    def test_worker_aggregates_internal_failure_and_recovery_keeps_error_exit(self):
        import acceptance_worker
        import recover_output
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            source = EVIDENCE/'sources/war/verifier/war_verify.py'
            (folder/'war_verify.py').write_bytes(source.read_bytes())
            job = adapter.prepare(self.s, self.o, source)
            (folder/'input.json').write_bytes(encoded(job['input']))
            output = io.StringIO()
            with patch.object(acceptance_worker, '__file__', str(folder/'acceptance_worker.py')), \
                 patch.object(acceptance_worker, 'evaluate', return_value={
                     'status': 'unavailable', 'reason_codes': ['evaluator_failed'], 'work_verdict': None}), \
                 patch.object(sys, 'argv', ['acceptance_worker.py', str(folder/'input.json')]), \
                 contextlib.redirect_stdout(output):
                acceptance_worker.main()
            self.v = decode(output.getvalue().encode())
            self.assertEqual('evaluator_error', self.v['state'])
            assessment = self.report()
            assessment['comparison'] = {'test': 'worker_failure_aggregation'}
            summary = make_summary(assessment, {})
            self.assertEqual('recorded_evaluator_error', summary['status'])
            for case in ('A', 'B'):
                self.assertEqual('unresolved', row(assessment, case)['binding_status'])
            receipt = folder/'receipt.json'
            receipt.write_bytes(encoded({}))
            # Exercise the recovery CLI's exit contract after the stored result
            # has been reconstructed; database recovery has separate real tests.
            summary.update(recovery={}, inbox={'run_id': 'failure-test'})
            recovery_output = io.StringIO()
            with patch.object(recover_output, 'recover', return_value=summary) as recover_call, \
                 patch.object(recover_output, 'receipt_from', return_value={'run_id': 'failure-test'}), \
                 patch.object(sys, 'argv', ['recover_output.py', '--vate-root', str(ROOT),
                    '--database', str(folder/'db.sqlite'), '--receipt', str(receipt), '--output', str(folder/'out')]), \
                 contextlib.redirect_stdout(recovery_output):
                self.assertEqual(64, recover_output.main())
            recover_call.assert_called_once()
            emitted = decode(recovery_output.getvalue().encode())
            self.assertEqual(('output_recovered', 'recorded_evaluator_error'),
                             (emitted['status'], emitted['saved_status']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-root', type=Path, required=True)
    args = parser.parse_args()
    EVIDENCE = args.evidence_root.resolve()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(IntegrationTests))
    print(encoded({'status': 'pass' if result.wasSuccessful() else 'fail', 'tests': result.testsRun,
                   'native_replay': 'saved_output_test_double'}).decode(), end='')
    raise SystemExit(0 if result.wasSuccessful() else 1)
