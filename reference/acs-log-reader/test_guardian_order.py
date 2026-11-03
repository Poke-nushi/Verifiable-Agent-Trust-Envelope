"""Guardian log order remains separate from clocks, action identity and decisions."""
from copy import deepcopy
import json
import unittest

import acs_reader as reader
from test_reader import HERE, inputs, jsonl, rows


class GuardianOrderTests(unittest.TestCase):
    def setUp(self):
        self.inputs = inputs()
        self.selection = (HERE / 'selection.example.json').read_bytes()

    def mutate(self, fn):
        data = rows(self.inputs['guardian_envelopes'])
        fn(data)
        self.inputs['guardian_envelopes'] = jsonl(data)

    def report(self):
        return reader.assess(self.inputs, self.selection)

    def main_hook(self, report=None):
        report = report if report is not None else self.report()
        return next(h for h in report['result_hook_observations']
                    if h['result_rpc_id'] == 'demo-result-main')

    def order(self):
        return self.main_hook()['order_vs_selected_request']

    def assert_unresolved(self, order):
        for name in ('file_order', 'sequence_order', 'recorded_time_order'):
            self.assertEqual(order[name]['status'], 'unresolved')
        self.assertFalse(order['same_action_proven'])

    def test_result_before_request_has_sequence_and_source_evidence(self):
        report = self.report()
        order = self.main_hook(report)['order_vs_selected_request']
        self.assertEqual((order['result_seq'], order['selected_request_seq']), (7, 9))
        self.assertEqual(order['file_order']['relation'], 'before')
        self.assertEqual(order['sequence_order']['status'], 'observed_sequence_order')
        self.assertEqual(order['sequence_order']['relation'], 'before')
        self.assertFalse(order['sequence_order']['clock_comparison_required'])
        self.assertEqual(order['recorded_time_order']['delta_microseconds'], -2950000)
        self.assertEqual(order['selected_request_source'], report['guardian_request']['records'][0]['source'])
        self.assertEqual(order['selected_request_source']['line'], 9)
        self.assertEqual(self.main_hook(report)['source']['line'], 7)
        self.assertEqual(order['scope'], 'supplied_guardian_log_only')

    def test_result_after_request_is_not_forced_into_before(self):
        def change(data):
            data[6:10] = data[8:10] + data[6:8]
            for seq, row in enumerate(data, 1):
                row['seq'] = seq
        self.mutate(change)
        order = self.order()
        self.assertEqual((order['result_seq'], order['selected_request_seq']), (9, 7))
        self.assertEqual(order['sequence_order']['relation'], 'after')
        self.assertEqual(order['file_order']['relation'], 'after')
        # The reordered capture's timestamps still say the opposite.
        self.assertEqual(order['recorded_time_order']['relation'], 'before')

    def test_equal_and_reversed_timestamps_do_not_change_sequence_order(self):
        for stamp, relation in (('2026-01-01T00:00:08.000Z', 'equal'),
                                ('2026-01-01T00:00:09.000Z', 'after')):
            with self.subTest(stamp=stamp):
                self.mutate(lambda data: data[6].update(recorded_at=stamp))
                order = self.order()
                self.assertEqual(order['sequence_order']['relation'], 'before')
                self.assertEqual(order['recorded_time_order']['relation'], relation)

    def test_sequence_gaps_zero_and_safe_integer_limit_are_supported(self):
        def change(data):
            for seq, row in enumerate(data):
                row['seq'] = seq * 2
            data[-1]['seq'] = reader.MAX_INTEGER
        self.mutate(change)
        order = self.order()
        self.assertEqual(order['sequence_order']['relation'], 'before')
        self.assertEqual((order['result_seq'], order['selected_request_seq']), (12, 16))

    def test_missing_sequence_keeps_file_and_time_order(self):
        for indexes in ((6,), (0,), tuple(range(10))):
            with self.subTest(indexes=indexes):
                self.inputs = inputs()
                def change(data):
                    for index in indexes:
                        data[index].pop('seq')
                self.mutate(change)
                order = self.order()
                self.assertEqual(order['sequence_order'], {
                    'status': 'unresolved', 'reason': 'MISSING_GUARDIAN_SEQUENCE'})
                self.assertEqual(order['file_order']['relation'], 'before')
                self.assertEqual(order['recorded_time_order']['delta_microseconds'], -2950000)

    def test_invalid_sequence_metadata_is_unresolved_without_echoing_values(self):
        for value in (None, True, False, -1, 7.0, 'private-seq-value', [], {'secret': 'private-seq-value'}):
            with self.subTest(value=value):
                self.inputs = inputs()
                self.mutate(lambda data: data[6].update(seq=value))
                report = self.report()
                order = self.main_hook(report)['order_vs_selected_request']
                self.assertEqual(order['sequence_order'], {
                    'status': 'unresolved', 'reason': 'INVALID_GUARDIAN_SEQUENCE'})
                self.assertIsNone(order['result_seq'])
                self.assertEqual(order['file_order']['relation'], 'before')
                self.assertNotIn(b'private-seq-value', reader.encode(report))

    def test_duplicate_and_reset_sequences_are_not_repaired(self):
        for index, value in ((7, 7), (8, 0), (0, 10)):
            with self.subTest(index=index, value=value):
                self.inputs = inputs()
                self.mutate(lambda data: data[index].update(seq=value))
                self.assertEqual(self.order()['sequence_order'], {
                    'status': 'unresolved', 'reason': 'NON_INCREASING_GUARDIAN_SEQUENCE'})

    def test_unknown_rows_participate_in_sequence_consistency(self):
        def change(data):
            data.insert(1, {'method': 'unknown/extension', 'seq': 1})
        self.mutate(change)
        self.assertEqual(self.order()['sequence_order']['reason'], 'NON_INCREASING_GUARDIAN_SEQUENCE')

    def test_reversed_file_is_not_sorted_to_restore_sequence(self):
        self.mutate(lambda data: data.reverse())
        order = self.order()
        self.assertEqual((order['result_seq'], order['selected_request_seq']), (7, 9))
        self.assertEqual(order['sequence_order']['status'], 'unresolved')
        self.assertEqual(order['file_order']['relation'], 'after')
        self.assertEqual(order['recorded_time_order']['relation'], 'before')

    def test_duplicate_selected_request_never_chooses_one(self):
        for other_session in (False, True):
            with self.subTest(other_session=other_session):
                self.inputs = inputs()
                def change(data):
                    other = deepcopy(data[8])
                    other['seq'] = 11
                    if other_session:
                        other['envelope']['params']['metadata']['session_id'] = 'other'
                    data.append(other)
                self.mutate(change)
                self.assert_unresolved(self.order())

    def test_cross_method_reuse_of_selected_request_is_unresolved(self):
        def change(data):
            other = deepcopy(data[6])
            rpc = data[8]['rpc_id']
            other['rpc_id'] = other['envelope']['id'] = other['envelope']['params']['request_id'] = rpc
            other['seq'] = 11
            data.append(other)
        self.mutate(change)
        self.assert_unresolved(self.order())

    def test_reused_result_id_is_unresolved_for_every_occurrence(self):
        for other_session in (False, True):
            with self.subTest(other_session=other_session):
                self.inputs = inputs()
                def change(data):
                    other = deepcopy(data[6])
                    other['seq'] = 11
                    if other_session:
                        other['envelope']['params']['metadata']['session_id'] = 'other'
                    data.append(other)
                self.mutate(change)
                hooks = [h for h in self.report()['result_hook_observations']
                         if h['result_rpc_id'] == 'demo-result-main']
                self.assertEqual(len(hooks), 1 if other_session else 2)
                for hook in hooks:
                    self.assert_unresolved(hook['order_vs_selected_request'])

    def test_unsupported_request_or_result_version_is_unresolved(self):
        for index in (6, 8):
            with self.subTest(index=index):
                self.inputs = inputs()
                self.mutate(lambda data: data[index]['envelope']['params'].update(acs_version='9.0'))
                self.assert_unresolved(self.order())

    def test_missing_request_and_wrong_selected_session_do_not_infer_a_match(self):
        selection = json.loads(self.selection)
        selection['request_id'] = 'not-observed'
        self.selection = reader.encode(selection)
        self.assert_unresolved(self.order())
        selection['acs_session_id'] = 'another-session'
        self.selection = reader.encode(selection)
        self.assertEqual(self.report()['result_hook_observations'], [])

    def test_log_order_does_not_require_a_decision_or_host_log(self):
        self.mutate(lambda data: data.pop())
        self.inputs['host_audit'] = self.inputs['host_events'] = self.inputs['proxy'] = None
        report = self.report()
        self.assertEqual(report['guardian_decision']['status'], 'not_observed')
        self.assertEqual(self.main_hook(report)['order_vs_selected_request']['sequence_order']['relation'], 'before')

    def test_every_same_session_result_remains_a_separate_observation(self):
        report = self.report()
        hooks = report['result_hook_observations']
        self.assertEqual([h['result_rpc_id'] for h in hooks], ['demo-result-first', 'demo-result-main'])
        for hook in hooks:
            order = hook['order_vs_selected_request']
            self.assertEqual(order['sequence_order']['relation'], 'before')
            self.assertFalse(order['same_action_proven'])
            self.assertEqual(hook['request_binding']['status'], 'unresolved')
            self.assertFalse(hook['response_is_permission_for_original_request'])
        self.assertEqual(report['bindings']['request_to_result']['status'], 'unresolved')
        self.assertEqual(report['bindings']['request_to_execution']['status'], 'unresolved')
        self.assertEqual(report['guardian_decision']['records'][0]['decision'], 'deny')
        self.assertEqual(report['host_effective_decision']['records'][0]['posture'], 'proceed')

    def test_extra_action_reference_never_establishes_binding(self):
        self.mutate(lambda data: data[6]['envelope']['params']['payload'].update(action_id='demo-request-main'))
        hook = self.main_hook()
        self.assertFalse(hook['order_vs_selected_request']['same_action_proven'])
        self.assertEqual(hook['request_binding']['status'], 'unresolved')


if __name__ == '__main__':
    unittest.main()
