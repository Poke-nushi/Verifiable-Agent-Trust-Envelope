"""Self-authored synthetic captures + mutations; no host or Guardian execution."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import acs_reader as reader

HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE / 'SAMPLE-PINS.json').read_bytes())


def inputs():
    result = {}
    for name, pin in PINS.items():
        raw = (HERE / pin['path']).read_bytes()
        if hashlib.sha256(raw).hexdigest() != pin['raw_sha256']:
            raise AssertionError('synthetic sample identity changed')
        result[name] = raw
    return result


def rows(value):
    return [json.loads(line) for line in value.splitlines()]


def jsonl(value):
    return b'\n'.join(reader.encode(row) for row in value) + b'\n'


class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.inputs = inputs()
        self.selection = (HERE / 'selection.example.json').read_bytes()

    def run_reader(self):
        return reader.assess(self.inputs, self.selection)

    def mutate(self, source, fn):
        data = rows(self.inputs[source]); fn(data); self.inputs[source] = jsonl(data)

    def assert_error(self, code):
        with self.assertRaises(reader.InputError) as raised:
            self.run_reader()
        self.assertEqual(raised.exception.code, code)

    def test_retained_source_observations(self):
        r = self.run_reader()
        self.assertEqual(r['host_effective_decision']['records'][0]['outcome'], 'proceeded')
        self.assertEqual(r['guardian_decision']['records'][0]['decision'], 'deny')
        self.assertEqual(r['bindings']['host_and_guardian_request']['status'], 'matched_by_rpc_id')
        self.assertFalse(r['bindings']['host_and_guardian_request']['authenticated'])
        self.assertEqual(r['bindings']['fallback_and_handshake']['status'], 'matched_by_value')
        self.assertEqual(r['negotiated_fallback']['records'][0]['default_timeout_ms'], 5000)
        self.assertEqual(r['timing']['guardian_response_vs_host_fallback_log']['delta_microseconds'], 3132000)

    def test_result_allow_not_request_allow(self):
        r = self.run_reader()
        self.assertEqual([h['responses']['records'][0]['decision'] for h in r['result_hook_observations']], ['allow', 'allow'])
        self.assertEqual(r['guardian_decision']['records'][0]['decision'], 'deny')
        self.assertTrue(all(not h['response_is_permission_for_original_request'] for h in r['result_hook_observations']))

    def test_matching_command_is_candidate_only(self):
        r = self.run_reader()
        matching = [e for e in r['execution_observations'] if e['command_text_matches_selected_request']]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]['reported_status'], 'completed')
        self.assertTrue(matching[0]['candidate_only'])
        self.assertEqual(matching[0]['request_binding'], 'unresolved')
        self.assertIsNone(matching[0]['actual_dispatch_at'])
        self.assertIsNone(r['timing']['decision_committed_at'])
        self.assertIsNone(r['timing']['dispatch_at'])
        self.assertEqual(r['timing']['host_received_late_decision'], 'unknown')

    def test_no_sensitive_command_or_output_echo(self):
        report = reader.encode(self.run_reader())
        self.assertNotIn(b'printf DEMO_FIRST', report)
        self.assertNotIn(b'printf DEMO_MAIN', report)
        self.assertNotIn(b'demo-output-body', report)

    def test_original_inputs_not_mutated_and_output_deterministic(self):
        before = deepcopy(self.inputs)
        first, second = reader.encode(self.run_reader()), reader.encode(self.run_reader())
        self.assertEqual(first, second)
        self.assertEqual(self.inputs, before)
        self.assertEqual(json.loads(first), json.loads((HERE / 'example-report.json').read_bytes()))

    def test_absent_each_source_and_all_sources(self):
        for source in reader.SOURCES:
            with self.subTest(source=source):
                original = self.inputs[source]; self.inputs[source] = None
                r = self.run_reader(); self.assertEqual(r['sources'][source], {'state': 'absent'})
                self.assertEqual(r['bindings']['request_to_execution']['status'], 'unresolved')
                self.inputs[source] = original
        self.inputs = dict.fromkeys(reader.SOURCES)
        r = self.run_reader()
        self.assertEqual(r['host_effective_decision']['status'], 'unavailable')
        self.assertEqual(r['guardian_decision']['status'], 'unavailable')

    def test_unmatched_id_is_not_missing_input(self):
        selection = json.loads(self.selection); selection['request_id'] = 'other'
        self.selection = reader.encode(selection); r = self.run_reader()
        self.assertEqual(r['host_effective_decision']['status'], 'not_observed')
        self.assertEqual(r['sources']['host_audit']['state'], 'present')

    def test_partial_then_full_does_not_rewrite_prior_report(self):
        full = deepcopy(self.inputs)
        self.inputs['guardian_envelopes'] = self.inputs['proxy'] = None
        before = reader.encode(self.run_reader()); self.inputs = full
        after = reader.encode(self.run_reader())
        self.assertEqual(json.loads(before)['guardian_decision']['status'], 'unavailable')
        self.assertEqual(json.loads(after)['guardian_decision']['records'][0]['decision'], 'deny')
        self.assertEqual(json.loads(before)['host_effective_decision'], json.loads(after)['host_effective_decision'])

    def test_duplicate_host_is_ambiguous(self):
        self.inputs['host_audit'] *= 2
        r = self.run_reader()
        self.assertEqual(r['host_effective_decision']['status'], 'ambiguous')
        self.assertEqual(r['bindings']['host_and_guardian_request']['status'], 'unresolved')
        self.assertEqual(r['timing']['guardian_response_vs_host_fallback_log']['status'], 'unresolved')

    def test_conflicting_guardian_decisions_both_retained(self):
        def change(data):
            other = deepcopy(data[-1]); other['envelope']['result']['decision'] = 'allow'; data.append(other)
        self.mutate('guardian_envelopes', change); r = self.run_reader()
        self.assertEqual(r['guardian_decision']['status'], 'ambiguous')
        self.assertEqual([x['decision'] for x in r['guardian_decision']['records']], ['deny', 'allow'])
        self.assertEqual(r['bindings']['host_and_guardian_request']['status'], 'unresolved')

    def test_duplicate_guardian_request_and_cross_session(self):
        for cross_session in (False, True):
            self.inputs = inputs()
            def change(data):
                other = deepcopy(data[-2])
                if cross_session:
                    other['envelope']['params']['metadata']['session_id'] = 'different'
                data.append(other)
            self.mutate('guardian_envelopes', change); r = self.run_reader()
            self.assertEqual(r['guardian_request']['status'], 'ambiguous')
            self.assertEqual(r['bindings']['host_and_guardian_request']['status'], 'unresolved')

    def test_cross_method_rpc_reuse_unresolved(self):
        def change(data):
            other = deepcopy(data[6]); rpc = data[8]['rpc_id']
            other['rpc_id'] = other['envelope']['id'] = other['envelope']['params']['request_id'] = rpc
            data.append(other)
        self.mutate('guardian_envelopes', change)
        self.assertEqual(self.run_reader()['bindings']['host_and_guardian_request']['status'], 'unresolved')

    def test_wrong_selected_sessions_never_bind(self):
        for field in ('host_session_id', 'acs_session_id'):
            selection = json.loads((HERE/'selection.example.json').read_bytes()); selection[field] = 'other'
            self.selection = reader.encode(selection)
            self.assertEqual(self.run_reader()['bindings']['host_and_guardian_request']['status'], 'unresolved')

    def test_inconsistent_request_and_response_ids(self):
        for index, kind in ((8, 'params'), (9, 'result')):
            self.inputs = inputs()
            self.mutate('guardian_envelopes', lambda data: data[index]['envelope'][kind].update(request_id='other'))
            self.assert_error('INCONSISTENT_RPC_ID')

    def test_inconsistent_rpc_method(self):
        self.mutate('guardian_envelopes', lambda data: data[8]['envelope'].update(method='different'))
        self.assert_error('INCONSISTENT_RPC_METHOD')

    def test_result_and_hello_inner_outer_method_mismatch_is_not_absence(self):
        for index in (0, 6):
            for changed in ('outer', 'inner'):
                self.inputs = inputs()
                def change(data):
                    if changed == 'outer':
                        data[index]['method'] = 'unrelated/method'
                    else:
                        data[index]['envelope']['method'] = 'unrelated/method'
                self.mutate('guardian_envelopes', change)
                self.assert_error('INCONSISTENT_RPC_METHOD')

    def test_missing_command_means_unassessable_not_mismatch(self):
        for where in ('guardian', 'host'):
            self.inputs = inputs()
            if where == 'guardian':
                self.mutate('guardian_envelopes', lambda data: data[8]['envelope']['params']['payload'].pop('raw_command'))
            else:
                self.mutate('host_events', lambda data: data[4]['part']['state']['input'].pop('command'))
            r = self.run_reader()
            selected = next(e for e in r['execution_observations'] if e['host_call_id'] == 'demo-call-main')
            self.assertIsNone(selected['command_text_matches_selected_request'])
            self.assertEqual(selected['request_binding'], 'unresolved')

    def test_corrupt_direction_cannot_hide_known_envelopes(self):
        for index in (0, 1, 2, 3, 6, 7, 8, 9):
            for direction in ('typo', None, 'response' if index % 2 == 0 else 'request'):
                with self.subTest(index=index, direction=direction):
                    self.inputs = inputs()
                    def change(data):
                        other = deepcopy(data[index]); other['direction'] = direction
                        data.append(other)
                    self.mutate('guardian_envelopes', change)
                    with self.assertRaises(reader.InputError) as raised:
                        self.run_reader()
                    self.assertIn(raised.exception.code, ('INVALID_DIRECTION', 'INVALID_RESPONSE', 'INCONSISTENT_RPC_METHOD'))
                    self.assertEqual(raised.exception.line, 11)

    def test_inner_id_collision_in_other_known_rpc_is_invalid(self):
        for target_index in (0, 6, 8):
            self.inputs = inputs()
            self.mutate('guardian_envelopes', lambda data: data[2]['envelope']['params'].update(request_id=data[target_index]['rpc_id']))
            with self.assertRaises(reader.InputError) as raised:
                self.run_reader()
            self.assertEqual(raised.exception.code, 'INCONSISTENT_RPC_ID')
            self.assertEqual(raised.exception.line, 3)

    def test_unknown_inner_id_does_not_count_as_rpc_reuse(self):
        for target_index in (0, 6, 8):
            self.inputs = inputs()
            def change(data):
                other = deepcopy(data[2])
                other['method'] = other['envelope']['method'] = 'unknown/extension'
                other['envelope']['params']['request_id'] = data[target_index]['rpc_id']
                data.append(other)
            self.mutate('guardian_envelopes', change)
            report = self.run_reader()
            self.assertEqual(report['bindings']['host_and_guardian_request']['status'], 'matched_by_rpc_id')
            self.assertEqual(report['bindings']['fallback_and_handshake']['status'], 'matched_by_value')
            self.assertTrue(all(h['response_association']['requests_with_same_rpc_id'] == 1 for h in report['result_hook_observations']))

    def test_unknown_outer_rpc_reuse_still_prevents_pairing(self):
        for target_index in (0, 6, 8):
            self.inputs = inputs()
            def change(data):
                other = deepcopy(data[2]); rpc = data[target_index]['rpc_id']
                other['method'] = other['envelope']['method'] = 'unknown/extension'
                other['rpc_id'] = other['envelope']['id'] = other['envelope']['params']['request_id'] = rpc
                data.append(other)
            self.mutate('guardian_envelopes', change)
            report = self.run_reader()
            if target_index == 0:
                self.assertEqual(report['bindings']['fallback_and_handshake']['status'], 'not_assessed')
            elif target_index == 8:
                self.assertEqual(report['bindings']['host_and_guardian_request']['status'], 'unresolved')
            else:
                hook = next(h for h in report['result_hook_observations'] if h['result_rpc_id'] == rows(self.inputs['guardian_envelopes'])[6]['rpc_id'])
                self.assertEqual(hook['responses']['status'], 'ambiguous')
                self.assertEqual(hook['response_association']['requests_with_same_rpc_id'], 2)

    def test_hello_request_without_response_is_retained(self):
        self.inputs['guardian_envelopes'] = jsonl(rows(self.inputs['guardian_envelopes'])[:1])
        r = self.run_reader()
        self.assertEqual(r['negotiated_fallback']['status'], 'not_observed')
        self.assertEqual(len(r['hello_request_observations']), 1)
        self.assertEqual(r['hello_request_observations'][0]['response_observation'], 'not_observed')

    def test_inconsistent_host_event_type(self):
        self.mutate('host_events', lambda data: data[4]['part'].update(type='text'))
        self.assert_error('INCONSISTENT_HOST_EVENT_TYPE')

    def test_unknown_version_or_nonfinal_not_promoted(self):
        for change in ({'acs_version': '9.0'}, {'type': 'progress'}, {'decision': 'ask'}):
            self.inputs = inputs()
            self.mutate('guardian_envelopes', lambda data: data[9]['envelope']['result'].update(change))
            r = self.run_reader()
            self.assertEqual(r['guardian_decision']['status'], 'not_assessed')
            self.assertEqual(r['bindings']['host_and_guardian_request']['status'], 'unresolved')

    def test_rpc_error_is_not_a_decision(self):
        def change(data):
            env = data[9]['envelope']; del env['result']; env['error'] = {'code': -32603}
        self.mutate('guardian_envelopes', change)
        self.assertEqual(self.run_reader()['guardian_decision']['status'], 'not_assessed')

    def test_posture_mismatch_observed_without_permission(self):
        self.mutate('guardian_envelopes', lambda data: data[1]['envelope']['result'].update(on_decision_failure='deny'))
        r = self.run_reader()
        self.assertEqual(r['bindings']['fallback_and_handshake']['status'], 'mismatched')
        self.assertIn('execution_permission', r['not_assessed'])

    def test_handshake_timeout_overrides_not_silently_ignored(self):
        self.mutate('guardian_envelopes', lambda data: data[1]['envelope']['result']['timeout_config'].update(per_method={'steps/toolCallRequest': 1}))
        r = self.run_reader()
        self.assertEqual(r['negotiated_fallback']['status'], 'not_assessed')
        self.assertIsNone(r['negotiated_fallback']['records'][0]['default_timeout_ms'])

    def test_duplicate_or_reused_hello_does_not_confirm_fallback(self):
        self.mutate('guardian_envelopes', lambda data: data.append(deepcopy(data[0])))
        self.assertEqual(self.run_reader()['bindings']['fallback_and_handshake']['status'], 'not_assessed')

    def test_hello_unknown_request_id_cannot_select_other_response(self):
        def change(data):
            data[1]['rpc_id'] = data[1]['envelope']['id'] = 'other-hello'
            data[1]['envelope']['result']['request_id'] = data[0]['rpc_id']
        self.mutate('guardian_envelopes', change)
        r = self.run_reader()
        self.assertEqual(r['negotiated_fallback']['status'], 'not_observed')
        self.assertEqual(r['bindings']['fallback_and_handshake']['status'], 'not_assessed')

    def test_result_rpc_collision_same_or_other_session_is_ambiguous(self):
        for other_session in (False, True):
            self.inputs = inputs()
            def change(data):
                repeated = deepcopy(data[6])
                if other_session:
                    repeated['envelope']['params']['metadata']['session_id'] = 'different'
                data.append(repeated)
            self.mutate('guardian_envelopes', change)
            r = self.run_reader()
            hooks = [h for h in r['result_hook_observations'] if h['result_rpc_id'] == 'demo-result-main']
            self.assertTrue(hooks)
            for hook in hooks:
                self.assertEqual(hook['responses']['status'], 'ambiguous')
                self.assertEqual(hook['response_association']['status'], 'unresolved')
                self.assertEqual(hook['response_association']['requests_with_same_rpc_id'], 2)

    def test_boolean_timestamp_and_exit_rejected(self):
        self.mutate('host_events', lambda data: data[4]['part']['state']['time'].update(end=True))
        self.assert_error('INVALID_EPOCH_MS')
        self.inputs = inputs()
        self.mutate('host_events', lambda data: data[4]['part']['state']['metadata'].update(exit=False))
        self.assert_error('INVALID_EXIT_CODE')

    def test_invalid_and_reversed_times(self):
        self.mutate('host_audit', lambda data: data[0].update(recorded_at='2026-02-30T00:00:00Z'))
        self.assert_error('INVALID_TIMESTAMP')
        self.inputs = inputs()
        self.mutate('host_events', lambda data: data[4]['part']['state']['time'].update(end=0))
        self.assert_error('REVERSED_TOOL_INTERVAL')

    def test_guardian_before_host_is_only_reported_clock_order(self):
        self.mutate('guardian_envelopes', lambda data: data[9].update(recorded_at='2025-12-31T23:59:59Z'))
        r = self.run_reader(); comparison = r['timing']['guardian_response_vs_host_fallback_log']
        self.assertEqual(comparison['relation'], 'before')
        self.assertFalse(comparison['host_arrival_or_dispatch_order_proven'])

    def test_line_order_does_not_choose_last_decision(self):
        self.mutate('guardian_envelopes', lambda data: data.reverse())
        r = self.run_reader()
        self.assertEqual(r['guardian_decision']['records'][0]['decision'], 'deny')
        self.assertEqual(r['timing']['guardian_response_vs_host_fallback_log']['delta_microseconds'], 3132000)

    def test_unknown_proof_fields_do_not_authenticate(self):
        self.mutate('host_audit', lambda data: data[0].update(signature='pretend', authority=True))
        r = self.run_reader()
        self.assertFalse(r['bindings']['host_and_guardian_request']['authenticated'])
        self.assertIn('signature', r['not_assessed'])

    def test_empty_null_document_wrong_bytes_and_bom(self):
        for raw in (b'', b'null\n', bytearray(b'{}'), b'\xef\xbb\xbf{}\n', b'\xff'):
            self.inputs['proxy'] = raw
            with self.assertRaises(reader.InputError):
                self.run_reader()

    def test_duplicate_names_and_nonfinite_numbers(self):
        for raw, code in ((b'{"a":1,"a":2}', 'DUPLICATE_JSON_KEY'),
                          (b'{"a":NaN}', 'NONFINITE_NUMBER'), (b'{"a":1e1000}', 'NUMBER_OUT_OF_RANGE'),
                          (b'{"a":9007199254740992}', 'NUMBER_OUT_OF_RANGE')):
            self.inputs['proxy'] = raw; self.assert_error(code)

    def test_decimal_bounds_are_exact_and_context_independent(self):
        from decimal import localcontext
        for precision in (4, 28, 60):
            with localcontext() as context:
                context.prec = precision
                for token in ('1e1000000', '-1e1000000', '9007199254740991.0000000000000000001', '-9007199254740991.0000000000000000001'):
                    self.inputs['proxy'] = ('{"ignored":'+token+'}').encode()
                    self.assert_error('NUMBER_OUT_OF_RANGE')
                self.inputs['proxy'] = b'{"ignored":9007199254740991.0}'
                self.run_reader()

    def test_crlf_supported_but_blank_lines_rejected(self):
        self.inputs['proxy'] = self.inputs['proxy'].replace(b'\n', b'\r\n')
        self.run_reader()
        self.inputs['proxy'] += b'\n'
        self.assert_error('INVALID_LINE_SIZE')

    def test_line_row_depth_and_byte_bounds(self):
        cases = [(b'{}\n'*(reader.MAX_ROWS+1), 'ROW_LIMIT'),
                 (b'{"x":"'+b'x'*reader.MAX_LINE+b'"}', 'INVALID_LINE_SIZE'),
                 (b'x'*(reader.MAX_BYTES+1), 'INVALID_BYTES_OR_SIZE'),
                 (b'{"x":'+b'['*40+b'0'+b']'*40+b'}', 'JSON_DEPTH')]
        for raw, code in cases:
            self.inputs['proxy'] = raw; self.assert_error(code)

    def test_selection_and_input_set_closed(self):
        self.inputs['extra'] = None; self.assert_error('INVALID_INPUT_SET'); self.inputs = inputs()
        value = json.loads(self.selection); value['extra'] = True; self.selection = reader.encode(value)
        self.assert_error('INVALID_SELECTION')

    def test_many_to_many_rpc_reuse_is_bounded(self):
        data = rows(self.inputs['guardian_envelopes'])
        self.inputs['guardian_envelopes'] = jsonl([data[6]] * 33 + [data[7]] * 33)
        self.assert_error('RELATION_LIMIT')

    def test_cli_parity_absence_and_errors(self):
        command = [sys.executable, '-B', str(HERE/'acs_reader.py'), '--selection', str(HERE/'selection.example.json')]
        for name, pin in PINS.items():
            command += ['--'+name.replace('_', '-'), str(HERE/pin['path'])]
        run = subprocess.run(command, capture_output=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout), self.run_reader())
        run = subprocess.run([sys.executable, '-B', str(HERE/'acs_reader.py'), '--unexpected-private-path'], capture_output=True)
        self.assertEqual(run.returncode, 64)
        self.assertNotIn(b'unexpected-private-path', run.stdout+run.stderr)
        with tempfile.TemporaryDirectory() as temp:
            link = Path(temp)/'link'; link.symlink_to(HERE/'selection.example.json')
            with self.assertRaises(reader.InputError):
                reader.read_file(link, 'selection')
            with self.assertRaises(reader.InputError):
                reader.read_file(temp, 'selection')

    def test_cli_empty_source_path_is_not_absence(self):
        for source in reader.SOURCES:
            command = [sys.executable, '-B', str(HERE/'acs_reader.py'), '--selection', str(HERE/'selection.example.json')]
            for name in reader.SOURCES:
                command += ['--'+name.replace('_', '-'), ''] if name == source else ['--'+name.replace('_', '-')+'-absent']
            run = subprocess.run(command, capture_output=True)
            self.assertEqual(run.returncode, 64)
            self.assertEqual(json.loads(run.stdout)['reason'], 'FILE_UNAVAILABLE')
            self.assertEqual(json.loads(run.stdout)['input'], source)


class ExampleInputTests(unittest.TestCase):
    def test_missing_inbox_tree_does_not_consume_output_path(self):
        import run_example
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            out = folder/'out'
            with self.assertRaisesRegex(ValueError, 'whole VATE source tree'):
                run_example.run(out, source_root=folder/'missing-tree')
            self.assertFalse(out.exists())

    def test_bad_source_is_bounded_before_output_creation(self):
        import os
        from unittest.mock import patch
        import run_example
        for kind in ('oversize', 'symlink', 'fifo', 'hash_mismatch', 'selection_empty'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                folder = Path(temp)
                source = inputs()
                pinfile = {name: {'path': name, 'raw_sha256': reader.digest(raw)} for name, raw in source.items()}
                for name, raw in source.items():
                    (folder/name).write_bytes(raw)
                (folder/'SAMPLE-PINS.json').write_bytes(reader.encode(pinfile))
                (folder/'selection.example.json').write_bytes((HERE/'selection.example.json').read_bytes())
                first = folder/'host_audit'
                if kind == 'oversize':
                    first.write_bytes(b'x' * (reader.MAX_BYTES + 1))
                elif kind in ('symlink', 'fifo'):
                    first.unlink()
                    if kind == 'symlink':
                        first.symlink_to(folder/'host_events')
                    else:
                        os.mkfifo(first)
                elif kind == 'hash_mismatch':
                    first.write_bytes(b'{}\n')
                else:
                    (folder/'selection.example.json').write_bytes(b'')
                out = folder/'out'
                with patch.object(run_example, 'HERE', folder):
                    with self.assertRaises((reader.InputError, ValueError)):
                        run_example.run(out)
                self.assertFalse(out.exists())

    def test_pin_mismatch_stops_before_reading_later_sources(self):
        from unittest.mock import patch
        import run_example
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            pins = {name: {'path': name, 'raw_sha256': '0'*64} for name in reader.SOURCES}
            (folder/'SAMPLE-PINS.json').write_bytes(reader.encode(pins))
            first = next(iter(json.loads((folder/'SAMPLE-PINS.json').read_bytes())))
            (folder/first).write_bytes(b'{}\n')
            with patch.object(run_example, 'HERE', folder), \
                 patch.object(run_example, 'read_file', wraps=reader.read_file) as reads:
                with self.assertRaisesRegex(ValueError, 'identity changed'):
                    run_example.run(folder/'out')
                self.assertEqual(len(reads.call_args_list), 2)
            self.assertFalse((folder/'out').exists())


if __name__ == '__main__':
    unittest.main()
