"""Optional command self-timestamps: precision, provenance and unbound observations."""
from copy import deepcopy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import acs_reader as reader
from test_reader import HERE, PINS, inputs, jsonl, rows


class CommandTimestampTests(unittest.TestCase):
    def setUp(self):
        self.inputs = inputs()
        self.selection = (HERE / 'selection.example.json').read_bytes()
        self.stamps = {name: (HERE / 'fixtures/synthetic' / (name.replace('_', '-') + '.txt')).read_bytes()
                       for name in reader.COMMAND_TIMESTAMP_SOURCES}

    def assess(self):
        return reader.assess(self.inputs, self.selection, command_timestamps=self.stamps)

    def comparisons(self):
        return self.assess()['timing']['command_self_timestamp_comparisons']

    def test_opt_out_preserves_pinned_report_bytes(self):
        expected = (HERE / 'example-report.json').read_bytes()
        self.assertEqual(reader.encode(reader.assess(self.inputs, self.selection)) + b'\n', expected)
        self.assertEqual(reader.encode(reader.assess(self.inputs, self.selection, command_timestamps=None)) + b'\n', expected)

    def test_exact_deltas_and_unresolved_associations(self):
        r = self.assess()
        comparisons = r['timing']['command_self_timestamp_comparisons']
        self.assertEqual(comparisons['start_vs_host_fallback_log']['delta_nanoseconds'], '15000001')
        self.assertEqual(comparisons['end_vs_start']['delta_nanoseconds'], '2000002')
        self.assertEqual(comparisons['guardian_response_vs_start']['delta_nanoseconds'], '3116999999')
        for value in comparisons.values():
            self.assertEqual(value['relation'], 'after')
            self.assertEqual(value['association_basis'], 'receiver_supplied_files_only')
            self.assertFalse(value['same_execution_proven'])
            self.assertFalse(value['host_arrival_or_dispatch_order_proven'])
        for name in ('pair_binding', 'request_binding', 'execution_binding'):
            self.assertEqual(r['command_self_timestamps'][name], 'unresolved')

    def test_input_extension_cannot_change_existing_decisions_or_bindings(self):
        before = reader.assess(self.inputs, self.selection)
        r = self.assess()
        del r['command_self_timestamps']
        del r['timing']['command_self_timestamp_comparisons']
        for name in reader.COMMAND_TIMESTAMP_SOURCES:
            del r['sources'][name]
        self.assertEqual(r, before)
        self.assertIsNone(r['timing']['dispatch_at'])
        self.assertIsNone(r['timing']['decision_committed_at'])

    def test_file_line_hashes_and_original_text(self):
        for ending in (b'', b'\n', b'\r\n'):
            with self.subTest(ending=ending):
                raw = b'2026-01-01T00:00:05.015000001Z' + ending
                self.stamps['command_start'] = raw
                r = self.assess()
                item = r['command_self_timestamps']['start']['records'][0]
                self.assertEqual(item['reported_at'], '2026-01-01T00:00:05.015000001Z')
                self.assertEqual(r['sources']['command_start']['raw_sha256'], reader.digest(raw))
                self.assertEqual(r['sources']['command_start']['byte_length'], len(raw))
                self.assertEqual(item['source'], {'input': 'command_start', 'line': 1,
                    'line_raw_sha256': reader.digest(raw[:-1] if raw.endswith(b'\n') else raw)})

    def test_one_nanosecond_across_leap_day(self):
        self.stamps = {'command_start': b'2024-02-29T23:59:59.999999999Z\n',
                       'command_end': b'2024-03-01T00:00:00Z\n'}
        self.assertEqual(self.comparisons()['end_vs_start']['delta_nanoseconds'], '1')

    def test_large_interval_is_exact_decimal_text(self):
        self.stamps = {'command_start': b'0001-01-01T00:00:00Z',
                       'command_end': b'9999-12-31T23:59:59.999999999Z'}
        delta = self.comparisons()['end_vs_start']['delta_nanoseconds']
        self.assertEqual(delta, '315537897599999999999')
        self.assertIs(type(delta), str)

    def test_zero_through_nine_fractional_digits(self):
        for count in range(10):
            with self.subTest(count=count):
                suffix = '.' + '1' * count if count else ''
                raw = ('2026-01-01T00:00:05' + suffix + 'Z').encode()
                self.stamps = dict.fromkeys(reader.COMMAND_TIMESTAMP_SOURCES, raw)
                item = self.comparisons()['end_vs_start']
                self.assertEqual((item['relation'], item['delta_nanoseconds']), ('equal', '0'))

    def test_reversed_unbound_stamps_remain_observations(self):
        self.stamps = {'command_start': b'2026-01-01T00:00:05.000000002Z',
                       'command_end': b'2026-01-01T00:00:05.000000001Z'}
        item = self.comparisons()['end_vs_start']
        self.assertEqual((item['relation'], item['delta_nanoseconds']), ('before', '-1'))
        self.assertFalse(item['same_execution_proven'])

    def test_different_fractional_widths_preserve_one_nanosecond(self):
        for start, end in (('', '.000000001'), ('.1', '.100000001'),
                           ('.12345', '.123450001'), ('.12345678', '.123456781')):
            with self.subTest(start=start, end=end):
                self.stamps = {'command_start': ('2026-01-01T00:00:05' + start + 'Z').encode(),
                               'command_end': ('2026-01-01T00:00:05' + end + 'Z').encode()}
                item = self.comparisons()['end_vs_start']
                self.assertEqual((item['relation'], item['delta_nanoseconds']), ('after', '1'))

    def test_missing_start_end_and_both_are_explicit(self):
        original = self.stamps.copy()
        for missing in (('command_start',), ('command_end',), reader.COMMAND_TIMESTAMP_SOURCES):
            self.stamps = {name: None if name in missing else raw for name, raw in original.items()}
            r = self.assess()
            for name in missing:
                self.assertEqual(r['sources'][name], {'state': 'absent'})
                self.assertEqual(r['command_self_timestamps'][name.removeprefix('command_')]['status'], 'unavailable')
            self.assertEqual(r['timing']['command_self_timestamp_comparisons']['end_vs_start']['status'], 'unresolved')

    def test_no_logs_does_not_prevent_unbound_stamp_observation(self):
        self.inputs = dict.fromkeys(reader.SOURCES)
        comparisons = self.comparisons()
        self.assertEqual(comparisons['end_vs_start']['status'], 'observed_timestamp_order')
        self.assertEqual(comparisons['start_vs_host_fallback_log']['status'], 'unresolved')
        self.assertEqual(comparisons['guardian_response_vs_start']['status'], 'unresolved')

    def test_missing_one_log_preserves_independent_comparisons(self):
        original, expected = self.inputs.copy(), self.comparisons()
        for source, affected in (('host_audit', 'start_vs_host_fallback_log'),
                                 ('guardian_envelopes', 'guardian_response_vs_start')):
            with self.subTest(source=source):
                self.inputs = {**original, source: None}
                actual = self.comparisons()
                self.assertEqual(actual[affected]['status'], 'unresolved')
                for name in expected:
                    if name != affected:
                        self.assertEqual(actual[name], expected[name])

    def test_ambiguous_host_prevents_host_comparison(self):
        self.inputs['host_audit'] *= 2
        self.assertEqual(self.comparisons()['start_vs_host_fallback_log']['status'], 'unresolved')

    def test_reused_guardian_request_or_response_prevents_guardian_comparison(self):
        original = self.inputs['guardian_envelopes']
        for index in (8, 9):
            data = rows(original)
            data.append(deepcopy(data[index]))
            self.inputs['guardian_envelopes'] = jsonl(data)
            self.assertEqual(self.comparisons()['guardian_response_vs_start']['status'], 'unresolved')

    def test_wrong_sessions_do_not_promote_selected_observations(self):
        selection = json.loads(self.selection)
        selection['acs_session_id'] = selection['host_session_id'] = 'other-session'
        self.selection = reader.encode(selection)
        comparisons = self.comparisons()
        self.assertEqual(comparisons['guardian_response_vs_start']['status'], 'unresolved')
        self.assertEqual(comparisons['start_vs_host_fallback_log']['status'], 'unresolved')

    def test_invalid_timestamp_shape_calendar_and_content(self):
        invalid = [b'2026-02-29T00:00:00Z', b'0000-01-01T00:00:00Z', b'2026-01-01T24:00:00Z',
                   b'2026-01-01T24:00:00.1Z', b'2026-01-01T00:60:00Z',
                   b'2026-01-01T00:00:60Z', b'2026-01-01T00:00:00+00:00', b'2026-01-01T00:00:00.1234567890Z',
                   b'2026-01-01T00:00:00.Z', b'2026-01-01T00:00:00Z ', b' 2026-01-01T00:00:00Z',
                   b'2026-01-01T00:00:00Z\r', b'\xef\xbb\xbf2026-01-01T00:00:00Z', b'\xff',
                   b'{"timestamp":"2026-01-01T00:00:00Z"}', b'null', b'https://private.example/secret',
                   '２０２６-01-01T00:00:00Z'.encode()]
        for raw in invalid:
            with self.subTest(raw=raw):
                self.stamps['command_start'] = raw
                with self.assertRaises(reader.InputError) as raised:
                    self.assess()
                self.assertEqual(raised.exception.code, 'INVALID_TIMESTAMP')
                self.assertEqual(raised.exception.report()['input'], 'command_start')
                self.assertNotIn(raw, reader.encode(raised.exception.report()))

    def test_type_size_line_and_set_validation(self):
        cases = [(b'', 'INVALID_BYTES_OR_SIZE'), (bytearray(b'anything'), 'INVALID_BYTES_OR_SIZE'),
                 ('2026-01-01T00:00:00Z', 'INVALID_BYTES_OR_SIZE'), (True, 'INVALID_BYTES_OR_SIZE'),
                 (b'x' * (reader.MAX_BYTES + 1), 'INVALID_BYTES_OR_SIZE'),
                 (b'x' * (reader.MAX_LINE + 1), 'INVALID_LINE_SIZE'), (b'\n', 'INVALID_LINE_SIZE'),
                 (b'2026-01-01T00:00:00Z\n\n', 'EXPECTED_SINGLE_TIMESTAMP'),
                 (b'2026-01-01T00:00:00Z\n2026-01-01T00:00:01Z', 'EXPECTED_SINGLE_TIMESTAMP')]
        for raw, expected in cases:
            self.stamps['command_end'] = raw
            with self.assertRaises(reader.InputError) as raised:
                self.assess()
            self.assertEqual(raised.exception.code, expected)
        for value in ({}, {'command_start': None}, {'command_start': None, 'extra': None},
                      {'command_start': None, 'command_end': None, 'extra': None},
                      dict.fromkeys(range(4096)), [], True):
            with self.assertRaises(reader.InputError) as raised:
                reader.assess(self.inputs, self.selection, command_timestamps=value)
            self.assertEqual(raised.exception.code, 'INVALID_COMMAND_TIMESTAMP_SET')

    def test_determinism_and_no_input_mutation(self):
        before = deepcopy((self.inputs, self.stamps))
        first = reader.encode(self.assess())
        self.assertEqual(reader.encode(self.assess()), first)
        self.assertEqual((self.inputs, self.stamps), before)

    def cli(self, extra):
        command = [sys.executable, '-S', '-B', str(HERE / 'acs_reader.py'),
                   '--selection', str(HERE / 'selection.example.json')]
        for name, pin in PINS.items():
            command += ['--' + name.replace('_', '-'), str(HERE / pin['path'])]
        return subprocess.run(command + extra, capture_output=True, timeout=10)

    def test_cli_matches_api_and_handles_explicit_absence(self):
        start, end = [str(HERE / 'fixtures/synthetic' / (name.replace('_', '-') + '.txt'))
                      for name in reader.COMMAND_TIMESTAMP_SOURCES]
        for extra, missing in ((['--command-start', start, '--command-end', end], ()),
                               (['--command-start', start, '--command-end-absent'], ('command_end',)),
                               (['--command-start-absent', '--command-end', end], ('command_start',)),
                               (['--command-start-absent', '--command-end-absent'], reader.COMMAND_TIMESTAMP_SOURCES)):
            original = self.stamps.copy()
            for name in missing:
                self.stamps[name] = None
            run = self.cli(extra)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout), self.assess())
            self.stamps = original

    def test_cli_requires_explicit_other_side_and_rejects_conflicts(self):
        for extra in (['--command-start', 'private-path'], ['--command-end-absent'],
                      ['--command-start', 'private-path', '--command-start-absent', '--command-end-absent']):
            run = self.cli(extra)
            self.assertEqual(run.returncode, 64)
            self.assertNotIn(b'private-path', run.stdout + run.stderr)

    def test_cli_rejects_repeated_timestamp_paths_before_reading_files(self):
        paths = [str(HERE / 'fixtures/synthetic' / (name.replace('_', '-') + '.txt'))
                 for name in reader.COMMAND_TIMESTAMP_SOURCES]
        pairs = ((paths[0], paths[1]), (paths[1], paths[0]), (paths[0], paths[0]),
                 ('private-missing-path', paths[0]), (paths[0], 'private-missing-path'))
        for name, other in (('command-start', 'command-end'), ('command-end', 'command-start')):
            for first, second in pairs:
                with self.subTest(name=name, first=first, second=second):
                    extra = ['--' + name, first, '--' + name, second, '--' + other + '-absent']
                    run = self.cli(extra)
                    self.assertEqual(run.returncode, 64)
                    self.assertEqual(json.loads(run.stdout)['reason'], 'INVALID_ARGUMENTS')
                    self.assertNotIn(b'private-missing-path', run.stdout + run.stderr)
                    argv = ['--selection', 'unread-selection'] + [
                        '--' + source.replace('_', '-') + '-absent' for source in reader.SOURCES] + extra
                    with patch.object(reader, 'read_file') as read, redirect_stdout(io.StringIO()):
                        self.assertEqual(reader.main(argv), 64)
                    read.assert_not_called()

    def test_cli_bad_file_is_not_absence_and_does_not_echo_content(self):
        import os
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'private-stamp'
            path.write_bytes(b'SECRET-MARKER')
            link, fifo = Path(temp) / 'link', Path(temp) / 'fifo'
            link.symlink_to(path)
            os.mkfifo(fifo)
            for target in (path, link, fifo, Path(temp), Path(temp) / 'missing', ''):
                run = self.cli(['--command-start', str(target), '--command-end-absent'])
                self.assertEqual(run.returncode, 64)
                self.assertNotIn(b'SECRET-MARKER', run.stdout + run.stderr)
                self.assertNotIn(str(temp).encode(), run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main()
