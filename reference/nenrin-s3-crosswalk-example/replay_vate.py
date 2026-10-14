#!/usr/bin/env python3
"""Run the three pinned VATE cases offline into a new local directory."""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

import compare_records as comparison
import crosswalk_core as c

BOOTSTRAP = c.VATE_BOOTSTRAP


def environment():
    return {'PATH': str(Path(sys.executable).parent) + os.pathsep + '/usr/bin:/bin',
            'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1'}


def invoke(root, entry, arguments, stem):
    argv = [sys.executable, '-I', '-B', '-c', BOOTSTRAP, entry, *arguments]
    _, record = comparison.capture_process(root, argv, env=environment(), stem=stem)
    return record


def replay(output, *, example=comparison.HERE, repository=comparison.REPOSITORY):
    # Refuse an existing destination before any writes, including a partial failed run.
    output = comparison.new_output(output)
    public = c.Reader(example)
    repo = c.Reader(repository, 'repository')
    try:
        pins, _, _ = comparison.verify_public_inputs(public)
        source_data = comparison.source_bytes(repo, pins)
        helper = public.read('helpers/build_cases.py')
    finally:
        public.close()
        repo.close()
    version = importlib.metadata.version('jsonschema')
    c.require(version == '4.26.0', 'requires an existing jsonschema==4.26.0 environment; no installation is performed')
    runtime = {'python_version': sys.version, 'implementation': platform.python_implementation(),
               'executable': sys.executable, 'executable_sha256': c.sha(Path(sys.executable).read_bytes()),
               'jsonschema_version': version, 'platform': platform.platform(),
               'scope': 'local interpreter and installed dependency; not a runtime attestation'}
    output.mkdir()
    for path, raw in source_data.items():
        comparison.write_new(output / 'source' / path, raw)
    comparison.write_new(output / 'helpers/build_cases.py', helper)
    comparison.write_new(output / 'inputs/receiver-policy.json', source_data[pins['policy_path']])
    preparation = invoke(output, 'helpers/build_cases.py', [], 'preparation')
    c.require(preparation['exit_code'] == 0, 'case preparation failed; inspect retained preparation.err')
    records = []
    for case in ('matching', 'target-mismatch', 'missing-post'):
        reader = c.Reader(output, 'vate_local_run')
        try:
            c.require(comparison.source_bytes(reader, pins, 'source/') == source_data, 'copied VATE source changed before execution')
            expected = comparison.expected_case(comparison.original_case(source_data, pins), case)
            folder = 'cases/' + case
            c.require(reader.names(folder) == set(expected), 'prepared case inventory differs')
            raw_inputs = {name: reader.read(folder + '/' + name) for name in expected}
            c.require(raw_inputs == expected, 'prepared VATE case differs from pinned case')
        finally:
            reader.close()
        record = invoke(output, 'source/reference/s3-observation-example/assess_observation.py',
                        ['--bundle', folder, '--trust', 'inputs/receiver-policy.json'], 'results/' + case)
        record.update(case=case, input_directory=folder, input_files={name: c.fingerprint(raw) for name, raw in raw_inputs.items()})
        c.require(record['exit_code'] == {'matching': 0, 'target-mismatch': 1, 'missing-post': 2}[case],
                  'unexpected VATE native exit; retained output requires inspection')
        comparison.verify_vate_report(c.Document(record['stdout']['path'], (output / record['stdout']['path']).read_bytes()),
                                      raw_inputs, case, comparison.receipt_source_hashes(pins, source_data))
        records.append(record)
    record = {'schema': comparison.VATE_FRESH, 'evidence_mode': 'fresh_local_run', 'source_commit': c.VATE_COMMIT,
              'source_files': {path: c.fingerprint(raw) for path, raw in source_data.items()}, 'runtime': runtime,
              'preparation': preparation, 'producer': {'helper': c.fingerprint(helper)},
              'receiver_policy': {'path': 'inputs/receiver-policy.json', **c.fingerprint(source_data[pins['policy_path']])},
              'cases': records, 'new_s3_execution': False,
              'record_scope': 'This command invoked the fixed local VATE checker on three recorded-input copies. The local record is not a signed execution attestation.'}
    comparison.write_json(output / 'RUN.json', record)
    # Reopen all inputs/outputs and verify the same public loader used by comparison.
    reader = c.Reader(output, 'vate_local_run')
    try:
        comparison.load_vate(reader, pins, comparison.original_case(source_data, pins), source_data,
                             fresh=True, expected_helper=helper)
    finally:
        reader.close()
    return output, record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path, help='New output directory; never reused')
    args = parser.parse_args(argv)
    try:
        output, record = replay(args.output)
        print(json.dumps({'run': str(output / 'RUN.json'), 'cases_executed': len(record['cases']), 'evidence_mode': record['evidence_mode']}))
        return 0
    except (OSError, ValueError, KeyError, TypeError, ImportError, subprocess.SubprocessError) as exc:
        print(json.dumps({'error': type(exc).__name__, 'detail': str(exc)}), file=sys.stderr)
        return 64


if __name__ == '__main__':
    raise SystemExit(main())
