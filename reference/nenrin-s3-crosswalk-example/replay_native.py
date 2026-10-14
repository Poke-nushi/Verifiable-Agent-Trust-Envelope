#!/usr/bin/env python3
"""Replay six NENRIN checks with explicitly supplied, already installed runtimes."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import compare_records as comparison
import crosswalk_core as c

PYTHON_ENTRY = c.NATIVE_PYTHON_ENTRY
PYTHON_PROBE = c.NATIVE_PYTHON_PROBE


def environment(node, python):
    return {'PATH': os.pathsep.join((str(node.parent), str(python.parent), '/usr/bin', '/bin')),
            'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1'}


def invoke_python(root, python, label, code, arguments=(), *, env, stdin=None, stem, timeout=60):
    # -B prevents writes, but alone it still reads an existing adjacent .pyc.
    # A new empty prefix selects a separate cache tree before Python starts.
    c.require(re.fullmatch(r'[a-z][a-z0-9_-]*', label), 'invalid local Python invocation label')
    cache_record = c.native_cache_record(label)
    cache = root / cache_record['path']
    c.require(not cache.parent.is_symlink(), 'Python cache parent must not be a symlink')
    cache.parent.mkdir(exist_ok=True)
    cache.mkdir()
    command = c.native_python_command(python, cache_record['path'], code, arguments)
    result, record = comparison.capture_process(root, command, env=env, stem=stem, timeout=timeout,
                                                stdin=stdin, python_cache=cache_record)
    reader = c.Reader(root)
    try:
        c.require(reader.names(cache_record['path']) == set(), 'Python cache is not empty after invocation')
    finally:
        reader.close()
    return result, record


def installed_identity(node, npm_entry, python, pins, *, root, phase):
    c.require(npm_entry.name == 'nenrin_verify.mjs' and not npm_entry.is_symlink(), 'supply the npm package nenrin_verify.mjs regular file')
    reader = c.Reader(npm_entry.parent.resolve(strict=True), 'installed_npm')
    try:
        identity = {name: c.fingerprint(reader.bound({'path': name, **reference}).raw) for name, reference in pins['npm']['files'].items()}
        package = c.json_object(reader.document('package.json'))
        c.require((package.get('name'), package.get('version')) == ('nenrin-verify', '0.5.1'), 'npm package version differs')
    finally:
        reader.close()
    env = environment(node, python)
    node_result, _ = comparison.capture_process(root, [str(node), '--version'], env=env,
                                                stem='checks/node-' + phase, timeout=15)
    version = node_result.stdout.decode('utf-8').strip()
    match = re.fullmatch(r'v(\d+)\.\d+\.\d+', version)
    c.require(node_result.returncode == 0 and match and int(match.group(1)) >= 20, 'requires an existing Node.js >=20 runtime')
    probe_input = c.canonical(pins['pypi']['files'])
    probe, probe_record = invoke_python(root, python, phase, PYTHON_PROBE, env=env,
                                       stdin=probe_input, stem='checks/' + phase, timeout=30)
    probe_record.update(phase=phase, stdin=c.fingerprint(probe_input))
    c.require(probe.returncode == 0, 'Python distribution source check failed: ' + probe.stderr.decode('utf-8', 'replace')[:2000])
    parsed = c.decode(probe.stdout)
    c.require(c.same(parsed['source_identity'], pins['pypi']['files']), 'Python source identity differs')
    return {'npm': identity, 'pypi': parsed['source_identity']}, {
        'node': {'executable': str(node), 'version': version, 'executable_sha256': c.sha(node.read_bytes())},
        'python': {**parsed['runtime'], 'executable_sha256': c.sha(python.read_bytes())}}, probe_record


def replay(output, node, npm_entry, python, *, example=comparison.HERE):
    output = comparison.new_output(output)
    node, npm_entry, python = (Path(os.path.abspath(path)) for path in (node, npm_entry, python))
    for executable in (node, python):
        c.require(executable.is_file() and os.access(executable, os.X_OK), 'explicit executable unavailable: ' + str(executable))
    public = c.Reader(example)
    try:
        comparison.verify_public_inputs(public)
        pins = c.json_object(public.document('NATIVE-PINS.json'))
        bundles, _ = comparison.load_bundles(public)
    finally:
        public.close()
    output.mkdir()
    identity, runtime, preflight = installed_identity(node, npm_entry, python, pins, root=output, phase='preflight')
    for case, document in bundles.items():
        comparison.write_new(output / 'inputs' / (case + '.json'), document.raw)
    records = []
    for case in c.CASES:
        for engine in c.PACKAGES:
            input_path = f'inputs/{case}.json'
            if engine == 'pypi':
                result, record = invoke_python(output, python, 'verify-' + case, PYTHON_ENTRY, [input_path],
                                               env=environment(node, python), stem=f'results/{engine}-{case}')
            else:
                argv = [str(node), str(npm_entry), input_path]
                result, record = comparison.capture_process(output, argv, env=environment(node, python),
                                                             stem=f'results/{engine}-{case}')
            record.update(case=case, engine=engine, package={'name': c.PACKAGES[engine][0], 'version': c.PACKAGES[engine][1]},
                          input={'path': input_path, **c.fingerprint(bundles[case].raw)})
            c.require(result.returncode == (0 if case == 'match' else 1), 'unexpected native exit; inspect retained output')
            c.verify_native_report(c.Document(record['stdout']['path'], result.stdout), bundles[case].value, case)
            records.append(record)
    after, runtime_after, postflight = installed_identity(node, npm_entry, python, pins, root=output, phase='postflight')
    c.require(c.same(after, identity) and c.same(runtime_after, runtime), 'installed source/runtime changed during replay')
    record = {'schema': comparison.NATIVE_FRESH, 'evidence_mode': 'fresh_local_run', 'source_commit': c.NENRIN_COMMIT,
              'runtime': runtime, 'source_identity': identity, 'entrypoints': {'npm': str(npm_entry), 'pypi': 'nenrin_verify.cli:main'},
              'python_cache_policy': c.NATIVE_CACHE_POLICY, 'python_source_checks': [preflight, postflight],
              'runs': records, 'signature_mode': 'unchanged published CLI default require_signatures=true',
              'record_scope': 'This command invoked the selected fixed local distributions. The local record is not a signed execution attestation.',
              'external_lookup_configured': False, 'new_s3_execution': False, 'installation_performed': False}
    comparison.write_json(output / 'RUN.json', record)
    reader = c.Reader(output, 'native_local_run')
    try:
        comparison.load_native(reader, bundles, fresh=True, native_pins=pins)
    finally:
        reader.close()
    return output, record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', required=True, type=Path, help='Existing Node.js executable')
    parser.add_argument('--npm-entry', required=True, type=Path, help='Installed nenrin-verify@0.5.1/nenrin_verify.mjs')
    parser.add_argument('--python', required=True, type=Path, help='Existing Python with nenrin-verify==0.5.3 installed')
    parser.add_argument('--output', required=True, type=Path, help='New output directory; never reused')
    args = parser.parse_args(argv)
    try:
        output, record = replay(args.output, args.node, args.npm_entry, args.python)
        print(json.dumps({'run': str(output / 'RUN.json'), 'cases_executed': len(record['runs']), 'evidence_mode': record['evidence_mode']}))
        return 0
    except (OSError, ValueError, KeyError, TypeError, ImportError, subprocess.SubprocessError) as exc:
        print(json.dumps({'error': type(exc).__name__, 'detail': str(exc)}), file=sys.stderr)
        return 64


if __name__ == '__main__':
    raise SystemExit(main())
