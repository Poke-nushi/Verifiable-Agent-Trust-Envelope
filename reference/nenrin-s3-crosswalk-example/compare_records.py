#!/usr/bin/env python3
"""Compare saved or local replay records; the comparison CLI executes no checker."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

import crosswalk_core as c

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[1]
SOURCES_SHA = 'dfae498efe5fa1fdda1898e6e0bd41e01a06314912cb35f5aca949d70463a7c7'
NATIVE_SAVED = 'nenrin-vate-saved-nenrin-reports-v1'
VATE_SAVED = 'nenrin-vate-saved-vate-reports-v1'
NATIVE_FRESH = 'nenrin-vate-native-replay-v1'
VATE_FRESH = 'nenrin-vate-vate-replay-v1'
HISTORICAL_PREFIX = 'reference/historical-runtime/e845a6a8/'


def document_reference(reader, path):
    return {'path': path, **c.fingerprint(reader.read(path))}


def new_output(path, *, directory=False):
    selected = Path(os.path.abspath(path))
    c.require(not selected.exists() and not selected.is_symlink(), 'output exists; choose a new path')
    result = selected.parent.resolve(strict=True) / selected.name
    c.require(result.parent.is_dir(), 'output parent must be an existing directory')
    c.require(not result.is_relative_to(HERE), 'write outputs outside the published example')
    if directory:
        result.mkdir()
    return result


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)


def write_json(path, value):
    write_new(path, (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + '\n').encode())


def capture_process(root, command, *, env, stem, timeout=60, stdin=None, python_cache=None):
    """Retain replay output, including partial bytes when a command times out."""
    started = datetime.now(timezone.utc).isoformat()

    def retain(result, *, timed_out=False):
        record = {'command': command, 'cwd': '.', 'started_at': started,
                  'finished_at': datetime.now(timezone.utc).isoformat(),
                  'exit_code': None if timed_out else result.returncode}
        if python_cache is not None:
            # A timeout skips the replay caller's post-invocation cache check.
            record['python_cache'] = {**python_cache, 'empty_after': None} if timed_out else python_cache
        for role, extension in [('stdout', 'out'), ('stderr', 'err')]:
            path = stem + '.' + extension
            raw = getattr(result, role)
            raw = b'' if raw is None else raw
            write_new(root / path, raw)
            record[role] = {'path': path, **c.fingerprint(raw)}
        if timed_out:
            record.update(schema='nenrin-vate-replay-timeout-v1', status='timed_out',
                          timeout_seconds=result.timeout)
            write_json(root / (stem + '.timeout.json'), record)
        return record

    try:
        result = subprocess.run(command, input=stdin, cwd=root, env=env, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        retain(exc, timed_out=True)
        raise
    return result, retain(result)


def verify_public_inputs(reader):
    sources = reader.document('SOURCES.json')
    c.require(c.sha(sources.raw) == SOURCES_SHA, 'public source inventory changed')
    value = c.json_object(sources)
    c.require(value.get('schema') == 'nenrin-vate-public-sources-v1', 'unknown public source inventory')
    for path, reference in value['artifacts'].items():
        reader.bound({'path': path, 'sha256': reference['sha256'], 'byte_length': reference['byte_length']})
    pins_document = reader.document('VATE-PINS.json')
    c.require(c.sha(pins_document.raw) == c.VATE_PINS_SHA, 'fixed VATE pins changed')
    return c.json_object(pins_document), sources, pins_document


def source_bytes(reader, pins, prefix=''):
    c.require(pins.get('commit') == c.VATE_COMMIT, 'wrong VATE source commit')
    result = {}
    for path, expected in pins['files'].items():
        result[path] = reader.bound({'path': prefix + path, 'sha256': expected['sha256'], 'byte_length': expected['byte_length']}).raw
    return result


def repository_source_bytes(reader, pins):
    """Read the fixed archived files; VATE-PINS still binds their original bytes."""
    return source_bytes(reader, pins, HISTORICAL_PREFIX)


def original_case(sources, pins):
    prefix = pins['supported_path'] + '/'
    return {path[len(prefix):]: raw for path, raw in sources.items() if path.startswith(prefix)}


def expected_case(original, case):
    c.require(case in c.CASES.values(), 'unknown VATE case')
    raws = dict(original)
    if case == 'missing-post':
        del raws['post.json']
    elif case == 'target-mismatch':
        request = c.decode(raws['get-request.json'])
        request['key'] = 'other.txt'
        raws['get-request.json'] = c.canonical(request)
        transport = c.decode(raws['get-transport.json'])
        transport['request_ref'] = {'path': 'get-request.json', 'digest': {'alg': 'sha-256', 'value': c.sha(raws['get-request.json'])},
                                    'byte_length': len(raws['get-request.json'])}
        raws['get-transport.json'] = c.canonical(transport)
    if case != 'matching':
        raws['manifest.json'] = c.canonical({'contract': c.CONTRACT, 'artifacts': {
            name: {'digest': {'alg': 'sha-256', 'value': c.sha(raw)}, 'byte_length': len(raw)}
            for name, raw in raws.items() if name != 'manifest.json'}})
    return raws


def load_bundles(reader):
    manifest = reader.document(c.NENRIN_ROOT + '/MANIFEST.json')
    c.require(c.sha(manifest.raw) == c.MANIFEST_SHA, 'fixed NENRIN submission manifest changed')
    value = c.json_object(manifest)
    files = c.unique(value['files'], 'path', 'submitted files')
    cases = c.unique(value['cases'], 'name', 'submitted cases')
    c.require(set(cases) == set(c.CASES), 'submitted case set differs')
    bundles = {}
    for case in c.CASES:
        relative = f'records/{case}/nenrin-bundle.json'
        c.require(cases[case]['file'] == relative and relative in files, 'submitted case assignment differs')
        reference = files[relative]
        document = reader.bound({'path': c.NENRIN_ROOT + '/' + relative, 'sha256': reference['sha256'], 'byte_length': reference['bytes']})
        bundle = c.json_object(document)
        c.require(set(bundle) == ({'task_id', 'grant'} | (set() if case == 'missing_receipt' else {'receipt'})),
                  'unexpected record or receipt reintroduced into missing case')
        bundles[case] = document
    c.require(set(files) == {f'records/{case}/nenrin-bundle.json' for case in c.CASES}, 'duplicate or additional submitted file role')
    base = bundles['match'].value
    for bundle in bundles.values():
        c.require(c.same(base['grant'], bundle.value['grant']) and c.same(base['task_id'], bundle.value['task_id']), 'grant/task changed across cases')
    altered = bundles['target_mismatch'].value['receipt']
    expected = c.decode(c.canonical(base['receipt']))
    expected['executed_action']['target'] = base['receipt']['executed_action']['target'].rsplit('/', 1)[0] + '/result-other.txt'
    for field in ('receipt_id', 'action_binding', 'provider_sig'):
        expected[field] = altered[field]
    c.require(c.same(expected, altered), 'NENRIN target mutation exceeds the fixed case')
    return bundles, manifest


def mode_record(reader, path, saved_schema, fresh_schema, source_commit):
    document = reader.document(path)
    value = c.json_object(document)
    expected_schema, mode = (saved_schema, 'saved') if path.startswith('saved/') else (fresh_schema, 'fresh_local_run')
    c.require(value.get('schema') == expected_schema and value.get('evidence_mode') == mode, 'saved/fresh record schema or mode differs')
    c.require(value.get('source_commit') == source_commit, 'run source commit differs')
    return document, value, mode


def runtime_executable(runtime):
    c.require(type(runtime) is dict, 'local runtime identity must be an object')
    executable = runtime.get('executable')
    c.require(type(executable) is str and '\x00' not in executable and Path(executable).is_absolute(),
              'local runtime executable must be an absolute path')
    c.require(type(runtime.get('executable_sha256')) is str and c.HEX.fullmatch(runtime['executable_sha256']),
              'local runtime executable fingerprint absent or invalid')
    return executable


def local_times(record):
    times = []
    for key in ('started_at', 'finished_at'):
        value = record.get(key)
        c.require(type(value) is str and value.endswith('+00:00'), 'local invocation requires a UTC ' + key)
        parsed = datetime.fromisoformat(value)
        c.require(parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0),
                  'local invocation requires a timezone-aware UTC ' + key)
        times.append(parsed)
    c.require(times[0] <= times[1], 'local invocation finishes before it starts')


def verify_python_cache(reader, record, label):
    expected = c.native_cache_record(label)
    c.require(c.same(record.get('python_cache'), expected), 'native Python cache metadata differs')
    c.require(reader.names(expected['path']) == set(), 'native Python cache must remain empty')
    return expected['path']


def verify_python_source_checks(reader, value, python, expected_identity):
    c.require(value.get('python_cache_policy') == c.NATIVE_CACHE_POLICY, 'native Python cache policy differs')
    checks = c.unique(value.get('python_source_checks'), 'phase', 'Python source checks')
    c.require(set(checks) == {'preflight', 'postflight'}, 'both Python source checks required')
    expected_runtime = {key: item for key, item in value['runtime']['python'].items() if key != 'executable_sha256'}
    for phase, record in checks.items():
        cache_path = verify_python_cache(reader, record, phase)
        c.require(c.same(record.get('command'), c.native_python_command(python, cache_path, c.NATIVE_PYTHON_PROBE))
                  and record.get('cwd') == '.', 'Python source probe command differs')
        c.require(type(record.get('exit_code')) is int and record['exit_code'] == 0, 'Python source probe failed')
        c.require(c.same(record.get('stdin'), c.fingerprint(c.canonical(expected_identity['pypi']))), 'Python source probe input differs')
        local_times(record)
        report = reader.bound(record['stdout'], 'checks/' + phase + '.out')
        reader.bound(record['stderr'], 'checks/' + phase + '.err')
        parsed = c.json_object(report)
        c.require(c.same(parsed.get('source_identity'), expected_identity['pypi']) and
                  c.same(parsed.get('runtime'), expected_runtime), 'Python source probe result differs from recorded identity')


def load_native(reader, bundles, *, fresh=False, native_pins=None):
    manifest, value, mode = mode_record(reader, 'RUN.json' if fresh else 'saved/nenrin/REPORTS.json', NATIVE_SAVED, NATIVE_FRESH, c.NENRIN_COMMIT)
    runs = value.get('runs')
    c.require(type(runs) is list and len(runs) == 6, 'exactly six native case/engine records required')
    if fresh:
        c.require(type(native_pins) is dict, 'native source pins required for local replay records')
        expected_identity = {engine: native_pins[engine]['files'] for engine in c.PACKAGES}
        c.require(c.same(value.get('source_identity'), expected_identity), 'native local source identity differs from fixed distributions')
        runtime, entrypoints = value.get('runtime'), value.get('entrypoints')
        c.require(type(runtime) is dict and type(entrypoints) is dict, 'native local runtime/entrypoint metadata absent')
        node = runtime_executable(runtime.get('node'))
        python = runtime_executable(runtime.get('python'))
        npm_entry = entrypoints.get('npm')
        c.require(type(npm_entry) is str and '\x00' not in npm_entry and Path(npm_entry).is_absolute()
                  and Path(npm_entry).name == 'nenrin_verify.mjs', 'native npm entrypoint differs')
        c.require(entrypoints.get('pypi') == 'nenrin_verify.cli:main', 'native Python entrypoint differs')
        c.require(runtime['python'].get('packages', {}).get('nenrin-verify') == '0.5.3', 'native Python runtime package version differs')
        verify_python_source_checks(reader, value, python, expected_identity)
    reports, records = {}, {}
    for record in runs:
        c.require(type(record) is dict, 'invalid native run record')
        engine, case = record.get('engine'), record.get('case')
        c.require(type(engine) is str and type(case) is str and engine in c.PACKAGES and case in c.CASES, 'unknown engine/case')
        pair = (engine, case)
        c.require(pair not in reports, 'duplicate native engine/case')
        package = record.get('package')
        c.require(type(package) is dict and (package.get('name'), package.get('version')) == c.PACKAGES[engine], 'native package pin differs')
        c.require(type(record.get('exit_code')) is int and record['exit_code'] == (0 if case == 'match' else 1), 'native exit status differs')
        input_path = f'inputs/{case}.json' if fresh else bundles[case].path
        input_document = reader.bound(record['input'], input_path)
        c.require(input_document.raw == bundles[case].raw, 'native run input differs from submitted case')
        prefix = 'results/' if fresh else 'saved/nenrin/'
        report = reader.bound(record['stdout'], f'{prefix}{engine}-{case}.out')
        reader.bound(record['stderr'], f'{prefix}{engine}-{case}.err')
        if fresh:
            command = record.get('command')
            if engine == 'npm':
                expected_command = [node, npm_entry, input_path]
            else:
                cache_path = verify_python_cache(reader, record, 'verify-' + case)
                expected_command = c.native_python_command(python, cache_path, c.NATIVE_PYTHON_ENTRY, [input_path])
            c.require(c.same(command, expected_command) and record.get('cwd') == '.', 'native command/input assignment differs')
            local_times(record)
        else:
            c.require(type(record.get('historical_execution')) is dict, 'saved report historical time record absent')
        c.verify_native_report(report, bundles[case].value, case)
        reports[pair], records[pair] = report, record
    return reports, records, manifest, mode


def receipt_source_hashes(pins, source_data):
    declared = c.decode(source_data['reference/receipt-linkage-example/SOURCE-PINS.json'])['files']
    expected = {path: pins['files'][path]['sha256'] for path in declared}
    c.require(c.same(declared, expected), 'receipt checker source pins differ from VATE pins')
    return expected


def verify_vate_report(report, raws, case, expected_receipt_sources):
    value = c.json_object(report)
    c.require(value.get('contract') == c.CONTRACT and value.get('retry_authorized') is False, 'VATE report contract/permission differs')
    assessments = {'matching': 'supported_under_local_assumptions', 'target-mismatch': 'contradictory', 'missing-post': 'insufficient'}
    c.require(value.get('assessment') == assessments[case], 'wrong-case or unexpected VATE assessment')
    c.require(value.get('record_linkage') == ('not_assessed' if case == 'missing-post' else 'matched'), 'wrong VATE linkage result')
    receipt = value.get('receipt_check')
    c.require(type(receipt) is dict, 'VATE report receipt_check must be an object')
    reported_sources = receipt.get('source_files')
    c.require(type(reported_sources) is dict and c.same(reported_sources, expected_receipt_sources),
              'VATE report receipt checker source_files differ from fixed VATE pins')
    inputs = receipt.get('inputs')
    c.require(type(inputs) is dict, 'VATE report receipt inputs must be an object')
    for name in ('admission', 'post'):
        supplied = name + '.json' in raws
        expected = {'supplied': supplied, 'raw_file_sha256': c.sha(raws[name + '.json']) if supplied else None}
        c.require(c.same(inputs.get(name), expected), 'VATE report receipt/input digest mismatch')


def load_vate(reader, pins, original, source_data, *, fresh=False, expected_helper=None):
    manifest, value, mode = mode_record(reader, 'RUN.json' if fresh else 'saved/vate/REPORTS.json', VATE_SAVED, VATE_FRESH, c.VATE_COMMIT)
    cases = c.unique(value.get('cases'), 'case', 'VATE cases')
    c.require(set(cases) == set(c.CASES.values()), 'VATE case set differs')
    if fresh:
        exported = source_bytes(reader, pins, 'source/')
        c.require(exported == source_data, 'VATE copied source differs')
        declared = value.get('source_files')
        expected_source = {path: c.fingerprint(raw) for path, raw in source_data.items()}
        c.require(c.same(declared, expected_source), 'VATE declared source closure differs')
        executable = runtime_executable(value.get('runtime'))
        c.require(value['runtime'].get('jsonschema_version') == '4.26.0', 'VATE runtime dependency version differs')
        c.require(type(expected_helper) is bytes and expected_helper, 'expected public VATE preparation helper bytes required')
        producer = value.get('producer')
        c.require(type(producer) is dict, 'VATE preparation producer must be an object')
        helper = producer.get('helper')
        c.require(type(helper) is dict and set(helper) == {'sha256', 'byte_length'}, 'VATE preparation helper fingerprint shape differs')
        copied_helper = reader.bound({'path': 'helpers/build_cases.py', **helper}, 'helpers/build_cases.py')
        c.require(copied_helper.raw == expected_helper, 'VATE preparation helper differs from public example')
        preparation = value.get('preparation')
        c.require(type(preparation) is dict, 'VATE preparation record must be an object')
        expected_command = [executable, '-I', '-B', '-c', c.VATE_BOOTSTRAP, 'helpers/build_cases.py']
        c.require(c.same(preparation.get('command'), expected_command) and preparation.get('cwd') == '.',
                  'VATE preparation command/cwd differs')
        c.require(type(preparation.get('exit_code')) is int and preparation['exit_code'] == 0, 'VATE preparation failed')
        local_times(preparation)
        reader.bound(preparation.get('stdout'), 'preparation.out')
        reader.bound(preparation.get('stderr'), 'preparation.err')
    policy_path = 'inputs/receiver-policy.json' if fresh else 'saved/vate/receiver-policy.json'
    policy = reader.bound(value['receiver_policy'], policy_path)
    c.require(policy.raw == source_data[pins['policy_path']], 'receiver policy is not the pinned external input')
    source_hashes = {path: pins['files'][path]['sha256'] for path in pins['source_paths']}
    receipt_sources = receipt_source_hashes(pins, source_data)
    c.require(c.same(c.json_object(policy)['source_hashes'], source_hashes), 'receiver source hash set differs')
    documents, reports = {}, {}
    for case, record in cases.items():
        folder = ('cases/' if fresh else 'saved/vate/cases/') + case
        c.require(record.get('input_directory') == folder, 'VATE case/input path assignment differs')
        expected = expected_case(original, case)
        inventory = record.get('input_files')
        c.require(type(inventory) is dict and set(inventory) == set(expected) and reader.names(folder) == set(expected), 'VATE case inventory differs')
        raws = {}
        for name, reference in inventory.items():
            c.require(type(reference) is dict and set(reference) == {'sha256', 'byte_length'}, 'VATE file fingerprint shape differs')
            path = folder + '/' + name
            raws[name] = reader.bound({'path': path, **reference}, path).raw
        c.require(raws == expected, 'VATE case differs from exact pinned mutation')
        c.require(c.same(c.decode(raws['sources.json']), source_hashes), 'VATE case source hashes differ')
        prefix = 'results/' if fresh else 'saved/vate/'
        report = reader.bound(record['stdout'], prefix + case + '.out')
        reader.bound(record['stderr'], prefix + case + '.err')
        expected_exit = {'matching': 0, 'target-mismatch': 1, 'missing-post': 2}[case]
        c.require(type(record.get('exit_code')) is int and record['exit_code'] == expected_exit, 'VATE exit status differs')
        if fresh:
            command = record.get('command')
            expected_command = [executable, '-I', '-B', '-c', c.VATE_BOOTSTRAP,
                                'source/reference/s3-observation-example/assess_observation.py',
                                '--bundle', folder, '--trust', 'inputs/receiver-policy.json']
            c.require(c.same(command, expected_command) and record.get('cwd') == '.', 'VATE local command/input assignment differs')
            local_times(record)
        else:
            c.require(type(record.get('historical_execution')) is dict, 'VATE saved historical time record absent')
        verify_vate_report(report, raws, case, receipt_sources)
        documents[case] = {name.rsplit('.', 1)[0]: c.Document(folder + '/' + name, raws.get(name), binary=name.endswith('.bin'), collection=reader.collection)
                           for name in original}
        reports[case] = report
    return documents, reports, cases, policy, manifest, mode


def build_report(*, vate_run=None, native_run=None, example=HERE, repository=REPOSITORY):
    readers = []
    def open_reader(path, label):
        reader = c.Reader(path, collection=label)
        readers.append(reader)
        return reader
    try:
        public = open_reader(example, 'example')
        pins, source_inventory, pins_document = verify_public_inputs(public)
        repo = open_reader(repository, 'repository')
        source_data = repository_source_bytes(repo, pins)
        bundles, submission = load_bundles(public)
        nr = open_reader(Path(native_run).resolve(strict=True), 'native_local_run') if native_run else public
        vr = open_reader(Path(vate_run).resolve(strict=True), 'vate_local_run') if vate_run else public
        native_pins = c.json_object(public.document('NATIVE-PINS.json'))
        reports, records, native_manifest, native_mode = load_native(nr, bundles, fresh=bool(native_run), native_pins=native_pins)
        vate, vate_reports, vate_records, policy, vate_manifest, vate_mode = load_vate(
            vr, pins, original_case(source_data, pins), source_data, fresh=bool(vate_run),
            expected_helper=public.read('helpers/build_cases.py') if vate_run else None)
        c.require(native_manifest.value.get('harness_only') is not True and vate_manifest.value.get('harness_only') is not True,
                  'synthetic harness records cannot produce a final comparison')
        modes = {'nenrin': native_mode, 'vate': vate_mode}
        cases = []
        for ncase, vcase in c.CASES.items():
            native = {engine: reports[engine, ncase] for engine in c.PACKAGES}
            rows = c.relationship_rows(bundles[ncase], vate[vcase], policy, submission, native)
            components = [{'name': engine + '_record_binding', 'status': 'matched', 'evidence_mode': native_mode,
                           'record': records[engine, ncase], 'sources': [native_manifest.ref(), bundles[ncase].ref(), native[engine].ref()]}
                          for engine in c.PACKAGES]
            components.append({'name': 'vate_record_binding', 'status': 'matched', 'evidence_mode': vate_mode,
                               'record': vate_records[vcase], 'sources': [vate_manifest.ref(), pins_document.ref(), vate_reports[vcase].ref()]})
            rows.append(c.row(11, 'saved/publication or local replay record bindings', components,
                'Saved rows bind the redistributed bytes and publication metadata. Fresh rows bind a separate local replay record. Comparison runs no checker; neither record type is a signed execution attestation.'))
            cases.append({'nenrin_case': ncase, 'vate_case': vcase, 'evidence_modes': dict(modes), 'relationships': rows,
                'attribution': {'crosswalk': 'not_inferred', 'scope': 'public test identities; no VATE/store/receiver authority mapping',
                    'missing_pair_signature_check': 'not_assessed' if ncase == 'missing_receipt' else 'see complete native reports'},
                'native_reports': {engine: c.report_copy(document) for engine, document in native.items()},
                'native_full_report_comparison': {'status': 'matched' if c.same(native['npm'].value, native['pypi'].value) else 'mismatched',
                    'raw_bytes_equal': native['npm'].raw == native['pypi'].raw,
                    'basis': 'all values, types, null/absence, array order, native vocabulary and verifier version'},
                'vate_report': c.report_copy(vate_reports[vcase])})
        return {'schema': 'nenrin-vate-public-crosswalk-v1', 'compared_at': datetime.now(timezone.utc).isoformat(),
            'evidence_modes': modes, 'checker_execution_performed_by_comparison': False,
            'scope': 'fixed three-case cross-record relationships; no combined verdict, signature attribution or execution/retry permission',
            'pins': {'nenrin_commit': c.NENRIN_COMMIT, 'vate_commit': c.VATE_COMMIT, 'public_sources': source_inventory.ref(), 'vate_source_pins': pins_document.ref()},
            'submission_label': submission.value['label'], 'submission_label_scope': submission.value['label_scope'],
            'native_window_precision': submission.value['window']['precision'],
            'records': {'nenrin': c.report_copy(native_manifest), 'vate': c.report_copy(vate_manifest)}, 'cases': cases}
    finally:
        for reader in readers:
            reader.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vate-run', type=Path, help='Existing directory produced by replay_vate.py')
    parser.add_argument('--native-run', type=Path, help='Existing directory produced by replay_native.py')
    parser.add_argument('--output', required=True, type=Path, help='New JSON file outside this example')
    args = parser.parse_args(argv)
    try:
        output = new_output(args.output)
        for supplied in (args.vate_run, args.native_run):
            if supplied:
                c.require(not output.is_relative_to(supplied.resolve(strict=True)), 'comparison output must be outside its run inputs')
        result = build_report(vate_run=args.vate_run, native_run=args.native_run)
        write_json(output, result)
        print(json.dumps({'output': str(output), 'cases_written': len(result['cases']), 'evidence_modes': result['evidence_modes']}))
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        print(json.dumps({'error': type(exc).__name__, 'detail': str(exc)}), file=sys.stderr)
        return 64


if __name__ == '__main__':
    raise SystemExit(main())
