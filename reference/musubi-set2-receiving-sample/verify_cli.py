"""Regression checks for the receiving CLI's error/status boundary.

Uses real Inbox storage, replacing only native replay with a saved output or
explicit failure. Actual native replay is verified separately by verify.py.
"""
import argparse
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

ap = argparse.ArgumentParser()
ap.add_argument('--candidate', type=Path, default=Path(__file__).resolve().parent)
ap.add_argument('--environment', type=Path, required=True)
ap.add_argument('--vate-root', type=Path, required=True)
ap.add_argument('--output', type=Path, required=True)
ap.add_argument('--case', action='append', choices=(
    'time-null', 'time-number', 'empty-database', 'unrelated-database',
    'spawn-error', 'native-error', 'evaluated', 'refused', 'argument-error',
    'native-malformed-pilot', 'native-malformed-row', 'native-malformed-identity',
    'empty-vate-root', 'missing-vate-root', 'file-vate-root',
    'broken-inbox-import', 'missing-inbox-export', 'ambient-inbox'))
a = ap.parse_args()
a.candidate = a.candidate.resolve(); a.vate_root = a.vate_root.resolve(); a.environment = a.environment.resolve()
a.output = a.output.resolve(); a.output.mkdir(parents=True, exist_ok=False)

wrapper = r'''
import json, sys
from pathlib import Path
candidate, mode = Path(sys.argv[1]), sys.argv[2]
sys.path.insert(0, str(candidate))
import receiving, offline_native
args = sys.argv[3:]
out = Path(args[args.index('--output') + 1])
if mode == 'ambient-inbox':
    import types
    ambient = types.ModuleType('recipient_inbox')
    ambient.__file__ = str(out.parent / 'ambient/recipient_inbox.py')
    ambient.Engine = ambient.Inbox = object
    sys.modules['recipient_inbox'] = ambient
def replay(*unused):
    (out.parent / 'native-mock-called').write_text(mode)
    if mode == 'spawn-error':
        raise OSError('regression: simulated native spawn failure')
    if mode == 'native-error':
        return ({'state': 'evaluator_error', 'error': 'regression_failure'}, b'', b'', {})
    if mode == 'refused':
        payload = {'type': 'musubi.ca2a.pilot-settlement.v0', 'profile': receiving.PROFILE,
                   'refused': 'unreadable_input'}
        return ({'state': 'process_completed', 'exit_code': 3}, receiving.encoded(payload), b'', {})
    selection = json.loads((candidate / 'sample/selection.json').read_text())
    stdout = (candidate / 'sample/originals' / selection['reference_output']['path']).read_bytes() + b'\n'
    if mode.startswith('native-malformed-'):
        payload = receiving.decode(stdout)
        if mode == 'native-malformed-pilot': payload['pilot'] = []
        elif mode == 'native-malformed-row': payload['pilot']['executions'][0] = []
        else: payload['pilot']['executions'][0]['seq'] = True
        stdout = receiving.encoded(payload)
    return ({'state': 'process_completed', 'exit_code': 0, 'regression_test_double': True},
            stdout, b'', {})
offline_native.replay = replay
sys.argv = ['receiving.py'] + args
sys.exit(receiving.main())
'''

cases = []
root_cases = ('empty-vate-root', 'missing-vate-root', 'file-vate-root',
              'broken-inbox-import', 'missing-inbox-export', 'ambient-inbox')
for name in (a.case or ('time-null', 'time-number', 'empty-database', 'unrelated-database',
             'spawn-error', 'native-error', 'evaluated', 'refused', 'argument-error',
             'native-malformed-pilot', 'native-malformed-row', 'native-malformed-identity', *root_cases)):
    case = a.output / name; case.mkdir()
    selection = json.loads((a.candidate / 'sample/selection.json').read_text())
    if name in ('time-null', 'time-number'):
        selection['assessment_time'] = None if name == 'time-null' else 1
    (case / 'selection.json').write_text(json.dumps(selection))
    db = case / 'inbox.sqlite'
    if name == 'empty-database':
        db.touch()
    if name == 'unrelated-database':
        with sqlite3.connect(db) as connection:
            connection.execute('CREATE TABLE unrelated (value TEXT)')
    vate_root = a.vate_root
    if name in root_cases:
        vate_root = case / 'selected-vate'
        if name == 'empty-vate-root':
            vate_root.mkdir()
        elif name == 'file-vate-root':
            vate_root.write_text('not a source directory')
        elif name in ('broken-inbox-import', 'missing-inbox-export', 'ambient-inbox'):
            module = vate_root / 'reference/recipient-inbox/recipient_inbox.py'
            module.parent.mkdir(parents=True)
            module.write_text('import missing_vate_regression_dependency\n' if name == 'broken-inbox-import'
                              else 'class Engine: pass\n' if name == 'missing-inbox-export'
                              else 'class Engine: pass\nclass Inbox: pass\n')
    inputs = {'originals': a.candidate / 'sample/originals',
              'manifest': a.candidate / 'sample/manifest.json', 'selection': case / 'selection.json',
              'source': a.candidate / 'sample/evaluator-source', 'runtime': a.environment / 'venv',
              'evaluator': a.environment / 'evaluator.json', 'vate-root': vate_root,
              'database': db, 'output': case / 'output'}
    cmd = [sys.executable, '-B', '-c', wrapper, str(a.candidate), name]
    for key, value in inputs.items():
        cmd.extend(['--' + key, str(value)])
    if name == 'argument-error':
        cmd.append('--not-an-option')
    result = subprocess.run(cmd, capture_output=True, timeout=60)
    (case / 'stdout.txt').write_bytes(result.stdout); (case / 'stderr.txt').write_bytes(result.stderr)
    error_path = case / 'output/ERROR.json'; result_path = case / 'output/RESULT.json'
    row = {'case': name, 'exit_code': result.returncode,
           'error_json_exists': error_path.exists(), 'result_json_exists': result_path.exists(),
           'native_mock_called': (case / 'native-mock-called').exists()}
    if name == 'argument-error':
        assert result.returncode == 2 and not result.stdout and not row['native_mock_called'], row
        assert not error_path.exists() and not result_path.exists(), row
    else:
        assert not result.stderr, result.stderr.decode()
        payload = json.loads(result.stdout); row['response'] = payload
        if name in ('evaluated', 'refused', 'native-error') or name.startswith('native-malformed-'):
            is_error = name == 'native-error' or name.startswith('native-malformed-')
            expected = 'recorded_evaluator_error' if is_error else 'recorded'
            assert payload['status'] == expected, row
            assert result.returncode == (64 if is_error else 0), row
            assert payload['native_state'] == ('evaluator_error' if is_error else name), row
            assert result_path.exists() and not error_path.exists(), row
            if name.startswith('native-malformed-'):
                report = json.loads((case/'output/assessment.json').read_text())
                assert report['overall_evidence_state'] == 'partial'
                assert sum(x['binding_status'] == 'bound' for x in report['requirements']) == 9
                assert all(x['semantic_assessment'] == 'unassessed' for x in report['requirements'])
                with sqlite3.connect(db) as connection:
                    assert connection.execute('SELECT status FROM runs').fetchall() == [('completed',)]
        else:
            assert result.returncode == 64 and payload['status'] == 'input_or_storage_error', row
            assert error_path.exists() and not result_path.exists(), row
            assert json.loads(error_path.read_text()) == payload, row
            expected = ('InputError' if name.startswith('time-') or name in root_cases else 'OperationalError'
                        if name.endswith('database') else 'OSError')
            assert payload['error_type'] == expected, row
            if name.startswith('time-') or name in root_cases:
                assert not row['native_mock_called'] and not db.exists(), row
    cases.append(row)
summary = {'status': 'pass', 'python': sys.version,
           'scope': 'Real CLI and Inbox; native replay test double only', 'cases': cases}
(a.output / 'RESULT.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps({'status': 'pass', 'cases': len(cases)}))
