"""Check fixed-sample continuation guards and actual isolated replay after recovery."""
from __future__ import annotations

import argparse
import copy
from contextlib import ExitStack, redirect_stdout
import io
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
from unittest.mock import patch

import continue_example as continuation
import offline_native
import receiving as r
import recover_output as recovery


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('vate-root', 'environment', 'output'):
        ap.add_argument('--' + name, type=Path, required=True)
    a = ap.parse_args()
    root = Path(__file__).resolve().parent
    environment = a.environment.resolve()
    output = a.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    cases = []

    def command(name, argv):
        proc = subprocess.run([sys.executable, '-B', str(root/argv[0]), *argv[1:]],
                              capture_output=True, timeout=180)
        (output/(name+'.stdout')).write_bytes(proc.stdout)
        (output/(name+'.stderr')).write_bytes(proc.stderr)
        assert proc.returncode == 0 and not proc.stderr, (name, proc.returncode, proc.stderr)
        return r.decode(proc.stdout)

    def state(db):
        with sqlite3.connect(db) as con:
            rows = {table: con.execute('SELECT * FROM '+table).fetchall()
                    for table in ('runs', 'heads')}
            counts = {table: con.execute('SELECT count(*) FROM '+table).fetchone()[0]
                      for table in ('objects', 'entries', 'deliveries', 'slots', 'runs', 'heads')}
        return {'sha256': r.sha(db.read_bytes()), 'rows': rows, 'counts': counts}

    # Fixed source files also work as an archive without Git metadata.
    archive = output/'vate archive'
    pin = r.decode((root/'vate-source.json').read_bytes())
    for item in pin['files']:
        src = a.vate_root/item['path']; dst = archive/item['path']
        dst.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(src, dst)
    assert not (archive/'.git').exists()
    sample = root/'sample'; db = output/'inbox.sqlite'
    baseline_out = output/'baseline'
    command('baseline', ['receiving.py', '--originals', str(sample/'originals'),
        '--manifest', str(sample/'manifest.json'), '--selection', str(sample/'selection.json'),
        '--source', str(sample/'evaluator-source'), '--runtime', str(environment/'venv'),
        '--evaluator', str(environment/'evaluator.json'), '--vate-root', str(archive),
        '--database', str(db), '--output', str(baseline_out)])
    baseline = r.decode((baseline_out/'RESULT.json').read_bytes())
    assert baseline['native_state'] == 'evaluated' and baseline['comparison']['exact_bytes']
    before = state(db)
    previous = output/'recovered/RESULT.json'
    command('recovered', ['recover_output.py', '--vate-root', str(archive), '--database', str(db),
        '--receipt', str(baseline_out/'RECOVERY.json'), '--output', str(previous.parent)])
    assert state(db) == before
    recovered = r.decode(previous.read_bytes())
    assert recovered['assessment_ref'] == baseline['assessment_ref']
    for name in recovered['original_refs']:
        assert (previous.parent/'materials/originals'/name).read_bytes() == (sample/'originals'/name).read_bytes()
    cases.append({'case': 'real-native-baseline-and-recovery', 'status': 'pass',
                  'database_unchanged_by_recovery': True, 'originals': len(recovered['original_refs'])})
    baseline_db = output/'baseline-copy.sqlite'; shutil.copy2(db, baseline_db)

    def argv(out, env=environment, database=db, predecessor=previous):
        return ['continue_example.py', '--vate-root', str(archive), '--environment', str(env),
                '--database', str(database), '--previous', str(predecessor), '--output', str(out)]

    def reject(name, error, env=environment, prefix=None, database=db, predecessor=previous):
        before = state(db); target = output/name
        with ExitStack() as stack:
            # Any call to run would be too late for these guard failures.
            run = stack.enter_context(patch.object(continuation, 'run', side_effect=AssertionError('run before guards')))
            native = stack.enter_context(patch.object(offline_native, 'replay', side_effect=AssertionError('native before guards')))
            load = stack.enter_context(patch.object(r, 'load_inbox', side_effect=AssertionError('DB before guards')))
            stack.enter_context(patch.object(sys, 'argv', argv(target, env, database, predecessor)))
            if prefix is not None:
                stack.enter_context(patch.object(sys, 'prefix', str(prefix)))
            stream = stack.enter_context(redirect_stdout(io.StringIO()))
            code = continuation.main()
        reply = r.decode(stream.getvalue().encode())
        assert code == 64 and reply['status'] == 'continuation_error' and error in reply['error'], reply
        assert not run.called and not native.called and not load.called
        assert reply['completed_runs'] == [] and not target.exists() and state(db) == before
        (output/(name+'.json')).write_bytes(r.encoded(reply))
        cases.append({'case': name, 'status': 'pass', 'no_replay_or_database_access': True,
                      'database_bytes_and_history_unchanged': True})

    changed = archive/'reference/required-records/required_records.py'
    original = changed.read_bytes()
    changed.write_bytes(original+b'\n# fixed-source rejection probe\n')
    reject('changed-vate-source', 'mismatch')
    changed.write_bytes(original)

    fixture = output/'changed-environment'; fixture.mkdir()
    config = r.decode((environment/'evaluator.json').read_bytes())
    config['source_commit'] = '0'*40
    (fixture/'evaluator.json').write_bytes(r.encoded(config))
    # Only the interpreter-prefix fixture is simulated; the template check is real.
    reject('changed-evaluator-descriptor', 'source/lock selection', fixture, fixture/'venv')
    reject('wrong-interpreter', 'prepared environment/venv/bin/python', prefix=output/'other-venv')
    missing = output/'missing.sqlite'
    reject('missing-database', 'existing database', database=missing)
    assert not missing.exists()

    # Repairing the changed source and using the original environment allows a new output.
    extended_out = output/'continued'
    reply = command('continued', argv(extended_out))
    extended = r.decode((extended_out/'RESULT.json').read_bytes())
    assert reply['native_state'] == 'evaluated' and reply['core_status'] == 'selected_empty'
    assert extended['comparison']['output_changes'] == [
        {'path': '$.companion.log.anchor_depth', 'before': 9, 'after': 14}]
    assert extended['inbox']['previous_id'] == baseline['inbox']['run_id']
    assert extended['overall_evidence_state'] == baseline['overall_evidence_state'] == 'partial'
    after = state(db)
    assert after['counts']['runs'] == before['counts']['runs']+1
    assert all(row in after['rows']['runs'] for row in before['rows']['runs'])
    command('historical', ['recover_output.py', '--vate-root', str(archive), '--database', str(db),
        '--receipt', str(baseline_out/'RECOVERY.json'), '--output', str(output/'historical')])
    assert state(db) == after
    historical = r.decode((output/'historical/RESULT.json').read_bytes())
    assert historical['assessment_ref'] == baseline['assessment_ref']
    assert historical['overall_evidence_state'] == 'partial'
    assert historical['inbox']['head'] == extended['inbox']['run_id']
    cases.append({'case': 'real-native-continuation-after-restoring-pins', 'status': 'pass',
                  'gitless_source_archive': True, 'old_assessment_preserved': True,
                  'header_delta': reply['header_delta'], 'overall_evidence_state': 'partial'})

    reject('extended-predecessor', 'fixed baseline selection', predecessor=extended_out/'RESULT.json')

    # Both a normal baseline RESULT and a recovered baseline are accepted.
    normal_db = output/'normal-baseline.sqlite'; shutil.copy2(baseline_db, normal_db)
    command('normal-baseline-continued', argv(output/'normal-baseline-continued',
            database=normal_db, predecessor=baseline_out/'RESULT.json'))
    normal = r.decode((output/'normal-baseline-continued/RESULT.json').read_bytes())
    assert normal['inbox']['previous_id'] == baseline['inbox']['run_id']
    assert normal['comparison'] == extended['comparison']
    assert state(normal_db)['counts']['runs'] == before['counts']['runs'] + 1
    cases.append({'case': 'real-native-continuation-from-normal-baseline', 'status': 'pass'})

    # A baseline-shaped ref must still belong to the actual predecessor in the DB.
    forged = copy.deepcopy(extended); forged['selection_ref'] = baseline['selection_ref']
    forged_path = output/'forged-previous.json'; forged_path.write_bytes(r.encoded(forged))
    def native(*args):
        return {'state': 'process_completed', 'exit_code': 0}, (extended_out/'native.stdout').read_bytes(), b'', {}
    with patch.object(offline_native, 'replay', native), \
         patch.object(sys, 'argv', argv(output/'forged', predecessor=forged_path)), \
         redirect_stdout(io.StringIO()) as stream:
        code = continuation.main()
    forged_reply = r.decode(stream.getvalue().encode())
    assert code == 64 and forged_reply['status'] == 'continuation_error'
    assert 'previous references do not belong' in forged_reply['error']
    assert forged_reply['completed_runs'] == [] and state(db) == after
    assert not (output/'forged/RESULT.json').exists()
    cases.append({'case': 'baseline-ref-spliced-onto-extended-run', 'status': 'pass',
                  'database_bytes_and_history_unchanged': True})

    # Saved-output diagnostics also survive this wrapper; these probes substitute replay.
    saved_db = output/'saved-output.sqlite'; shutil.copy2(baseline_db, saved_db)
    Engine, Inbox = r.load_inbox(archive)
    args = argv(output/'saved-output', database=saved_db)
    original_export = Inbox.export
    with patch.object(offline_native, 'replay', native), \
         patch.object(Inbox, 'export', side_effect=OSError('continuation output failure')), \
         patch.object(sys, 'argv', args), redirect_stdout(io.StringIO()) as stream:
        code = continuation.main()
    reply = r.decode(stream.getvalue().encode())
    # An export of the previous run occurs first, before any new run is saved.
    assert code == 64 and reply['status'] == 'continuation_error'
    assert reply['completed_runs'] == [] and state(saved_db) == before
    cases.append({'case': 'previous-export-failure-does-not-save-new-run', 'status': 'pass'})

    def export(box, run_id, destination):
        if run_id != baseline['inbox']['run_id']:
            raise OSError('output failure after continuation was saved')
        return original_export(box, run_id, destination)
    args[args.index('--output')+1] = str(output/'saved-output-retry')
    with patch.object(offline_native, 'replay', native), patch.object(Inbox, 'export', export), \
         patch.object(sys, 'argv', args), redirect_stdout(io.StringIO()) as stream:
        code = continuation.main()
    reply = r.decode(stream.getvalue().encode())
    assert code == 64 and reply['status'] == 'saved_output_error' and reply['phase'] == 'export'
    assert state(saved_db)['counts']['runs'] == before['counts']['runs']+1
    before_recovery = state(saved_db)
    with patch.object(offline_native, 'replay', side_effect=AssertionError('replay during recovery')):
        restored = recovery.recover(archive, saved_db, reply['recovery'], output/'saved-output-recovered')
    assert state(saved_db) == before_recovery
    assert restored['inbox']['run_id'] == reply['recovery']['run_id']
    cases.append({'case': 'continuation-preserves-saved-output-receipt', 'status': 'pass',
                  'recovery_database_unchanged': True})

    summary = {'status': 'pass', 'python': sys.version, 'cases': cases,
               'scope': 'Real isolated native baseline and continuation; real SQLite/Inbox; guard probes stub run/replay/Inbox; spliced-reference and output-failure probes substitute native only'}
    (output/'RESULT.json').write_bytes(r.encoded(summary))
    print(r.encoded({'status': 'pass', 'cases': len(cases)}).decode(), end='')


if __name__ == '__main__':
    main()
