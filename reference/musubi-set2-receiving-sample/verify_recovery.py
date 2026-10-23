"""Fault injection against real SQLite/Inbox; only native replay is substituted."""
from __future__ import annotations

import argparse
from contextlib import ExitStack, redirect_stdout
import copy
import io
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

import offline_native
import receiving as r
import recover_output as recovery
import run_example


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('vate-root', 'environment', 'output'):
        ap.add_argument('--' + name, type=Path, required=True)
    a = ap.parse_args()
    root = Path(__file__).resolve().parent
    sample = root/'sample'
    output = a.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    vate = a.vate_root.resolve(); environment = a.environment.resolve()
    Engine, Inbox = r.load_inbox(vate)
    inbox_module = sys.modules[Inbox.__module__]
    selection = r.decode((sample/'selection.json').read_bytes())
    raw = (sample/'originals'/selection['reference_output']['path']).read_bytes() + b'\n'
    original_write, original_export = r.write_json, Inbox.export
    original_read = inbox_module.read_file
    cases = []
    native_calls = []

    def native(mode='evaluated'):
        def replay(*args):
            native_calls.append(mode)
            if mode == 'evaluator_error':
                return {'state': 'evaluator_error', 'error': 'injected'}, b'', b'', {}
            if mode == 'refused':
                return ({'state': 'process_completed', 'exit_code': 3},
                        r.encoded({'type': 'musubi.ca2a.pilot-settlement.v0', 'profile': r.PROFILE,
                                   'refused': 'unreadable_input'}), b'', {})
            payload = r.decode(raw)
            if r.decode(args[3])['view'] != r.decode((sample/'originals'/selection['bundle']['path']).read_bytes())['view']:
                payload['companion']['log']['anchor_depth'] = 14
                data = r.encoded(payload)
            else:
                data = raw
            return {'state': 'process_completed', 'exit_code': 0}, data, b'', {}
        return replay

    def inputs(folder, **changes):
        values = dict(originals=sample/'originals', manifest=sample/'manifest.json',
            selection=sample/'selection.json', source=sample/'evaluator-source', runtime=environment/'venv',
            evaluator=environment/'evaluator.json', vate_root=vate, database=folder/'inbox.sqlite',
            output=folder/'run', previous=None, view=None)
        values.update(changes)
        return SimpleNamespace(**values)

    def cli_args(args):
        argv = ['receiving.py']
        for k, v in vars(args).items():
            if v is not None: argv.extend(['--' + k.replace('_', '-'), str(v)])
        return argv

    def db_state(db):
        with sqlite3.connect(db) as con:
            counts = {t: con.execute('SELECT count(*) FROM '+t).fetchone()[0]
                      for t in ('objects', 'entries', 'deliveries', 'slots', 'runs', 'heads')}
            runs = con.execute('SELECT run_id,status FROM runs ORDER BY run_id').fetchall()
            heads = con.execute('SELECT * FROM heads ORDER BY stream_id').fetchall()
        return {'sha256': r.sha(db.read_bytes()), 'counts': counts, 'runs': runs, 'heads': heads}

    def safe_recover(db, receipt, out):
        before = db_state(db); calls = len(native_calls)
        with ExitStack() as stack:
            stack.enter_context(patch.object(offline_native, 'replay', side_effect=AssertionError('replay during recovery')))
            for name in ('put', 'receive', 'prepare', 'run'):
                stack.enter_context(patch.object(Inbox, name, side_effect=AssertionError(name+' during recovery')))
            result = recovery.recover(vate, db, receipt, out)
        assert db_state(db) == before and len(native_calls) == calls
        assert r.decode((out/'RESULT.json').read_bytes()) == result
        assert result['overall_evidence_state'] == 'partial'
        return result

    # The CLI must return a receipt even if neither RECOVERY nor ERROR can be written.
    failures = ('export', 'result', 'recovery_receipt', 'export_and_error', 'receipt_and_error',
                'partial_export', 'export_readback_mismatch')
    saved = {}
    for mode in failures:
        folder = output/mode; folder.mkdir()
        args = inputs(folder)
        def write(path, value):
            if (path.name == 'RESULT.json' and mode == 'result') or (
                path.name == 'RECOVERY.json' and mode in ('recovery_receipt', 'receipt_and_error')) or (
                path.name == 'ERROR.json' and mode in ('export_and_error', 'receipt_and_error')):
                path.with_name(path.name+'.tmp').write_bytes(b'{')
                raise OSError('injected output failure: '+path.name)
            return original_write(path, value)
        def export(box, run_id, destination):
            if mode == 'partial_export':
                destination.mkdir(); (destination/'incomplete').write_bytes(b'partial')
                raise OSError('injected mid-export failure')
            if mode in ('export', 'export_and_error'):
                raise OSError('injected export failure')
            return original_export(box, run_id, destination)
        def read_back(path, *other, **kw):
            value = original_read(path, *other, **kw)
            if mode == 'export_readback_mismatch' and Path(path).is_relative_to(args.output/'export'):
                return value + b'!'  # Real export detects a mismatching read after writing.
            return value
        stdout = io.StringIO()
        with patch.object(offline_native, 'replay', native()), patch.object(r, 'write_json', write), \
             patch.object(Inbox, 'export', export), patch.object(inbox_module, 'read_file', read_back), \
             patch.object(sys, 'argv', cli_args(args)), redirect_stdout(stdout):
            code = r.main()
        message = r.decode(stdout.getvalue().encode())
        assert code == 64 and message['status'] == 'saved_output_error', message
        if mode == 'export_readback_mismatch':
            assert message['phase'] == 'export' and message['error_type'] == 'InboxError'
        assert not (args.output/'RESULT.json').exists()
        state = db_state(args.database)
        assert len(state['runs']) == 1 and state['runs'][0][1] == 'completed'
        assert state['heads'][0][1] == message['recovery']['run_id']
        (folder/'stdout.json').write_text(stdout.getvalue())
        receipt = recovery.receipt_from(folder/'stdout.json')
        recovered = safe_recover(args.database, receipt, folder/'recovered')
        assert recovered['native_state'] == 'evaluated' and recovered['comparison']['exact_bytes']
        assert recovered['inbox']['run_id'] == message['recovery']['run_id']
        again = safe_recover(args.database, receipt, folder/'recovered-again')
        assert again['assessment_ref'] == recovered['assessment_ref']
        for name, ref in recovered['original_refs'].items():
            assert (folder/'recovered/materials/originals'/name).read_bytes() == (sample/'originals'/name).read_bytes()
        saved[mode] = (args.database, receipt, recovered)
        cases.append({'case': mode, 'status': 'pass', 'completed_runs': 1, 'recovery_count': 2,
                      'originals_restored': len(recovered['original_refs']), 'database_unchanged': True})

    # Do not classify an unrelated export integrity failure as a writable-output failure.
    folder = output/'export-integrity-error'; folder.mkdir()
    args = inputs(folder)
    with patch.object(offline_native, 'replay', native()), \
         patch.object(Inbox, 'export', side_effect=inbox_module.InboxError('DIGEST_MISMATCH', 'corrupt object')), \
         patch.object(sys, 'argv', cli_args(args)), redirect_stdout(io.StringIO()) as stream:
        code = r.main()
    message = r.decode(stream.getvalue().encode())
    assert code == 64 and message['status'] == 'input_or_storage_error'
    assert 'recovery' not in message and not (args.output/'RESULT.json').exists()
    assert (args.output/'RECOVERY.json').is_file()
    assert len(db_state(args.database)['runs']) == 1
    cases.append({'case': 'other-export-integrity-error-is-not-output-failure', 'status': 'pass'})

    # A real second writer can block export's read transaction after the save committed.
    folder = output/'post-completion-lock'; folder.mkdir()
    args = inputs(folder)
    held = []
    real_run = Inbox.run
    def run_then_lock(box, run_id):
        state = real_run(box, run_id)
        blocker = sqlite3.connect(args.database, isolation_level=None)
        blocker.execute('BEGIN IMMEDIATE')
        held.append(blocker)
        box.db.execute('PRAGMA busy_timeout=30')
        return state
    stream = io.StringIO()
    try:
        with patch.object(offline_native, 'replay', native()), patch.object(Inbox, 'run', run_then_lock), \
             patch.object(sys, 'argv', cli_args(args)), redirect_stdout(stream):
            code = r.main()
    finally:
        for blocker in held:
            blocker.rollback(); blocker.close()
    message = r.decode(stream.getvalue().encode())
    assert code == 64 and message['status'] == 'saved_output_error'
    assert message['phase'] == 'export' and message['error_type'] == 'OperationalError'
    assert r.decode((args.output/'ERROR.json').read_bytes()) == message
    state = db_state(args.database)
    assert len(state['runs']) == 1 and state['runs'][0][1] == 'completed'
    safe_recover(args.database, message['recovery'], folder/'recovered')
    cases.append({'case': 'post-completion-sqlite-lock', 'status': 'pass',
                  'error_type': message['error_type'], 'completed_runs': 1})

    db, receipt, first = saved['export']
    # A recovered RESULT is a usable predecessor; old runs remain recoverable after the head moves.
    with patch.object(offline_native, 'replay', native()):
        second = r.run(inputs(output/'export', selection=sample/'extended-selection.json',
            view=sample/'extended-view.json', previous=output/'export/recovered/RESULT.json',
            output=output/'export/extended'))
    assert second['inbox']['previous_id'] == first['inbox']['run_id']
    # Full evaluated RESULTs exceed 64 KiB; the documented --receipt form must work.
    extended_result = output/'export/extended/RESULT.json'
    assert extended_result.stat().st_size > 64 * 1024
    before = db_state(db)
    cmd = [sys.executable, '-B', str(root/'recover_output.py'), '--vate-root', str(vate),
           '--database', str(db), '--receipt', str(extended_result),
           '--output', str(output/'extended-result-recovered')]
    proc = subprocess.run(cmd, capture_output=True, timeout=60)
    assert proc.returncode == 0 and not proc.stderr, proc.stderr
    reply = r.decode(proc.stdout)
    assert reply['status'] == 'output_recovered' and reply['run_id'] == second['inbox']['run_id']
    assert db_state(db) == before
    cases.append({'case': 'full-extended-result-as-receipt', 'status': 'pass',
                  'result_bytes': extended_result.stat().st_size})
    historical = safe_recover(db, receipt, output/'historical')
    assert historical['inbox']['head'] == second['inbox']['run_id']
    assert historical['assessment_ref'] == first['assessment_ref']
    cases.append({'case': 'recovered_predecessor_and_historical_export', 'status': 'pass'})

    def rejected(name, test_db, test_receipt, out=None):
        before = db_state(test_db) if test_db.exists() else None
        out = out or output/name
        try:
            safe_recover(test_db, test_receipt, out)
        except (ValueError, KeyError, TypeError, OSError, sqlite3.Error):
            pass
        else:
            raise AssertionError('accepted '+name)
        assert not (out/'RESULT.json').exists()
        assert before == (db_state(test_db) if test_db.exists() else None)
        cases.append({'case': name, 'status': 'pass', 'database_unchanged': True})

    for field, replacement in (('run_id', '00000000-0000-0000-0000-000000000000'),
                               ('receiver_id', 'another-receiver'), ('namespace', 'another-namespace'),
                               ('selection_ref', second['selection_ref']), ('assessment_ref', second['assessment_ref']),
                               ('report_ref', second['selection_ref'])):
        altered = copy.deepcopy(receipt); altered[field] = replacement
        rejected('mixed-'+field, db, altered)
    rejected('wrong-database', saved['result'][0], receipt)
    existing = output/'existing'; existing.mkdir(); (existing/'keep').write_bytes(b'keep')
    rejected('existing-output', db, receipt, existing)
    assert list(existing.iterdir()) == [existing/'keep'] and (existing/'keep').read_bytes() == b'keep'
    linked = output/'linked'; linked.symlink_to(existing, target_is_directory=True)
    rejected('symlink-output', db, receipt, linked)

    corrupt = output/'corrupt.sqlite'; shutil.copy2(db, corrupt)
    with sqlite3.connect(corrupt) as con:
        con.execute('UPDATE objects SET raw=? WHERE digest=?',
                    (b'corrupt', receipt['assessment_ref']['digest']['value']))
    rejected('corrupt-object', corrupt, receipt)
    incomplete = output/'incomplete.sqlite'; shutil.copy2(db, incomplete)
    with sqlite3.connect(incomplete) as con:
        con.execute('UPDATE runs SET status=? WHERE run_id=?', ('prepared', receipt['run_id']))
    rejected('incomplete-run', incomplete, receipt)

    # Keep the pinned report and assessment, but splice a different valid original
    # through new index/review/selection/job objects in a copied database.
    spliced = output/'spliced-index.sqlite'; shutil.copy2(db, spliced)
    with sqlite3.connect(spliced) as con:
        def get(ref):
            data = con.execute('SELECT raw FROM objects WHERE digest=?',
                               (ref['digest']['value'],)).fetchone()[0]
            assert r.sha(data) == ref['digest']['value']
            return r.decode(data)
        def put(value):
            data = r.encoded(value); digest = r.sha(data)
            con.execute('INSERT INTO objects VALUES (?,?)', (digest, data))
            return {'path_base': 'inbox', 'path': 'objects/'+digest, 'media_type': 'application/json',
                    'digest_basis': 'raw_file_sha256', 'digest': {'alg': 'sha-256', 'value': digest},
                    'byte_length': len(data)}
        job_ref = r.decode(con.execute('SELECT job_ref FROM runs WHERE run_id=?',
                                     (receipt['run_id'],)).fetchone()[0].encode())
        job = get(job_ref); core = get(job['selection_ref']); review = get(job['review_set_ref'])
        index = get(review['population_basis_refs'][1])
        names = [n for n in index if n.startswith('originals/')]
        victim, donor = names[:2]
        assert index[victim] != index[donor]
        index[victim] = index[donor]
        index_ref = put(index); review['population_basis_refs'][1] = index_ref
        review_ref = put(review); core['review_set_ref'] = review_ref
        core_ref = put(core); job['review_set_ref'] = review_ref; job['selection_ref'] = core_ref
        job['assets'].extend([index_ref, review_ref, core_ref])
        new_job_ref = put(job)
        con.execute('UPDATE runs SET job_ref=? WHERE run_id=?',
                    (r.encoded(new_job_ref).decode(), receipt['run_id']))
    rejected('report-index-splice', spliced, receipt)
    assert not (output/'report-index-splice/materials').exists()

    for mode in ('refused', 'evaluator_error'):
        folder = output/mode; folder.mkdir()
        with patch.object(offline_native, 'replay', native(mode)):
            result = r.run(inputs(folder))
        recovered = safe_recover(folder/'inbox.sqlite', result['recovery'], folder/'recovered')
        assert recovered['status'] == result['status'] and recovered['native_state'] == mode
        cmd = [sys.executable, '-B', str(root/'recover_output.py'), '--vate-root', str(vate),
               '--database', str(folder/'inbox.sqlite'), '--receipt', str(folder/'run/RESULT.json'),
               '--output', str(folder/'cli-recovered')]
        before = db_state(folder/'inbox.sqlite')
        proc = subprocess.run(cmd, capture_output=True, timeout=60)
        assert not proc.stderr and proc.returncode == (0 if mode == 'refused' else 64), proc.stderr
        reply = r.decode(proc.stdout)
        assert reply['status'] == 'output_recovered' and reply['native_state'] == mode
        assert db_state(folder/'inbox.sqlite') == before
        cases.append({'case': 'preserve-'+mode, 'status': 'pass', 'exit_code': proc.returncode})

    # Second output failure leaves the existing DB and original receipt usable.
    before = db_state(db)
    with patch.object(Inbox, 'export', side_effect=OSError('second output failure')), \
         patch.object(sys, 'argv', ['recover_output.py', '--vate-root', str(vate), '--database', str(db),
                                  '--receipt', str(output/'export/stdout.json'), '--output', str(output/'retry-error')]):
        stream = io.StringIO()
        with redirect_stdout(stream): code = recovery.main()
    reply = r.decode(stream.getvalue().encode())
    assert code == 64 and reply['status'] == 'output_recovery_error' and reply['recovery'] == receipt
    assert db_state(db) == before
    safe_recover(db, receipt, output/'retry-success')
    cases.append({'case': 'recovery-failure-then-retry', 'status': 'pass'})

    # Fail after export as well, including partially restored materials.
    for mode in ('RECOVERY.json', 'materials', 'assessment.json', 'RESULT.json'):
        folder = output/('late-'+mode); before = db_state(db)
        original_open = Path.open
        material_writes = []
        def late_write(path, value):
            if path.name == mode:
                raise OSError('injected recovery write failure: '+mode)
            return original_write(path, value)
        def open_material(path, *args, **kwargs):
            if mode == 'materials' and path.is_relative_to(folder/'materials') and args == ('xb',):
                if len(material_writes) == 2:
                    raise OSError('injected partial materials failure')
                material_writes.append(path)
            return original_open(path, *args, **kwargs)
        with ExitStack() as stack:
            stack.enter_context(patch.object(offline_native, 'replay', side_effect=AssertionError('replay during recovery')))
            for name in ('put', 'receive', 'prepare', 'run'):
                stack.enter_context(patch.object(Inbox, name, side_effect=AssertionError(name+' during recovery')))
            stack.enter_context(patch.object(recovery, 'write_json', late_write))
            stack.enter_context(patch.object(Path, 'open', open_material))
            stack.enter_context(patch.object(sys, 'argv', ['recover_output.py', '--vate-root', str(vate),
                '--database', str(db), '--receipt', str(output/'export/stdout.json'), '--output', str(folder)]))
            stream = stack.enter_context(redirect_stdout(io.StringIO()))
            code = recovery.main()
        reply = r.decode(stream.getvalue().encode())
        assert code == 64 and reply['status'] == 'output_recovery_error' and reply['recovery'] == receipt
        assert db_state(db) == before and not (folder/'RESULT.json').exists()
        if mode == 'materials':
            assert len(material_writes) == 2 and all(p.is_file() for p in material_writes)
        retry = output/('late-'+mode+'-retry')
        restored = safe_recover(db, receipt, retry)
        assert restored['assessment_ref'] == first['assessment_ref']
        for name in restored['original_refs']:
            assert (retry/'materials/originals'/name).read_bytes() == (sample/'originals'/name).read_bytes()
        cases.append({'case': 'recovery-late-failure-'+mode, 'status': 'pass',
                      'database_unchanged': True, 'originals_restored': len(restored['original_refs'])})

    # The fixed example wrapper must not discard the saved-output diagnostic.
    wrapper = output/'wrapper'
    with patch.object(offline_native, 'replay', native()), \
         patch.object(Inbox, 'export', side_effect=OSError('wrapper export failure')), \
         patch.object(sys, 'argv', ['run_example.py', '--vate-root', str(vate), '--environment', str(environment),
                                  '--output', str(wrapper)]):
        stream = io.StringIO()
        with redirect_stdout(stream): code = run_example.main()
    reply = r.decode(stream.getvalue().encode())
    assert code == 64 and reply['status'] == 'saved_output_error'
    safe_recover(wrapper/'inbox.sqlite', reply['recovery'], output/'wrapper-recovered')
    cases.append({'case': 'wrapper-preserves-receipt', 'status': 'pass'})

    wrapper = output/'wrapper-summary'
    def summary_failure(path, value):
        if path.name == 'EXAMPLE.json': raise OSError('summary disk failure')
        return original_write(path, value)
    with patch.object(offline_native, 'replay', native()), patch.object(run_example, 'write_json', summary_failure), \
         patch.object(sys, 'argv', ['run_example.py', '--vate-root', str(vate), '--environment', str(environment),
                                  '--output', str(wrapper)]):
        stream = io.StringIO()
        with redirect_stdout(stream): code = run_example.main()
    reply = r.decode(stream.getvalue().encode())
    assert code == 64 and reply['status'] == 'example_error' and len(reply['completed_runs']) == 2
    assert all((wrapper/n/'RESULT.json').exists() for n in ('baseline', 'extended'))
    cases.append({'case': 'wrapper-summary-failure-keeps-both-results', 'status': 'pass'})

    # Verify the receipt's file shape before touching SQLite or creating output.
    for name, value in (('bad-contract', {**receipt, 'contract': 'other'}),
                        ('extra-field', {**receipt, 'extra': 1}),
                        ('unsafe-ref', {**receipt, 'assessment_ref': {**receipt['assessment_ref'], 'path': '../outside'}})):
        p = output/(name+'.json'); p.write_bytes(r.encoded(value))
        try: recovery.receipt_from(p)
        except ValueError: pass
        else: raise AssertionError('accepted '+name)
        cases.append({'case': name, 'status': 'pass'})

    summary = {'status': 'pass', 'python': sys.version, 'cases': cases,
               'scope': 'Real SQLite/Inbox and CLI; native replay test double; no installs or network'}
    (output/'RESULT.json').write_bytes(r.encoded(summary))
    print(r.encoded({'status': 'pass', 'cases': len(cases)}).decode(), end='')


if __name__ == '__main__':
    main()
