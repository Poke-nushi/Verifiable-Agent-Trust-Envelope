"""Rebuild one completed run's outputs from its Inbox; never evaluate or receive."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sqlite3
import sys

from prepare_environment import ROOT, check_vate
from receiving import (MIB, decode, encoded, load_inbox, make_summary,
                       need, read, relative, sha, write_json)


def receipt_from(path):
    # RESULT includes comparison details and payload refs, not just a small receipt.
    value = decode(read(path.parent, path.name, 2 * MIB))
    need(type(value) is dict, 'recovery receipt must be an object')
    receipt = value.get('recovery', value)
    fields = {'contract', 'database', 'run_id', 'receiver_id', 'namespace',
              'selection_ref', 'assessment_ref', 'report_ref'}
    need(type(receipt) is dict and set(receipt) == fields
         and receipt['contract'] == 'musubi-set2-output-recovery-1', 'unknown recovery receipt')
    for name in ('database', 'run_id', 'receiver_id', 'namespace'):
        need(type(receipt[name]) is str and bool(receipt[name]), 'invalid recovery ' + name)
    need(re.fullmatch(r'[0-9a-f-]{36}', receipt['run_id']), 'invalid recovery run ID')
    for name in ('selection_ref', 'assessment_ref', 'report_ref'):
        check_ref(receipt[name])
    return receipt


def check_ref(ref):
    need(type(ref) is dict and set(ref) == {'path_base', 'path', 'media_type', 'digest_basis',
                                          'digest', 'byte_length'}, 'invalid stored reference')
    d = ref['digest']
    need(type(d) is dict and set(d) == {'alg', 'value'} and d['alg'] == 'sha-256'
         and type(d['value']) is str and re.fullmatch('[0-9a-f]{64}', d['value']), 'invalid stored digest')
    need(ref['path_base'] == 'inbox' and ref['path'] == 'objects/' + d['value']
         and ref['digest_basis'] == 'raw_file_sha256'
         and type(ref['media_type']) is str and bool(ref['media_type'])
         and type(ref['byte_length']) is int and 0 <= ref['byte_length'] <= 2*MIB,
         'invalid stored reference shape or bound')


def saved_bytes(root, ref):
    check_ref(ref)
    raw = read(root, ref['path'])
    need(sha(raw) == ref['digest']['value'] and len(raw) == ref['byte_length'],
         'exported object does not match its stored reference')
    return raw


def rebuild(root, receipt, state, exported):
    # Join through the exported run/job, never through refs supplied independently.
    runs = decode(read(root, 'runs.json'))
    need(runs['selected'] == receipt['run_id'], 'export selected another run')
    row = runs['runs'][0]
    need(row['run_id'] == receipt['run_id'] and row['status'] == 'completed', 'run not completed')
    job = decode(saved_bytes(root, row['job_ref']))
    need((job['run_id'], job['receiver_id'], job['namespace']) ==
         (receipt['run_id'], receipt['receiver_id'], receipt['namespace']), 'recovery stream mismatch')
    core_raw = saved_bytes(root, job['selection_ref'])
    need(core_raw == read(root, 'selection.json'), 'export selection mismatch')
    core = decode(core_raw)
    need(core['selection_basis_ref'] == receipt['selection_ref']
         and core['receiver_id'] == receipt['receiver_id']
         and core['review_set_ref'] == job['review_set_ref']
         and core['submission_snapshot_ref'] == job['snapshot_ref'], 'recovery selection mismatch')
    review_raw = saved_bytes(root, core['review_set_ref'])
    review = decode(review_raw)
    need(review['review_set_id'] == 'musubi-set2-retention' and review['requirements'] == []
         and review['namespace'] == receipt['namespace']
         and len(review['population_basis_refs']) == 2, 'run is not this receiving adapter')
    index = decode(saved_bytes(root, review['population_basis_refs'][1]))
    need(type(index) is dict and 0 < len(index) <= 256, 'invalid application index')
    need(index['evaluation/assessment.json'] == receipt['assessment_ref'], 'recovery assessment mismatch')
    selection = decode(saved_bytes(root, receipt['selection_ref']))
    need((selection['receiver_id'], selection['namespace']) ==
         (receipt['receiver_id'], receipt['namespace']), 'stored receiver selection mismatch')
    need(saved_bytes(root, index['evaluation/selection.json']) ==
         saved_bytes(root, receipt['selection_ref']), 'payload selection mismatch')
    report_raw = saved_bytes(root, receipt['report_ref'])
    result = decode(saved_bytes(root, row['result_ref']))
    need(result['report_ref'] == receipt['report_ref'] == state['report_ref']
         and report_raw == read(root, 'report.json'), 'recovery report mismatch')
    report = decode(report_raw)
    # The receipt pins this report. Bind the reconstructed index to the selection
    # it actually assessed, even if valid objects/job refs were spliced in the DB.
    for field, raw in (('selection_identity', core_raw), ('review_set_identity', review_raw),
                       ('submission_snapshot_identity', saved_bytes(root, job['snapshot_ref']))):
        need(report[field] == {'raw_sha256': sha(raw), 'byte_length': len(raw)},
             'stored report does not bind recovered ' + field)
    need(report['selection'] == core, 'stored report selection mismatch')
    need(report['review_set_status'] == 'selected_empty' and report['requirements'] == []
         and report['native_calls'] == [] and report['invocation_errors'] is False,
         'unexpected stored core semantics')
    assessment = decode(saved_bytes(root, receipt['assessment_ref']))
    need(assessment['contract'] == 'local-musubi-set2-receiving-1', 'unknown stored assessment')
    for field in ('experiment', 'run', 'question', 'assessment_time'):
        need(assessment[field] == selection[field], 'assessment selection mismatch: ' + field)
    prior = assessment['previous']
    need((prior['run_id'] if prior else None) == job['previous_id'] == state['previous_id'],
         'assessment history mismatch')
    need(assessment['native']['state'] in ('evaluated', 'refused', 'evaluator_error'),
         'unknown saved evaluator state')
    originals, payloads, restored = {}, {}, {}
    total = 0
    for name, ref in index.items():
        relative(name)
        group, separator, tail = name.partition('/')
        need(separator and group in ('originals', 'evaluation'), 'unknown indexed material')
        relative(tail)
        raw = saved_bytes(root, ref)
        total += len(raw)
        need(total <= 16*MIB, 'restored material bound')
        if group == 'originals':
            originals[tail] = ref
        elif tail != 'assessment.json':
            payloads[tail] = ref
        # Restore payloads in a separate folder; their names never select RESULT/export paths.
        restored[name] = raw
    summary = make_summary(assessment, {'inbox': state, 'export': exported,
        'original_refs': originals, 'selection_ref': receipt['selection_ref'],
        'assessment_ref': receipt['assessment_ref'], 'payload_refs': payloads,
        'recovery': receipt})
    return summary, assessment, restored


def recover(vate_root, database, receipt, output):
    check_vate(vate_root)
    Engine, Inbox = load_inbox(vate_root.resolve())
    output = output.absolute()
    need(not output.resolve().is_relative_to(ROOT), 'put recovered outputs outside the sample')
    # Existing DB only: a typo must not create an empty replacement database.
    box = Inbox(database, Engine(vate_root), create=False)
    try:
        state = box.status(receipt['run_id'])
        need(state['status'] == 'completed', 'recovery requires a completed run')
        need(state['report_ref'] == receipt['report_ref'], 'saved report differs from recovery receipt')
        output.mkdir(parents=True, exist_ok=False)
        exported = box.export(receipt['run_id'], output / 'export')
        summary, assessment, restored = rebuild(output / 'export', receipt, state, exported)
        write_json(output / 'RECOVERY.json', receipt)
        for name, raw in restored.items():
            path = output / 'materials' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as stream:
                stream.write(raw)
        write_json(output / 'assessment.json', assessment)
        write_json(output / 'RESULT.json', summary)
        return summary
    finally:
        box.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('vate-root', 'database', 'receipt', 'output'):
        ap.add_argument('--' + name, type=Path, required=True)
    a = ap.parse_args()
    receipt = None
    try:
        receipt = receipt_from(a.receipt)
        summary = recover(a.vate_root, a.database, receipt, a.output)
        print(encoded({'status': 'output_recovered', 'run_id': receipt['run_id'],
                       'saved_status': summary['status'], 'native_state': summary['native_state'],
                       'overall_evidence_state': summary['overall_evidence_state'],
                       'result': str(a.output.absolute() / 'RESULT.json')}).decode(), end='')
        return 0 if summary['status'] == 'recorded' else 64
    except (KeyError, IndexError, TypeError, ValueError, OSError, sqlite3.Error) as exc:
        # Never write to an existing/partially created directory on failure.
        print(encoded({'status': 'output_recovery_error', 'error_type': type(exc).__name__,
                       'detail': str(exc), 'recovery': receipt}).decode(), end='')
        return 64


if __name__ == '__main__':
    sys.exit(main())
