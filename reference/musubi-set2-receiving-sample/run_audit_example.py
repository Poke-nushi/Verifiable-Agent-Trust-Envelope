"""Receive the fixed baseline, then the public A/C audit and dataset originals."""
from __future__ import annotations

import argparse
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace

from prepare_environment import ROOT, check_environment, check_vate
from receiving import SavedOutputError, decode, encoded, failure_result, need, read, run, sha, write_json


def example(vate_root, environment, output, completed):
    environment = environment.resolve()
    need(Path(sys.prefix).resolve() == environment / 'venv',
         'run with the prepared environment/venv/bin/python -B')
    check_environment(environment)
    check_vate(vate_root)
    output = output.resolve()
    need(not output.is_relative_to(ROOT) and not output.is_relative_to(environment),
         'put results outside the sample and prepared runtime directories')
    output.mkdir(parents=True, exist_ok=False)
    args = dict(originals=ROOT/'sample/originals', manifest=ROOT/'sample/manifest.json',
                selection=ROOT/'sample/selection.json', source=ROOT/'sample/evaluator-source',
                runtime=environment/'venv', evaluator=environment/'evaluator.json',
                vate_root=vate_root.resolve(), database=output/'inbox.sqlite', output=output/'baseline',
                view=None, previous=None)
    baseline = run(SimpleNamespace(**args))
    completed.append(baseline['recovery'])
    need(baseline['native_state'] == 'evaluated' and baseline['comparison']['exact_bytes'],
         'baseline differs from the fixed native result; inspect its saved result')
    original_assessment = read(output/'baseline', 'assessment.json')
    args.update(manifest=ROOT/'sample/audit-manifest.json', selection=ROOT/'sample/audit-selection.json',
                previous=output/'baseline/RESULT.json', output=output/'audits')
    added = run(SimpleNamespace(**args))
    completed.append(added['recovery'])
    need(added['native_state'] == 'evaluated' and added['comparison']['exact_bytes'],
         'additional originals changed the native result; inspect both saved assessments')
    need(added['overall_evidence_state'] == 'partial', 'missing evidence must remain partial')
    assessment = decode(read(output/'audits', 'assessment.json'))
    records = {r['id']: r for r in assessment['requirements']}
    for case in ('A', 'C'):
        for kind in ('audit_original', 'dataset_original'):
            r = records['hs51-musubi-2-' + case + ':' + kind]
            need(r['binding_status'] == 'bound' and r['semantic_assessment'] == 'digest_linkage_checked',
                 'A/C published digest linkage did not check')
    for kind in ('audit_original', 'dataset_original', 'acceptance'):
        need(records['hs51-musubi-2-B:' + kind]['binding_status'] == 'not_received',
             'B evidence was filled in without an original')
    need(all(row['accepted'] is None for row in assessment['native']['output']['pilot']['executions']),
         'new originals must not create acceptance')
    historical = read(output/'audits/export', baseline['assessment_ref']['path'])
    need(historical == original_assessment == read(output/'baseline', 'assessment.json'),
         'old assessment changed')
    # Read both originals back from the final export and check their retained refs.
    restored = {}
    for name in ('supplementary/audit-A-C.json', 'supplementary/souba-db.json'):
        ref = added['original_refs'][name]
        raw = read(output/'audits/export', ref['path'])
        need(sha(raw) == ref['digest']['value'] and len(raw) == ref['byte_length']
             and raw == read(ROOT/'sample/originals', name), 'additional original did not restore exactly')
        restored[name] = ref['digest']['value']
    summary = {'status': 'recorded', 'overall_evidence_state': 'partial',
               'native_raw_sha256': added['comparison']['actual_raw_sha256'],
               'native_output_unchanged': True, 'old_assessment_preserved': True,
               'baseline_run': baseline['inbox']['run_id'], 'audit_run': added['inbox']['run_id'],
               'additional_originals': restored,
               'linked_occurrences': ['hs51-musubi-2-A', 'hs51-musubi-2-C'],
               'missing_audit_occurrences': ['hs51-musubi-2-B'],
               'claim_scope': 'published_digest_linkage_only', 'native_acceptance': None}
    write_json(output/'AUDIT-EXAMPLE.json', summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('vate-root', 'environment', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    completed = []
    try:
        summary = example(args.vate_root, args.environment, args.output, completed)
        print(encoded(summary).decode(), end='')
        return 0
    except SavedOutputError as exc:
        print(encoded(failure_result(exc)).decode(), end='')
        return 64
    except (ValueError, KeyError, TypeError, OSError, sqlite3.Error) as exc:
        print(encoded({'status': 'audit_example_error', 'error': str(exc),
                       'completed_runs': completed,
                       'next': 'keep the database and output; an error does not imply rollback'}).decode(), end='')
        return 64


if __name__ == '__main__':
    raise SystemExit(main())
