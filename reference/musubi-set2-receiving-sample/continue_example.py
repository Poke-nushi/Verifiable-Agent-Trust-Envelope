"""Continue the fixed sample from a saved baseline with the extended header view."""
from __future__ import annotations

import argparse
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace

from prepare_environment import ROOT, check_environment, check_vate
from receiving import SavedOutputError, decode, encoded, failure_result, need, read, run, sha


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('vate-root', 'environment', 'database', 'previous', 'output'):
        ap.add_argument('--' + name, type=Path, required=True)
    a = ap.parse_args()
    completed = []
    try:
        environment = a.environment.resolve()
        need(Path(sys.prefix).resolve() == environment / 'venv',
             'run with the prepared environment/venv/bin/python -B')
        check_environment(environment)
        check_vate(a.vate_root)
        output = a.output.resolve()
        need(not output.is_relative_to(ROOT) and not output.is_relative_to(environment),
             'put results outside the sample and prepared runtime directories')
        need(a.database.is_file(), 'continuation requires an existing database')
        need(a.previous.is_file(), 'continuation requires the saved baseline RESULT.json')
        baseline_raw = encoded(decode(read(ROOT / 'sample', 'selection.json')))
        baseline_digest = sha(baseline_raw)
        baseline_ref = {'path_base': 'inbox', 'path': 'objects/' + baseline_digest,
                        'media_type': 'application/json', 'digest_basis': 'raw_file_sha256',
                        'digest': {'alg': 'sha-256', 'value': baseline_digest},
                        'byte_length': len(baseline_raw)}
        previous = decode(read(a.previous.parent, a.previous.name))
        need(previous['selection_ref'] == baseline_ref,
             'continuation requires the fixed baseline selection; the extended result cannot be continued again')
        result = run(SimpleNamespace(
            originals=ROOT/'sample/originals', manifest=ROOT/'sample/manifest.json',
            selection=ROOT/'sample/extended-selection.json', view=ROOT/'sample/extended-view.json',
            source=ROOT/'sample/evaluator-source', runtime=environment/'venv',
            evaluator=environment/'evaluator.json', vate_root=a.vate_root.resolve(),
            database=a.database.resolve(), previous=a.previous.resolve(), output=output))
        completed.append(result['recovery'])
        need(result['native_state'] == 'evaluated', 'extended evaluator did not complete; keep its result')
        need(result['comparison']['output_changes'] ==
             [{'path': '$.companion.log.anchor_depth', 'before': 9, 'after': 14}],
             'extended result has an unexpected change; inspect both saved assessments')
        report_ref = result['inbox']['report_ref']
        report_raw = read(output/'export', report_ref['path'])
        need(sha(report_raw) == report_ref['digest']['value'] and len(report_raw) == report_ref['byte_length'],
             'exported Inbox report differs from its stored reference')
        summary = {'status': 'recorded', 'native_state': result['native_state'],
                   'header_delta': result['comparison']['output_changes'],
                   'previous_run': result['inbox']['previous_id'], 'extended_run': result['inbox']['run_id'],
                   'overall_evidence_state': result['overall_evidence_state'],
                   'core_status': decode(report_raw)['review_set_status'],
                   'result': str(output/'RESULT.json')}
        print(encoded(summary).decode(), end='')
        return 0
    except SavedOutputError as exc:
        print(encoded(failure_result(exc)).decode(), end='')
        return 64
    except (ValueError, KeyError, TypeError, OSError, sqlite3.Error) as exc:
        print(encoded({'status': 'continuation_error', 'error': str(exc),
                       'completed_runs': completed,
                       'next': 'keep the database and output; an error does not imply rollback'}).decode(), end='')
        return 64


if __name__ == '__main__':
    raise SystemExit(main())
