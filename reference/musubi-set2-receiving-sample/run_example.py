"""Receive the fixed sample, then reassess it with the extended header view."""
from __future__ import annotations

import argparse
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace

from prepare_environment import ROOT, check_environment, check_vate
from receiving import SavedOutputError, decode, encoded, failure_result, need, read, run, sha, write_json


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--vate-root', type=Path, required=True)
    ap.add_argument('--environment', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True, help='new directory for database and both runs')
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
        output.mkdir(parents=True, exist_ok=False)
        args = dict(originals=ROOT/'sample/originals', manifest=ROOT/'sample/manifest.json',
                    selection=ROOT/'sample/selection.json', source=ROOT/'sample/evaluator-source',
                    runtime=environment/'venv', evaluator=environment/'evaluator.json',
                    vate_root=a.vate_root.resolve(), database=output/'inbox.sqlite', output=output/'baseline',
                    view=None, previous=None)
        baseline = run(SimpleNamespace(**args))
        completed.append(baseline['recovery'])
        need(baseline['native_state'] == 'evaluated', 'baseline evaluator did not complete; keep its result')
        need(baseline['comparison']['exact_bytes'], 'baseline differs from the published reference output')
        args.update(selection=ROOT/'sample/extended-selection.json', view=ROOT/'sample/extended-view.json',
                    previous=output/'baseline/RESULT.json', output=output/'extended')
        extended = run(SimpleNamespace(**args))
        completed.append(extended['recovery'])
        need(extended['native_state'] == 'evaluated', 'extended evaluator did not complete; keep its result')
        need(extended['comparison']['output_changes'] ==
             [{'path': '$.companion.log.anchor_depth', 'before': 9, 'after': 14}],
             'extended result has an unexpected change; inspect both saved assessments')
        report_ref = extended['inbox']['report_ref']
        report_raw = read(output/'extended/export', report_ref['path'])
        need(sha(report_raw) == report_ref['digest']['value'] and len(report_raw) == report_ref['byte_length'],
             'exported Inbox report differs from its stored reference')
        summary = {'status': 'recorded', 'baseline_raw_sha256': baseline['comparison']['actual_raw_sha256'],
                   'header_delta': extended['comparison']['output_changes'],
                   'baseline_run': baseline['inbox']['run_id'], 'extended_run': extended['inbox']['run_id'],
                   'overall_evidence_state': extended['overall_evidence_state'],
                   'core_status': decode(report_raw)['review_set_status']}
        write_json(output/'EXAMPLE.json', summary)
        print(encoded(summary).decode(), end='')
        return 0
    except SavedOutputError as exc:
        print(encoded(failure_result(exc)).decode(), end='')
        return 64
    except (ValueError, KeyError, TypeError, OSError, sqlite3.Error) as exc:
        print(encoded({'status': 'example_error', 'error': str(exc),
                       'completed_runs': completed,
                       'next': 'keep the database and output; an error does not imply rollback'}).decode(), end='')
        return 64


if __name__ == '__main__':
    raise SystemExit(main())
