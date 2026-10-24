"""Three local intake stages, using explicitly supplied HS51 acceptance originals."""
from __future__ import annotations

import argparse
import base64
import copy
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace

from acceptance_adapter import PROFILE, VERIFIER_SHA256
from prepare_environment import ROOT, check_environment, check_vate
from receiving import (SavedOutputError, decode, encoded, failure_result, need, now,
                       read, run, sha, verified_files, write_json)
from run_audit_example import example as audit_example

COMMIT = '235aaabc45ebe6fa36dd02ca2cd6a44a69297d93'
FILES = {
    'hs51-musubi-2-A.json': '204915d07bacd0ba0589c3a98c92af4b9feb0a4ef5dd5b1786c9ad5cc5eb5dac',
    'hs51-musubi-2-B.json': '7e05c6c112111bd1cbebfd63b28fbb3375e54851d2a453eb9ed750b2f1c31f0f',
    'hs51-aps-A.json': '254a789f07b24354deb55db33cfa4c4dbc3f8321e9438bc94253c0d0b3fc4e00',
    'hs51-aps-B.json': '0b2a26dc95b28d3c529c2b196357ec3c4aa02dc97eb8c5aa02c2b52170df993b',
}
ROOT_HASHES = ['a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc',
               '552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988']


def prepare_inputs(acceptance_dir, tsa_roots, output):
    """No downloads. The example's pins are independent of the supplied records."""
    manifest = decode(read(ROOT/'sample', 'audit-manifest.json'))
    originals = verified_files(ROOT/'sample/originals', manifest['files'])
    rows = copy.deepcopy(manifest['files'])
    for name, expected in FILES.items():
        raw = read(acceptance_dir, name, 256*1024)
        need(sha(raw) == expected, 'fixed acceptance original mismatch: ' + name)
        path = 'foreign-acceptance/' + name
        originals[path] = raw
        rows.append({'path': path, 'sha256': expected, 'bytes': len(raw), 'source_commit': COMMIT,
                     'url': 'https://raw.githubusercontent.com/babyblueviper1/preaction-governance-conformance/'
                            + COMMIT + '/examples/hs51-acceptance-set/' + name})
    roots = decode(read(tsa_roots.parent, tsa_roots.name, 65536))
    need(type(roots) is list and len(roots) == 2, 'supply the two selected DER roots as a JSON base64 array')
    raw_roots = [base64.b64decode(s, validate=True) for s in roots]
    need(sorted(sha(raw) for raw in raw_roots) == sorted(ROOT_HASHES), 'fixed example TSA roots mismatch')
    selection = decode(read(ROOT/'sample', 'audit-selection.json'))
    selected_roots = []
    for raw in sorted(raw_roots, key=sha):
        path = 'foreign-acceptance/tsa-root-' + sha(raw) + '.der'
        originals[path] = raw
        selected_roots.append({'path': path, 'sha256': sha(raw)})
        rows.append({'path': path, 'sha256': sha(raw), 'bytes': len(raw),
                     'basis': 'receiver_selected_fixed_WAR_vector_31_32_trust_anchor'})
    selection.update(assessment_time=now(), acceptance_binding_profile=PROFILE,
                     question='Verify signed foreign acceptance for the selected A/B occurrences and preserve earlier assessments.',
                     acceptance_verification={'verifier_sha256': VERIFIER_SHA256, 'tsa_roots': selected_roots})
    for r in selection['requirements']:
        if r['kind'] == 'acceptance' and r['required']:
            r.update(files=['foreign-acceptance/' + r['occurrence_id'] + '.json'],
                     execution_requirement=r['occurrence_id'] + ':execution',
                     criteria_requirement=r['occurrence_id'] + ':criteria')
    output.mkdir(parents=True, exist_ok=False)
    for name, raw in originals.items():
        p = output/'originals'/name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(raw)
    write_json(output/'manifest.json', dict(manifest, files=rows))
    write_json(output/'selection.json', selection)
    return selection, originals


def example(args, completed):
    environment = args.environment.resolve()
    need(Path(sys.prefix).resolve() == environment/'venv', 'run with prepared environment/venv/bin/python -B')
    check_environment(environment)
    check_vate(args.vate_root)
    need(sha(read(args.acceptance_verifier.parent, args.acceptance_verifier.name)) == VERIFIER_SHA256,
         'acceptance verifier source mismatch')
    output = args.output.resolve()
    need(not output.is_relative_to(ROOT) and not output.is_relative_to(environment),
         'put results outside sample and prepared runtime')
    output.mkdir(parents=True, exist_ok=False)
    selection, originals = prepare_inputs(args.acceptance_dir, args.tsa_roots, output/'intake')
    audit_example(args.vate_root, environment, output/'history', completed)
    previous = output/'history/audits/RESULT.json'
    saved = {name: read(output/'history'/name, 'assessment.json') for name in ('baseline', 'audits')}
    result = run(SimpleNamespace(originals=output/'intake/originals', manifest=output/'intake/manifest.json',
        selection=output/'intake/selection.json', source=ROOT/'sample/evaluator-source',
        runtime=environment/'venv', evaluator=environment/'evaluator.json', vate_root=args.vate_root.resolve(),
        database=output/'history/inbox.sqlite', output=output/'acceptance', view=None,
        previous=previous, acceptance_verifier=args.acceptance_verifier))
    completed.append(result['recovery'])
    assessment = decode(read(output/'acceptance', 'assessment.json'))
    need(result['status'] == 'recorded' and result['comparison']['exact_bytes'], 'inspect saved evaluator results')
    records = {r['id']: r for r in assessment['requirements']}
    verdicts = {}
    for case, expected in (('A', 'pass'), ('B', 'fail')):
        r = records['hs51-musubi-2-' + case + ':acceptance']
        need(r['binding_status'] == 'bound' and r['semantic_assessment'] == 'foreign_acceptance_verified'
             and r['work_verdict'] == expected, 'foreign acceptance did not match the fixed expected result')
        verdicts[case] = r['work_verdict']
    need(assessment['overall_evidence_state'] == 'partial'
         and all(r['accepted'] is None for r in assessment['native']['output']['pilot']['executions']),
         'foreign acceptance must preserve native output and missing evidence')
    for name, raw in saved.items():
        old = decode(read(output/'history'/name, 'RESULT.json'))
        need(read(output/'acceptance/export', old['assessment_ref']['path']) == raw,
             'historical assessment changed')
    for name, raw in originals.items():
        need(read(output/'acceptance/export', result['original_refs'][name]['path']) == raw,
             'original did not export exactly')
    summary = {'status': 'recorded', 'foreign_work_verdicts': verdicts, 'native_acceptance': None,
               'overall_evidence_state': 'partial', 'historical_assessments_preserved': True,
               'original_count': len(originals), 'originals_exported_exactly': True,
               'run_id': result['inbox']['run_id'], 'recovery': result['recovery']}
    write_json(output/'ACCEPTANCE-EXAMPLE.json', summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('vate-root', 'environment', 'acceptance-dir', 'acceptance-verifier', 'tsa-roots', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    completed = []
    try:
        print(encoded(example(args, completed)).decode(), end='')
        return 0
    except SavedOutputError as exc:
        print(encoded(failure_result(exc)).decode(), end='')
        return 64
    except (ValueError, KeyError, TypeError, OSError, sqlite3.Error) as exc:
        print(encoded({'status': 'acceptance_example_error', 'error': str(exc),
                       'completed_runs': completed}).decode(), end='')
        return 64


if __name__ == '__main__':
    raise SystemExit(main())
