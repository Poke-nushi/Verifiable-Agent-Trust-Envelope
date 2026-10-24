"""Opt-in foreign WAR bindings; never rewrite the native MUSUBI settlement."""
from __future__ import annotations

import base64
from pathlib import Path
import re

from receiving import decode, encoded, need, read, sha

PROFILE = 'hs51-war-bindings-v0-1'
VERIFIER_SHA256 = 'ac3ac35d9356cbb5f3371c19a2113ad03c1fd486c247a2ed586bdfdbdd32ae49'
ROOT = Path(__file__).resolve().parent


def validate(s, originals):
    if 'acceptance_binding_profile' not in s:
        return
    need(s['acceptance_binding_profile'] == PROFILE, 'unsupported acceptance binding profile')
    config = s['acceptance_verification']
    need(config['verifier_sha256'] == VERIFIER_SHA256, 'unsupported acceptance verifier source')
    roots = config['tsa_roots']
    need(type(roots) is list and len(roots) <= 8, 'TSA root count bound')
    names = set()
    for root in roots:
        name = root['path']
        need(name in originals and name not in names, 'TSA root must be uniquely selected from originals')
        names.add(name)
        need(len(originals[name]) <= 16384 and sha(originals[name]) == root['sha256'],
             'selected TSA root identity mismatch')
    by_id = {r['id']: r for r in s['requirements']}
    selected = [r for r in s['requirements'] if r['kind'] == 'acceptance' and r['required']]
    need(len(selected) <= 16, 'acceptance candidate count bound')
    for r in selected:
        for field, kind in (('execution_requirement', 'execution'), ('criteria_requirement', 'criteria')):
            need(type(r.get(field)) is str and r[field] in by_id,
                 'acceptance requires an explicitly selected prerequisite')
            parent = by_id[r[field]]
            need(r['occurrence_id'] is not None and parent['kind'] == kind and parent['required']
                 and parent['occurrence_id'] == r['occurrence_id'],
                 'acceptance prerequisite must be selected in the same occurrence')


def expectations(s, originals, requirement):
    by_id = {r['id']: r for r in s['requirements']}
    c = next(c for c in s['cases'] if c['occurrence_id'] == requirement['occurrence_id'])
    execution = by_id[requirement['execution_requirement']]
    criteria = by_id[requirement['criteria_requirement']]
    need(len(execution['files']) == len(criteria['files']) == 1, 'acceptance prerequisite not unique')
    item = decode(originals[execution['files'][0]])['item']
    outcome = item['outcome']
    need(outcome['kind'] == 'result' and outcome['stage'] == 'audited', 'execution has no audited response')
    result = {'occurrence_id': c['occurrence_id'], 'request_sha256': c['request_sha256'],
              'execution_sha256': execution['item_sha256'], 'audit_sha256': outcome['response_sha256'],
              'checker_public_key_hex': c['checker'], 'producer_public_key_hex': item['responder'],
              'criteria_sha256': c['criteria_sha256']}
    need(all(type(v) is str and re.fullmatch('[0-9a-f]{64}', v)
             for k, v in result.items() if k != 'occurrence_id'), 'acceptance prerequisite digest/key malformed')
    return result


def prepare(s, originals, verifier_path):
    if 'acceptance_binding_profile' not in s:
        need(verifier_path is None, 'select the acceptance profile before supplying its verifier')
        return None
    validate(s, originals)
    need(verifier_path is not None, 'selected acceptance profile requires --acceptance-verifier')
    source = read(verifier_path.parent, verifier_path.name, 256*1024)
    need(sha(source) == VERIFIER_SHA256, 'acceptance verifier source pin mismatch')
    config = s['acceptance_verification']
    items = []
    for r in s['requirements']:
        if r['kind'] != 'acceptance' or not r['required'] or len(r['files']) != 1:
            continue
        try:
            expected = expectations(s, originals, r)
        except (ValueError, KeyError, TypeError, StopIteration):
            # assess() reports the actual prerequisite's missing/invalid state.
            continue
        items.append({'id': r['id'], 'expected': expected,
                      'raw_base64': base64.b64encode(originals[r['files'][0]]).decode('ascii')})
    return {'input': {'profile': PROFILE, 'items': items,
                     'tsa_roots_base64': [base64.b64encode(originals[r['path']]).decode('ascii')
                                          for r in config['tsa_roots']]},
            'sources': {'war_verify.py': source,
                        'acceptance_checks.py': read(ROOT, 'acceptance_checks.py'),
                        'acceptance_worker.py': read(ROOT, 'acceptance_worker.py')},
            'config': {'profile': PROFILE, **config}}


def bind(s, originals, records, verification):
    if 'acceptance_binding_profile' not in s:
        return
    by_id = {r['id']: r for r in records}
    results = (verification['results'] if type(verification) is dict
               and verification.get('state') == 'evaluated' and verification.get('profile') == PROFILE
               and type(verification.get('results')) is dict else {})
    for r in records:
        if r['kind'] != 'acceptance' or not r['required'] or len(r['files']) != 1:
            continue
        r['claim_scope'] = 'signed_foreign_acceptance_and_occurrence_binding'
        parents = [by_id[r[f]] for f in ('execution_requirement', 'criteria_requirement')]
        if any(p['binding_status'] != 'bound' or p['semantic_assessment'] != 'native_result_attached'
               for p in parents):
            r.update(binding_status='unresolved', reason='selected_prerequisite_not_verified')
            continue
        try:
            expected = expectations(s, originals, r)
        except (ValueError, KeyError, TypeError, StopIteration):
            r.update(binding_status='unresolved', reason='selected_prerequisite_invalid')
            continue
        result = results.get(r['id'])
        if (type(result) is not dict or result.get('expected') != expected
                or result.get('raw_sha256') != sha(originals[r['files'][0]])):
            r.update(binding_status='unresolved', reason='acceptance_evaluator_unavailable')
            continue
        r['foreign_acceptance'] = result
        status = result.get('status')
        if status == 'verified' and result.get('work_verdict') in ('pass', 'fail', 'incomplete'):
            r.update(binding_status='bound', semantic_assessment='foreign_acceptance_verified',
                     work_verdict=result['work_verdict'])
        elif status == 'rejected':
            r.update(binding_status='contradictory', reason='acceptance_verification_failed')
        elif status == 'unsupported':
            r.update(binding_status='unsupported', reason='unsupported_acceptance_record')
        else:
            r.update(binding_status='unresolved', reason='acceptance_evaluator_unavailable')


def output_evidence(job, output):
    """Copy fixed execution materials into the existing isolated evaluator area."""
    folder = output / 'acceptance-source'
    folder.mkdir()
    evidence = {'acceptance-input.json': encoded(job['input']),
                'acceptance-evaluator.json': encoded(job['config'])}
    for name, raw in job['sources'].items():
        (folder / name).write_bytes(raw)
        evidence['acceptance-source/' + name] = raw
    (output/'acceptance-input.json').write_bytes(evidence['acceptance-input.json'])
    return evidence
