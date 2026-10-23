"""Bounded MUSUBI set2 receiving adapter. No public VATE contract changes."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import sys

PROFILE = 'musubi.ca2a.pilot.v0'
CONTRACT = 'local-musubi-set2-receiving-1'
AUDIT_PROFILE = 'horizon-estimate-audit-dataset-linkage-1'
AUDIT_TYPE = 'horizon-shield.estimate-audit.v0'
MIB = 1024 * 1024
KINDS = {k: 'musubi.ca2a.' + v + '.v0' for k, v in {
    'execution': 'execution-receipt', 'payment': 'payment-receipt',
    'criteria': 'criteria-commitment'}.items()}


class InputError(ValueError):
    pass


class SavedOutputError(OSError):
    """A completed, retained assessment needs only output reconstruction."""
    def __init__(self, receipt, phase, cause):
        self.receipt, self.phase, self.cause = receipt, phase, cause
        super().__init__(str(cause))


def failure_result(exc):
    if isinstance(exc, SavedOutputError):
        return {'status': 'saved_output_error', 'phase': exc.phase,
                'error_type': type(exc.cause).__name__, 'detail': str(exc.cause),
                'recovery': exc.receipt}
    return {'status': 'input_or_storage_error', 'error_type': type(exc).__name__, 'detail': str(exc)}


def write_json(path, value):
    # A failed write must not leave an apparently complete RESULT/RECOVERY file.
    temporary = path.with_name(path.name + '.tmp')
    with temporary.open('xb') as stream:
        stream.write(encoded(value))
        stream.flush()
    os.replace(temporary, path)


def keep_error(out, failure):
    try:
        write_json(out / 'ERROR.json', failure)
    except OSError:
        pass  # stdout remains the recovery channel when this filesystem is full.


def make_summary(assessment, stored):
    state = assessment['native']['state']
    return {'status': 'recorded' if state in ('evaluated', 'refused') else 'recorded_evaluator_error',
            'native_state': state, 'comparison': assessment['comparison'],
            'overall_evidence_state': assessment['overall_evidence_state'], **stored}


def need(test, message):
    if not test:
        raise InputError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2,
                       allow_nan=False) + '\n').encode()


def now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def decode(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    def invalid(_):
        raise InputError('non-integer JSON number')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                          parse_float=invalid, parse_constant=invalid)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise InputError('invalid bounded JSON') from exc


def canonical(value):
    """Only ASCII/safe-integer JCS subset; never silently approximate general JCS."""
    def check(v, depth=0):
        need(depth <= 64, 'JSON nesting bound')
        if type(v) is str:
            need(v.isascii(), 'non-ASCII outside this adapter digest subset')
        elif type(v) is int:
            need(abs(v) <= 2**53 - 1, 'unsafe integer')
        elif type(v) is list:
            for x in v: check(x, depth + 1)
        elif type(v) is dict:
            for k, x in v.items():
                need(type(k) is str, 'object key must be string')
                check(k, depth + 1); check(x, depth + 1)
        else:
            need(v is None or type(v) is bool, 'unsupported JSON type')
    check(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return sha(canonical(value))


def relative(name):
    need(type(name) is str and name and '\\' not in name and '\x00' not in name,
         'invalid relative path')
    p = PurePosixPath(name)
    need(not p.is_absolute() and '..' not in p.parts and p.as_posix() == name
         and name != '.', 'non-canonical relative path')
    return p


def read(root, name, maximum=2*MIB):
    p = Path(root)
    for part in relative(name).parts:
        p = p / part
        need(not p.is_symlink(), 'symlink input refused: ' + name)
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        need(stat.S_ISREG(os.fstat(fd).st_mode), 'expected regular file')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum + 1)
        need(len(raw) <= maximum, 'file size bound')
        return raw
    finally:
        os.close(fd)


def verified_files(root, rows, maximum_count=96, maximum_total=10*MIB):
    need(type(rows) is list and 0 < len(rows) <= maximum_count, 'file count bound')
    out = {}
    total = 0
    for row in rows:
        name = row['path']; relative(name)
        need(name not in out, 'duplicate manifest path')
        raw = read(root, name)
        need(sha(raw) == row['sha256'] and len(raw) == row['bytes'], 'file identity mismatch: ' + name)
        out[name] = raw; total += len(raw)
        need(total <= maximum_total, 'total input byte bound')
    return out


def validate_selection(s, originals):
    need(s['contract'] == CONTRACT and s['profile'] == PROFILE, 'unsupported selection contract/profile')
    for key in ('receiver_id', 'namespace', 'experiment', 'run', 'question'):
        need(type(s[key]) is str and 0 < len(s[key]) <= 256, 'invalid selection label: ' + key)
    need(re.fullmatch(r'[A-Za-z0-9_.:-]+', s['namespace']) is not None, 'namespace characters')
    need(type(s['assessment_time']) is str and s['assessment_time'].endswith('Z'),
         'assessment time must be a UTC Z string')
    datetime.fromisoformat(s['assessment_time'].replace('Z', '+00:00'))
    for key in ('bundle', 'reference_output'):
        ref = s[key]
        need(ref['path'] in originals and sha(originals[ref['path']]) == ref['sha256'], key + ' identity mismatch')
    cases = s['cases']; requirements = s['requirements']
    need(type(cases) is list and 0 < len(cases) <= 16, 'case count bound')
    need(len({c['occurrence_id'] for c in cases}) == len(cases), 'duplicate selected occurrence')
    need(len({c['request_sha256'] for c in cases}) == len(cases), 'duplicate selected request')
    need(type(requirements) is list and len(requirements) <= 64, 'requirement count bound')
    need(len({r['id'] for r in requirements}) == len(requirements), 'duplicate requirement id')
    for r in requirements:
        need(type(r['required']) is bool and type(r['files']) is list and len(r['files']) <= 8,
             'invalid requirement')
        need(r['occurrence_id'] is None or r['occurrence_id'] in {c['occurrence_id'] for c in cases},
             'requirement outside selected cases')
        for name in r['files']:
            need(name in originals, 'candidate must be in verified acquisition manifest')
        if r['kind'] in KINDS:
            need(r['occurrence_id'] is not None and re.fullmatch('[0-9a-f]{64}', r['item_sha256']),
                 'supported record needs selected occurrence and item digest')
    canonical(s['trust'])
    if 'audit_binding_profile' in s:
        need(s['audit_binding_profile'] == AUDIT_PROFILE, 'unsupported audit binding profile')
        by_id = {r['id']: r for r in requirements}
        for r in requirements:
            if r['kind'] not in ('audit_original', 'dataset_original'):
                continue
            field, kind = (('execution_requirement', 'execution') if r['kind'] == 'audit_original'
                           else ('audit_requirement', 'audit_original'))
            need(type(r.get(field)) is str and r[field] in by_id,
                 'audit linkage requires an explicitly selected prerequisite')
            parent = by_id[r[field]]
            need(r['occurrence_id'] is not None and parent['kind'] == kind
                 and parent['occurrence_id'] == r['occurrence_id'] and parent['required'],
                 'audit prerequisite must be selected in the same request occurrence')


def bind_audit_originals(s, originals, records):
    """Join raw evidence bytes; never assert audit quality or actual dataset use."""
    if s.get('audit_binding_profile') != AUDIT_PROFILE:
        return
    by_id = {r['id']: r for r in records}
    # Audit first, dataset second. Selection order cannot choose the dependency order.
    for kind in ('audit_original', 'dataset_original'):
        for r in records:
            if r['kind'] != kind or not r['required'] or len(r['files']) != 1:
                continue
            field = 'execution_requirement' if kind == 'audit_original' else 'audit_requirement'
            parent = by_id[r[field]]
            r['claim_scope'] = 'published_digest_linkage_only'
            if parent['binding_status'] != 'bound':
                r.update(binding_status='unresolved', reason='selected_prerequisite_not_bound')
                continue
            raw = originals[r['files'][0]]
            if kind == 'audit_original':
                entry = decode(originals[parent['files'][0]])
                item = entry['item']
                outcome = item.get('outcome')
                if (type(outcome) is not dict or outcome.get('kind') != 'result'
                        or outcome.get('stage') != 'audited'
                        or type(outcome.get('response_sha256')) is not str
                        or re.fullmatch('[0-9a-f]{64}', outcome['response_sha256']) is None):
                    r.update(binding_status='contradictory', reason='execution_does_not_name_audit_result')
                    continue
                if sha(raw) != outcome['response_sha256']:
                    r.update(binding_status='contradictory', reason='audit_response_digest_mismatch')
                    continue
                try:
                    audit = decode(raw)
                    need(type(audit) is dict, 'audit must be an object')
                    if audit.get('type') != AUDIT_TYPE:
                        r.update(binding_status='unsupported', reason='unsupported_audit_type')
                        continue
                    lines = audit.get('lines')
                    need(type(lines) is list and 0 < len(lines) <= 256, 'audit line count bound')
                    need(all(type(line) is dict and type(line.get('dataset_sha256')) is str
                             and re.fullmatch('[0-9a-f]{64}', line['dataset_sha256'])
                             for line in lines), 'audit dataset digest shape')
                    dataset_digests = sorted({line['dataset_sha256'] for line in lines})
                except ValueError:
                    # JSON's bounded integer parser may raise plain ValueError
                    # (for example, an excessive digit count), not InputError.
                    r.update(binding_status='contradictory', reason='invalid_audit_shape')
                    continue
                if len(dataset_digests) != 1:
                    r.update(binding_status='unsupported', reason='multiple_dataset_digests_not_supported')
                    continue
                r.update(binding_status='bound', reason='audit_bytes_match_selected_execution',
                         dataset_sha256=dataset_digests[0],
                         linkage_basis={'execution_requirement': parent['id'],
                                        'request_sha256': item['request_sha256'],
                                        'execution_item_sha256': parent['item_sha256'],
                                        'execution_raw_sha256': parent['raw_sha256'][0],
                                        'response_sha256': outcome['response_sha256']})
                if parent['semantic_assessment'] == 'native_result_attached':
                    r['semantic_assessment'] = 'digest_linkage_checked'
            else:
                expected = parent['dataset_sha256']
                if sha(raw) != expected:
                    r.update(binding_status='contradictory', reason='audit_dataset_digest_mismatch')
                    continue
                r.update(binding_status='bound', reason='dataset_bytes_match_selected_audit',
                         linkage_basis={'audit_requirement': parent['id'],
                                        'audit_raw_sha256': parent['raw_sha256'][0],
                                        'dataset_sha256': expected})
                if parent['semantic_assessment'] == 'digest_linkage_checked':
                    r['semantic_assessment'] = 'digest_linkage_checked'


def changes(left, right, path='$'):
    if type(left) is dict and type(right) is dict:
        result = []
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                result.append({'path': path + '.' + key, 'before': left.get(key), 'after': right.get(key)})
            else:
                result.extend(changes(left[key], right[key], path + '.' + key))
        return result
    if type(left) is list and type(right) is list:
        same = len(left) == len(right) and all(not changes(a, b) for a, b in zip(left, right))
    else:
        same = type(left) is type(right) and left == right
    if not same:
        return [{'path': path, 'before': left, 'after': right}]
    return []


def interpret_native(stdout, execution):
    """Honor the pinned pilot_v0 main contract: 2/3 can carry a real refusal."""
    if execution['state'] != 'process_completed':
        return None
    try:
        native = decode(stdout)
        need(type(native) is dict and native.get('type') == 'musubi.ca2a.pilot-settlement.v0'
             and native.get('profile') == PROFILE, 'native output contract')
        refused = type(native.get('refused')) is str and bool(native['refused'])
        verified = native.get('companion', {}).get('log', {}).get('verified')
        code = execution['exit_code']
        if code == 0 and verified is True and not refused:
            pilot = native.get('pilot')
            need(type(pilot) is dict, 'native pilot must be an object')
            for key in ('executions', 'payments', 'criteria_commitments'):
                rows = pilot.get(key)
                need(type(rows) is list, 'native rows must be an array: ' + key)
                need(all(type(row) is dict and type(row.get('seq')) is int
                         and row['seq'] >= 0 and type(row.get('request_sha256')) is str
                         and re.fullmatch('[0-9a-f]{64}', row['request_sha256'])
                         for row in rows), 'invalid native row identity: ' + key)
            execution['state'] = 'evaluated'
        elif (code == 2 and (refused or verified is False)) or (code == 3 and refused):
            execution['state'] = 'refused'
        else:
            raise InputError('exit and settlement outcome disagree')
        return native
    except (ValueError, TypeError, AttributeError):
        execution['state'] = 'evaluator_error'
        execution['error'] = 'invalid_native_output_or_exit_contract'
        return None


def assess(s, originals, bundle, native, execution):
    """Binding findings are independent from authored native judgments."""
    request_rows = bundle['requests']
    entries = bundle['log']['entries']
    global_findings = []
    if bundle['profile'] != s['profile']:
        global_findings.append('profile_mismatch')
    cp = bundle['log']['checkpoint']
    if (cp['log_id'], cp['head']) != (s['log_identity']['log_id'], s['log_identity']['head']):
        global_findings.append('selected_log_mismatch')
    if sorted(r['occurrence_id'] for r in request_rows) != sorted(c['occurrence_id'] for c in s['cases']):
        global_findings.append('selected_occurrence_set_mismatch')
    cases = []
    for c in s['cases']:
        found = [r for r in request_rows if r['occurrence_id'] == c['occurrence_id']]
        state = ('not_received' if not found else 'ambiguous' if len(found) != 1 else
                 'bound' if digest(found[0]) == c['request_sha256'] else 'contradictory')
        cases.append({**c, 'binding_status': state})
    by_case = {c['occurrence_id']: c for c in cases}
    records = []
    for requirement in s['requirements']:
        r = {**requirement, 'native_rows': None, 'semantic_assessment': 'unassessed'}
        files = r['files']; kind = r['kind']
        if not r['required']:
            state = 'not_selected'
        elif not files:
            state = 'not_received'
        elif len(files) > 1:
            state = 'ambiguous'
        elif kind not in KINDS:
            state = 'unsupported'
        else:
            c = by_case[r['occurrence_id']]
            try:
                entry = decode(originals[files[0]])
                need(type(entry) is dict and type(entry.get('item')) is dict, 'not a log entry')
                canonical(entry)
            except InputError:
                r.update(binding_status='contradictory', reason='invalid_candidate_entry',
                         raw_sha256=[sha(originals[n]) for n in files])
                records.append(r)
                continue
            matches = [e for e in entries if canonical(e) == canonical(entry)]
            item = entry.get('item', {})
            ok = (not global_findings and c['binding_status'] == 'bound'
                  and item.get('type') == KINDS[kind]
                  and item.get('request_sha256') == c['request_sha256']
                  and digest(item) == r['item_sha256'])
            if kind == 'criteria':
                ok = ok and (item.get('criteria_sha256'), item.get('checker')) == (c['criteria_sha256'], c['checker'])
            state = 'ambiguous' if len(matches) > 1 else 'bound' if ok and len(matches) == 1 else 'contradictory'
            if state == 'bound' and execution['state'] == 'evaluated':
                key = {'execution': 'executions', 'payment': 'payments', 'criteria': 'criteria_commitments'}[kind]
                rows = [x for x in native.get('pilot', {}).get(key, [])
                        if x.get('seq') == entry['seq'] and x.get('request_sha256') == c['request_sha256']]
                r['native_rows'] = rows
                r['semantic_assessment'] = 'native_result_attached' if len(rows) == 1 else 'unassessed'
        r['binding_status'] = state
        r['raw_sha256'] = [sha(originals[n]) for n in files]
        records.append(r)
    bind_audit_originals(s, originals, records)
    complete = (not global_findings and all(c['binding_status'] == 'bound' for c in cases)
                and execution['state'] == 'evaluated'
                and all(not r['required'] or (r['binding_status'] == 'bound'
                        and r['semantic_assessment'] in ('native_result_attached', 'digest_linkage_checked'))
                        for r in records))
    result = {'contract': CONTRACT, 'experiment': s['experiment'], 'run': s['run'],
            'question': s['question'], 'assessment_time': s['assessment_time'],
            'global_findings': global_findings, 'cases': cases, 'requirements': records,
            'overall_evidence_state': 'selected_records_bound' if complete else 'partial',
            'native': {'state': execution['state'], 'output': native},
            'core_foreign_semantics': 'not_implemented_selected_empty',
            'arrival_basis': 'local_material_selection_not_external_late_delivery'}
    if 'audit_binding_profile' in s:
        result['audit_binding_profile'] = s['audit_binding_profile']
    return result


def load_inbox(vate_root):
    module_path = vate_root / 'reference/recipient-inbox/recipient_inbox.py'
    need(module_path.is_file(), '--vate-root must contain reference/recipient-inbox/recipient_inbox.py')
    search_path = list(sys.path)
    try:
        sys.path.insert(0, str(module_path.parent))
        try:
            from recipient_inbox import Engine, Inbox
        except ImportError as exc:
            raise InputError('cannot load Inbox from --vate-root: ' + str(exc)) from exc
        loaded_path = getattr(sys.modules['recipient_inbox'], '__file__', None)
        need(loaded_path is not None and Path(loaded_path).resolve() == module_path.resolve(),
             'loaded Inbox module does not belong to --vate-root')
        return Engine, Inbox
    finally:
        sys.path[:] = search_path


def retain(vate_root, database, out, s, originals, manifest_raw, assessment, payloads, previous, inbox_types):
    Engine, Inbox = inbox_types
    box = Inbox(database, Engine(vate_root), create=not database.exists())
    try:
        prior = None
        if previous:
            old = decode(previous.read_bytes())
            prior_state = box.status(old['inbox']['run_id'])
            need(prior_state['head'] == old['inbox']['run_id'], 'previous evaluation is not current history head')
            # A run ID and independently valid refs can still name different evaluations.
            # Use the actual stored run's selection and index as the authoritative join.
            box.export(old['inbox']['run_id'], out / 'previous-export')
            core_selection = decode((out / 'previous-export/selection.json').read_bytes())
            core_review = decode(box.get(core_selection['review_set_ref']))
            need(len(core_review['population_basis_refs']) == 2, 'previous application index unavailable')
            index = decode(box.get(core_review['population_basis_refs'][1]))
            need(core_selection['selection_basis_ref'] == old['selection_ref']
                 and index['evaluation/assessment.json'] == old['assessment_ref'],
                 'previous references do not belong to selected history run')
            box.get(old['assessment_ref'])
            prior = {'run_id': old['inbox']['run_id'], 'assessment_ref': old['assessment_ref'],
                     'selection_ref': old['selection_ref']}
            old_selection = decode(box.get(old['selection_ref']))
            need((old_selection['receiver_id'], old_selection['namespace']) ==
                 (s['receiver_id'], s['namespace']), 'previous stream differs')
            assessment['changed_selection'] = changes(old_selection, s)
        else:
            assessment['changed_selection'] = []
        assessment['previous'] = prior
        (out / 'assessment.json').write_bytes(encoded(assessment))
        basis = box.put(manifest_raw)
        refs = {}
        def receive(name, raw, source_basis):
            ref = box.put(raw, 'application/octet-stream')
            identity = digest([s['namespace'], name, ref, source_basis])
            delivery = {'document_type': 'recipient_inbox_delivery', 'version': 1,
                        'event_id': identity, 'entry_id': identity, 'source_namespace': s['namespace'],
                        'native_input_kind': 'foreign_musubi_material', 'received_at': None,
                        'receipt_basis_ref': source_basis, 'originals': {'original': ref}}
            box.receive(encoded(delivery)); refs[name] = ref
        for name, raw in originals.items(): receive('originals/' + name, raw, basis)
        selection_ref = box.put(encoded(s))
        evaluator_ref = box.put(payloads['evaluator.json'])
        for name, raw in payloads.items():
            stable = name.startswith('evaluator-source/') or name in ('evaluator.json', 'runtime-identity.json', 'requirements.lock')
            receive('evaluation/' + name, raw, evaluator_ref if stable else selection_ref)
        receive('evaluation/assessment.json', encoded(assessment), selection_ref)
        index = box.put(encoded(refs))
        collection = box.put(encoded({'state': assessment['overall_evidence_state'], 'index': index}))
        revision = box.put(encoded({'previous': prior, 'changed_selection': assessment['changed_selection']})) if prior else None
        stamp = now()
        plan = {'document_type': 'recipient_inbox_plan', 'version': 1,
                'receiver_id': s['receiver_id'], 'review_set_selected_at': stamp,
                'assessment_cutoff': stamp, 'assessment_time': stamp, 'inventory_state': 'partial',
                'collection_basis_ref': collection, 'selection_basis_ref': selection_ref,
                'native_policy_refs': {'s3': None, 'signature': None}, 'revision_basis_ref': revision,
                'review_set': {'document_type': 'receiver_review_set_design', 'design_revision': 2,
                    'review_set_id': 'musubi-set2-retention', 'revision': 1, 'namespace': s['namespace'],
                    'population_basis_refs': [basis, index], 'collection_scope': 'receiver_selected_set_only',
                    'requirements': []}}
        prepared = box.prepare(encoded(plan))
        need(prepared['previous_id'] == (prior['run_id'] if prior else None), 'concurrent history change')
        state = box.run(prepared['run_id'])
        need(state['status'] == 'completed', 'Inbox evaluation did not complete')
        report = decode(box.get(state['report_ref']))
        need(report['review_set_status'] == 'selected_empty' and report['requirements'] == []
             and report['native_calls'] == [] and report['invocation_errors'] is False, 'unexpected core semantics')
        receipt = {'contract': 'musubi-set2-output-recovery-1', 'database': str(database),
                   'run_id': state['run_id'], 'receiver_id': s['receiver_id'], 'namespace': s['namespace'],
                   'selection_ref': selection_ref, 'assessment_ref': refs['evaluation/assessment.json'],
                   'report_ref': state['report_ref']}
        phase = 'recovery_receipt'
        try:
            write_json(out / 'RECOVERY.json', receipt)
            phase = 'export'
            export = box.export(state['run_id'], out / 'export')
        except (OSError, sqlite3.Error) as exc:
            raise SavedOutputError(receipt, phase, exc) from exc
        except ValueError as exc:
            if phase == 'export' and getattr(exc, 'code', None) == 'EXPORT_MISMATCH':
                raise SavedOutputError(receipt, phase, exc) from exc
            raise
        return {'inbox': state, 'export': export, 'original_refs': {n: refs['originals/' + n] for n in originals},
                'selection_ref': selection_ref, 'assessment_ref': refs['evaluation/assessment.json'],
                'payload_refs': {n: refs['evaluation/' + n] for n in payloads}, 'recovery': receipt}
    finally:
        box.close()


def run(args):
    from offline_native import replay
    out = args.output.absolute()
    out.mkdir(parents=True, exist_ok=False)
    try:
        vate_root = args.vate_root.resolve()
        inbox_types = load_inbox(vate_root)
        manifest_raw = read(args.manifest.parent, args.manifest.name)
        manifest = decode(manifest_raw)
        originals = verified_files(args.originals, manifest['files'])
        s = decode(read(args.selection.parent, args.selection.name))
        validate_selection(s, originals)
        bundle_raw = originals[s['bundle']['path']]
        bundle = decode(bundle_raw); canonical(bundle)
        derived = decode(bundle_raw)
        derived['trust'] = s['trust']
        view_raw = b''
        if args.view:
            view_raw = read(args.view.parent, args.view.name)
            need(sha(view_raw) == s['view_sha256'], 'selected view identity mismatch')
            derived['view'] = decode(view_raw)
        else:
            need(s['view_sha256'] is None, 'selected view file is required')
        condition_changes = changes(bundle['trust'], derived['trust'], '$.trust') + changes(bundle['view'], derived['view'], '$.view')
        native_raw = bundle_raw if not condition_changes else encoded(derived)
        evaluator_raw = read(args.evaluator.parent, args.evaluator.name)
        execution, stdout, stderr, evidence = replay(args.source, args.runtime, decode(evaluator_raw), native_raw, out / 'native')
        native = interpret_native(stdout, execution)
        reference = originals[s['reference_output']['path']] + b'\n'
        comparison = {'kind': 'changed_conditions' if condition_changes else 'same_conditions',
                      'condition_changes': condition_changes, 'expected_raw_sha256': sha(reference),
                      'actual_raw_sha256': sha(stdout), 'exact_bytes': stdout == reference,
                      'output_changes': changes(decode(reference), native) if native is not None else None}
        result = assess(s, originals, bundle, native, execution)
        result['comparison'] = comparison
        payloads = {'selection.json': encoded(s), 'evaluator.json': evaluator_raw,
                    'native-input.json': native_raw, 'native.stdout': stdout, 'native.stderr': stderr,
                    'execution.json': encoded(execution), **evidence}
        if args.view: payloads['selected-view.json'] = view_raw
        for name, raw in payloads.items():
            p = out / name
            p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(raw)
        stored = retain(vate_root, args.database.absolute(), out, s, originals, manifest_raw,
                        result, payloads, args.previous, inbox_types)
        summary = make_summary(result, stored)
        try:
            write_json(out / 'RESULT.json', summary)
        except OSError as exc:
            raise SavedOutputError(stored['recovery'], 'result', exc) from exc
        return summary
    except (KeyError, TypeError, ValueError, OSError, sqlite3.Error) as exc:
        keep_error(out, failure_result(exc))
        raise


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('originals', 'manifest', 'selection', 'source', 'runtime', 'evaluator', 'vate-root', 'database', 'output'):
        ap.add_argument('--' + name, type=Path, required=True)
    ap.add_argument('--view', type=Path)
    ap.add_argument('--previous', type=Path)
    args = ap.parse_args()
    try:
        result = run(args)
        print(json.dumps({k: result[k] for k in ('status', 'native_state', 'overall_evidence_state')}))
        return 0 if result['native_state'] in ('evaluated', 'refused') else 64
    except (KeyError, TypeError, ValueError, OSError, sqlite3.Error) as exc:
        print(json.dumps(failure_result(exc)))
        return 64


if __name__ == '__main__':
    sys.exit(main())
