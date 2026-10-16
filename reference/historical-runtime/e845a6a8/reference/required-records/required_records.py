"""Receiver-selected required-record review. Local revision 2, no aggregate pass."""
from __future__ import annotations

import argparse
import copy
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time

def capture_loaded_source(path, code):
    # A valid timestamp cache may still contain an older implementation.
    try:
        raw = path.read_bytes()
        compiled = compile(raw, code.co_filename, 'exec', dont_inherit=True,
                           optimize=sys.flags.optimize)
        if compiled != code:
            return None, 'loaded module code differs from source: '+path.name
        return hashlib.sha256(raw).hexdigest(), None
    except (OSError, SyntaxError, ValueError, OverflowError) as exc:
        return None, 'cannot identify loaded source: '+str(exc)


LOADED_SOURCE_SHA256, LOADED_SOURCE_ERROR = capture_loaded_source(Path(__file__), sys._getframe().f_code)
CONTRACT = 'vate-required-records-local-v2'
S3 = 'vate-local-s3-observation-v1'
CANON = 'vate-v0.3-fixture-json;ascii-escaped;sorted;compact;no-floats'
MEMBERS = frozenset(('effective-request.json', 'permit.json', 'admission-request.json',
    'admission-decision.json', 'admission.json', 'attempt.json', 'put-request.json',
    'put-transport.json', 'put-headers.txt', 'put-body.bin', 'put-response-body.bin',
    'get-request.json', 'get-transport.json', 'get-headers.txt', 'get-body.bin',
    'post.json', 'sources.json', 'manifest.json'))
CHECKS = frozenset(('receipt_linkage', 's3_observation_binding', 'signatures_and_issuer_authority',
    'independent_execution_observation', 'operation_population_coverage', 'current_permission_to_execute'))
DEFAULT_LIMITS = {'bytes': 16*1024*1024, 'seconds': 60, 'native_calls': 64,
                  'native_result_bytes': 16*1024*1024, 'history_bytes': 128*1024*1024}
MIB = 1024*1024
REPORT_LIMIT = 128*MIB


class Problem(ValueError):
    def __init__(self, code, detail):
        self.code, self.detail = code, detail
        super().__init__(detail)
    def as_dict(self):
        return {'code': self.code, 'detail': self.detail}


def need(condition, detail, code='INVALID_INPUT'):
    if not condition:
        raise Problem(code, detail)


def encode(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(raw):
    return {'raw_sha256': sha(raw), 'byte_length': len(raw)} if raw is not None else None


def decode(raw, depth=16):
    def pairs(items):
        out = {}
        for k, v in items:
            need(k not in out, 'duplicate JSON key')
            out[k] = v
        return out
    def number(_):
        raise Problem('INVALID_INPUT', 'non-integer number')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                           parse_float=number, parse_constant=number)
        queue = [(value, 0)]
        while queue:
            item, d = queue.pop()
            need(d <= depth, 'JSON depth limit')
            if type(item) is dict:
                queue.extend((v, d+1) for pair in item.items() for v in pair)
            elif type(item) is list:
                queue.extend((v, d+1) for v in item)
            elif type(item) is str:
                item.encode('utf-8')
            elif type(item) is int:
                need(abs(item) <= 9007199254740991, 'integer limit')
        need(type(value) is dict, 'expected JSON object')
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, Problem):
            raise
        raise Problem('INVALID_INPUT', str(exc)) from exc


def exact(obj, keys, optional=()):
    need(type(obj) is dict and set(keys) <= set(obj) <= set(keys) | set(optional), 'object fields differ')


def label(value):
    need(type(value) is str and 0 < len(value.encode('utf-8')) <= 256
         and not any(ord(c) < 32 or ord(c) == 127 for c in value), 'invalid identifier')


def stamp(value):
    need(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z', value), 'invalid UTC timestamp')
    whole, dot, fraction = value[:-1].partition('.')
    try:
        return datetime.fromisoformat(whole + ('.'+fraction.ljust(6, '0') if dot else '') + '+00:00')
    except ValueError as exc:
        raise Problem('INVALID_INPUT', str(exc)) from exc


def ref_shape(ref, max_bytes=MIB):
    exact(ref, ('path_base', 'path', 'media_type', 'digest_basis', 'digest', 'byte_length'))
    label(ref['path_base']); label(ref['media_type'])
    path = ref['path']
    need(type(path) is str and 0 < len(path.encode('utf-8')) <= 2048 and '\\' not in path
         and not any(ord(c) < 32 for c in path), 'unsafe path')
    need(not path.startswith('/') and all(p not in ('', '.', '..') for p in path.split('/')), 'unsafe path')
    need(ref['digest_basis'] == 'raw_file_sha256', 'unknown digest basis')
    exact(ref['digest'], ('alg', 'value'))
    need(ref['digest']['alg'] == 'sha-256' and type(ref['digest']['value']) is str
         and re.fullmatch('[0-9a-f]{64}', ref['digest']['value']), 'invalid digest')
    need(type(ref['byte_length']) is int and 0 <= ref['byte_length'] <= max_bytes, 'invalid byte length')


def context_shape(context):
    exact(context, ('transaction_id', 'runtime', 'effective_request_hash', 'action_binding'))
    label(context['transaction_id']); label(context['runtime'])
    binding = context['action_binding']
    exact(binding, ('type', 'preimage_profile', 'canonicalization', 'digest'))
    exact(binding['digest'], ('alg', 'value'))
    need(binding['type'] == 'profile_defined_digest' and binding['preimage_profile'] == S3
         and binding['canonicalization'] == CANON and binding['digest']['alg'] == 'sha-256'
         and type(binding['digest']['value']) is str and re.fullmatch('[0-9a-f]{64}', binding['digest']['value']), 'unsupported S3 context')
    need(context['effective_request_hash'] == 'sha-256:'+binding['digest']['value'], 'request/binding hash mismatch')


def metadata(obj, kind, keys, optional=()):
    exact(obj, ('document_type', 'design_revision', *keys), optional)
    need(obj['document_type'] == kind and type(obj['design_revision']) is int and obj['design_revision'] == 2, 'unsupported metadata revision')


def review_shape(review):
    metadata(review, 'receiver_review_set_design', ('review_set_id', 'revision', 'namespace',
             'population_basis_refs', 'collection_scope', 'requirements'),
             ('previous_review_set_ref', 'previous_report_ref', 'revision_basis_ref'))
    label(review['review_set_id']); label(review['namespace'])
    need(type(review['revision']) is int and review['revision'] >= 1, 'invalid revision')
    need(review['collection_scope'] == 'receiver_selected_set_only', 'unknown collection scope')
    refs_shape(review['population_basis_refs'])
    rows = review['requirements']
    need(type(rows) is list and len(rows) <= 256, 'requirements bound')
    ids, labels, contexts, subjects = set(), {}, {}, {}
    for row in rows:
        exact(row, ('requirement_id', 'subject', 'record_kind', 'binding_profile', 'obligation',
                    'basis_refs', 'requested_native_checks'), ('due_at', 'waiver_ref'))
        label(row['requirement_id']); need(row['requirement_id'] not in ids, 'duplicate requirement ID')
        ids.add(row['requirement_id'])
        sub = row['subject']
        exact(sub, ('kind', 'operation_id', 'native_context'), ('attempt_id',))
        need(sub['kind'] in ('operation', 'attempt'), 'unknown subject kind')
        label(sub['operation_id']); context_shape(sub['native_context'])
        ck = encode(sub['native_context']); op = sub['operation_id']
        need(labels.get(op, ck) == ck and contexts.get(ck, op) == op, 'operation label/context alias')
        labels[op], contexts[ck] = ck, op
        need(row['record_kind'] in ('admission', 'post_execution'), 'unknown record kind')
        if sub['kind'] == 'attempt':
            label(sub.get('attempt_id'))
            need(row['record_kind'] == 'post_execution' and row['binding_profile'] == 'vate_s3_attempt_context', 'unsupported attempt requirement')
            key = sub['attempt_id']
        else:
            need('attempt_id' not in sub and row['binding_profile'] == 'vate_receipt_operation_context', 'unsupported operation requirement')
            key = None
        seen = subjects.setdefault((ck, row['record_kind']), set())
        need(key not in seen and not (seen and (key is None or None in seen)), 'duplicate/overlapping semantic subject')
        seen.add(key)
        need(row['obligation'] in ('required', 'undetermined', 'waived_by_receiver'), 'unknown obligation')
        refs_shape(row['basis_refs'])
        if row['obligation'] == 'required':
            need('due_at' in row and 'waiver_ref' not in row, 'required deadline/waiver shape')
        if 'due_at' in row:
            stamp(row['due_at'])
        if row['obligation'] == 'waived_by_receiver':
            need('waiver_ref' in row, 'missing waiver basis'); ref_shape(row['waiver_ref'])
        else:
            need('waiver_ref' not in row, 'waiver on non-waived requirement')
        checks = row['requested_native_checks']
        need(type(checks) is list and all(type(c) is str and c in CHECKS for c in checks)
             and len(set(checks)) == len(checks), 'unknown/duplicate requested check')
    prior = ('previous_review_set_ref', 'previous_report_ref', 'revision_basis_ref')
    need(all(k in review for k in prior) if review['revision'] > 1 else not any(k in review for k in prior), 'revision references')
    for k in prior:
        if k in review:
            ref_shape(review[k], REPORT_LIMIT if k == 'previous_report_ref' else MIB)


def refs_shape(refs):
    need(type(refs) is list and 0 < len(refs) <= 16, 'basis refs bound')
    for ref in refs:
        ref_shape(ref)


def event_shape(event, cutoff, assessed):
    if event is None:
        return
    exact(event, ('ref', 'received_at', 'cutoff_membership', 'receipt_basis_ref'))
    ref_shape(event['ref']); ref_shape(event['receipt_basis_ref'])
    member, received = event['cutoff_membership'], event['received_at']
    need(member in ('included', 'after', 'unknown'), 'unknown cutoff membership')
    if received is not None:
        when = stamp(received)
        need(when <= assessed and ((member == 'included' and when <= cutoff)
             or (member == 'after' and when > cutoff)), 'inconsistent receipt time/membership')
    else:
        need(member in ('included', 'after', 'unknown'), 'unknown membership')


def snapshot_shape(snapshot, cutoff, assessed):
    metadata(snapshot, 'submission_snapshot_design', ('snapshot_id', 'as_of', 'inventory_state', 'collection_basis_ref', 'entries'))
    label(snapshot['snapshot_id']); need(stamp(snapshot['as_of']) == cutoff, 'snapshot/cutoff mismatch')
    ref_shape(snapshot['collection_basis_ref'])
    need(snapshot['inventory_state'] in ('closed', 'partial', 'unavailable'), 'unknown inventory state')
    entries = snapshot['entries']; ids = set()
    need(type(entries) is list and len(entries) <= 256, 'entries bound')
    for entry in entries:
        exact(entry, ('entry_id', 'source_namespace', 'native_input_kind', 'originals'), ('candidate_for', 'detached_proofs'))
        for k in ('entry_id', 'source_namespace', 'native_input_kind'):
            label(entry[k])
        need(entry['entry_id'] not in ids, 'duplicate entry ID'); ids.add(entry['entry_id'])
        if 'candidate_for' in entry:
            hints = entry['candidate_for']; need(type(hints) is list and len(hints) <= 256, 'hint bound')
            for hint in hints:
                label(hint)
        originals = entry['originals']
        need(type(originals) is dict and len(originals) <= 18, 'original inventory bound')
        kind = entry['native_input_kind']
        if kind == 'receipt_pair':
            need(set(originals) == {'admission', 'post'}, 'receipt inventory fields')
        if kind == 's3_bundle':
            need(set(originals) == MEMBERS, 'S3 member inventory fields')
        for name, ev in originals.items():
            label(name); event_shape(ev, cutoff, assessed)
        if 'detached_proofs' in entry:
            exact(entry['detached_proofs'], ('admission', 'post'))
            for ev in entry['detached_proofs'].values():
                event_shape(ev, cutoff, assessed)


class Reader:
    def __init__(self, roots, limits, started):
        self.roots = {key: Path(value).resolve() for key, value in roots.items()}
        self.limits, self.started = limits, started
        self.used = 0
        self.history_used = 0
        self.log = []
        self.cache = {}
    def read(self, ref, cap=MIB, *, history=False):
        ref_shape(ref, REPORT_LIMIT if history else MIB)
        key = (history, encode(ref))
        limit = self.limits['history_bytes' if history else 'bytes']
        used = self.history_used if history else self.used
        if key in self.cache and len(self.cache[key]) <= cap:
            return self.cache[key]
        item = {'ref': copy.deepcopy(ref)}
        self.log.append(item)
        try:
            need(time.monotonic()-self.started < self.limits['seconds'], 'assessment time bound', 'EVALUATION_LIMIT')
            need(ref['byte_length'] <= cap, 'individual file bound', 'INPUT_SIZE_ERROR')
            need(used+ref['byte_length'] <= limit, 'cumulative input bound', 'EVALUATION_LIMIT')
            need(ref['path_base'] in self.roots, 'path base is not selected', 'REF_UNAVAILABLE')
            fd = os.open(self.roots[ref['path_base']], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                parts = PurePosixPath(ref['path']).parts
                for part in parts[:-1]:
                    nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd); fd = nxt
                f = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    info = os.fstat(f)
                    need(stat.S_ISREG(info.st_mode), 'not a regular file', 'UNSAFE_REFERENCE')
                    need(info.st_size <= cap, 'individual file bound', 'INPUT_SIZE_ERROR')
                    need(used+info.st_size <= limit, 'cumulative input bound', 'EVALUATION_LIMIT')
                    with os.fdopen(os.dup(f), 'rb') as stream:
                        raw = stream.read(min(cap, limit-used)+1)
                    used += len(raw)
                    if history:
                        self.history_used = used
                    else:
                        self.used = used
                finally:
                    os.close(f)
            finally:
                os.close(fd)
            need(len(raw) <= cap and used <= limit, 'read bound', 'EVALUATION_LIMIT')
            item['observed'] = identity(raw)
            need(len(raw) == ref['byte_length'] and sha(raw) == ref['digest']['value'], 'raw identity mismatch', 'RAW_IDENTITY_MISMATCH')
            item['status'] = 'read'
            self.cache[key] = raw
            return raw
        except OSError as exc:
            issue = Problem('REF_UNAVAILABLE', str(exc)); item['error'] = issue.as_dict(); raise issue from exc
        except Problem as exc:
            item['error'] = exc.as_dict(); raise


def extract(raw, kind):
    doc = decode(raw, 32)
    need(doc.get('version') == 'vate-0.3' and doc.get('profile') == 'VATE-AL2-Verifier-Admission-v0.3'
         and doc.get('receipt_type') == kind, 'unsupported receipt profile')
    try:
        if kind == 'admission':
            part = doc['request']; runtime = doc['subject']['runtime']
            need(part['action'] == 's3.put_object', 'unsupported admission action')
            request_hash = part['input_hash']
        else:
            part = doc['execution']; runtime = part['runtime']; request_hash = part['effective_request_hash']
        context = {'transaction_id': part['transaction_id'], 'runtime': runtime,
                   'effective_request_hash': request_hash, 'action_binding': part['action_binding']}
        context_shape(context)
        return doc, context
    except (KeyError, TypeError) as exc:
        raise Problem('UNSUPPORTED_CONTEXT', str(exc)) from exc


def event_read(event, reader, cap=MIB):
    if event is None:
        return {'state': 'absent', 'event': None, 'raw': None}
    result = {'state': event['cutoff_membership'], 'event': copy.deepcopy(event), 'raw': None}
    try:
        reader.read(event['receipt_basis_ref'])
        result['raw'] = reader.read(event['ref'], cap)
    except Problem as exc:
        result['state'] = 'unknown'; result['error'] = exc.as_dict()
    return result


def public_event(value):
    return {k: v for k, v in value.items() if k != 'raw'} | {'raw_identity': identity(value['raw'])}


def timed(events, due):
    stamps = [stamp(e['event']['received_at']) for e in events if e['event']
              and e['event']['received_at'] is not None and e['state'] != 'after']
    unknown = any(e['event'] and e['event']['received_at'] is None and e['state'] != 'after' for e in events)
    if any(t <= due for t in stamps):
        return 'on_time'
    return 'unknown' if unknown or not stamps else 'late'


def native_error(code, detail):
    return {'invocation': {'status': 'error'}, 'error': {'code': code, 'detail': detail}}


def is_error(result):
    return result.get('invocation', {}).get('status') == 'error'


class Reviewer:
    def __init__(self, *, path_bases, source_root, openssl=None, openssl_sha256=None, limits=None):
        self.roots = path_bases; self.source_root = Path(source_root).resolve()
        self.openssl, self.openssl_sha256 = openssl, openssl_sha256
        self.limits = dict(DEFAULT_LIMITS)
        if limits:
            need(type(limits) is dict and set(limits) <= set(DEFAULT_LIMITS), 'unknown limits')
            for k, v in limits.items():
                need(type(v) is int and 0 < v <= DEFAULT_LIMITS[k], 'limits may only shrink')
            self.limits.update(limits)

    def assess(self, selection_raw):
        started = time.monotonic()
        reader = Reader(self.roots, self.limits, started)
        out = {'contract': CONTRACT, 'scope': 'receiver_selected_set_only', 'review_set_status': 'not_assessed',
               'requirements': [], 'native_calls': [], 'diagnostics': [], 'input_refs': reader.log,
               'selection_identity': identity(selection_raw) if type(selection_raw) is bytes else None, 'limits': dict(self.limits),
               'not_checked': ['global_activity_completeness', 'obligation_authority', 'actual_execution', 'current_permission_to_execute']}
        try:
            need(selection_raw is not None, 'receiver selection absent', 'SELECTION_ABSENT')
            need(type(selection_raw) is bytes and len(selection_raw) <= MIB, 'selection bytes bound')
            selected = decode(selection_raw)
            metadata(selected, 'receiver_selection_design', ('receiver_id', 'review_set_selected_at', 'snapshot_selected_at',
                'assessment_time', 'assessment_cutoff', 'review_set_ref', 'submission_snapshot_ref', 'selection_basis_ref', 'native_policy_refs'))
            label(selected['receiver_id'])
            cutoff, assessed = stamp(selected['assessment_cutoff']), stamp(selected['assessment_time'])
            need(stamp(selected['review_set_selected_at']) <= assessed and cutoff <= stamp(selected['snapshot_selected_at']) <= assessed, 'selection time order')
            for key in ('review_set_ref', 'submission_snapshot_ref', 'selection_basis_ref'):
                ref_shape(selected[key])
            exact(selected['native_policy_refs'], ('s3', 'signature'))
            for ref in selected['native_policy_refs'].values():
                if ref is not None:
                    ref_shape(ref)
            reader.read(selected['selection_basis_ref'])
            review = decode(reader.read(selected['review_set_ref'])); review_shape(review)
            snapshot = decode(reader.read(selected['submission_snapshot_ref'])); snapshot_shape(snapshot, cutoff, assessed)
            for ref in review['population_basis_refs']:
                reader.read(ref)
            reader.read(snapshot['collection_basis_ref'])
            for row in review['requirements']:
                for ref in row['basis_refs']:
                    reader.read(ref)
                if 'waiver_ref' in row:
                    reader.read(row['waiver_ref'])
            prior = self._prior(review, selected, reader, cutoff)
            policy = {k: reader.read(ref, 256*1024 if k == 's3' else 64*1024) if ref else None
                      for k, ref in selected['native_policy_refs'].items()}
            out.update(selection=selected, review_set_identity=identity(reader.read(selected['review_set_ref'])),
                       submission_snapshot_identity=identity(reader.read(selected['submission_snapshot_ref'])),
                       assessment_cutoff=selected['assessment_cutoff'], previous=prior,
                       review_set_status='selected' if review['requirements'] else 'selected_empty',
                       review_set_selection_timing='after_cutoff' if stamp(selected['review_set_selected_at']) > cutoff else 'before_or_at_cutoff')
            from native_bridge import Bridge
            bridge = Bridge(source_root=self.source_root, openssl=self.openssl, openssl_sha256=self.openssl_sha256,
                            limits=self.limits, started=started, calls=out['native_calls'],
                            composer_sha256=LOADED_SOURCE_SHA256, composer_error=LOADED_SOURCE_ERROR)
            out['source_identity'] = bridge.identity
            if bridge.source_error:
                out['diagnostics'].append(copy.deepcopy(bridge.source_error['error']))
            processed = []
            for entry in sorted(snapshot['entries'], key=lambda e: e['entry_id']):
                checks = sorted({check for row in review['requirements'] for check in row['requested_native_checks']
                                 if entry['source_namespace'] == review['namespace']})
                processed.append(self._entry(entry, reader, bridge, policy, checks))
            deadline = started + self.limits['seconds']
            for row in sorted(review['requirements'], key=lambda r: r['requirement_id']):
                out['requirements'].append(self._row(row, review['namespace'], snapshot['inventory_state'], processed, cutoff, deadline))
            out['entries'] = [self._public_entry(e) for e in processed]
            out['counts'] = {state: sum(r['record_coverage'] == state for r in out['requirements'])
                             for state in ('present', 'missing', 'pending', 'unresolved', 'waived_by_receiver')}
            source_error = bridge.check_composer()
            if source_error and source_error['error'] not in out['diagnostics']:
                out['diagnostics'].append(copy.deepcopy(source_error['error']))
        except Problem as exc:
            out['review_set_status'] = 'not_assessed' if exc.code in ('SELECTION_ABSENT', 'REF_UNAVAILABLE', 'EVALUATION_LIMIT') else 'invalid'
            out['requirements'] = []; out['diagnostics'].append(exc.as_dict())
        if time.monotonic() - started >= self.limits['seconds']:
            out['diagnostics'].append({'code': 'EVALUATION_LIMIT', 'detail': 'processing deadline reached; unfinished candidate comparisons remain unknown'})
        out['usage'] = {'bytes_read': reader.used, 'history_bytes_read': reader.history_used, 'native_calls': len(out['native_calls']),
                        'native_result_bytes': sum(len(encode(c['result'])) for c in out['native_calls']),
                        'elapsed_milliseconds': int((time.monotonic()-started)*1000)}
        out['invocation_errors'] = (out['review_set_status'] in ('invalid', 'not_assessed')
            or bool(out['diagnostics'])
            or any('error' in log for log in reader.log) or any(is_error(c['result']) for c in out['native_calls'])
            or any(any(s.get('status') == 'error' for s in c['result'].get('signatures', {}).values()) for c in out['native_calls']))
        if len(encode(out)) > REPORT_LIMIT:
            out['review_set_status'] = 'not_assessed'
            out['requirements'] = []
            out['diagnostics'].append({'code': 'REPORT_SIZE_LIMIT', 'detail': 'comparison details exceed the report bound; full native calls and inputs retained'})
            out.pop('counts', None)
            out['invocation_errors'] = True
        elapsed = time.monotonic()-started
        out['usage']['elapsed_milliseconds'] = int(elapsed*1000)
        if elapsed >= self.limits['seconds'] and not any(d['code'] == 'EVALUATION_LIMIT' for d in out['diagnostics']):
            out['diagnostics'].append({'code': 'EVALUATION_LIMIT', 'detail': 'report preparation reached the processing deadline'})
            out['invocation_errors'] = True
        return out

    @staticmethod
    def _prior(review, selected, reader, cutoff):
        if review['revision'] == 1:
            return None
        old = decode(reader.read(review['previous_review_set_ref'])); review_shape(old)
        report_raw = reader.read(review['previous_report_ref'], REPORT_LIMIT, history=True); report = decode(report_raw, 64)
        reader.read(review['revision_basis_ref'])
        need(old['review_set_id'] == review['review_set_id'] and old['namespace'] == review['namespace']
             and old['revision']+1 == review['revision'], 'previous revision mismatch')
        need(report.get('contract') == CONTRACT and report.get('review_set_status') in ('selected', 'selected_empty')
             and report.get('review_set_identity') == identity(reader.read(review['previous_review_set_ref'])), 'previous report binding')
        need(stamp(report.get('assessment_cutoff')) <= cutoff, 'revision cutoff regressed')
        new = {r['requirement_id']: r for r in review['requirements']}
        for row in old['requirements']:
            need(row['requirement_id'] in new, 'removed prior requirement; use waiver')
            nxt = new[row['requirement_id']]
            need(encode(row['subject']) == encode(nxt['subject']) and row['record_kind'] == nxt['record_kind'], 'changed prior requirement subject')
        return {k: copy.deepcopy(review[k]) for k in ('previous_review_set_ref', 'previous_report_ref', 'revision_basis_ref')}

    @staticmethod
    def _entry(entry, reader, bridge, policies, checks):
        s3 = entry['native_input_kind'] == 's3_bundle'
        originals = {k: event_read(v, reader, 256*1024 if s3 else MIB) for k, v in sorted(entry['originals'].items())}
        proofs = {k: event_read(v, reader, 4096) for k, v in entry.get('detached_proofs', {}).items()}
        supported = {'receipt_linkage', 'signatures_and_issuer_authority'}
        if s3:
            supported.add('s3_observation_binding')
        if entry['native_input_kind'] not in ('receipt_pair', 's3_bundle'):
            supported = set()
        value = {'entry': entry, 'originals': originals, 'proofs': proofs, 'native_refs': [], 's3_result': None,
                 'check_support': {'requested': checks, 'supported_by_components': sorted(set(checks) & supported),
                                   'unsupported': sorted(set(checks) - supported)}}
        if entry['native_input_kind'] not in ('receipt_pair', 's3_bundle'):
            return value
        def available(ev):
            return ev['raw'] if ev and ev['state'] == 'included' else None
        admission = available(originals.get('admission.json' if s3 else 'admission'))
        post = available(originals.get('post.json' if s3 else 'post'))
        reuse = False; block_fallback = False
        if 'signatures_and_issuer_authority' in checks:
            sig, call_id = bridge.call('signature', {'admission': admission, 'post': post,
                'admission_proof': available(proofs.get('admission')), 'post_proof': available(proofs.get('post')),
                'receiver_policy': policies['signature']}, checks)
            value['native_refs'].append(call_id)
            reuse = 'receipt_assessment' in sig
            if is_error(sig):
                code = sig['error']['code']
                block_fallback = any(x in code for x in ('SOURCE', 'WRAPPER', 'COMPOSER', 'RECIPIENT_API'))
        if not reuse and not block_fallback:
            _, call_id = bridge.call('receipt', {'admission': admission, 'post': post}, checks)
            value['native_refs'].append(call_id)
        if s3:
            bundle = {name: ev['raw'] for name, ev in originals.items() if ev['state'] == 'included' and ev['raw'] is not None}
            result, call_id = bridge.call('s3', {'members': bundle, 'receiver_policy': policies['s3']}, checks)
            value['s3_result'] = result; value['native_refs'].append(call_id)
        return value

    @staticmethod
    def _public_entry(entry):
        return {'entry': entry['entry'], 'originals': {k: public_event(v) for k,v in entry['originals'].items()},
                'proofs': {k: public_event(v) for k,v in entry['proofs'].items()}, 'native_result_refs': entry['native_refs'],
                'check_support': entry['check_support']}

    @staticmethod
    def _candidate(row, namespace, entry):
        data = entry['entry']; s3 = data['native_input_kind'] == 's3_bundle'
        name = ('admission' if row['record_kind'] == 'admission' else 'post') + ('.json' if s3 else '')
        ev = entry['originals'].get(name)
        answer = {'entry_id': data['entry_id'], 'binding': 'unknown', 'reason': 'UNSUPPORTED_INPUT',
                  'record': {'original_name': name, 'state': ev['state'], 'raw_identity': identity(ev['raw'])} if ev else None, 'native_result_refs': entry['native_refs']}
        def verdict(binding, reason):
            answer.update(binding=binding, reason=reason); return answer, ev
        if namespace != data['source_namespace']:
            return verdict('excluded', 'NAMESPACE_MISMATCH')
        if data['native_input_kind'] not in ('receipt_pair', 's3_bundle'):
            return verdict('unknown', 'UNSUPPORTED_INPUT')
        if ev['state'] == 'absent':
            return verdict('absent', 'NOT_SUPPLIED')
        # A failed identity/basis read must not lend an unverified exclusion.
        if ev['state'] == 'after':
            return verdict('excluded', 'AFTER_CUTOFF')
        if ev['raw'] is None or 'error' in ev:
            return verdict('unknown', 'ORIGINAL_UNAVAILABLE')
        try:
            cache = entry.setdefault('parsed_contexts', {})
            if name not in cache:
                try:
                    cache[name] = extract(ev['raw'], row['record_kind'])
                except Problem as error:
                    cache[name] = error
            if isinstance(cache[name], Problem):
                raise cache[name]
            doc, context = cache[name]
        except Problem:
            return verdict('unknown', 'UNSUPPORTED_CONTEXT')
        if encode(context) != encode(row['subject']['native_context']):
            return verdict('excluded', 'CONTEXT_MISMATCH')
        if ev['state'] == 'unknown':
            return verdict('unknown', 'CUTOFF_MEMBERSHIP_UNKNOWN')
        if row['subject']['kind'] == 'attempt':
            if not s3:
                return verdict('unknown', 'ATTEMPT_ORIGINALS_REQUIRED')
            if not all(e['state'] == 'included' and e['raw'] is not None and 'error' not in e for e in entry['originals'].values()):
                return verdict('unknown', 'ATTEMPT_SUPPORT_UNAVAILABLE_AT_CUTOFF')
            native = (entry['s3_result'] or {}).get('native_result', {})
            if not all(native.get(k) == v for k,v in {'request_binding':'matched', 'attempt_binding':'response_linked',
                    'post_observation_binding':'matched', 'source_trust':'accepted_local_assumption'}.items()):
                return verdict('unknown', 'ATTEMPT_NATIVE_BINDING_NOT_ESTABLISHED')
            try:
                attempt = decode(entry['originals']['attempt.json']['raw'], 32)
                label(attempt['attempt_id'])
                need(attempt['contract'] == S3, 'unknown attempt contract')
            except (Problem, KeyError):
                return verdict('unknown', 'UNSUPPORTED_ATTEMPT')
            try:
                label(doc.get('receipt_id'))
            except Problem:
                return verdict('unknown', 'POST_IDENTIFIER_UNAVAILABLE')
            wanted = row['subject']['attempt_id']
            if attempt['attempt_id'] != wanted:
                return verdict('excluded', 'ATTEMPT_ID_MISMATCH')
            if doc.get('receipt_id') != 'post-'+wanted:
                return verdict('unknown', 'POST_IDENTIFIER_BINDING_UNSUPPORTED')
            times = [e['event']['received_at'] for e in entry['originals'].values()]
            answer['binding_available_at'] = max(times, key=stamp) if all(times) else None
        return verdict('matched', 'CONTEXT_MATCHED')

    def _row(self, row, namespace, inventory, entries, cutoff, deadline):
        candidates, matching, unknown = [], {}, []
        events = []; witnesses = {}; unprocessed = []
        def bundle_bytes(entry):
            if entry['entry']['native_input_kind'] != 's3_bundle':
                return None
            originals = entry['originals']
            if set(originals) != MEMBERS or any(v['raw'] is None or 'error' in v for v in originals.values()):
                return None
            return tuple((k, v['raw']) for k,v in sorted(originals.items()))
        for position, entry in enumerate(entries):
            if time.monotonic() >= deadline:
                unprocessed = [e['entry']['entry_id'] for e in entries[position:] if e['entry']['source_namespace'] == namespace]
                break
            candidate, ev = self._candidate(row, namespace, entry)
            candidates.append(candidate)
            if candidate['binding'] == 'matched':
                matching.setdefault(ev['raw'], []).append(ev); events.append(ev)
                witness = bundle_bytes(entry)
                if witness is not None:
                    witnesses[witness] = candidate['entry_id']
            elif candidate['binding'] == 'unknown':
                unknown.append((candidate, ev, entry))
        # Identical bytes with unknown arrival cannot create a second candidate;
        # its uncertain time is still retained. Unsupported attempt linkage is
        # not cured merely by a matching post in another bundle.
        unresolved = list(unprocessed)
        for candidate, ev, entry in unknown:
            if (candidate['reason'] == 'CUTOFF_MEMBERSHIP_UNKNOWN' and ev and ev['raw'] in matching
                    and row['subject']['kind'] == 'operation'):
                events.append(ev)
                candidate['deduplicated_unknown'] = 'identical_operation_bytes'
            elif (row['subject']['kind'] == 'attempt' and ev and ev['raw'] in matching
                  and candidate['reason'] in ('CUTOFF_MEMBERSHIP_UNKNOWN', 'ATTEMPT_SUPPORT_UNAVAILABLE_AT_CUTOFF')
                  and bundle_bytes(entry) in witnesses):
                events.append(ev)
                candidate['deduplicated_unknown'] = 'identical_complete_bundle'
                candidate['binding_reused_from'] = witnesses[bundle_bytes(entry)]
            else:
                unresolved.append(candidate['entry_id'])
        reasons = []
        if inventory != 'closed': reasons.append('INVENTORY_NOT_CLOSED')
        if unresolved: reasons.append('UNKNOWN_COMPETING_CANDIDATE')
        if unprocessed: reasons.append('EVALUATION_LIMIT')
        if len(matching) > 1: reasons.append('AMBIGUOUS_ORIGINALS')
        obligation = row['obligation']
        if obligation == 'waived_by_receiver':
            coverage = 'waived_by_receiver'
        elif obligation == 'undetermined':
            coverage = 'unresolved'; reasons.append('OBLIGATION_UNDETERMINED')
        elif reasons:
            coverage = 'unresolved'
        elif matching:
            coverage = 'present'
        else:
            coverage = 'missing' if cutoff > stamp(row['due_at']) else 'pending'
        present = any(c['binding'] not in ('excluded', 'absent') and c['record'] and c['record']['raw_identity'] for c in candidates)
        unread = any(c['binding'] == 'unknown' and (not c['record'] or not c['record']['raw_identity']) for c in candidates) or bool(unprocessed)
        presence = 'mixed' if present and unread else 'bytes_available' if present else 'unavailable' if unread or inventory != 'closed' else 'absent_in_snapshot'
        timeliness = timed(events, stamp(row['due_at'])) if events and 'due_at' in row else 'unknown' if coverage == 'unresolved' else 'not_received'
        if coverage == 'unresolved' and timeliness == 'late':
            timeliness = 'unknown'
        return {'requirement_id': row['requirement_id'], 'unprocessed_entry_ids': unprocessed, 'requirement': copy.deepcopy(row),
                'record_coverage': coverage, 'timeliness': timeliness, 'candidate_presence': presence,
                'unique_candidates': len(matching), 'reasons': reasons, 'candidates': candidates,
                'native_result_refs': sorted({ref for c in candidates for ref in c['native_result_refs']})}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', type=Path, required=True)
    parser.add_argument('--base', action='append', default=[], help='receiver selected NAME=directory')
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--openssl'); parser.add_argument('--openssl-sha256')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        roots = {}
        for arg in args.base:
            name, path = arg.split('=', 1); label(name); need(name not in roots, 'duplicate path base'); roots[name] = path
        fd = os.open(args.selection, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            need(stat.S_ISREG(os.fstat(fd).st_mode), 'selection must be a regular file')
            with os.fdopen(os.dup(fd), 'rb') as stream:
                raw = stream.read(MIB+1)
        finally:
            os.close(fd)
        result = Reviewer(path_bases=roots, source_root=args.source_root, openssl=args.openssl,
                          openssl_sha256=args.openssl_sha256).assess(raw)
        # Exclusive creation keeps an earlier report immutable.
        with args.output.open('xb') as stream:
            stream.write(encode(result)+b'\n')
        return 64 if result['invocation_errors'] else 0
    except (Problem, OSError, ValueError) as exc:
        print(json.dumps({'contract': CONTRACT, 'error': str(exc)})); return 64


if __name__ == '__main__':
    raise SystemExit(main())
