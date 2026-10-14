#!/usr/bin/env python3
"""Compare the fixed three NENRIN/VATE cases without creating an overall verdict.

Standard library only. Never executes, imports, repairs, or rewrites an input.
Run manifests are local custody records, not signed proof of execution.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

NENRIN_COMMIT = 'bfde94be9d8089b7c683bc31b9c39c3879b07ab2'
VATE_COMMIT = 'b3b6d4f9610e159e92d3b41b66e72fc7251758dc'
NENRIN_ROOT = 'third_party/nenrin'
MANIFEST_SHA = 'c2689c92050bec2285466282eeccff3549e9d72e8869e6b4906c017775664ea7'
VATE_PINS_SHA = '57b40ffb1f302f2bc2fb05b5b448677867fa3bf56491af234bb4095a7acef2c8'
CONTRACT = 'vate-local-s3-observation-v1'
VATE_CANON = 'vate-v0.3-fixture-json;ascii-escaped;sorted;compact;no-floats'
NENRIN_CANON = 'musubi-canonical-v0'
CASES = {'match': 'matching', 'target_mismatch': 'target-mismatch', 'missing_receipt': 'missing-post'}
PACKAGES = {'npm': ('nenrin-verify', '0.5.1'), 'pypi': ('nenrin-verify', '0.5.3')}
NATIVE_PYTHON_ENTRY = 'from nenrin_verify.cli import main; raise SystemExit(main())'
NATIVE_CACHE_POLICY = 'fresh-empty-prefix-per-invocation-no-bytecode-writes-v1'
NATIVE_PYTHON_PROBE = r'''
import hashlib, importlib.metadata as metadata, json, pathlib, sys
expected = json.load(sys.stdin)
distribution = metadata.distribution('nenrin-verify')
assert distribution.version == '0.5.3', 'expected nenrin-verify==0.5.3'
root = pathlib.Path(distribution.locate_file('')).resolve()
package = root / 'nenrin_verify'
assert package.is_dir() and not package.is_symlink(), 'invalid Python package directory'
files = {}
for relative in sorted(expected):
    path = root / relative
    cursor = root
    for part in pathlib.PurePosixPath(relative).parts:
        cursor /= part
        assert not cursor.is_symlink(), 'symlink in Python package source'
    raw = path.read_bytes()
    files[relative] = {'sha256': hashlib.sha256(raw).hexdigest(), 'byte_length': len(raw)}
actual = {path.relative_to(root).as_posix() for path in package.rglob('*.py')}
assert actual == set(expected), 'unexpected/missing Python package source'
assert files == expected, 'Python package source hash differs'
versions = {name: metadata.version(name) for name in ('nenrin-verify', 'cryptography', 'cffi', 'pycparser')}
print(json.dumps({'source_identity': files, 'runtime': {'python_version': sys.version,
      'executable': sys.executable, 'packages': versions}}, sort_keys=True))
'''
VATE_BOOTSTRAP = ("import pathlib,runpy,sys;root=pathlib.Path('source').resolve();"
                  "sys.path.insert(0,str(root/'reference/s3-observation-example'));"
                  "import contract;assert contract.ROOT==root,'wrong source root';"
                  "entry=sys.argv.pop(1);runpy.run_path(entry,run_name='__main__')")
TARGET_KEYS = ('endpoint_profile_id', 'bucket', 'key')
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_FILES = 512
HEX = re.compile(r'[0-9a-f]{64}\Z')
MISSING = object()


class InputError(ValueError):
    """Unusable custody record, path, or fixed input: produce no comparison."""


class Unavailable(ValueError):
    """One relationship cannot be assessed; independent relationships continue."""


def require(ok, message):
    if not ok:
        raise InputError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fingerprint(raw):
    return {'sha256': sha(raw), 'byte_length': len(raw)}


def native_python_command(executable, cache_path, code, arguments=()):
    return [str(executable), '-I', '-B', '-X', 'pycache_prefix=' + cache_path, '-c', code, *arguments]


def native_cache_record(label):
    return {'path': '.python-cache/' + label, 'empty_before': True, 'empty_after': True}


def check_value(value, depth=0, musubi=False):
    if depth > 40:
        raise ValueError('JSON nesting exceeds 40')
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if abs(value) > 9007199254740991:
            raise ValueError('unsafe integer')
    elif type(value) is str:
        value.encode('utf-8')  # Reject isolated surrogates.
    elif type(value) is list:
        if len(value) > 4096:
            raise ValueError('array exceeds 4096 items')
        for item in value:
            check_value(item, depth + 1, musubi)
    elif type(value) is dict:
        if len(value) > 4096:
            raise ValueError('object exceeds 4096 entries')
        for key, item in value.items():
            if type(key) is not str or (musubi and not re.fullmatch(r'[\x20-\x7e]*', key)):
                raise ValueError('object key outside canonical profile')
            check_value(key, depth + 1, musubi)
            check_value(item, depth + 1, musubi)
    else:
        raise ValueError('non-integer number or non-JSON value')


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key: ' + key)
            result[key] = value
        return result

    def integer(text):
        if text == '-0':
            raise ValueError('negative zero outside the local input profile')
        number = int(text)
        if abs(number) > 9007199254740991:
            raise ValueError('unsafe integer')
        return number

    def no_float(text):
        raise ValueError('non-integer JSON number: ' + text)

    try:
        require(len(raw) <= MAX_FILE, 'JSON exceeds size limit')
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                           parse_float=no_float, parse_constant=no_float, parse_int=integer)
        check_value(value)
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InputError('invalid bounded JSON: ' + str(exc)) from exc


def canonical(value, *, musubi=False):
    check_value(value, musubi=musubi)
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=not musubi, allow_nan=False).encode('utf-8')


def same(left, right):
    return canonical(left) == canonical(right)


def relative_parts(path):
    require(type(path) is str and 0 < len(path) <= 1024, 'invalid relative path')
    parts = path.split('/')
    require(all(part not in ('', '.', '..') and '\\' not in part and '\x00' not in part for part in parts),
            'unsafe relative path: ' + repr(path))
    return parts


class Reader:
    """Read bounded regular files through no-follow directory descriptors."""
    def __init__(self, root, collection='example'):
        self.collection = collection
        self.root = Path(os.path.abspath(root))
        # Do not turn a user-supplied symlink into an apparently ordinary root.
        cursor = Path(self.root.anchor)
        for part in self.root.parts[1:]:
            cursor /= part
            require(not cursor.is_symlink(), 'symlink in input root')
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.cache = {}
        self.total = 0

    def close(self):
        os.close(self.fd)

    @contextmanager
    def directory(self, parts):
        fd = os.dup(self.fd)
        try:
            for part in parts:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            yield fd
        finally:
            os.close(fd)

    def read(self, path):
        parts = relative_parts(path)
        if path in self.cache:
            return self.cache[path]
        require(len(self.cache) < MAX_FILES, 'too many input files')
        with self.directory(parts[:-1]) as directory:
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                info = os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE, 'not a bounded regular file: ' + path)
                with os.fdopen(os.dup(fd), 'rb') as stream:
                    raw = stream.read(MAX_FILE + 1)
                require(len(raw) <= MAX_FILE, 'file grew beyond limit: ' + path)
            finally:
                os.close(fd)
        self.total += len(raw)
        require(self.total <= MAX_TOTAL, 'total input byte limit exceeded')
        self.cache[path] = raw
        return raw

    def names(self, path):
        with self.directory(relative_parts(path)) as directory:
            names = os.listdir(directory)
        require(len(names) <= MAX_FILES, 'directory inventory exceeds limit')
        return set(names)

    def document(self, path):
        return Document(path, self.read(path), collection=self.collection)

    def bound(self, reference, expected_path=None):
        require(type(reference) is dict, 'artifact reference must be an object')
        path = reference.get('path')
        relative_parts(path)
        require(expected_path is None or path == expected_path, 'wrong case/artifact path: ' + path)
        raw = self.read(path)
        require(type(reference.get('byte_length')) is int and HEX.fullmatch(str(reference.get('sha256', ''))) is not None,
                'invalid raw fingerprint: ' + path)
        require(same(fingerprint(raw), {key: reference[key] for key in ('sha256', 'byte_length')}),
                'raw input/output binding mismatch: ' + path)
        return Document(path, raw, collection=self.collection)


class Document:
    def __init__(self, path, raw, *, binary=False, collection='example'):
        self.path, self.raw, self.collection = path, raw, collection
        self.value, self.error = None, None
        if raw is None:
            self.error = 'artifact absent'
        elif not binary:
            try:
                self.value = decode(raw)
            except InputError as exc:
                self.error = str(exc)

    def ref(self, pointer=''):
        result = {'collection': self.collection, 'path': self.path, 'pointer': pointer, 'basis': 'raw-file-sha256'}
        if self.raw is not None:
            result.update(fingerprint(self.raw))
        else:
            result['absent'] = True
        return result

    def get(self, pointer=''):
        if self.error:
            raise Unavailable(self.path + ': ' + self.error)
        value = self.value
        if pointer:
            for key in pointer[1:].split('/'):
                key = key.replace('~1', '/').replace('~0', '~')
                try:
                    value = value[int(key)] if type(value) is list else value[key]
                except (KeyError, IndexError, TypeError, ValueError) as exc:
                    raise Unavailable(self.path + ': absent pointer ' + pointer) from exc
        return value

    def operand(self, pointer='', validator=None, profile=None):
        result = {'sources': [self.ref(pointer)]}
        try:
            if profile:
                for field, expected in profile.items():
                    if not same(self.get('/' + field), expected):
                        raise Unavailable('unknown profile: ' + field)
            value = self.get(pointer)
            result['value'] = validator(value) if validator else value
        except (Unavailable, ValueError, TypeError, UnicodeError) as exc:
            result['unavailable'] = str(exc)
        return result


def text_value(value):
    if type(value) is not str or not value:
        raise Unavailable('nonempty string required')
    return value


def hex_value(value):
    if type(value) is not str or not HEX.fullmatch(value):
        raise Unavailable('lowercase SHA-256 hex required')
    return value


def tagged_hash(value):
    if type(value) is not str or not value.startswith('sha-256:'):
        raise Unavailable('sha-256: digest prefix required')
    return hex_value(value[8:])


def descriptor(value):
    if type(value) is not dict or set(value) != {'alg', 'value'} or value.get('alg') != 'sha-256':
        raise Unavailable('unknown digest algorithm or shape')
    return hex_value(value['value'])


def length_value(value):
    if type(value) is not int or not 0 <= value <= 4096:
        raise Unavailable('body length must be an integer in 0..4096, not bool')
    return value


def identifier(value):
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9_.-]{1,90}', value) or value in ('.', '..'):
        raise Unavailable('identifier outside fixed ASCII profile')
    return value


def version_value(value):
    value = text_value(value)
    if value == 'null':
        raise Unavailable('version must identify a stored version, not null')
    return value


def exact_time(value):
    if type(value) is not str or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z', value):
        raise Unavailable('six-digit UTC timestamp required for this fixed comparison')
    datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ')
    return value


def micros(value):
    delta = datetime.strptime(exact_time(value), '%Y-%m-%dT%H:%M:%S.%fZ') - datetime(1970, 1, 1)
    return (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds


def effective_value(value):
    fields = {'contract', 'operation_id', 'action', *TARGET_KEYS, 'body_digest', 'byte_length', 'if_none_match'}
    if type(value) is not dict or set(value) != fields:
        raise Unavailable('effective request field set differs')
    if (value['contract'], value['action'], value['if_none_match']) != (CONTRACT, 's3.put_object', '*'):
        raise Unavailable('unknown effective request contract')
    for key in ('operation_id', *TARGET_KEYS):
        identifier(value[key])
    descriptor(value['body_digest'])
    length_value(value['byte_length'])
    return value


def vate_binding_value(value):
    if type(value) is not dict or set(value) != {'type', 'canonicalization', 'preimage_profile', 'digest'}:
        raise Unavailable('unknown VATE action binding shape')
    if (value['type'], value['canonicalization'], value['preimage_profile']) != ('profile_defined_digest', VATE_CANON, CONTRACT):
        raise Unavailable('unknown VATE action binding profile')
    descriptor(value['digest'])
    return value


def literal(value, basis='literal fixed comparison rule'):
    return {'value': value, 'sources': [], 'basis': basis}


def computed(basis, function, *operands):
    result = {'basis': basis, 'sources': [source for operand in operands for source in operand['sources']]}
    unavailable = [operand['unavailable'] for operand in operands if 'unavailable' in operand]
    if unavailable:
        result['unavailable'] = '; '.join(dict.fromkeys(unavailable))
    else:
        try:
            result['value'] = function(*(operand['value'] for operand in operands))
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            result['unavailable'] = str(exc)
    return result


def comparison(name, *operands):
    if any('unavailable' in operand for operand in operands):
        status = 'not_assessed'
    else:
        status = 'matched' if all(same(operands[0]['value'], operand['value']) for operand in operands[1:]) else 'mismatched'
    return {'name': name, 'status': status, 'operands': list(operands)}


def row(number, name, components, note=None):
    statuses = {component['status'] for component in components}
    status = 'mismatched' if 'mismatched' in statuses else 'not_assessed' if 'not_assessed' in statuses else 'matched'
    result = {'id': f'CW-{number:02}', 'relationship': name, 'status': status, 'components': components}
    if note:
        result['note'] = note
    return result


def raw_operand(document, function, basis):
    result = {'sources': [document.ref()], 'basis': basis}
    if document.raw is None:
        result['unavailable'] = 'raw artifact absent'
    else:
        result['value'] = function(document.raw)
    return result


def relationship_rows(bundle, vate, policy, manifest, native):
    """Pure comparison; tests may supply explicitly synthetic, unbound Documents.

    The comparison CLI calls this after the public saved/run bindings are checked.
    No component result establishes authenticity or authorization.
    """
    record_profile = {'grant': 'task-execution-bind-v0/grant', 'receipt': 'task-execution-bind-v0/receipt'}

    def n(record, pointer, validator=text_value):
        op = bundle.operand('/' + record + pointer, validator)
        try:
            if bundle.get('/' + record + '/schema') != record_profile[record]:
                op.pop('value', None)
                op['unavailable'] = 'unknown NENRIN record profile'
        except Unavailable as exc:
            op.pop('value', None)
            op['unavailable'] = str(exc)
        return op

    def v(name, pointer, validator=text_value):
        profile = {'version': 'vate-0.3', 'profile': 'VATE-AL2-Verifier-Admission-v0.3'} if name in ('admission', 'post') else {'contract': CONTRACT}
        return vate[name].operand(pointer, validator, profile)

    def target(name):
        return computed('exact ASCII endpoint_profile_id/bucket/key join', lambda *parts: '/'.join(parts),
                        *(v(name, '/' + key, identifier) for key in TARGET_KEYS))

    rows = []
    operation = v('effective-request', '/operation_id', identifier)
    rows.append(row(1, 'operation identifiers', [
        comparison('native_input_to_effective', bundle.operand('/task_id', text_value), operation),
        comparison('grant_to_effective', n('grant', '/task_id'), operation),
        comparison('receipt_to_effective', n('receipt', '/task_id'), operation),
        *[comparison(name + ':' + pointer, v(name, pointer), operation) for name, pointer in
          [('admission', '/request/transaction_id'), ('attempt', '/operation_id'), ('attempt', '/transaction_id'), ('post', '/execution/transaction_id')]]],
        'Identifier equality does not identify an actor, principal, or actual execution.'))
    action = v('effective-request', '/action')
    rows.append(row(2, 'tool name', [comparison('known_tool', action, literal('s3.put_object')),
        comparison('grant_to_effective', n('grant', '/action/tool'), action),
        comparison('receipt_to_effective', n('receipt', '/executed_action/tool'), action)]))
    e_target = target('effective-request')
    g_target, r_target = n('grant', '/action/target'), n('receipt', '/executed_action/target')
    rows.append(row(3, 'NENRIN target relationships', [comparison('grant_to_effective', g_target, e_target),
        comparison('receipt_to_effective', r_target, e_target), comparison('receipt_to_grant', r_target, g_target)],
        'The NENRIN mutation changes receipt target to result-other.txt while retaining the grant.'))
    effective = v('effective-request', '', effective_value)
    request_hash = computed('SHA-256 of full effective-request object; ' + VATE_CANON, lambda value: sha(canonical(value)), effective)
    vate_binding = computed('VATE action_binding over full effective request', lambda h: {
        'type': 'profile_defined_digest', 'canonicalization': VATE_CANON,
        'preimage_profile': CONTRACT, 'digest': {'alg': 'sha-256', 'value': h}}, request_hash)
    rows.append(row(4, 'full effective request digest', [
        comparison('grant_args_to_full_request', n('grant', '/action/args_sha256', hex_value), request_hash),
        comparison('receipt_args_to_full_request', n('receipt', '/executed_action/args_sha256', hex_value), request_hash),
        *[comparison(name + ':' + pointer, v(name, pointer, tagged_hash), request_hash) for name, pointer in
          [('admission', '/request/input_hash'), ('attempt', '/effective_request_hash'), ('post', '/execution/effective_request_hash')]],
        *[comparison(name + '_action_binding', v(name, pointer, vate_binding_value), vate_binding) for name, pointer in
          [('admission', '/request/action_binding'), ('post', '/execution/action_binding')]]],
        'This is the complete nine-field VATE object, not raw body bytes or the NENRIN action object.'))
    put_hash = raw_operand(vate['put-body'], sha, 'SHA-256 of raw PUT body bytes')
    get_hash = raw_operand(vate['get-body'], sha, 'SHA-256 of raw GET body bytes')
    put_length = raw_operand(vate['put-body'], len, 'raw PUT byte length')
    get_length = raw_operand(vate['get-body'], len, 'raw GET byte length')
    body_hash = v('effective-request', '/body_digest', descriptor)
    body_length = v('effective-request', '/byte_length', length_value)
    rows.append(row(5, 'raw body relationships', [
        comparison('receipt_result_to_get_body', n('receipt', '/outcome/result_sha256', hex_value), get_hash),
        comparison('receipt_evidence_ref_to_get_body', n('receipt', '/outcome/evidence/ref', hex_value), get_hash),
        comparison('evidence_kind', n('receipt', '/outcome/evidence/kind'), literal('document_sha256')),
        comparison('evidence_system_present', computed('nonempty opaque system string; never opened', lambda s: True,
                   n('receipt', '/outcome/evidence/system')), literal(True)),
        comparison('put_body_to_effective', put_hash, body_hash), comparison('get_body_to_effective', get_hash, body_hash),
        comparison('put_length_to_effective', put_length, body_length), comparison('get_length_to_effective', get_length, body_length)],
        'Local file hashing does not replace the retained native evidence_bound_unchecked finding.'))
    put_version = v('put-transport', '/returned_version_id', version_value)
    get_version = v('get-transport', '/returned_version_id', version_value)
    requested_version = v('get-request', '/requested_version_id', version_value)
    receipt_version = n('receipt', '/outcome/version_id', version_value)
    components = [comparison('native_versions', put_version, requested_version, get_version),
                  comparison('receipt_to_native_versions', receipt_version, put_version, requested_version, get_version)]
    for name in ('put-request', 'get-request'):
        components.extend([comparison(name + '_to_effective_target', target(name), e_target),
                           comparison(name + '_to_receipt_target', target(name), r_target),
                           comparison(name + '_endpoint_to_receiver_policy', v(name, '/endpoint'),
                                      policy.operand('/endpoint', text_value, {'contract': CONTRACT}))])
    components.append(comparison('receipt_target_to_effective', r_target, e_target))
    rows.append(row(6, 'target AND specified version', components,
        'All target and version components are required. VATE mutates GET key to other.txt; the NENRIN receipt mutation is separate. Equal version/body alone cannot satisfy this row.'))
    result_view = computed('contract.result_view reproduced without importing native source', lambda e, version, h, length: {
        'contract': CONTRACT, **{key: e[key] for key in TARGET_KEYS}, 'version_id': version,
        'body_digest': {'alg': 'sha-256', 'value': h}, 'byte_length': length}, effective, get_version, get_hash, get_length)
    result_hash = computed('SHA-256 of full structured VATE result view; ' + VATE_CANON, lambda value: sha(canonical(value)), result_view)
    effects = computed('one exact structured side effect projection', lambda view: [
        {'tool': 's3.put_object', **{key: value for key, value in view.items() if key != 'contract'}}], result_view)
    rows.append(row(7, 'structured VATE result projection', [
        comparison('structured_output_hash', v('post', '/result/output_hash', tagged_hash), result_hash),
        comparison('side_effect_projection', v('post', '/result/side_effects', lambda x: x), effects),
        comparison('outcome', v('post', '/result/outcome'), literal('success')),
        comparison('policy_violations', v('post', '/result/policy_violations', lambda x: x), literal([]))],
        'Projection equality does not override CW-06 or the native post_observation_binding. Raw body digest, request digest, and structured result digest are separate preimages.'))
    start, finish = (v('put-transport', '/' + field, exact_time) for field in ('started_at', 'finished_at'))
    before, after = (n('grant', '/' + field, exact_time) for field in ('not_before', 'not_after'))
    rows.append(row(8, 'timestamp text and microsecond window', [
        comparison('executed_at_exact_finish_text', n('receipt', '/executed_at', exact_time), finish),
        comparison('ordered_put_inside_grant_window', computed('integer UTC microseconds; inclusive bounds',
            lambda nb, start, finish, na: micros(nb) <= micros(start) <= micros(finish) <= micros(na),
            before, start, finish, after), literal(True))],
        'Native window checks use milliseconds. These crosswalk comparisons preserve six digits and independently include PUT start.'))
    components = []
    for record, action_pointer, id_key, omitted in [('grant', '/action', 'grant_ref', {'grant_ref', 'caller_sig', 'action_binding'}),
            ('receipt', '/executed_action', 'receipt_id', {'receipt_id', 'provider_sig', 'action_binding'})]:
        action_object = n(record, action_pointer, lambda x: x)
        outer_hash = computed('SHA-256 of NENRIN signed action object; musubi-canonical-v0 raw UTF-8',
                              lambda value: sha(canonical(value, musubi=True)), action_object)
        binding = n(record, '/action_binding', lambda x: x)
        expected = computed('optional derived NENRIN action binding; separate from args_sha256', lambda h: {
            'type': 'canonical_request_digest', 'canonicalization': NENRIN_CANON,
            'preimage_profile': 'task-execution-bind-v0/action', 'digest': {'alg': 'sha-256', 'value': h}}, outer_hash)
        # Unknown algorithms/profiles cannot be interpreted as a known mismatching digest.
        if 'value' in binding:
            try:
                b = binding['value']
                if type(b) is not dict or (b.get('type'), b.get('canonicalization'), b.get('preimage_profile')) != (
                        'canonical_request_digest', NENRIN_CANON, 'task-execution-bind-v0/action'):
                    raise Unavailable('unknown NENRIN action binding profile')
                descriptor(b.get('digest'))
            except (ValueError, TypeError) as exc:
                binding.pop('value', None)
                binding['unavailable'] = str(exc)
        components.append(comparison(record + '_outer_action_binding', binding, expected))
        content_id = computed('SHA-256 of NENRIN record preimage; signature and documented derived fields excluded',
            lambda rec, omitted=omitted: sha(canonical({k: val for k, val in rec.items() if k not in omitted}, musubi=True)),
            n(record, '', lambda x: x))
        components.append(comparison(record + '_content_id', n(record, '/' + id_key, hex_value), content_id))
    components.append(comparison('receipt_grant_reference', n('receipt', '/grant_ref', hex_value), n('grant', '/grant_ref', hex_value)))
    rows.append(row(9, 'NENRIN own content and action bindings', components,
        'Local digest recomputation adds no signature claim. Optional absent action_binding is not_assessed, not a native refusal. Complete native recompute/signature reports remain unchanged.'))
    caller = manifest.operand('/keys/caller/did', text_value)
    provider = manifest.operand('/keys/provider/did', text_value)
    components = [comparison('test_caller_manifest', n('grant', '/caller_id'), caller),
                  comparison('test_provider_manifest', n('grant', '/provider_id'), provider),
                  comparison('receipt_provider_to_grant', n('receipt', '/provider_id'), n('grant', '/provider_id'))]
    for engine, report in native.items():
        components += [comparison(engine + '_reported_caller', report.operand('/signers/caller_id', text_value), caller),
                       comparison(engine + '_reported_provider', report.operand('/signers/provider_id', text_value), provider)]
    rows.append(row(10, 'test identity context, without issuer attribution', components,
        'Public test seeds do not establish signer identity or independence. Native signatures_required is a setting, not proof that missing-pair signatures were checked. VATE actor/principal/runtime and store/receiver authority are not inferred.'))
    return rows


def json_object(document):
    require(document.error is None and type(document.value) is dict, 'required JSON object unavailable: ' + document.path)
    return document.value


def unique(items, key, label):
    require(type(items) is list and len(items) <= MAX_FILES, 'invalid bounded list: ' + label)
    result = {}
    for item in items:
        require(type(item) is dict and key in item, 'invalid entry: ' + label)
        name = item[key]
        require(type(name) is str and name not in result, 'duplicate or invalid entry: ' + label)
        result[name] = item
    return result


def verify_native_report(document, bundle, case):
    report = json_object(document)
    require(report.get('schema') == 'nenrin-provenance-verify-v0', 'unknown native report schema')
    require(report.get('verifier_version') == '0.1.6', 'unexpected native verifier version')
    require(same(report.get('task_id'), bundle.get('task_id')), 'native report task/input mismatch')
    layers, signers = report.get('layers'), report.get('signers')
    require(type(layers) is dict and type(signers) is dict, 'native report layers/signers shape differs')
    execution = layers.get('execution')
    require(type(execution) is dict, 'native report execution shape differs')
    require(execution.get('present') is True, 'native report execution layer absent')
    if case == 'missing_receipt':
        require(execution.get('complete') is False and 'receipt_id' not in execution and 'outcome' not in execution,
                'wrong-case native report assigned to missing receipt')
    else:
        receipt = bundle['receipt']
        require(execution.get('complete') is True and same(execution.get('receipt_id'), receipt['receipt_id'])
                and same(execution.get('outcome'), receipt['outcome']), 'native report receipt/input mismatch')
    require(signers.get('signatures_required') is True, 'native run did not require signatures')


def report_copy(document):
    # Keep full values AND exact UTF-8 bytes represented reversibly as a JSON string.
    return {'artifact': document.ref(), 'raw_utf8': document.raw.decode('utf-8'), 'report': json_object(document)}
