"""Bounded S3 observation example; composes with existing VATE checks."""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'reference/vate-verifier-core/vate_verifier_core.py').is_file())
CONTRACT = 'vate-local-s3-observation-v1'
ACTION = 's3.put_object'
COLLECTOR = 'urn:vate:local:s3-collector'
RUNTIME = 'urn:vate:local:s3-writer'
VERIFIER = 'urn:vate:local:s3-admission'
MAX_BODY = 4096
MAX_FILE = 256 * 1024
MAX_TOTAL = 2 * 1024 * 1024
TARGET_KEYS = ('endpoint_profile_id', 'bucket', 'key')
NAMES = {'effective-request.json', 'permit.json', 'admission-request.json', 'admission-decision.json',
         'admission.json', 'attempt.json', 'put-request.json', 'put-transport.json', 'put-headers.txt',
         'put-body.bin', 'put-response-body.bin', 'get-request.json', 'get-transport.json', 'get-headers.txt', 'get-body.bin',
         'post.json', 'sources.json'}
RECIPIENT = 'reference/receipt-linkage-example/recipient_example.py'
SOURCE_PATHS = [str((HERE / n).relative_to(ROOT)) for n in
                ('contract.py', 'capture_s3.py', 'assess_observation.py', 'native_fixture.py', 'sandbox_macos.py', 'run_trial.py', 'SEAWEEDFS-PIN.json')]
SOURCE_PATHS += [RECIPIENT, 'reference/receipt-linkage-example/SOURCE-PINS.json',
                 'reference/vate-verifier-core/vate_verifier_core.py', 'scripts/vate_conformance.py',
                 'schemas/admission-request.schema.json', 'schemas/admission-receipt.schema.json',
                 'schemas/post-execution-receipt.schema.json', 'registries/evidence-vocabulary.v0.3.json']



class Invalid(ValueError):
    pass


def need(ok, detail):
    if not ok:
        raise Invalid(detail)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def same(left, right):
    """JSON equality retaining the distinction between booleans and integers."""
    return encode(left) == encode(right)


def decode(raw):
    need(len(raw) <= MAX_FILE, 'JSON size limit')
    def pairs(items):
        out = {}
        for k, v in items:
            need(k not in out, 'duplicate JSON key')
            out[k] = v
        return out
    def no_float(text):
        raise Invalid('non-integer JSON number outside local profile')
    def integer(text):
        number = int(text)
        need(abs(number) <= 9007199254740991, 'unsafe integer')
        return number
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_float=no_float,
                          parse_constant=no_float, parse_int=integer)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Invalid(str(exc)) from exc


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(raw):
    return {'alg': 'sha-256', 'value': sha(raw)}


def object_hash(value):
    return 'sha-256:' + sha(encode(value))


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def time_value(value):
    need(isinstance(value, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z', value), 'invalid UTC time')
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00'))


def exact(obj, names, label):
    need(isinstance(obj, dict) and set(obj) == set(names), label + ': fields differ')


def write(path, value):
    raw = value if isinstance(value, bytes) else encode(value)
    with Path(path).open('xb') as f:
        f.write(raw)


def descriptor(path, raw):
    return {'path': path, 'digest': digest(raw), 'byte_length': len(raw)}


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def recipient():
    return module('s3_existing_recipient', ROOT / RECIPIENT).RecipientExample()


def sources():
    return {p: sha((ROOT / p).read_bytes()) for p in SOURCE_PATHS}


def target(value):
    return {k: value[k] for k in TARGET_KEYS}


def resource(value):
    return 'urn:vate:local:s3:' + ':'.join(value[k] for k in TARGET_KEYS)


def validate_effective(value):
    exact(value, ('contract', 'operation_id', 'action', *TARGET_KEYS, 'body_digest', 'byte_length', 'if_none_match'), 'effective request')
    need(value['contract'] == CONTRACT and value['action'] == ACTION and value['if_none_match'] == '*', 'unknown effective request contract')
    for key in ('operation_id', *TARGET_KEYS):
        need(isinstance(value[key], str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,90}', value[key]), 'unsafe target or identifier')
    need(value['key'] not in ('.', '..'), 'dot-segment key outside local profile')
    exact(value['body_digest'], ('alg', 'value'), 'body digest')
    need(value['body_digest']['alg'] == 'sha-256' and isinstance(value['body_digest']['value'], str)
         and re.fullmatch('[0-9a-f]{64}', value['body_digest']['value']), 'invalid body digest')
    need(type(value['byte_length']) is int and 0 <= value['byte_length'] <= MAX_BODY, 'invalid body length')


def action_binding(effective):
    return {'type': 'profile_defined_digest', 'preimage_profile': CONTRACT,
            'canonicalization': 'vate-v0.3-fixture-json;ascii-escaped;sorted;compact;no-floats',
            'digest': digest(encode(effective))}


def mint(effective, permit, evaluated_at, checker):
    """A controller-owned unsigned test permit, validated before core.admit."""
    validate_effective(effective)
    exact(permit, ('contract', 'operation_id', 'input_hash', 'issued_at', 'expires_at', 'status'), 'permit')
    need(permit['contract'] == CONTRACT and permit['operation_id'] == effective['operation_id']
         and permit['input_hash'] == object_hash(effective) and permit['status'] == 'active', 'permit/preimage mismatch')
    issued, expires, evaluated = (time_value(x) for x in (permit['issued_at'], permit['expires_at'], evaluated_at))
    need(issued <= evaluated <= expires and dt.timedelta(0) < expires - issued <= dt.timedelta(minutes=10), 'permit window')
    core = checker.core
    request = {'version': core.VERSION, 'profile': core.PROFILE, 'request_id': 'request-' + effective['operation_id'],
               'transaction_id': effective['operation_id'], 'issued_at': permit['issued_at'], 'expires_at': permit['expires_at'],
               'action': ACTION, 'target': {'resource': resource(effective), 'audience': RUNTIME},
               'actor': 'urn:vate:local:writer', 'principal': 'urn:vate:local:owner', 'runtime': RUNTIME, 'audience': RUNTIME,
               'input_hash': object_hash(effective), 'constraints': {'tool_allowlist': [ACTION],
               'target_resource': resource(effective), 'expected_runtime': RUNTIME, 'status': {'state': 'active'}},
               'evidence_refs': [{'type': 'mission_permit', 'uri': 'local:permit.json', 'media_type': 'application/json',
                                  'digest': digest(encode(permit))}]}
    policy = {'policy_id': CONTRACT, 'policy_version': '1', 'policy_ref': 'local:controller-policy', 'allowed_actions': [ACTION]}
    decision = core.VateVerifier(verifier_id=VERIFIER, policy=policy).admit(request, now=evaluated)
    need(decision['decision'] == 'allow', 'core did not allow this test operation')
    admission = copy.deepcopy(decision['admission_receipt'])
    admission['proof'] = {'format': 'none'}
    admission['request']['action_binding'] = action_binding(effective)
    admission['evidence'][0]['verification']['method'] = 'local-permit-binding-and-vate-core'
    checker.validators['admission'].validate(admission)
    return request, decision, admission


def result_view(effective, version, body):
    return {'contract': CONTRACT, **target(effective), 'version_id': version,
            'body_digest': digest(body), 'byte_length': len(body)}


def parse_headers(raw):
    need(len(raw) <= 32768, 'headers too large')
    if not raw:
        return {'status': None, 'version_id': None, 'content_length': None}
    lines = raw.decode('iso-8859-1').splitlines()
    statuses, fields = [], {}
    for line in lines:
        match = re.fullmatch(r'HTTP/1\.[01] (\d{3})(?: .*)?', line)
        if match:
            statuses.append(int(match.group(1)))
        elif line:
            need(':' in line and not line[0].isspace(), 'unsupported header line')
            key, value = line.split(':', 1)
            fields.setdefault(key.lower(), []).append(value.strip())
    need(len(statuses) == 1, 'not one HTTP response')
    for k in ('x-amz-version-id', 'content-length', 'content-encoding', 'transfer-encoding'):
        need(len(fields.get(k, [])) <= 1, 'duplicate critical header: ' + k)
    need(fields.get('content-encoding', ['identity']) == ['identity'], 'encoded body not supported')
    length = fields.get('content-length', [None])[0]
    need(length is None or re.fullmatch('[0-9]{1,8}', length), 'invalid Content-Length')
    return {'status': statuses[0], 'version_id': fields.get('x-amz-version-id', [None])[0],
            'content_length': int(length) if length is not None else None}


def make_post(admission, attempt, put, observation, body):
    view = result_view(attempt, observation['returned_version_id'], body)
    effect = {k: v for k, v in view.items() if k != 'contract'}
    return {'version': admission['version'], 'profile': admission['profile'], 'receipt_type': 'post_execution',
            'receipt_id': 'post-' + attempt['attempt_id'], 'issued_at': now(),
            'issuer': {'id': 'urn:vate:local:s3-observing-adapter', 'role': 'broker'},
            'admission': {'receipt_id': admission['receipt_id'], 'uri': 'local:admission.json',
                          'digest': digest(encode(admission)), 'decision': admission['decision']['outcome']},
            'execution': {'transaction_id': attempt['transaction_id'], 'runtime': attempt['runtime'],
                          'started_at': put['started_at'], 'finished_at': put['finished_at'],
                          'effective_request_hash': attempt['effective_request_hash'],
                          'action_binding': admission['request']['action_binding']},
            'result': {'outcome': 'success', 'output_hash': object_hash(view),
                       'side_effects': [{'tool': ACTION, **effect}], 'policy_violations': []}, 'proof': {'format': 'none'}}


def seal(folder):
    entries = {}
    for p in sorted(Path(folder).iterdir()):
        if p.name == 'manifest.json':
            continue
        need(p.name in NAMES and p.is_file() and not p.is_symlink(), 'unexpected artifact')
        raw = p.read_bytes()
        entries[p.name] = {'digest': digest(raw), 'byte_length': len(raw)}
    write(Path(folder) / 'manifest.json', {'contract': CONTRACT, 'artifacts': entries})


class Bundle:
    """Flat, finite, no-link receiver. All reads are from an already opened dirfd."""
    def __init__(self, path):
        self.raw = {}
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            names = os.listdir(fd)
            need(len(names) <= len(NAMES) + 1 and set(names) <= NAMES | {'manifest.json'}, 'unexpected artifact name')
            def read(name):
                f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                try:
                    info = os.fstat(f)
                    need(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE, 'not a bounded regular artifact')
                    with os.fdopen(os.dup(f), 'rb') as stream:
                        raw = stream.read(MAX_FILE + 1)
                    need(len(raw) <= MAX_FILE, 'artifact too large')
                    return raw
                finally:
                    os.close(f)
            manifest = decode(read('manifest.json'))
            exact(manifest, ('contract', 'artifacts'), 'manifest')
            need(isinstance(manifest['contract'], str) and manifest['contract'], 'invalid manifest contract')
            self.contract = manifest['contract']
            if self.contract != CONTRACT:
                return
            entries = manifest['artifacts']
            need(isinstance(entries, dict) and set(entries) <= NAMES, 'manifest entries')
            need(set(names) == set(entries) | {'manifest.json'}, 'manifest file inventory mismatch')
            for name, ref in entries.items():
                exact(ref, ('digest', 'byte_length'), 'manifest descriptor')
                raw = read(name)
                need(type(ref['byte_length']) is int and ref['byte_length'] == len(raw) and ref['digest'] == digest(raw), 'artifact digest/length mismatch: ' + name)
                self.raw[name] = raw
            need(sum(map(len, self.raw.values())) <= MAX_TOTAL, 'bundle size limit')
        finally:
            os.close(fd)

    def get(self, name):
        return decode(self.raw[name]) if name in self.raw else None

    def ref_ok(self, ref, name):
        return name in self.raw and same(ref, descriptor(name, self.raw[name]))
