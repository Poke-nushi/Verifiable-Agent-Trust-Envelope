#!/usr/bin/env python3
"""Offline acceptance cases. Mutations are synthetic copies, never native runs."""
import argparse
import datetime as dt
import re
import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import contract as c
from assess_observation import assess
from capture_s3 import S3Capture


def read(p, n):
    return c.decode((p / n).read_bytes())


def save(p, n, value):
    (p / n).write_bytes(value if isinstance(value, bytes) else c.encode(value))


def edit(p, n, fn):
    value = read(p, n)
    fn(value)
    save(p, n, value)


def ref(p, n):
    return c.descriptor(n, (p / n).read_bytes())


def rebind(p, prefix):
    edit(p, prefix + '-transport.json', lambda t: t.update(
        request_ref=ref(p, prefix + '-request.json'), headers_ref=ref(p, prefix + '-headers.txt'),
        body_ref=ref(p, 'put-response-body.bin' if prefix == 'put' else 'get-body.bin')))


def short_body(p, size):
    """Synthetic internally consistent controls for bool-vs-integer regression."""
    body = b'x' * size
    effective = read(p, 'effective-request.json')
    effective.update(body_digest=c.digest(body), byte_length=size)
    permit = read(p, 'permit.json')
    permit['input_hash'] = c.object_hash(effective)
    req, decision, admission = c.mint(effective, permit, read(p, 'admission.json')['issued_at'], c.recipient())
    for n, v in {'effective-request.json': effective, 'permit.json': permit, 'admission-request.json': req,
                 'admission-decision.json': decision, 'admission.json': admission,
                 'put-body.bin': body, 'get-body.bin': body}.items():
        save(p, n, v)
    edit(p, 'attempt.json', lambda d: d.update(admission_digest=c.digest(c.encode(admission)),
         effective_request_hash=c.object_hash(effective), body_ref=ref(p, 'put-body.bin')))
    edit(p, 'put-request.json', lambda d: d.update(attempt_ref=ref(p, 'attempt.json'), body_ref=ref(p, 'put-body.bin')))
    edit(p, 'put-transport.json', lambda d: d.update(attempt_ref=ref(p, 'attempt.json')))
    save(p, 'get-headers.txt', re.sub(rb'(?im)^Content-Length: \d+', b'Content-Length: ' + str(size).encode(),
                                   (p / 'get-headers.txt').read_bytes()))
    rebind(p, 'put')
    rebind(p, 'get')
    save(p, 'post.json', c.make_post(admission, read(p, 'attempt.json'), read(p, 'put-transport.json'), read(p, 'get-transport.json'), body))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, default=c.HERE / 'inputs/seaweedfs-4.48', help='Capture root containing instance/; defaults to included native inputs')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    instance = args.run / 'instance'
    policy = read(instance, 'receiver-policy.json')
    output = args.output or Path(tempfile.mkdtemp(prefix='vate-s3-offline-'))
    output.mkdir(parents=True, exist_ok=True)
    records = []
    def case(name, change=None, expected=None, *, base='supported', trust=None, after_seal=None, required_codes=()):
        folder = output / name
        shutil.copytree(instance / 'bundles' / base, folder)
        (folder / 'manifest.json').unlink()
        if change:
            change(folder)
        c.seal(folder)
        if after_seal:
            after_seal(folder)
        result = assess(folder, policy if trust is None else trust)
        expected = expected or {'assessment': 'contradictory'}
        passed = all(result.get(k) == v for k, v in expected.items()) and result['retry_authorized'] is False
        passed = passed and set(required_codes) <= {d['code'] for d in result['diagnostics']}
        records.append({'case': name, 'basis': 'native-replay' if change is None and after_seal is None else 'synthetic-copy',
                        'expected': expected, 'required_codes': list(required_codes), 'passed': passed, 'result': result})
        return folder
    supported = {'assessment': 'supported_under_local_assumptions', 'record_linkage': 'matched'}
    insufficient = {'assessment': 'insufficient'}
    case('T01-native', expected=supported)
    def remove_get(p):
        for n in ('get-request.json', 'get-transport.json', 'get-headers.txt', 'get-body.bin'):
            (p / n).unlink()
    case('T02-no-observation', remove_get, {**insufficient, 'record_linkage': 'matched', 'target_observation': 'not_observed'})
    def wrong_body(p):
        body = (p / 'get-body.bin').read_bytes()
        save(p, 'get-body.bin', b'X' + body[1:])
        rebind(p, 'get')
    case('T03-other-body', wrong_body, {'assessment': 'contradictory', 'target_observation': 'mismatch'})
    for field, value in [('bucket', 'other-bucket'), ('key', 'other.txt'), ('endpoint_profile_id', 'other-endpoint'),
                         ('endpoint', 'http://127.0.0.1:1'), ('requested_version_id', 'other-version')]:
        def wrong_target(p, field=field, value=value):
            edit(p, 'get-request.json', lambda d: d.update({field: value}))
            rebind(p, 'get')
        case('T04-' + field, wrong_target)
    def missing_put_latest(p):
        for n in ('put-transport.json', 'put-headers.txt', 'put-response-body.bin', 'post.json'):
            (p / n).unlink()
        edit(p, 'get-request.json', lambda d: d.update(requested_version_id=None))
        rebind(p, 'get')
    case('T05-disclosure-loss-latest', missing_put_latest,
         {**insufficient, 'target_observation': 'matched', 'attempt_binding': 'unknown', 'version_scope': 'latest_at_observed_time'})
    for prefix in ('put', 'get'):
        def null_version(p, prefix=prefix):
            save(p, prefix + '-headers.txt', re.sub(rb'(?im)^X-Amz-Version-Id: [^\r\n]*', b'X-Amz-Version-Id: null',
                                                   (p / (prefix + '-headers.txt')).read_bytes()))
            edit(p, prefix + '-transport.json', lambda d: d.update(returned_version_id='null'))
            rebind(p, prefix)
        case('T06-null-' + prefix + '-version', null_version, insufficient)
        def missing_version(p, prefix=prefix):
            save(p, prefix + '-headers.txt', re.sub(rb'(?im)^X-Amz-Version-Id: [^\r\n]*\r?\n', b'',
                                                   (p / (prefix + '-headers.txt')).read_bytes()))
            edit(p, prefix + '-transport.json', lambda d: d.update(returned_version_id=None))
            rebind(p, prefix)
        case('T06-missing-' + prefix + '-version', missing_version, insufficient)
    for name in ('effective-request.json', 'permit.json', 'attempt.json', 'put-request.json', 'put-transport.json', 'get-request.json', 'get-transport.json'):
        def unknown(p, name=name):
            edit(p, name, lambda d: d.update(contract='future-contract'))
            if name in ('put-request.json', 'get-request.json'):
                rebind(p, name.split('-')[0])
            if name == 'attempt.json':
                edit(p, 'put-request.json', lambda d: d.update(attempt_ref=ref(p, name)))
                edit(p, 'put-transport.json', lambda d: d.update(attempt_ref=ref(p, name)))
                rebind(p, 'put')
        case('T06-unknown-' + name, unknown, {'assessment': 'unsupported'})
    case('T06-unknown-bundle', expected={'assessment': 'unsupported'},
         after_seal=lambda p: edit(p, 'manifest.json', lambda d: d.update(contract='future-contract')))
    for name in ('admission.json', 'post.json'):
        for field in ('version', 'profile'):
            case('R06-unknown-' + name + '-' + field,
                 lambda p, name=name, field=field: edit(p, name, lambda d: d.update({field: 'future-value'})),
                 {'assessment': 'unsupported', 'record_linkage': 'not_assessed'})
    def unknown_post_hash(p):
        edit(p, 'post.json', lambda d: d.update(profile='future-profile'))
        edit(p, 'post.json', lambda d: d['result'].update(output_hash='sha-256:' + '0' * 64))
    case('R06-unknown-post-hash', unknown_post_hash, {'assessment': 'unsupported'})
    def unknown_post_known_wrong_body(p):
        unknown_post_hash(p)
        wrong_body(p)
    case('R06-unknown-post-known-wrong-body', unknown_post_known_wrong_body)
    for label, trust in [('unknown', {**policy, 'contract': 'future-contract'}),
                         ('unknown-target', {**policy, 'contract': 'future-contract', 'endpoint': 'http://127.0.0.1:1'})]:
        case('R06-policy-' + label, trust=trust, expected={'assessment': 'unsupported'})
    case('R06-unknown-policy-known-wrong-body', wrong_body, trust={**policy, 'contract': 'future-contract'})
    for label in ('actual-403', 'actual-404'):
        case('T07-' + label, expected={**insufficient, 'target_observation': 'not_observed'}, base=label)
    for status in (None, 503):
        def unavailable(p, status=status):
            save(p, 'get-headers.txt', b'' if status is None else b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n')
            save(p, 'get-body.bin', b'')
            edit(p, 'get-transport.json', lambda d: d.update(curl_exit=28 if status is None else 0, http_status=status,
                 returned_version_id=None, invocation_error='TimeoutExpired' if status is None else None))
            rebind(p, 'get')
        case('T07-synthetic-' + str(status), unavailable, {**insufficient, 'target_observation': 'not_observed'})
    for label, rc, status, error in [('timeout-partial', 28, 200, None),
                                    ('capture-timeout-partial', None, None, 'TimeoutExpired'),
                                    ('claimed-complete-short', 0, 200, None)]:
        def partial(p, rc=rc, status=status, error=error):
            save(p, 'get-body.bin', (p / 'get-body.bin').read_bytes()[:4])
            edit(p, 'get-transport.json', lambda d: d.update(curl_exit=rc, http_status=status, invocation_error=error))
            rebind(p, 'get')
        expected = {'assessment': 'contradictory'} if rc == 0 else {**insufficient, 'target_observation': 'not_observed'}
        case('T07-' + label, partial, expected)
    for field, value in [('key', 'other.txt'), ('bucket', 'other-bucket')]:
        def partial_wrong_target(p, field=field, value=value):
            save(p, 'get-body.bin', (p / 'get-body.bin').read_bytes()[:4])
            edit(p, 'get-transport.json', lambda d: d.update(curl_exit=28))
            edit(p, 'get-request.json', lambda d: d.update({field: value}))
            rebind(p, 'get')
        case('T07-partial-wrong-' + field, partial_wrong_target, {'assessment': 'contradictory'})
    case('T08-historical-version', expected=supported, base='historical-v1')
    case('T09-raw-tamper', expected=insufficient, after_seal=lambda p: save(p, 'get-body.bin', b'changed without resealing'))
    case('T09-missing-get-original', lambda p: (p / 'get-body.bin').unlink(), insufficient)
    case('T09-missing-put-original', lambda p: (p / 'put-body.bin').unlink(), insufficient)
    for field, value in [('operation_id', 'other-operation'), ('runtime', 'urn:other:runtime'),
                         ('key', 'other.txt'), ('effective_request_hash', 'sha-256:' + '0' * 64)]:
        def missing_put_wrong_attempt(p, field=field, value=value):
            (p / 'put-body.bin').unlink()
            edit(p, 'attempt.json', lambda d: d.update({field: value}))
            edit(p, 'put-request.json', lambda d: d.update(attempt_ref=ref(p, 'attempt.json')))
            edit(p, 'put-transport.json', lambda d: d.update(attempt_ref=ref(p, 'attempt.json')))
            rebind(p, 'put')
        case('R07-missing-put-wrong-attempt-' + field, missing_put_wrong_attempt)
    def missing_put_wrong_request(p):
        (p / 'put-body.bin').unlink()
        edit(p, 'put-request.json', lambda d: d.update(key='other.txt'))
        rebind(p, 'put')
    case('R07-missing-put-wrong-request', missing_put_wrong_request)
    def missing_put_wrong_response_version(p):
        (p / 'put-body.bin').unlink()
        save(p, 'put-headers.txt', re.sub(rb'(?im)^X-Amz-Version-Id: [^\r\n]*', b'X-Amz-Version-Id: other-version',
                                       (p / 'put-headers.txt').read_bytes()))
        edit(p, 'put-transport.json', lambda d: d.update(returned_version_id='other-version'))
        rebind(p, 'put')
    case('R07-missing-put-wrong-response-version', missing_put_wrong_response_version,
         {'assessment': 'contradictory', 'attempt_binding': 'mismatch'}, required_codes=('PUT_GET_VERSION_TARGET_MISMATCH',))
    # Each comparison uses its own originals; unrelated disclosure loss must not hide it.
    for missing in ('put-request.json', 'put-headers.txt', 'put-response-body.bin',
                    'get-request.json', 'get-headers.txt', 'get-body.bin', 'get-transport.json'):
        case('R09-only-missing-' + missing, lambda p, missing=missing: (p / missing).unlink(), insufficient)
    for missing in ('get-body.bin', 'get-headers.txt', 'get-transport.json'):
        def incomplete_wrong_get_target(p, missing=missing):
            (p / missing).unlink()
            edit(p, 'get-request.json', lambda d: d.update(key='other.txt'))
            if (p / 'get-transport.json').exists():
                edit(p, 'get-transport.json', lambda d: d.update(request_ref=ref(p, 'get-request.json')))
        case('R09-wrong-target-without-' + missing, incomplete_wrong_get_target, required_codes=('GET_TARGET_MISMATCH',))
    for prefix in ('put', 'get'):
        body_name = 'put-response-body.bin' if prefix == 'put' else 'get-body.bin'
        for missing, wrong_ref in [(prefix + '-request.json', 'headers_ref'),
                                   (prefix + '-headers.txt', 'body_ref'), (body_name, 'headers_ref')]:
            def incomplete_wrong_ref(p, prefix=prefix, missing=missing, wrong_ref=wrong_ref):
                (p / missing).unlink()
                edit(p, prefix + '-transport.json', lambda d: d[wrong_ref]['digest'].update(value='0' * 64))
            case('R09-wrong-reference-without-' + missing, incomplete_wrong_ref, required_codes=(prefix.upper() + '_RAW_REFERENCE_MISMATCH',))
    for missing, changed in [('admission-request.json', 'admission-decision.json'),
                             ('admission-decision.json', 'admission-request.json')]:
        def missing_core_original(p, missing=missing, changed=changed):
            (p / missing).unlink()
            def change_runtime(d):
                if changed == 'admission-decision.json':
                    d['admission_receipt']['subject']['runtime'] = 'urn:other:runtime'
                else:
                    d['runtime'] = 'urn:other:runtime'
            edit(p, changed, change_runtime)
        case('R09-wrong-core-original-without-' + missing, missing_core_original, required_codes=(changed + '_MISMATCH',))
    def missing_get_wrong_response_version(p):
        (p / 'get-body.bin').unlink()
        save(p, 'put-headers.txt', re.sub(rb'(?im)^X-Amz-Version-Id: [^\r\n]*', b'X-Amz-Version-Id: other-version',
                                       (p / 'put-headers.txt').read_bytes()))
        edit(p, 'put-transport.json', lambda d: d.update(returned_version_id='other-version'))
        rebind(p, 'put')
    case('R09-missing-get-wrong-response-version', missing_get_wrong_response_version,
         required_codes=('PUT_GET_VERSION_TARGET_MISMATCH',))
    def missing_put_unknown_get(p):
        (p / 'put-body.bin').unlink()
        edit(p, 'get-request.json', lambda d: d.update(contract='future-contract'))
        rebind(p, 'get')
    case('T09-missing-put-unknown-get', missing_put_unknown_get, {'assessment': 'unsupported'})
    for missing in ('permit.json', 'admission-request.json', 'admission-decision.json'):
        case('R05-missing-' + missing, lambda p, missing=missing: (p / missing).unlink(), insufficient)
        def missing_with_wrong_body(p, missing=missing):
            (p / missing).unlink()
            save(p, 'put-body.bin', b'X' + (p / 'put-body.bin').read_bytes()[1:])
            edit(p, 'attempt.json', lambda d: d.update(body_ref=ref(p, 'put-body.bin')))
            edit(p, 'put-request.json', lambda d: d.update(body_ref=ref(p, 'put-body.bin'), attempt_ref=ref(p, 'attempt.json')))
            edit(p, 'put-transport.json', lambda d: d.update(attempt_ref=ref(p, 'attempt.json')))
            rebind(p, 'put')
        case('R05-missing-plus-wrong-body-' + missing, missing_with_wrong_body)
    case('T09-wrong-raw-reference', lambda p: edit(p, 'get-transport.json', lambda d: d['headers_ref']['digest'].update(value='0' * 64)))
    case('T09-other-attempt', lambda p: edit(p, 'put-transport.json', lambda d: d['attempt_ref']['digest'].update(value='0' * 64)))
    def other_transport(p):
        other = read(p, 'attempt.json')
        other['attempt_id'] += '-other'
        other_ref = c.descriptor('attempt.json', c.encode(other))
        edit(p, 'put-request.json', lambda d: d.update(exchange_id=other['attempt_id'], attempt_ref=other_ref))
        edit(p, 'put-transport.json', lambda d: d.update(attempt_ref=other_ref, returned_version_id='other-version'))
        save(p, 'put-headers.txt', re.sub(rb'(?im)^X-Amz-Version-Id: [^\r\n]*', b'X-Amz-Version-Id: other-version', (p / 'put-headers.txt').read_bytes()))
        rebind(p, 'put')
    case('T09-other-transport-set', other_transport)
    def header_only(p):
        save(p, 'get-headers.txt', re.sub(rb'(?im)^X-Amz-Version-Id: [^\r\n]*', b'X-Amz-Version-Id: swapped', (p / 'get-headers.txt').read_bytes()))
        rebind(p, 'get')
    case('T09-header-only-swap', header_only)
    case('T09-no-source', lambda p: (p / 'sources.json').unlink(), insufficient)
    for label, trust in [('no-policy', {}), ('not-accepted', {**policy, 'accept_local_unsigned': False}),
                         ('invalid-policy', {k: v for k, v in policy.items() if k != 'endpoint'})]:
        case('T10-' + label, trust=trust, expected={**insufficient, 'source_trust': 'unverified'})
    for field, value in [('runtime', 'urn:other:runtime'), ('effective_request_hash', 'sha-256:' + '0' * 64),
                         ('started_at', '2000-01-01T00:00:00Z'), ('finished_at', '2099-01-01T00:00:00Z')]:
        case('T11-execution-' + field, lambda p, field=field, value=value: edit(p, 'post.json', lambda d: d['execution'].update({field: value})))
    case('T11-output-hash', lambda p: edit(p, 'post.json', lambda d: d['result'].update(output_hash='sha-256:' + '0' * 64)))
    for field, value in [('bucket', 'other-bucket'), ('version_id', 'other-version'), ('byte_length', 0), ('key', 'other.txt')]:
        case('T11-effect-' + field, lambda p, field=field, value=value: edit(p, 'post.json', lambda d: d['result']['side_effects'][0].update({field: value})))
    for outcome in ('failed', 'partial_success', 'cancelled'):
        case('T11-result-' + outcome, lambda p, outcome=outcome: edit(p, 'post.json', lambda d: d['result'].update(outcome=outcome)), {'assessment': 'unsupported'})
    for size in (0, 1):
        case('R01-integer-' + str(size), lambda p, size=size: short_body(p, size), supported)
        def boolean_effect(p, size=size):
            short_body(p, size)
            edit(p, 'post.json', lambda d: d['result']['side_effects'][0].update(byte_length=bool(size)))
        case('R01-boolean-' + str(size), boolean_effect)
    case('R01-boolean-reference', lambda p: edit(p, 'put-transport.json', lambda d: d['body_ref'].update(byte_length=False)))
    case('R02-missing-manifest-contract', expected=insufficient,
         after_seal=lambda p: edit(p, 'manifest.json', lambda d: d.pop('contract')))
    def duplicate_json(p):
        save(p, 'get-request.json', b'{"contract":"a","contract":"b"}')
        rebind(p, 'get')
    case('R02-duplicate-json-key', duplicate_json, insufficient)
    case('R02-extra-artifact', expected=insufficient, after_seal=lambda p: save(p, 'extra.txt', b'extra'))
    def symlink(p):
        (p / 'get-body.bin').unlink()
        (p / 'get-body.bin').symlink_to(instance / 'bundles/supported/get-body.bin')
    case('R02-symlink', expected=insufficient, after_seal=symlink)
    case('R02-path-reference', lambda p: edit(p, 'get-transport.json', lambda d: d['body_ref'].update(path='../outside.bin')))
    # Dispatch gate: no socket, using a spy. Even with an original admission, a changed body cannot reach exchange.
    gate = output / 'R03-pre-dispatch-gate'
    gate.mkdir()
    for n in ('effective-request.json', 'permit.json', 'admission-request.json', 'admission-decision.json', 'admission.json', 'put-body.bin'):
        shutil.copyfile(instance / 'bundles/supported' / n, gate / n)
    save(gate, 'put-body.bin', b'changed before dispatch')
    cap = S3Capture(None)
    failure = None
    with patch('capture_s3.now', return_value=read(gate, 'admission.json')['issued_at']), patch.object(cap, 'exchange') as spy:
        try:
            cap.put_authorized(gate, c.recipient())
        except c.Invalid as exc:
            failure = str(exc)
        passed = failure == 'body changed before dispatch' and not spy.called and not (gate / 'attempt.json').exists()
    records.append({'case': 'R03-pre-dispatch-gate', 'basis': 'offline-spy', 'passed': passed, 'failure': failure})
    # The clock crosses expiry only at actual dispatch, after the first authorization check.
    for label, delta, should_call in [('expired', 1, False), ('valid', -1, True)]:
        gate = output / ('R08-dispatch-' + label)
        gate.mkdir()
        for n in ('effective-request.json', 'permit.json', 'admission-request.json', 'admission-decision.json', 'admission.json', 'put-body.bin'):
            shutil.copyfile(instance / 'bundles/supported' / n, gate / n)
        admission = read(gate, 'admission.json')
        at_dispatch = (c.time_value(admission['expires_at']) + dt.timedelta(seconds=delta)).isoformat().replace('+00:00', 'Z')
        fixture = SimpleNamespace(endpoint_profile_id=policy['endpoint_profile_id'], bucket=policy['bucket'], endpoint=policy['endpoint'],
                                  process=Mock(), sandbox=[], credentials={'writer': ('synthetic-access', 'synthetic-secret')}, work=gate, env={})
        fixture.process.poll.return_value = None
        with patch('capture_s3.now', side_effect=[admission['issued_at']] * 3 + [at_dispatch] * 2), \
                patch('capture_s3.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=b'200')) as spy:
            _, transport, _ = S3Capture(fixture).put_authorized(gate, c.recipient())
        passed = spy.call_count == int(should_call) and (gate / 'put-transport.json').exists()
        if not should_call:
            passed = passed and transport['invocation_error'] == 'DispatchAborted' and transport['curl_exit'] is None and transport['http_status'] is None
        records.append({'case': 'R08-dispatch-' + label, 'basis': 'offline-clock-and-curl-mock', 'passed': passed,
                        'curl_calls': spy.call_count, 'expires_at': admission['expires_at'], 'transport': transport})
    for key in ('.', '..'):
        effective = read(instance / 'bundles/supported', 'effective-request.json')
        effective['key'] = key
        errors = []
        for check in (lambda: c.validate_effective(effective),
                      lambda: S3Capture(None).exchange(output, 'put', 'PUT', 'writer', bucket='test-bucket', key=key)):
            try:
                check()
            except c.Invalid as exc:
                errors.append(str(exc))
        records.append({'case': 'R04-dot-key-' + str(len(key)), 'basis': 'offline-validation',
                        'passed': errors == ['dot-segment key outside local profile'] * 2})
    # Actual credential controls and cleanup are evaluated independently of the synthesized copies.
    controls = read(instance, 'native-checks.json')
    lifecycle = read(instance, 'LIFECYCLE.json')
    expected_denials = {'observer-put-denied': 403, 'observer-delete-denied': 403, 'observer-other-denied': 403, 'conditional-duplicate': 412}
    passed = all(any(c['label'] == k and c['passed'] and c['http_status'] == v for c in controls) for k, v in expected_denials.items())
    passed = passed and lifecycle['cleanup_ok'] and lifecycle['process_stopped'] and lifecycle['credentials_file_removed'] and not lifecycle['credential_marker_residual_paths'] and not any(lifecycle['grpc_sockets'].values())
    records.append({'case': 'T10-native-denials-and-cleanup', 'basis': 'native-records', 'passed': bool(passed)})
    result = {'source_run': str(args.run.resolve()), 'all_passed': all(r['passed'] for r in records), 'count': len(records), 'cases': records}
    c.write(output / 'RESULTS.json', result)
    print(c.encode({'all_passed': result['all_passed'], 'count': len(records), 'failed': [r['case'] for r in records if not r['passed']], 'output': str(output)}).decode())
    return 0 if result['all_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
