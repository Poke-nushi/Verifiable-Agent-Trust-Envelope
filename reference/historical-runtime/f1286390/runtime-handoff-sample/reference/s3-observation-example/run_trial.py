#!/usr/bin/env python3
"""Create a fresh admission, perform one PUT, then observe and assess locally."""
import argparse
import datetime as dt
import json
import secrets
import shutil
import signal
from pathlib import Path

from assess_observation import assess
from capture_s3 import S3Capture, S3Observer
from contract import (ACTION, COLLECTOR, CONTRACT, HERE, ROOT, decode, digest, encode, make_post, mint,
                      need, now, object_hash, recipient, seal, sources, time_value, write)
from native_fixture import LocalSeaweed


def clone_without_observation(source, destination):
    destination.mkdir()
    for p in source.iterdir():
        if p.name not in ('manifest.json', 'post.json') and not p.name.startswith('get-'):
            shutil.copyfile(p, destination / p.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--weed', type=Path, required=True, help='Existing macOS arm64 SeaweedFS binary matching SEAWEEDFS-PIN.json')
    parser.add_argument('--output', type=Path, required=True, help='New directory; never overwrites an existing run')
    args = parser.parse_args()
    need(not args.output.exists(), 'output already exists')
    run_id = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + secrets.token_hex(3)
    destination = args.output.resolve()
    checker = recipient()
    expected_sources = sources()
    findings, assessments = [], {}
    error = None
    try:
        with LocalSeaweed(destination, args.weed) as fixture:
            capture = S3Capture(fixture)
            observer = S3Observer(capture)
            def native(label, role, method, *, key='', bucket=None, body=b'', query=None, version=None, headers=(), status=200):
                folder = fixture.work / 'native-controls' / label
                folder.mkdir()
                record, raw = capture.exchange(folder, 'put' if method == 'PUT' else 'get', method, role,
                    bucket=bucket or fixture.bucket, key=key, body=body, query=query, version=version, headers=headers)
                ok = record['curl_exit'] == 0 and record['http_status'] == status and not record['validation_errors']
                findings.append({'label': label, 'passed': ok, 'http_status': record['http_status']})
                need(ok, label + ' native control failed')
                return folder, record, raw
            native('create-bucket', 'setup', 'PUT')
            native('enable-versioning', 'setup', 'PUT', query={'versioning': ''},
                   body=b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>')
            _, _, versioning = native('read-versioning', 'setup', 'GET', query={'versioning': ''})
            need(b'<Status>Enabled</Status>' in versioning, 'versioning not enabled')
            policy = {'contract': CONTRACT, 'collector_id': COLLECTOR, 'store_id': 'seaweedfs-4.48-530be3e',
                      'endpoint_profile_id': fixture.endpoint_profile_id, 'endpoint': fixture.endpoint,
                      'bucket': fixture.bucket, 'source_hashes': expected_sources, 'accept_local_unsigned': True}
            write(fixture.work / 'receiver-policy.json', policy)  # Receiver input is outside every bundle.
            original = fixture.work / 'bundles' / 'supported'
            original.mkdir()
            body = b'VATE S3 local authorization-bound observation.\n'
            effective = {'contract': CONTRACT, 'operation_id': 'operation-' + secrets.token_hex(10),
                         'action': ACTION, 'endpoint_profile_id': fixture.endpoint_profile_id,
                         'bucket': fixture.bucket, 'key': 'result.txt', 'body_digest': digest(body),
                         'byte_length': len(body), 'if_none_match': '*'}
            issued = now()
            permit = {'contract': CONTRACT, 'operation_id': effective['operation_id'], 'input_hash': object_hash(effective),
                      'issued_at': issued, 'expires_at': (time_value(issued) + dt.timedelta(minutes=5)).isoformat().replace('+00:00', 'Z'),
                      'status': 'active'}
            request, decision, admission = mint(effective, permit, now(), checker)
            for name, value in {'effective-request.json': effective, 'permit.json': permit,
                                'admission-request.json': request, 'admission-decision.json': decision,
                                'admission.json': admission, 'sources.json': expected_sources, 'put-body.bin': body}.items():
                write(original / name, value)
            attempt, put, _ = capture.put_authorized(original, checker)
            need(put['curl_exit'] == 0 and put['http_status'] == 200 and put['returned_version_id'] not in (None, '', 'null'), 'PUT not confirmed; no retry')
            get, returned = observer.observe(original, key=effective['key'], version=put['returned_version_id'])
            need(get['curl_exit'] == 0 and get['http_status'] == 200, 'GET failed; no success post generated')
            post = make_post(admission, attempt, put, get, returned)
            checker.validators['post'].validate(post)
            write(original / 'post.json', post)
            seal(original)
            assessments['supported'] = assess(original, policy)
            need(assessments['supported']['assessment'] == 'supported_under_local_assumptions', 'baseline assessment did not support')

            # Actual status/credential checks. They are setup probes, not VATE-authorized effects.
            native('conditional-duplicate', 'writer', 'PUT', key=effective['key'], body=b'duplicate\n', headers=('If-None-Match: *',), status=412)
            native('observer-put-denied', 'observer', 'PUT', key=effective['key'], body=b'forbidden\n', status=403)
            native('observer-delete-denied', 'observer', 'DELETE', key=effective['key'], version=put['returned_version_id'], status=403)
            native('create-other-bucket', 'setup', 'PUT', bucket=fixture.other_bucket)
            native('other-bucket-write', 'setup', 'PUT', bucket=fixture.other_bucket, key='result.txt', body=b'other namespace\n')
            native('observer-other-denied', 'observer', 'GET', bucket=fixture.other_bucket, key='result.txt', status=403)

            for label, role, version, status in [('actual-403', None, put['returned_version_id'], 403),
                                                  ('actual-404', 'observer', 'version-that-does-not-exist', 404)]:
                destination_bundle = fixture.work / 'bundles' / label
                clone_without_observation(original, destination_bundle)
                observed, _ = capture.exchange(destination_bundle, 'get', 'GET', role, bucket=fixture.bucket,
                                                key=effective['key'], version=version)
                need(observed['http_status'] == status, 'native negative status differed')
                # Retain the original successful post; failed later observation does not erase it.
                shutil.copyfile(original / 'post.json', destination_bundle / 'post.json')
                seal(destination_bundle)
                assessments[label] = assess(destination_bundle, policy)
                need(assessments[label]['target_observation'] == 'not_observed'
                     and assessments[label]['assessment'] == 'insufficient', 'native negative observation classification')

            _, newer, _ = native('setup-overwrite-v2', 'setup', 'PUT', key=effective['key'], body=b'Newer setup version, separate from authorized attempt.\n')
            need(newer['returned_version_id'] not in (None, '', 'null', put['returned_version_id']), 'new native version missing')
            historical = fixture.work / 'bundles' / 'historical-v1'
            clone_without_observation(original, historical)
            old, old_body = observer.observe(historical, key=effective['key'], version=put['returned_version_id'])
            new_post = make_post(admission, attempt, put, old, old_body)
            new_post['receipt_id'] += '-later-observation'
            write(historical / 'post.json', new_post)
            seal(historical)
            assessments['historical-v1'] = assess(historical, policy)
            need(assessments['historical-v1']['assessment'] == 'supported_under_local_assumptions', 'historical readback failed')
            _, latest, latest_body = native('latest-v2', 'observer', 'GET', key=effective['key'])
            need(latest['returned_version_id'] == newer['returned_version_id'] and latest_body != body, 'latest version observation differed')
            write(fixture.work / 'native-observations.json', {'version_1': put['returned_version_id'], 'version_2': newer['returned_version_id'],
                                                           'latest_scope': 'latest_at_observed_time', 'body_1_digest': digest(body),
                                                           'body_2_digest': digest(latest_body)})
            write(fixture.work / 'native-checks.json', findings)
            write(fixture.work / 'ASSESSMENTS.json', assessments)
            need(sources() == expected_sources, 'source changed during trial')
    except BaseException as exc:
        error = type(exc).__name__ + ': ' + str(exc)
    summary = {'run_id': run_id, 'error': error, 'assessments': {k: v['assessment'] for k, v in assessments.items()},
               'native_controls': findings}
    if destination.exists():
        write(destination / 'SUMMARY.json', summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if error is None else 1


if __name__ == '__main__':
    def terminate(signum, frame):
        raise KeyboardInterrupt('task termination')
    signal.signal(signal.SIGTERM, terminate)
    raise SystemExit(main())
