"""Explicit local S3 acquisition. Never follow endpoint URLs from a bundle."""
import re
import secrets
import subprocess
from urllib.parse import urlencode

from contract import (COLLECTOR, CONTRACT, MAX_BODY, RUNTIME, Invalid, decode, descriptor, digest, encode,
                      mint, need, now, object_hash, parse_headers, same, target, time_value, write)


class DispatchAborted(Invalid):
    """The local authorization window closed before curl was invoked."""


class S3Capture:
    def __init__(self, fixture):
        self.fixture = fixture

    def put_authorized(self, folder, checker):
        """Small local test gate; no replay/distributed executor claim."""
        read = lambda name: decode((folder / name).read_bytes())
        effective, permit, admission = (read(n) for n in ('effective-request.json', 'permit.json', 'admission.json'))
        req, decision, checked = mint(effective, permit, admission['issued_at'], checker)
        need(same(admission, checked) and same(read('admission-request.json'), req)
             and same(read('admission-decision.json'), decision), 'authorization changed before dispatch')
        need(time_value(admission['issued_at']) <= time_value(now()) <= time_value(admission['expires_at']), 'authorization no longer current')
        body = (folder / 'put-body.bin').read_bytes()
        need(digest(body) == effective['body_digest'] and len(body) == effective['byte_length'], 'body changed before dispatch')
        need(effective['endpoint_profile_id'] == self.fixture.endpoint_profile_id and effective['bucket'] == self.fixture.bucket, 'target differs from trusted fixture')
        attempt = {'contract': CONTRACT, 'operation_id': effective['operation_id'],
                   'attempt_id': 'attempt-' + secrets.token_hex(12), 'transaction_id': effective['operation_id'],
                   'runtime': RUNTIME, 'collector_id': COLLECTOR, 'admission_digest': digest(encode(admission)),
                   'effective_request_hash': object_hash(effective), **target(effective),
                   'body_ref': descriptor('put-body.bin', body), 'created_at': now()}
        write(folder / 'attempt.json', attempt)  # Exclusive creation before the first request.
        result, raw = self.exchange(folder, 'put', 'PUT', 'writer', bucket=effective['bucket'], key=effective['key'],
                                    body=body, headers=('If-None-Match: *',), attempt=attempt,
                                    admission_window=(admission['issued_at'], admission['expires_at']))
        return attempt, result, raw

    def exchange(self, folder, prefix, method, role, *, bucket, key='', version=None,
                 body=b'', query=None, headers=(), attempt=None, admission_window=None):
        need(prefix in ('put', 'get'), 'unsupported record prefix')
        need(method in ('PUT', 'GET', 'DELETE'), 'unsupported method')
        need(re.fullmatch('[a-z0-9-]{1,90}', bucket), 'unsafe bucket')
        need(not key or re.fullmatch('[A-Za-z0-9_.-]{1,90}', key), 'unsafe key')
        need(key not in ('.', '..'), 'dot-segment key outside local profile')
        need(type(body) is bytes and len(body) <= MAX_BODY, 'body exceeds local bound')
        need(version is None or (isinstance(version, str) and re.fullmatch('[A-Za-z0-9_.-]{1,160}', version) and version != 'null'), 'invalid version')
        need(self.fixture.process is not None and self.fixture.process.poll() is None, 'fixture not active')
        f = self.fixture
        url = f.endpoint + '/' + bucket + ('/' + key if key else '')
        need(query is None or query == {'versioning': ''}, 'unsupported query')
        if version is not None:
            need(query is None, 'ambiguous query')
            query = {'versionId': version}
        if query is not None:
            url += '?' + urlencode(query)
        request_body = None
        if method == 'PUT':
            name = prefix + '-body.bin'
            if (folder / name).exists():
                need((folder / name).read_bytes() == body, 'precommitted body changed')
            else:
                write(folder / name, body)
            request_body = descriptor(name, body)
        attempt_ref = None
        if attempt is not None:
            need(method == 'PUT' and role == 'writer', 'attempt applies only to writer PUT')
            need(admission_window is not None, 'authorized attempt requires an admission window')
            raw = (folder / 'attempt.json').read_bytes()
            attempt_ref = descriptor('attempt.json', raw)
        q = {'contract': CONTRACT, 'collector_id': COLLECTOR,
             'exchange_id': attempt['attempt_id'] if attempt else 'read-' + secrets.token_hex(8),
             'method': method, 'endpoint': f.endpoint, 'endpoint_profile_id': f.endpoint_profile_id,
             'bucket': bucket, 'key': key, 'requested_version_id': version, 'headers': list(headers),
             'body_ref': request_body, 'attempt_ref': attempt_ref, 'requested_at': now()}
        write(folder / (prefix + '-request.json'), q)
        response_body_name = 'put-response-body.bin' if prefix == 'put' else 'get-body.bin'
        header_path = folder / (prefix + '-headers.txt')
        body_path = folder / response_body_name
        args = [*f.sandbox, '/usr/bin/curl', '-q', '--silent', '--show-error', '--http1.1',
                '--noproxy', '*', '--proto', '=http', '--max-redirs', '0', '--connect-timeout', '2',
                '--max-time', '15', '--max-filesize', str(MAX_BODY), '--request', method,
                '--output', str(body_path), '--dump-header', str(header_path), '--write-out', '%{http_code}',
                '--header', 'Expect:', '--header', 'Content-Type: application/octet-stream']
        for h in headers:
            need(h == 'If-None-Match: *', 'unsupported request header')
            args += ['--header', h]
        if method == 'PUT':
            args += ['--data-binary', '@' + str(folder / (prefix + '-body.bin'))]
        auth = b''
        if role is not None:
            access, secret = f.credentials[role]
            args += ['--aws-sigv4', 'aws:amz:us-east-1:s3', '--config', '-']
            auth = f'user = "{access}:{secret}"\n'.encode()
        args += [url]
        started = now()
        error = None
        rc, output = None, b''
        try:
            if admission_window is not None:
                first, last = (time_value(value) for value in admission_window)
                if not first <= time_value(started) <= last:
                    raise DispatchAborted('authorization outside validity window at dispatch')
            result = subprocess.run(args, input=auth, capture_output=True, cwd=f.work, env=f.env, timeout=20)
            rc, output = result.returncode, result.stdout
        except BaseException as exc:
            error = exc
            output = getattr(exc, 'stdout', None) or b''
        finished = now()
        for p in (header_path, body_path):
            if not p.exists():
                write(p, b'')
        raw_headers, raw_body = header_path.read_bytes(), body_path.read_bytes()
        issues = []
        try:
            parsed = parse_headers(raw_headers)
        except ValueError as exc:
            parsed = {'version_id': None}
            issues.append(str(exc))
        if len(raw_body) > MAX_BODY:
            issues.append('body exceeds local bound')
        t = {'contract': CONTRACT, 'collector_id': COLLECTOR,
             'request_ref': descriptor(prefix + '-request.json', (folder / (prefix + '-request.json')).read_bytes()),
             'attempt_ref': attempt_ref, 'started_at': started, 'finished_at': finished,
             'curl_exit': rc, 'http_status': int(output) if output.isdigit() and output != b'000' else None,
             'headers_ref': descriptor(header_path.name, raw_headers), 'body_ref': descriptor(body_path.name, raw_body),
             'returned_version_id': parsed['version_id'], 'invocation_error': type(error).__name__ if error else None,
             'validation_errors': issues}
        write(folder / (prefix + '-transport.json'), t)
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise error
        return t, raw_body


class S3Observer:
    """Only GET with the fixture's separately scoped Read credential."""
    def __init__(self, capture):
        self.capture = capture

    def observe(self, folder, *, key, version=None):
        f = self.capture.fixture
        return self.capture.exchange(folder, 'get', 'GET', 'observer', bucket=f.bucket, key=key, version=version)
