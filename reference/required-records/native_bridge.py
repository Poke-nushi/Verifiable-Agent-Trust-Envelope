"""Pinned, bounded native calls; no evaluator result accepted from input JSON."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import types

sys.path.insert(0, str(Path(__file__).resolve().parent))

from required_records import (Problem, encode, sha, native_error, MIB,
    LOADED_SOURCE_SHA256, LOADED_SOURCE_ERROR, capture_loaded_source)

HERE = Path(__file__).resolve().parent
LOADED_BRIDGE_SHA256, LOADED_BRIDGE_ERROR = capture_loaded_source(Path(__file__), sys._getframe().f_code)
PIN_SHA = '5558d6703b80cf014a4a11401aab7a2990b104804524aea476b83be414f27f4c'
OUTPUT_CAP = 2*MIB


def verify_composer(expected):
    if LOADED_SOURCE_ERROR or LOADED_BRIDGE_ERROR:
        raise Problem('COMPOSER_CODE_MISMATCH', LOADED_SOURCE_ERROR or LOADED_BRIDGE_ERROR)
    names = ('required_records.py', 'native_bridge.py', 'NATIVE-SOURCES.json')
    if type(expected) is not dict or set(expected) != set(names):
        raise Problem('COMPOSER_SOURCE_MISMATCH', 'composer source identity differs')
    for name in names:
        if sha((HERE/name).read_bytes()) != expected[name]:
            raise Problem('COMPOSER_SOURCE_MISMATCH', 'composer source changed: '+name)


def source_identity(root):
    raw = (HERE/'NATIVE-SOURCES.json').read_bytes()
    if sha(raw) != PIN_SHA:
        raise Problem('SOURCE_MANIFEST_MISMATCH', 'native source manifest changed')
    pins = json.loads(raw)
    for name, expected in pins.items():
        path = Path(root)
        for part in Path(name).parts:
            path /= part
            if path.is_symlink():
                raise Problem('SOURCE_MISMATCH', 'native source symlink: '+name)
        if sha(path.read_bytes()) != expected:
            raise Problem('SOURCE_MISMATCH', 'native source changed: '+name)
    return pins


def module(name, path):
    # Execute the source bytes just read, never a timestamp-selected .pyc.
    mod = types.ModuleType(name); mod.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec', dont_inherit=True), mod.__dict__)
    return mod


def wire(value):
    if isinstance(value, bytes):
        return {'bytes_base64': base64.b64encode(value).decode('ascii')}
    if type(value) is dict:
        return {k: wire(v) for k,v in value.items()}
    return value


def unwire(value):
    if type(value) is dict and set(value) == {'bytes_base64'}:
        return base64.b64decode(value['bytes_base64'], validate=True)
    if type(value) is dict:
        return {k: unwire(v) for k,v in value.items()}
    return value


class Bridge:
    def __init__(self, *, source_root, openssl, openssl_sha256, limits, started, calls,
                 composer_sha256=LOADED_SOURCE_SHA256, composer_error=LOADED_SOURCE_ERROR):
        self.root, self.openssl, self.openssl_sha256 = source_root, openssl, openssl_sha256
        self.limits, self.started, self.calls = limits, started, calls
        self.cache = {}; self.used = 0; self.executed = 0
        self.identity = {'composer_sources': {'required_records.py':composer_sha256,
            'native_bridge.py':LOADED_BRIDGE_SHA256, 'NATIVE-SOURCES.json':PIN_SHA},
            'python': sys.version, 'native_sources': None}
        try:
            if composer_error:
                raise Problem('COMPOSER_CODE_MISMATCH', composer_error)
            verify_composer(self.identity['composer_sources'])
            self.identity['native_sources'] = source_identity(self.root)
            self.source_error = None
        except (Problem, OSError) as exc:
            self.source_error = native_error(getattr(exc, 'code', 'SOURCE_UNAVAILABLE'), str(exc))

    def check_composer(self):
        try:
            verify_composer(self.identity['composer_sources'])
        except (Problem, OSError) as exc:
            self.source_error = native_error(getattr(exc, 'code', 'SOURCE_UNAVAILABLE'), str(exc))
        return self.source_error

    def call(self, kind, payload, checks):
        request = {'kind': kind, 'payload': wire(payload), 'checks': checks,
                   'source_root': str(self.root), 'source_identity': self.identity,
                   'openssl': self.openssl, 'openssl_sha256': self.openssl_sha256}
        raw = encode(request); call_id = sha(raw)
        if call_id in self.cache:
            return self.cache[call_id], call_id
        left = self.limits['seconds'] - (time.monotonic()-self.started)
        if self.source_error:
            result = self.source_error
        elif self.executed >= self.limits['native_calls'] or left <= 0 or self.used + OUTPUT_CAP > self.limits['native_result_bytes']:
            result = native_error('EVALUATION_LIMIT', 'native count/time/result-storage limit')
        elif kind in ('signature', 's3') and payload.get('receiver_policy') is None:
            result = native_error('MISSING_RECEIVER_POLICY', 'selected native check lacks receiver policy')
        elif kind == 'signature' and (not self.openssl or not self.openssl_sha256):
            result = native_error('VERIFIER_NOT_CONFIGURED', 'receiver must select executable and SHA-256')
        else:
            self.executed += 1
            result = self._run(raw, max(0.001, min(left, 30)))
        self.cache[call_id] = result; self.used += len(encode(result))
        # No input body copied into the report: its raw hash and source descriptor
        # identify the complete call, while the originals remain in the snapshot.
        self.calls.append({'call_id': call_id, 'kind': kind, 'input_identity': sha(raw),
                           'payload_identities': identities(payload), 'checks': checks,
                           'result': result})
        return result, call_id

    def _run(self, raw, timeout):
        with tempfile.TemporaryDirectory(prefix='vate-required-native-') as directory:
            folder = Path(directory); inp = folder/'input.json'; inp.write_bytes(raw)
            with (folder/'stdout').open('w+b') as out, (folder/'stderr').open('w+b') as err:
                proc = None
                try:
                    proc = subprocess.Popen([sys.executable, '-I', '-B', '-X', 'pycache_prefix='+str(folder/'bytecode'), str(HERE/'native_bridge.py'), str(inp)],
                        stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True,
                        env={**os.environ, 'PYTHONDONTWRITEBYTECODE':'1',
                             'TMPDIR':str(folder), 'TMP':str(folder), 'TEMP':str(folder)})
                    end = time.monotonic()+timeout
                    while proc.poll() is None:
                        if time.monotonic() >= end or out.tell() > OUTPUT_CAP or err.tell() > 65536:
                            os.killpg(proc.pid, signal.SIGKILL); proc.wait()
                            return native_error('EVALUATION_LIMIT', 'native process time/output limit')
                        time.sleep(min(0.01, max(0.001, end-time.monotonic())))
                    out.seek(0); data = out.read(OUTPUT_CAP+1)
                    err.seek(0); errors = err.read(65537)
                    if len(data) > OUTPUT_CAP or len(errors) > 65536:
                        return native_error('EVALUATION_LIMIT', 'native process output limit')
                    if proc.returncode != 0 or errors:
                        return {'invocation': {'status':'error'}, 'error': {'code':'NATIVE_PROCESS_ERROR',
                            'detail': 'worker failed', 'returncode':proc.returncode,
                            'stdout_base64':base64.b64encode(data).decode(), 'stderr_base64':base64.b64encode(errors).decode()}}
                    result = json.loads(data)
                    if type(result) is not dict:
                        raise ValueError('native response must be an object')
                    return result
                except (OSError, ValueError) as exc:
                    return native_error('NATIVE_PROCESS_ERROR', str(exc))
                finally:
                    if proc is not None and proc.poll() is None:
                        os.killpg(proc.pid, signal.SIGKILL); proc.wait()


def identities(value):
    if isinstance(value, bytes):
        return {'raw_sha256': sha(value), 'byte_length':len(value)}
    if type(value) is dict:
        return {k:identities(v) for k,v in value.items()}
    return value


def worker(request):
    verify_composer(request['source_identity']['composer_sources'])
    root = Path(request['source_root']); source_identity(root)
    payload = unwire(request['payload']); kind = request['kind']
    if kind == 'signature':
        sig = module('required_sig', root/'reference/recipient-signature-authority/recipient_trial.py')
        trial = sig.RecipientTrial(expected_contract=sig.CONTRACT, source_root=root,
            openssl=request['openssl'], openssl_sha256=request['openssl_sha256'], timeout_seconds=10)
        return trial.assess(payload['admission'], payload['post'], admission_proof=payload['admission_proof'],
            post_proof=payload['post_proof'], receiver_policy=payload['receiver_policy'])
    api = module('required_api', root/'reference/recipient-assessment/vate_recipient.py')
    assessor = api.RecipientAssessor(expected_api_contract=api.API_CONTRACT, source_root=root, timeout_seconds=20)
    if kind == 'receipt':
        return assessor.assess_receipts(payload['admission'], payload['post'], requested_checks=request['checks'])
    if kind == 's3':
        with tempfile.TemporaryDirectory(prefix='vate-required-snapshot-') as directory:
            for name, raw in payload['members'].items():
                if name not in __import__('required_records').MEMBERS:
                    raise Problem('INVALID_INPUT', 'unexpected S3 member')
                (Path(directory)/name).write_bytes(raw)
            return assessor.assess_s3(directory, payload['receiver_policy'], requested_checks=request['checks'])
    raise Problem('INVALID_INPUT', 'unknown worker operation')


if __name__ == '__main__':
    try:
        request = json.loads(Path(sys.argv[1]).read_bytes())
        result = worker(request)
    except Exception as exc:
        if hasattr(exc, 'as_dict'):
            result = exc.as_dict()
            if 'invocation' not in result:
                result = native_error(getattr(exc, 'code', 'NATIVE_ERROR'), str(exc))
        else:
            result = native_error('NATIVE_ERROR', str(exc))
    sys.stdout.buffer.write(encode(result)+b'\n')
