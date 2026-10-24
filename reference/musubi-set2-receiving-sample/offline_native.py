"""Receiver-selected, pinned MUSUBI evaluator. macOS only; no unsafe fallback."""
from __future__ import annotations

import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

from receiving import MIB, decode, encoded, need, read, relative, sha, verified_files


def runtime_identity(root, config):
    root = root.absolute()
    expected = {r['path']: r for r in config['runtime_files']}
    need(len(expected) == len(config['runtime_files']), 'duplicate runtime pin')
    # Bytecode is never consumed (-B alone does not disable reads); refuse it.
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and not p.is_symlink()}
    need(actual == set(expected), 'runtime files differ from receiver pin')
    for name, row in expected.items():
        raw = read(root, name, 64*MIB)
        need(sha(raw) == row['sha256'] and len(raw) == row['bytes'], 'runtime content changed: ' + name)
        need(not name.endswith(('.pyc', '.pyo')), 'bytecode not admitted to pinned runtime')
    python = root / 'bin/python'
    need(python.is_file(), 'runtime Python is absent')
    target = python.resolve(strict=True)
    need(sha(target.read_bytes()) == config['interpreter_sha256'], 'interpreter changed')
    for row in config['runtime_executables']:
        need(sha(Path(row['path']).read_bytes()) == row['sha256'], 'runtime launcher changed')
    links = {p.relative_to(root).as_posix(): str(p.resolve()) for p in root.rglob('*') if p.is_symlink()}
    need(links == config['runtime_links'], 'runtime symlinks changed')
    return {'interpreter_sha256': config['interpreter_sha256'], 'interpreter_path': str(target),
            'runtime_files_sha256': sha(encoded(config['runtime_files'])),
            'runtime_links': links, 'runtime_executables': config['runtime_executables'],
            'lock_sha256': config['lock_sha256']}


def replay(source, runtime, config, bundle_raw, output, *, acceptance_job=None):
    output.mkdir(parents=True, exist_ok=False)
    need(config['contract'] == 'local-musubi-native-evaluator-1', 'evaluator contract')
    files = verified_files(source, config['source_files'])
    relative(config['entrypoint'])
    need(config['entrypoint'] in files and config['entrypoint'].endswith('/pilot_v0.py'), 'entrypoint pin')
    need(sha(read(runtime.parent, 'requirements.lock')) == config['lock_sha256'], 'dependency lock changed')
    identity = runtime_identity(runtime, config)
    for name, raw in files.items():
        p = output / 'source' / name
        p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(raw)
    (output / 'input.json').write_bytes(bundle_raw)
    evidence = {'runtime-identity.json': encoded(identity),
                'requirements.lock': read(runtime.parent, 'requirements.lock')}
    evidence.update({'evaluator-source/' + n: raw for n, raw in files.items()})
    if acceptance_job is not None:
        from acceptance_adapter import output_evidence
        evidence.update(output_evidence(acceptance_job, output))
    if sys.platform != 'darwin' or not Path('/usr/bin/sandbox-exec').is_file():
        return {'state': 'evaluator_error', 'error': 'sandbox_unsupported_platform'}, b'', b'', evidence
    # Resolve output because /var and /tmp are symlinks on macOS.
    output = output.resolve(); runtime = runtime.absolute()
    def quote(path):
        text = str(path)
        need(not any(c in text for c in ('"', '\\', '\n', '\r')), 'unsupported sandbox path characters')
        return '"' + text + '"'
    profile = '\n'.join([
        '(version 1)', '(allow default)', '(deny network*)', '(deny file-write*)',
        f'(allow file-write* (literal "/dev/null") (subpath {quote(output)}))',
        f'(deny file-read* (subpath {quote(Path.home().resolve())}))',
        f'(allow file-read* (subpath {quote(runtime.resolve())}) (subpath {quote(output)}))',
        f'(allow file-read-metadata (subpath {quote(Path.home().resolve())}))',
        '(deny file-read* (subpath "/Library/Keychains"))',
        '(deny process-exec)',
        '(allow process-exec ' + ' '.join('(literal ' + quote(p) + ')' for p in
            [identity['interpreter_path']] + [r['path'] for r in config['runtime_executables']]) + ')',
        '(deny mach-lookup (global-name "com.apple.securityd") (global-name "com.apple.secd"))', ''])
    (output / 'execution.sb').write_text(profile)
    evidence['execution.sb'] = profile.encode()
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(output), 'LANG': 'C', 'LC_ALL': 'C',
           'PYTHONDONTWRITEBYTECODE': '1'}
    prefix = ['/usr/bin/sandbox-exec', '-f', str(output / 'execution.sb'),
              str(runtime / 'bin/python'), '-I', '-B']
    def execute(code, stem):
        with (output / (stem + '.stdout')).open('wb') as out, (output / (stem + '.stderr')).open('wb') as err:
            proc = subprocess.Popen(prefix + ['-c', code], cwd=output, env=env,
                                    stdout=out, stderr=err, start_new_session=True)
            timeout = False
            try:
                proc.wait(timeout=90)
            except subprocess.TimeoutExpired:
                timeout = True
                os.killpg(proc.pid, signal.SIGKILL); proc.wait()
        return proc.returncode, timeout, (output / (stem + '.stdout')).read_bytes(), (output / (stem + '.stderr')).read_bytes()
    with tempfile.TemporaryDirectory(prefix='.vate-offline-probe-', dir=Path.home()) as tmp:
        canary = Path(tmp) / 'canary'; canary.write_text('local permission probe, no secret')
        probe = ('import socket,importlib.metadata,json,sys\n'
                 'try:\n socket.socket().connect(("127.0.0.1",9))\n raise RuntimeError("network allowed")\n'
                 'except PermissionError: pass\n'
                 f'try:\n open({str(canary)!r},"rb")\n raise RuntimeError("home read allowed")\n'
                 'except PermissionError: pass\n'
                 'print(json.dumps({"network_denied":True,"home_read_denied":True,'
                 '"python":sys.version,"packages":{d.metadata["Name"]:d.version for d in importlib.metadata.distributions()}},sort_keys=True))')
        rc, timed, out, err = execute(probe, 'probe')
        evidence['sandbox-probe.stdout'] = out; evidence['sandbox-probe.stderr'] = err
        if rc or timed:
            return {'state': 'evaluator_error', 'error': 'sandbox_probe_failed', 'exit_code': rc}, b'', err, evidence
    facts = decode(out)
    need(facts['packages'] == config['packages'], 'runtime package versions changed')
    script = output / 'source' / config['entrypoint']
    # Import only the fixed source copy, never the incoming originals directory.
    code = ('import sys,runpy,resource\n'
            'resource.setrlimit(resource.RLIMIT_FSIZE,(4194304,4194304))\n'
            f'sys.path.insert(0,{str(script.parent)!r})\n'
            f'sys.argv=[{str(script)!r},"--settle",{str(output / "input.json")!r}]\n'
            f'runpy.run_path({str(script)!r},run_name="__main__")\n')
    rc, timed, stdout, stderr = execute(code, 'settlement')
    if acceptance_job is not None:
        # Use the same deny-network/Keychain sandbox and pinned runtime. The
        # foreign format cannot choose Python code, import paths or trust roots.
        worker = output/'acceptance-source/acceptance_worker.py'
        acceptance_code = ('import sys,runpy,resource\n'
                           'resource.setrlimit(resource.RLIMIT_FSIZE,(4194304,4194304))\n'
                           'resource.setrlimit(resource.RLIMIT_CPU,(30,30))\n'
                           f'sys.path.insert(0,{str(worker.parent)!r})\n'
                           f'sys.argv=[{str(worker)!r},{str(output/"acceptance-input.json")!r}]\n'
                           f'runpy.run_path({str(worker)!r},run_name="__main__")\n')
        arc, atimed, aout, aerr = execute(acceptance_code, 'acceptance')
        evidence['acceptance.stdout'] = aout
        evidence['acceptance.stderr'] = aerr
        verified = {'state': 'evaluator_error', 'error': 'acceptance_worker_failed', 'results': {}}
        if arc == 0 and not atimed:
            try:
                parsed = decode(aout)
                expected_ids = {row['id'] for row in acceptance_job['input']['items']}
                need(type(parsed) is dict and parsed.get('profile') == acceptance_job['input']['profile']
                     and parsed.get('state') in ('evaluated', 'evaluator_error') and type(parsed.get('results')) is dict
                     and set(parsed['results']) == expected_ids, 'acceptance worker output contract')
                verified = parsed
            except (ValueError, TypeError):
                verified['error'] = 'acceptance_worker_output_contract'
        evidence['acceptance-verification.json'] = encoded(verified)
        evidence['acceptance-execution.json'] = encoded({'exit_code': arc, 'timeout': atimed,
            'state': verified['state'], 'input_sha256': sha(evidence['acceptance-input.json']),
            'stdout_sha256': sha(aout), 'stderr_sha256': sha(aerr),
            'verifier_sha256': acceptance_job['config']['verifier_sha256'],
            'source_sha256': {n: sha(raw) for n, raw in acceptance_job['sources'].items()},
            'profile_sha256': sha(profile.encode()), 'network_denied_probe': True,
            'outside_home_content_denied_probe': True})
        for name, raw in acceptance_job['sources'].items():
            need(read(output/'acceptance-source', name) == raw, 'acceptance source changed during execution')
        need(read(output, 'acceptance-input.json') == evidence['acceptance-input.json'],
             'acceptance input changed during execution')
    # Refuse accepting a run if receiver-selected source/runtime drifted.
    runtime_identity(runtime, config)
    for name, raw in files.items():
        need(read(output / 'source', name) == raw, 'evaluator source changed during execution')
    record = {'state': 'process_completed' if rc in (0, 2, 3) and not timed else 'evaluator_error',
              'exit_code': rc, 'timeout': timed, 'command': prefix + ['-c', code],
              'input_sha256': sha(bundle_raw), 'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr),
              'evaluator_identity_sha256': sha(encoded(config)), 'profile_sha256': sha(profile.encode()),
              'network_denied_probe': True, 'outside_home_content_denied_probe': True,
              'runtime': facts}
    return record, stdout, stderr, evidence
