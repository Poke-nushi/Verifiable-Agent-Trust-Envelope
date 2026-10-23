"""Prepare a new, hash-locked local runtime; never update an existing one."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from receiving import encoded, need, sha, verified_files

ROOT = Path(__file__).resolve().parent


def template():
    config = json.loads((ROOT / 'evaluator-template.json').read_bytes())
    need(sha((ROOT / 'requirements.lock').read_bytes()) == config['lock_sha256'],
         'dependency lock differs from the sample pin')
    verified_files(ROOT / 'sample/evaluator-source', config['source_files'])
    return config


def check_vate(root):
    pin = json.loads((ROOT / 'vate-source.json').read_bytes())
    verified_files(root.resolve(), pin['files'])
    return pin


def check_environment(environment):
    from offline_native import runtime_identity
    fixed = template()
    config = json.loads((environment / 'evaluator.json').read_bytes())
    need(all(config.get(k) == v for k, v in fixed.items()),
         'prepared evaluator does not use this sample source/lock selection')
    need(sha((environment / 'requirements.lock').read_bytes()) == fixed['lock_sha256'],
         'prepared dependency lock changed')
    runtime_identity(environment / 'venv', config)
    return config


def prepare(output, vate_root, uv):
    need(sys.platform == 'darwin' and Path('/usr/bin/sandbox-exec').is_file(),
         'native replay requires macOS sandbox-exec; no unsandboxed fallback')
    need((3, 11) <= sys.version_info[:2] <= (3, 14), 'use Python 3.11 through 3.14')
    fixed = template()
    vate_pin = check_vate(vate_root)
    output = output.resolve()
    need(not output.is_relative_to(ROOT), 'put the runtime outside the sample directory')
    need(not output.exists(), 'environment already exists; choose a new directory')
    uv_path = shutil.which(uv)
    need(uv_path is not None, 'uv is required; select an existing uv executable with --uv')
    output.mkdir(parents=True, exist_ok=False)
    runtime = output / 'venv'
    # Do not inherit package-index, authentication, bytecode or Python path overrides.
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(output), 'LANG': 'C', 'LC_ALL': 'C',
           'PYTHONDONTWRITEBYTECODE': '1'}
    log = output / 'PREPARATION.log'
    with log.open('wb') as stream:
        subprocess.run([sys.executable, '-I', '-B', '-m', 'venv', '--without-pip', str(runtime)],
                       check=True, stdout=stream, stderr=stream, env=env, timeout=90)
        shutil.copyfile(ROOT / 'requirements.lock', output / 'requirements.lock')
        subprocess.run([uv_path, '--no-config', '--no-cache', '--system-certs', 'pip', 'sync',
                        '--python', str(runtime / 'bin/python'), '--require-hashes',
                        '--only-binary', ':all:', '--link-mode', 'copy', '--keyring-provider', 'disabled',
                        '--default-index', 'https://pypi.org/simple', str(output / 'requirements.lock')],
                       check=True, stdout=stream, stderr=stream, env=env, timeout=600)
    # Inspect distribution metadata, not arbitrary package imports.
    probe = ('import importlib.metadata,json,sys,pathlib; '
             'print(json.dumps({"packages":{d.metadata["Name"]:d.version '
             'for d in importlib.metadata.distributions()},"python":sys.version,'
             '"base_prefix":sys.base_prefix}))')
    metadata = json.loads(subprocess.check_output([str(runtime / 'bin/python'), '-I', '-B', '-c', probe],
                                                  env=env, timeout=30))
    need(metadata['packages'] == fixed['packages'], 'installed distributions differ from the selected pins')
    files, links = [], {}
    for path in sorted(runtime.rglob('*')):
        name = path.relative_to(runtime).as_posix()
        if path.is_symlink():
            links[name] = str(path.resolve(strict=True))
        elif path.is_file():
            need(path.suffix not in ('.pyc', '.pyo'), 'unexpected bytecode in new runtime')
            raw = path.read_bytes()
            files.append({'path': name, 'sha256': sha(raw), 'bytes': len(raw)})
    launcher = Path(metadata['base_prefix']) / 'Resources/Python.app/Contents/MacOS/Python'
    executables = ([{'path': str(launcher.resolve()), 'sha256': sha(launcher.read_bytes())}]
                   if launcher.is_file() else [])
    fixed.update(runtime_files=files, runtime_links=links, runtime_executables=executables,
                 interpreter_sha256=sha((runtime / 'bin/python').resolve(strict=True).read_bytes()))
    (output / 'evaluator.json').write_bytes(encoded(fixed))
    check_environment(output)
    record = {'status': 'prepared', 'python': metadata['python'], 'packages': fixed['packages'],
              'evaluator_sha256': sha((output / 'evaluator.json').read_bytes()),
              'vate_source_commit': vate_pin['commit'], 'runtime_files': len(files),
              'scope': 'local installation snapshot; native replay is checked separately'}
    (output / 'PREPARED.json').write_bytes(encoded(record))
    return record


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True, help='new local environment directory')
    ap.add_argument('--vate-root', type=Path, required=True, help='pinned VATE checkout or source archive')
    ap.add_argument('--uv', default='uv', help='existing uv executable; no tool installation')
    a = ap.parse_args()
    try:
        result = prepare(a.output, a.vate_root, a.uv)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({'status': 'preparation_error', 'error': str(exc),
                          'next': 'keep the preparation log; retry with a new output directory'}))
        return 64
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
