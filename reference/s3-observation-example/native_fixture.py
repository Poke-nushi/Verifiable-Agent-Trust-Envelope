"""Single-owner local test fixture using an explicitly supplied, pinned runtime."""
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import tempfile
import time

from contract import HERE, decode, need, now, sha, write
from sandbox_macos import free_ports, profile_text


class LocalSeaweed:
    def __init__(self, destination, binary):
        need(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'native fixture requires macOS arm64')
        self.binary = Path(binary).resolve(strict=True)
        self.installation = decode((HERE / 'SEAWEEDFS-PIN.json').read_bytes())
        need(self.binary.is_file() and self.binary.stat().st_size == self.installation['binary_size'], 'binary size/type mismatch')
        need(sha(self.binary.read_bytes()) == self.installation['binary_sha256'], 'binary pin mismatch')
        self.destination = Path(destination).resolve()
        self.destination.mkdir(mode=0o700)
        self.work = Path(tempfile.mkdtemp(prefix='vate-s3-link-', dir='/private/tmp'))
        self.process = None
        self.log = None
        self.sockets = []
        self.owned_sockets = []
        self.credentials = {}
        self.lifecycle = {'started_at': now(), 'work_directory': str(self.work),
                          'binary_sha256': self.installation['binary_sha256']}

    def __enter__(self):
        try:
            self.start()
            return self
        except BaseException as exc:
            self.__exit__(type(exc), exc, exc.__traceback__)
            raise

    def start(self):
        for d in ('data', 'tmp', 'bundles', 'native-controls'):
            (self.work / d).mkdir(mode=0o700)
        self.ports = free_ports(8)
        master, mg, volume, vg, filer, fg, s3, sg = self.ports
        self.sockets = [Path(f'/private/tmp/seaweedfs-{name}-grpc-{port}.sock')
                        for name, port in zip(('master', 'volume', 'filer', 's3'), self.ports[1::2])]
        need(all(not os.path.lexists(p) for p in self.sockets), 'existing socket')
        self.owned_sockets = list(self.sockets)
        self.profile = self.work / 'sandbox.sb'
        self.profile.write_text(profile_text(self.binary, self.work, self.ports, self.sockets))
        self.sandbox = ['/usr/bin/sandbox-exec', '-f', str(self.profile)]
        self.env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'TMPDIR': str(self.work / 'tmp')}
        self.bucket = 'vate-linkage-' + secrets.token_hex(5)
        self.other_bucket = 'vate-other-' + secrets.token_hex(5)
        self.endpoint = f'http://127.0.0.1:{s3}'
        self.endpoint_profile_id = 'local-seaweed-' + secrets.token_hex(6)
        self.credentials = {role: (role + secrets.token_hex(8), secrets.token_hex(24)) for role in ('setup', 'writer', 'observer')}
        actions = {'setup': ['Admin'], 'writer': ['Write:' + self.bucket], 'observer': ['Read:' + self.bucket]}
        config = {'identities': [{'name': r, 'credentials': [{'accessKey': key, 'secretKey': secret}], 'actions': actions[r]}
                                  for r, (key, secret) in self.credentials.items()]}
        write(self.work / 'credentials.json', config)
        (self.work / 'credentials.json').chmod(0o600)
        write(self.work / 'roles-redacted.json', actions)
        args = [str(self.binary), 'server', '-ip=127.0.0.1', '-ip.bind=127.0.0.1',
                '-dir=' + str(self.work / 'data'), '-master.dir=' + str(self.work / 'data'),
                '-master.port=' + str(master), '-master.port.grpc=' + str(mg), '-master.peers=none',
                '-master.volumeSizeLimitMB=5', '-master.volumePreallocate=false', '-master.telemetry=false',
                '-volume.max=8', '-volume.port=' + str(volume), '-volume.port.grpc=' + str(vg),
                '-filer', '-filer.port=' + str(filer), '-filer.port.grpc=' + str(fg), '-filer.localSocket=' + str(self.work / 'filer.sock'),
                '-s3', '-s3.port=' + str(s3), '-s3.port.grpc=' + str(sg), '-s3.ip.bind=127.0.0.1',
                '-s3.port.iceberg=0', '-s3.port.lance=0', '-s3.iam=false', '-s3.autoCreateBucket=false',
                '-s3.config=' + str(self.work / 'credentials.json'), '-s3.localSocket=' + str(self.work / 's3.sock'),
                '-metricsPort=0', '-debug=false']
        write(self.work / 'launch.json', {'argv': [*self.sandbox, *args], 'environment': self.env, **self.lifecycle})
        self.log = (self.work / 'server.log').open('wb')
        self.process = subprocess.Popen([*self.sandbox, *args], cwd=self.work, env=self.env,
                                        stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        write(self.destination / 'active-process.json', {'pid': self.process.pid, 'work': str(self.work)})
        deadline = time.monotonic() + 45
        while True:
            need(self.process.poll() is None, 'server exited during startup')
            try:
                with socket.create_connection(('127.0.0.1', s3), timeout=0.3):
                    break
            except OSError:
                need(time.monotonic() < deadline, 'server startup timeout')
                time.sleep(0.2)
        found = subprocess.run(['/usr/sbin/lsof', '-nP', '-a', '-p', str(self.process.pid), '-iTCP', '-sTCP:LISTEN'], capture_output=True)
        write(self.work / 'listeners.txt', found.stdout + found.stderr)
        rows = found.stdout.decode().splitlines()[1:]
        observed = {int(m.group(1)) for row in rows if (m := re.search(r'127\.0\.0\.1:(\d+) \(LISTEN\)', row))}
        need(bool(rows) and all('127.0.0.1:' in row and '(LISTEN)' in row for row in rows) and observed == set(self.ports), 'listener isolation failed')
        self.lifecycle['listeners'] = sorted(observed)
        self.lifecycle['pid'] = self.process.pid

    def __exit__(self, exc_type, exc, tb):
        errors = []
        def perform(label, action):
            try:
                action()
            except BaseException as failure:
                errors.append({'step': label, 'error_type': type(failure).__name__})

        def signal_group(signum):
            try:
                os.killpg(self.process.pid, signum)
            except ProcessLookupError:
                pass  # The process can exit between poll and killpg.

        def stop_process():
            if self.process is None:
                self.lifecycle['process_stopped'] = True
                return
            if self.process.poll() is None:
                try:
                    signal_group(signal.SIGTERM)
                    self.process.wait(timeout=20)
                except BaseException as failure:
                    if not isinstance(failure, subprocess.TimeoutExpired):
                        errors.append({'step': 'graceful_stop', 'error_type': type(failure).__name__})
                    signal_group(signal.SIGKILL)
                    self.process.wait(timeout=5)
            self.lifecycle['exit_code'] = self.process.returncode
            handles = subprocess.run(['/usr/sbin/lsof', '-nP', '-a', '-p', str(self.process.pid), '-i'], capture_output=True)
            self.lifecycle['process_stopped'] = self.process.poll() is not None and not handles.stdout

        def scan_credentials():
            values = [v.encode() for pair in self.credentials.values() for v in pair]
            residual_paths = []
            for p in self.work.rglob('*'):
                if p.is_file() and not p.is_symlink():
                    raw = p.read_bytes()
                    if any(v in raw for v in values):
                        residual_paths.append(str(p.relative_to(self.work)))
            self.lifecycle['credential_marker_residual_paths'] = residual_paths

        def remove_sockets():
            # Never touch sockets found before this fixture started, or a live server's sockets.
            if not self.lifecycle.get('process_stopped'):
                return
            for p in self.owned_sockets:
                if p.is_socket() and p.lstat().st_uid == os.getuid():
                    p.unlink()
            for p in self.work.rglob('*'):
                if p.is_socket():
                    p.unlink()

        try:
            perform('stop_process', stop_process)
            if self.log is not None:
                perform('close_log', self.log.close)
            perform('remove_credentials', lambda: (self.work / 'credentials.json').unlink(missing_ok=True))
            self.lifecycle['credentials_file_removed'] = not (self.work / 'credentials.json').exists()
            perform('scan_credentials', scan_credentials)
            perform('remove_sockets', remove_sockets)
            self.lifecycle['grpc_sockets'] = {str(p): os.path.lexists(p) for p in self.owned_sockets}
            self.lifecycle['finished_at'] = now()
            self.lifecycle['exception_type'] = exc_type.__name__ if exc_type else None
            if self.lifecycle.get('process_stopped'):
                perform('retain_instance', lambda: shutil.move(str(self.work), self.destination / 'instance'))
            self.lifecycle['cleanup_errors'] = errors
            self.lifecycle['cleanup_ok'] = bool(
                self.lifecycle.get('process_stopped') and self.lifecycle['credentials_file_removed']
                and self.lifecycle.get('credential_marker_residual_paths') == []
                and not any(self.lifecycle['grpc_sockets'].values()) and not errors)
            retained = self.work if self.work.exists() else self.destination / 'instance'
            perform('write_lifecycle', lambda: write(retained / 'LIFECYCLE.json', self.lifecycle))
        finally:
            self.credentials.clear()
        need(self.lifecycle.get('cleanup_ok') and not errors,
             'fixture cleanup incomplete; inspect retained output/work directory')
        return False
