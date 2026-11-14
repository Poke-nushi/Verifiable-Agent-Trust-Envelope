"""One HTTPS fetch in a disposable process, with bounded pipes and owned deadlines."""
from dataclasses import dataclass
from contextlib import contextmanager
import base64
import hashlib
import os
from pathlib import Path
import selectors
import ssl
import subprocess
import sys
from threading import Event, Lock, Thread
import time

# The worker runs with -I -S: add only this installation's selected source tree.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import https_source as https
import snapshot as s

MAX_CA_BYTES = 1024 * 1024
MAX_REQUEST_BYTES = 2 * MAX_CA_BYTES
CLEANUP_SECONDS = 3
WORKER_CONTRACT = "vate-supervised-https-fetch-v1"
_source = None
try:
    _source = Path(__file__).read_bytes()
    LOADED_SOURCE_SHA256 = (hashlib.sha256(_source).hexdigest() if hasattr(sys, "_getframe")
        and sys._getframe().f_code == compile(_source, sys._getframe().f_code.co_filename,
            "exec", dont_inherit=True, optimize=sys.flags.optimize) else None)
except (OSError, SyntaxError, ValueError):
    LOADED_SOURCE_SHA256 = None
del _source


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ca_data(raw):
    # SSL accepts PEM as ASCII text and DER as bytes.
    return raw.decode("ascii") if b"-----BEGIN CERTIFICATE-----" in raw else raw


@dataclass(frozen=True)
class _Configuration:
    request: bytes
    timeout: float
    python: Path
    python_sha256: str
    worker: Path
    sources: tuple


class _Attempt:
    def __init__(self):
        self.done, self.cancel = Event(), Event()
        self.thread = self.process = self.result = self.error = None
        self.start_gate = Lock()
        self.owner_started = self.start_cancelled = False
        self.cleanup_complete = False


class SupervisedHttpsSnapshotSource:
    """Fetch only; AuthorityStore.refresh still authenticates and installs the result."""

    _loaded_source_path = Path(__file__).resolve()
    _loaded_source_sha256 = LOADED_SOURCE_SHA256

    def __init__(self, url: str, *, ca_file: str | Path | None = None,
                 timeout_seconds: float = 5.0):
        s.need(os.name == "posix", "AUTHORITY_SUPERVISOR_UNSUPPORTED")
        s.class_identity(self, sys.modules[__name__])
        s.module_identity(https)
        try:
            raw_ca = None
            if ca_file is not None:
                with Path(ca_file).open("rb") as stream:
                    raw_ca = stream.read(MAX_CA_BYTES + 1)
                s.need(0 < len(raw_ca) <= MAX_CA_BYTES, "AUTHORITY_CA_CONFIGURATION_INVALID")
            https.validate_source_options(url, timeout_seconds)
            if raw_ca is not None:
                # Parse only the selected bundle. Do not load environmental trust
                # paths or SSLKEYLOGFILE into the parent process.
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.load_verify_locations(cadata=_ca_data(raw_ca))
            worker = Path(__file__).resolve(strict=True)
            sources = tuple((path, _sha(path)) for path in (worker, worker.with_name("https_source.py")))
            python = Path(sys.executable).resolve(strict=True)
            request = s.b.encode({"contract": WORKER_CONTRACT, "url": url,
                "timeout_seconds": str(timeout_seconds),
                "ca_base64": base64.b64encode(raw_ca).decode("ascii") if raw_ca is not None else None,
                "source_sha256": {path.name: digest for path, digest in sources}})
            s.need(len(request) <= MAX_REQUEST_BYTES, "AUTHORITY_FETCH_CONFIGURATION_INVALID")
            self._config = _Configuration(request, timeout_seconds, python, _sha(python), worker, sources)
            self._owner_pid, self._lock, self._pending_attempt = os.getpid(), Lock(), None
        except s.AuthorityError:
            raise
        except (OSError, ValueError, TypeError, RuntimeError):
            raise s.AuthorityError("AUTHORITY_FETCH_CONFIGURATION_INVALID") from None

    def _check_files(self):
        s.class_identity(self, sys.modules[__name__])
        s.module_identity(https)
        cfg = self._config
        try:
            s.need(_sha(cfg.python) == cfg.python_sha256
                   and all(_sha(path) == digest for path, digest in cfg.sources),
                   "AUTHORITY_FETCH_IMPLEMENTATION_CHANGED")
        except OSError:
            raise s.AuthorityError("AUTHORITY_FETCH_IMPLEMENTATION_CHANGED") from None

    def _command(self):
        cfg = self._config
        return [str(cfg.python), "-I", "-S", "-B", str(cfg.worker), "--worker"]

    @contextmanager
    def _gate(self):
        s.need(os.getpid() == self._owner_pid, "AUTHORITY_FETCH_FORK_NEW_SOURCE_REQUIRED")
        s.need(self._lock.acquire(blocking=False), "AUTHORITY_FETCH_BUSY")
        try:
            yield
        finally:
            self._lock.release()

    @property
    def pending_worker_pid(self):
        """Diagnostic only: a startup still in progress may have no available PID."""
        with self._gate():
            attempt = self._pending_attempt
            return attempt.process.pid if attempt is not None and attempt.process is not None else None

    @property
    def cleanup_required(self):
        with self._gate():
            return self._pending_attempt is not None

    def cleanup_pending(self):
        with self._gate():
            attempt = self._pending_attempt
            if attempt is not None:
                self._finish_attempt(attempt, retry=True)

    def __call__(self) -> bytes:
        with self._gate():
            s.need(self._pending_attempt is None, "AUTHORITY_FETCH_CLEANUP_REQUIRED")
            self._check_files()
            raw = self._supervise()
            self._check_files()
            return raw

    def _supervise(self):
        deadline = time.monotonic() + self._config.timeout
        attempt = _Attempt()
        attempt.thread = Thread(target=self._run_attempt, args=(attempt, deadline), daemon=True)
        # Publish ownership before Thread.start and Popen: SIGINT is handled by
        # Python's main thread, while this owner retains every created child.
        self._pending_attempt = attempt
        failure = None
        try:
            try:
                attempt.thread.start()
            except Exception:
                # A normal thread-creation failure created no owner or child.
                # An asynchronous BaseException leaves startup unconfirmed.
                attempt.cleanup_complete = True
                attempt.done.set()
                raise s.AuthorityError("AUTHORITY_FETCH_WORKER_FAILED") from None
            s.need(attempt.done.wait(max(0, deadline - time.monotonic())), "AUTHORITY_FETCH_TIMEOUT")
            if attempt.error is not None:
                raise attempt.error
            s.need(time.monotonic() <= deadline, "AUTHORITY_FETCH_TIMEOUT")
            return attempt.result
        except BaseException as error:
            failure = error
            raise
        finally:
            try:
                self._finish_attempt(attempt)
            except BaseException:
                # Keep the pending owner, but do not swallow a caller's interrupt.
                if failure is not None and not isinstance(failure, Exception):
                    raise failure
                raise

    def _run_attempt(self, attempt, deadline):
        try:
            with attempt.start_gate:
                if attempt.start_cancelled:
                    return
                attempt.owner_started = True
            attempt.result = self._process(attempt, deadline)
        except BaseException as error:
            attempt.error = error
        finally:
            attempt.done.set()

    def _finish_attempt(self, attempt, *, retry=False):
        attempt.cancel.set()
        deadline = time.monotonic() + CLEANUP_SECONDS
        s.need(attempt.start_gate.acquire(timeout=CLEANUP_SECONDS), "AUTHORITY_FETCH_CLEANUP_FAILED")
        try:
            if not attempt.owner_started:
                # Close the acquisition gate even if OS thread startup is still
                # pending. A late owner cannot enter _process or create a child.
                attempt.start_cancelled = True
                attempt.cleanup_complete = True
                if attempt.thread.ident is None:
                    self._pending_attempt = None
                    return
        finally:
            attempt.start_gate.release()
        s.need(attempt.done.wait(max(0, deadline - time.monotonic())), "AUTHORITY_FETCH_CLEANUP_FAILED")
        if attempt.thread.ident is not None:
            attempt.thread.join(max(0, deadline - time.monotonic()))
        s.need(not attempt.thread.is_alive(), "AUTHORITY_FETCH_CLEANUP_FAILED")
        if retry and not attempt.cleanup_complete and attempt.process is not None:
            self._cleanup(attempt.process, timeout=max(0, deadline - time.monotonic()))
            attempt.cleanup_complete = True
        s.need(attempt.cleanup_complete, "AUTHORITY_FETCH_CLEANUP_FAILED")
        self._pending_attempt = None

    def _cleanup(self, process, *, timeout=CLEANUP_SECONDS):
        try:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            raise s.AuthorityError("AUTHORITY_FETCH_CLEANUP_FAILED") from None
        finally:
            process.stdin.close()
            process.stdout.close()

    def _process(self, attempt, deadline):
        cfg, process = self._config, None
        try:
            s.need(not attempt.cancel.is_set(), "AUTHORITY_FETCH_CANCELLED")
            process = subprocess.Popen(self._command(), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0, close_fds=True,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
            attempt.process = process
            position, output = 0, bytearray()
            with selectors.DefaultSelector() as selector:
                os.set_blocking(process.stdin.fileno(), False)
                os.set_blocking(process.stdout.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE)
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    s.need(not attempt.cancel.is_set(), "AUTHORITY_FETCH_CANCELLED")
                    remaining = deadline - time.monotonic()
                    s.need(remaining > 0, "AUTHORITY_FETCH_TIMEOUT")
                    for key, _ in selector.select(min(remaining, 0.05)):
                        if key.fileobj is process.stdin:
                            position += os.write(key.fd, cfg.request[position:position + 4096])
                            if position == len(cfg.request):
                                selector.unregister(process.stdin)
                                process.stdin.close()
                        else:
                            chunk = os.read(key.fd, s.jwt.MAX_TOKEN_BYTES + 1 - len(output))
                            output.extend(chunk)
                            s.need(len(output) <= s.jwt.MAX_TOKEN_BYTES, "AUTHORITY_FETCH_OUTPUT_INVALID")
                            if not chunk:
                                selector.unregister(process.stdout)
            while True:
                s.need(not attempt.cancel.is_set(), "AUTHORITY_FETCH_CANCELLED")
                remaining = deadline - time.monotonic()
                s.need(remaining > 0, "AUTHORITY_FETCH_TIMEOUT")
                try:
                    s.need(process.wait(timeout=min(remaining, 0.05)) == 0, "AUTHORITY_FETCH_WORKER_FAILED")
                    break
                except subprocess.TimeoutExpired:
                    pass
            s.need(time.monotonic() <= deadline, "AUTHORITY_FETCH_TIMEOUT")
            s.need(bool(output), "AUTHORITY_FETCH_OUTPUT_INVALID")
            return bytes(output)
        except subprocess.TimeoutExpired:
            raise s.AuthorityError("AUTHORITY_FETCH_TIMEOUT") from None
        except (OSError, ValueError) as error:
            if isinstance(error, s.AuthorityError):
                raise
            raise s.AuthorityError("AUTHORITY_FETCH_WORKER_FAILED") from None
        finally:
            if process is not None:
                self._cleanup(process)
            attempt.cleanup_complete = True


@contextmanager
def _worker_deadline(timeout):
    # The parent may die without running cleanup. Keep a local acquisition
    # deadline even while the worker's main thread is blocked in DNS or TLS.
    done = Event()
    deadline = time.monotonic() + timeout
    def expire():
        if not done.wait(max(0, deadline - time.monotonic())):
            os._exit(1)
    guard = Thread(target=expire, name="authority-fetch-deadline", daemon=True)
    guard.start()
    try:
        yield
    finally:
        done.set()
        guard.join()


def _worker():
    """Fixed private pipe protocol; never print errors, configuration or partial bodies."""
    try:
        raw_request = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        s.need(0 < len(raw_request) <= MAX_REQUEST_BYTES, "AUTHORITY_FETCH_REQUEST_INVALID")
        request = s.b.decode(raw_request)
        s.need(type(request) is dict and set(request) == {
            "contract", "url", "timeout_seconds", "ca_base64", "source_sha256"}
            and request["contract"] == WORKER_CONTRACT, "AUTHORITY_FETCH_REQUEST_INVALID")
        expected = request["source_sha256"]
        paths = (Path(__file__).resolve(), Path(__file__).resolve().with_name("https_source.py"))
        s.need(type(expected) is dict and set(expected) == {path.name for path in paths}
               and s.module_identity(sys.modules[__name__]) == expected[paths[0].name]
               and s.module_identity(https) == expected[paths[1].name],
               "AUTHORITY_FETCH_IMPLEMENTATION_CHANGED")
        ca = request["ca_base64"]
        if ca is not None:
            s.need(type(ca) is str, "AUTHORITY_FETCH_REQUEST_INVALID")
            raw_ca = base64.b64decode(ca, validate=True)
            s.need(0 < len(raw_ca) <= MAX_CA_BYTES
                   and base64.b64encode(raw_ca).decode("ascii") == ca, "AUTHORITY_FETCH_REQUEST_INVALID")
            ca = _ca_data(raw_ca)
        s.need(type(request["timeout_seconds"]) is str and 0 < len(request["timeout_seconds"]) <= 64,
               "AUTHORITY_FETCH_REQUEST_INVALID")
        timeout = float(request["timeout_seconds"])
        https.validate_source_options(request["url"], timeout)
        with _worker_deadline(timeout):
            source = https.HttpsSnapshotSource(request["url"], ca_data=ca, timeout_seconds=timeout)
            raw = source()
            s.need(all(_sha(path) == expected[path.name] for path in paths),
                   "AUTHORITY_FETCH_IMPLEMENTATION_CHANGED")
            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()
        return 0
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(_worker() if sys.argv[1:] == ["--worker"] else 2)
