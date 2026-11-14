"""Cooperative refresh, retry and shutdown for one application's managed verifier."""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import sys
from threading import Event, Lock
import time

import managed_verifier as managed
import snapshot as s
from supervised_https import SupervisedHttpsSnapshotSource

_source = None
try:
    _source = Path(__file__).read_bytes()
    LOADED_SOURCE_SHA256 = (hashlib.sha256(_source).hexdigest() if hasattr(sys, "_getframe")
        and sys._getframe().f_code == compile(_source, sys._getframe().f_code.co_filename,
            "exec", dont_inherit=True, optimize=sys.flags.optimize) else None)
except (OSError, SyntaxError, ValueError):
    LOADED_SOURCE_SHA256 = None
del _source


def _finite(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


@dataclass(frozen=True)
class RefreshStatus:
    """Local scheduling observations, not an authorization or store-health result."""

    phase: str
    next_attempt_in_seconds: float | None
    last_installed_revision: int | None
    last_failure: str | None


class RefreshingAuthorityVerifier:
    """Serialize complete refreshes and managed calls; the application drives poll()."""

    _loaded_source_path = Path(__file__).resolve()
    _loaded_source_sha256 = LOADED_SOURCE_SHA256

    def __init__(self, *, verifier, fetch, refresh_interval_seconds,
                 retry_interval_seconds, monotonic=time.monotonic):
        s.class_identity(self, sys.modules[__name__])
        s.need(type(verifier) is managed.ManagedAuthorityVerifier
               and type(fetch) is SupervisedHttpsSnapshotSource and callable(monotonic)
               and all(_finite(value) and value > 0 for value in
                       (refresh_interval_seconds, retry_interval_seconds)),
               "AUTHORITY_REFRESH_CONFIGURATION_INVALID")
        self._verifier, self._fetch, self._source = verifier, fetch, verifier.source
        self._source_id = self._source.configuration_id()
        self._interval, self._retry = refresh_interval_seconds, retry_interval_seconds
        self._monotonic, self._clock_high, self._clock_failed = monotonic, None, False
        self._pid, self._lock, self._stop = os.getpid(), Lock(), Event()
        self._entry_lock = Lock()
        self._ready = self._closed = False
        self._due = self._revision = self._failure = None
        self._now()

    def _owner(self):
        s.need(os.getpid() == self._pid, "AUTHORITY_REFRESH_FORK_REOPEN_REQUIRED")

    @contextmanager
    def _gate(self):
        self._owner()
        s.need(self._lock.acquire(blocking=False), "AUTHORITY_REFRESH_BUSY")
        try:
            yield
        except BaseException as error:
            if not isinstance(error, Exception):
                self._ready = False
                self.request_stop()
            raise
        finally:
            self._lock.release()

    def _running(self):
        s.need(not self._stop.is_set(), "AUTHORITY_REFRESH_STOP_REQUESTED")
        s.class_identity(self, sys.modules[__name__])
        s.class_identity(self._verifier, managed)
        s.need(self._verifier.source is self._source
               and self._source.configuration_id() == self._source_id,
               "AUTHORITY_CONFIGURATION_CHANGED")

    def _bad_clock(self):
        self._clock_failed, self._ready = True, False
        self._failure = "AUTHORITY_REFRESH_CLOCK_INVALID"
        raise s.AuthorityError(self._failure)

    def _now(self):
        if self._clock_failed:
            self._bad_clock()
        try:
            value = self._monotonic()
        except Exception:
            self._bad_clock()
        if not _finite(value) or value < 0 or (self._clock_high is not None and value < self._clock_high):
            self._bad_clock()
        self._clock_high = value
        return value

    def _deadline(self, now, interval):
        value = now + interval
        if not _finite(value) or value <= now:
            self._bad_clock()
        return value

    def _poll(self):
        # Preflight errors reject this call without changing the refresh schedule.
        # Clock failures and stop requests have their own latched state.
        self._running()
        now = self._now()
        if self._due is not None and now < self._due:
            return None
        # Close the local execution gate before cleanup, acquisition or install.
        # This does not depend on successfully marking the shared store unavailable.
        self._ready, self._due = False, None
        try:
            if self._fetch.cleanup_required:
                self._fetch.cleanup_pending()
            self._running()
            installed = self._source.refresh(self._fetch)
            self._revision = installed["revision"]
            self._running()
            self._due = self._deadline(self._now(), self._interval)
            self._failure = None
            self._ready = True
            return installed
        except BaseException as error:
            self._ready = False
            self._failure = (error.cause if type(error) is s.AuthorityError
                             else "AUTHORITY_REFRESH_FAILED")
            if isinstance(error, Exception) and not self._stop.is_set():
                self._due = self._deadline(self._now(), self._retry)
            else:
                # Cancellation is not an automatic retry request.
                self.request_stop()
            raise

    def poll(self):
        """Refresh if due; return installation metadata or None, and propagate failure."""
        with self._gate():
            return self._poll()

    def _accept_managed_call(self):
        # Passing this final check accepts the handoff. Stop uses the same lock;
        # neither configuration checks nor the managed call run while it is held.
        with self._entry_lock:
            s.need(not self._stop.is_set(), "AUTHORITY_REFRESH_STOP_REQUESTED")

    def _invoke(self, operation):
        with self._gate():
            self._poll()
            s.need(self._ready, "AUTHORITY_REFRESH_RETRY_WAIT")
            self._running()
            self._accept_managed_call()
            try:
                return operation()
            except BaseException as error:
                if not isinstance(error, Exception):
                    self._ready = False
                    self.request_stop()
                raise

    def admit(self, admission_request, *, original, evidence_artifacts, caller_proof,
              require_new_permit=False):
        return self._invoke(lambda: self._verifier.admit(admission_request, original=original,
            evidence_artifacts=evidence_artifacts, caller_proof=caller_proof,
            require_new_permit=require_new_permit))

    def restore_admission(self, request_id):
        return self._invoke(lambda: self._verifier.restore_admission(request_id))

    def dispatch(self, admission, *, caller_proof):
        return self._invoke(lambda: self._verifier.dispatch(admission, caller_proof=caller_proof))

    def dispatch_status(self, request_id):
        """Retained attempt history remains readable without refreshing, even after close."""
        with self._gate():
            return self._verifier.dispatch_status(request_id)

    def status(self):
        with self._gate():
            if self._stop.is_set() or self._clock_failed:
                phase = "stopped" if self._closed else "stop_requested" if self._stop.is_set() else "clock_failed"
                return RefreshStatus(phase, None, self._revision, self._failure)
            now = self._now()
            delay = max(0, self._due - now) if self._due is not None else 0
            phase = ("refresh_required" if delay == 0 else "refreshed" if self._ready else "retry_wait")
            return RefreshStatus(phase, delay, self._revision, self._failure)

    def request_stop(self):
        """Request cooperative stop; close() separately acknowledges local completion."""
        self._owner()
        with self._entry_lock:
            self._stop.set()

    def close(self):
        """Stop new calls and finish pending fetch cleanup; busy/failed cleanup raises."""
        self.request_stop()
        with self._gate():
            self._ready = False
            if self._fetch.cleanup_required:
                self._fetch.cleanup_pending()
            self._closed = True
