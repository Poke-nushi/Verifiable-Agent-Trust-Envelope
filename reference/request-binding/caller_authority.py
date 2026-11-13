"""Application-selected authentication and authorization of an exact instruction.

The adapter must verify the actor's proof and independent principal permission
and delegation. These typed results are local adapter output, not received JSON.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
from pathlib import Path
import sys
from typing import Callable

import request_binding as b

_source = Path(__file__).read_bytes()
LOADED_SOURCE_SHA256 = (hashlib.sha256(_source).hexdigest() if hasattr(sys, "_getframe")
    and sys._getframe().f_code == compile(_source, sys._getframe().f_code.co_filename,
        "exec", dont_inherit=True, optimize=sys.flags.optimize) else None)
del _source

CONTRACT = "vate-caller-authorization-v1"


@dataclass(frozen=True)
class CallerAuthorityContext:
    admission_request: bytes
    original: bytes
    now: datetime


@dataclass(frozen=True)
class AuthenticatedCallerClaims:
    proof_sha256: str
    request_sha256: str
    original_sha256: str
    principal: str
    actor: str
    runtime: str
    audience: str
    authority_id: str
    grant_id: str
    issued_at: str
    not_before: str
    valid_until: str


@dataclass(frozen=True)
class CallerAuthorityVerifier:
    method: str
    media_type: str
    max_age_seconds: int
    configuration_id: str
    verify: Callable[[bytes, CallerAuthorityContext], AuthenticatedCallerClaims]


def descriptor(adapter: CallerAuthorityVerifier) -> dict:
    b.need(type(adapter) is CallerAuthorityVerifier, "INVALID_CALLER_AUTHORIZER")
    b.need(all(type(value) is str and 0 < len(value) <= 1024 for value in
        (adapter.method, adapter.media_type, adapter.configuration_id))
        and type(adapter.max_age_seconds) is int and 0 < adapter.max_age_seconds <= 2**31 - 1
        and callable(adapter.verify), "INVALID_CALLER_AUTHORIZER")
    return {"method": adapter.method, "media_type": adapter.media_type,
            "max_age_seconds": adapter.max_age_seconds, "configuration_id": adapter.configuration_id}


def verify(adapter: CallerAuthorityVerifier, raw: bytes, admission: bytes,
           original: bytes, now: datetime) -> dict:
    descriptor(adapter)
    b.need(type(raw) is bytes and 0 < len(raw) <= b.MAX_BYTES, "CALLER_PROOF_REQUIRED")
    request = b.decode(admission)
    context = CallerAuthorityContext(admission, original, now)
    try:
        claims = adapter.verify(raw, context)
    except Exception:
        raise b.Invalid("CALLER_AUTHORIZATION_FAILED") from None
    b.need(type(claims) is AuthenticatedCallerClaims, "INVALID_CALLER_AUTHORIZATION_RESULT")
    b.need(all(type(value) is str and 0 < len(value) <= 1024 for value in vars(claims).values()),
           "INVALID_CALLER_AUTHORIZATION_RESULT")
    b.need((claims.proof_sha256, claims.request_sha256, claims.original_sha256) ==
           tuple(b.digest(value)["value"] for value in (raw, admission, original)),
           "CALLER_AUTHORIZATION_DIGEST_MISMATCH")
    b.need(all(getattr(claims, key) == request[key] for key in
               ("principal", "actor", "runtime", "audience")), "CALLER_AUTHORIZATION_SUBJECT_MISMATCH")
    issued, start, end = (b.core.safe_parse_time(value) for value in
                         (claims.issued_at, claims.not_before, claims.valid_until))
    b.need(issued is not None and start is not None and end is not None
           and issued <= end and start <= end, "INVALID_CALLER_AUTHORIZATION_WINDOW")
    b.need(issued <= now and start <= now <= end, "CALLER_AUTHORIZATION_OUTSIDE_WINDOW")
    freshness = timedelta(seconds=adapter.max_age_seconds)
    b.need(now - issued <= freshness, "CALLER_AUTHORIZATION_STALE")
    deadline = end if freshness >= end - issued else issued + freshness
    proof_ref = {**b.reference(raw), "media_type": adapter.media_type}
    return {"contract": CONTRACT, "proof_ref": proof_ref,
        "admission_request_ref": b.reference(admission), "original_ref": b.reference(original),
        **{key: getattr(claims, key) for key in ("principal", "actor", "runtime", "audience",
            "authority_id", "grant_id", "issued_at", "not_before", "valid_until")},
        "usable_until": b.core.iso(deadline), "max_age_seconds": adapter.max_age_seconds,
        "verification": {"result": "verified", "checked_at": b.core.iso(now), "method": adapter.method}}
