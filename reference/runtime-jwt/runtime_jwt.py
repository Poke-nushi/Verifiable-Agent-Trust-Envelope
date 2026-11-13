"""Optional compact JWT/ES256 adapter for request-bound runtime evidence.

The application selects trust snapshots and the existing Node crypto backend.
This module implements the narrow contract in CONTRACT.md, not generic JOSE.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import math
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Callable

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reference/request-binding"))
import request_binding as binding

_source = None
try:
    _source = Path(__file__).read_bytes()
    LOADED_SOURCE_SHA256 = (hashlib.sha256(_source).hexdigest() if hasattr(sys, "_getframe")
        and sys._getframe().f_code == compile(_source, sys._getframe().f_code.co_filename,
            "exec", dont_inherit=True, optimize=sys.flags.optimize) else None)
except (OSError, SyntaxError, ValueError):
    # Import remains available; identity-dependent entry points reject None.
    LOADED_SOURCE_SHA256 = None
del _source

PROFILE = "vate-runtime-jwt-es256-v1"
TOKEN_TYPE = "vate-runtime-evidence+jwt"
MEDIA_TYPE = "application/jwt"
BACKEND_CONTRACT = "vate-runtime-es256-backend-v1"
MAX_TOKEN_BYTES = 64 * 1024
MAX_NUMERIC_DATE = 253402300799  # 9999-12-31T23:59:59Z
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
HEADER_FIELDS = {"alg", "kid", "typ"}
CLAIM_FIELDS = {"iss", "sub", "aud", "iat", "nbf", "exp", "vate_context_hash"}


class RuntimeJwtError(ValueError):
    """A stable local diagnostic; the admission core sanitizes adapter errors."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise RuntimeJwtError(code)


def text(value: object) -> bool:
    return (type(value) is str and 0 < len(value) <= 1024
            and not any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value))


def numeric_date(value: object) -> datetime:
    require(type(value) is int and 0 <= value <= MAX_NUMERIC_DATE, "INVALID_NUMERIC_DATE")
    return EPOCH + timedelta(seconds=value)


def positive_seconds(value: object) -> bool:
    return type(value) is int and 0 < value <= 2**31 - 1


def file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decode_segment(segment: bytes, limit: int) -> bytes:
    require(0 < len(segment) <= 4 * ((limit + 2) // 3)
            and re.fullmatch(rb"[A-Za-z0-9_-]+", segment) is not None, "INVALID_COMPACT_JWT")
    try:
        raw = base64.urlsafe_b64decode(segment + b"=" * (-len(segment) % 4))
    except ValueError:
        raise RuntimeJwtError("INVALID_COMPACT_JWT") from None
    require(len(raw) <= limit and base64.urlsafe_b64encode(raw).rstrip(b"=") == segment,
            "INVALID_COMPACT_JWT")
    return raw


@dataclass(frozen=True)
class RuntimeIssuerGrant:
    issuer: str
    kid: str
    public_key_spki: bytes
    runtime: str
    audience: str
    not_before: int
    expires_at: int
    revoked: bool = False


@dataclass(frozen=True)
class RuntimeTrustPolicy:
    """Application-controlled snapshot. All dates are integer NumericDates."""

    issued_at: int
    expires_at: int
    grants: tuple[RuntimeIssuerGrant, ...]


class Es256Backend:
    """Pinned local Node crypto bridge shared by the two explicit JWT profiles."""

    _loaded_source_path = Path(__file__).resolve()
    _loaded_source_sha256 = LOADED_SOURCE_SHA256

    def __init__(self, *, node: str | Path, node_sha256: str,
                 timeout_seconds: float = 10.0):
        require(type(timeout_seconds) in (int, float) and math.isfinite(timeout_seconds)
                and 0 < timeout_seconds <= 60
                and type(node_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", node_sha256) is not None,
                "INVALID_CONFIGURATION")
        try:
            selected = Path(node)
            require(selected.is_absolute(), "INVALID_CONFIGURATION")
            self.node = selected.resolve(strict=True)
            self.bridge = Path(__file__).with_name("verify_es256.mjs")
            self.bridge_sha256 = file_sha(self.bridge)
        except (OSError, TypeError, ValueError, RuntimeError):
            raise RuntimeJwtError("BACKEND_UNAVAILABLE") from None
        self.node_sha256 = node_sha256
        self.timeout = timeout_seconds
        # Never inherit NODE_OPTIONS, preload hooks, or user OpenSSL settings.
        self.env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "OPENSSL_CONF": os.devnull}
        self._check_backend()
        version = self._process(["--version"])
        match = re.fullmatch(rb"v([0-9]+)\.[0-9]+\.[0-9]+\r?\n", version.stdout)
        require(version.returncode == 0 and not version.stderr and match is not None
                and int(match[1]) >= 22, "UNSUPPORTED_BACKEND")

    def _check_backend(self) -> None:
        try:
            require(self.node.is_file() and os.access(self.node, os.X_OK)
                    and file_sha(self.node) == self.node_sha256
                    and file_sha(self.bridge) == self.bridge_sha256, "BACKEND_CHANGED")
        except OSError:
            raise RuntimeJwtError("BACKEND_UNAVAILABLE") from None

    def _process(self, args: list[str], raw: bytes | None = None) -> subprocess.CompletedProcess:
        try:
            return subprocess.run([str(self.node), *args], input=raw, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=self.env, timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired:
            raise RuntimeJwtError("BACKEND_TIMEOUT") from None
        except OSError:
            raise RuntimeJwtError("BACKEND_UNAVAILABLE") from None

    def _signature(self, signing_input: bytes, signature: bytes, key: bytes) -> None:
        raw = binding.encode({"contract": BACKEND_CONTRACT,
            "signing_input_base64": base64.b64encode(signing_input).decode("ascii"),
            "signature_base64": base64.b64encode(signature).decode("ascii"),
            "spki_base64": base64.b64encode(key).decode("ascii")})
        self._check_backend()
        completed = self._process([str(self.bridge)], raw)
        self._check_backend()
        require(completed.returncode == 0 and not completed.stderr and len(completed.stdout) <= 2048,
                "BACKEND_FAILED")
        try:
            result = binding.decode(completed.stdout)
        except binding.Invalid:
            raise RuntimeJwtError("BACKEND_FAILED") from None
        require(type(result) is dict and set(result) == {"contract", "request_sha256", "verified"}
                and result["contract"] == BACKEND_CONTRACT
                and result["request_sha256"] == hashlib.sha256(raw).hexdigest()
                and type(result["verified"]) is bool, "BACKEND_FAILED")
        require(result["verified"], "INVALID_SIGNATURE")



def validate_policy(policy: RuntimeTrustPolicy, now: datetime, max_policy_age_seconds: int):
    """Validate an application-selected snapshot without fetching or signing it."""
    require(type(policy) is RuntimeTrustPolicy and type(policy.grants) is tuple
            and len(policy.grants) <= 128, "INVALID_TRUST_POLICY")
    issued, expires = numeric_date(policy.issued_at), numeric_date(policy.expires_at)
    require(issued < expires and issued <= now < expires, "TRUST_POLICY_OUTSIDE_WINDOW")
    freshness = timedelta(seconds=max_policy_age_seconds)
    require(now - issued <= freshness, "TRUST_POLICY_STALE")
    validity_end = expires - timedelta(microseconds=1)
    deadline = validity_end if freshness >= validity_end - issued else issued + freshness
    identities, keys, serialized = set(), {}, []
    for grant in policy.grants:
        require(type(grant) is RuntimeIssuerGrant and all(text(value) for value in
            (grant.issuer, grant.kid, grant.runtime, grant.audience))
            and type(grant.public_key_spki) is bytes and len(grant.public_key_spki) == 91
            and grant.public_key_spki.startswith(SPKI_PREFIX) and type(grant.revoked) is bool,
            "INVALID_TRUST_POLICY")
        require(numeric_date(grant.not_before) < numeric_date(grant.expires_at), "INVALID_TRUST_POLICY")
        identity = (grant.issuer, grant.kid, grant.runtime, grant.audience)
        key_id = (grant.issuer, grant.kid)
        require(identity not in identities and keys.get(key_id, grant.public_key_spki) == grant.public_key_spki,
                "AMBIGUOUS_TRUST_POLICY")
        identities.add(identity)
        keys[key_id] = grant.public_key_spki
        serialized.append({"issuer": grant.issuer, "kid": grant.kid, "runtime": grant.runtime,
            "audience": grant.audience, "spki_base64": base64.b64encode(grant.public_key_spki).decode("ascii"),
            "not_before": grant.not_before, "expires_at": grant.expires_at, "revoked": grant.revoked})
    snapshot = binding.encode({"issued_at": policy.issued_at, "expires_at": policy.expires_at, "grants": serialized})
    return policy, snapshot, deadline


class RuntimeJwtVerifier(Es256Backend):
    def __init__(self, *, expected_profile: str, node: str | Path, node_sha256: str,
                 trust_policy_provider: Callable[[], RuntimeTrustPolicy],
                 max_token_age_seconds: int, max_policy_age_seconds: int,
                 timeout_seconds: float = 10.0):
        require(expected_profile == PROFILE and callable(trust_policy_provider)
                and positive_seconds(max_token_age_seconds) and positive_seconds(max_policy_age_seconds),
                "INVALID_CONFIGURATION")
        self.trust_policy_provider = trust_policy_provider
        self.max_token_age_seconds = max_token_age_seconds
        self.max_policy_age_seconds = max_policy_age_seconds
        super().__init__(node=node, node_sha256=node_sha256, timeout_seconds=timeout_seconds)

    def as_runtime_verifier(self) -> binding.RuntimeEvidenceVerifier:
        return binding.RuntimeEvidenceVerifier(method=PROFILE, media_type=MEDIA_TYPE,
            max_age_seconds=self.max_token_age_seconds, verify=self.verify)

    def _policy(self, now: datetime) -> tuple[RuntimeTrustPolicy, bytes, datetime]:
        try:
            policy = self.trust_policy_provider()
        except Exception:
            raise RuntimeJwtError("TRUST_POLICY_UNAVAILABLE") from None
        return validate_policy(policy, now, self.max_policy_age_seconds)

    def verify(self, raw: bytes, context: binding.RuntimeEvidenceContext) -> binding.AuthenticatedRuntimeClaims:
        require(type(raw) is bytes and 0 < len(raw) <= MAX_TOKEN_BYTES, "INVALID_COMPACT_JWT")
        require(type(context) is binding.RuntimeEvidenceContext and isinstance(context.now, datetime)
                and context.now.tzinfo is not None and context.now.utcoffset() is not None, "INVALID_CONTEXT")
        now = context.now.astimezone(timezone.utc)
        parts = raw.split(b".")
        require(len(parts) == 3, "INVALID_COMPACT_JWT")
        try:
            header = binding.decode(decode_segment(parts[0], 4096))
            claims = binding.decode(decode_segment(parts[1], MAX_TOKEN_BYTES))
        except binding.Invalid:
            raise RuntimeJwtError("INVALID_JWT_JSON") from None
        signature = decode_segment(parts[2], 64)
        require(len(signature) == 64, "INVALID_COMPACT_JWT")
        require(type(header) is dict and set(header) == HEADER_FIELDS and header["alg"] == "ES256"
                and header["typ"] == TOKEN_TYPE and text(header["kid"]), "UNSUPPORTED_JWT_HEADER")
        require(type(claims) is dict and set(claims) == CLAIM_FIELDS
                and all(text(claims[k]) for k in ("iss", "sub", "aud", "vate_context_hash"))
                and re.fullmatch(r"sha-256:[0-9a-f]{64}", claims["vate_context_hash"]) is not None,
                "INVALID_JWT_CLAIMS")
        issued, not_before, expires = (numeric_date(claims[k]) for k in ("iat", "nbf", "exp"))
        require(issued < expires and not_before < expires and issued <= now and not_before <= now < expires,
                "TOKEN_OUTSIDE_WINDOW")
        require(now - issued <= timedelta(seconds=self.max_token_age_seconds), "TOKEN_STALE")
        policy, snapshot, policy_deadline = self._policy(now)
        matches = [grant for grant in policy.grants if (grant.issuer, grant.kid, grant.runtime, grant.audience)
                   == (claims["iss"], header["kid"], claims["sub"], claims["aud"])]
        require(len(matches) == 1 and not matches[0].revoked, "ISSUER_NOT_AUTHORIZED")
        grant = matches[0]
        grant_start, grant_end = numeric_date(grant.not_before), numeric_date(grant.expires_at)
        require(grant_start <= issued and grant_start <= now < grant_end, "GRANT_OUTSIDE_WINDOW")
        self._signature(parts[0] + b"." + parts[1], signature, grant.public_key_spki)
        # Do not accept a trust change observed while the crypto backend ran.
        _, latest, _ = self._policy(now)
        require(latest == snapshot, "TRUST_POLICY_CHANGED")
        require(claims["sub"] == context.runtime and claims["aud"] == context.audience
                and claims["vate_context_hash"] == context.context_hash, "REQUEST_CONTEXT_MISMATCH")
        deadline = min(expires - timedelta(microseconds=1), grant_end - timedelta(microseconds=1), policy_deadline)
        return binding.AuthenticatedRuntimeClaims(
            artifact_sha256=hashlib.sha256(raw).hexdigest(), context_hash=claims["vate_context_hash"],
            runtime=claims["sub"], audience=claims["aud"], issuer=claims["iss"],
            issued_at=binding.core.iso(issued), not_before=binding.core.iso(max(not_before, grant_start)),
            valid_until=binding.core.iso(deadline))
