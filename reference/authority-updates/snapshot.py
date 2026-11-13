"""Authenticate complete runtime/caller policy snapshots from a selected authority."""
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
import base64
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reference/caller-authority"))
import caller_jwt as c

b, jwt = c.b, c.jwt
PROFILE = "vate-authority-snapshot-v1"
TOKEN_TYPE = "vate-authority-snapshot+jwt"
MAX_REVISION = 2**53 - 1
CLAIMS = {"iss", "aud", "scope", "epoch", "revision", "iat", "nbf", "exp", "runtime_grants", "delegation_grants"}
_source = Path(__file__).read_bytes()
LOADED_SOURCE_SHA256 = (hashlib.sha256(_source).hexdigest() if hasattr(sys, "_getframe")
    and sys._getframe().f_code == compile(_source, sys._getframe().f_code.co_filename,
        "exec", dont_inherit=True, optimize=sys.flags.optimize) else None)
del _source


class AuthorityError(ValueError):
    def __init__(self, cause: str):
        self.cause = cause
        super().__init__(cause)


def need(condition, cause):
    if not condition:
        raise AuthorityError(cause)


def module_identity(module) -> str:
    digest = jwt.file_sha(Path(module.__file__))
    need(digest == module.LOADED_SOURCE_SHA256, "AUTHORITY_IMPLEMENTATION_CHANGED")
    return digest


def class_identity(instance, module) -> None:
    need(vars(type(instance)).get("_loaded_source_path") == Path(module.__file__).resolve()
         and vars(type(instance)).get("_loaded_source_sha256") == module_identity(module),
         "AUTHORITY_IMPLEMENTATION_CHANGED")


def public_key(raw) -> bytes:
    need(type(raw) is str and len(raw) <= 128, "AUTHORITY_INVALID_KEY")
    try:
        key = base64.b64decode(raw, validate=True)
    except ValueError:
        raise AuthorityError("AUTHORITY_INVALID_KEY") from None
    need(base64.b64encode(key).decode("ascii") == raw and len(key) == 91
         and key.startswith(jwt.SPKI_PREFIX), "AUTHORITY_INVALID_KEY")
    return key


@dataclass(frozen=True)
class AuthoritySelection:
    issuer: str
    audience: str
    scope: str
    epoch: str
    kid: str
    public_key_spki: bytes
    minimum_revision: int
    max_snapshot_age_seconds: int

    def descriptor(self):
        need(type(self) is AuthoritySelection and all(jwt.text(getattr(self, key)) for key in
             ("issuer", "audience", "scope", "epoch", "kid"))
             and type(self.public_key_spki) is bytes and len(self.public_key_spki) == 91
             and self.public_key_spki.startswith(jwt.SPKI_PREFIX)
             and type(self.minimum_revision) is int and 1 <= self.minimum_revision <= MAX_REVISION
             and jwt.positive_seconds(self.max_snapshot_age_seconds), "AUTHORITY_SELECTION_INVALID")
        return {**{key: value for key, value in vars(self).items() if key != "public_key_spki"},
                "public_key_spki_base64": base64.b64encode(self.public_key_spki).decode("ascii")}


@dataclass(frozen=True)
class VerifiedSnapshot:
    raw: bytes
    payload: bytes
    revision: int
    issued_at: int
    not_before: int
    expires_at: int
    runtime_policy: jwt.RuntimeTrustPolicy
    authority_policy: c.AuthorityPolicy


def grant_from_json(value, cls):
    expected = {item.name for item in fields(cls)} - {"public_key_spki"} | {"public_key_spki_base64"}
    need(type(value) is dict and set(value) == expected, "AUTHORITY_GRANT_INVALID")
    kwargs = {key: item for key, item in value.items() if key != "public_key_spki_base64"}
    kwargs["public_key_spki"] = public_key(value["public_key_spki_base64"])
    if cls is c.DelegationGrant:
        need(type(kwargs["tool_allowlist"]) is list, "AUTHORITY_GRANT_INVALID")
        kwargs["tool_allowlist"] = tuple(kwargs["tool_allowlist"])
    return cls(**kwargs)


class SnapshotVerifier:
    _loaded_source_path = Path(__file__).resolve()
    _loaded_source_sha256 = LOADED_SOURCE_SHA256

    def __init__(self, *, expected_profile, selection, node, node_sha256, timeout_seconds=10.0):
        need(expected_profile == PROFILE and type(selection) is AuthoritySelection, "AUTHORITY_SELECTION_INVALID")
        selection.descriptor()
        self.selection = selection
        self.backend = jwt.Es256Backend(node=node, node_sha256=node_sha256, timeout_seconds=timeout_seconds)
        self._identity = self.configuration_id()

    def configuration_id(self):
        class_identity(self, sys.modules[__name__])
        need(type(self.backend) is jwt.Es256Backend, "AUTHORITY_IMPLEMENTATION_CHANGED")
        class_identity(self.backend, jwt)
        sources = {str(Path(module.__file__).resolve().relative_to(ROOT)): module_identity(module)
                   for module in (sys.modules[__name__], c, jwt)}
        return b.object_hash({"profile": PROFILE, "selection": self.selection.descriptor(), "sources": sources,
            "node": str(self.backend.node), "node_sha256": self.backend.node_sha256,
            "bridge": str(self.backend.bridge), "bridge_sha256": self.backend.bridge_sha256,
            "timeout_microseconds": int(self.backend.timeout * 1000000), "env": self.backend.env})

    def verify(self, raw: bytes, now: datetime) -> VerifiedSnapshot:
        need(self.configuration_id() == self._identity, "AUTHORITY_CONFIGURATION_CHANGED")
        need(isinstance(now, datetime) and now.tzinfo is not None and now.utcoffset() is not None,
             "AUTHORITY_CLOCK_INVALID")
        need(type(raw) is bytes and 0 < len(raw) <= jwt.MAX_TOKEN_BYTES, "AUTHORITY_TOKEN_INVALID")
        try:
            parts = raw.split(b".")
            need(len(parts) == 3, "AUTHORITY_TOKEN_INVALID")
            header = b.decode(jwt.decode_segment(parts[0], 4096))
            claims = b.decode(jwt.decode_segment(parts[1], jwt.MAX_TOKEN_BYTES))
            signature = jwt.decode_segment(parts[2], 64)
            need(type(header) is dict and set(header) == jwt.HEADER_FIELDS and header["alg"] == "ES256"
                 and header["typ"] == TOKEN_TYPE and header["kid"] == self.selection.kid and len(signature) == 64,
                 "AUTHORITY_HEADER_INVALID")
            need(type(claims) is dict and set(claims) == CLAIMS, "AUTHORITY_CLAIMS_INVALID")
            need(tuple(claims[key] for key in ("iss", "aud", "scope", "epoch")) ==
                 (self.selection.issuer, self.selection.audience, self.selection.scope, self.selection.epoch),
                 "AUTHORITY_CONTEXT_MISMATCH")
            need(type(claims["revision"]) is int and self.selection.minimum_revision <= claims["revision"] <= MAX_REVISION,
                 "AUTHORITY_REVISION_INVALID")
            issued, start, end = (jwt.numeric_date(claims[key]) for key in ("iat", "nbf", "exp"))
            need(issued < end and start < end and issued <= now and start <= now < end,
                 "AUTHORITY_OUTSIDE_WINDOW")
            need(now - issued <= timedelta(seconds=self.selection.max_snapshot_age_seconds), "AUTHORITY_STALE")
            need(type(claims["runtime_grants"]) is list and type(claims["delegation_grants"]) is list
                 and len(claims["runtime_grants"]) <= 128 and len(claims["delegation_grants"]) <= 128,
                 "AUTHORITY_GRANT_INVALID")
            runtime = jwt.RuntimeTrustPolicy(claims["iat"], claims["exp"], tuple(
                grant_from_json(value, jwt.RuntimeIssuerGrant) for value in claims["runtime_grants"]))
            authority = c.AuthorityPolicy(claims["iat"], claims["exp"], tuple(
                grant_from_json(value, c.DelegationGrant) for value in claims["delegation_grants"]))
            jwt.validate_policy(runtime, now, self.selection.max_snapshot_age_seconds)
            c.validate_policy(authority, now, self.selection.max_snapshot_age_seconds)
            self.backend._signature(parts[0] + b"." + parts[1], signature, self.selection.public_key_spki)
        except (jwt.RuntimeJwtError, b.Invalid, TypeError, KeyError):
            raise AuthorityError("AUTHORITY_VERIFICATION_FAILED") from None
        need(self.configuration_id() == self._identity, "AUTHORITY_CONFIGURATION_CHANGED")
        return VerifiedSnapshot(raw, b.encode(claims), claims["revision"], claims["iat"], claims["nbf"], claims["exp"],
                                runtime, authority)

    def check_window(self, value: VerifiedSnapshot, now: datetime):
        need(jwt.numeric_date(value.issued_at) <= now and jwt.numeric_date(value.not_before) <= now
             < jwt.numeric_date(value.expires_at), "AUTHORITY_OUTSIDE_WINDOW")
        need(now - jwt.numeric_date(value.issued_at) <= timedelta(seconds=self.selection.max_snapshot_age_seconds),
             "AUTHORITY_STALE")
