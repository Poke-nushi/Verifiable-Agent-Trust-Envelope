"""Narrow actor-signed purchase instructions under operator-selected authority."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import base64
import hashlib
from pathlib import Path
import re
import sys
from typing import Callable

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reference/runtime-jwt"))
import runtime_jwt as jwt

b = jwt.binding
a = b.caller_authority_module()
require = jwt.require
_source = Path(__file__).read_bytes()
LOADED_SOURCE_SHA256 = (hashlib.sha256(_source).hexdigest() if hasattr(sys, "_getframe")
    and sys._getframe().f_code == compile(_source, sys._getframe().f_code.co_filename,
        "exec", dont_inherit=True, optimize=sys.flags.optimize) else None)
del _source

PROFILE = "vate-caller-jwt-es256-v1"
TOKEN_TYPE = "vate-caller-proof+jwt"
CLAIM_FIELDS = {"iss", "sub", "aud", "iat", "nbf", "exp", "grant_id", "request_sha256", "original_sha256"}


@dataclass(frozen=True)
class DelegationGrant:
    """Trusted authority decision: principal permission AND delegation to actor."""

    grant_id: str
    principal: str
    actor: str
    kid: str
    public_key_spki: bytes
    runtime: str
    audience: str
    resource: str
    action: str
    currency: str
    max_amount: str
    tool_allowlist: tuple[str, ...]
    not_before: int
    expires_at: int
    revoked: bool = False


@dataclass(frozen=True)
class AuthorityPolicy:
    issued_at: int
    expires_at: int
    grants: tuple[DelegationGrant, ...]


class CallerJwtAuthorizer:
    # Own-class stamps survive a module reload without relabeling retained
    # old methods as the current implementation. Unstamped subclasses fail.
    _loaded_source_path = Path(__file__).resolve()
    _loaded_source_sha256 = LOADED_SOURCE_SHA256

    def __init__(self, *, expected_profile: str, authority_id: str,
                 node: str | Path, node_sha256: str,
                 authority_policy_provider: Callable[[], AuthorityPolicy],
                 max_token_age_seconds: int, max_policy_age_seconds: int,
                 timeout_seconds: float = 10.0):
        require(expected_profile == PROFILE and jwt.text(authority_id)
                and callable(authority_policy_provider) and jwt.positive_seconds(max_token_age_seconds)
                and jwt.positive_seconds(max_policy_age_seconds), "INVALID_CALLER_CONFIGURATION")
        self.authority_id = authority_id
        self.authority_policy_provider = authority_policy_provider
        self.max_token_age_seconds = max_token_age_seconds
        self.max_policy_age_seconds = max_policy_age_seconds
        self.backend = jwt.Es256Backend(node=node, node_sha256=node_sha256, timeout_seconds=timeout_seconds)
        self._configuration_id = self._identity()

    def _identity(self) -> str:
        require(vars(type(self)).get("_loaded_source_path") == Path(__file__).resolve()
                and vars(type(self)).get("_loaded_source_sha256") == LOADED_SOURCE_SHA256
                and type(self.backend) is jwt.Es256Backend
                and vars(type(self.backend)).get("_loaded_source_path") == Path(jwt.__file__).resolve()
                and vars(type(self.backend)).get("_loaded_source_sha256") == jwt.LOADED_SOURCE_SHA256,
                "CALLER_IMPLEMENTATION_CHANGED")
        sources = {}
        for module in (sys.modules[__name__], jwt):
            require(jwt.file_sha(Path(module.__file__)) == module.LOADED_SOURCE_SHA256,
                    "CALLER_IMPLEMENTATION_CHANGED")
            sources[str(Path(module.__file__).resolve().relative_to(ROOT))] = module.LOADED_SOURCE_SHA256
        return b.object_hash({"profile": PROFILE, "authority_id": self.authority_id,
            "max_token_age_seconds": self.max_token_age_seconds,
            "max_policy_age_seconds": self.max_policy_age_seconds, "sources": sources,
            "node": str(self.backend.node), "node_sha256": self.backend.node_sha256,
            "bridge": str(self.backend.bridge), "bridge_sha256": self.backend.bridge_sha256,
            "timeout_microseconds": int(self.backend.timeout * 1000000), "env": self.backend.env})

    def as_caller_authorizer(self) -> a.CallerAuthorityVerifier:
        require(self._identity() == self._configuration_id, "CALLER_CONFIGURATION_CHANGED")
        return a.CallerAuthorityVerifier(PROFILE, jwt.MEDIA_TYPE, self.max_token_age_seconds,
                                         self._configuration_id, self.verify)

    def _policy(self, now: datetime) -> tuple[AuthorityPolicy, bytes, datetime]:
        try:
            policy = self.authority_policy_provider()
        except Exception:
            raise jwt.RuntimeJwtError("AUTHORITY_POLICY_UNAVAILABLE") from None
        require(type(policy) is AuthorityPolicy and type(policy.grants) is tuple
                and len(policy.grants) <= 128, "INVALID_AUTHORITY_POLICY")
        issued, expires = jwt.numeric_date(policy.issued_at), jwt.numeric_date(policy.expires_at)
        require(issued < expires and issued <= now < expires, "AUTHORITY_POLICY_OUTSIDE_WINDOW")
        freshness = timedelta(seconds=self.max_policy_age_seconds)
        require(now - issued <= freshness, "AUTHORITY_POLICY_STALE")
        end = expires - timedelta(microseconds=1)
        deadline = end if freshness >= end - issued else issued + freshness
        ids, keys, serialized = set(), {}, []
        for grant in policy.grants:
            require(type(grant) is DelegationGrant and all(jwt.text(getattr(grant, key)) for key in
                ("grant_id", "principal", "actor", "kid", "runtime", "audience", "resource", "action"))
                and type(grant.public_key_spki) is bytes and len(grant.public_key_spki) == 91
                and grant.public_key_spki.startswith(jwt.SPKI_PREFIX) and type(grant.revoked) is bool
                and type(grant.tool_allowlist) is tuple and 0 < len(grant.tool_allowlist) <= 32
                and all(jwt.text(tool) for tool in grant.tool_allowlist)
                and len(set(grant.tool_allowlist)) == len(grant.tool_allowlist), "INVALID_AUTHORITY_POLICY")
            b.money({"currency": grant.currency, "value": grant.max_amount})
            require(jwt.numeric_date(grant.not_before) < jwt.numeric_date(grant.expires_at), "INVALID_AUTHORITY_POLICY")
            key_id = (grant.actor, grant.kid)
            require(grant.grant_id not in ids and keys.get(key_id, grant.public_key_spki) == grant.public_key_spki,
                    "AMBIGUOUS_AUTHORITY_POLICY")
            ids.add(grant.grant_id)
            keys[key_id] = grant.public_key_spki
            item = {key: value for key, value in vars(grant).items() if key not in ("public_key_spki", "tool_allowlist")}
            item.update(spki_base64=base64.b64encode(grant.public_key_spki).decode("ascii"),
                        tool_allowlist=list(grant.tool_allowlist))
            serialized.append(item)
        return policy, b.encode({"issued_at": policy.issued_at, "expires_at": policy.expires_at,
                                 "grants": serialized}), deadline

    def verify(self, raw: bytes, context: a.CallerAuthorityContext) -> a.AuthenticatedCallerClaims:
        require(self._identity() == self._configuration_id, "CALLER_CONFIGURATION_CHANGED")
        require(type(context) is a.CallerAuthorityContext and isinstance(context.now, datetime)
                and context.now.tzinfo is not None and context.now.utcoffset() is not None, "INVALID_CALLER_CONTEXT")
        now = context.now.astimezone(timezone.utc)
        original, request = b.decode(context.original), b.decode(context.admission_request)
        b.validate_operation(original)
        b.validate_admission(request, original)
        require(type(raw) is bytes and 0 < len(raw) <= jwt.MAX_TOKEN_BYTES, "INVALID_COMPACT_JWT")
        parts = raw.split(b".")
        require(len(parts) == 3, "INVALID_COMPACT_JWT")
        header = b.decode(jwt.decode_segment(parts[0], 4096))
        claims = b.decode(jwt.decode_segment(parts[1], jwt.MAX_TOKEN_BYTES))
        signature = jwt.decode_segment(parts[2], 64)
        require(len(signature) == 64, "INVALID_COMPACT_JWT")
        require(type(header) is dict and set(header) == jwt.HEADER_FIELDS and header["alg"] == "ES256"
                and header["typ"] == TOKEN_TYPE and jwt.text(header["kid"]), "UNSUPPORTED_JWT_HEADER")
        require(type(claims) is dict and set(claims) == CLAIM_FIELDS
                and all(jwt.text(claims[key]) for key in ("iss", "sub", "aud", "grant_id"))
                and all(type(claims[key]) is str and re.fullmatch(r"[0-9a-f]{64}", claims[key]) is not None
                        for key in ("request_sha256", "original_sha256")), "INVALID_JWT_CLAIMS")
        issued, start, end = (jwt.numeric_date(claims[key]) for key in ("iat", "nbf", "exp"))
        require(issued < end and start < end and issued <= now and start <= now < end, "TOKEN_OUTSIDE_WINDOW")
        require(now - issued <= timedelta(seconds=self.max_token_age_seconds), "TOKEN_STALE")
        require(claims["iss"] == claims["sub"] == request["actor"] and claims["aud"] == request["audience"]
                and claims["request_sha256"] == b.digest(context.admission_request)["value"]
                and claims["original_sha256"] == b.digest(context.original)["value"], "CALLER_REQUEST_MISMATCH")
        policy, snapshot, policy_deadline = self._policy(now)
        matches = [grant for grant in policy.grants if grant.grant_id == claims["grant_id"]]
        require(len(matches) == 1 and not matches[0].revoked, "DELEGATION_NOT_AUTHORIZED")
        grant = matches[0]
        require(all(getattr(grant, key) == request[key] for key in ("principal", "actor", "runtime", "audience", "action"))
                and grant.kid == header["kid"] and grant.resource == request["target"]["resource"],
                "DELEGATION_SCOPE_MISMATCH")
        cap, actual = original["constraints"]["max_amount"], original["payload"]["amount"]
        require(cap["currency"] == actual["currency"] == grant.currency
                and b.amount(actual["value"]) <= b.amount(cap["value"]) <= b.amount(grant.max_amount)
                and set(original["constraints"]["tool_allowlist"]) <= set(grant.tool_allowlist)
                and original["payload"]["tool"] in grant.tool_allowlist, "DELEGATION_CONSTRAINTS_EXCEEDED")
        grant_start, grant_end = jwt.numeric_date(grant.not_before), jwt.numeric_date(grant.expires_at)
        require(grant_start <= issued and grant_start <= now < grant_end, "GRANT_OUTSIDE_WINDOW")
        self.backend._signature(parts[0] + b"." + parts[1], signature, grant.public_key_spki)
        _, latest, _ = self._policy(now)
        require(latest == snapshot, "AUTHORITY_POLICY_CHANGED")
        require(self._identity() == self._configuration_id, "CALLER_CONFIGURATION_CHANGED")
        return a.AuthenticatedCallerClaims(b.digest(raw)["value"], claims["request_sha256"], claims["original_sha256"],
            grant.principal, grant.actor, grant.runtime, grant.audience, self.authority_id, grant.grant_id,
            b.core.iso(issued), b.core.iso(max(start, grant_start)),
            b.core.iso(min(end - timedelta(microseconds=1), grant_end - timedelta(microseconds=1), policy_deadline)))
