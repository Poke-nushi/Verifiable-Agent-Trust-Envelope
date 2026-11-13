"""One selected Hydra/OpenFGA registration to complete signed VATE snapshots."""
from dataclasses import dataclass, replace
import base64
import re
import threading

from service_client import JsonService, s
from authority_store import AuthorityStore

b, c, jwt = s.b, s.c, s.jwt
PROFILE = "vate-hydra-openfga-authority-issuer-v1"
MODEL = {"schema_version": "1.1", "type_definitions": [
    {"type": "user"},
    {"type": "purchase", "relations": {
        "user_permission": {"this": {}}, "delegation": {"this": {}},
        "can_execute": {"intersection": {"child": [
            {"computedUserset": {"relation": "user_permission"}},
            {"computedUserset": {"relation": "delegation"}}]}}},
     "metadata": {"relations": {
         "user_permission": {"directly_related_user_types": [{"type": "user"}]},
         "delegation": {"directly_related_user_types": [{"type": "user"}]}}}}
]}


def grant_json(grant):
    result = dict(vars(grant))
    result["public_key_spki_base64"] = base64.b64encode(result.pop("public_key_spki")).decode("ascii")
    if "tool_allowlist" in result:
        result["tool_allowlist"] = list(result["tool_allowlist"])
    return result


def model_identity(value):
    """Fill protobuf JSON defaults at known locations; retain all other fields."""
    value = b.decode(b.encode(value))
    s.need(type(value) is dict and set(value) <= {"schema_version", "type_definitions", "conditions"}
           and type(value.get("type_definitions")) is list, "ISSUER_MODEL_MISMATCH")
    value.setdefault("conditions", {})
    def usersets(node):
        if type(node) is dict:
            for key, child in node.items():
                if key in ("computedUserset", "tupleset") and type(child) is dict:
                    child.setdefault("object", "")
                usersets(child)
        elif type(node) is list:
            for child in node:
                usersets(child)
    for definition in value["type_definitions"]:
        s.need(type(definition) is dict, "ISSUER_MODEL_MISMATCH")
        definition.setdefault("relations", {})
        definition.setdefault("metadata", {})
        if definition["metadata"] is None:
            definition["metadata"] = {}
        metadata = definition["metadata"]
        s.need(type(metadata) is dict, "ISSUER_MODEL_MISMATCH")
        metadata.setdefault("relations", {})
        metadata.setdefault("module", "")
        metadata.setdefault("source_info", None)
        s.need(type(metadata["relations"]) is dict, "ISSUER_MODEL_MISMATCH")
        for relation in metadata["relations"].values():
            s.need(type(relation) is dict, "ISSUER_MODEL_MISMATCH")
            relation.setdefault("module", "")
            relation.setdefault("source_info", None)
            for reference in relation.get("directly_related_user_types", []):
                s.need(type(reference) is dict, "ISSUER_MODEL_MISMATCH")
                reference.setdefault("condition", "")
        usersets(definition["relations"])
    return b.object_hash(value)


@dataclass(frozen=True)
class Registration:
    oauth_issuer: str
    oauth_audience: str
    oauth_subject: str
    oauth_client: str
    store_id: str
    model_id: str
    fga_user: str
    fga_object: str
    runtime_grant: jwt.RuntimeIssuerGrant
    delegation_grant: c.DelegationGrant

    def descriptor(self):
        s.need(type(self) is Registration and all(jwt.text(getattr(self, field)) for field in
            ("oauth_issuer", "oauth_audience", "oauth_subject", "oauth_client", "fga_user", "fga_object"))
            and all(type(getattr(self, field)) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", getattr(self, field))
                    for field in ("store_id", "model_id"))
            and self.fga_user.startswith("user:") and self.fga_object.startswith("purchase:"),
            "ISSUER_REGISTRATION_INVALID")
        r, g = self.runtime_grant, self.delegation_grant
        s.need(type(r) is jwt.RuntimeIssuerGrant and type(g) is c.DelegationGrant
               and (r.runtime, r.audience) == (g.runtime, g.audience)
               and not r.revoked and not g.revoked, "ISSUER_REGISTRATION_INVALID")
        # Existing grant validators also validate amounts, keys and exact field types.
        now = jwt.numeric_date(max(r.not_before, g.not_before))
        issued = int((now - jwt.EPOCH).total_seconds())
        try:
            jwt.validate_policy(jwt.RuntimeTrustPolicy(issued, issued + 1, (r,)), now, 1)
            c.validate_policy(c.AuthorityPolicy(issued, issued + 1, (g,)), now, 1)
        except (jwt.RuntimeJwtError, b.Invalid):
            raise s.AuthorityError("ISSUER_REGISTRATION_INVALID") from None
        return {**{key: value for key, value in vars(self).items()
                   if key not in ("runtime_grant", "delegation_grant")},
                "runtime_grant": grant_json(r), "delegation_grant": grant_json(g)}


def selected_scope(registration, oauth, pdp, ttl_seconds):
    s.need(type(ttl_seconds) is int and 1 <= ttl_seconds <= 300, "ISSUER_TTL_INVALID")
    return "urn:vate:authority-registration:" + b.object_hash({"profile": PROFILE,
        "registration": registration.descriptor(), "oauth": oauth.descriptor(), "pdp": pdp.descriptor(),
        "model_sha256": model_identity(MODEL), "ttl_seconds": ttl_seconds})


class AuthorityIssuer:
    """No token cache. One application-selected token provider and signer per scope.

    The separate AuthorityStore is the issuer's revision/clock ledger; it is not
    the recipient store. A failed poll publishes nothing. Recipients must mark
    delivery failures unavailable and enforce their own freshness limit.
    """

    def __init__(self, *, registration, oauth, pdp, state, token_provider, signer, ttl_seconds=30):
        s.need(type(state) is AuthorityStore and callable(token_provider) and callable(signer),
               "ISSUER_CONFIGURATION_INVALID")
        self.registration, self.oauth, self.pdp = registration, oauth, pdp
        self.state, self.token_provider, self.signer, self.ttl_seconds = state, token_provider, signer, ttl_seconds
        self._scope = selected_scope(registration, oauth, pdp, ttl_seconds)
        s.need(state.verifier.selection.scope == self._scope, "ISSUER_REGISTRATION_MISMATCH")
        s.need(ttl_seconds <= state.verifier.selection.max_snapshot_age_seconds, "ISSUER_TTL_INVALID")
        self._lock = threading.Lock()

    def _observe(self, start):
        registration = self.registration
        token = self.token_provider()
        s.need(type(token) is str and 0 < len(token) <= 16384
               and all(32 < ord(ch) < 127 for ch in token), "ISSUER_TOKEN_INVALID")
        auth = self.oauth.request("/admin/oauth2/introspect", form={"token": token})
        s.need(type(auth) is dict and type(auth.get("active")) is bool, "ISSUER_INTROSPECTION_INVALID")
        if auth["active"] is False:
            return None, None
        s.need(all(auth.get(key) == expected for key, expected in (
            ("iss", registration.oauth_issuer), ("sub", registration.oauth_subject),
            ("client_id", registration.oauth_client), ("token_use", "access_token")))
            and auth.get("aud") == [registration.oauth_audience], "ISSUER_TOKEN_CONTEXT_MISMATCH")
        try:
            issued, expires = jwt.numeric_date(auth["iat"]), jwt.numeric_date(auth["exp"])
            not_before = jwt.numeric_date(auth.get("nbf", auth["iat"]))
        except (KeyError, jwt.RuntimeJwtError):
            raise s.AuthorityError("ISSUER_TOKEN_TIME_INVALID") from None
        s.need(issued <= start < expires and not_before <= start and issued < expires
               and not_before < expires, "ISSUER_TOKEN_TIME_INVALID")
        prefix = "/stores/" + registration.store_id
        response = self.pdp.request(prefix + "/authorization-models/" + registration.model_id)
        s.need(type(response) is dict and set(response) == {"authorization_model"}
               and type(response["authorization_model"]) is dict, "ISSUER_MODEL_MISMATCH")
        model = dict(response["authorization_model"])
        s.need(model.pop("id", None) == registration.model_id
               and model_identity(model) == model_identity(MODEL), "ISSUER_MODEL_MISMATCH")
        decision = self.pdp.request(prefix + "/check", body={
            "authorization_model_id": registration.model_id, "consistency": "HIGHER_CONSISTENCY",
            "tuple_key": {"user": registration.fga_user, "relation": "can_execute", "object": registration.fga_object}})
        s.need(type(decision) is dict and set(decision) <= {"allowed", "resolution"}
               and type(decision.get("allowed")) is bool, "ISSUER_DECISION_INVALID")
        if not decision["allowed"]:
            return None, None
        grant = replace(registration.delegation_grant,
            not_before=max(registration.delegation_grant.not_before, auth["iat"], auth.get("nbf", auth["iat"])),
            expires_at=min(registration.delegation_grant.expires_at, auth["exp"]))
        if not grant.not_before <= int((start - jwt.EPOCH).total_seconds()) < grant.expires_at:
            return None, None
        return grant, auth["exp"]

    def publish(self):
        s.need(self._lock.acquire(blocking=False), "ISSUER_BUSY")
        try:
            self.state.mark_unavailable()
            status = self.state.status()
            start = b.core.parse_time(status["clock_high"])
            s.need(selected_scope(self.registration, self.oauth, self.pdp, self.ttl_seconds) == self._scope,
                   "ISSUER_REGISTRATION_MISMATCH")
            grant, token_expiry = self._observe(start)
            issued = int((start - jwt.EPOCH).total_seconds())
            expiry = issued + self.ttl_seconds
            if token_expiry is not None:
                expiry = min(expiry, token_expiry)
            selection = self.state.verifier.selection
            claims = {"iss": selection.issuer, "aud": selection.audience, "scope": selection.scope,
                "epoch": selection.epoch, "revision": max(selection.minimum_revision, status["revision"] + 1),
                "iat": issued, "nbf": issued, "exp": expiry,
                "runtime_grants": [grant_json(self.registration.runtime_grant)],
                "delegation_grants": [] if grant is None else [grant_json(grant)]}
            s.need(claims["revision"] <= s.MAX_REVISION, "ISSUER_REVISION_EXHAUSTED")
            expected_payload = b.encode(claims)
            raw = self.signer({"alg": "ES256", "typ": s.TOKEN_TYPE, "kid": selection.kid}, claims)
            s.need(type(raw) is bytes and 0 < len(raw) <= jwt.MAX_TOKEN_BYTES, "ISSUER_SIGNER_MISMATCH")
            parts = raw.split(b".")
            s.need(len(parts) == 3 and b.encode(b.decode(jwt.decode_segment(parts[1], jwt.MAX_TOKEN_BYTES)))
                   == expected_payload, "ISSUER_SIGNER_MISMATCH")
            s.need(selected_scope(self.registration, self.oauth, self.pdp, self.ttl_seconds) == self._scope,
                   "ISSUER_REGISTRATION_MISMATCH")
            # accept observes the clock again after all IO/signing; no delayed
            # signing can mint a later observation time or renew this expiry.
            self.state.accept(raw)
            return raw
        except Exception:
            try:
                self.state.mark_unavailable()
            except Exception:
                pass
            # Source callbacks may contain secrets in their exception text.
            raise s.AuthorityError("ISSUER_PUBLICATION_FAILED") from None
        finally:
            self._lock.release()
