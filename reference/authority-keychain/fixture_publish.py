"""Fresh-process test fixture: real issuer/store/signature, simulated IAM responses."""
import base64
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import sys

from keychain_signer import KeychainSigner, PROFILE, ROOT, s, b, jwt
sys.path.insert(0, str(ROOT / "reference/authority-issuer"))
from authority_issuer import AuthorityIssuer, Registration, MODEL, selected_scope, c
from authority_store import AuthorityStore


class FixtureService:
    def __init__(self, response, base):
        self.response, self.base = response, base

    def descriptor(self):
        return {"base_url": self.base, "development_loopback": False}

    def request(self, path, **_options):
        if "/authorization-models/" in path:
            return {"authorization_model": {"id": "fixture-model", **MODEL}}
        return self.response


def context(config, second, allowed):
    public = base64.b64decode(config["public_key_spki_base64"], validate=True)
    start = int((b.core.parse_time("2026-11-14T00:00:00Z") - jwt.EPOCH).total_seconds())
    oauth = FixtureService({"active": True, "iss": "https://auth.example/", "sub": "alice", "client_id": "agent",
        "token_use": "access_token", "aud": ["purchase-api"], "iat": start - 10,
        "exp": start + 300, "scope": "purchase.execute"}, "https://auth-admin.example")
    pdp = FixtureService({"allowed": allowed}, "https://pdp.example")
    runtime = jwt.RuntimeIssuerGrant("runtime-issuer", "runtime-key", public, "runtime", "vate-audience",
                                    start - 60, start + 600)
    grant = c.DelegationGrant("grant", "principal", "actor", "actor-key", public, "runtime", "vate-audience",
        "resource", "commerce.purchase", "USD", "120.00", ("checkout",), start - 60, start + 600)
    registration = Registration("https://auth.example/", "purchase-api", "alice", "agent", "fixture-store",
                                "fixture-model", "user:alice", "purchase:order", runtime, grant)
    selection = s.AuthoritySelection("authority", "verifier", selected_scope(registration, oauth, pdp, 30),
                                     "epoch1", "authority-key", public, 1, 30)
    verifier = s.SnapshotVerifier(expected_profile=s.PROFILE, selection=selection,
                                 node=config["node"], node_sha256=config["node_sha256"])
    signer = KeychainSigner(expected_profile=PROFILE, helper=config["helper"], helper_sha256=config["helper_sha256"],
        keychain=config["keychain"], application_tag=config["application_tag"], selection=selection)
    return registration, oauth, pdp, selection, verifier, signer, jwt.EPOCH + timedelta(seconds=second)


def main():
    config_path, mode, second = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
    config = json.loads(config_path.read_text())
    registration, oauth, pdp, selection, verifier, signer, now = context(config, second, mode in ("create", "permit"))
    anchor_path = config_path.with_name("issuer-anchor.json")
    if mode == "create":
        state = AuthorityStore.create(config["store"], verifier=verifier, clock=lambda: now)
        # Public anchor, separated from the store; never regenerate it on reopen.
        with anchor_path.open("xb") as handle:
            handle.write(state.anchor)
    else:
        state = AuthorityStore(config["store"], verifier=verifier,
                               expected_anchor=anchor_path.read_bytes(), clock=lambda: now)
    result = {"pid": os.getpid(), "public_key_sha256": hashlib.sha256(selection.public_key_spki).hexdigest()}
    if mode == "inspect":
        result["status"] = state.status()
        if not result["status"]["unavailable"]:
            with state.lease():
                result["delegation_count"] = len(state.authority_policy().grants)
    else:
        issuer = AuthorityIssuer(registration=registration, oauth=oauth, pdp=pdp, state=state,
                                  token_provider=lambda: "fixture-only-token", signer=signer)
        try:
            raw = issuer.publish()
            claims = b.decode(jwt.decode_segment(raw.split(b".")[1], jwt.MAX_TOKEN_BYTES))
            result.update(published=True, delegation_count=len(claims["delegation_grants"]),
                          token_base64=base64.b64encode(raw).decode("ascii"))
        except s.AuthorityError as error:
            result.update(published=False, cause=error.cause)
        result["status"] = state.status()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
