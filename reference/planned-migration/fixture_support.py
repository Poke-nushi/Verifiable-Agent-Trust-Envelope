"""Synthetic local fixture inputs for the explicitly selected program pair."""
import base64
from contextlib import ExitStack
from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reference/authority-issuer"))
from authority_issuer import s, b, c, jwt, grant_json
from fixture_signer import FixtureSigner
from run_native import fresh_purchase


class Fixture:
    def __init__(self, directory, *, source_root=ROOT, now=None, configure_authority=None):
        self.root, self.source = Path(directory).resolve(), Path(source_root).resolve()
        self.stack = ExitStack()
        self.node = Path(shutil.which("node")).resolve(strict=True)
        self.node_sha = jwt.file_sha(self.node)
        self.now = now or b.core.parse_time("2026-11-16T00:00:10Z")
        try:
            self.runtime, self.actor = [self.stack.enter_context(FixtureSigner(self.node, self.node_sha)) for _ in range(2)]
            self.old = self.root / "old"
            self.old.mkdir()
            self.purchases = {name: self.purchase("-" + name) for name in ("pending", "returned", "unknown", "denied")}
            if configure_authority is None:
                self.old_signer, self.new_signer = [self.stack.enter_context(FixtureSigner(self.node, self.node_sha)) for _ in range(2)]
                scope = "planned-migration-fixture"
            else:
                scope, self.old_signer, self.new_signer = configure_authority(self)
            self.selection = s.AuthoritySelection("urn:example:merchant-authority", "urn:example:verifier",
                scope, "epoch-1", "old-key", self.old_signer.public_key, 1, 120)
            self.new_selection = replace(self.selection, kid="new-key", public_key_spki=self.new_signer.public_key)
            self.policy = self.purchases["pending"]["policy"]
            self.base = {"selection": self.selection.descriptor(), "node": str(self.node),
                         "node_sha256": self.node_sha, "now": b.core.iso(self.now),
                         "directory": str(self.old), "policy": self.policy}
            self.anchors = self.worker({"action": "create"})["anchors"]
            self.base["anchors"] = self.anchors
            self.install(self.snapshot(1))
            self.history = {}
            for name, purchase in self.purchases.items():
                self.history[name] = self.worker({**purchase, "action": "admit",
                    "dispatch": name in ("returned", "unknown"),
                    "callback": "unknown" if name == "unknown" else "return",
                    "require_new_permit": name == "denied"})
            self.last_snapshot = self.snapshot(2, revoked=True)
            self.install(self.last_snapshot)
        except BaseException:
            self.close()
            raise

    def purchase(self, suffix, *, request_suffix="", order_padding=0, policy_padding=0):
        original, request, policy, token, proof = fresh_purchase(self.runtime, self.actor, self.now, suffix)
        if request_suffix or order_padding or policy_padding:
            value = b.decode(request)
            if policy_padding:
                policy["allowed_actions"].append("unused:" + "x" * policy_padding)
                for ref in value["evidence_refs"]:
                    if ref["type"] == "local_policy":
                        ref["digest"] = b.digest(b.encode(policy))
            if order_padding:
                operation = b.decode(original)
                operation["payload"]["order_id"] += "x" * order_padding
                original = b.encode(operation)
                value["input_hash"] = b.object_hash(operation)
            value["request_id"] += request_suffix
            value["evidence_refs"] = [r for r in value["evidence_refs"] if r["type"] != "runtime_attestation"]
            second = int((self.now - jwt.EPOCH).total_seconds())
            token = self.runtime({"alg": "ES256", "kid": "runtime-key", "typ": jwt.TOKEN_TYPE}, {
                "iss": "urn:example:runtime-issuer", "sub": value["runtime"], "aud": value["audience"],
                "iat": second, "nbf": second, "exp": second + 180,
                "vate_context_hash": b.runtime_context_hash(b.encode(value), original)})
            value["evidence_refs"].append({"type": "runtime_attestation", "uri": "urn:example:runtime-jwt",
                "media_type": jwt.MEDIA_TYPE, "digest": b.digest(token)})
            request = b.encode(value)
            proof = self.actor({"alg": "ES256", "kid": "actor-key", "typ": c.TOKEN_TYPE}, {
                "iss": value["actor"], "sub": value["actor"], "aud": value["audience"],
                "iat": second, "nbf": second, "exp": second + 180, "grant_id": "purchase-grant",
                "request_sha256": b.digest(request)["value"], "original_sha256": b.digest(original)["value"]})
        return {**{k: base64.b64encode(v).decode() for k, v in
            (("original", original), ("request", request), ("runtime_token", token), ("proof", proof))}, "policy": policy}

    def grants(self):
        request = b.decode(base64.b64decode(self.purchases["pending"]["request"]))
        second = int((self.now - jwt.EPOCH).total_seconds())
        runtime = jwt.RuntimeIssuerGrant("urn:example:runtime-issuer", "runtime-key", self.runtime.public_key,
            request["runtime"], request["audience"], second - 5, second + 240)
        grant = c.DelegationGrant("purchase-grant", request["principal"], request["actor"], "actor-key",
            self.actor.public_key, request["runtime"], request["audience"], request["target"]["resource"],
            request["action"], "USD", "120.00", ("merchant.checkout.confirm",), second - 5, second + 240)
        return runtime, grant

    def snapshot(self, revision, *, revoked=False, new=False):
        selection = self.new_selection if new else self.selection
        signer = self.new_signer if new else self.old_signer
        runtime, grant = self.grants()
        second = int((self.now - jwt.EPOCH).total_seconds())
        return signer({"alg": "ES256", "typ": s.TOKEN_TYPE, "kid": selection.kid}, {
            "iss": selection.issuer, "aud": selection.audience, "scope": selection.scope,
            "epoch": selection.epoch, "revision": revision, "iat": second, "nbf": second, "exp": second + 120,
            "runtime_grants": [grant_json(runtime)], "delegation_grants": [] if revoked else [grant_json(grant)]})

    def worker(self, job, *, target=False, succeeds=True):
        root = ROOT if target else self.source
        settings = self.target_base if target else self.base
        result = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).with_name("fixture_worker.py")), str(root)],
            input=b.encode({**settings, **job}), capture_output=True, timeout=30)
        try:
            value = json.loads(result.stdout)
        except (ValueError, UnicodeError):
            raise RuntimeError("Fixture worker did not return a bounded result") from None
        if bool(value["ok"]) != succeeds or bool(result.returncode == 0) != succeeds:
            raise RuntimeError("Unexpected fixture outcome: " + str(value.get("cause", "success")))
        return value["result"] if succeeds else value["cause"]

    def install(self, raw, *, target=False, succeeds=True):
        return self.worker({"action": "install", "snapshot": base64.b64encode(raw).decode()},
                           target=target, succeeds=succeeds)

    def close(self):
        self.stack.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
