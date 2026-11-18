"""Synthetic owner/authority/runtime fixtures. Temporary keys only; never Keychain."""
from pathlib import Path
import uuid

from dependencies import fixture_crypto, crypto, original_admission
from handoff_contract import (Context, PROFILE, PROOF_TYP, STATUS_TYP, OBS_TYP, encode, decode, sha, b64,
                              iso, make_authorization, source_pins)
from handoff_provider import Provider, initialize

BASE = 1792886400  # fixed fixture clock, not trusted real-world time


class Clock:
    def __init__(self, value=BASE):
        self.value = value

    def __call__(self):
        return self.value


class Keys:
    def __init__(self, path):
        self.items = {role: fixture_crypto.generate_keypair(Path(path), "synthetic-" + role)
                      for role in ("runtime-a", "runtime-b", "authority")}
        for v in self.items.values():
            v["private_key"].chmod(0o600)

    def sign(self, payload, role, typ):
        header = {"alg": "ES256", "typ": typ, "kid": "synthetic-local-key"}
        data = (crypto.url64(encode(header)) + "." + crypto.url64(encode(payload))).encode("ascii")
        signature = fixture_crypto.der_to_raw_ecdsa(fixture_crypto.sign_bytes(data, self.items[role]["private_key"]))
        return data + b"." + crypto.url64(signature).encode("ascii")


class Case:
    def __init__(self, path, keys, *, clock=None, hook=None, journal="WAL"):
        self.path, self.keys = Path(path), keys
        self.clock, self.owner = clock or Clock(), object()
        policy = original_admission.make_policy()
        policy["allowed_output_names"] = ["first.txt", "second.txt"]
        context = {"profile": PROFILE, "provider": "provider-local", "store": "store-" + uuid.uuid4().hex,
                   "namespace": "owner-local", "receiver": "receiver-local", "authority": "authority-local",
                   "epoch": "epoch-one", "policy": policy, "sources": source_pins(),
                   "actors": {r: {"public_pem": b64(keys.items[r]["public_key"].read_bytes()),
                                  "spki_sha256": keys.items[r]["spki_sha256"]} for r in ("runtime-a", "runtime-b")},
                   "authority_public_pem": b64(keys.items["authority"]["public_key"].read_bytes()),
                   "authority_spki_sha256": keys.items["authority"]["spki_sha256"]}
        self.context_raw = encode(context)
        initialize(self.path, self.context_raw, journal=journal)
        self.provider = Provider(self.path, clock=self.clock, hook=hook, owner_capability=self.owner)
        self.operation = self.provider.prepare_operation(self.owner, "operation-one",
                            [{"name": "first.txt", "text": "first local effect\n"},
                             {"name": "second.txt", "text": "second local effect\n"}])
        self.auth_a = self.authorization("runtime-a", "permit-a")
        self.provider.register(self.owner, self.operation, self.auth_a)
        for runtime in ("runtime-a", "runtime-b"):
            self.set_status(runtime)

    def authorization(self, runtime, permit_id=None, *, operation=None, issued=None, expires=None, evaluated=None):
        operation = operation or self.operation
        issued = issued or iso(self.clock())
        permit = original_admission.make_permit(operation, permit_id or "permit-" + uuid.uuid4().hex, issued_at=issued)
        if expires:
            permit["expires_at"] = expires
        return make_authorization(self.provider.context, operation, runtime, permit, evaluated or issued)

    def signed_status(self, runtime, **overrides):
        p = {"profile": PROFILE, "context_sha256": self.provider.context.digest, "runtime": runtime,
             "runtime_spki_sha256": self.keys.items[runtime]["spki_sha256"], "issuer": "authority-local",
             "epoch": "epoch-one", "sequence": 1, "state": "active", "generated_at": self.clock(),
             "last_changed_at": BASE, "next_update_at": self.clock() + 60}
        p.update(overrides)
        return self.keys.sign(p, "authority", STATUS_TYP)

    def set_status(self, runtime, **overrides):
        raw = self.signed_status(runtime, **overrides)
        (self.path / "authority" / (runtime + ".jws")).write_bytes(raw)
        return raw

    def attempt(self, runtime="runtime-a", *, operation_id="operation-one", **overrides):
        ticket = self.provider.ticket(operation_id, runtime)
        return ticket, self.keys.sign({**ticket, **overrides}, runtime, PROOF_TYP)

    def submit(self, runtime="runtime-a"):
        ticket, proof = self.attempt(runtime)
        return self.provider.submit("operation-one", ticket["attempt_id"], proof)

    def unknown(self, ticket, *, observed_at=None):
        p = {"profile": PROFILE, "context_sha256": self.provider.context.digest, "operation_id": ticket["operation_id"],
             "attempt_id": ticket["attempt_id"], "runtime": ticket["runtime"],
             "observed_at": self.clock() if observed_at is None else observed_at, "outcome": "unknown"}
        raw = self.keys.sign(p, ticket["runtime"], OBS_TYP)
        self.provider.record_unknown(ticket["operation_id"], ticket["attempt_id"], ticket["runtime"], raw)
        return raw

    def request(self, *, target="runtime-b", request_id=None, authorization=None, read_attempts=None):
        with self.provider.connection() as c:
            state, _ = self.provider.load(c)
        op = state["operations"]["operation-one"]
        return encode({"context_sha256": self.provider.context.digest, "request_id": request_id or "handoff-" + uuid.uuid4().hex,
                       "operation_id": "operation-one", "old_runtime": op["runtime"],
                       "expected_generation": op["generation"], "expected_revision": op["revision"],
                       "authorization": authorization or self.authorization(target),
                       "read_attempts": sorted(op["tickets"]) if read_attempts is None else read_attempts})

    def handoff(self, **kwargs):
        return self.provider.handoff(self.owner, self.request(**kwargs))

    def reopen(self, *, hook=None):
        self.provider = Provider(self.path, clock=self.clock, hook=hook, owner_capability=self.owner)
        return self.provider
