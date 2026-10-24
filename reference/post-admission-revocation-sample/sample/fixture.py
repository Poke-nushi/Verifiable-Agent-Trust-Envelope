"""Synthetic fixture issuance only. Temporary test keys; no Keychain or operational signing."""
from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
from pathlib import Path

from contract import AUTH_FIELDS, PROFILE, ROOT, STATUS_TYP, PROOF_TYP, b64, encode, url64
from admission import evaluate, make_permit, make_policy
from demo_contract import ACTION, CONTRACT, RUNTIME
from provider import Provider, initialize

spec = importlib.util.spec_from_file_location("revocation_test_crypto", ROOT / "reference/minimal-al2-demo/trust_envelope_demo.py")
test_crypto = importlib.util.module_from_spec(spec)
spec.loader.exec_module(test_crypto)
BASE = int(datetime(2026, 10, 23, tzinfo=timezone.utc).timestamp())


class Clock:
    def __init__(self, value=BASE):
        self.value = value

    def __call__(self):
        return self.value


class Keys:
    def __init__(self, temporary_dir: Path):
        self.items = {role: test_crypto.generate_keypair(temporary_dir, "test-" + role)
                      for role in ("runtime", "authority", "untrusted")}
        for value in self.items.values():
            value["private_key"].chmod(0o600)

    def sign(self, payload, role, typ, *, header=None, payload_raw=None):
        h = header or {"alg": "ES256", "typ": typ, "kid": "test-key-label"}
        signed_input = (url64(encode(h)) + "." + url64(encode(payload) if payload_raw is None else payload_raw)).encode("ascii")
        der = test_crypto.sign_bytes(signed_input, self.items[role]["private_key"])
        sig = test_crypto.der_to_raw_ecdsa(der)
        return signed_input + b"." + url64(sig).encode("ascii")


class Case:
    def __init__(self, path: Path, keys: Keys, *, journal="WAL", clock=None, hook=None,
                 permit_issued_at=None, permit_expires_at=None, evaluated_at=None):
        self.path, self.keys = path, keys
        self.clock = clock or Clock()
        resource = "urn:vate:demo:revocation-sandbox"
        operation = {"contract": CONTRACT, "operation_key": "operation-fixed-1", "action": ACTION,
                     "target": {"resource": resource, "files": [
                         {"name": "first.txt", "text": "first synthetic effect\n"},
                         {"name": "second.txt", "text": "second synthetic effect\n"}]}}
        policy = make_policy()
        policy["allowed_output_names"] = ["first.txt", "second.txt"]
        issued = permit_issued_at or datetime.fromtimestamp(BASE, timezone.utc).isoformat().replace("+00:00", "Z")
        permit = make_permit(operation, "permit-fixed-1", issued_at=issued)
        if permit_expires_at is not None:
            permit["expires_at"] = permit_expires_at
        auth = evaluate(operation, permit, policy, resource=resource, permit_uri="local:permit.json",
                        evaluated_at=evaluated_at or issued)
        self.selection = {"profile": PROFILE, "receiver": "receiver-local", "provider": "provider-local",
                          "runtime": RUNTIME, "authority": "authority-local", "epoch": "epoch-fixed-1", "max_age": 60,
                          "resource": resource, "policy": policy, "permit_uri": "local:permit.json",
                          "authorization": {name: b64(getattr(auth, name)) if getattr(auth, name) is not None else None
                                            for name in AUTH_FIELDS}}
        for role in ("runtime", "authority"):
            self.selection[role + "_public_pem"] = b64(keys.items[role]["public_key"].read_bytes())
            self.selection[role + "_spki_sha256"] = keys.items[role]["spki_sha256"]
        self.selection_raw = encode(self.selection)
        initialize(path, self.selection_raw, journal=journal)
        self.provider = Provider(path, clock=self.clock, hook=hook)
        self.set_status()

    def status_payload(self, **overrides):
        value = {"profile": PROFILE, "object_type": "runtime", "runtime": self.selection["runtime"],
                 "runtime_spki_sha256": self.selection["runtime_spki_sha256"], "issuer": self.selection["authority"],
                 "epoch": self.selection["epoch"], "sequence": 1, "state": "active", "generated_at": BASE,
                 "last_changed_at": BASE, "next_update_at": BASE + 60}
        value.update(overrides)
        return value

    def signed_status(self, *, role="authority", **overrides):
        return self.keys.sign(self.status_payload(**overrides), role, STATUS_TYP)

    def set_status(self, **overrides):
        raw = self.signed_status(**overrides)
        (self.path / "authority-status.jws").write_bytes(raw)
        return raw

    def challenge_and_proof(self, *, role="runtime", header=None, **overrides):
        challenge = self.provider.challenge()
        value = {**self.provider.selection.binding(), "attempt_id": challenge["attempt_id"],
                 "nonce": challenge["nonce"], "issued_at": self.clock(), "expires_at": self.clock() + 60}
        value.update(overrides)
        proof = self.keys.sign(value, role, PROOF_TYP, header=header)
        return challenge, proof

    def submit(self, **overrides):
        challenge, proof = self.challenge_and_proof(**overrides)
        return self.provider.submit(challenge["attempt_id"], proof)
