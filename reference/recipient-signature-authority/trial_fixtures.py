"""Synthetic test signatures over unchanged archived receipts; never real keys."""
import base64
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import recipient_trial as trial


class Fixtures:
    def __init__(self, openssl=None):
        self.openssl = Path(openssl or os.environ.get("VATE_TRIAL_OPENSSL") or shutil.which("openssl")).resolve(strict=True)
        self.binary_sha256 = trial.sha(self.openssl.read_bytes())
        self.env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "OPENSSL_CONF": os.devnull}
        self.public_test_scalars = [1, 2, 3]
        # SEC1 private keys with public test scalars. Never use these real-world.
        self.private_der = [bytes.fromhex("30310201010420") + scalar.to_bytes(32, "big")
                            + bytes.fromhex("a00a06082a8648ce3d030107") for scalar in self.public_test_scalars]
        self.keys = []
        with tempfile.TemporaryDirectory(prefix="vate-public-test-keys-") as directory:
            path = Path(directory) / "test-key.der"
            for private in self.private_der:
                path.write_bytes(private)
                public = self.run(["pkey", "-inform", "DER", "-in", str(path), "-pubout", "-outform", "DER"])
                if not public.startswith(trial.SPKI_PREFIX) or len(public) != 91:
                    raise AssertionError("unexpected test public key format")
                self.keys.append({"key_sha256": trial.sha(public), "spki_der_base64": base64.b64encode(public).decode()})
        source = trial.ROOT / "reference/s3-observation-example/inputs/seaweedfs-4.48/instance/bundles/supported"
        self.admission = (source / "admission.json").read_bytes()
        self.post = (source / "post.json").read_bytes()
        self.policy = {"contract": trial.POLICY_CONTRACT, "evaluation_time": "2026-10-14T00:00:00Z",
                       "verification_keys": deepcopy(self.keys), "grants": []}
        for kind, raw, key in (("admission", self.admission, 0), ("post_execution", self.post, 1)):
            context, _ = trial.receipt_context(kind, raw)
            self.policy["grants"].append({**context, "key_sha256": self.keys[key]["key_sha256"],
                                         "valid_from": "2026-10-12T00:00:00Z", "valid_until": "2026-10-15T00:00:00Z"})
        self.admission_proof = self.sign("admission", self.admission, 0)
        self.post_proof = self.sign("post_execution", self.post, 1)

    def run(self, arguments):
        if trial.sha(self.openssl.read_bytes()) != self.binary_sha256:
            raise AssertionError("selected test runtime changed")
        result = subprocess.run([str(self.openssl), *arguments], capture_output=True, env=self.env,
                                stdin=subprocess.DEVNULL, timeout=10, check=True)
        if trial.sha(self.openssl.read_bytes()) != self.binary_sha256:
            raise AssertionError("selected test runtime changed")
        return result.stdout

    def sign(self, kind, raw, key):
        with tempfile.TemporaryDirectory(prefix="vate-public-test-sign-") as directory:
            folder = Path(directory)
            (folder / "test-key.der").write_bytes(self.private_der[key])
            (folder / "message.bin").write_bytes(trial.signing_input(kind, raw))
            signature = self.run(["pkeyutl", "-sign", "-rawin", "-digest", "sha256", "-keyform", "DER", "-inkey", str(folder / "test-key.der"),
                                  "-in", str(folder / "message.bin"), "-provider", "default", "-propquery", "provider=default"])
        if not 8 <= len(signature) <= 72:
            raise AssertionError("unexpected test signature length")
        return trial.encoded({"contract": trial.PROOF_CONTRACT, "key_sha256": self.keys[key]["key_sha256"],
                              "signature_base64": base64.b64encode(signature).decode()})

    def assessor(self):
        return trial.RecipientTrial(expected_contract=trial.CONTRACT, openssl=self.openssl,
                                     openssl_sha256=self.binary_sha256)

    def arguments(self):
        return {"admission": self.admission, "post": self.post, "admission_proof": self.admission_proof,
                "post_proof": self.post_proof, "receiver_policy": trial.encoded(self.policy)}

    def save(self, destination):
        destination.mkdir()
        originals = {}
        for name, raw in self.arguments().items():
            filename = name.replace("_", "-") + ".json"
            (destination / filename).write_bytes(raw)
            originals[filename] = trial.identity(raw)
        manifest = {"kind": "synthetic_local_detached_signatures", "source_receipts": "unchanged saved S3 supported case",
                    "signatures_created_after_original_operation": True, "private_keys_are_public_test_material": True,
                    "public_test_private_scalars": self.public_test_scalars, "signatures_are_nondeterministic": True, "files": originals,
                    "openssl": str(self.openssl), "openssl_sha256": self.binary_sha256}
        (destination / "MANIFEST.json").write_bytes(trial.encoded(manifest) + b"\n")
        return manifest
