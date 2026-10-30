"""Saved receipt controls signed by OpenSSL with public test scalars only."""
import base64
from copy import deepcopy
import json
from pathlib import Path
import shutil
import sys
import tempfile

import jcs_recipient_trial as trial

sys.path.insert(0, str(trial.ROOT / "reference/recipient-signature-authority"))
from trial_fixtures import Fixtures as RawFixtures


def url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def fixture_canonical(raw):
    """Independent JCS subset for these ASCII, safe-integer fixtures only."""
    value = json.loads(raw)
    def check(item):
        if type(item) is str:
            item.encode("ascii")
        elif type(item) is int:
            if abs(item) > 2**53 - 1:
                raise ValueError("fixture signer accepts safe integers only")
        elif type(item) in (bool, type(None)):
            pass
        elif type(item) is list:
            for child in item:
                check(child)
        elif type(item) is dict:
            for key, child in item.items():
                check(key)
                check(child)
        else:
            raise ValueError("fixture signer accepts ASCII and safe integers only")
    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("ascii")


def p1363(der):
    """Convert OpenSSL's short DER ECDSA output for this test signer."""
    if not 8 <= len(der) <= 72 or der[0] != 0x30 or der[1] != len(der) - 2:
        raise ValueError("invalid fixture signature DER sequence")
    cursor, values = 2, []
    for _ in range(2):
        if cursor + 2 > len(der) or der[cursor] != 2:
            raise ValueError("invalid fixture signature DER integer tag")
        length = der[cursor + 1]
        part = der[cursor + 2:cursor + 2 + length]
        if not 1 <= length <= 33 or len(part) != length or part[0] & 0x80:
            raise ValueError("invalid fixture signature DER integer encoding")
        if length > 1 and part[0] == 0 and not part[1] & 0x80:
            raise ValueError("nonminimal fixture signature DER integer")
        integer = int.from_bytes(part, "big")
        if not 0 < integer < 2**256:
            raise ValueError("fixture signature integer is out of range")
        values.append(integer.to_bytes(32, "big"))
        cursor += 2 + length
    if cursor != len(der):
        raise ValueError("trailing fixture signature DER bytes")
    return b"".join(values)


class Fixtures:
    def __init__(self):
        self.base = RawFixtures()
        self.node = Path(shutil.which("node")).resolve(strict=True)
        self.node_sha = trial.file_sha(self.node)
        self.admission, self.post = self.base.admission, self.base.post
        self.policy = deepcopy(self.base.policy)
        self.admission_proof = self.sign("admission", self.admission, 0)
        self.post_proof = self.sign("post_execution", self.post, 1)

    def sign(self, kind, raw, key, *, canonical=None, header=None):
        protected = url(trial.encoded(header or {"alg": "ES256", "kid": self.base.keys[key]["key_sha256"],
                                                "typ": "urn:vate:local:jcs-es256:" + kind + ":v1"}))
        payload = fixture_canonical(raw) if canonical is None else canonical
        with tempfile.TemporaryDirectory(prefix="vate-jcs-public-test-sign-") as directory:
            folder = Path(directory)
            (folder / "test-key.der").write_bytes(self.base.private_der[key])
            (folder / "message.bin").write_bytes(protected + b"." + url(payload))
            signature = self.base.run(["pkeyutl", "-sign", "-rawin", "-digest", "sha256", "-keyform", "DER",
                                      "-inkey", str(folder / "test-key.der"), "-in", str(folder / "message.bin"),
                                      "-provider", "default", "-propquery", "provider=default"])
        return protected + b".." + url(p1363(signature))

    def assessor(self, **changes):
        options = {"expected_contract": trial.CONTRACT, "node": self.node, "node_sha256": self.node_sha}
        options.update(changes)
        return trial.JcsRecipientTrial(**options)

    def arguments(self):
        return {"admission": self.admission, "post": self.post, "admission_proof": self.admission_proof,
                "post_proof": self.post_proof, "receiver_policy": trial.encoded(self.policy)}

    def save(self, destination):
        destination.mkdir()
        names = {"admission": "admission.json", "post": "post.json", "admission_proof": "admission.jws",
                 "post_proof": "post.jws", "receiver_policy": "receiver-policy.json"}
        files = {}
        for name, raw in self.arguments().items():
            (destination / names[name]).write_bytes(raw)
            files[names[name]] = {"sha256": trial.sha(raw), "bytes": len(raw)}
        manifest = {"kind": "synthetic_local_jcs_es256_signatures", "source_receipts": "unchanged saved S3 supported case",
                    "signatures_created_after_original_operation": True, "private_keys_are_public_test_material": True,
                    "public_test_private_scalars": self.base.public_test_scalars, "signatures_are_nondeterministic": True,
                    "openssl_signer": {"path": str(self.base.openssl), "sha256": self.base.binary_sha256}, "files": files}
        (destination / "MANIFEST.json").write_bytes(trial.encoded(manifest) + b"\n")
        return manifest
