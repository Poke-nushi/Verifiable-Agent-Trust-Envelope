"""Local fixture issuance; generated private keys never leave the Node process."""
import base64
import json
import os
from pathlib import Path
import subprocess

from runtime_jwt import binding


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def sign_fixture(node, header_raw, claims_raw, **options):
    signing_input = b64(header_raw) + b"." + b64(claims_raw)
    request = {"signing_input_base64": base64.b64encode(signing_input).decode(), **options}
    result = subprocess.run([str(node), str(Path(__file__).with_name("fixture_signer.mjs"))],
        input=binding.encode(request), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "OPENSSL_CONF": os.devnull},
        check=True, timeout=10)
    output = json.loads(result.stdout)
    signature = base64.b64decode(output["signature_base64"])
    return signing_input + b"." + b64(signature), base64.b64decode(output["spki_base64"])
