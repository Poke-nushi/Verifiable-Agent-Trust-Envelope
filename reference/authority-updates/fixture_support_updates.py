"""Disposable signing helper for tests/examples, never an authority key service."""
import base64
import json
import os
from pathlib import Path
import subprocess

import snapshot as s


def grant_json(grant):
    result = dict(vars(grant))
    result["public_key_spki_base64"] = base64.b64encode(result.pop("public_key_spki")).decode("ascii")
    if "tool_allowlist" in result:
        result["tool_allowlist"] = list(result["tool_allowlist"])
    return result


def sign_snapshots(node, claims, *, headers=None):
    if headers is None:
        headers = [{"alg": "ES256", "typ": s.TOKEN_TYPE, "kid": "authority-key"}] * len(claims)
    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=")
    inputs = [b64(s.b.encode(header)) + b"." + b64(s.b.encode(payload)) for header, payload in zip(headers, claims)]
    output = subprocess.run([str(node), str(Path(__file__).with_name("fixture_signer.mjs"))],
        input=s.b.encode([base64.b64encode(raw).decode("ascii") for raw in inputs]),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "OPENSSL_CONF": os.devnull})
    result = json.loads(output.stdout)
    tokens = [raw + b"." + b64(base64.b64decode(signature)) for raw, signature in zip(inputs, result["signatures"])]
    return tokens, base64.b64decode(result["public_key"])
