#!/usr/bin/env python3
"""Repository sanity checker for the public trust envelope draft repository.

This script intentionally stays dependency-free and fast. It validates obvious
shape mismatches, runs the educational demo, and checks expected failure cases.
It is not a full JSON Schema validator. For strict schema validation, use
scripts/check_repo_strict.py when jsonschema is available locally.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "reference" / "minimal-al2-demo" / "trust_envelope_demo.py"
HTTP_DEMO = ROOT / "reference" / "http-verifier-demo" / "http_verifier_demo.py"
EXAMPLE_PAIRS = [
    ("examples/passport-credential.example.json", "schemas/passport-credential.schema.json"),
    ("examples/runtime-proof.example.json", "schemas/runtime-proof.schema.json"),
    ("examples/mission-permit.example.json", "schemas/mission-permit.schema.json"),
    ("examples/execution-receipt.example.json", "schemas/execution-receipt.schema.json"),
    ("examples/artifact-reference.example.json", "schemas/artifact-reference.schema.json"),
    ("examples/evidence-reference.example.json", "schemas/evidence-reference.schema.json"),
    ("examples/admission-request.example.json", "schemas/admission-request.schema.json"),
    ("examples/a2a/metadata-admission-requested.json", "schemas/a2a-vate-metadata.schema.json"),
    ("examples/a2a/metadata-admission-issued.json", "schemas/a2a-vate-metadata.schema.json"),
    ("examples/a2a/metadata-post-execution-issued.json", "schemas/a2a-vate-metadata.schema.json"),
    ("examples/receipts/admission-allow.example.json", "schemas/admission-receipt.schema.json"),
    ("examples/receipts/admission-attenuate-max-amount.example.json", "schemas/admission-receipt.schema.json"),
    ("examples/receipts/admission-deny-expired-permit.example.json", "schemas/admission-receipt.schema.json"),
    ("examples/receipts/post-execution-success.example.json", "schemas/post-execution-receipt.schema.json"),
    ("examples/attenuation-tool-allowlist.example.json", "schemas/attenuation-effect.schema.json"),
    ("examples/attenuation-max-amount.example.json", "schemas/attenuation-effect.schema.json"),
    ("examples/attenuation-approval.example.json", "schemas/attenuation-effect.schema.json"),
    ("examples/status-bundle.example.json", "schemas/status-bundle.schema.json"),
    ("examples/status-entry.example.json", "schemas/status-entry.schema.json"),
    ("examples/status-event.example.json", "schemas/status-event.schema.json"),
    ("policies/al2-http-verifier.example.json", "schemas/verifier-policy.schema.json"),
    (
        "conformance/al2-http/positive/allow-active/expected-report.json",
        "conformance/al2-http/verification-report.schema.json",
    ),
    (
        "conformance/al2-http/positive/attenuate-tool-narrow/expected-report.json",
        "conformance/al2-http/verification-report.schema.json",
    ),
    (
        "conformance/al2-http/negative/deny-revoked/expected-report.json",
        "conformance/al2-http/verification-report.schema.json",
    ),
    (
        "conformance/al2-http/negative/deny-unknown-effect/expected-report.json",
        "conformance/al2-http/verification-report.schema.json",
    ),
]


def resolve_local_ref(root_schema: dict, schema: dict) -> dict:
    ref = schema.get("$ref")
    if not ref or not ref.startswith("#/"):
        return schema
    current = root_schema
    for part in ref[2:].split("/"):
        current = current[part]
    return current


def check(root_schema: dict, schema: dict, value, path: str = "root") -> list[str]:
    schema = resolve_local_ref(root_schema, schema)
    errors = []
    expected_type = schema.get("type")

    if expected_type == "object":
        if not isinstance(value, dict):
            return [f"{path}: expected object"]
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing required key {key}")
        properties = schema.get("properties", {})
        for key, child in properties.items():
            if key in value:
                errors.extend(check(root_schema, child, value[key], f"{path}.{key}"))
        return errors

    if expected_type == "array":
        if not isinstance(value, list):
            return [f"{path}: expected array"]
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: expected at least {schema['minItems']} items")
        item_schema = schema.get("items")
        if item_schema:
            for index, item in enumerate(value):
                errors.extend(check(root_schema, item_schema, item, f"{path}[{index}]"))
        return errors

    if expected_type == "string":
        if not isinstance(value, str):
            return [f"{path}: expected string"]
        if "const" in schema and value != schema["const"]:
            errors.append(f"{path}: expected const {schema['const']}")
        if "enum" in schema and value not in schema["enum"]:
            errors.append(f"{path}: expected one of {schema['enum']}")
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: expected minLength {schema['minLength']}")
        if schema.get("format") == "date-time":
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                errors.append(f"{path}: invalid date-time {value}")
        if schema.get("format") == "uri" and "://" not in value:
            errors.append(f"{path}: invalid uri {value}")
        return errors

    if expected_type == "number":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return [f"{path}: expected number"]
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: expected >= {schema['minimum']}")
        return errors

    if expected_type == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            return [f"{path}: expected integer"]
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: expected >= {schema['minimum']}")
        return errors

    if expected_type == "boolean":
        if not isinstance(value, bool):
            return [f"{path}: expected boolean"]
        return errors

    return errors


def run(cmd: list[str], *, cwd: Path = ROOT) -> None:
    subprocess.run(cmd, cwd=cwd, check=True)


def find_free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_health(url: str, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError(f"status service did not become healthy: {url}")


def validate_examples() -> None:
    for example_rel, schema_rel in EXAMPLE_PAIRS:
        example = json.loads((ROOT / example_rel).read_text())
        schema = json.loads((ROOT / schema_rel).read_text())
        errors = check(schema, schema, example)
        if errors:
            joined = "\n".join(errors)
            raise RuntimeError(f"{example_rel} failed validation:\n{joined}")


def main() -> int:
    validate_examples()
    run([sys.executable, "-m", "py_compile", str(DEMO)])
    run([sys.executable, "-m", "py_compile", str(HTTP_DEMO)])

    tmp_dir = Path(tempfile.mkdtemp(prefix="trust-envelope-check-"))
    port = find_free_port()
    status_base = f"http://127.0.0.1:{port}"
    server = None
    try:
        run([sys.executable, str(DEMO), "generate-demo", "--out", str(tmp_dir)])
        run([sys.executable, str(DEMO), "verify-demo", "--dir", str(tmp_dir), "--status-mode", "stapled"])
        run([sys.executable, str(DEMO), "verify-demo", "--dir", str(tmp_dir), "--status-mode", "push"])

        server = subprocess.Popen(
            [
                sys.executable,
                str(DEMO),
                "serve-status",
                "--dir",
                str(tmp_dir),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wait_for_health(f"{status_base}/healthz")
        run(
            [
                sys.executable,
                str(DEMO),
                "verify-demo",
                "--dir",
                str(tmp_dir),
                "--status-mode",
                "pull",
                "--status-base",
                status_base,
            ]
        )
        run(
            [
                sys.executable,
                str(DEMO),
                "fetch-status",
                "--dir",
                str(tmp_dir),
                "--status-base",
                status_base,
                "--mode",
                "all",
            ]
        )
        run([sys.executable, str(DEMO), "run-negative-tests", "--dir", str(tmp_dir)])
        run(
            [
                sys.executable,
                str(HTTP_DEMO),
                "run-corpus",
                "--corpus-root",
                str(ROOT / "conformance" / "al2-http"),
                "--policy",
                str(ROOT / "policies" / "al2-http-verifier.example.json"),
            ]
        )
        print("trust envelope draft repo sanity check: ok")
        return 0
    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
