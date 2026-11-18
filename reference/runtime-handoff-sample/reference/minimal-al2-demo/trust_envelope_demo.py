#!/usr/bin/env python3
"""Minimal AL2 demo for Verifiable Agent Trust Envelope.

This educational reference demo uses compact JWS packaging for the trust envelope artifacts and
provides a minimal status service that can be consumed in pull, stapled, or push
delivery modes.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import json
import math
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from functools import lru_cache
from http import HTTPStatus
from http.client import HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from os.path import lexists
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse
from urllib.request import urlopen

OPENSSL = shutil.which("openssl")
TRUST_BUNDLE_VERSION = "app-trust-0.1"
ROLE_ORDER = ("issuer", "attestor", "broker", "runtime", "status")
ARTIFACT_SPECS = {
    "passport": {
        "basename": "passport-credential",
        "role": "issuer",
        "typ": "appc+jws",
        "cty": "application/appc+json",
    },
    "runtime_proof": {
        "basename": "runtime-proof",
        "role": "attestor",
        "typ": "arp+jws",
        "cty": "application/arp+json",
    },
    "permit": {
        "basename": "mission-permit",
        "role": "broker",
        "typ": "amp+jws",
        "cty": "application/amp+json",
    },
    "receipt": {
        "basename": "execution-receipt",
        "role": "runtime",
        "typ": "aer+jws",
        "cty": "application/aer+json",
    },
}
STATUS_TYP = "asn+jws"
STATUS_EVENT_TYP = "asn-event+jws"
STATUS_CONTENT_TYPE = "application/asn+json"
STATUS_EVENT_CONTENT_TYPE = "application/asn-event+json"
STATUS_KINDS = ("passport", "runtime", "permit")
BLOCKING_STATUS_STATES = frozenset({"suspended", "revoked", "quarantined"})
STATUS_STATES = BLOCKING_STATUS_STATES.union(("active", "attenuated"))
# Compare group parameters independently of the optional seed and point encoding.
EC_GROUP_FORMAT = ("-param_enc", "explicit", "-conv_form", "uncompressed", "-no_seed", "-outform", "DER")
TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.([0-9]+))?([Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    match = TIMESTAMP.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError("timestamp must include a date, time and UTC offset")
    if (match[1] or "")[6:].strip("0"):
        raise ValueError("timestamp exceeds the demo's microsecond precision")
    return datetime.fromisoformat(value.upper().replace("Z", "+00:00"))


def canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("JSON contains a duplicate object member")
    return obj


def json_number(token: str) -> int | float:
    number = float(token)
    if not math.isfinite(number):
        raise ValueError("JSON number exceeds the supported finite range")
    try:
        exact = Decimal(token)
    except InvalidOperation as exc:
        raise ValueError("invalid JSON number") from exc
    # Preserve whole-number limits when a binary float would round them.
    if exact == exact.to_integral_value() and exact != number:
        return int(exact)
    if exact != Decimal(str(number)):
        raise ValueError("JSON number cannot be represented without losing decimal precision")
    return number


def parse_demo_json(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=unique_json_object,
                          parse_float=json_number, parse_constant=json_number)
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds the supported depth") from exc


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(data: str) -> bytes:
    raw = base64.b64decode(data + "=" * (-len(data) % 4), altchars=b"-_", validate=True)
    if not data or b64url_encode(raw) != data:
        raise ValueError("compact JWS segments must use unpadded canonical base64url")
    return raw


def ensure_openssl() -> str:
    if not OPENSSL:
        raise RuntimeError("OpenSSL is required for this demo but was not found in PATH.")
    return OPENSSL


def run_command(
    args: list[str], *, check: bool = True, input_data: bytes | None = None
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(args, input=input_data, capture_output=True, check=False)
    if check and result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"command failed ({' '.join(args)}): {stderr}")
    return result


def read_der_length(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    length_bytes = first & 0x7F
    length = int.from_bytes(data[offset : offset + length_bytes], "big")
    return length, offset + length_bytes


def encode_der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def encode_der_integer(value: bytes) -> bytes:
    trimmed = value.lstrip(b"\x00") or b"\x00"
    if trimmed[0] & 0x80:
        trimmed = b"\x00" + trimmed
    return b"\x02" + encode_der_length(len(trimmed)) + trimmed


def der_to_raw_ecdsa(signature: bytes, size: int = 32) -> bytes:
    if not signature or signature[0] != 0x30:
        raise ValueError("invalid DER ECDSA signature")
    seq_length, offset = read_der_length(signature, 1)
    end = offset + seq_length
    if end != len(signature):
        raise ValueError("unexpected DER sequence length")

    if signature[offset] != 0x02:
        raise ValueError("missing DER integer for r")
    r_length, offset = read_der_length(signature, offset + 1)
    r = signature[offset : offset + r_length]
    offset += r_length

    if signature[offset] != 0x02:
        raise ValueError("missing DER integer for s")
    s_length, offset = read_der_length(signature, offset + 1)
    s = signature[offset : offset + s_length]

    r = (r.lstrip(b"\x00") or b"\x00").rjust(size, b"\x00")
    s = (s.lstrip(b"\x00") or b"\x00").rjust(size, b"\x00")
    return r + s


def raw_to_der_ecdsa(signature: bytes) -> bytes:
    if len(signature) != 64:
        raise ValueError("expected 64-byte raw ECDSA signature")
    body = encode_der_integer(signature[:32]) + encode_der_integer(signature[32:])
    return b"\x30" + encode_der_length(len(body)) + body


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> dict:
    return parse_demo_json(path.read_text(encoding="utf-8"))


def write_text(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data + "\n", encoding="utf-8")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").removesuffix("\n")


def key_path(out_dir: Path, role: str, kind: str) -> Path:
    return out_dir / "keys" / f"{role}-{kind}.pem"


def generate_keypair(out_dir: Path, role: str) -> dict:
    openssl = ensure_openssl()
    private_key = key_path(out_dir, role, "private")
    public_key = key_path(out_dir, role, "public")
    private_key.parent.mkdir(parents=True, exist_ok=True)

    run_command(
        [
            openssl,
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            str(private_key),
        ]
    )
    run_command([openssl, "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)])

    return {
        "kid": f"{role}-key-1",
        "alg": "ES256",
        "private_key": private_key,
        "public_key": public_key,
        "spki_sha256": spki_sha256(public_key),
    }


@lru_cache(maxsize=1)
def p256_group_parameters(openssl: str) -> bytes:
    return run_command([openssl, "ecparam", "-name", "prime256v1", *EC_GROUP_FORMAT]).stdout


def public_key_der(public_key: Path) -> bytes:
    """Load the exact SPKI used for the fingerprint and ES256 verification."""
    openssl = ensure_openssl()
    try:
        if not public_key.is_file():
            raise RuntimeError("the registered public key file is unavailable")
        der = run_command(
            [openssl, "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"]
        ).stdout
        parameters = run_command(
            [openssl, "ec", "-pubin", "-inform", "DER", "-param_out", "-param_enc", "explicit", "-outform", "DER"],
            input_data=der,
        )
        group = run_command([openssl, "ecparam", "-inform", "DER", *EC_GROUP_FORMAT], input_data=parameters.stdout)
        if not group.stdout or group.stdout != p256_group_parameters(openssl):
            raise RuntimeError("the registered ES256 public key must identify the P-256 curve")
        return der
    except (OSError, ValueError) as exc:
        raise RuntimeError("the registered public key could not be read") from exc


def spki_sha256(public_key: Path) -> str:
    return "sha256:" + hashlib.sha256(public_key_der(public_key)).hexdigest()


def sign_bytes(data: bytes, private_key: Path) -> bytes:
    openssl = ensure_openssl()
    with tempfile.TemporaryDirectory() as tmp_dir_name:
        tmp_dir = Path(tmp_dir_name)
        payload_path = tmp_dir / "payload.bin"
        signature_path = tmp_dir / "signature.bin"
        payload_path.write_bytes(data)
        run_command(
            [
                openssl,
                "dgst",
                "-sha256",
                "-sign",
                str(private_key),
                "-out",
                str(signature_path),
                str(payload_path),
            ]
        )
        return signature_path.read_bytes()


def verify_bytes(data: bytes, signature: bytes, public_key: Path, *, expected_fingerprint: str | None = None) -> bool:
    openssl = ensure_openssl()
    der = public_key_der(public_key)
    if expected_fingerprint is not None and "sha256:" + hashlib.sha256(der).hexdigest() != expected_fingerprint:
        raise RuntimeError("the registered public key differs from its local fingerprint")
    with tempfile.TemporaryDirectory() as tmp_dir_name:
        tmp_dir = Path(tmp_dir_name)
        payload_path = tmp_dir / "payload.bin"
        signature_path = tmp_dir / "signature.bin"
        key_path = tmp_dir / "public.der"
        key_path.write_bytes(der)
        payload_path.write_bytes(data)
        signature_path.write_bytes(signature)
        result = run_command(
            [
                openssl,
                "dgst",
                "-sha256",
                "-verify",
                str(key_path),
                "-keyform",
                "DER",
                "-signature",
                str(signature_path),
                str(payload_path),
            ],
            check=False,
        )
        if result.returncode == 0:
            return True
        if result.returncode == 1 and result.stdout.strip().lower() == b"verification failure":
            return False
        raise RuntimeError("OpenSSL could not complete signature verification")


def build_compact_jws(payload: dict, *, key_info: dict, typ: str, cty: str) -> str:
    protected = {
        "alg": key_info["alg"],
        "kid": key_info["kid"],
        "typ": typ,
        "cty": cty,
    }
    protected_b64 = b64url_encode(canonical(protected))
    payload_b64 = b64url_encode(canonical(payload))
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    signature_der = sign_bytes(signing_input, key_info["private_key"])
    signature_raw = der_to_raw_ecdsa(signature_der)
    signature_b64 = b64url_encode(signature_raw)
    return f"{protected_b64}.{payload_b64}.{signature_b64}"


def decode_compact_jws(token: str) -> tuple[dict, dict, bytes, bytes]:
    if not isinstance(token, str):
        raise ValueError("compact JWS must be a string")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("compact JWS must have three parts")
    protected = parse_demo_json(b64url_decode(parts[0]).decode("utf-8"))
    payload = parse_demo_json(b64url_decode(parts[1]).decode("utf-8"))
    if not isinstance(protected, dict) or not isinstance(payload, dict):
        raise ValueError("demo JWS header and payload must be JSON objects")
    if not isinstance(protected.get("kid"), str) or not protected["kid"]:
        raise ValueError("demo JWS kid must be a non-empty string")
    signature = b64url_decode(parts[2])
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    return protected, payload, signing_input, signature


def tamper_compact_jws_payload(token: str, mutate) -> str:
    protected, payload, _, signature = decode_compact_jws(token)
    mutate(payload)
    protected_b64 = b64url_encode(canonical(protected))
    payload_b64 = b64url_encode(canonical(payload))
    signature_b64 = b64url_encode(signature)
    return f"{protected_b64}.{payload_b64}.{signature_b64}"


def build_trust_bundle(now: datetime, keys: dict[str, dict]) -> dict:
    entries = {}
    for role, key_info in keys.items():
        entries[key_info["kid"]] = {
            "owner": role,
            "alg": key_info["alg"],
            "public_key": str(key_info["public_key"].relative_to(key_info["public_key"].parents[1])),
            "spki_sha256": key_info["spki_sha256"],
        }
    return {
        "version": TRUST_BUNDLE_VERSION,
        "generated_at": iso(now),
        "keys": entries,
    }


def build_status_store(now: datetime, passport: dict, runtime_proof: dict, permit: dict) -> dict:
    next_update = now + timedelta(minutes=30)
    return {
        "version": "asn-store-0.1",
        "issuer": {"id": "status:demo:authority"},
        "sequence": 1,
        "generated_at": iso(now),
        "next_update_at": iso(next_update),
        "entries": {
            "passport": {
                "id": passport["passport_id"],
                "state": "active",
                "last_changed_at": iso(now),
                "reason": "good-standing",
            },
            "runtime": {
                "id": runtime_proof["runtime_id"],
                "state": "active",
                "last_changed_at": iso(now),
                "reason": "fresh-attestation",
            },
            "permit": {
                "id": permit["permit_id"],
                "state": "active",
                "last_changed_at": iso(now),
                "reason": "within-policy",
            },
        },
    }


def build_status_bundle_payload(status_store: dict, delivery: str) -> dict:
    return {
        "version": "asn-0.1",
        "issuer": status_store["issuer"],
        "delivery": delivery,
        "generated_at": status_store["generated_at"],
        "next_update_at": status_store["next_update_at"],
        "entries": copy.deepcopy(status_store["entries"]),
    }


def build_status_event_payload(status_store: dict) -> dict:
    return {
        "version": "asn-event-0.1",
        "issuer": status_store["issuer"],
        "delivery": "push",
        "event_id": f"asn-event:{status_store['sequence']}",
        "generated_at": status_store["generated_at"],
        "next_update_at": status_store["next_update_at"],
        "entries": copy.deepcopy(status_store["entries"]),
    }


def build_status_entry_payload(status_store: dict, object_type: str) -> dict:
    entry = status_store["entries"][object_type]
    payload = {
        "version": "asn-entry-0.1",
        "issuer": status_store["issuer"],
        "delivery": "pull",
        "object_type": object_type,
        "object_id": entry["id"],
        "state": entry["state"],
        "reason": entry["reason"],
        "last_changed_at": entry["last_changed_at"],
        "generated_at": status_store["generated_at"],
        "next_update_at": status_store["next_update_at"],
    }
    if "effect" in entry:
        payload["effect"] = copy.deepcopy(entry["effect"])
    return payload


class DemoOutputError(ValueError):
    """The destination cannot be replaced without risking unrelated data."""


@contextmanager
def staged_output(destination: Path):
    """Build beside the destination so a completed directory can be renamed into place."""
    if (not destination.name or destination.name == ".." or destination.is_symlink()
            or destination.resolve() in (Path.cwd(), *Path.cwd().parents)):
        raise DemoOutputError("choose a dedicated demo directory by name")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".vate-stage-", dir=destination.parent) as work:
        staged = Path(work) / "new"
        staged.mkdir(mode=0o700)
        yield staged


def publish_output(staged: Path, destination: Path, *, optional_files=(), seed: Path | None = None,
                   validate_previous: Callable[[Path, set[Path]], None] | None = None) -> None:
    """Replace only a complete demo, an empty directory, or the explicitly selected seed file."""
    files = {p.relative_to(staged) for p in staged.rglob("*") if p.is_file()}
    allowed = files.union(optional_files)
    directories = {parent for name in allowed for parent in name.parents}

    def check_previous(root: Path) -> list[Path]:
        seen = set()
        entries = []

        def visit(folder: Path) -> None:
            for entry in folder.iterdir():
                name = entry.relative_to(root)
                mode = entry.lstat().st_mode
                if name in allowed and stat.S_ISREG(mode):
                    seen.add(name)
                elif name in directories and stat.S_ISDIR(mode):
                    visit(entry)
                else:
                    raise DemoOutputError(f"unrecognized demo output {destination / name}; choose a new directory")
                entries.append(name)

        if not stat.S_ISDIR(root.lstat().st_mode):
            raise DemoOutputError(f"{destination} must be a directory")
        visit(root)
        if not entries:
            return entries
        if seed is not None and entries == [seed] and (root / seed).read_bytes() == (staged / seed).read_bytes():
            return entries
        if not files.issubset(seen):
            raise DemoOutputError(f"incomplete or different demo at {destination}; choose a new directory")
        for name in files:
            if name.name == "trust-bundle.json":
                try:
                    trust = read_json(root / name)
                except ValueError:
                    trust = None
                if (not isinstance(trust, dict) or trust.get("version") != TRUST_BUNDLE_VERSION
                        or not isinstance(trust.get("keys"), dict) or not trust["keys"]):
                    raise DemoOutputError(f"unrecognized trust bundle at {destination / name}; choose a new directory")
        if validate_previous is not None:
            validate_previous(root, seen)
        return entries

    # The lock also holds the previous generation until the new one is installed.
    lock = destination.parent / f".{destination.name}.vate-update"
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise DemoOutputError(f"another update or a recoverable prior generation exists at {lock}") from exc
    previous = lock / "previous"
    entries = []
    try:
        try:
            if lexists(destination):
                check_previous(destination)
                destination.rename(previous)
                entries = check_previous(previous)
            staged.rename(destination)
        except BaseException:
            if lexists(previous) and not lexists(destination):
                previous.rename(destination)
            raise
        if lexists(previous):
            # Remove only inventoried entries. A newly added file keeps the
            # previous directory recoverable instead of being swept up.
            try:
                for name in entries:
                    path = previous / name
                    if name in directories:
                        path.rmdir()
                    else:
                        path.unlink()
                previous.rmdir()
            except OSError as exc:
                raise DemoOutputError(f"new demo installed at {destination}; previous files remain at {previous}") from exc
    finally:
        if not lexists(previous):
            lock.rmdir()


def clear_bundle_reports(out_dir: Path) -> None:
    for name in ("verification-report.json", "negative-test-report.json"):
        (out_dir / name).unlink(missing_ok=True)


def example_execution_receipt(permit: dict, runtime_proof: dict, completed_at: datetime) -> dict:
    """Describe the fixture's instantaneous, completed synthetic action."""
    return {
        "version": "aer-0.1",
        "receipt_id": "aer:demo-receipt",
        "receipt_phase": "post_execution",
        "transaction_id": permit["transaction_id"],
        "actor": permit["actor"],
        "principal": permit["principal"],
        "runtime_ref": runtime_proof["runtime_id"],
        "permit_ref": permit["permit_id"],
        "verifier": permit["aud"],
        "issuer_role": "runtime",
        "skill": {"id": "report.generate", "version": "0.1.0"},
        "input_hash": "sha256:demo-input",
        "output_hash": "sha256:demo-output",
        "policy_ref": permit["approval"]["policy_ref"],
        "policy_id": permit["approval"]["policy_ref"],
        "policy_version": "demo-policy-0.1",
        "evidence_refs": ["urn:artifact:demo:summary-v1"],
        "artifact_digests": {
            "request": "sha256:demo-request",
            "response": "sha256:demo-response",
        },
        "started_at": iso(completed_at),
        "finished_at": iso(completed_at),
        "outcome": "success",
    }


def build_demo_bundle(out_dir: Path, *, audience: str = "https://verifier.example/a2a",
                      include_execution_receipt: bool = True) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    clear_bundle_reports(out_dir)

    now = utc_now()
    passport_expires = now + timedelta(days=30)
    runtime_expires = now + timedelta(minutes=5)
    permit_expires = now + timedelta(minutes=10)

    keys = {role: generate_keypair(out_dir, role) for role in ROLE_ORDER}
    trust_bundle = build_trust_bundle(now, keys)

    passport = {
        "version": "appc-0.1",
        "passport_id": "appc:demo-passport",
        "subject": {
            "root_id": "did:key:z6MknDemoRoot",
            "public_alias": "agent:public:demo-reviewer-01",
        },
        "controller": {"id": "org:demo:ops", "type": "organization"},
        "issuer": {"id": "issuer:demo:passport-authority"},
        "assurance_level": "AL2",
        "capabilities": {
            "self_declared": ["task.execute", "report.generate"],
            "verified": ["readonly_project_access"],
            "observed": ["successful_demo_runs>=1"],
        },
        "status_ref": "https://status.example/demo/passport/appc:demo-passport",
        "valid_from": iso(now),
        "valid_until": iso(passport_expires),
    }

    runtime_proof = {
        "version": "arp-0.1",
        "runtime_id": "arp:demo-runtime",
        "subject_id": passport["subject"]["root_id"],
        "attestor": {"id": "attestor:demo:runtime-authority"},
        "environment": {
            "type": "container",
            "class": "cloud-sandbox",
            "measurement": "sha256:demo-measurement",
        },
        "challenge_binding": {
            "nonce": "nonce:demo-1234",
            "aud": audience,
        },
        "presented_key": {
            "kid": keys["runtime"]["kid"],
            "alg": keys["runtime"]["alg"],
            "spki_sha256": keys["runtime"]["spki_sha256"],
        },
        "issued_at": iso(now),
        "expires_at": iso(runtime_expires),
    }

    permit = {
        "version": "amp-0.1",
        "permit_id": "amp:demo-permit",
        "transaction_id": "txn:demo-001",
        "actor": passport["subject"]["public_alias"],
        "principal": "user:pairwise:demo-service:01",
        "aud": audience,
        "issued_at": iso(now),
        "actions": ["task.execute", "files.read"],
        "constraints": {
            "resource": "project:demo-alpha",
            "max_amount_usd": 0,
            "max_redelegation_depth": 0,
            "expires_at": iso(permit_expires),
            "tool_allowlist": ["read_file", "summarize"],
        },
        "approval": {
            "mode": "policy_auto",
            "policy_ref": "policy:demo:readonly-low-risk",
        },
        "proof_binding": {
            "type": "cnf-kid",
            "kid": keys["runtime"]["kid"],
            "spki_sha256": keys["runtime"]["spki_sha256"],
        },
    }

    status_store = build_status_store(now, passport, runtime_proof, permit)

    artifacts = {
        "passport": {"payload": passport},
        "runtime_proof": {"payload": runtime_proof},
        "permit": {"payload": permit},
    }
    if include_execution_receipt:
        artifacts["receipt"] = {"payload": example_execution_receipt(permit, runtime_proof, now)}
    bundle = {
        "trust_bundle": trust_bundle,
        "status_store": status_store,
        "artifacts": artifacts,
        "status_tokens": {},
    }
    issue_artifact_tokens(bundle, out_dir, keys=keys)
    issue_status_tokens(bundle, out_dir, keys=keys)
    return bundle


def issue_artifact_tokens(bundle: dict, out_dir: Path, *, keys: dict[str, dict] | None = None) -> None:
    key_lookup = keys or {
        role: {
            "kid": f"{role}-key-1",
            "alg": "ES256",
            "private_key": key_path(out_dir, role, "private"),
            "public_key": key_path(out_dir, role, "public"),
        }
        for role in ROLE_ORDER
    }
    for name, artifact in bundle["artifacts"].items():
        spec = ARTIFACT_SPECS[name]
        artifact["token"] = build_compact_jws(
            artifact["payload"],
            key_info=key_lookup[spec["role"]],
            typ=spec["typ"],
            cty=spec["cty"],
        )


def _sign_status_payload(out_dir: Path, trust_bundle: dict, payload: dict, *, key_info: dict | None = None) -> str:
    status_key = key_info or {
        "kid": "status-key-1", "alg": "ES256", "private_key": key_path(out_dir, "status", "private"),
    }
    if payload["version"] == "asn-event-0.1":
        typ, cty = STATUS_EVENT_TYP, STATUS_EVENT_CONTENT_TYPE
    else:
        typ, cty = STATUS_TYP, STATUS_CONTENT_TYPE
    token = build_compact_jws(payload, key_info=status_key, typ=typ, cty=cty)
    verified = verify_role_bound_jws(out_dir=out_dir, trust_bundle=trust_bundle, token=token,
                                     expected_typ=typ, expected_cty=cty, expected_role="status")
    if not verified["ok"]:
        raise RuntimeError("the status signing key does not match its local registration")
    return token


def issue_status_tokens(bundle: dict, out_dir: Path, *, keys: dict[str, dict] | None = None) -> None:
    store, trust = bundle["status_store"], bundle["trust_bundle"]
    key_info = keys["status"] if keys else None
    stapled = _sign_status_payload(out_dir, trust, build_status_bundle_payload(store, "stapled"), key_info=key_info)
    push = _sign_status_payload(out_dir, trust, build_status_event_payload(store), key_info=key_info)
    bundle["status_tokens"].update(stapled=stapled, push=push)


def write_bundle(out_dir: Path, bundle: dict, template_dir: Path | None = None) -> None:
    clear_bundle_reports(out_dir)
    if template_dir:
        shutil.copytree(template_dir / "keys", out_dir / "keys")

    write_json(out_dir / "trust-bundle.json", bundle["trust_bundle"])
    write_json(out_dir / "status-store.json", bundle["status_store"])
    write_text(out_dir / "stapled-status.jws", bundle["status_tokens"]["stapled"])
    write_text(out_dir / "push-status-event.jws", bundle["status_tokens"]["push"])

    for name, artifact in bundle["artifacts"].items():
        basename = ARTIFACT_SPECS[name]["basename"]
        write_json(out_dir / f"{basename}.json", artifact["payload"])
        write_text(out_dir / f"{basename}.jws", artifact["token"])


def generate_demo(out_dir: Path) -> None:
    with staged_output(out_dir) as staged:
        write_bundle(staged, build_demo_bundle(staged))
        bundle_files = {p.relative_to(staged) for p in staged.rglob("*") if p.is_file()}
        report = Path("verification-report.json")
        optional = {report, Path("negative-test-report.json")}
        for case in negative_cases(staged):
            case_dir = Path("negative-cases") / case["name"]
            optional.update(case_dir / f for f in bundle_files | {report})
        publish_output(staged, out_dir, optional_files=optional)


def load_bundle(out_dir: Path) -> dict:
    artifacts = {}
    for artifact_name, spec in ARTIFACT_SPECS.items():
        basename = spec["basename"]
        artifacts[artifact_name] = {
            "payload": read_json(out_dir / f"{basename}.json"),
            "token": read_text(out_dir / f"{basename}.jws"),
        }
    return {
        "trust_bundle": read_json(out_dir / "trust-bundle.json"),
        "status_store": read_json(out_dir / "status-store.json"),
        "artifacts": artifacts,
        "status_tokens": {
            "stapled": read_text(out_dir / "stapled-status.jws"),
            "push": read_text(out_dir / "push-status-event.jws"),
        },
    }


def registered_key(trust_bundle: dict, kid: str) -> dict:
    keys = trust_bundle["keys"]
    if not isinstance(kid, str) or kid not in keys:
        return {}
    key_entry = keys[kid]
    if (not isinstance(key_entry, dict) or not isinstance(key_entry.get("public_key"), str)
            or not key_entry["public_key"]
            or ("spki_sha256" in key_entry and not isinstance(key_entry["spki_sha256"], str))):
        raise RuntimeError("the local public key registration is incomplete")
    return key_entry


def resolve_public_key(out_dir: Path, trust_bundle: dict, kid: str) -> Path | None:
    entry = registered_key(trust_bundle, kid)
    return out_dir / entry["public_key"] if entry else None


def verify_compact_jws(
    *,
    out_dir: Path,
    trust_bundle: dict,
    token: str,
    expected_typ: str,
    expected_cty: str,
) -> dict:
    """Check compact JWS packaging and signature, without assigning issuer authority."""
    try:
        header, payload, signing_input, signature_raw = decode_compact_jws(token)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError, binascii.Error) as exc:
        return {
            "ok": False,
            "header": {},
            "payload": {},
            "details": f"unable to decode compact JWS: {exc}",
        }

    kid = header.get("kid", "")
    public_key = resolve_public_key(out_dir, trust_bundle, kid)
    if public_key is None:
        return {
            "ok": False,
            "header": header,
            "payload": payload,
            "details": f"unknown kid {kid}",
        }

    key_entry = trust_bundle["keys"][kid]
    if header.get("typ") != expected_typ:
        return {
            "ok": False,
            "header": header,
            "payload": payload,
            "details": f"unexpected typ {header.get('typ')}",
        }

    if header.get("cty") != expected_cty:
        return {
            "ok": False,
            "header": header,
            "payload": payload,
            "details": f"unexpected cty {header.get('cty')}",
        }

    if header.get("alg") != "ES256" or key_entry.get("alg") != "ES256":
        return {
            "ok": False,
            "header": header,
            "payload": payload,
            "details": f"unexpected alg {header.get('alg')} for {kid}",
        }

    try:
        signature_der = raw_to_der_ecdsa(signature_raw)
    except ValueError as exc:
        return {
            "ok": False,
            "header": header,
            "payload": payload,
            "details": f"invalid JWS signature encoding: {exc}",
        }

    ok = verify_bytes(signing_input, signature_der, public_key, expected_fingerprint=key_entry.get("spki_sha256"))
    return {
        "ok": ok,
        "header": header,
        "payload": payload,
        "details": f"signature {'verified' if ok else 'does not match'} for kid {kid}",
    }


def verify_role_bound_jws(
    *,
    out_dir: Path,
    trust_bundle: dict,
    token: str,
    expected_typ: str,
    expected_cty: str,
    expected_role: str,
) -> dict:
    """Authenticate a demo artifact using a verifier-selected signer role.

    Signature validity and role authorization remain separate report checks.
    An unauthorized payload cannot supply identities to the caller.
    """
    if not isinstance(expected_role, str) or not expected_role:
        raise ValueError("the verifier must select a non-empty expected signer role")
    result = verify_compact_jws(out_dir=out_dir, trust_bundle=trust_bundle, token=token,
                                expected_typ=expected_typ, expected_cty=expected_cty)
    signature_ok = result["ok"]
    role_ok = signature_ok and (
        trust_bundle["keys"][result["header"]["kid"]].get("owner") == expected_role
    )
    return {**result, "signature_ok": signature_ok, "signer_role_ok": role_ok,
            "signer_role_details": f"authenticated signer must have demo role {expected_role}",
            "ok": role_ok, "payload": result["payload"] if role_ok else {}}


def required_text(obj: object, field: str) -> str:
    value = obj.get(field) if isinstance(obj, dict) else None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def matching_text(first: object, *others: object) -> bool:
    return isinstance(first, str) and bool(first) and all(value == first for value in others)


def runtime_key_bound(out_dir: Path, trust_bundle: dict, permit: dict, runtime_proof: dict) -> bool:
    binding = permit.get("proof_binding")
    presented = runtime_proof.get("presented_key")
    if not isinstance(binding, dict) or not isinstance(presented, dict) or binding.get("type") != "cnf-kid":
        return False
    kid = presented.get("kid")
    if not matching_text(kid, binding.get("kid")):
        return False
    public_key = resolve_public_key(out_dir, trust_bundle, kid)
    if public_key is None:
        return False
    entry = trust_bundle["keys"][kid]
    if entry.get("owner") != "runtime" or entry.get("alg") != "ES256":
        return False
    if "alg" in presented and presented["alg"] != entry["alg"]:
        return False
    # The local profile also accepts a kid-only binding. If the artifacts
    # carry a fingerprint, both refer to the same registered public key.
    fingerprint = spki_sha256(public_key)
    if "spki_sha256" in entry and entry["spki_sha256"] != fingerprint:
        raise RuntimeError("the registered runtime public key differs from its local fingerprint")
    if "spki_sha256" not in binding and "spki_sha256" not in presented:
        return True
    return matching_text(fingerprint, binding.get("spki_sha256"), presented.get("spki_sha256"))


def validated_permit_scope(permit: dict) -> tuple[str, list[str]]:
    """Read the task identity and action names used by the legacy demos.

    Authentication and the remaining permit constraints are checked separately.
    """
    transaction_id = required_text(permit, "transaction_id")
    actions = permit.get("actions")
    if (not isinstance(actions, list) or not actions
            or any(not isinstance(action, str) or not action for action in actions)):
        raise ValueError("permit actions must be a non-empty list of non-empty strings")
    return transaction_id, actions


def build_status_token(out_dir: Path, kind: str, *, object_type: str | None = None) -> str:
    store = read_json(out_dir / "status-store.json")
    if kind in ("bundle", "stapled"):
        payload = build_status_bundle_payload(store, delivery="pull" if kind == "bundle" else "stapled")
    elif kind == "event":
        payload = build_status_event_payload(store)
    elif kind == "entry" and object_type:
        payload = build_status_entry_payload(store, object_type)
    else:
        raise ValueError(f"unsupported status token kind {kind}")
    return _sign_status_payload(out_dir, read_json(out_dir / "trust-bundle.json"), payload)


def http_get_text(url: str) -> str:
    with urlopen(url) as response:
        body = response.read().decode("utf-8")
        return body.removesuffix("\r\n") if body.endswith("\r\n") else body.removesuffix("\n")


def normalize_status_payload(payload: dict) -> dict:
    if payload.get("version") == "asn-0.1":
        return payload
    if payload.get("version") == "asn-event-0.1":
        return {
            "version": "asn-0.1",
            "issuer": payload["issuer"],
            "delivery": payload.get("delivery", "push"),
            "generated_at": payload["generated_at"],
            "next_update_at": payload["next_update_at"],
            "entries": payload["entries"],
        }
    if payload.get("version") == "asn-entry-0.1":
        object_type = payload["object_type"]
        entry = {
            "id": payload["object_id"],
            "state": payload["state"],
            "reason": payload["reason"],
            "last_changed_at": payload["last_changed_at"],
        }
        if "effect" in payload:
            entry["effect"] = payload["effect"]
        return {
            "version": "asn-0.1",
            "issuer": payload["issuer"],
            "delivery": payload.get("delivery", "pull"),
            "generated_at": payload["generated_at"],
            "next_update_at": payload["next_update_at"],
            "entries": {
                object_type: entry
            },
        }
    raise ValueError(f"unsupported status payload version {payload.get('version')}")


class StatusEffectError(ValueError):
    def __init__(self, field: str, message: str):
        super().__init__(message)
        self.field = field


def validated_status_payload(payload: dict) -> dict:
    """Check fields used by both bundle demos; signature and freshness are separate."""
    payload = normalize_status_payload(payload)
    for field in ("generated_at", "next_update_at"):
        parse_time(payload[field])
    entries = payload["entries"]
    if not isinstance(entries, dict):
        raise ValueError("status entries must be a JSON object")
    for name in STATUS_KINDS:
        entry = entries.get(name)
        if not isinstance(entry, dict):
            raise ValueError(f"missing or invalid {name} status entry")
        if not isinstance(entry.get("id"), str) or not entry["id"]:
            raise ValueError(f"{name} status id must be a non-empty string")
        required_text(entry, "reason")
        state = entry.get("state")
        if not isinstance(state, str) or state not in STATUS_STATES:
            raise ValueError(f"unsupported {name} status state")
        if entry["state"] == "attenuated" or "effect" in entry:
            effect = entry.get("effect")
            if not isinstance(effect, dict) or not isinstance(effect.get("constraints"), dict):
                raise StatusEffectError("constraints", f"{name} status effect requires a constraints object")
            if effect.get("mode") != "narrow":
                raise StatusEffectError("mode", f"{name} status effect requires mode=narrow")
            if type(effect.get("require_new_permit")) is not bool:
                raise StatusEffectError("require_new_permit", f"{name} status effect requires a boolean reissue flag")
    return payload


def status_attenuation_requirements(entries: dict) -> tuple[list[str], list[str]]:
    """Return unsupported narrowing subjects and all explicit permit reissue requests."""
    unsupported, reissue = [], []
    for kind in STATUS_KINDS:
        entry = entries[kind]
        effect = entry.get("effect")
        if effect is None:
            continue
        if effect["require_new_permit"]:
            reissue.append(kind)
        narrowed = entry["state"] == "attenuated"
        if (narrowed and kind != "permit") or (not narrowed and effect["constraints"]):
            unsupported.append(kind)
    return unsupported, reissue


def resolve_status(
    out_dir: Path,
    trust_bundle: dict,
    *,
    status_mode: str,
    status_base: str | None,
) -> tuple[dict | None, list[dict]]:
    """Return usable authenticated status, or no status plus a failed check."""
    checks = []

    def record(name: str, ok: bool, details: str) -> None:
        checks.append({"name": name, "ok": ok, "details": details})

    if status_mode == "pull":
        if not status_base:
            record("status_pull_fetch", False, "pull mode requires --status-base")
            return None, checks
        try:
            token = http_get_text(f"{status_base.rstrip('/')}/status/bundle")
        except (OSError, ValueError, HTTPException) as exc:
            record("status_pull_fetch", False, f"unable to fetch status bundle: {exc}")
            return None, checks
        record("status_pull_fetch", True, "fetched status bundle from remote service")
    elif status_mode in {"stapled", "push"}:
        filename = "stapled-status.jws" if status_mode == "stapled" else "push-status-event.jws"
        try:
            token = read_text(out_dir / filename)
        except (OSError, UnicodeError) as exc:
            record("status_input", False, f"unable to read {filename}: {exc}")
            return None, checks
    else:
        raise ValueError(f"unsupported status mode {status_mode}")

    verification = verify_role_bound_jws(
        out_dir=out_dir,
        trust_bundle=trust_bundle,
        token=token,
        expected_typ=STATUS_EVENT_TYP if status_mode == "push" else STATUS_TYP,
        expected_cty=STATUS_EVENT_CONTENT_TYPE if status_mode == "push" else STATUS_CONTENT_TYPE,
        expected_role="status",
    )
    record("status_signature", verification["signature_ok"], verification["details"])
    record("status_signer_role", verification["signer_role_ok"], verification["signer_role_details"])
    if not verification["ok"]:
        return None, checks
    try:
        payload = validated_status_payload(verification["payload"])
    except (KeyError, TypeError, ValueError) as exc:
        record("status_payload", False, f"unusable status payload: {exc}")
        if isinstance(exc, StatusEffectError):
            record("status_attenuation_effect", False, str(exc))
        return None, checks
    record("status_payload", True, "status contains timestamps and entries usable by this demo")
    return payload, checks


def collect_demo_checks(out_dir: Path, *, status_mode: str, status_base: str | None, checks: list[dict],
                        checked_at: datetime) -> None:
    def record(name: str, ok: bool, details: str) -> None:
        checks.append({"name": name, "ok": ok, "details": details})

    record("status_mode", True, f"verification uses {status_mode} status delivery")
    # Decoded JSON and status-store files are generator/service inputs. Only
    # signed artifacts and the selected status delivery are verification inputs.
    trust_bundle = read_json(out_dir / "trust-bundle.json")

    artifact_results = {}
    for artifact_name, spec in ARTIFACT_SPECS.items():
        verification = verify_role_bound_jws(
            out_dir=out_dir,
            trust_bundle=trust_bundle,
            token=read_text(out_dir / f"{spec['basename']}.jws"),
            expected_typ=spec["typ"],
            expected_cty=spec["cty"],
            expected_role=spec["role"],
        )
        artifact_results[artifact_name] = verification
        record(f"{artifact_name}_signature", verification["signature_ok"], verification["details"])

    if not all(result["signature_ok"] for result in artifact_results.values()):
        return
    record("artifact_signer_roles", all(result["signer_role_ok"] for result in artifact_results.values()),
           "artifact tokens are signed by the roles selected by the demo profile")
    if not all(result["signer_role_ok"] for result in artifact_results.values()):
        return

    passport = artifact_results["passport"]["payload"]
    runtime_proof = artifact_results["runtime_proof"]["payload"]
    permit = artifact_results["permit"]["payload"]
    receipt = artifact_results["receipt"]["payload"]
    permit_transaction, _ = validated_permit_scope(permit)

    artifact_kids = {
        artifact_results["passport"]["header"].get("kid"),
        artifact_results["runtime_proof"]["header"].get("kid"),
        artifact_results["permit"]["header"].get("kid"),
        artifact_results["receipt"]["header"].get("kid"),
        runtime_proof.get("presented_key", {}).get("kid"),
    }
    artifact_kids.discard(None)
    record(
        "trust_bundle_coverage",
        artifact_kids.issubset(set(trust_bundle["keys"])),
        "all artifact signer keys and the runtime-presented key resolve in the trust bundle",
    )

    record(
        "runtime_presented_key_owner",
        registered_key(trust_bundle, runtime_proof.get("presented_key", {}).get("kid")).get("owner") == "runtime",
        "the runtime-presented key resolves to a runtime-owned key in the trust bundle",
    )

    status_payload, status_checks = resolve_status(
        out_dir, trust_bundle, status_mode=status_mode, status_base=status_base
    )
    checks.extend(status_checks)

    if status_payload is not None:
        entries = status_payload["entries"]
        generated_at = parse_time(status_payload["generated_at"])
        next_update_at = parse_time(status_payload["next_update_at"])
        record(
            "status_document_window",
            generated_at <= checked_at <= next_update_at,
            "status document is fresh enough for the current verification time",
        )

        status_ids_match = (
            entries.get("passport", {}).get("id") == passport.get("passport_id")
            and entries.get("runtime", {}).get("id") == runtime_proof.get("runtime_id")
            and entries.get("permit", {}).get("id") == permit.get("permit_id")
        )
        record(
            "status_entry_ids",
            status_ids_match,
            "status entries reference the presented passport, runtime, and permit ids",
        )

        record(
            "status_entries_not_blocked",
            all(entries[name]["state"] not in BLOCKING_STATUS_STATES for name in STATUS_KINDS),
            "passport, runtime, and permit are not in a blocking status state",
        )

        unsupported, reissue = status_attenuation_requirements(entries)
        record("status_attenuation_scope", not unsupported,
               f"unsupported narrowing on {', '.join(unsupported)}" if unsupported else "supported status scope")
        attenuated = entries["permit"]["state"] == "attenuated"
        record("status_attenuation_effect", True,
               "the signed status contains mode=narrow, a constraints object and a boolean reissue flag"
               if attenuated else "no attenuation effect is required for this permit state")
        record(
            "status_attenuation_policy",
            not reissue,
            f"new permit required by {', '.join(reissue)}" if reissue else "no status entry requires a new permit",
        )

    record(
        "subject_binding",
        matching_text(runtime_proof.get("subject_id"), passport.get("subject", {}).get("root_id")),
        "runtime proof subject matches passport root id",
    )

    record(
        "actor_binding",
        matching_text(permit.get("actor"), passport.get("subject", {}).get("public_alias"), receipt.get("actor")),
        "permit actor and receipt actor match the passport alias",
    )

    record(
        "audience_binding",
        matching_text(runtime_proof.get("challenge_binding", {}).get("aud"), permit.get("aud"), receipt.get("verifier")),
        "runtime proof audience, mission permit audience, and receipt verifier agree",
    )

    record(
        "proof_of_possession_binding",
        runtime_key_bound(out_dir, trust_bundle, permit, runtime_proof)
        and runtime_proof["presented_key"]["kid"] == artifact_results["receipt"]["header"]["kid"],
        "permit binding matches the runtime-presented key and receipt signer",
    )

    record(
        "receipt_issuer_role",
        receipt.get("issuer_role")
        == trust_bundle["keys"].get(artifact_results["receipt"]["header"].get("kid"), {}).get("owner"),
        "receipt issuer_role matches the observed signer role",
    )

    record("receipt_phase", receipt.get("receipt_phase") == "post_execution",
           "the signed receipt identifies a post-execution result")
    runtime_issued_at = parse_time(runtime_proof["issued_at"])
    runtime_expires_at = parse_time(runtime_proof["expires_at"])
    permit_issued_at = parse_time(permit["issued_at"])
    permit_expires_at = parse_time(permit["constraints"]["expires_at"])
    receipt_started_at = parse_time(receipt["started_at"])
    receipt_finished_at = parse_time(receipt["finished_at"])
    record("receipt_completed", receipt_finished_at <= checked_at,
           "the recorded execution finished by the verification time")
    passport_from = parse_time(passport["valid_from"])
    passport_until = parse_time(passport["valid_until"])
    record(
        "passport_window",
        all(passport_from <= point <= passport_until for point in (receipt_started_at, receipt_finished_at)),
        "the passport covers the recorded execution from start to finish",
    )
    record(
        "permit_runtime_window",
        max(runtime_issued_at, permit_issued_at)
        <= receipt_started_at
        <= receipt_finished_at
        <= min(runtime_expires_at, permit_expires_at),
        "execution starts at or after both issuance times, finishes at or after its start, "
        "and finishes at or before both expiry times",
    )

    record(
        "receipt_transaction_binding",
        isinstance(receipt.get("transaction_id"), str)
        and receipt["transaction_id"] == permit_transaction,
        "receipt transaction matches the mission permit transaction",
    )

    record(
        "receipt_references",
        matching_text(receipt.get("runtime_ref"), runtime_proof.get("runtime_id"))
        and matching_text(receipt.get("permit_ref"), permit.get("permit_id")),
        "receipt references the generated runtime proof and mission permit",
    )


def verify_demo(out_dir: Path, *, status_mode: str, status_base: str | None = None) -> dict:
    # A later operational error must not leave an earlier success in place.
    report_path = out_dir / "verification-report.json"
    report_path.unlink(missing_ok=True)
    checks = []
    checked_at = utc_now()
    try:
        collect_demo_checks(out_dir, status_mode=status_mode, status_base=status_base, checks=checks, checked_at=checked_at)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        # This legacy demo reads JSON and interprets its fields directly. Input
        # read/shape/time failures deny verification; output errors still raise.
        checks.append({"name": "verification_input", "ok": False,
                       "details": f"unable to interpret verification input ({type(exc).__name__}): {exc}"})
    ok = all(check["ok"] for check in checks)
    report = {
        "ok": ok,
        "checked_at": iso(checked_at),
        "status_mode": status_mode,
        "checks": checks,
        "request_binding": {"status": "not_checked", "pass": None,
                            "binding_requirement_met": False,
                            "cause": "LEGACY_AER_PROFILE"},
    }
    write_json(report_path, report)
    return report


def resign_artifact(bundle: dict, artifact_name: str, out_dir: Path) -> None:
    spec = ARTIFACT_SPECS[artifact_name]
    key_info = {
        "kid": f"{spec['role']}-key-1",
        "alg": "ES256",
        "private_key": key_path(out_dir, spec["role"], "private"),
    }
    bundle["artifacts"][artifact_name]["token"] = build_compact_jws(
        bundle["artifacts"][artifact_name]["payload"],
        key_info=key_info,
        typ=spec["typ"],
        cty=spec["cty"],
    )


def refresh_status_tokens(bundle: dict, out_dir: Path) -> None:
    issue_status_tokens(bundle, out_dir)


def negative_cases(template_dir: Path) -> list[dict]:
    def tamper_passport_alias(bundle: dict) -> None:
        def mutate(payload: dict) -> None:
            payload["subject"]["public_alias"] = "agent:public:tampered-reviewer-01"

        mutate(bundle["artifacts"]["passport"]["payload"])
        bundle["artifacts"]["passport"]["token"] = tamper_compact_jws_payload(
            bundle["artifacts"]["passport"]["token"], mutate
        )

    def runtime_subject_mismatch(bundle: dict) -> None:
        bundle["artifacts"]["runtime_proof"]["payload"]["subject_id"] = "did:key:z6MknUnexpectedRoot"
        resign_artifact(bundle, "runtime_proof", template_dir)

    def permit_revoked_push(bundle: dict) -> None:
        bundle["status_store"]["entries"]["permit"]["state"] = "revoked"
        refresh_status_tokens(bundle, template_dir)

    def audience_mismatch(bundle: dict) -> None:
        bundle["artifacts"]["permit"]["payload"]["aud"] = "https://verifier.example/other"
        resign_artifact(bundle, "permit", template_dir)

    def pop_mismatch(bundle: dict) -> None:
        bundle["artifacts"]["permit"]["payload"]["proof_binding"]["kid"] = "issuer-key-1"
        bundle["artifacts"]["permit"]["payload"]["proof_binding"]["spki_sha256"] = bundle["trust_bundle"]["keys"][
            "issuer-key-1"
        ]["spki_sha256"]
        resign_artifact(bundle, "permit", template_dir)

    def receipt_reference_mismatch(bundle: dict) -> None:
        bundle["artifacts"]["receipt"]["payload"]["runtime_ref"] = "arp:unexpected-runtime"
        resign_artifact(bundle, "receipt", template_dir)

    def expired_permit_window(bundle: dict) -> None:
        bundle["artifacts"]["permit"]["payload"]["constraints"]["expires_at"] = "2026-04-15T01:59:59Z"
        resign_artifact(bundle, "permit", template_dir)

    def stale_stapled_status(bundle: dict) -> None:
        bundle["status_store"]["generated_at"] = "2026-04-15T01:00:00Z"
        bundle["status_store"]["next_update_at"] = "2026-04-15T01:05:00Z"
        refresh_status_tokens(bundle, template_dir)

    def attenuated_without_effect(bundle: dict) -> None:
        bundle["status_store"]["entries"]["permit"]["state"] = "attenuated"
        bundle["status_store"]["entries"]["permit"].pop("effect", None)
        bundle["status_store"]["entries"]["permit"]["reason"] = "policy-tightened"
        refresh_status_tokens(bundle, template_dir)

    def attenuated_requires_new_permit(bundle: dict) -> None:
        bundle["status_store"]["entries"]["permit"]["state"] = "attenuated"
        bundle["status_store"]["entries"]["permit"]["reason"] = "manual-approval-escalation"
        bundle["status_store"]["entries"]["permit"]["effect"] = {
            "mode": "narrow",
            "require_new_permit": True,
            "constraints": {
                "max_amount_usd": 0,
                "max_redelegation_depth": 0,
                "tool_allowlist": ["read_file"],
                "approval": {"mode": "human_required"},
            },
        }
        refresh_status_tokens(bundle, template_dir)

    return [
        {
            "name": "tampered-passport-alias",
            "description": "passport alias is modified inside the compact JWS without a new issuer signature",
            "expected_failed_checks": ["passport_signature"],
            "status_mode": "stapled",
            "mutate": tamper_passport_alias,
        },
        {
            "name": "runtime-subject-mismatch",
            "description": "runtime proof is legitimately re-signed but rebound to a different subject",
            "expected_failed_checks": ["subject_binding"],
            "status_mode": "stapled",
            "mutate": runtime_subject_mismatch,
        },
        {
            "name": "permit-revoked-push",
            "description": "push status event marks the permit as revoked",
            "expected_failed_checks": ["status_entries_not_blocked"],
            "status_mode": "push",
            "mutate": permit_revoked_push,
        },
        {
            "name": "audience-mismatch",
            "description": "mission permit is re-signed for a different verifier audience",
            "expected_failed_checks": ["audience_binding"],
            "status_mode": "stapled",
            "mutate": audience_mismatch,
        },
        {
            "name": "proof-of-possession-mismatch",
            "description": "mission permit binds to the wrong runtime key while remaining correctly signed",
            "expected_failed_checks": ["proof_of_possession_binding"],
            "status_mode": "stapled",
            "mutate": pop_mismatch,
        },
        {
            "name": "receipt-reference-mismatch",
            "description": "receipt is re-signed but points at the wrong runtime reference",
            "expected_failed_checks": ["receipt_references"],
            "status_mode": "stapled",
            "mutate": receipt_reference_mismatch,
        },
        {
            "name": "expired-permit-window",
            "description": "mission permit expires before the recorded execution starts",
            "expected_failed_checks": ["permit_runtime_window"],
            "status_mode": "stapled",
            "mutate": expired_permit_window,
        },
        {
            "name": "stale-stapled-status",
            "description": "stapled status is no longer fresh enough for verification",
            "expected_failed_checks": ["status_document_window"],
            "status_mode": "stapled",
            "mutate": stale_stapled_status,
        },
        {
            "name": "attenuated-without-effect",
            "description": "permit status is attenuated but does not carry machine-readable narrowing instructions",
            "expected_failed_checks": ["status_attenuation_effect"],
            "status_mode": "stapled",
            "mutate": attenuated_without_effect,
        },
        {
            "name": "attenuated-requires-new-permit",
            "description": "permit status is attenuated and explicitly requires permit re-issuance",
            "expected_failed_checks": ["status_attenuation_policy"],
            "status_mode": "stapled",
            "mutate": attenuated_requires_new_permit,
        },
    ]


def run_negative_tests(source_dir: Path) -> dict:
    report_path = source_dir / "negative-test-report.json"
    report_path.unlink(missing_ok=True)
    base_bundle = load_bundle(source_dir)
    negative_dir = source_dir / "negative-cases"
    with staged_output(negative_dir) as staged:
        results = evaluate_negative_cases(source_dir, base_bundle, staged)
        summary = {
            "ok": all(result["ok"] for result in results),
            "checked_at": iso(utc_now()),
            "results": results,
        }
        new_report = staged.parent / report_path.name
        write_json(new_report, summary)
        publish_output(staged, negative_dir)
        new_report.replace(report_path)
    return summary


def evaluate_negative_cases(source_dir: Path, base_bundle: dict, negative_dir: Path) -> list[dict]:
    results = []
    for case in negative_cases(source_dir):
        case_dir = negative_dir / case["name"]
        bundle = copy.deepcopy(base_bundle)
        case["mutate"](bundle)
        write_bundle(case_dir, bundle, source_dir)
        report = verify_demo(case_dir, status_mode=case["status_mode"])
        actual_failed = sorted(check["name"] for check in report["checks"] if not check["ok"])
        expected_failed = sorted(case["expected_failed_checks"])
        results.append(
            {
                "name": case["name"],
                "description": case["description"],
                "status_mode": case["status_mode"],
                "expected_failed_checks": expected_failed,
                "actual_failed_checks": actual_failed,
                "ok": set(expected_failed).issubset(actual_failed),
                "report": f"negative-cases/{case['name']}/verification-report.json",
            }
        )

    return results


def fetch_status(out_dir: Path, *, status_base: str, mode: str) -> None:
    base = status_base.rstrip("/")
    targets = []
    if mode in ("stapled", "all"):
        targets.append((f"{base}/status/stapled", out_dir / "stapled-status.jws"))
    if mode in ("push", "all"):
        targets.append((f"{base}/events/latest", out_dir / "push-status-event.jws"))

    for url, path in targets:
        token = http_get_text(url)
        clear_bundle_reports(out_dir)
        write_text(path, token)


def serve_status(out_dir: Path, *, host: str, port: int) -> None:
    class StatusHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"

            try:
                if path == "/healthz":
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json")
                    body = json.dumps({"ok": True}).encode("utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                if path == "/status/bundle":
                    self.send_token(build_status_token(out_dir, "bundle"))
                    return

                if path == "/status/stapled":
                    self.send_token(build_status_token(out_dir, "stapled"))
                    return

                if path == "/events/latest":
                    self.send_token(build_status_token(out_dir, "event"))
                    return

                parts = path.strip("/").split("/")
                if len(parts) == 3 and parts[0] == "status" and parts[1] in {"passport", "runtime", "permit"}:
                    object_type = parts[1]
                    requested_id = unquote(parts[2])
                    status_store = read_json(out_dir / "status-store.json")
                    entry = status_store["entries"][object_type]
                    if entry["id"] != requested_id:
                        self.send_error(HTTPStatus.NOT_FOUND, "status entry not found")
                        return
                    payload = build_status_entry_payload(status_store, object_type)
                    self.send_token(_sign_status_payload(out_dir, read_json(out_dir / "trust-bundle.json"), payload))
                    return

                self.send_error(HTTPStatus.NOT_FOUND, "unsupported path")
            except Exception:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "status service unavailable")

        def send_token(self, token: str) -> None:
            body = token.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/jose")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

    server = ThreadingHTTPServer((host, port), StatusHandler)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Minimal AL2 demo for Verifiable Agent Trust Envelope")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate-demo", help="generate a demo bundle")
    generate.add_argument("--out", required=True, help="output directory")

    verify = subparsers.add_parser("verify-demo", help="verify a generated demo bundle")
    verify.add_argument("--dir", required=True, help="bundle directory")
    verify.add_argument(
        "--status-mode",
        choices=("pull", "stapled", "push"),
        default="stapled",
        help="how the verifier resolves status",
    )
    verify.add_argument("--status-base", help="base URL for the status service in pull mode")

    negative = subparsers.add_parser(
        "run-negative-tests", help="create tampered bundles and verify that checks fail"
    )
    negative.add_argument("--dir", required=True, help="bundle directory")

    fetch = subparsers.add_parser("fetch-status", help="fetch stapled or push status artifacts from the service")
    fetch.add_argument("--dir", required=True, help="bundle directory")
    fetch.add_argument("--status-base", required=True, help="base URL of the status service")
    fetch.add_argument(
        "--mode",
        choices=("stapled", "push", "all"),
        default="all",
        help="which status delivery artifacts to fetch",
    )

    serve = subparsers.add_parser("serve-status", help="run the minimal status service")
    serve.add_argument("--dir", required=True, help="bundle directory")
    serve.add_argument("--host", default="127.0.0.1", help="host to bind")
    serve.add_argument("--port", type=int, default=8042, help="port to bind")

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "generate-demo":
        generate_demo(Path(args.out))
    elif args.command == "verify-demo":
        verify_demo(Path(args.dir), status_mode=args.status_mode, status_base=args.status_base)
    elif args.command == "run-negative-tests":
        if not run_negative_tests(Path(args.dir))["ok"]:
            raise SystemExit("one or more negative cases differed from the expected result")
    elif args.command == "fetch-status":
        fetch_status(Path(args.dir), status_base=args.status_base, mode=args.mode)
    elif args.command == "serve-status":
        serve_status(Path(args.dir), host=args.host, port=args.port)


if __name__ == "__main__":
    try:
        main()
    except DemoOutputError as exc:
        raise SystemExit(str(exc)) from exc
