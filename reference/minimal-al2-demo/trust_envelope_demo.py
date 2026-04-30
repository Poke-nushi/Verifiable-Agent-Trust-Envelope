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
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlparse
from urllib.request import urlopen

OPENSSL = shutil.which("openssl")
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


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def ensure_openssl() -> str:
    if not OPENSSL:
        raise SystemExit("OpenSSL is required for this demo but was not found in PATH.")
    return OPENSSL


def run_command(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(args, capture_output=True, check=False)
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
    return json.loads(path.read_text(encoding="utf-8"))


def write_text(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data.rstrip() + "\n", encoding="utf-8")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


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


def spki_sha256(public_key: Path) -> str:
    openssl = ensure_openssl()
    der = run_command(
        [openssl, "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"]
    ).stdout
    digest = hashlib.sha256(der).hexdigest()
    return f"sha256:{digest}"


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


def verify_bytes(data: bytes, signature: bytes, public_key: Path) -> bool:
    openssl = ensure_openssl()
    with tempfile.TemporaryDirectory() as tmp_dir_name:
        tmp_dir = Path(tmp_dir_name)
        payload_path = tmp_dir / "payload.bin"
        signature_path = tmp_dir / "signature.bin"
        payload_path.write_bytes(data)
        signature_path.write_bytes(signature)
        result = run_command(
            [
                openssl,
                "dgst",
                "-sha256",
                "-verify",
                str(public_key),
                "-signature",
                str(signature_path),
                str(payload_path),
            ],
            check=False,
        )
        return result.returncode == 0


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
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("compact JWS must have three parts")
    protected = json.loads(b64url_decode(parts[0]).decode("utf-8"))
    payload = json.loads(b64url_decode(parts[1]).decode("utf-8"))
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
        "version": "app-trust-0.1",
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


def build_demo_bundle(out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)

    now = utc_now()
    passport_expires = now + timedelta(days=30)
    runtime_expires = now + timedelta(minutes=5)
    permit_expires = now + timedelta(minutes=10)
    finish = now + timedelta(seconds=27)

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
            "aud": "https://verifier.example/a2a",
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
        "aud": "https://verifier.example/a2a",
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

    receipt = {
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
        "started_at": iso(now),
        "finished_at": iso(finish),
        "outcome": "success",
    }

    status_store = build_status_store(now, passport, runtime_proof, permit)

    artifacts = {
        "passport": {"payload": passport},
        "runtime_proof": {"payload": runtime_proof},
        "permit": {"payload": permit},
        "receipt": {"payload": receipt},
    }
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
    for artifact_name, spec in ARTIFACT_SPECS.items():
        payload = bundle["artifacts"][artifact_name]["payload"]
        bundle["artifacts"][artifact_name]["token"] = build_compact_jws(
            payload,
            key_info=key_lookup[spec["role"]],
            typ=spec["typ"],
            cty=spec["cty"],
        )


def issue_status_tokens(bundle: dict, out_dir: Path, *, keys: dict[str, dict] | None = None) -> None:
    key_lookup = keys or {
        "status": {
            "kid": "status-key-1",
            "alg": "ES256",
            "private_key": key_path(out_dir, "status", "private"),
            "public_key": key_path(out_dir, "status", "public"),
        }
    }
    status_key = key_lookup["status"]
    bundle["status_tokens"]["stapled"] = build_compact_jws(
        build_status_bundle_payload(bundle["status_store"], delivery="stapled"),
        key_info=status_key,
        typ=STATUS_TYP,
        cty=STATUS_CONTENT_TYPE,
    )
    bundle["status_tokens"]["push"] = build_compact_jws(
        build_status_event_payload(bundle["status_store"]),
        key_info=status_key,
        typ=STATUS_EVENT_TYP,
        cty=STATUS_EVENT_CONTENT_TYPE,
    )


def write_bundle(out_dir: Path, bundle: dict, template_dir: Path | None = None) -> None:
    if template_dir:
        if out_dir.exists():
            shutil.rmtree(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        shutil.copytree(template_dir / "keys", out_dir / "keys")

    write_json(out_dir / "trust-bundle.json", bundle["trust_bundle"])
    write_json(out_dir / "status-store.json", bundle["status_store"])
    write_text(out_dir / "stapled-status.jws", bundle["status_tokens"]["stapled"])
    write_text(out_dir / "push-status-event.jws", bundle["status_tokens"]["push"])

    for artifact_name, spec in ARTIFACT_SPECS.items():
        basename = spec["basename"]
        artifact = bundle["artifacts"][artifact_name]
        write_json(out_dir / f"{basename}.json", artifact["payload"])
        write_text(out_dir / f"{basename}.jws", artifact["token"])


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


def resolve_public_key(out_dir: Path, trust_bundle: dict, kid: str) -> Path | None:
    key_entry = trust_bundle["keys"].get(kid)
    if not key_entry:
        return None
    return out_dir / key_entry["public_key"]


def verify_compact_jws(
    *,
    out_dir: Path,
    trust_bundle: dict,
    token: str,
    expected_typ: str,
    expected_cty: str,
) -> dict:
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
    key_entry = trust_bundle["keys"].get(kid)
    public_key = resolve_public_key(out_dir, trust_bundle, kid)
    if not public_key or not public_key.exists():
        return {
            "ok": False,
            "header": header,
            "payload": payload,
            "details": f"unknown kid {kid}",
        }

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

    if header.get("alg") != key_entry.get("alg"):
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

    ok = verify_bytes(signing_input, signature_der, public_key)
    return {
        "ok": ok,
        "header": header,
        "payload": payload,
        "details": f"verified compact JWS with kid {kid}",
    }


def build_status_token(out_dir: Path, kind: str, *, object_type: str | None = None) -> str:
    bundle = load_bundle(out_dir)
    status_key = {
        "kid": "status-key-1",
        "alg": "ES256",
        "private_key": key_path(out_dir, "status", "private"),
    }
    if kind == "bundle":
        payload = build_status_bundle_payload(bundle["status_store"], delivery="pull")
        return build_compact_jws(payload, key_info=status_key, typ=STATUS_TYP, cty=STATUS_CONTENT_TYPE)
    if kind == "stapled":
        payload = build_status_bundle_payload(bundle["status_store"], delivery="stapled")
        return build_compact_jws(payload, key_info=status_key, typ=STATUS_TYP, cty=STATUS_CONTENT_TYPE)
    if kind == "event":
        payload = build_status_event_payload(bundle["status_store"])
        return build_compact_jws(
            payload,
            key_info=status_key,
            typ=STATUS_EVENT_TYP,
            cty=STATUS_EVENT_CONTENT_TYPE,
        )
    if kind == "entry" and object_type:
        payload = build_status_entry_payload(bundle["status_store"], object_type)
        return build_compact_jws(payload, key_info=status_key, typ=STATUS_TYP, cty=STATUS_CONTENT_TYPE)
    raise ValueError(f"unsupported status token kind {kind}")


def http_get_text(url: str) -> str:
    with urlopen(url) as response:
        return response.read().decode("utf-8").strip()


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


def resolve_status(
    out_dir: Path,
    trust_bundle: dict,
    *,
    status_mode: str,
    status_base: str | None,
) -> tuple[dict, list[dict]]:
    checks = []

    def record(name: str, ok: bool, details: str) -> None:
        checks.append({"name": name, "ok": ok, "details": details})

    if status_mode == "pull":
        if not status_base:
            raise SystemExit("pull mode requires --status-base")
        try:
            token = http_get_text(f"{status_base.rstrip('/')}/status/bundle")
        except (HTTPError, URLError) as exc:
            record("status_pull_fetch", False, f"unable to fetch status bundle: {exc}")
            return {"entries": {}}, checks
        record("status_pull_fetch", True, "fetched status bundle from remote service")
        verification = verify_compact_jws(
            out_dir=out_dir,
            trust_bundle=trust_bundle,
            token=token,
            expected_typ=STATUS_TYP,
            expected_cty=STATUS_CONTENT_TYPE,
        )
        record("status_signature", verification["ok"], verification["details"])
        if not verification["payload"]:
            return {"entries": {}}, checks
        return normalize_status_payload(verification["payload"]), checks

    if status_mode == "stapled":
        token = read_text(out_dir / "stapled-status.jws")
        verification = verify_compact_jws(
            out_dir=out_dir,
            trust_bundle=trust_bundle,
            token=token,
            expected_typ=STATUS_TYP,
            expected_cty=STATUS_CONTENT_TYPE,
        )
        record("status_signature", verification["ok"], verification["details"])
        if not verification["payload"]:
            return {"entries": {}}, checks
        return normalize_status_payload(verification["payload"]), checks

    if status_mode == "push":
        token = read_text(out_dir / "push-status-event.jws")
        verification = verify_compact_jws(
            out_dir=out_dir,
            trust_bundle=trust_bundle,
            token=token,
            expected_typ=STATUS_EVENT_TYP,
            expected_cty=STATUS_EVENT_CONTENT_TYPE,
        )
        record("status_signature", verification["ok"], verification["details"])
        if not verification["payload"]:
            return {"entries": {}}, checks
        return normalize_status_payload(verification["payload"]), checks

    raise ValueError(f"unsupported status mode {status_mode}")


def verify_demo(out_dir: Path, *, status_mode: str, status_base: str | None = None) -> dict:
    bundle = load_bundle(out_dir)
    trust_bundle = bundle["trust_bundle"]

    checks = []

    def record(name: str, ok: bool, details: str) -> None:
        checks.append({"name": name, "ok": ok, "details": details})

    record("status_mode", True, f"verification uses {status_mode} status delivery")

    artifact_results = {}
    for artifact_name, spec in ARTIFACT_SPECS.items():
        verification = verify_compact_jws(
            out_dir=out_dir,
            trust_bundle=trust_bundle,
            token=bundle["artifacts"][artifact_name]["token"],
            expected_typ=spec["typ"],
            expected_cty=spec["cty"],
        )
        artifact_results[artifact_name] = verification
        record(f"{artifact_name}_signature", verification["ok"], verification["details"])

    passport = artifact_results["passport"]["payload"]
    runtime_proof = artifact_results["runtime_proof"]["payload"]
    permit = artifact_results["permit"]["payload"]
    receipt = artifact_results["receipt"]["payload"]

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
        "artifact_signer_roles",
        trust_bundle["keys"].get(artifact_results["passport"]["header"].get("kid"), {}).get("owner") == "issuer"
        and trust_bundle["keys"].get(artifact_results["runtime_proof"]["header"].get("kid"), {}).get("owner")
        == "attestor"
        and trust_bundle["keys"].get(artifact_results["permit"]["header"].get("kid"), {}).get("owner") == "broker",
        "passport, runtime proof, and permit tokens are signed by the expected demo roles",
    )

    record(
        "runtime_presented_key_owner",
        trust_bundle["keys"].get(runtime_proof.get("presented_key", {}).get("kid"), {}).get("owner") == "runtime",
        "the runtime-presented key resolves to a runtime-owned key in the trust bundle",
    )

    status_payload, status_checks = resolve_status(
        out_dir, trust_bundle, status_mode=status_mode, status_base=status_base
    )
    checks.extend(status_checks)

    entries = status_payload.get("entries", {})
    if status_payload:
        now = utc_now()
        generated_at = parse_time(status_payload["generated_at"])
        next_update_at = parse_time(status_payload["next_update_at"])
        record(
            "status_document_window",
            generated_at <= now <= next_update_at,
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

        blocking_states = {"suspended", "revoked", "quarantined"}
        record(
            "status_entries_not_blocked",
            all(entries.get(name, {}).get("state") not in blocking_states for name in ("passport", "runtime", "permit")),
            "passport, runtime, and permit are not in a blocking status state",
        )

        permit_status = entries.get("permit", {})
        record(
            "status_attenuation_effect",
            permit_status.get("state") != "attenuated" or bool(permit_status.get("effect")),
            "attenuated permit entries include a machine-readable effect object",
        )
        attenuation_effect = permit_status.get("effect", {})
        record(
            "status_attenuation_policy",
            permit_status.get("state") != "attenuated"
            or (
                attenuation_effect.get("mode") == "narrow"
                and attenuation_effect.get("require_new_permit") is False
            ),
            "attenuated permits can proceed only when the effect is narrow and does not require permit re-issuance",
        )

    record(
        "subject_binding",
        runtime_proof.get("subject_id") == passport.get("subject", {}).get("root_id"),
        "runtime proof subject matches passport root id",
    )

    record(
        "actor_binding",
        permit.get("actor") == passport.get("subject", {}).get("public_alias")
        and receipt.get("actor") == permit.get("actor"),
        "permit actor and receipt actor match the passport alias",
    )

    record(
        "audience_binding",
        runtime_proof.get("challenge_binding", {}).get("aud")
        == permit.get("aud")
        == receipt.get("verifier"),
        "runtime proof audience, mission permit audience, and receipt verifier agree",
    )

    record(
        "proof_of_possession_binding",
        permit.get("proof_binding", {}).get("kid")
        == runtime_proof.get("presented_key", {}).get("kid")
        == artifact_results["receipt"]["header"].get("kid")
        and permit.get("proof_binding", {}).get("spki_sha256")
        == runtime_proof.get("presented_key", {}).get("spki_sha256"),
        "permit binding matches the runtime-presented key and receipt signer",
    )

    record(
        "receipt_issuer_role",
        receipt.get("issuer_role")
        == trust_bundle["keys"].get(artifact_results["receipt"]["header"].get("kid"), {}).get("owner"),
        "receipt issuer_role matches the observed signer role",
    )

    runtime_issued_at = parse_time(runtime_proof["issued_at"])
    runtime_expires_at = parse_time(runtime_proof["expires_at"])
    permit_issued_at = parse_time(permit["issued_at"])
    permit_expires_at = parse_time(permit["constraints"]["expires_at"])
    receipt_started_at = parse_time(receipt["started_at"])
    receipt_finished_at = parse_time(receipt["finished_at"])
    record(
        "permit_runtime_window",
        runtime_issued_at <= receipt_started_at <= permit_expires_at
        and permit_issued_at <= receipt_started_at
        and receipt_finished_at <= runtime_expires_at,
        "execution starts after runtime and permit issuance and completes before runtime and permit expiry",
    )

    record(
        "receipt_references",
        receipt.get("runtime_ref") == runtime_proof.get("runtime_id")
        and receipt.get("permit_ref") == permit.get("permit_id"),
        "receipt references the generated runtime proof and mission permit",
    )

    ok = all(check["ok"] for check in checks)
    report = {
        "ok": ok,
        "checked_at": iso(utc_now()),
        "status_mode": status_mode,
        "checks": checks,
    }
    write_json(out_dir / "verification-report.json", report)
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
            "expected_failed_checks": ["passport_signature", "actor_binding"],
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
    base_bundle = load_bundle(source_dir)
    negative_dir = source_dir / "negative-cases"
    if negative_dir.exists():
        shutil.rmtree(negative_dir)
    negative_dir.mkdir(parents=True, exist_ok=True)

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
                "report": str((case_dir / "verification-report.json").relative_to(source_dir)),
            }
        )

    summary = {
        "ok": all(result["ok"] for result in results),
        "checked_at": iso(utc_now()),
        "results": results,
    }
    write_json(source_dir / "negative-test-report.json", summary)
    return summary


def fetch_status(out_dir: Path, *, status_base: str, mode: str) -> None:
    base = status_base.rstrip("/")
    targets = []
    if mode in ("stapled", "all"):
        targets.append((f"{base}/status/stapled", out_dir / "stapled-status.jws"))
    if mode in ("push", "all"):
        targets.append((f"{base}/events/latest", out_dir / "push-status-event.jws"))

    for url, path in targets:
        token = http_get_text(url)
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
                    self.send_token(build_status_token(out_dir, "entry", object_type=object_type))
                    return

                self.send_error(HTTPStatus.NOT_FOUND, "unsupported path")
            except Exception as exc:  # pragma: no cover - demo error path
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

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
        bundle = build_demo_bundle(Path(args.out))
        write_bundle(Path(args.out), bundle)
    elif args.command == "verify-demo":
        verify_demo(Path(args.dir), status_mode=args.status_mode, status_base=args.status_base)
    elif args.command == "run-negative-tests":
        run_negative_tests(Path(args.dir))
    elif args.command == "fetch-status":
        fetch_status(Path(args.dir), status_base=args.status_base, mode=args.mode)
    elif args.command == "serve-status":
        serve_status(Path(args.dir), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
