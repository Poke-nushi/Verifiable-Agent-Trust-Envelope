"""Single-use-case demonstration contract. No keys or network authority discovery."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference/execution-evidence-demo"))
from admission import Authorization, assert_authorization  # noqa: E402
from demo_contract import decode, encode, need, time_value, validate_operation  # noqa: E402

PROFILE = "local-runtime-revocation-demo-v1"
STATUS_TYP = "vate-local-runtime-status+jws"
PROOF_TYP = "vate-local-operation-possession+jws"
MAX = 2 * 1024 * 1024
STATUS_FIELDS = {"profile", "object_type", "runtime", "runtime_spki_sha256", "issuer",
                 "epoch", "sequence", "state", "generated_at", "next_update_at", "last_changed_at"}
PROOF_FIELDS = {"profile", "runtime", "runtime_spki_sha256", "receiver", "provider",
                "operation_key", "input_sha256", "admission_sha256", "attempt_id", "nonce",
                "issued_at", "expires_at"}
AUTH_FIELDS = tuple(Authorization.__dataclass_fields__)
OPENSSL = shutil.which("openssl")
VERIFICATION_ERRORS = {"executable_missing", "launch_failed", "timeout", "process_failed", "io_failed"}


class VerificationUnavailable(RuntimeError):
    """Local verifier could not finish; never evidence that an input is invalid."""
    def __init__(self, code):
        self.code = code
        super().__init__("local signature verifier unavailable: " + code)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def unb64(text: str) -> bytes:
    need(isinstance(text, str) and len(text) <= MAX * 2, "invalid base64 field")
    raw = base64.b64decode(text, validate=True)
    need(b64(raw) == text, "noncanonical base64 field")
    return raw


def url64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unurl64(text: str) -> bytes:
    need(isinstance(text, str) and re.fullmatch(r"[A-Za-z0-9_-]+", text) is not None,
         "noncanonical JWS segment")
    raw = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    need(url64(raw) == text, "noncanonical JWS pad bits")
    return raw


def exact(value, keys):
    need(isinstance(value, dict) and set(value) == set(keys), "unexpected object fields")


def integer(value):
    need(type(value) is int and 0 <= value <= 9007199254740991, "invalid integer")
    return value


def time_microseconds(value: str) -> int:
    """Preserve the original UTC instant without a floating-point timestamp."""
    elapsed = time_value(value) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (elapsed.days * 86400 + elapsed.seconds) * 1_000_000 + elapsed.microseconds


def safe_read(path: Path, limit=MAX) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(f.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
             "unsafe or oversized file")
        data = f.read(limit + 1)
        need(len(data) <= limit, "oversized file")
        return data


def exclusive_write(path: Path, raw: bytes):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())


def openssl(*args, check=True):
    if OPENSSL is None:
        raise VerificationUnavailable("executable_missing")
    try:
        result = subprocess.run([OPENSSL, *map(str, args)], capture_output=True, timeout=10)
    except subprocess.TimeoutExpired as exc:
        raise VerificationUnavailable("timeout") from exc
    except OSError as exc:
        raise VerificationUnavailable("launch_failed") from exc
    except subprocess.SubprocessError as exc:
        raise VerificationUnavailable("process_failed") from exc
    if result.returncode < 0:
        raise VerificationUnavailable("process_failed")
    if check:
        need(result.returncode == 0, "OpenSSL operation failed")
    return result


def spki(pem: bytes) -> str:
    with tempfile.TemporaryDirectory(prefix="vate-public-key-") as td:
        p = Path(td) / "public.pem"
        p.write_bytes(pem)
        der = openssl("pkey", "-pubin", "-in", p, "-outform", "DER").stdout
    # This local profile chooses only id-ecPublicKey / prime256v1, uncompressed.
    prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
    need(len(der) == 91 and der.startswith(prefix), "expected P-256 SPKI")
    return "sha256:" + sha(der)


def raw_to_der(signature: bytes) -> bytes:
    need(len(signature) == 64, "ES256 signature must contain 64 bytes")
    parts = []
    for raw in (signature[:32], signature[32:]):
        n = raw.lstrip(b"\0") or b"\0"
        if n[0] & 128:
            n = b"\0" + n
        parts.append(b"\x02" + bytes([len(n)]) + n)
    body = b"".join(parts)
    return b"\x30" + bytes([len(body)]) + body


@dataclass(frozen=True)
class Verified:
    payload: dict
    raw: bytes
    signing_input: bytes

    @property
    def raw_sha256(self):
        return sha(self.raw)

    @property
    def signing_input_sha256(self):
        return sha(self.signing_input)


def verify_jws(raw: bytes, pem: bytes, typ: str) -> Verified:
    need(type(raw) is bytes and 0 < len(raw) <= 65536, "invalid JWS size/type")
    parts = raw.decode("ascii").split(".")
    need(len(parts) == 3, "compact JWS requires three segments")
    header, payload = [decode(unurl64(x)) for x in parts[:2]]
    exact(header, {"alg", "typ", "kid"})
    need(header["alg"] == "ES256" and header["typ"] == typ, "unsupported algorithm/type")
    need(type(header["kid"]) is str and 0 < len(header["kid"]) <= 128, "invalid key label")
    # kid is only a label. The selected public key, never kid/jku/x5u, is authoritative.
    signature = raw_to_der(unurl64(parts[2]))
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    try:
        with tempfile.TemporaryDirectory(prefix="vate-verify-") as td:
            d = Path(td)
            (d / "key.pem").write_bytes(pem)
            (d / "input").write_bytes(signing_input)
            (d / "signature").write_bytes(signature)
            result = openssl("dgst", "-sha256", "-verify", d / "key.pem", "-signature",
                             d / "signature", d / "input", check=False)
    except OSError as exc:
        raise VerificationUnavailable("io_failed") from exc
    if result.returncode != 0:
        # A nonzero process exit alone is not a cryptographic rejection.
        if result.returncode == 1 and result.stdout.strip() == b"Verification failure":
            raise ValueError("signature_invalid")
        raise VerificationUnavailable("process_failed")
    return Verified(payload, raw, signing_input)


class Selection:
    """Receiver-owned configuration, explicitly separate from caller-supplied artifacts."""
    def __init__(self, raw: bytes):
        self.raw = raw
        self.data = decode(raw)
        c = self.data
        exact(c, {"profile", "receiver", "provider", "runtime", "authority", "epoch", "max_age",
                  "runtime_public_pem", "authority_public_pem", "runtime_spki_sha256",
                  "authority_spki_sha256", "policy", "resource", "permit_uri", "authorization"})
        need(c["profile"] == PROFILE and type(c["max_age"]) is int and c["max_age"] == 60,
             "unsupported selection")
        for name in ("receiver", "provider", "runtime", "authority", "epoch", "resource", "permit_uri"):
            need(type(c[name]) is str and 0 < len(c[name]) < 256, "invalid selection identity")
        for role in ("runtime", "authority"):
            need(spki(unb64(c[role + "_public_pem"])) == c[role + "_spki_sha256"], "SPKI mismatch")
        exact(c["authorization"], AUTH_FIELDS)
        # This profile requires an original allow, so every capsule preimage,
        # including its effective operation, must be present as canonical bytes.
        originals = {k: unb64(v) for k, v in c["authorization"].items()}
        record = decode(originals["record"])
        need(isinstance(record, dict) and "evaluated_at" in record,
             "invalid authorization record")
        time_value(record["evaluated_at"])
        self.auth = Authorization(**originals)
        assert_authorization(self.auth, c["policy"], c["resource"], c["permit_uri"])
        receipt = decode(self.auth.receipt)
        need(self.auth.effective is not None and receipt["decision"]["outcome"] == "allow",
             "this local profile requires an original allow")
        self.operation = decode(self.auth.effective)
        validate_operation(self.operation, c["resource"])
        need(decode(self.auth.request)["runtime"] == c["runtime"], "admission runtime mismatch")
        permit = decode(self.auth.permit)
        self.not_before_us = max(time_microseconds(item["issued_at"]) for item in (permit, receipt))
        self.expires_us = min(time_microseconds(item["expires_at"]) for item in (permit, receipt))
        need(self.not_before_us < self.expires_us, "empty admission validity window")

    def admission_current(self, now: int) -> bool:
        checked_us = integer(now) * 1_000_000
        return self.not_before_us <= checked_us < self.expires_us

    def binding(self):
        c = self.data
        return {"profile": PROFILE, "runtime": c["runtime"],
                "runtime_spki_sha256": c["runtime_spki_sha256"], "receiver": c["receiver"],
                "provider": c["provider"], "operation_key": self.operation["operation_key"],
                "input_sha256": sha(self.auth.effective), "admission_sha256": sha(self.auth.receipt)}

    def status(self, raw: bytes, now: int) -> Verified:
        return self.status_at(self.authenticate_status(raw), now)

    def authenticate_status(self, raw: bytes) -> Verified:
        return verify_jws(raw, unb64(self.data["authority_public_pem"]), STATUS_TYP)

    def status_at(self, verified: Verified, now: int) -> Verified:
        c = self.data
        s = verified.payload
        exact(s, STATUS_FIELDS)
        for key, value in {"profile": PROFILE, "object_type": "runtime", "runtime": c["runtime"],
                           "runtime_spki_sha256": c["runtime_spki_sha256"], "issuer": c["authority"],
                           "epoch": c["epoch"]}.items():
            need(s[key] == value, "status authority/target mismatch")
        need(integer(s["sequence"]) >= 1, "invalid sequence")
        for name in ("generated_at", "next_update_at", "last_changed_at"):
            integer(s[name])
        need(s["last_changed_at"] <= s["generated_at"] <= now and
             s["generated_at"] < s["next_update_at"], "invalid status time order")
        need(type(s["state"]) is str and s["state"] in
             ("active", "revoked", "suspended", "quarantined", "attenuated"), "unsupported state")
        # Freshness is deliberately not part of evidence validity (Pro M1).
        return verified

    def proof(self, raw: bytes, attempt: dict, now: int) -> Verified:
        return self.proof_at(self.authenticate_proof(raw), attempt, now)

    def authenticate_proof(self, raw: bytes) -> Verified:
        return verify_jws(raw, unb64(self.data["runtime_public_pem"]), PROOF_TYP)

    def proof_at(self, verified: Verified, attempt: dict, now: int) -> Verified:
        p = verified.payload
        exact(p, PROOF_FIELDS)
        expected = {**self.binding(), "attempt_id": attempt["attempt_id"], "nonce": attempt["nonce"]}
        need(all(p[k] == v for k, v in expected.items()), "proof binding mismatch")
        integer(p["issued_at"]); integer(p["expires_at"])
        need(p["issued_at"] <= now < p["expires_at"] and
             0 < p["expires_at"] - p["issued_at"] <= 60, "proof not fresh")
        return verified

    def fresh(self, s: dict, now: int) -> bool:
        return (s["generated_at"] <= now < s["next_update_at"] and
                now - s["generated_at"] <= self.data["max_age"])
