#!/usr/bin/env python3
"""Local experiment: detached P-256/SHA-256, authority, unchanged VATE API."""
from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import types

CONTRACT = "vate-local-signature-authority-p256-trial-v1"
PROOF_CONTRACT = "vate-local-detached-p256-sha256-trial-v1"
POLICY_CONTRACT = "vate-local-issuer-authority-p256-policy-trial-v1"
API_CONTRACT = "vate-recipient-assessment-api-v1"
KINDS = ("admission", "post_execution")
LIMIT = 1024 * 1024
POLICY_LIMIT = 64 * 1024
PROOF_LIMIT = 4096
# id-ecPublicKey + named prime256v1 + uncompressed point. No explicit curves.
SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
HEX = re.compile(r"[0-9a-f]{64}\Z")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
API_PINS = {
    "vate_recipient.py": "f04249301cc7861e8854db2b0464f5f1fabaee3eae64969ba082eec11a702c93",
    "_worker.py": "5834df316c2d07c822d1e7f5c3733d61af68e1278c48f0e570199d0954564696",
    "EVALUATOR-SOURCES.json": "97b46ce56abaaf0afc1e1ba77b3d73b48504fb05f35042793eb3aa81eee0a226",
}


class TrialError(Exception):
    def __init__(self, code, detail, native=None):
        self.code, self.detail, self.native = code, detail, native
        super().__init__(code + ": " + detail)

    def as_dict(self):
        error = {"code": self.code, "detail": self.detail}
        if self.native is not None:
            error["native"] = self.native
        return {"trial_contract": CONTRACT, "invocation": {"status": "error"}, "error": error}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(raw):
    return {"supplied": raw is not None, "raw_sha256": sha(raw) if raw is not None else None,
            "byte_length": len(raw) if raw is not None else None}


def process_record(returncode, stdout, stderr, *, complete=True):
    return {"returncode": returncode, "complete": complete,
            "stdout": stdout.decode("utf-8", "replace"), "stderr": stderr.decode("utf-8", "replace"),
            "stdout_base64": base64.b64encode(stdout).decode(), "stderr_base64": base64.b64encode(stderr).decode()}


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()


def require(condition, code, detail):
    if not condition:
        raise TrialError(code, detail)


def bounded(raw, limit, name, *, optional=False):
    require((optional and raw is None) or type(raw) is bytes, "INPUT_TYPE_ERROR", name + " must be bytes")
    if raw is not None:
        require(len(raw) <= limit, "INPUT_SIZE_ERROR", name + " exceeds its byte bound")


def strict_json(raw):
    def object_pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate object key")
            out[key] = value
        return out

    def invalid_number(_):
        raise ValueError("only integer JSON numbers are supported")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=object_pairs,
                           parse_float=invalid_number, parse_constant=invalid_number)
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            if depth > 32:
                raise ValueError("JSON nesting exceeds trial bound")
            if isinstance(item, dict):
                pending.extend((v, depth + 1) for pair in item.items() for v in pair)
            elif isinstance(item, list):
                pending.extend((v, depth + 1) for v in item)
            elif isinstance(item, str):
                item.encode("utf-8")
        if type(value) is not dict:
            raise ValueError("expected JSON object")
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise TrialError("INVALID_JSON", str(exc)) from exc


def exact(obj, keys):
    return type(obj) is dict and set(obj) == set(keys)


def text(value):
    return type(value) is str and 0 < len(value) <= 1024 and not any(ord(c) < 32 for c in value)


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value):
        raise ValueError("expected UTC timestamp with optional microseconds")
    # Python 3.10 accepts only 3 or 6 fractional digits. Pad for parsing,
    # preserving the exact instant and leaving the signed original untouched.
    whole, point, fraction = value[:-1].partition(".")
    normalized = whole + ("." + fraction.ljust(6, "0") if point else "")
    return datetime.fromisoformat(normalized + "+00:00")


def decode64(value, length, maximum=None):
    if type(value) is not str:
        raise ValueError("expected canonical base64")
    raw = base64.b64decode(value, validate=True)
    if not length <= len(raw) <= (maximum if maximum is not None else length) or base64.b64encode(raw).decode() != value:
        raise ValueError("noncanonical base64 or incorrect byte length")
    return raw


def action_binding(value):
    return (exact(value, ("type", "canonicalization", "preimage_profile", "digest"))
            and value["type"] == "profile_defined_digest"
            and value["canonicalization"] == "vate-v0.3-fixture-json;ascii-escaped;sorted;compact;no-floats"
            and value["preimage_profile"] == "vate-local-s3-observation-v1"
            and exact(value["digest"], ("alg", "value"))
            and value["digest"]["alg"] == "sha-256"
            and type(value["digest"]["value"]) is str and HEX.fullmatch(value["digest"]["value"]))


def policy_from(raw):
    bounded(raw, POLICY_LIMIT, "receiver_policy")
    try:
        policy = strict_json(raw)
        if not exact(policy, ("contract", "evaluation_time", "verification_keys", "grants")) or policy["contract"] != POLICY_CONTRACT:
            raise ValueError("unknown policy contract or shape")
        evaluation_time = timestamp(policy["evaluation_time"])
        keys = policy["verification_keys"]
        if type(keys) is not list or not 1 <= len(keys) <= 16:
            raise ValueError("supply 1..16 receiver-selected verification keys")
        decoded = {}
        for entry in keys:
            if not exact(entry, ("key_sha256", "spki_der_base64")):
                raise ValueError("invalid key entry")
            der = decode64(entry["spki_der_base64"], 91)
            key = sha(der)
            if not der.startswith(SPKI_PREFIX) or entry["key_sha256"] != key or key in decoded:
                raise ValueError("invalid, duplicate or non-P-256 key")
            decoded[key] = der
        grants = policy["grants"]
        if type(grants) is not list or len(grants) > 64:
            raise ValueError("expected at most 64 grants")
        fields = ("issuer_id", "issuer_role", "receipt_kind", "key_sha256", "transaction_id", "runtime",
                  "action_binding", "valid_from", "valid_until")
        for grant in grants:
            if not exact(grant, fields) or not all(text(grant[k]) for k in fields if k != "action_binding"):
                raise ValueError("invalid grant fields")
            if grant["receipt_kind"] not in KINDS or grant["key_sha256"] not in decoded or not action_binding(grant["action_binding"]):
                raise ValueError("invalid grant kind, key or action binding")
            if timestamp(grant["valid_from"]) >= timestamp(grant["valid_until"]):
                raise ValueError("empty or reversed grant interval")
        return policy, decoded, evaluation_time
    except (TrialError, ValueError, TypeError, KeyError, binascii.Error) as exc:
        raise TrialError("INVALID_POLICY", str(exc)) from exc


def signing_input(kind, raw):
    require(kind in KINDS and type(raw) is bytes, "INPUT_TYPE_ERROR", "invalid signing input")
    return b"VATE local detached P-256 SHA-256 receipt trial v1\x00" + kind.encode("ascii") + b"\x00" + raw


def api_module(root):
    folder = root / "reference/recipient-assessment"
    try:
        sources = {name: (folder / name).read_bytes() for name in API_PINS}
    except OSError as exc:
        raise TrialError("API_SOURCE_UNAVAILABLE", str(exc)) from exc
    require({name: sha(raw) for name, raw in sources.items()} == API_PINS,
            "API_SOURCE_MISMATCH", "trial requires the unchanged reviewed recipient API")
    name = "_vate_signature_trial_recipient"
    module = types.ModuleType(name)
    module.__file__ = str(folder / "vate_recipient.py")
    # Compile the pinned bytes directly: never import a possibly stale .pyc.
    exec(compile(sources["vate_recipient.py"], module.__file__, "exec"), module.__dict__)
    return module


class RecipientTrial:
    def __init__(self, *, expected_contract, openssl, openssl_sha256, source_root=ROOT, timeout_seconds=10.0):
        require(expected_contract == CONTRACT, "UNKNOWN_CONTRACT", "explicit local trial contract required")
        require(type(timeout_seconds) in (float, int) and 0 < timeout_seconds <= 60
                and math.isfinite(timeout_seconds), "INVALID_CONFIGURATION", "timeout must be in (0, 60] seconds")
        require(type(openssl_sha256) is str and HEX.fullmatch(openssl_sha256),
                "INVALID_CONFIGURATION", "expected OpenSSL executable SHA-256 is required")
        try:
            selected = Path(openssl)
            require(selected.is_absolute(), "INVALID_CONFIGURATION", "OpenSSL path must be absolute")
            self.openssl = selected.resolve(strict=True)
            self.root = Path(source_root).resolve(strict=True)
        except (TypeError, ValueError, OSError, RuntimeError) as exc:
            raise TrialError("INVALID_CONFIGURATION", str(exc)) from exc
        self.expected_sha = openssl_sha256
        self.timeout = timeout_seconds
        self.env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "OPENSSL_CONF": os.devnull}
        self._binary_check()
        version = self._process(["version"])
        require(version.returncode == 0 and not version.stderr and re.fullmatch(rb"OpenSSL [34]\.\d+\.\d+ [^\r\n]+\n", version.stdout),
                "VERIFIER_UNSUPPORTED", "requires an explicit existing OpenSSL 3 or 4 binary")
        self.verifier_identity = {"executable": str(self.openssl), "executable_sha256": openssl_sha256,
                                  "version": version.stdout.decode().strip(), "algorithm": "ECDSA-P-256-SHA-256",
                                  "provider": "default", "configuration": "empty",
                                  "dynamic_libraries_attested": False}
        self.api = api_module(self.root)
        self.assessor = self.api.RecipientAssessor(expected_api_contract=API_CONTRACT, source_root=self.root)

    def _binary_check(self):
        try:
            require(self.openssl.is_file() and os.access(self.openssl, os.X_OK),
                    "VERIFIER_UNAVAILABLE", "selected executable is unavailable")
            require(sha(self.openssl.read_bytes()) == self.expected_sha,
                    "VERIFIER_CHANGED", "selected executable differs from receiver pin")
        except OSError as exc:
            raise TrialError("VERIFIER_UNAVAILABLE", str(exc)) from exc

    def _process(self, arguments):
        self._binary_check()
        try:
            result = subprocess.run([str(self.openssl), *arguments], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env,
                                    timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise TrialError("VERIFIER_TIMEOUT", "external verifier exceeded timeout",
                             process_record(None, exc.stdout or b"", exc.stderr or b"", complete=False)) from exc
        except OSError as exc:
            raise TrialError("VERIFIER_UNAVAILABLE", str(exc)) from exc
        try:
            self._binary_check()
        except TrialError as exc:
            exc.native = process_record(result.returncode, result.stdout, result.stderr)
            raise
        return result

    def _validate_keys(self, keys):
        results = {}
        with tempfile.TemporaryDirectory(prefix="vate-public-key-check-") as directory:
            path = Path(directory) / "key.der"
            for key_id, der in keys.items():
                path.write_bytes(der)
                run = self._process(["pkey", "-pubin", "-inform", "DER", "-in", str(path), "-pubcheck", "-noout",
                                     "-provider", "default", "-propquery", "provider=default"])
                native = process_record(run.returncode, run.stdout, run.stderr)
                if run.returncode != 0 or run.stdout != b"Key is valid\n" or run.stderr:
                    raise TrialError("KEY_VALIDATION_FAILED", "OpenSSL did not validate receiver key " + key_id, native)
                results[key_id] = {"status": "validated", "native": native}
        return results

    def _signature(self, kind, raw, proof_raw, keys):
        result = {"status": "not_assessed", "reason": "MISSING_RECEIPT" if raw is None else "MISSING_PROOF",
                  "key_sha256": None, "native": None}
        if raw is None or proof_raw is None:
            return result
        try:
            proof = strict_json(proof_raw)
            if not exact(proof, ("contract", "key_sha256", "signature_base64")) or proof["contract"] != PROOF_CONTRACT:
                raise ValueError("unknown detached proof contract or shape")
            key_id = proof["key_sha256"]
            if type(key_id) is not str or not HEX.fullmatch(key_id):
                raise ValueError("invalid key identifier")
            # P-256 ECDSA signature in DER; OpenSSL parses its ASN.1 content.
            signature = decode64(proof["signature_base64"], 8, 72)
        except (TrialError, ValueError, TypeError, binascii.Error) as exc:
            return {**result, "reason": "INVALID_PROOF", "detail": str(exc)}
        result["key_sha256"] = key_id
        if key_id not in keys:
            return {**result, "reason": "KEY_NOT_IN_RECEIVER_KEYRING"}
        try:
            with tempfile.TemporaryDirectory(prefix="vate-signature-trial-") as directory:
                folder = Path(directory)
                for name, value in (("key.der", keys[key_id]), ("signature.bin", signature),
                                    ("message.bin", signing_input(kind, raw))):
                    (folder / name).write_bytes(value)
                run = self._process(["pkeyutl", "-verify", "-rawin", "-digest", "sha256", "-pubin", "-keyform", "DER",
                                     "-inkey", str(folder / "key.der"), "-sigfile", str(folder / "signature.bin"),
                                     "-in", str(folder / "message.bin"), "-provider", "default", "-propquery", "provider=default"])
            result["native"] = process_record(run.returncode, run.stdout, run.stderr)
            if run.returncode == 0 and run.stdout == b"Signature Verified Successfully\n" and not run.stderr:
                return {**result, "status": "verified", "reason": "SIGNATURE_VERIFIED"}
            # OpenSSL builds can emit this one diagnostic when ECDSA
            # verification returns zero, with either observed source-path
            # spelling. Other or extra diagnostics remain operational errors.
            known_mismatch = not run.stderr or re.fullmatch(
                rb"[0-9A-Fa-f]+:error:030000EA:digital envelope routines:EVP_DigestVerifyFinal:"
                rb"provider signature failure:(?:\.\./)?crypto/evp/m_sigver\.c:[0-9]+:ECDSA digest_verify_final:\n", run.stderr)
            if run.returncode == 1 and run.stdout == b"Signature Verification Failure\n" and known_mismatch:
                return {**result, "status": "invalid", "reason": "SIGNATURE_INVALID"}
            return {**result, "status": "error", "reason": "VERIFIER_EXECUTION_ERROR"}
        except (TrialError, OSError) as exc:
            return {**result, "status": "error", "reason": getattr(exc, "code", "LOCAL_IO_ERROR"),
                    "detail": str(exc), "native": getattr(exc, "native", None)}

    def assess(self, admission, post, *, admission_proof, post_proof, receiver_policy):
        for name, raw, size in (("admission", admission, LIMIT), ("post", post, LIMIT),
                                ("admission_proof", admission_proof, PROOF_LIMIT), ("post_proof", post_proof, PROOF_LIMIT)):
            bounded(raw, size, name, optional=True)
        policy, keys, evaluation_time = policy_from(receiver_policy)
        try:
            key_validation = self._validate_keys(keys)
        except OSError as exc:
            raise TrialError("LOCAL_IO_ERROR", str(exc)) from exc
        try:
            native = self.assessor.assess_receipts(admission, post,
                        requested_checks=["receipt_linkage", "signatures_and_issuer_authority"])
        except self.api.AssessmentError as exc:
            raise TrialError("RECIPIENT_API_ERROR", str(exc)) from exc
        signatures, authority = {}, {}
        for kind, raw, proof in (("admission", admission, admission_proof), ("post_execution", post, post_proof)):
            signature = self._signature(kind, raw, proof, keys)
            signatures[kind] = signature
            authority[kind] = assess_authority(kind, raw, signature, policy, evaluation_time)
        return {"trial_contract": CONTRACT, "invocation": {"status": "returned"},
                "receipt_assessment": native, "signatures": signatures, "issuer_authority": authority,
                "key_validation": key_validation,
                "receiver_evaluation_time": policy["evaluation_time"], "external_verifier": self.verifier_identity,
                "inputs": {name: identity(raw) for name, raw in (("admission", admission), ("post", post),
                           ("admission_proof", admission_proof), ("post_proof", post_proof), ("receiver_policy", receiver_policy))},
                "scope": "Local detached-proof experiment; authority under receiver policy, not actual execution or current permission to execute."}


def receipt_context(kind, raw):
    record = strict_json(raw)
    if (record.get("version") != "vate-0.3" or record.get("profile") != "VATE-AL2-Verifier-Admission-v0.3"
            or record.get("receipt_type") != kind or record.get("proof") != {"format": "none"}):
        raise ValueError("outside the trial receipt shape")
    issued = timestamp(record["issued_at"])
    if kind == "admission":
        part = record["request"]
        issuer, role, runtime = record["verifier"]["id"], "verifier", record["subject"]["runtime"]
        action_hash = part["input_hash"]
        if part["action"] != "s3.put_object":
            raise ValueError("outside the trial action")
    else:
        part = record["execution"]
        issuer, role, runtime = record["issuer"]["id"], record["issuer"]["role"], part["runtime"]
        action_hash = part["effective_request_hash"]
    binding, transaction = part["action_binding"], part["transaction_id"]
    if not all(text(v) for v in (issuer, role, runtime, transaction)) or not action_binding(binding):
        raise ValueError("unsupported authority context")
    if action_hash != "sha-256:" + binding["digest"]["value"]:
        raise ValueError("action binding does not match recorded request hash")
    return {"issuer_id": issuer, "issuer_role": role, "receipt_kind": kind,
            "transaction_id": transaction, "runtime": runtime, "action_binding": binding}, issued


def assess_authority(kind, raw, signature, policy, evaluation_time):
    if signature["status"] != "verified":
        return {"status": "not_assessed", "reason": "SIGNATURE_NOT_VERIFIED"}
    try:
        context, issued = receipt_context(kind, raw)
    except (TrialError, ValueError, TypeError, KeyError) as exc:
        return {"status": "not_assessed", "reason": "UNSUPPORTED_RECEIPT_CONTEXT", "detail": str(exc)}
    result = {"status": "denied", "context": context}
    if issued > evaluation_time:
        return {**result, "reason": "ISSUED_AFTER_EVALUATION_TIME"}
    context["key_sha256"] = signature["key_sha256"]
    candidates = [g for g in policy["grants"] if all(g[k] == context[k]
                  for k in ("issuer_id", "issuer_role", "receipt_kind", "key_sha256"))]
    if not candidates:
        return {**result, "reason": "AUTHORITY_NOT_GRANTED"}
    candidates = [g for g in candidates if all(encoded(g[k]) == encoded(context[k])
                  for k in ("transaction_id", "runtime", "action_binding"))]
    if not candidates:
        return {**result, "reason": "AUTHORITY_SCOPE_MISMATCH"}
    for grant in candidates:
        start, end = timestamp(grant["valid_from"]), timestamp(grant["valid_until"])
        if start <= issued < end and start <= evaluation_time < end:
            return {**result, "status": "authorized_under_policy", "reason": "AUTHORITY_GRANTED"}
    return {**result, "reason": "AUTHORITY_TIME_MISMATCH"}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise TrialError("CLI_USAGE_ERROR", message)


def read_file(path, limit):
    if path is None:
        return None
    try:
        require(path.is_file(), "INPUT_FILE_ERROR", "expected a regular file")
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
        bounded(raw, limit, str(path))
        return raw
    except OSError as exc:
        raise TrialError("INPUT_FILE_ERROR", str(exc)) from exc


def main(argv=None):
    parser = Parser(description=__doc__)
    for name in ("trial-contract", "openssl", "openssl-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="seconds per OpenSSL subprocess (default: 10; finite, > 0 and <= 60); "
                             "the receipt-assessment worker has a separate 30-second timeout; "
                             "this is not a deadline for the whole assessment")
    for name in ("admission", "post", "admission-proof", "post-proof", "receiver-policy"):
        parser.add_argument("--" + name, type=Path, required=name == "receiver-policy")
    try:
        args = parser.parse_args(argv)
        trial = RecipientTrial(expected_contract=args.trial_contract, openssl=args.openssl,
                               openssl_sha256=args.openssl_sha256, source_root=args.source_root, timeout_seconds=args.timeout)
        result = trial.assess(read_file(args.admission, LIMIT), read_file(args.post, LIMIT),
                              admission_proof=read_file(args.admission_proof, PROOF_LIMIT),
                              post_proof=read_file(args.post_proof, PROOF_LIMIT),
                              receiver_policy=read_file(args.receiver_policy, POLICY_LIMIT))
        code = 64 if any(s["status"] == "error" for s in result["signatures"].values()) else 0
    except TrialError as exc:
        result, code = exc.as_dict(), 64
    print(encoded(result).decode())
    return code


if __name__ == "__main__":
    raise SystemExit(main())
