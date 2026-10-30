#!/usr/bin/env python3
"""Explicit local JCS/JWS verification joined to the existing receipt policy."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import types

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = "vate-local-jcs-signature-authority-trial-v1"
BRIDGE_CONTRACT = "vate-local-jcs-es256-bridge-v1"
SIGNATURE_PROFILE = "vate-local-jcs-es256-detached-v1"
LEGACY_PATH = "reference/recipient-signature-authority/recipient_trial.py"
LEGACY_SHA = "c91b6b2ddb9c7199c1193db5934af2e6f1c21c11abea74e9ce585a512210b4d4"
BRIDGE_PATH = "reference/recipient-jcs-signature-authority/bridge.mjs"
BRIDGE_SOURCES = (BRIDGE_PATH, "packages/vate-core-ts/dist/jcs-es256.js", "packages/vate-core-ts/dist/jcs.js")
KINDS = ("admission", "post_execution")
LIMIT, PROOF_LIMIT, POLICY_LIMIT = 1024 * 1024, 4096, 64 * 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


class TrialError(Exception):
    def __init__(self, code, detail):
        self.code, self.detail = code, detail
        super().__init__(code + ": " + detail)

    def as_dict(self):
        return {"trial_contract": CONTRACT, "invocation": {"status": "error"},
                "error": {"code": self.code, "detail": self.detail}}


def require(condition, code, detail):
    if not condition:
        raise TrialError(code, detail)


class JcsRecipientTrial:
    def __init__(self, *, expected_contract, node, node_sha256, source_root=ROOT, timeout_seconds=10.0):
        require(expected_contract == CONTRACT, "UNKNOWN_CONTRACT", "explicit local JCS trial contract required")
        require(type(timeout_seconds) in (int, float) and math.isfinite(timeout_seconds) and 0 < timeout_seconds <= 60,
                "INVALID_CONFIGURATION", "timeout must be finite, positive and at most 60 seconds")
        require(type(node_sha256) is str and HEX.fullmatch(node_sha256), "INVALID_CONFIGURATION", "Node executable pin required")
        try:
            selected = Path(node)
            require(selected.is_absolute(), "INVALID_CONFIGURATION", "Node path must be absolute")
            self.node, self.root = selected.resolve(strict=True), Path(source_root).resolve(strict=True)
            legacy_raw = (self.root / LEGACY_PATH).read_bytes()
            require(sha(legacy_raw) == LEGACY_SHA, "AUTHORITY_SOURCE_MISMATCH", "existing authority adapter changed")
            self.sources = {name: sha((self.root / name).read_bytes()) for name in BRIDGE_SOURCES}
        except (OSError, TypeError, ValueError, RuntimeError) as exc:
            raise TrialError("SOURCE_OR_RUNTIME_UNAVAILABLE", "select an existing runtime and run npm run ts:check: " + str(exc)) from exc
        self.expected_sha, self.timeout = node_sha256, timeout_seconds
        # Exclude NODE_OPTIONS, preload hooks and user OpenSSL configuration.
        self.env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "OPENSSL_CONF": os.devnull}
        self._check_runtime()
        module = types.ModuleType("_vate_jcs_reused_authority")
        module.__file__ = str(self.root / LEGACY_PATH)
        exec(compile(legacy_raw, module.__file__, "exec"), module.__dict__)
        self.legacy = module
        try:
            self.api = module.api_module(self.root)
        except module.TrialError as exc:
            raise TrialError("RECIPIENT_API_UNAVAILABLE", str(exc)) from exc
        try:
            self.assessor = self.api.RecipientAssessor(expected_api_contract=module.API_CONTRACT, source_root=self.root)
        except self.api.AssessmentError as exc:
            raise TrialError("RECIPIENT_API_UNAVAILABLE", str(exc)) from exc

    def _check_runtime(self):
        try:
            require(self.node.is_file() and os.access(self.node, os.X_OK), "VERIFIER_UNAVAILABLE", "Node is not executable")
            require(file_sha(self.node) == self.expected_sha, "VERIFIER_CHANGED", "Node differs from receiver pin")
            require(all(sha((self.root / name).read_bytes()) == expected for name, expected in self.sources.items()),
                    "BRIDGE_SOURCE_CHANGED", "bridge or built verifier changed during this trial")
        except OSError as exc:
            raise TrialError("VERIFIER_UNAVAILABLE", str(exc)) from exc

    def _verify(self, request):
        raw = encoded(request)
        self._check_runtime()
        try:
            completed = subprocess.run([str(self.node), str(self.root / BRIDGE_PATH)], input=raw,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env,
                                       timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise TrialError("VERIFIER_TIMEOUT", "local signature verifier exceeded timeout") from exc
        except OSError as exc:
            raise TrialError("VERIFIER_UNAVAILABLE", str(exc)) from exc
        self._check_runtime()
        require(len(completed.stdout) <= 32768 and len(completed.stderr) <= 4096,
                "INVALID_VERIFIER_RESPONSE", "verifier output exceeded bound")
        try:
            result = self.legacy.strict_json(completed.stdout)
        except self.legacy.TrialError as exc:
            raise TrialError("INVALID_VERIFIER_RESPONSE", "verifier did not return a strict JSON object") from exc
        if completed.returncode != 0 or completed.stderr:
            code = "KEY_VALIDATION_FAILED" if result.get("error") == "INVALID_VERIFICATION_KEYS" else "VERIFIER_ERROR"
            raise TrialError(code, "local verifier did not complete normally")
        require(self.legacy.exact(result, ("contract", "request_sha256", "signatures", "validated_keys", "runtime"))
                and result["contract"] == BRIDGE_CONTRACT and result["request_sha256"] == sha(raw),
                "INVALID_VERIFIER_RESPONSE", "verifier contract/input binding mismatch")
        require(result["validated_keys"] == [key["key_sha256"] for key in request["verification_keys"]]
                and self.legacy.exact(result["signatures"], KINDS), "INVALID_VERIFIER_RESPONSE", "missing keys or receipt results")
        runtime = result["runtime"]
        require(self.legacy.exact(runtime, ("node", "openssl")) and all(type(v) is str and 0 < len(v) < 128 for v in runtime.values()),
                "INVALID_VERIFIER_RESPONSE", "missing runtime identity")
        fields = ("profile", "status", "reason", "key_sha256", "source_sha256", "proof_sha256", "canonical_sha256", "signing_input_sha256")
        for kind in KINDS:
            item, entry = result["signatures"][kind], request["receipts"][kind]
            require(self.legacy.exact(item, fields) and item["profile"] == SIGNATURE_PROFILE
                    and item["status"] in ("verified", "invalid", "not_assessed", "error")
                    and type(item["reason"]) is str and bool(re.fullmatch(r"[A-Z0-9_]{1,80}", item["reason"])),
                    "INVALID_VERIFIER_RESPONSE", "invalid signature result")
            for field in ("key_sha256", "source_sha256", "proof_sha256", "canonical_sha256", "signing_input_sha256"):
                value = item[field]
                require(value is None or (type(value) is str and HEX.fullmatch(value)), "INVALID_VERIFIER_RESPONSE", "invalid digest identity")
            for field, source_field in (("source_sha256", "source_base64"), ("proof_sha256", "proof_base64")):
                expected = None if entry[source_field] is None else sha(base64.b64decode(entry[source_field]))
                require(item[field] == expected, "INVALID_VERIFIER_RESPONSE", "receipt/proof identity mismatch")
            if item["status"] == "verified":
                require(item["reason"] == "SIGNATURE_VERIFIED" and item["key_sha256"] in result["validated_keys"]
                        and all(item[k] is not None for k in fields[4:]), "INVALID_VERIFIER_RESPONSE", "incomplete verified result")
        return result

    def _authority(self, kind, raw, signature, policy, evaluation_time):
        if signature["status"] == "verified":
            try:
                pending = [self.legacy.strict_json(raw)]
                while pending:
                    item = pending.pop()
                    if type(item) is int and abs(item) > 2**53 - 1:
                        raise ValueError("JCS receipt authority requires safe integer JSON numbers")
                    if type(item) is dict:
                        pending.extend(item.values())
                    elif type(item) is list:
                        pending.extend(item)
            except (self.legacy.TrialError, ValueError) as exc:
                return {"status": "not_assessed", "reason": "UNSUPPORTED_RECEIPT_CONTEXT", "detail": str(exc)}
        return self.legacy.assess_authority(kind, raw, signature, policy, evaluation_time)

    def assess(self, admission, post, *, admission_proof, post_proof, receiver_policy):
        try:
            for name, raw, size in (("admission", admission, LIMIT), ("post", post, LIMIT),
                                    ("admission_proof", admission_proof, PROOF_LIMIT), ("post_proof", post_proof, PROOF_LIMIT)):
                self.legacy.bounded(raw, size, name, optional=True)
            policy, _, evaluation_time = self.legacy.policy_from(receiver_policy)
        except self.legacy.TrialError as exc:
            raise TrialError(exc.code, exc.detail) from exc
        entries = (("admission", admission, admission_proof), ("post_execution", post, post_proof))
        to64 = lambda raw: None if raw is None else base64.b64encode(raw).decode()
        checked = self._verify({"contract": BRIDGE_CONTRACT, "verification_keys": policy["verification_keys"],
                               "receipts": {kind: {"source_base64": to64(raw), "proof_base64": to64(proof)} for kind, raw, proof in entries}})
        try:
            native = self.assessor.assess_receipts(admission, post,
                         requested_checks=["receipt_linkage", "signatures_and_issuer_authority"])
        except self.api.AssessmentError as exc:
            raise TrialError("RECIPIENT_API_ERROR", str(exc)) from exc
        authority = {kind: self._authority(kind, raw, checked["signatures"][kind], policy, evaluation_time)
                     for kind, raw, _ in entries}
        return {"trial_contract": CONTRACT, "invocation": {"status": "returned"}, "receipt_assessment": native,
                "signatures": checked["signatures"], "issuer_authority": authority, "validated_keys": checked["validated_keys"],
                "receiver_evaluation_time": policy["evaluation_time"],
                "verifier": {"executable": str(self.node), "executable_sha256": self.expected_sha, "runtime": checked["runtime"],
                             "source_files": self.sources, "authority_source": {LEGACY_PATH: LEGACY_SHA},
                             "dynamic_libraries_attested": False},
                "inputs": {name: self.legacy.identity(raw) for name, raw in (("admission", admission), ("post", post),
                           ("admission_proof", admission_proof), ("post_proof", post_proof), ("receiver_policy", receiver_policy))},
                "scope": "Local JCS/JWS experiment; record issuance under receiver policy, not actual execution or permission to execute."}


def read_file(path, limit):
    if path is None:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "INPUT_FILE_ERROR", "expected a regular file")
            raw = stream.read(limit + 1)
        require(len(raw) <= limit, "INPUT_SIZE_ERROR", "input exceeds bound")
        return raw
    except OSError as exc:
        raise TrialError("INPUT_FILE_ERROR", str(exc)) from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("trial-contract", "node", "node-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--timeout", type=float, default=10.0, help="seconds per signature subprocess; receipt worker has its own 30-second timeout")
    for name in ("admission", "post", "admission-proof", "post-proof", "receiver-policy"):
        parser.add_argument("--" + name, type=Path, required=name == "receiver-policy")
    args = parser.parse_args(argv)
    try:
        trial = JcsRecipientTrial(expected_contract=args.trial_contract, node=args.node, node_sha256=args.node_sha256, timeout_seconds=args.timeout)
        result = trial.assess(read_file(args.admission, LIMIT), read_file(args.post, LIMIT),
                             admission_proof=read_file(args.admission_proof, PROOF_LIMIT), post_proof=read_file(args.post_proof, PROOF_LIMIT),
                             receiver_policy=read_file(args.receiver_policy, POLICY_LIMIT))
        code = 64 if any(s["status"] == "error" for s in result["signatures"].values()) else 0
    except TrialError as exc:
        result, code = exc.as_dict(), 64
    print(encoded(result).decode())
    return code


if __name__ == "__main__":
    raise SystemExit(main())
