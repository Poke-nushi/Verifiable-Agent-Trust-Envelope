"""Independent UIBC v0.3 receiving example; no UIBC imports.

Reuses the frozen reader's bounded file/JSON input layer. The Ed25519 backend
is cryptography 50.0.1; the legacy reader stays stdlib.
"""
from __future__ import annotations
import argparse
import base64
import hmac
import json
from pathlib import Path
import sys
from receive import (Package, InputError, canonical, digest, parse_json, result,
                     load_key, _hex, _path_parts, MAX_ENTRIES, EVIDENCE_TYPES,
                     NOT_ASSESSED)
from ed25519_key_policy import public_key_issue

PROFILE = "uibc-0.3.0-evidence-receiving-candidate-v1"
UPSTREAM_COMMIT = "dc9eba3146e4e32bb1356f24ce8d72249a64702a"
SCHEMAS = {"uibc-core/0.2.2-proposal", "uibc-core/0.3.0-proposal"}


def aggregate(states):
    return ("mismatched" if "mismatched" in states else
            "not_assessed" if "not_assessed" in states else "matched")


def decode_field(value, size):
    if not isinstance(value, str):
        return None
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
        return raw if len(raw) == size else None
    except (ValueError, UnicodeError):
        return None


def assess_seal(raw, identity, manifest, key, public_key):
    signature = result("not_assessed", "signature_not_checked")
    selected = key is not None or public_key is not None
    binding = result("not_assessed", "selected_key_not_compared" if selected
                     else "receiver_key_not_selected")
    payload = canonical({"identity": identity, "manifest": manifest})
    selected_id = None if key is None and public_key is None else digest(
        key if key is not None else public_key)["value"]
    reported_id = None
    algorithm = None
    if raw is None:
        check = result("not_assessed" if key is None else "mismatched", "seal_absent")
        if selected:
            binding = result("not_assessed", "seal_absent")
    else:
        seal = parse_json(raw, "seal")
        algorithm = seal.get("algorithm")
        # Only known algorithms are exposed in reports, never arbitrary JSON values.
        if algorithm not in ("HMAC-SHA256", "Ed25519"):
            algorithm = None
        if (not isinstance(seal.get("schema"), str)
                or seal.get("schema") not in SCHEMAS | {"uibc-core/0.2.0-proposal"}
                or seal.get("signed") != "identity+manifest" or algorithm is None
                or (algorithm == "Ed25519" and seal.get("schema") not in SCHEMAS)):
            check = result("not_assessed", "unsupported_seal_profile")
            if selected:
                binding = result("not_assessed", "unsupported_seal_profile")
        elif algorithm == "HMAC-SHA256":
            if key is None:
                check = result("not_assessed", "verification_key_missing")
                if public_key is not None:
                    binding = result("not_assessed", "public_key_cannot_select_hmac_signer")
            else:
                same = seal.get("key_id") == selected_id
                binding = result("matched" if same else "mismatched",
                                 "selected_key_id_matched" if same else "selected_key_id_mismatch")
                sig = decode_field(seal.get("signature"), 32)
                valid = sig is not None and hmac.compare_digest(hmac.digest(key, payload, "sha256"), sig)
                signature = result("matched" if valid else "mismatched",
                                   "hmac_matched" if valid else "hmac_mismatch")
                check = signature if same else binding
        else:
            public = decode_field(seal.get("public_key"), 32)
            if public is None:
                check = result("mismatched", "invalid_recorded_public_key")
                if selected:
                    binding = result("not_assessed", "invalid_recorded_public_key")
            else:
                reported_id = digest(public)["value"]
                if public_key is not None:
                    same = hmac.compare_digest(public_key, public)
                    binding = result("matched" if same else "mismatched",
                                     "selected_public_key_matched" if same else "selected_public_key_mismatch")
                elif key is not None:
                    binding = result("mismatched", "hmac_key_cannot_select_ed25519_signer")
                issue = public_key_issue(public)
                if issue is not None:
                    # No backend call and no signature success for excluded keys.
                    signature = result("not_assessed", issue)
                if seal.get("key_id") != reported_id:
                    check = result("mismatched", "recorded_public_key_id_mismatch")
                elif issue is not None:
                    check = binding if binding["status"] == "mismatched" else signature
                else:
                    try:
                        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
                        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                    except ImportError:
                        raise InputError("ed25519_backend_unavailable", "verifier") from None
                    sig = decode_field(seal.get("signature"), 64)
                    valid = False
                    if sig is not None:
                        try:
                            Ed25519PublicKey.from_public_bytes(public).verify(sig, payload)
                            valid = True
                        except (InvalidSignature, ValueError):
                            pass
                        except UnsupportedAlgorithm:
                            raise InputError("ed25519_backend_unavailable", "verifier") from None
                    signature = result("matched" if valid else "mismatched",
                                       "ed25519_matched" if valid else "ed25519_mismatch")
                    check = binding if binding["status"] == "mismatched" else signature
    return {**check, "upstream_check": "S6", "algorithm": algorithm,
            "signature": signature, "selected_key_binding": binding,
            "selected_key_id": selected_id, "recorded_public_key_id": reported_id,
            "payload_digest": digest(payload)}


def assess(package_dir: Path | str, *, key=None, public_key=None):
    for value in (key, public_key):
        if value is not None and (not isinstance(value, bytes) or len(value) != 32):
            raise InputError("expected_32_byte_key", "key")
    if key is not None and public_key is not None:
        raise InputError("select_one_key_mode", "key")
    if public_key is not None:
        issue = public_key_issue(public_key)
        if issue is not None:
            raise InputError(issue, "selected_public_key")
    pkg = Package(Path(package_dir))
    try:
        manifest = parse_json(pkg.read("manifest.json"), "manifest")
        identity = parse_json(pkg.read("identity.json"), "identity")
        index = parse_json(pkg.read("evidence/index.json"), "index")
        if (not isinstance(manifest.get("schema"), str)
                or manifest.get("schema") not in SCHEMAS
                or identity.get("schema") != manifest.get("schema")):
            raise InputError("unsupported_package_schema", "package")
        declared_root = _hex(manifest.get("evidence_root"), "manifest")
        entries = index.get("entries")
        if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
            raise InputError("invalid_evidence_entries", "index")
        checks, evidence, hashes = {}, [], []
        for entry in entries:
            if not isinstance(entry, dict):
                raise InputError("invalid_evidence_entry", "index")
            path = entry.get("path")
            _path_parts(path, "index")
            expected = _hex(entry.get("content_hash"), "index")
            etype = entry.get("type")
            if not isinstance(etype, str):
                raise InputError("invalid_evidence_type", "index")
            data = pkg.read("evidence/" + path, optional=True)
            actual = None if data is None else digest(data)["value"]
            if actual is not None:
                hashes.append(actual)
            reason = ("missing_evidence_file" if data is None else
                      "content_hash_mismatch" if actual != expected else
                      "unknown_evidence_type" if etype not in EVIDENCE_TYPES else
                      "content_hash_matched")
            evidence.append({"path": path, "declared_sha256": expected,
                             "observed_sha256": actual,
                             **result("matched" if reason == "content_hash_matched" else
                                      "mismatched", reason)})
        files_ok = all(e["status"] == "matched" for e in evidence)
        checks["evidence_files"] = result(
            "matched" if files_ok else "mismatched",
            "listed_evidence_checked" if files_ok else "listed_evidence_mismatch",
            upstream_check="S4", entries=evidence)
        if entries and files_ok:
            computed = digest(canonical(sorted(hashes)))["value"]
            checks["evidence_root"] = result(
                "matched" if computed == declared_root else "mismatched",
                "root_matched" if computed == declared_root else "root_mismatch",
                upstream_check="S5", computed_sha256=computed, declared_sha256=declared_root)
        else:
            checks["evidence_root"] = result("not_assessed", "evidence_incomplete_or_mismatched",
                                             upstream_check="S5", declared_sha256=declared_root)

        checks["seal"] = assess_seal(pkg.read("signatures/seal.json", optional=True),
                                     identity, manifest, key, public_key)
        states = [c["status"] for c in checks.values()]
        receiving_states = states + [checks["seal"]["selected_key_binding"]["status"]]
        return {"kind": "uibc-evidence-assessment", "profile": PROFILE,
                "upstream_contract_commit": UPSTREAM_COMMIT,
                "checks_status": aggregate(states),
                "receiver_checks_status": aggregate(receiving_states),
                "checks": checks, "inputs": sorted(pkg.refs, key=lambda r: r["path"]),
                "digest_basis": "uibc-python-sorted-compact-utf8-provisional",
                "not_assessed": NOT_ASSESSED.copy()}
    finally:
        pkg.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--key", type=Path, help="external disposable HMAC key file")
    mode.add_argument("--pubkey", type=Path, help="receiver-selected external public key file")
    args = parser.parse_args(argv)
    try:
        key = None if args.key is None else load_key(args.key, args.package)
        public = None if args.pubkey is None else load_key(args.pubkey, args.package)
        report = assess(args.package, key=key, public_key=public)
        code = 0
    except InputError as exc:
        report = {"kind": "uibc-evidence-input-error", "profile": PROFILE,
                  "checks_status": "invalid_input", "reason": exc.code, "input": exc.input_name}
        code = 64
    print(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
