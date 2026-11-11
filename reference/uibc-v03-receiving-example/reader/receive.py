"""Bounded, independent UIBC evidence reader. Python stdlib; no upstream imports."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sys

PROFILE = "uibc-0.2.2-evidence-receiving-v1"
UPSTREAM_COMMIT = "163d81b030ef16a58fa21ec70caee70ace53f1e3"
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 8 * MAX_FILE_BYTES
MAX_ENTRIES = 128
HEX = re.compile(r"[0-9a-f]{64}\Z")
EVIDENCE_TYPES = frozenset({
    "IDENTITY", "LIFECYCLE", "INPUT", "ACTION", "TOOL", "MEMORY", "OUTPUT",
    "EVALUATION", "HUMAN_DECISION", "VERIFICATION", "INCIDENT", "RETIREMENT",
})
NOT_ASSESSED = [
    "complete_package_structure", "identity_consistency_and_subject_binding",
    "lifecycle_transitions_and_event_signatures", "evidence_metadata_binding",
    "issuer_authority", "key_status_and_revocation", "external_time_anchoring",
    "request_and_delegation_binding", "execution_admission", "execution_outcome",
    "behavioral_truth", "unlisted_files",
]


class InputError(ValueError):
    """A stable error code, without input contents or local paths."""

    def __init__(self, code: str, input_name: str):
        super().__init__(code)
        self.code, self.input_name = code, input_name


def digest(data: bytes) -> dict:
    return {"alg": "sha-256", "value": hashlib.sha256(data).hexdigest()}


def canonical(value) -> bytes:
    """UIBC's pinned provisional Python encoding, deliberately not RFC 8785."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def parse_json(data: bytes, label: str) -> dict:
    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise InputError("duplicate_json_key", label)
            obj[key] = value
        return obj

    def unsupported(_):
        raise InputError("unsupported_json_number", label)

    def inspect(value, depth=0):
        if depth > 32:
            raise InputError("json_depth_limit", label)
        if isinstance(value, str):
            value.encode("utf-8", errors="strict")
        elif type(value) is int and abs(value) > 9007199254740991:
            raise InputError("unsupported_json_number", label)
        elif isinstance(value, dict):
            for k, v in value.items():
                inspect(k, depth + 1)
                inspect(v, depth + 1)
        elif isinstance(value, list):
            for v in value:
                inspect(v, depth + 1)
    try:
        obj = json.loads(data.decode("utf-8", errors="strict"),
                         object_pairs_hook=pairs, parse_float=unsupported,
                         parse_constant=unsupported)
        if not isinstance(obj, dict):
            raise InputError("expected_json_object", label)
        inspect(obj)
        return obj
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, InputError):
            raise
        raise InputError("invalid_json", label) from None


def _path_parts(path: str, label: str) -> list[str]:
    if (not isinstance(path, str) or len(path) > 512 or "\\" in path
            or "\0" in path or ":" in path
            or any(p in ("", ".", "..") for p in path.split("/"))):
        raise InputError("unsafe_relative_path", label)
    return path.split("/")


class Package:
    """Read regular files beneath a held directory fd, refusing internal links."""

    def __init__(self, root: Path):
        self.cache = {}
        self.refs = []
        self.total = 0
        try:
            self.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except (OSError, ValueError):
            raise InputError("invalid_package_directory", "package") from None

    def close(self):
        os.close(self.fd)

    def read(self, relative: str, optional=False) -> bytes | None:
        if relative in self.cache:
            return self.cache[relative]
        parts = _path_parts(relative, "package_file")
        parent = os.dup(self.fd)
        fd = None
        try:
            for part in parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=parent)
                os.close(parent)
                parent = next_fd
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=parent)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise InputError("not_regular_file", "package_file")
            if before.st_size > MAX_FILE_BYTES:
                raise InputError("file_size_limit", "package_file")
            with os.fdopen(fd, "rb") as stream:
                fd = None
                data = stream.read(MAX_FILE_BYTES + 1)
                after = os.fstat(stream.fileno())
            if len(data) > MAX_FILE_BYTES:
                raise InputError("file_size_limit", "package_file")
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise InputError("input_changed_during_read", "package_file")
            self.total += len(data)
            if self.total > MAX_TOTAL_BYTES:
                raise InputError("total_size_limit", "package_file")
            self.cache[relative] = data
            self.refs.append({"path": relative, "bytes": len(data), "digest": digest(data)})
            return data
        except FileNotFoundError:
            if optional:
                self.cache[relative] = None
                return None
            raise InputError("missing_input", "package_file") from None
        except OSError:
            raise InputError("unreadable_or_linked_file", "package_file") from None
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)


def result(status, reason, **details):
    return {"status": status, "reason": reason, **details}


def _hex(value, label):
    if not isinstance(value, str) or HEX.fullmatch(value) is None:
        raise InputError("invalid_sha256", label)
    return value


def assess(package_dir: Path | str, *, key: bytes | None = None) -> dict:
    """Evaluate only S4/S5/S6-like checks; key is selected by the caller."""
    if key is not None and (not isinstance(key, bytes) or len(key) != 32):
        raise InputError("expected_32_byte_key", "key")
    pkg = Package(Path(package_dir))
    try:
        manifest = parse_json(pkg.read("manifest.json"), "manifest")
        identity = parse_json(pkg.read("identity.json"), "identity")
        index = parse_json(pkg.read("evidence/index.json"), "index")
        if any(x.get("schema") != "uibc-core/0.2.2-proposal" for x in (manifest, identity)):
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

        raw_seal = pkg.read("signatures/seal.json", optional=True)
        key_id = None if key is None else digest(key)["value"]
        payload_digest = None
        if raw_seal is None:
            seal_result = result("not_assessed" if key is None else "mismatched", "seal_absent")
        else:
            seal = parse_json(raw_seal, "seal")
            if (seal.get("schema") != "uibc-core/0.2.0-proposal"
                    or seal.get("algorithm") != "HMAC-SHA256"
                    or seal.get("signed") != "identity+manifest"):
                seal_result = result("not_assessed", "unsupported_seal_profile")
            elif key is None:
                seal_result = result("not_assessed", "verification_key_missing")
            elif seal.get("key_id") != key_id:
                seal_result = result("mismatched", "selected_key_id_mismatch")
            else:
                payload = canonical({"identity": identity, "manifest": manifest})
                payload_digest = digest(payload)
                try:
                    sig = base64.b64decode(seal.get("signature", ""), validate=True)
                except (ValueError, TypeError):
                    sig = b""
                valid = hmac.compare_digest(hmac.digest(key, payload, "sha256"), sig)
                seal_result = result("matched" if valid else "mismatched",
                                     "hmac_matched" if valid else "hmac_mismatch")
        checks["seal"] = {**seal_result, "upstream_check": "S6",
                          "selected_key_id": key_id, "payload_digest": payload_digest}
        states = {c["status"] for c in checks.values()}
        summary = ("mismatched" if "mismatched" in states else
                   "not_assessed" if "not_assessed" in states else "matched")
        return {"kind": "uibc-evidence-assessment", "profile": PROFILE,
                "upstream_contract_commit": UPSTREAM_COMMIT,
                "checks_status": summary, "checks": checks,
                "inputs": sorted(pkg.refs, key=lambda r: r["path"]),
                "digest_basis": "uibc-python-sorted-compact-utf8-provisional",
                "not_assessed": NOT_ASSESSED.copy()}
    finally:
        pkg.close()


def load_key(path: Path, package_dir: Path) -> bytes:
    # Explicit external key selection, never discover a key in a received package.
    fd = None
    try:
        if path.resolve().is_relative_to(package_dir.resolve()):
            raise InputError("key_must_be_outside_package", "key")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise InputError("not_regular_file", "key")
        if info.st_size not in (64, 65):
            raise InputError("expected_64_hex_test_key", "key")
        raw = os.read(fd, 67)
        if raw.endswith(b"\n"):
            raw = raw[:-1]
        if len(raw) != 64 or re.fullmatch(b"[0-9a-fA-F]{64}", raw) is None:
            raise InputError("expected_64_hex_test_key", "key")
        return bytes.fromhex(raw.decode("ascii"))
    except (OSError, RuntimeError, ValueError) as exc:
        if isinstance(exc, InputError):
            raise
        raise InputError("unreadable_key", "key") from None
    finally:
        if fd is not None:
            os.close(fd)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--key", type=Path, help="receiver-selected external 64-hex key file")
    args = parser.parse_args(argv)
    try:
        key = None if args.key is None else load_key(args.key, args.package)
        report = assess(args.package, key=key)
        exit_code = 0
    except InputError as exc:
        report = {"kind": "uibc-evidence-input-error", "profile": PROFILE,
                  "checks_status": "invalid_input", "reason": exc.code, "input": exc.input_name}
        exit_code = 64
    print(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
