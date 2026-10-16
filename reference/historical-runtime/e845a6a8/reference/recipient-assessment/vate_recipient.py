#!/usr/bin/env python3
"""Versioned local entry point for the fixed receipt and S3 assessors."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile

API_CONTRACT = "vate-recipient-assessment-api-v1"
WRAPPER_VERSION = "0.1.0"
_HERE = Path(__file__).resolve().parent
_MANIFEST_SHA256 = "97b46ce56abaaf0afc1e1ba77b3d73b48504fb05f35042793eb3aa81eee0a226"
_WRAPPER_FILES = ("vate_recipient.py", "_worker.py", "EVALUATOR-SOURCES.json")
_LOADED_MODULE_CODE = sys._getframe().f_code
_RECEIPT_LIMIT = 1024 * 1024
_POLICY_LIMIT = 256 * 1024
_CHECKS = (
    "receipt_linkage",
    "s3_observation_binding",
    "signatures_and_issuer_authority",
    "independent_execution_observation",
    "operation_population_coverage",
    "current_permission_to_execute",
)
_SUPPORTED = {
    "receipt_pair": ("receipt_linkage",),
    "s3_observation": ("receipt_linkage", "s3_observation_binding"),
}


class AssessmentError(Exception):
    """An API/configuration/invocation failure, without a native verdict."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(code + ": " + detail)

    def __reduce__(self):
        return type(self), (self.code, self.detail), self.__dict__

    def as_dict(self) -> dict:
        return {"api_contract": API_CONTRACT, "invocation": {"status": "error"},
                "error": {"code": self.code, "detail": self.detail}}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _manifest() -> dict:
    try:
        raw = (_HERE / "EVALUATOR-SOURCES.json").read_bytes()
    except OSError as exc:
        raise AssessmentError("SOURCE_MANIFEST_ERROR", str(exc)) from exc
    if _sha(raw) != _MANIFEST_SHA256:
        raise AssessmentError("SOURCE_MANIFEST_ERROR", "fixed evaluator manifest changed")
    return json.loads(raw)


def _wrapper_sources() -> dict:
    try:
        return {"reference/recipient-assessment/" + name: (_HERE / name).read_bytes()
                for name in _WRAPPER_FILES}
    except OSError as exc:
        raise AssessmentError("WRAPPER_SOURCE_UNAVAILABLE", str(exc)) from exc


def _capture_wrapper_import():
    # A timestamp-valid .pyc can contain older code than the source currently on
    # disk. Compare the actual module code with that source compiled under this
    # interpreter's import options; compiling does not execute the source again.
    try:
        sources = _wrapper_sources()
        raw = sources["reference/recipient-assessment/vate_recipient.py"]
        compiled = compile(raw, _LOADED_MODULE_CODE.co_filename, "exec",
                           dont_inherit=True, optimize=sys.flags.optimize)
        if compiled != _LOADED_MODULE_CODE:
            return None, ("WRAPPER_CODE_MISMATCH", "loaded API code does not match its source bytes")
        return {name: _sha(raw) for name, raw in sources.items()}, None
    except AssessmentError as exc:
        return None, (exc.code, exc.detail)
    except (SyntaxError, ValueError, OverflowError) as exc:
        return None, ("WRAPPER_CODE_MISMATCH", "loaded API source cannot be compiled: " + str(exc))


def _wrapper_identity() -> dict:
    if _WRAPPER_IMPORT_ERROR is not None:
        raise AssessmentError(*_WRAPPER_IMPORT_ERROR)
    files = {name: _sha(raw) for name, raw in _wrapper_sources().items()}
    if files != _LOADED_WRAPPER_HASHES:
        raise AssessmentError("WRAPPER_SOURCE_CHANGED", "wrapper sources changed since this module was imported; import a reviewed update in a new process")
    return {"version": WRAPPER_VERSION, "source_files": files}


def _native_identity(root: Path, evaluator: str) -> dict:
    identity = _manifest()[evaluator]
    for relative, expected in identity["source_files"].items():
        try:
            path = root
            for part in Path(relative).parts:
                path = path / part
                if path.is_symlink():
                    raise AssessmentError("SOURCE_UNAVAILABLE", "source symlink: " + relative)
            raw = path.read_bytes()
        except OSError as exc:
            raise AssessmentError("SOURCE_UNAVAILABLE", relative + ": " + str(exc)) from exc
        if _sha(raw) != expected:
            raise AssessmentError("SOURCE_MISMATCH", "fixed evaluator source changed: " + relative)
    return identity


def _raw_identity(raw: bytes | None) -> dict:
    return {"supplied": raw is not None, "raw_sha256": _sha(raw) if raw is not None else None,
            "byte_length": len(raw) if raw is not None else None}


def _wire_bytes(raw: bytes | None) -> str | None:
    return base64.b64encode(raw).decode("ascii") if raw is not None else None


def _requested(evaluator: str, checks) -> dict:
    if not isinstance(checks, (tuple, list)) or any(not isinstance(c, str) for c in checks):
        raise AssessmentError("INPUT_TYPE_ERROR", "requested_checks must be a list or tuple of check names")
    if len(set(checks)) != len(checks):
        raise AssessmentError("INVALID_CHECK_REQUEST", "duplicate requested check")
    unknown = [c for c in checks if c not in _CHECKS]
    if unknown:
        raise AssessmentError("UNKNOWN_CHECK", "unknown requested check: " + ", ".join(unknown))
    return {"requested": list(checks),
            "supported": [c for c in checks if c in _SUPPORTED[evaluator]],
            "unsupported": [c for c in checks if c not in _SUPPORTED[evaluator]]}


class RecipientAssessor:
    """Use a trusted local source tree; inputs never select executable modules."""

    def __init__(self, *, expected_api_contract: str, source_root=None,
                 timeout_seconds: float = 30.0) -> None:
        if expected_api_contract != API_CONTRACT:
            raise AssessmentError("UNKNOWN_API_CONTRACT", "expected API contract is not supported")
        try:
            timeout_valid = (not isinstance(timeout_seconds, bool) and isinstance(timeout_seconds, (int, float))
                             and math.isfinite(timeout_seconds) and timeout_seconds > 0)
        except OverflowError:
            timeout_valid = False
        if not timeout_valid:
            raise AssessmentError("INVALID_CONFIGURATION", "timeout_seconds must be a positive finite number")
        try:
            self._root = (Path(source_root) if source_root is not None else _HERE.parents[1]).resolve()
        except (TypeError, ValueError, OSError, RuntimeError) as exc:
            raise AssessmentError("INVALID_CONFIGURATION", "invalid source_root") from exc
        self._timeout = timeout_seconds
        _wrapper_identity()

    def capabilities(self) -> dict:
        """Static supported groups, not an execution trace or trust decision."""
        return {"api_contract": API_CONTRACT, "wrapper": _wrapper_identity(), "evaluators": {
            key: {"supported_checks": list(value),
                  "unsupported_checks": [c for c in _CHECKS if c not in value]}
            for key, value in _SUPPORTED.items()}}

    def assess_receipts(self, admission: bytes | None, post: bytes | None, *,
                        requested_checks=()) -> dict:
        for name, value in (("admission", admission), ("post", post)):
            if value is not None and not isinstance(value, bytes):
                raise AssessmentError("INPUT_TYPE_ERROR", name + " must be original bytes or None")
            if value is not None and len(value) > _RECEIPT_LIMIT:
                raise AssessmentError("INPUT_SIZE_ERROR", name + " exceeds the local 1 MiB bound")
        inputs = {"admission": _raw_identity(admission), "post": _raw_identity(post)}
        payload = {"admission": _wire_bytes(admission), "post": _wire_bytes(post)}
        return self._invoke("receipt_pair", payload, inputs, requested_checks)

    def assess_s3(self, bundle, receiver_policy: bytes, *, requested_checks=()) -> dict:
        if not isinstance(receiver_policy, bytes):
            raise AssessmentError("INPUT_TYPE_ERROR", "receiver_policy must be original bytes")
        if len(receiver_policy) > _POLICY_LIMIT:
            raise AssessmentError("INPUT_SIZE_ERROR", "receiver_policy exceeds the local 256 KiB bound")
        if not isinstance(bundle, (str, os.PathLike)):
            raise AssessmentError("INPUT_TYPE_ERROR", "bundle must be a local path")
        try:
            # Do not resolve the bundle symlink: native Bundle must enforce its no-follow rule.
            selected = str(Path(bundle).absolute())
        except (TypeError, ValueError, OSError) as exc:
            raise AssessmentError("INPUT_TYPE_ERROR", "bundle must be a local path") from exc
        inputs = {"bundle": {"selected_path": selected}, "receiver_policy": _raw_identity(receiver_policy)}
        payload = {"bundle": selected, "receiver_policy": _wire_bytes(receiver_policy)}
        return self._invoke("s3_observation", payload, inputs, requested_checks)

    def _invoke(self, evaluator: str, payload: dict, inputs: dict, requested_checks) -> dict:
        checks = _requested(evaluator, requested_checks)
        wrapper = _wrapper_identity()
        identity = _native_identity(self._root, evaluator)
        request = {"evaluator": evaluator, "source_root": str(self._root), "payload": payload}
        executable = sys.executable
        if not executable:
            raise AssessmentError("WORKER_START_FAILED", "cannot locate the running Python executable")
        try:
            # -B prevents cache writes but still permits cached code reads. An
            # empty private prefix also avoids stale native bytecode; the parent
            # removes it even if the worker times out or cannot start.
            with tempfile.TemporaryDirectory(prefix="vate-recipient-bytecode-") as cache:
                completed = subprocess.run(
                    [executable, "-I", "-B", "-X", "pycache_prefix=" + cache, str(_HERE / "_worker.py")],
                    input=json.dumps(request, ensure_ascii=True).encode("utf-8"),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=str(_HERE),
                    timeout=self._timeout, check=False,
                )
        except subprocess.TimeoutExpired as exc:
            raise AssessmentError("WORKER_TIMEOUT", "native worker exceeded the configured timeout") from exc
        except OverflowError as exc:
            raise AssessmentError("INVALID_CONFIGURATION", "timeout_seconds exceeds the platform subprocess timeout range") from exc
        except OSError as exc:
            raise AssessmentError("WORKER_START_FAILED", str(exc)) from exc
        if _wrapper_identity() != wrapper:
            raise AssessmentError("WRAPPER_SOURCE_CHANGED", "wrapper sources changed during invocation")
        if completed.returncode != 0:
            raise AssessmentError("WORKER_FAILED", "native worker exited with code " + str(completed.returncode))
        try:
            response = json.loads(completed.stdout)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise AssessmentError("WORKER_PROTOCOL_ERROR", "worker did not return a JSON response") from exc
        if not isinstance(response, dict):
            raise AssessmentError("WORKER_PROTOCOL_ERROR", "worker response is not an object")
        if set(response) == {"error"}:
            error = response["error"]
            if isinstance(error, dict) and set(error) == {"code", "detail"} and all(isinstance(v, str) for v in error.values()):
                raise AssessmentError(error["code"], error["detail"])
            raise AssessmentError("WORKER_PROTOCOL_ERROR", "invalid worker error")
        if (set(response) != {"native_result", "evaluator"} or not isinstance(response["native_result"], dict)
                or response["evaluator"] != identity):
            raise AssessmentError("WORKER_PROTOCOL_ERROR", "invalid worker result or evaluator identity")
        _native_identity(self._root, evaluator)
        return {"api_contract": API_CONTRACT, "wrapper": wrapper, "evaluator": identity,
                "invocation": {"status": "returned"}, "requested_checks": checks,
                "inputs": inputs, "native_result": response["native_result"]}


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise AssessmentError("CLI_USAGE_ERROR", message)


def _read_input(path: Path | None, limit: int) -> bytes | None:
    if path is None:
        return None
    try:
        if not path.is_file():
            raise OSError("expected a regular local file")
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise AssessmentError("INPUT_SIZE_ERROR", str(path) + ": input exceeds the local " + str(limit) + " byte bound")
        return raw
    except OSError as exc:
        raise AssessmentError("INPUT_FILE_ERROR", str(path) + ": " + str(exc)) from exc


def _policy_inside_bundle(policy: Path, bundle: Path) -> bool:
    policy, bundle = policy.resolve(), bundle.resolve()
    if policy.is_relative_to(bundle):
        return True
    try:
        bundle_stat = bundle.stat()
    except (FileNotFoundError, NotADirectoryError):
        # A missing bundle still belongs to the native insufficient-evidence path.
        return False
    # resolve() need not normalize filesystem case or Unicode aliases. Compare
    # actual locations too, without changing the path passed to native Bundle.
    for candidate in (policy, *policy.parents):
        try:
            candidate_stat = candidate.stat()
        except (FileNotFoundError, NotADirectoryError):
            continue
        if os.path.samestat(candidate_stat, bundle_stat):
            return True
    return False


def main(argv=None) -> int:
    parser = _Parser(prog="vate_recipient.py", description=__doc__)
    parser.add_argument("--api-contract", required=True, help="Expected local API contract identifier")
    parser.add_argument("--source-root", type=Path, help="Trusted VATE source tree; defaults to this tree")
    parser.add_argument("--timeout", type=float, default=30.0, help="Worker timeout in seconds")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    commands.add_parser("capabilities", help="Show static capabilities; no native evaluation")
    receipts = commands.add_parser("receipts", help="Assess original receipt files; omitted files mean not supplied")
    receipts.add_argument("--admission", type=Path)
    receipts.add_argument("--post", type=Path)
    receipts.add_argument("--check", action="append", default=[], help="Requested check name; repeat as needed")
    s3 = commands.add_parser("s3", help="Assess a selected offline bundle with receiver-selected policy bytes")
    s3.add_argument("--bundle", type=Path, required=True)
    s3.add_argument("--receiver-policy", type=Path, required=True)
    s3.add_argument("--check", action="append", default=[], help="Requested check name; repeat as needed")
    try:
        args = parser.parse_args(argv)
        assessor = RecipientAssessor(expected_api_contract=args.api_contract, source_root=args.source_root,
                                     timeout_seconds=args.timeout)
        if args.command == "capabilities":
            result, code = assessor.capabilities(), 0
        else:
            if args.command == "receipts":
                result = assessor.assess_receipts(_read_input(args.admission, _RECEIPT_LIMIT),
                                                  _read_input(args.post, _RECEIPT_LIMIT), requested_checks=args.check)
                code = {"matched": 0, "mismatch": 1, "not_assessed": 2}[result["native_result"]["record_linkage"]]
            else:
                try:
                    policy_inside_bundle = _policy_inside_bundle(args.receiver_policy, args.bundle)
                except (OSError, ValueError, RuntimeError) as exc:
                    raise AssessmentError("INVALID_CONFIGURATION", "cannot resolve the bundle or receiver-policy path") from exc
                if policy_inside_bundle:
                    raise AssessmentError("INVALID_CONFIGURATION", "receiver policy must be supplied outside the bundle")
                result = assessor.assess_s3(args.bundle, _read_input(args.receiver_policy, _POLICY_LIMIT),
                                            requested_checks=args.check)
                code = {"supported_under_local_assumptions": 0, "contradictory": 1, "insufficient": 2,
                        "unsupported": 3}[result["native_result"]["assessment"]]
            if result["requested_checks"]["unsupported"]:
                code = 4
    except AssessmentError as exc:
        result, code = exc.as_dict(), 64
    try:
        output = json.dumps(result, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    except (ValueError, RecursionError):
        result = AssessmentError("WORKER_PROTOCOL_ERROR", "worker result cannot be encoded as JSON").as_dict()
        code = 64
        output = json.dumps(result, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    print(output)
    return code


_LOADED_WRAPPER_HASHES, _WRAPPER_IMPORT_ERROR = _capture_wrapper_import()


if __name__ == "__main__":
    raise SystemExit(main())
