#!/usr/bin/env python3
"""Private isolated transport; use vate_recipient.py as the public entry point."""
from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
import sys


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    api = _load("_vate_recipient_worker_api", Path(__file__).with_name("vate_recipient.py"))
    try:
        api._wrapper_identity()
        request = json.loads(sys.stdin.buffer.read())
        evaluator, payload = request["evaluator"], request["payload"]
        root = Path(request["source_root"])
        identity = api._native_identity(root, evaluator)
        def raw(name):
            value = payload[name]
            return base64.b64decode(value, validate=True) if value is not None else None
        if evaluator == "receipt_pair":
            native = _load("_vate_fixed_receipt", root / "reference/receipt-linkage-example/recipient_example.py")
            reviewer = native.RecipientExample()
            result = reviewer.assess(raw("admission"), raw("post"))
        elif evaluator == "s3_observation":
            # This process is private and isolated. Never expose its generic contract name
            # to the caller, or add a producer bundle/source folder to the import path.
            contract = _load("_vate_fixed_s3_contract", root / "reference/s3-observation-example/contract.py")
            sys.modules["contract"] = contract
            native = _load("_vate_fixed_s3_assessor", root / "reference/s3-observation-example/assess_observation.py")
            try:
                policy = contract.decode(raw("receiver_policy"))
                contract.need(isinstance(policy, dict), "receiver policy object required")
            except (ValueError, TypeError, RecursionError) as exc:
                raise api.AssessmentError("POLICY_INVALID", str(exc)) from exc
            result = native.assess(payload["bundle"], policy)
        else:
            raise api.AssessmentError("WORKER_PROTOCOL_ERROR", "unknown evaluator")
        api._native_identity(root, evaluator)
        response = {"evaluator": identity, "native_result": result}
    except api.AssessmentError as exc:
        response = {"error": {"code": exc.code, "detail": exc.detail}}
    except ImportError as exc:
        response = {"error": {"code": "EVALUATOR_UNAVAILABLE", "detail": str(exc)}}
    except Exception as exc:
        response = {"error": {"code": "EVALUATOR_ERROR", "detail": type(exc).__name__ + ": " + str(exc)}}
    print(json.dumps(response, ensure_ascii=True, allow_nan=False))


if __name__ == "__main__":
    main()
