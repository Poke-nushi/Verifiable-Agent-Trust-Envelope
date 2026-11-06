"""Run pinned x402 SDK code with local test doubles and export actual returns.

No MCP transport, wallet, cryptographic signature, or payment service is used.
The two cancellation-fault cases inject failure at the dispatcher boundary.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile

HERE = Path(__file__).resolve().parent
VENDOR = None
COMMIT = "2ef9f3872fbc0cfc93b1143f26ed668d13a7725e"
CASES = ("01-cancel-unknown", "02-upfront-and-unknown", "03-reapproval-return", "04-success-control")
NETWORK = "x402:cash"


def require(value, message):
    if not value:
        raise RuntimeError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    raw = value if type(value) is bytes else encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
    return {"sha256": sha(raw), "bytes": len(raw)}


def tool_snapshot(result):
    # Explicit field export from x402.mcp.types.MCPToolResult, not a wire trace.
    require(set(vars(result)) == {"content", "is_error", "meta", "structured_content"},
            "unexpected SDK raw-result fields")
    return json.loads(encoded({"content": result.content, "is_error": result.is_error,
        "meta": result.meta, "structured_content": result.structured_content}))


def result_snapshot(result):
    require(set(vars(result)) == {"content", "is_error", "payment_made", "payment_response", "raw_result"},
            "unexpected SDK call-result fields")
    receipt = result.payment_response
    return json.loads(encoded({"content": result.content, "is_error": result.is_error,
        "payment_made": result.payment_made,
        "payment_response": None if receipt is None else receipt.model_dump(
            mode="json", by_alias=True, exclude_none=True),
        "raw_result": tool_snapshot(result.raw_result)}))


def run_case(case_id, target, attempt_id):
    from x402 import x402ClientSync, x402ResourceServerSync
    from x402.mcp.client import x402MCPClientSync
    from x402.mcp.server_sync import create_payment_wrapper_sync
    from x402.mcp.types import PaymentWrapperHooks, SyncPaymentWrapperConfig
    from x402.schemas import (PaymentRequirements, RecoveredResponseResult,
                              SettleResponse, SupportedKind, SupportedResponse, VerifyResponse)

    target.mkdir(mode=0o700)
    events, tool_returns = [], []
    fault = case_id in CASES[:2]
    upfront = case_id == CASES[1]
    denied = case_id == CASES[2]
    context = {"server_id": "local-sdk-test-server", "operation_id": "sdk-intake-" + case_id,
               "attempt_id": attempt_id}
    request = {"name": "sdk_intake_tool", "arguments": {"input": 1, "label": case_id}}
    request_bytes = encoded(request)
    # These are fixed before the SDK call; no identity is adopted from the return.
    save(target / "request.json", request_bytes)
    save(target / "receiver-plan.json", {"profile": "vate-local-x402-mcp-receiving-v1",
        "context": context, "request_sha256": sha(request_bytes)})

    def event(kind, **detail):
        events.append({"sequence": len(events) + 1, "kind": kind, **detail})

    class LocalFacilitator:
        """Only supplies predetermined local verification/settlement responses."""
        def get_supported(self):
            return SupportedResponse(kinds=[SupportedKind(x402_version=2, scheme="cash", network=NETWORK)],
                                     extensions=[], signers={})

        def verify(self, payload, requirements):
            event("facilitator_verify", test_double=True, accepted=not denied)
            return VerifyResponse(is_valid=not denied,
                invalid_reason="local_test_correction_required" if denied else None,
                payer="test-payer-no-wallet")

        def settle(self, payload, requirements):
            event("facilitator_settle", test_double=True, amount=requirements.amount)
            return SettleResponse(success=True, transaction="local-test-receipt-" + case_id,
                                  network=NETWORK, amount=requirements.amount)

    class LocalScheme:
        scheme = "cash"
        default_asset_transfer_method = "default"
        payment_flows = {"default": {"supported": ("authorization", "upfront"), "default": "authorization"}}

        def enhance_payment_requirements(self, requirements, supported_kind, extensions):
            return requirements

        def create_payment_payload(self, requirements):
            event("test_payload_created", amount=requirements.amount, cryptographic_signature=False)
            return {"localTestOnly": True, "case": case_id}

    class FaultDispatcher:
        def cancel_sync(self, options):
            event("cancellation_fault_injected", reason=options.reason, test_double=True)
            raise TimeoutError("local injected cancellation failure")

    class ResourceServerWithCancelFault(x402ResourceServerSync):
        # This is the sole overridden SDK method. No vendor file is changed.
        def create_payment_cancellation_dispatcher(self, *args, **kwargs):
            if fault:
                return FaultDispatcher()
            return super().create_payment_cancellation_dispatcher(*args, **kwargs)

    server = ResourceServerWithCancelFault(LocalFacilitator())
    server.register(NETWORK, LocalScheme())
    server.initialize()
    server.on_before_settle(lambda ctx: event("sdk_settlement_phase", phase=ctx.phase))
    terms = PaymentRequirements(scheme="cash", network=NETWORK, asset="USD", amount="1000",
        pay_to="test-recipient-no-wallet", max_timeout_seconds=300,
        extra={"paymentFlow": "upfront"} if upfront else {})

    def meter(ctx):
        event("metering_hook", inject_invalid_amount=fault)
        if fault:
            ctx.payment_requirements.amount = "1001"
        return True

    def handler(arguments, tool_context):
        event("local_handler_called", external_side_effect=False)
        return {"content": [{"type": "text", "text": "local SDK control output"}], "isError": False}

    wrapped = create_payment_wrapper_sync(server, SyncPaymentWrapperConfig(
        accepts=[terms], hooks=PaymentWrapperHooks(on_before_execution=meter)))(handler)

    class InProcessTransport:
        def call_tool(self, params, **kwargs):
            application_request = {"name": params["name"], "arguments": params["arguments"]}
            require(application_request == request, "SDK changed application request")
            meta = params.get("_meta", {})
            event("in_process_tool_call", payment_present="x402/payment" in meta,
                  request_sha256=sha(encoded(application_request)))
            native = wrapped(params["arguments"], {"toolName": params["name"], "_meta": meta})
            tool_returns.append(tool_snapshot(native))
            return native

    payment_client = x402ClientSync()
    payment_client.register(NETWORK, LocalScheme())
    payment_client.set_spend_controls({"allowed_assets": [
        {"network": NETWORK, "asset": "USD", "max_amount_per_payment": "1000"}]})

    def response_hook(ctx):
        recovered = denied and ctx.payment_required is not None
        event("sdk_payment_response_hook", recovered=recovered,
              settlement_present=ctx.settle_response is not None)
        return RecoveredResponseResult() if recovered else None

    payment_client.on_payment_response(response_hook)
    approvals = []

    def approve(ctx):
        allowed = not (denied and approvals)
        approvals.append(allowed)
        event("application_approval", allowed=allowed)
        return allowed

    client = x402MCPClientSync(InProcessTransport(), payment_client, on_payment_requested=approve)
    native = client.call_tool(request["name"], request["arguments"])
    result = result_snapshot(native)
    # Snapshot everything first. Later verification must not repair a surprising result.
    native_ref = save(target / "native-sdk-result.json", result)
    save(target / "native-tool-results.json", tool_returns)
    local = {"payment_phase": "before_handler" if any(
        e["kind"] == "sdk_settlement_phase" and e["phase"] == "before-handler" for e in events) else "unknown",
        "reapproval": "denied" if len(approvals) > 1 and approvals[-1] is False else "not_recorded",
        "client_recovered": next((e["recovered"] for e in reversed(events)
                                  if e["kind"] == "sdk_payment_response_hook"), None)}
    capture = {"export_profile": "local-x402-python-mcp-export-v1",
        "sdk": {"package": "x402", "version": "2.27.0", "source_commit": COMMIT},
        "client_kind": "sync", "origin": "retained_sdk_export", "context": context,
        "request_sha256": sha(request_bytes), "carrier": "return", "exception_type": None,
        "result": result, "local_observations": local}
    capture_ref = save(target / "capture.json", capture)
    save(target / "TRACE.json", {"case": case_id, "events": events,
        "sdk_result_type": type(native).__module__ + "." + type(native).__name__,
        "sdk_raw_result_type": type(native.raw_result).__module__ + "." + type(native.raw_result).__name__,
        "sdk_result_ref": native_ref, "capture_ref": capture_ref,
        "real_sdk_modules": ["x402.client", "x402.server", "x402.mcp.client", "x402.mcp.server_sync"],
        "test_doubles": ["InProcessTransport", "LocalFacilitator", "LocalScheme", "local tool handler",
                         "application approval/response/metering hooks"] + (["FaultDispatcher"] if fault else []),
        "mcp_wire_transport_used": False, "real_payment_used": False,
        "cryptographic_signature_verified": False})
    return {"case": case_id, "capture": capture_ref, "result": native_ref}


def snapshot_source(source, target, pins):
    """Copy only verified source files into a fresh import tree without caches."""
    seen = set()
    for pin in pins["files"]:
        rel = PurePosixPath(pin["path"])
        require(not rel.is_absolute() and rel.parts and
                all(p not in (".", "..") for p in rel.parts) and
                str(rel) == pin["path"] and "\\" not in str(rel) and
                str(rel) not in seen, "invalid SDK source inventory")
        seen.add(str(rel))
        raw = (source / rel).read_bytes()
        require(len(raw) == pin["bytes"] and sha(raw) == pin["sha256"], "SDK source changed")
        destination = target / rel
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        save(destination, raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-source", type=Path, required=True, help="Root of the fixed x402 source checkout")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--case", choices=CASES)
    parser.add_argument("--attempt-id", default="application-call-001")
    args = parser.parse_args(argv)
    require(re.fullmatch(r"[A-Za-z0-9._-]{1,128}", args.attempt_id), "invalid local attempt label")
    source_root = args.sdk_source.resolve(strict=True)
    pins = json.loads((HERE / "SOURCE.json").read_bytes())
    require(pins["source_commit"] == COMMIT, "SDK source commit changed")
    # Do not execute pre-existing bytecode or unlisted modules from the supplied
    # checkout. This also freezes the verified bytes before SDK imports begin.
    with tempfile.TemporaryDirectory(prefix="vate-x402-source-") as temporary:
        sdk_root = Path(temporary).resolve()
        snapshot_source(source_root, sdk_root, pins)
        return capture(args, sdk_root, pins)


def capture(args, sdk_root, pins):
    global VENDOR
    VENDOR = sdk_root / "python"
    sys.dont_write_bytecode = True
    dependencies = json.loads((HERE / "DEPENDENCIES.json").read_bytes())
    for pin in dependencies["packages"]:
        require(importlib.metadata.version(pin["name"]) == pin["version"], "SDK dependency changed")
    network_attempts = []

    def network_guard(event, arguments):
        if event in ("socket.connect", "socket.sendto", "socket.getaddrinfo", "socket.bind"):
            network_attempts.append(event)
            raise RuntimeError("network operations disabled in local SDK experiment")

    sys.addaudithook(network_guard)
    sys.path.insert(0, str(VENDOR))
    import x402
    require(Path(x402.__file__).resolve() == VENDOR / "x402/__init__.py", "wrong SDK module")
    require(x402.__version__ == "2.27.0", "SDK version label mismatch")
    args.out.mkdir(mode=0o700)
    cases = (args.case,) if args.case else CASES
    rows = [run_case(case_id, args.out / case_id, args.attempt_id) for case_id in cases]
    imported = []
    for name, module in sorted(sys.modules.items()):
        if name == "x402" or name.startswith("x402."):
            path = Path(module.__file__).resolve()
            require(path.is_relative_to(VENDOR), "mixed SDK import source")
            expected = next((p for p in pins["files"] if p["path"] == str(path.relative_to(sdk_root))), None)
            require(expected is not None and sha(path.read_bytes()) == expected["sha256"], "unlisted or changed SDK module")
            imported.append({"module": name, "path": str(path.relative_to(VENDOR)),
                             "sha256": sha(path.read_bytes())})
    require(not network_attempts, "unexpected attempted network operation")
    files = {str(p.relative_to(args.out)): {"sha256": sha(p.read_bytes()), "bytes": p.stat().st_size}
             for p in sorted(args.out.rglob("*.json"))}
    save(args.out / "CAPTURE-MANIFEST.json", {"source_commit": COMMIT, "cases": rows, "files": files,
        "capture_script_sha256": sha(Path(__file__).read_bytes()),
        "python": sys.version, "sdk_source_commit": COMMIT, "imported_sdk_modules": imported,
        "network_guard_attempts": network_attempts, "network_guard_is_full_os_sandbox": False,
        "origin": "real_pinned_sdk_with_local_test_doubles", "external_service_or_payment": False,
        "export_serialization": "explicit SDK attributes; receipt model_dump json/by_alias/exclude_none"})
    print(json.dumps({"sdk_cases_captured": len(rows), "loaded_sdk_modules": len(imported),
                      "network_attempts": len(network_attempts), "external_service_or_payment": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
