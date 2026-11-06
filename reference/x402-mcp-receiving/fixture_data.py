"""Hand-authored synthetic SDK exports, not records from an x402 execution."""
from copy import deepcopy

from receive import EXPORT, PROFILE, SDK, CANCEL_UNKNOWN, encoded, sha

CASE_IDS = ("01-cancel-unknown", "02-upfront-and-unknown", "03-reapproval-return",
            "04-reapproval-exception-result", "05-reapproval-exception-mcp-result")


def fixture(case_id):
    if case_id not in CASE_IDS:
        raise ValueError("unknown fixture")
    request = encoded({"name": "synthetic_paid_tool", "arguments": {"input": 1}})
    ctx = {"server_id": "synthetic-server", "operation_id": "synthetic-operation",
           "attempt_id": case_id}
    denied = case_id.startswith(("03", "04", "05"))
    offer = {"x402Version": 2, "accepts": [{"scheme": "exact", "network": "eip155:84532",
             "amount": "1000", "asset": "USDC", "payTo": "0xrecipient", "maxTimeoutSeconds": 300}]}
    texts = ([encoded(offer).decode().strip()] if denied else
             ["Payment metering failed", CANCEL_UNKNOWN])
    blocks = [{"type": "text", "text": text} for text in texts]
    upfront = case_id.startswith("02")
    receipt = ({"success": True, "transaction": "synthetic-deposit-not-a-real-transaction",
                "network": "eip155:84532", "amount": "1000"} if upfront else None)
    carrier, error, kind = "return", None, "sync"
    if case_id.startswith("04"):
        carrier, error, kind = "exception.result", "PaymentRequiredError", "async"
    elif case_id.startswith("05"):
        carrier, error, kind = "exception.mcp_result", "ValueError", "async"
    capture = encoded({"export_profile": EXPORT, "sdk": SDK, "client_kind": kind,
        "origin": "synthetic_fixture", "context": ctx, "request_sha256": sha(request),
        "carrier": carrier, "exception_type": error,
        "result": {"content": deepcopy(blocks), "is_error": True, "payment_made": True,
                   "payment_response": deepcopy(receipt),
                   "raw_result": {"content": blocks, "is_error": True,
                       "meta": {"x402/payment-response": receipt} if receipt else {},
                       "structured_content": None}},
        "local_observations": {"payment_phase": "before_handler" if upfront else "unknown",
                               "reapproval": "denied" if denied else "not_recorded",
                               "client_recovered": True if denied else None}})
    selection = encoded({"profile": PROFILE, "context": ctx,
                         "request_sha256": sha(request), "capture_sha256": sha(capture)})
    return {"selection": selection, "request": request, "capture": capture}
