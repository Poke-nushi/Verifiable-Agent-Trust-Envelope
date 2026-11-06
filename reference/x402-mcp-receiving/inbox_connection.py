"""Store x402 originals using VATE's existing Inbox; no receipt projection."""
from receive import PROFILE, assess, encoded, parse, sha

NATIVE_KIND = "local_x402_mcp_export"


def retain(inbox, *, selection, request, capture):
    """The caller supplies its own initialized trusted local Inbox instance.

    No plan, native verification or execution is invoked. This unknown native
    kind remains unassessable by the generic required-record reviewer.
    """
    inputs = {"selection": selection, "request": request, "capture": capture}
    report = assess(**inputs)
    original_bytes = {**inputs, "inspection": encoded(report)}
    refs = {name: inbox.put(raw) for name, raw in original_bytes.items()}
    ctx = parse(selection, "selection")["context"]
    operation = encoded({k: ctx[k] for k in ("server_id", "operation_id")})
    # Identical intake is idempotent; revised captures or evaluations become
    # separate entries. No occupied original slot is rewritten.
    identity = sha(encoded(refs))
    basis = inbox.put(encoded({"profile": PROFILE, "basis": "local_receiver_registration",
        "originals": refs, "received_at": None, "is_execution_ticket": False}))
    delivery = {"document_type": "recipient_inbox_delivery", "version": 1,
        "event_id": "x402-event-" + identity, "entry_id": "x402-entry-" + identity,
        "source_namespace": "x402-operation-" + sha(operation), "native_input_kind": NATIVE_KIND,
        "received_at": None, "receipt_basis_ref": basis, "originals": refs}
    registration = inbox.receive(encoded(delivery))
    # Check exact originals after registration, including error-path results.
    if any(inbox.get(refs[name]) != raw for name, raw in original_bytes.items()):
        raise RuntimeError("inbox_original_mismatch")
    return {"registration": registration, "originals": refs, "delivery": delivery,
            "generic_native_assessment": "not_supported_for_this_kind",
            "is_execution_ticket": False}
