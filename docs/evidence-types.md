# VATE Evidence Types

## Status

This registry is the canonical evidence type vocabulary for the
`VATE AL2 Verifier Admission v0.2` conformance corpus.

Evidence `type` values are generic verifier inputs.
Concrete adjacent protocols belong in `protocol_hint` when the distinction is
useful for logs, receipts, or local policy.

## Core Rule

Admission requests and admission receipts MUST use a canonical `type` value
from this registry when they are evaluated under the AL2 v0.2 conformance
profile.

`protocol_hint` is optional and informative. A verifier MUST NOT infer trust,
authority, freshness, or spend limits from `protocol_hint` alone. Those
properties must come from the verified evidence content, trust bundle, status
checks, and local policy.

For example, AP2 Human Not Present payment authority is represented as:

```json
{
  "type": "payment_mandate",
  "protocol_hint": "ap2_human_not_present"
}
```

## Canonical Evidence Types

### Admission And Receipts

- `admission_request`
- `admission_receipt`
- `post_execution_receipt`
- `attenuation_candidate`

### Agent And Identity Evidence

- `agent_card`
- `signed_agent_card`
- `openid_subject`
- `oid4vp_presentation`
- `verifiable_credential`
- `vc_status`
- `did_document`

### Authorization And Transport Evidence

- `oauth_access_token`
- `oauth_transaction_token`
- `mission_permit`
- `http_message_signature`
- `web_bot_auth_signature`

### Runtime And Status Evidence

- `runtime_attestation`
- `runtime_disclosure`
- `status_bundle`

### Policy Evidence

- `local_policy`
- `policy_snapshot`

### Payment And Commerce Evidence

- `payment_authority`
- `payment_mandate`
- `payment_required_state`
- `delegated_payment_token`
- `ucp_checkout_session`

### Adjacent Decision Evidence

- `oap_decision`

## Canonical Protocol Hints

- `ap2`
- `ap2_human_not_present`
- `mcp-oauth`
- `oap_aport`
- `openid-connect`
- `spiffe`
- `stripe_spt`
- `ucp`
- `x402`

## Extension Rule

The AL2 v0.2 conformance corpus is closed over the values above.
Unknown evidence types or protocol hints fail the profile checks.

Future profiles may add values, but they should prefer a generic evidence type
plus a protocol hint when the same verifier semantics are shared across
adjacent protocols.
