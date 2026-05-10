# VATE Evidence Types

## Status

The machine-readable registry is
[`registries/evidence-vocabulary.v0.3.json`](../registries/evidence-vocabulary.v0.3.json).
That file is the canonical source for evidence type values, protocol hint
values, and allowed evidence type / protocol hint combinations under the
`VATE AL2 Verifier Admission v0.3` conformance corpus.

This document is the human-readable companion to that registry.

Some JSON Schemas repeat the registry values as local enums so standalone
schema validators can reject unknown values without custom registry loading.
`scripts/check_repo.py` treats those enums as derived copies and fails if they
drift from the machine-readable registry.

Evidence `type` values are generic verifier inputs.
Concrete adjacent protocols belong in `protocol_hint` when the distinction is
useful for logs, receipts, or local policy.

## Core Rule

Admission requests and admission receipts MUST use a canonical `type` value
from this registry when they are evaluated under the AL2 v0.3 conformance
profile.

`protocol_hint` is optional and informative. When present, it MUST be allowed
for the evidence `type` by the machine-readable registry. A verifier MUST NOT
infer trust, authority, freshness, or spend limits from `protocol_hint` alone.
Those properties must come from the verified evidence content, trust bundle,
status checks, and local policy.

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

## Allowed Type / Hint Combinations

The following combinations are registered for the AL2 v0.3 conformance profile.
Any `protocol_hint` not listed for a given `type` fails the profile checks.

| Evidence type | Allowed protocol hints |
| --- | --- |
| `delegated_payment_token` | `stripe_spt` |
| `oap_decision` | `oap_aport` |
| `oauth_access_token` | `mcp-oauth` |
| `oauth_transaction_token` | `mcp-oauth` |
| `openid_subject` | `openid-connect` |
| `payment_authority` | `x402` |
| `payment_mandate` | `ap2`, `ap2_human_not_present` |
| `payment_required_state` | `x402` |
| `runtime_attestation` | `spiffe` |
| `ucp_checkout_session` | `ucp` |
| `verifiable_credential` | `oap_aport` |

All other registered evidence types currently have no registered
`protocol_hint` values in this profile.

## Extension Rule

The AL2 v0.3 conformance corpus is closed over the values in
`registries/evidence-vocabulary.v0.3.json`. Unknown evidence types, unknown
protocol hints, or unregistered type/hint combinations fail the profile checks.

Future profiles may add values, but they should prefer a generic evidence type
plus a protocol hint when the same verifier semantics are shared across
adjacent protocols.
