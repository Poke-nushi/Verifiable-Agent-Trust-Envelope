# AP2 / UCP Commerce To VATE Crosswalk

## Status

This is a small interoperability note for the `VATE AL2 Admission Interop Profile 2026-07`.

It does not claim that VATE replaces AP2, UCP, A2A, PSP rails, wallet flows, merchant checkout systems, or banking systems.
It shows how an AP2 / UCP-style commerce flow can be consumed as VATE evidence at the verifier-side admission boundary.

Relevant adjacent references:

- Google Cloud AP2 announcement: <https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol>
- UCP overview: <https://ucp.dev/2026-01-23/>
- UCP repository: <https://github.com/universal-commerce-protocol/ucp>

## Boundary

AP2 / UCP is close to:

- agentic commerce discovery
- checkout session negotiation
- user or wallet payment mandates
- payment service provider handoff
- merchant order lifecycle
- A2A or MCP transport between agents and services

VATE's narrower role is:

- take AP2 / UCP artifacts as `evidence_ref`
- bind them to actor, principal, runtime, target audience, action, amount, and local policy
- decide whether the risky external digital action is admitted, narrowed, or denied
- emit a VATE admission receipt before execution
- link later order, payment, and fulfillment evidence back to the admitted request

These mappings are evidence-consumption mappings, not semantic equivalence
mappings. VATE does not assert that an adjacent artifact is valid, current,
sufficient, or transferable merely because it is mapped to a VATE evidence
type. Validity and authority must be established by adjacent-protocol
verification, trust bundles, status checks, and local policy.

## Mapping

| AP2 / UCP concept | VATE field |
|---|---|
| User intent / mandate | `evidence_refs[type=payment_mandate, protocol_hint=ap2]` |
| Cart or checkout session | `evidence_refs[type=ucp_checkout_session]` |
| Merchant / checkout endpoint | `target.resource` |
| Merchant or PSP audience | `target.audience` and `audience` |
| Agent identity | `actor` |
| Buyer or account holder | `principal` |
| Agent runtime binding | `runtime` |
| Payment amount or spending limit | `constraints.max_amount` and optional attenuation |
| Order or payment status | admission receipt `evidence[].verification.status_result` and later post-execution receipt |
| A2A task or context | admission request `correlation` and admission receipt `request` |

The native AP2 mandate fixture may still use its source protocol field
`type=ap2_mandate`. VATE records that artifact as generic
`payment_mandate` evidence with `protocol_hint=ap2`.

## PoC Fixture

The fixture under `examples/interop/ap2-ucp-to-vate/` uses:

- `ap2-mandate.example.json` as adjacent payment authority evidence
- `ucp-checkout-session.example.json` as adjacent commerce session evidence
- `vate-admission-request-from-ap2-ucp.example.json` as the VATE request
- `vate-admission-receipt-from-ap2-ucp.example.json` as the verifier decision

The corresponding conformance case is:

- `conformance/al2-vate-v0.3/cases/interop-ap2-ucp-commerce-evidence.json`

## Non-Goals

This crosswalk does not define AP2, UCP, payment settlement, chargeback handling, merchant-of-record semantics, wallet UX, or banking ledger behavior.
It only demonstrates how a VATE verifier can consume adjacent commerce and payment artifacts as evidence before admitting a risky purchase action.
