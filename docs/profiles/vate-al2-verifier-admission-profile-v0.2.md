# VATE AL2 Verifier Admission Profile v0.2
## Narrow profile for external digital action admission

## Status

This document is a `v0.2` profile proposal.
It does not replace the `v0.1` core discussion draft or the existing AL2 minimal profile.

The goal is to make one verifier-side boundary precise enough for review:

> May this actor and runtime perform this requested action, for this principal, under these constraints, at this time, according to this verifier policy?

## Scope

This profile is for `AL2` external digital actions where an agent action can cause a meaningful side effect in another system.

Examples include:

- creating, updating, sending, booking, purchasing, or deleting through a remote service
- invoking an MCP tool with write effects
- accepting an A2A delegated task that can trigger a digital write
- using a payment mandate, payment token, or payment-required event as part of the admission decision

This profile is not intended for safety-critical physical actuation, regulated financial settlement, or a global identity layer.

## Boundary

VATE v0.2 stays adjacent to A2A, MCP, OAuth, VC, DID, OID4VP, Web Bot Auth, AP2, x402, ACP, and payment-token systems.

Those systems provide discovery, credentials, authorization tokens, signed requests, mandates, or payment evidence.
This profile defines how a verifier turns those inputs into:

- `allow`
- `attenuate`
- `deny`

and how it records that decision in receipts.

## Required Profile Concepts

### Admission Request

An admission request is the verifier input for one requested action.
It may be carried over HTTP, referenced from A2A metadata, or bound to an MCP tool call.

It should identify:

- the requested action
- the target resource
- the actor
- the principal
- the runtime
- the audience
- the input digest
- evidence references

### Evidence Reference

Evidence references point to artifacts that the verifier consumed or resolved.

Examples include:

- A2A Agent Card or signed Agent Card
- OAuth access token or transaction token
- OID4VP presentation
- Verifiable Credential or status list entry
- HTTP message signature or Web Bot Auth evidence
- runtime attestation or runtime disclosure manifest
- payment mandate, payment-required state, delegated payment token, or payment authority evidence

Concrete systems such as AP2, x402, ACP, and Stripe-style delegated payment tokens are examples of those evidence sources.
The core evidence type should stay generic unless a profile intentionally defines a protocol-specific subtype.

VATE does not define these evidence formats.
It records how they were used in the admission decision.

### Admission Receipt

An admission receipt is issued before execution.
It records the verifier decision and the policy basis for that decision.

For AL2, an admission receipt should include:

- receipt id
- transaction id
- actor, principal, and runtime
- action and input digest
- decision outcome
- reason codes
- policy id and policy version
- evidence verification results
- expiration
- attenuation details when the verifier narrowed the request

### Post-Execution Receipt

A post-execution receipt is issued after execution or after an attempted execution.
It links back to the admission receipt.

For AL2, it should include:

- admission receipt reference and digest
- transaction id
- effective request hash
- runtime id
- execution start and finish time
- result outcome
- output digest
- side effects
- policy violations, if any

## Verification Stages

The earlier v0.1 shorthand was:

`status -> identity -> runtime -> permit -> policy`

That remains a useful mental model, but v0.2 treats verification as dependency-aware stages rather than a rigid linear order.

Recommended stages:

1. Parse and classify the request.
2. Resolve evidence references.
3. Verify identity, principal, and actor binding.
4. Verify runtime binding and freshness.
5. Verify task-scoped permit or mandate constraints.
6. Check status, revocation, suspension, quarantine, and freshness.
7. Evaluate local verifier policy.
8. Decide `allow`, `attenuate`, or `deny`.
9. Issue or persist an admission receipt.
10. Require or issue a post-execution receipt when execution proceeds.

All required stages should be reflected in the receipt evidence and reason codes.

## Decision Model

### `allow`

The verifier found the evidence sufficient and did not narrow the requested authority.

### `attenuate`

The verifier found enough evidence to proceed only after narrowing the requested authority.

Examples:

- lower the maximum amount
- restrict the target merchant or resource
- narrow the tool allowlist
- shorten the execution window
- require a fresh permit before a larger action

Attenuation must be machine-readable.
It should include the original request hash, the effective request hash, explicit changes, reason codes, and effective constraints.

### `deny`

The verifier rejects the request before execution.

Examples:

- expired permit
- audience mismatch
- revoked or suspended status
- stale runtime proof
- missing approval
- digest mismatch
- unsupported attenuation effect

## Status And Freshness

AL2 defaults should normally fail closed when current status cannot be established.

A profile implementation may allow bounded exceptions for low-risk actions, but the admission receipt must record:

- status source
- checked time
- result
- freshness requirement
- fail behavior
- reason code when unavailable or stale

## A2A Binding

A2A should carry task flow and optional VATE references.
It should not carry the full VATE receipt body by default.

The profile-specific binding is described in:

- [docs/a2a-metadata-binding-v0.2.md](../a2a-metadata-binding-v0.2.md)

## Receipt Model

The v0.2 receipt split is described in:

- [docs/receipt-model-v0.2.md](../receipt-model-v0.2.md)

## Non-Goals

This profile does not define:

- A2A core type changes
- a universal trust score
- a new agent identity registry
- a new signature scheme
- a payment settlement protocol
- an MCP authorization replacement
- a global policy language
- a runtime disclosure manifest format

## Related Schemas

- `schemas/admission-request.schema.json`
- `schemas/evidence-reference.schema.json`
- `schemas/artifact-reference.schema.json`
- `schemas/a2a-vate-metadata.schema.json`
- `schemas/admission-receipt.schema.json`
- `schemas/post-execution-receipt.schema.json`
