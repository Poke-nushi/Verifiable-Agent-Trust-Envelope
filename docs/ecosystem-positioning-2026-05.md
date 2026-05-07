# VATE Ecosystem Positioning - May 2026

## Status

This note records the current public positioning boundary for VATE after the May 2026 agentic commerce and protocol updates.

It is not a new profile and does not broaden the `VATE AL2 Verifier Admission v0.2` scope.

## Boundary

VATE is a verifier-side admission and receipt layer for risky external digital actions.

It should consume adjacent artifacts by reference, bind them to the concrete action context, and emit admission and post-execution receipts.
It should not redefine the adjacent protocols that already own identity, transport, checkout, payment authority, or payment rails.

## Adjacent Protocol Roles

| Surface | Primary role | VATE relationship |
|---|---|---|
| MCP / OAuth | Tool/resource access, token issuance, audience/resource validation, scope challenges | Input to admission. VATE should run after transport authorization and record verifier-side policy, freshness, replay, and receipt evidence. |
| A2A | Agent discovery, task coordination, metadata, extensions, signed Agent Cards | Metadata and identity-adjacent binding surface. VATE should use digest-bound references rather than embedding large artifacts. |
| AP2 / Verifiable Intent | User-authorized payment authority and agentic payment mandates | Payment-authority evidence. VATE should check mandate freshness, limits, replay state, actor/principal/runtime binding, and local policy. |
| ACP / UCP | Commerce checkout/session/order flow | Commerce-session evidence. VATE should bind checkout/session artifacts to the admitted action without redefining merchant checkout. |
| x402 / payment rails | Payment requirement, verification, settlement, or rail-specific payment proof | Payment-state evidence. VATE should reference payment proof or payment-required state when local policy needs it. |
| Runtime attestation | Workload/runtime binding | Evidence for actor/runtime checks and post-execution accountability. |

## Current Public Claim

For AL2 external digital actions, VATE's strongest claim is:

1. Before execution, a verifier evaluates actor, principal, runtime, audience, evidence references, policy snapshot, status freshness, replay controls, and limits.
2. The verifier returns `allow`, `attenuate`, or `deny` with machine-readable reason codes.
3. If execution proceeds, post-execution evidence links the side effect back to the admission receipt and effective request hash.

## Non-Goals

VATE should not present itself as:

- a payment protocol
- a checkout protocol
- an OAuth or MCP profile
- an A2A replacement
- a wallet, PSP, or settlement layer
- an identity registry

## May 2026 Inputs

The following public updates make this boundary more important:

- AP2 was contributed to FIDO, and AP2 v0.2 added Human Not Present payment flows: <https://blog.google/products-and-platforms/platforms/google-pay/agent-payments-protocol-fido-alliance/>
- FIDO announced agentic authentication and payments workstreams around verifiable user instructions, agent authentication, and trusted delegation: <https://fidoalliance.org/fido-alliance-to-develop-standards-for-trusted-ai-agent-interactions/>
- A2A v1.0 stabilized signed Agent Cards, extension governance, and enterprise deployment requirements: <https://a2a-protocol.org/latest/announcing-1.0/>
- MCP authorization continues to harden around OAuth 2.1, Protected Resource Metadata, Resource Indicators, Client ID Metadata Documents, PKCE, and least-privilege scope handling: <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>

## Implementation Consequence

The immediate implementation priority is not to define a broad commerce profile.

This repository therefore includes small conformance fixtures that show VATE consuming AP2-style Human Not Present payment authority as evidence, enforcing limits and freshness, detecting replay, and linking post-execution receipts.
