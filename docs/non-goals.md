# Non-Goals

This note makes the draft boundary explicit.

This draft is intentionally narrow.
If it grows into every adjacent layer, it becomes a vague platform idea instead of a reviewable protocol draft.

## What This Draft Is Not Trying To Be

- a universal agent ID registry
- a single global passport issuer
- a transport protocol that replaces A2A, MCP, or HTTP
- a multi-agent control plane
- an orchestration broker
- a marketplace, scanner, or registry product
- a gateway or API management product
- an eval, observability, or A/B testing suite
- a payment settlement rail
- an agent checkout protocol
- a crawler payment protocol
- a universal reputation score
- a generic trust score for every verifier and domain
- a request-signature or web bot authentication scheme
- a global policy language
- an A2A core state-machine extension
- an MCP authorization replacement
- a runtime disclosure manifest format
- a mandatory real-name identity system for every assurance level
- a forced blockchain, cloud, DID method, or PKI topology

## Why These Are Non-Goals

### 1. Keep the core legible

The repo is strongest when it stays centered on:

- credential
- runtime proof
- mission permit
- admission and post-execution receipts
- status and attenuation

### 2. Compose rather than replace

Other layers already exist for:

- discovery
- messaging
- delegated authorization
- checkout and payment tokenization
- signed automated web requests
- workload identity
- governance
- transport

This draft should compose with them rather than re-specify them.

For `v0.2`, this means A2A, MCP, OAuth, OID4VP, VC, DID, Web Bot Auth, AP2, x402, ACP, and payment-token systems are treated as adjacent evidence or transport layers.
VATE standardizes the verifier-side admission decision and receipt semantics around those inputs.

### 3. Avoid platform sprawl

Recent product signals make this more important, not less.
Vendors are already building:

- enterprise execution surfaces
- control planes
- gateway enforcement
- marketplaces and registries

If this draft chases those layers directly, the protocol boundary becomes blurry.

## What This Draft Does Try To Standardize

This draft is trying to standardize a portable artifact model for:

- who is acting
- on whose behalf
- in which runtime
- under which task-scoped permit
- with which status outcome
- with which receipt afterward

That is the narrow boundary this draft should protect.

The v0.2 AL2 verifier admission profile narrows this further to:

- verifier-side admission requests
- evidence references
- `allow`, `attenuate`, or `deny` decisions
- machine-readable attenuation
- admission receipts
- post-execution receipts linked to admission receipts
