# Transport Binding Notes
## Proposed ways to carry trust envelope artifacts over existing protocols

## Purpose

This draft should not require a new transport.
Instead, the trust envelope artifacts should be carried over existing protocols in a way that preserves verifier clarity and minimizes protocol conflicts.

This document proposes transport binding principles and a few concrete binding patterns.

---

## Binding Principles

### 1. Do not modify the core transport unless necessary

This draft should prefer application-level envelopes, metadata, or token claims before proposing changes to the transport itself.

### 2. Preserve verifier-visible semantics

A verifier should be able to determine:

- who the actor is
- what permit is being presented
- how the runtime is being claimed
- what audience and resource the permit is targeting

without relying on hidden state.

### 3. Support inline and by-reference presentation

Artifacts may be:

- carried inline
- carried by signed reference
- partially inlined with resolvable references

The verifier should define which modes are accepted.

### 4. Keep canonical fields stable across transports

Regardless of transport, the semantic fields should remain stable:

- actor
- principal
- audience
- resource
- actions
- runtime reference
- permit reference

---

## Proposed Envelope

One practical trust envelope looks like this:

```json
{
  "app_context": {
    "passport": {},
    "runtime_proof": {},
    "mission_permit": {}
  }
}
```

Each object may be:

- fully embedded
- represented as a signed compact token
- replaced by a reference plus digest

---

## A2A Binding

### Goal

Use this draft to complement A2A discovery and task delegation without changing the purpose of the A2A layer itself.

The `v0.3` direction is a reference-only metadata binding for the AL2 verifier admission profile.
The detailed draft binding is in [docs/a2a-metadata-binding-v0.3.md](a2a-metadata-binding-v0.3.md).

### Suggested approach

- keep agent discovery in A2A-native structures
- carry stable references to trust envelope artifacts in task or message metadata where possible
- avoid requiring A2A to carry full permit, status, or receipt bodies unless a profile explicitly chooses that packaging
- require the remote agent or service to verify those artifacts before accepting the delegated task
- prefer `uri`, `media_type`, `digest`, `issuer`, `issued_at`, and `expires_at` descriptors over bare string references

Example metadata shape:

```json
{
  "https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/a2a/admission/v0.3": {
    "profile": "VATE-AL2-Verifier-Admission-v0.3",
    "phase": "admission_issued",
    "transaction_id": "txn:6e7d",
    "assurance_level": "AL2",
    "admission_receipt": {
      "type": "admission_receipt",
      "uri": "https://verifier.example/vate/admission-receipts/admrec-54f2",
      "media_type": "application/vate-admission-receipt+json",
      "digest": {
        "alg": "sha-256",
        "value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      }
    },
    "issuer": "did:web:verifier.example",
    "issued_at": "2026-05-04T03:00:08Z",
    "expires_at": "2026-05-04T03:10:08Z"
  }
}
```

### Important rule

An A2A Agent Card should not be treated as sufficient proof of current authority.
Receipt bodies and attenuation semantics should live in the adjacent verifier / receipt layer, while A2A carries the task flow and optional references.

---

## MCP Binding

### Goal

Use this draft to complement MCP authorization and tool access with stronger caller context.

### Suggested approach

- keep MCP authorization aligned with MCP and OAuth expectations
- carry the trust envelope context in authorization token claims, request metadata, or application-level context passed alongside tool invocation
- let the MCP server evaluate whether the permit and runtime proof are sufficient for the requested tool action

### Important rule

This draft should not require every MCP tool or server to understand new transport primitives before basic interoperability is possible.

VATE must not expand MCP or OAuth authority. The effective authority for a tool
call is the intersection of:

- the MCP server's tool and resource authorization
- the OAuth or OpenID token audience, subject, client, and resource constraints
- the VATE permit, runtime, status, attenuation, and local verifier policy

If the VATE effective request exceeds any upstream authorization boundary, the
verifier should deny or fail closed. An `allow` VATE admission only means the
request passed VATE's additional gate; it is not a union with, or replacement
for, MCP/OAuth authorization.

### AL2 transport-bound fixtures

The `v0.3` conformance corpus includes an MCP/OAuth fixture set. The first
positive fixture binds a single MCP-shaped admission request:

- `examples/transport/mcp-oauth-admission-request.example.json`
- `examples/receipts/admission-allow-mcp-oauth-bound.example.json`
- `conformance/al2-vate-v0.3/cases/allow-mcp-oauth-transport-bound.json`

It also includes a negative fixture proving that VATE cannot widen upstream MCP
or OAuth authority by changing the requested tool beyond the token resource:

- `examples/transport/mcp-oauth-overscope-admission-request.example.json`
- `examples/receipts/admission-deny-mcp-oauth-overscope.example.json`
- `conformance/al2-vate-v0.3/cases/deny-mcp-oauth-overscope.json`

The companion negative fixture keeps the requested MCP tool stable but denies
the request when the OAuth token lacks the action scope:

- `examples/transport/mcp-oauth-upstream-denied-admission-request.example.json`
- `examples/receipts/admission-deny-mcp-oauth-upstream-denied.example.json`
- `conformance/al2-vate-v0.3/cases/deny-mcp-oauth-upstream-denied.json`

Additional negative fixtures keep the same boundary but split common authority
confusion modes into smaller reviewable cases:

- `examples/transport/mcp-oauth-token-passthrough-admission-request.example.json`
- `examples/receipts/admission-deny-token-passthrough-as-authority.example.json`
- `conformance/al2-vate-v0.3/cases/deny-token-passthrough-as-authority.json`
- `examples/transport/mcp-oauth-resource-indicator-drift-admission-request.example.json`
- `examples/receipts/admission-deny-resource-indicator-drift.example.json`
- `conformance/al2-vate-v0.3/cases/deny-resource-indicator-drift.json`
- `examples/transport/mcp-oauth-tool-class-mismatch-admission-request.example.json`
- `examples/receipts/admission-deny-mcp-tool-class-mismatch.example.json`
- `conformance/al2-vate-v0.3/cases/deny-mcp-tool-class-mismatch.json`

Each of those denial modes has a minimal positive-control companion so the
corpus shows that VATE denies the boundary mismatch, not every MCP/OAuth-shaped
input:

- `examples/transport/mcp-oauth-token-authority-bound-admission-request.example.json`
- `examples/receipts/admission-allow-mcp-oauth-token-authority-bound.example.json`
- `conformance/al2-vate-v0.3/cases/allow-mcp-oauth-token-authority-bound.json`
- `examples/transport/mcp-oauth-resource-indicator-aligned-admission-request.example.json`
- `examples/receipts/admission-allow-mcp-oauth-resource-indicator-aligned.example.json`
- `conformance/al2-vate-v0.3/cases/allow-resource-indicator-aligned.json`
- `examples/transport/mcp-oauth-tool-class-aligned-admission-request.example.json`
- `examples/receipts/admission-allow-mcp-oauth-tool-class-aligned.example.json`
- `conformance/al2-vate-v0.3/cases/allow-mcp-tool-class-aligned.json`

The paired cases carry `pairing` metadata in the corpus index. Each pair keeps
the actor, requested target resource, requested action class, local policy, and
freshness window stable, then flips the intended authority boundary fact:

- token authority binding: `missing` versus `matched` upstream authority and
  resource binding
- resource indicator binding: mismatched versus matched OAuth resource and
  protected-resource indicators
- tool-class binding: read/search authority versus write authority for the
  requested tool class

The fixture treats OAuth and OpenID artifacts as verifier evidence.
It does not define a new MCP authorization flow.
The verifier-visible requirement is narrower:

- the MCP target audience is stable
- the OAuth token audience and resource are visible
- the OpenID subject and client binding are visible
- the runtime binding is preserved
- the admission receipt records the evidence and local policy decision
- denial diagnostics use typed reason codes and diagnostic tokens without
  echoing full tokens, tool payloads, or prompt-like resource descriptions

---

## REST and Generic HTTP Binding

### Goal

Allow the trust envelope artifacts to be carried in generic service-to-service HTTP interactions.

### Suggested approach

- use existing authorization channels for bearer or PoP-bound tokens
- carry the trust envelope artifacts or references in request metadata or application payload
- bind audience and nonce/challenge semantics to the receiving service

### Important rule

The verifier should treat trust envelope verification as separate from business authorization, even when both happen in the same request path.

---

## CLI and Local IDE Surfaces

### Goal

Clarify how this draft relates to command-line, IDE, and coding-agent surfaces.

### Suggested approach

- treat a CLI or IDE as a local invocation and presentation surface, not as a separate protocol family
- let that local surface obtain, cache, present, or pre-verify the trust envelope artifacts before outbound calls
- bind decisive verifier checks to the actual remote audience, nonce, and protocol interaction such as MCP, A2A, or HTTP

### Important rule

A CLI command can act as a holder or verifier surface.
But the trust envelope artifacts typically become security-relevant when that local surface triggers an outbound MCP, A2A, or HTTP request that a remote verifier can evaluate.

---

## Delegated Chains

When agent A delegates to agent B:

- the child permit should be narrower than or equal to the parent permit
- delegated depth should be explicit
- the receipt chain should remain linkable
- each verifier should evaluate the child request independently

---

## Recommended Direction

The best near-term strategy is:

1. keep this draft transport-neutral in the core spec
2. publish narrow binding notes for A2A, MCP, and HTTP
3. let profiles tighten specific rules as implementations mature

That approach keeps this draft composable while still giving implementers something concrete to build against.
