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

### Suggested approach

- keep agent discovery in A2A-native structures
- carry the trust envelope artifacts in message metadata or a request envelope
- require the remote agent or service to verify those artifacts before accepting the delegated task

### Important rule

An A2A Agent Card should not be treated as sufficient proof of current authority.

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
