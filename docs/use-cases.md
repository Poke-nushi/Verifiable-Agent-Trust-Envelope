# Use Cases

This note makes the current draft more concrete.
It focuses on three scenarios that match the current repository emphasis:

- AL2 external digital write
- MCP tool call with delegated user context
- agent-to-agent delegation

These are illustrative scenarios, not normative wire-format requirements.

## 1. AL2 External Digital Write

### Scenario

An external agent wants to create or modify a record in a third-party business system.

Example shape:

- actor: an enterprise support agent
- principal: a human account owner or an approved workflow
- target: a remote ticketing or refund API
- effect: external write with business impact

### Why this draft matters here

The relying party usually needs more than "this request has a valid token."
It needs to know:

- who the actor is
- on whose behalf it acts
- whether the runtime is fresh and genuine
- what task-scoped authority exists right now
- whether that authority has been revoked or attenuated
- what receipt should exist after execution

### Artifact chain

- `APC` identifies the actor and its controller context
- `ARP` proves the current runtime instance
- `AMP` narrows the action, resource, audience, and time window
- `ASN` can revoke or attenuate the request before execution
- `AER` records what the verifier allowed or observed

### What the verifier decides

The current repo models this as:

- `allow`
- `attenuate`
- `deny`

This is the narrowest practical wedge in the repo today.

## 2. MCP Tool Call With Delegated User Context

### Scenario

A coding agent or assistant invokes an MCP tool that reaches an enterprise system.

Example shape:

- actor: a coding agent running in an IDE or local assistant
- principal: a signed-in enterprise user
- target: an MCP server exposing a CRM, file system, or workflow action
- effect: a tool call that may read or write enterprise data

### Why this draft matters here

OAuth/OIDC delegated identity can answer part of the question:

- which user is represented
- whether the call is allowed on behalf of that user

But some deployments may still want portable artifacts for:

- actor identity distinct from user identity
- runtime proof for the executing agent instance
- mission-scoped constraints narrower than the general delegated session
- receipt and post-hoc accountability semantics

### Draft role

This draft does not replace MCP auth.
Instead, it can add a portable trust envelope around a tool call by carrying:

- actor and runtime context
- a narrower permit for the specific task
- machine-readable status and attenuation
- a receipt model after the tool interaction

See [delegated-identity-composition-example.md](delegated-identity-composition-example.md) for a non-normative coexistence example.

## 3. Agent-To-Agent Delegation

### Scenario

Agent A delegates a sub-task to Agent B.

Example shape:

- principal: a user or workflow behind the original task
- parent actor: a planner or coordinator agent
- child actor: a specialist agent
- target: another agent endpoint or service

### Why this draft matters here

Pure delegation messaging is not enough if the receiver must verify:

- whether the child actor is the expected actor
- whether redelegation depth is still valid
- whether the child runtime is bound to the expected proof
- whether the child permit is narrower than the parent scope
- whether the child action later yields a receipt chain

### Draft role

This draft can help by making the following explicit:

- controller / principal / actor / runtime separation
- parent-to-child narrowing of permit scope
- status-based attenuation or revocation during the chain
- receipt linkage across handoffs

### What this repo does today

The repo does not yet ship a full agent-to-agent reference flow.
But the current object model and verifier notes are already written to support this direction.

## What These Use Cases Have In Common

Across all three scenarios, this draft is trying to standardize the same narrow boundary:

- portable actor identity
- portable runtime proof
- task-scoped mission permit
- status and attenuation behavior
- receipts as first-class evidence

This draft is not trying to replace the surrounding execution surface, transport, or control plane.
