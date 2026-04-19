# Delegated Identity Composition Example

This note is a non-normative coexistence example.

Its purpose is to show how this draft can sit alongside gateway- and OAuth/OIDC-based delegated identity propagation rather than replacing it.

The scenario is intentionally shaped like recent enterprise product patterns, including:

- API / MCP / CLI exposure of enterprise capabilities
- multi-vendor governance or control-plane behavior
- on-behalf-of delegated identity propagation

This note does **not** standardize vendor behavior.

## Scenario

A coding agent helps an authenticated employee update a customer record through an enterprise MCP tool.

Illustrative surrounding stack:

- an enterprise surface exposes business actions through APIs or MCP tools
- a gateway propagates delegated user identity using OAuth/OIDC on-behalf-of patterns
- governance systems apply local policy, routing, and audit controls

This draft adds a portable trust envelope for:

- the acting agent
- the current runtime
- the mission-scoped permit
- status and attenuation
- the resulting receipt

## Division Of Labor

### The delegated identity system answers

- which user is represented
- whether on-behalf-of delegation is valid
- whether step-up authentication is required
- which downstream audience should receive the delegated token

### This draft answers

- which actor is acting in addition to the represented user
- which runtime is presenting the request now
- what narrower task-scoped permit exists for this action
- whether status has attenuated or revoked that permit
- what receipt should exist after execution

## Request Flow

1. A user authenticates to an enterprise surface.
2. A delegated identity system issues or exchanges an OAuth/OIDC token for the downstream audience.
3. The coding agent prepares a trust envelope context containing `APC`, `ARP`, and `AMP`.
4. The request reaches an MCP server or API through normal enterprise controls.
5. The relying party evaluates both:
   - delegated identity validity
   - trust envelope artifact validity and local verifier policy
6. The relying party allows, attenuates, or denies the action.
7. If execution proceeds, a receipt is emitted or required.

## Simplified Envelope

This is illustrative only:

```json
{
  "authorization": {
    "scheme": "Bearer or PoP-bound delegated token",
    "purpose": "OAuth/OIDC on-behalf-of user context"
  },
  "app_context": {
    "passport": "compact-or-by-reference APC",
    "runtime_proof": "compact-or-by-reference ARP",
    "mission_permit": "compact-or-by-reference AMP"
  },
  "request": {
    "tool": "update_customer_record",
    "resource": "crm/customer/12345",
    "action": "write"
  }
}
```

## Why Both Layers Can Coexist

Because they solve different problems.

- delegated identity propagation is primarily about preserving authenticated user authority across hops
- this draft is primarily about portable trust artifacts for actor, runtime, permit, status, and receipt

A deployment may use:

- only delegated identity
- only the artifacts from this draft in a private system
- or both together

The strongest enterprise pattern may often be "both together" for higher-risk external write actions.

## Practical Benefit

This combined model lets a verifier reason about:

- the represented human or workflow authority
- the specific agent actor that is actually performing the task
- the runtime freshness of that actor
- narrower mission constraints than the broad delegated session
- post-execution evidence

That is the core coexistence story.
