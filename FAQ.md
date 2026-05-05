# Verifiable Agent Trust Envelope FAQ

## What Is This Draft In One Sentence?

Verifiable Agent Trust Envelope is an early discussion draft for the verifier-side trust / permit / receipt boundary that appears when an external agent wants to perform a risky write against a remote system.

## What Exact Moment Is This Repo About?

The focal moment is narrow:

- an external agent is asking a remote relying party to allow a risky action
- the relying party needs to decide `allow / attenuate / deny`
- the decision should be based on portable artifacts, not only on vendor-local context

The preserved `v0.1` core makes that concrete through a verifier-centered `AL2` HTTP wedge that evaluates:

`status -> identity -> runtime -> permit -> policy`

and then emits a machine-readable receipt.

The `v0.2` profile keeps that boundary, but makes the admission moment more explicit by separating admission requests, admission receipts, A2A metadata references, attenuation records, and post-execution receipts.

## Why Isn't A Valid Token Enough?

Because a valid token does not necessarily answer all of the questions that matter for a higher-risk external action.

The relying party may still need to know:

- which actor is acting
- on whose behalf it acts
- whether the current runtime is fresh and genuine
- whether authority is task-scoped for this exact action
- whether current status has narrowed or revoked that authority
- what receipt should exist after execution

For many low-risk interactions, a token may be enough.
This draft is about the narrower cases where it is not.

## Is This Draft Trying To Replace A2A, MCP, OAuth, Or Verifiable Credentials?

No.

- `A2A` handles discovery, messaging, and delegation flow between agents.
- `MCP` handles tool and server interaction, plus adjacent authorization work.
- `OAuth / OpenID` handle delegated authorization, federation, and event signaling.
- `VC / workload identity` handle portable credentials and runtime trust anchors.
- `This draft` focuses on the combined trust envelope across actor, principal, runtime, permit, receipt, and status.

## Why Not Just Use MCP Plus OAuth Or OpenID?

Because those layers solve adjacent pieces of the problem, not the full verifier-side admission boundary by themselves.

- `MCP` gives a tool and resource interaction surface
- `OAuth / OpenID` give delegated authorization, federation, and event signaling
- `This draft` adds a portable artifact model across identity, runtime proof, task-scoped permit, status, attenuation, and receipt

The intended composition is:

- existing layers handle transport, auth, and federation
- this draft defines what a verifier should evaluate when a risky external action is about to happen

## Isn't This Just Another Passport Protocol?

Close adjacent work already exists, and reviewers should treat that overlap seriously.

The important claim here is narrower:

- this repo is not claiming to be the first work on agent identity or agent authorization
- it is proposing a reviewable verifier-side boundary
- its center of gravity is the combined artifact model across identity, runtime proof, permit, status, and receipt

If someone thinks this already exists elsewhere, the right next step is to compare boundaries directly.
That is why this repo includes [docs/close-adjacent-work-2026-04.md](docs/close-adjacent-work-2026-04.md).

## Why This Draft If Salesforce Already Has Headless 360, Agent Fabric, Or Trusted Agent Identity?

Because those product layers solve adjacent problems, not the same protocol boundary.

- `Salesforce Headless 360` is about making Salesforce capabilities callable through APIs, MCP tools, and CLI commands, plus rendering experiences across surfaces.
- `Agent Fabric` is about governed discovery, orchestration, and multi-vendor control-plane behavior.
- `Trusted Agent Identity` is about propagating authenticated user context with on-behalf-of delegation and gateway enforcement.
- `This draft` is about portable artifacts for identity, runtime proof, mission permit, execution receipt, and status that can travel across vendors and surfaces.

In practice, this draft should compose with those systems rather than compete with them.
This repository is **not** trying to become:

- an agent platform
- a control plane
- an MCP / A2A connector suite
- a gateway product

The intended fit is narrower: this draft provides the portable trust envelope that those systems can carry, verify, or emit.

## Is This Draft Still Too Broad?

That is a fair concern, and the current answer should be:

- the core claim is narrow
- the durable battlefield is still `AL2` external digital write
- `v0.2` moves the most concrete new work into an AL2 verifier admission profile
- broader deployment shapes should move into profiles, extensions, or later drafts where possible

If reviewers think a concept does not help that verifier-side boundary, it is a good candidate to remove from the core.

## What Is In The Core Today?

The preserved v0.1 core discussion draft centers on:

- `APC` - passport credential
- `ARP` - runtime proof
- `AMP` - mission permit
- `AER` - execution receipt
- `ASN` - status, revocation, and attenuation signaling

The repository also includes payload schemas, examples, verifier guidance, negative tests, and educational reference demos.
The current v0.2 additions provide a concrete AL2 verifier admission profile, reference-only A2A metadata binding, separate admission and post-execution receipt schemas, and a small machine-readable conformance corpus.

## What Is Still Future Work?

The current repo does not yet freeze:

- selective-disclosure or VC-native packaging profiles
- richer capability claim registries
- formal `AID` identifier abstraction
- physical `ABS` profiles
- full runnable conformance corpora across multiple implementations

## What Does `attenuated` Mean?

`attenuated` means an artifact is not fully revoked, but it is no longer usable under the original scope.

Typical effects include:

- lower transaction limits
- narrower tool allowlists
- reduced redelegation depth
- stronger approval requirements

In this draft, attenuation should be machine-readable. The status payload should carry an `effect` object so a verifier can decide whether it can safely narrow execution or must require a new permit.

## How Should Pairwise Identifiers Work?

This draft prefers pairwise presentation where practical.

The core payload schemas in this repo currently model decoded artifacts, not a final selective-disclosure presentation format.
An informative pairwise presentation could look like this:

```json
{
  "presentation": {
    "subject_alias": "agent:pairwise:verifier-x:4f9c",
    "principal_alias": "user:pairwise:verifier-x:ab12",
    "aud": "https://verifier.example/mcp",
    "derived_from_passport": "appc:8f85b2e6-cc6f-4b18-a90a-fb7b80f0842c"
  }
}
```

The point is to avoid reusing one globally stable alias across every relying party unless the use case requires it.

## Are Receipts Always Signed By The Runtime?

No.

This draft currently models receipt semantics with `issuer_role`.
Examples include:

- `runtime` - the actor runtime signs what it claims it executed
- `verifier` - the relying party signs what it accepted or observed
- `broker` - an intermediary signs a policy or settlement-side record

The educational demo currently uses `issuer_role: runtime`.

## Is The Reference Demo Production Ready?

No.

The `reference/minimal-al2-demo` directory is intentionally educational.
It demonstrates artifact relationships, compact JWS packaging, and status delivery modes.
It does not claim production-grade JOSE interoperability, hardened key management, or federation-ready trust discovery.
