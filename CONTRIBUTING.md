# Contributing to Verifiable Agent Trust Envelope

Verifiable Agent Trust Envelope is an open discussion draft about trust, permission, and accountability for AI agent systems.
This repository is intended to evolve into a clearer protocol discussion space for specifications, profiles, schemas, and conformance-oriented artifacts.

## Contributions That Help Most

- tightening interoperability with existing standards
- reducing ambiguity in the object model or threat model
- improving example artifacts and JSON Schemas
- clarifying assurance levels and profile boundaries
- mapping this draft more precisely onto A2A, MCP, OAuth, VC, and workload identity systems
- proposing well-scoped extensions for P2P, external exchange, or physical AI
- contributing attack scenarios, failure modes, or operational counterexamples

## Ground Rules

- this draft is **not** a replacement for A2A or MCP
- this draft is **not** a rejection of OAuth, OpenID, or VC
- the core should stay small
- domain-specific concerns should move into profiles or extensions
- this draft should not assume a single global registry or a single issuer
- privacy-preserving and pairwise presentation should be preferred where appropriate
- capability and authority must remain separate concepts
- runtime proof and stable identity must not be conflated

## How to Frame an Issue or PR

Please include the following when possible.

### 1. Problem

- What is unclear?
- What is risky?
- What conflicts with an existing standard or deployment reality?

### 2. Change Type

Use one or more of:

- `core`
- `profile`
- `extension`
- `editorial`
- `schema`
- `reference`

### 3. Source Quality

Indicate the strength of the source you are relying on:

- `final standard`
- `RFC / Recommendation`
- `working draft`
- `official product doc`
- `OSS implementation`
- `ecosystem signal`

### 4. Compatibility Impact

- relationship to A2A
- relationship to MCP
- relationship to OAuth / OpenID
- relationship to VC / DID
- privacy or deployability impact

## Evaluation Priorities

Changes are evaluated in roughly this order:

1. correctness
2. security
3. interoperability
4. deployability
5. privacy
6. clarity

## Changes That Should Be Avoided

- embedding a universal reputation score into the core
- assuming vendor-specific or chain-specific lock-in
- making legal identity or KYC mandatory for all use cases
- mixing settlement logic into the core protocol
- weakening receipts or status handling for high-risk use cases

## What Good PRs Usually Look Like

- spec, examples, and schemas stay consistent
- date-sensitive references include dates
- official sources are preferred when available
- normative proposals are clearly separated from informative discussion
- new concepts are introduced only when existing concepts cannot absorb the problem cleanly

## Near-Term Priorities

1. stabilize the data model
2. clarify verification flows
3. separate profiles more cleanly
4. refine status and attenuation semantics
5. establish the foundation for conformance tests

## Related Documents

- `README.md`
- `docs/verifiable-agent-trust-envelope-spec-v0.1.md`
- `docs/standards-and-ecosystem-landscape-2026-04.md`
- `schemas/*.schema.json`
