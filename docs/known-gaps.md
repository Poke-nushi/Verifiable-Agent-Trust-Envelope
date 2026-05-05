# Known Gaps

This repository is a discussion draft.
The goal of this note is to make the unresolved parts explicit rather than implied.

## Summary

The current repo is strongest on:

- object-model framing
- verifier ordering
- status and attenuation semantics
- a narrow AL2 verifier wedge

It is weaker on:

- packaging profile finalization
- multi-implementation interoperability
- stronger runtime attestation profiles
- higher-assurance operational guidance
- v0.2 profile interop across A2A, MCP, and HTTP bindings

## Current Gaps

### 1. Final Packaging Profile Is Not Fixed

The repo currently uses decoded JSON payloads plus compact JWS demo packaging.

What is still open:

- VC-native packaging profiles
- final JOSE profile choices
- selective-disclosure presentation approach

### 2. Pairwise Presentation Guidance Is Still Early

The draft prefers pairwise presentation where practical, but it does not yet freeze:

- subject alias derivation rules
- verifier-specific presentation packaging
- privacy-preserving status lookup patterns

### 3. Runtime Assurance Strength Varies Too Much

`ARP` is conceptually important, but the repo does not yet define strong interoperable profiles across:

- local desktop agents
- cloud-hosted agents
- hardware-backed attested runtimes
- browser or mixed execution environments

### 4. Receipt Semantics Need More Precision

The draft now distinguishes admission receipts from post-execution receipts, but more work is still needed on:

- verifier-signed versus runtime-signed receipt semantics
- evidence attachment models
- dispute and audit expectations
- chain linkage across delegated execution
- canonical correlation rules for `admission_receipt_ref`, `attestation_id`, and profile-specific correlation objects
- when an admission receipt should be inline, dereferenceable, or both

The v0.2 AL2 verifier admission profile adds separate admission and post-execution receipt schemas.
Remaining work is to validate those shapes across independent implementations and decide which proof packaging profiles are mandatory for each assurance level.

### 5. Status Policy Is Still Profile-Dependent

The repo models revocation, suspension, quarantine, and attenuation, but still needs sharper guidance for:

- freshness windows by assurance level
- fail-open versus fail-closed rules
- push versus pull versus stapled policy behavior

### 6. Capability Registry Is Unresolved

The draft intentionally avoids freezing a universal capability vocabulary.
That keeps the core small, but it leaves open:

- how skills and capabilities should be described consistently
- what should be profile-specific versus global
- how verifiers should interpret domain-specific actions

### 7. AL3 And AL4 Are Not Yet Concrete Enough

The repo names higher assurance levels, but the concrete profiles are still missing for:

- regulated digital action
- sensitive data domains
- physical or safety-critical actuation

### 8. Physical AI Remains Future Work

The future `ABS` direction exists, but the repo does not yet define:

- body identity packaging
- inspection and maintenance semantics
- operator linkage
- physical safety policy integration

### 9. Shared Conformance Across Implementations Is Not Ready

The repo now includes two small machine-readable corpora:

- an `AL2` HTTP corpus for the reference verifier demo
- a `v0.2` mini corpus for admission decisions, attenuation, A2A metadata references, and post-execution linkage

Those corpora make the draft easier to inspect, but they are not yet a cross-language, multi-implementation conformance suite.

Remaining work includes:

- runnable verifier fixtures for the `v0.2` mini corpus
- revoked status denial
- digest mismatch denial
- replayed admission receipt denial
- post-execution receipt linkage mismatch
- cross-implementation report format and certification language

### 10. Persistent Namespace Is Not Yet Chosen

The v0.2 examples use repository-hosted draft URIs.
A future draft may move schema and extension identifiers to a persistent namespace such as `w3id.org`, but only after the namespace is controlled and documented.

## Practical Reading Of These Gaps

These gaps do **not** mean the current repo is empty.
They mean the repo should be read as:

- a serious problem framing
- a concrete object-model proposal
- a verifier-oriented AL2 draft wedge
- an invitation for sharper profile and interoperability work
