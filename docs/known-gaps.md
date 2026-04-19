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

The draft already models `issuer_role`, but more work is still needed on:

- verifier-signed versus runtime-signed receipt semantics
- evidence attachment models
- dispute and audit expectations
- chain linkage across delegated execution

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

The current corpus is useful, but still narrow.
It is not yet a cross-language, multi-implementation conformance suite.

## Practical Reading Of These Gaps

These gaps do **not** mean the current repo is empty.
They mean the repo should be read as:

- a serious problem framing
- a concrete object-model proposal
- a verifier-oriented AL2 draft wedge
- an invitation for sharper profile and interoperability work
