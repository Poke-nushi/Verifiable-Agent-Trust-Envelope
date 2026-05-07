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
- independent implementation evidence across A2A, MCP, and HTTP bindings

## Current Gaps

### 1. Final Packaging Profile Is Not Fixed

The repo currently uses decoded JSON payloads plus compact JWS demo packaging.

What is still open:

- VC-native packaging profiles
- production JOSE signature verification profile choices
- selective-disclosure presentation approach

The v0.2 AL2 corpus now includes detached JWS byte-level fixtures, but those fixtures do not perform production cryptographic signature verification.

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

The repo now includes two machine-readable conformance corpora:

- an `AL2` HTTP corpus for the reference verifier demo
- a runnable `v0.2` AL2 corpus for admission decisions, attenuation, A2A metadata references, negative cases, adjacent evidence, and post-execution linkage
- a language-neutral `corpus.json` index for the `v0.2` AL2 corpus

Those corpora make the draft easier to inspect and replay, but they are not yet a multi-implementation conformance suite.

Remaining work includes:

- independent implementation reports
- transport-bound SUT adapters beyond the generic result comparison contract
- production signature verification fixtures
- cross-implementation report comparison
- formal conformance claim wording, if a future governance path justifies it

### 10. Persistent Namespace Is Not Yet Chosen

The v0.2 examples use repository-hosted draft URIs.
A future draft may move schema and extension identifiers to a persistent namespace such as `w3id.org`, but only after the namespace is controlled and documented.

### 11. Digest And Canonicalization Need A Stable Profile

The v0.2 runner uses dependency-free JSON canonical bytes produced by sorting
object keys and removing insignificant whitespace before SHA-256 hashing.
That is sufficient for current fixtures, but it is not a full production
canonicalization profile.

Remaining work includes:

- deciding whether production profiles use RFC 8785 / JCS or a different named
  byte basis
- avoiding floats, duplicate object keys, and ambiguous Unicode normalization
  until the byte basis is fixed
- aligning digest descriptor shape and encoding across artifact references,
  request hashes, attenuation hashes, receipts, policy snapshots, and A2A
  metadata references

### 12. Execution Semantics Need Sharper Production Semantics

The conformance runner now treats `should_execute` as a first-class comparison
field, and `require_new_permit` fixtures use `should_execute: false`. Production
profiles still need a sharper execution gate model so "admitted with
attenuation" is never misread as unconditional execution approval.

Remaining work includes:

- deciding whether future profiles keep `require_new_permit` as an `attenuate`
  outcome with `should_execute: false`, or introduce a deny/defer-style outcome
- extending execution-gate checks beyond fixture-level admission receipts into
  adapter behavior and post-execution receipt validation
- adding more fixtures where an admission decision exists but execution must not
  proceed
- adding transport-bound fixtures that prove VATE never widens MCP/OAuth
  authority beyond the intersection of upstream authorization and local verifier
  policy

### 13. Post-Execution Linkage Is Still Too Narrow

The runner checks the admission receipt id and admitted effective request hash,
but stronger linkage is needed before claiming broad conformance readiness.

Remaining work includes negative fixtures and checks for:

- admission receipt digest mismatch
- transaction id mismatch
- runtime mismatch
- post-execution receipt after deny
- post-execution receipt after admission expiry
- side effects that exceed attenuated effective constraints
- policy snapshot digest mismatch after an otherwise matching effective request

### 14. Status, Replay, And Runtime Binding Need Minimum AL2 Context

The draft already names stale status, revoked status, replay, and runtime
mismatch as fail-closed cases, but the minimum AL2 verification context is not
yet explicit enough.

Remaining work includes:

- status source, checked time, freshness window, result, and fail behavior
- replay key, nonce or equivalent uniqueness input, window, and idempotent retry
  behavior
- runtime proof freshness, audience, subject, and bound request hash
- boundary fixtures for status freshness and replay behavior
- explicit evaluation-order fixtures showing that malformed proof, stale proof,
  replay, and digest mismatch fail closed before policy or attenuation can allow
  execution
- algorithm-confusion fixtures beyond `alg=none`, such as symmetric/asymmetric
  downgrade attempts
- attenuation boundary fixtures for malicious paths and schema type edges

### 15. Evidence Type Vocabulary Is Still Informal

The repo has canonical reason codes, but evidence type strings are currently
spread across schemas, fixtures, and interop notes.

Remaining work includes:

- creating a small evidence type registry
- separating generic evidence types from protocol-specific hints
- defining naming and extension rules for adjacent protocols
- ensuring trust bundles and policy snapshots refer to the same vocabulary

### 16. Report Integrity Is Not Yet Defined

The SUT result and implementation report schemas carry corpus digests, but they
do not yet define how a third-party report is authenticated or published.

Remaining work includes:

- documenting how implementation reports should be hosted under an implementer
  controlled origin
- deciding whether report proofs should use detached JWS references
- clarifying what can and cannot be inferred from a passing report

## Practical Reading Of These Gaps

These gaps do **not** mean the current repo is empty.
They mean the repo should be read as:

- a serious problem framing
- a concrete object-model proposal
- a verifier-oriented AL2 draft wedge
- an invitation for sharper profile and interoperability work
