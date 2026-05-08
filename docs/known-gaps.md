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
- richer reason-code ordering beyond the current exact-order and terminal-marker
  checks
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
- adding more transport-bound fixtures that prove VATE never widens MCP/OAuth
  authority beyond the intersection of upstream authorization and local verifier
  policy; the initial MCP/OAuth denial fixtures are
  `deny-mcp-oauth-overscope` and `deny-mcp-oauth-upstream-denied`

### 13. Post-Execution Linkage Needs Independent Implementation Evidence

The runner now checks admission receipt id, admission digest, transaction id,
runtime, decision, expiry, admitted effective request hash, and basic
attenuated amount boundaries. That is enough for the v0.2 corpus, but not yet
enough to claim multi-implementation readiness.

Remaining work includes:

- policy snapshot digest mismatch after an otherwise matching effective request
- side-effect checks beyond simple amount limits
- independent implementation reports that exercise the linkage checks

### 14. Status, Replay, And Runtime Binding Need Broader Context Coverage

The corpus now includes minimum AL2 context checks for representative status
freshness, runtime proof freshness, runtime binding, and replay state cases.
Broader coverage is still needed before treating those checks as a complete
profile.

Remaining work includes:

- additional boundary fixtures for status freshness and replay behavior; the
  exact status freshness max-age boundary is covered by
  `allow-status-fresh-at-boundary`, and the unused replay-key boundary is
  covered by `allow-replay-state-unused`
- more explicit evaluation-order fixtures showing that malformed proof, replay,
  and digest mismatch fail closed before policy or attenuation can allow
  execution; the first stale runtime proof fixture is
  `deny-runtime-proof-stale`
- more algorithm-confusion fixtures beyond `alg=none`; the first
  symmetric/asymmetric downgrade fixture is `deny-jose-hs256-downgrade`
- more attenuation boundary fixtures beyond the initial unsafe-path and
  max-amount type-edge cases

### 15. Evidence Type Vocabulary Needs Wider Implementation Coverage

The repo now has a machine-readable evidence type and protocol hint registry
for AL2 admission fixtures. The conformance runner checks admission request
references and admission receipt evidence against that vocabulary, including
allowed evidence type / protocol hint combinations.

Remaining work includes:

- carrying the same vocabulary into independent verifier implementations
- deciding how extension evidence types are registered after v0.2
- ensuring trust bundles and policy snapshots refer to the same vocabulary
- adding more negative fixtures for unknown, malformed, or unregistered
  type/hint combinations

### 16. Report Integrity Needs External Proof Implementation

The SUT result and implementation report schemas now define publication
metadata and optional external proof references. The runner can write an
implementation report for both reference runs and external SUT comparisons.

Remaining work includes:

- implementing real proof verification for detached JWS, signed git tags, or
  Sigstore bundles
- publishing real implementation reports under implementer-controlled origins
- deciding whether future profiles require a specific proof format

## Practical Reading Of These Gaps

These gaps do **not** mean the current repo is empty.
They mean the repo should be read as:

- a serious problem framing
- a concrete object-model proposal
- a verifier-oriented AL2 draft wedge
- an invitation for sharper profile and interoperability work
