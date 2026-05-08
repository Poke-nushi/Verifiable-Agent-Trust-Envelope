# Roadmap

## Current Milestone

### `v0.2-al2-verifier-admission-profile`

Focus:

- preserve the `v0.1` discussion draft as the core framing
- narrow the next profile to `AL2` verifier-side admission for external digital actions
- define reference-only A2A metadata binding for admission and receipt artifacts
- split admission receipts from post-execution receipts in profile-specific schemas
- make `allow / attenuate / deny` decisions and machine-readable attenuation explicit
- treat A2A, MCP, OAuth, VC, DID, OID4VP, Web Bot Auth, AP2, x402, ACP, and payment tokens as adjacent evidence or transport layers
- add examples and schema validation for v0.2 admission requests, A2A references, and receipts
- add a maintainer brief and mini conformance corpus for early A2A-adjacent review
- keep the May 2026 ecosystem boundary explicit: VATE consumes MCP/OAuth, A2A, AP2, ACP/UCP, and x402 artifacts as adjacent evidence rather than replacing them
- publish `v0.2.0` as a discussion-draft pre-release

## May 2026 Review Hardening

External review of commit `80b66fe` found that the boundary is coherent enough
for narrow review, but not yet strong enough to call the AL2 package
conformance-ready. The next work should harden the security basis before adding
new adjacent profiles.

### P0 Before The Next External Review Round

- [x] align A2A signed Agent Card evidence with A2A v1.0 JWS header expectations,
  including the `typ` protected header
- [x] resolve `require_new_permit` execution semantics so fixtures and docs agree
  on whether execution may proceed
- [x] document the v0.2 fixture canonicalization limits and the intended production
  canonicalization migration path
- [x] split the conformance language so `run` is clearly a reference artifact /
  fixture integrity check and `compare` is the external SUT comparison path

### P1 Before Adjacent Maintainer Outreach

- define reason-code ordering or compare reason-code sets with a primary reason
  code; terminal marker ordering is now documented and enforced in `run` and
  `compare`
- strengthen post-execution linkage checks beyond presence checks, including
  receipt id, receipt digest, transaction, runtime, admitted effective request
  hash, decision, and expiry semantics
- add minimum AL2 verification context for status freshness, replay protection,
  and runtime binding
- add transport-bound fixtures proving VATE only narrows MCP/OAuth authority and
  never unions with upstream authorization; first fixture added:
  `deny-mcp-oauth-overscope`
- add evaluation-order and algorithm-confusion fixtures before presenting the
  corpus as broad security conformance; first stale runtime proof fixture added:
  `deny-runtime-proof-stale`; first HS256 downgrade fixture added:
  `deny-jose-hs256-downgrade`
- add attenuation boundary fixtures for malicious paths and schema type edges;
  first unsafe-path and max-amount type-edge fixtures added
- strengthen post-execution linkage checks beyond presence checks; digest,
  transaction, runtime, denial, expiry, and effective-constraint fixtures added
- add minimum AL2 verification context for status freshness, replay protection,
  and runtime binding; first `al2_context_checks` fixtures added
- add an evidence type vocabulary for generic evidence types and
  protocol-specific hints; initial registry and runner checks added
- keep the language-neutral conformance corpus index current as cases change

### P2 Before Independent Implementation Collection

- add report integrity guidance for SUT result and implementation report
  publication
- decide whether to add a pinned dependency for production-grade JOSE signature
  fixtures, or keep v0.2 as byte-level detached proof fixtures only
- add a byte-level A2A signed Agent Card fixture only after the digest target
  and validation responsibility are fixed
- define a persistent namespace migration plan for schema and extension URIs
- document extension-field handling before tightening `additionalProperties`

## Next

- execute the May 2026 review hardening items in P1/P2 order
- prepare A2A-adjacent review updates from `docs/a2a-issue-update-2026-05.md`
  after P0 is complete
- collect independent implementation reports using
  `schemas/implementation-report.schema.json` after the SUT comparison contract
  and report integrity guidance are clear
- add additional transport-bound fixtures beyond the initial MCP/OAuth,
  AP2/UCP, and AP2 Human Not Present examples after the AL2 security basis is
  stable
- expand policy snapshot digest fixtures beyond the initial positive and
  mismatch cases
- refine pairwise presentation guidance
- add clearer MCP / OAuth / OpenID binding notes and transport-bound examples
- improve comparison material around close adjacent work where interoperability
  questions remain
- add production-signature fixtures after the detached JWS byte-level basis and
  dependency policy are fixed

## June 2026 Target

The June target is to complete the `v0.2` AL2 review package, not to broaden the protocol.
Items should land only when they preserve the verifier boundary and pass the runnable checks.

Completion means:

- reproducible implementation reports with corpus manifests
- transport-bound fixtures for the most important adjacent paths
- policy snapshot digest checks across receipts, metadata references, and fixtures
- trust-bundle hardening checks for issuer, key id, algorithm, evidence type, status, and validity windows
- detached JOSE fixture checks that separate byte-level proof binding from production signature verification
- language-neutral corpus guidance and a committed corpus index for non-reference implementations
- SUT result comparison contract for non-reference implementation reports
- AP2 Human Not Present evidence cases for pre-authorization, stale authority, amount overrun, replay, and post-execution linkage
- an A2A-adjacent review package that does not require A2A core changes, including an A2A v1.0-shaped extension sketch
- review-derived hardening for digest basis, execution semantics, reason codes,
  post-execution linkage, status freshness, replay, runtime binding, evidence
  vocabulary, and report integrity

## Later

- selective-disclosure or VC-oriented packaging profile
- richer capability claim registry and extension points
- formal `AID` abstraction guidance
- review whether internal mnemonic aliases should gain clearer public-facing alternatives after external feedback
- AL3 and AL4 profiles
- physical AI / `ABS` extensions
- stronger status discovery and federation guidance
