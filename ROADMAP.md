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
- publish `v0.2.0` as a discussion-draft pre-release

## Next

- collect independent implementation reports using `schemas/implementation-report.schema.json`
- prepare A2A-adjacent review updates from `docs/a2a-issue-update-2026-05.md`
- add additional transport-bound fixtures beyond the initial MCP/OAuth and AP2/UCP examples
- expand policy snapshot digest fixtures beyond the initial positive and mismatch cases
- refine pairwise presentation guidance
- add clearer MCP / OAuth / OpenID binding notes and transport-bound examples
- improve comparison material around close adjacent work where interoperability questions remain
- keep the language-neutral conformance corpus index current as cases change
- turn production JOSE profile notes into byte-level detached JWS fixtures after the signing basis is fixed

## June 2026 Target

The June target is to complete the `v0.2` AL2 review package, not to broaden the protocol.
Items should land only when they preserve the verifier boundary and pass the runnable checks.

Completion means:

- reproducible implementation reports with corpus manifests
- transport-bound fixtures for the most important adjacent paths
- policy snapshot digest checks across receipts, metadata references, and fixtures
- trust-bundle hardening checks for issuer, key id, algorithm, evidence type, status, and validity windows
- production JOSE profile notes that separate fixture semantics from proof verification
- language-neutral corpus guidance and a committed corpus index for non-reference implementations
- an A2A-adjacent review package that does not require A2A core changes

## Later

- selective-disclosure or VC-oriented packaging profile
- richer capability claim registry and extension points
- formal `AID` abstraction guidance
- review whether internal mnemonic aliases should gain clearer public-facing alternatives after external feedback
- AL3 and AL4 profiles
- physical AI / `ABS` extensions
- stronger status discovery and federation guidance
