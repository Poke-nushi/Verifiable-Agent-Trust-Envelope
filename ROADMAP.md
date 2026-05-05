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

- broaden the v0.2 mini conformance corpus into runnable verifier fixtures
- add negative cases for expired permits, audience mismatches, revoked status, digest mismatches, replayed admission receipts, and post-execution linkage mismatches
- refine pairwise presentation guidance
- add clearer MCP / OAuth / OpenID binding notes and transport-bound examples
- improve comparison material around close adjacent work where interoperability questions remain
- publish a language-neutral conformance corpus shape
- improve JOSE hardening and profile notes

## Later

- selective-disclosure or VC-oriented packaging profile
- richer capability claim registry and extension points
- formal `AID` abstraction guidance
- review whether internal mnemonic aliases should gain clearer public-facing alternatives after external feedback
- AL3 and AL4 profiles
- physical AI / `ABS` extensions
- stronger status discovery and federation guidance
