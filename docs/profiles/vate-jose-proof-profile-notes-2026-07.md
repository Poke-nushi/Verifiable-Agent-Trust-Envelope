# VATE JOSE Proof Profile Notes 2026-07

## Status

This note records production JOSE profile constraints that should be resolved before VATE claims production-grade proof verification.

It is not yet a normative VATE profile.
The current v0.2 AL2 conformance corpus includes dependency-free detached JWS fixture checks, but still treats cryptographic signature verification as a hook.

For the reviewable production proof boundary, see
`docs/profiles/vate-proof-profile-jose-jcs-v0.2.md`.

## v0.2 Decision

The v0.2 decision is to keep byte-level detached proof fixtures in the public
corpus and not add production JOSE signature verification to the conformance
claim.

No new JOSE dependency is added for v0.2. This keeps the repository
dependency-light while the exact production verification profile is still under
review.

Production signature verification remains outside the v0.2 fixture conformance
claim. A future production profile can add a pinned, maintained JOSE dependency
or accept implementation reports from verifiers that already perform production
signature validation.

## Standards Basis

These notes are aligned with:

- JSON Web Signature (JWS), RFC 7515: https://datatracker.ietf.org/doc/html/rfc7515
- JSON Web Token Best Current Practices, RFC 8725: https://datatracker.ietf.org/doc/html/rfc8725
- CFRG curves and EdDSA for JOSE, RFC 8037: https://www.rfc-editor.org/rfc/rfc8037

## Profile Boundary

A production VATE JOSE proof profile should define how to verify signed VATE evidence artifacts, not how to discover identity, issue credentials, or run a global PKI.

The profile should cover:

- compact JWS and detached JWS handling
- protected header requirements
- accepted algorithms and key types
- payload digest binding
- trust-bundle key resolution
- critical header rejection behavior
- replay and time-window interactions
- canonical failure reason mapping

The profile should not require A2A core changes or require one global issuer registry.

## Required Verification Behavior

A verifier should fail closed unless all of the following hold:

- the JWS uses a protected header
- `alg` is present and allowed by the matched trust anchor
- `alg` is not `none`
- `kid` is present and resolves to exactly one active trust anchor
- the trust anchor is valid at verification time
- the trust anchor is authorized for the evidence type
- the payload digest matches the digest-bound reference used by the admission flow
- the signature verifies over the exact signing input
- any unsupported `crit` header parameter causes rejection
- the verified payload profile matches the expected VATE artifact type

For detached payloads, the verifier should reconstruct the signing input from the protected header, the exact detached payload bytes, and the signature.
It should not verify a reserialized JSON object unless the profile explicitly names that canonicalization.

## Algorithm Policy

The profile should use an explicit allowlist.
For the current VATE fixtures, `ES256` remains the reference algorithm because the existing demos already use P-256 style keys.

Production profile candidates:

- `ES256` for broad JOSE library compatibility
- `EdDSA` with Ed25519 where the implementation environment supports RFC 8037 reliably

The profile should reject:

- `none`
- algorithms not listed by the matched trust anchor
- algorithm confusion between asymmetric and symmetric verification
- accepting a header-selected algorithm without checking local verifier policy

## Header Fields

The protected header should include:

- `alg`
- `kid`
- `typ` or an equivalent profile discriminator

The profile may later add:

- `crit` for VATE-specific protected extensions
- `cty` when nested or detached payload typing is needed
- `x5t#S256` or certificate-oriented fields if a future profile chooses certificate path validation

The verifier should ignore unprotected headers for trust decisions.

## Payload Binding

The signed payload should bind to the verifier decision basis.
For AL2 admission this means at minimum:

- VATE artifact type
- artifact version and profile id
- issuer or subject identifiers needed by local policy
- audience or verifier binding when applicable
- nonce or transaction id when replay protection is required
- issued-at and expiration window when applicable
- digest of any external request, permit, evidence, or policy snapshot referenced by the receipt

The conformance corpus currently checks digest-bound references at the artifact level.
A production JOSE profile should define the exact payload bytes that are signed and how those bytes are compared to digest references.

## Current Fixture Coverage

The v0.2 AL2 corpus now includes detached JWS fixture checks for:

- protected header canonical bytes and base64url encoding
- detached payload canonical bytes and base64url encoding
- detached payload SHA-256 digest
- signing input digest over `BASE64URL(protected) || "." || BASE64URL(payload)`
- `alg=none` rejection
- unsupported `crit` rejection
- trust-bundle binding for issuer, key id, algorithm, and evidence type

These checks are intentionally byte-level and dependency-free.
They do not claim that a real ECDSA or EdDSA signature was verified.

## Failure Reason Mapping

JOSE verification failures should map to existing canonical reason codes where possible:

- malformed JOSE or missing required header: `SCHEMA_INVALID`
- unsupported or disallowed algorithm: `ALG_NOT_ALLOWED`
- unknown or ambiguous `kid`: `UNKNOWN_TRUST_ANCHOR` or `SCHEMA_INVALID`
- inactive, expired, or not-yet-valid trust anchor: `TRUST_ANCHOR_REVOKED`, `TRUST_ANCHOR_EXPIRED`, or `TRUST_ANCHOR_NOT_YET_VALID`
- invalid signature: `SIGNATURE_INVALID`
- digest mismatch between verified payload and referenced artifact: `DIGEST_MISMATCH`
- unsupported critical header: `SCHEMA_INVALID`

Denial receipts should include `FAIL_CLOSED` when proof verification failure prevents execution.

## Deferred Decisions

These decisions should remain outside v0.2 fixture conformance:

- DID resolution rules
- certificate path building
- OCSP, CRL, or status-list priority
- hardware-backed key attestation
- post-quantum algorithm migration
- formal media types for every payload packaging
- library-specific API requirements

The next concrete step is to add a production-signature fixture after the repository accepts a maintained JOSE verification dependency or a separate implementation report from a verifier that already uses one.
