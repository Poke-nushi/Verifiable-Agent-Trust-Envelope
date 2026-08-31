# VATE JOSE Proof Profile Notes 2026-09

## Status

This note carries the production JOSE questions forward for the active
`2026-09` conformance artifact line. It is not a normative VATE profile.

The current v0.3 AL2 corpus performs dependency-free, byte-level checks over
detached JWS fixtures. Production signature verification remains outside the
current conformance claim. For the reviewable proof boundary, see
`vate-proof-profile-jose-jcs-v0.2.md`.

## v0.2 Decision Carried Forward

The v0.2 decision remains in force: keep detached proof fixtures in the public
corpus and add no new JOSE dependency to the reference runner. The active
artifact-line migration does not turn the fixture checker into a production
cryptographic verifier.

A future production profile may add a separately reviewed and pinned JOSE
implementation, or may accept implementation reports from verifiers that
already perform production signature validation.

## Standards Basis

- JSON Web Signature (JWS), RFC 7515
- JSON Web Token Best Current Practices, RFC 8725
- CFRG curves and EdDSA for JOSE, RFC 8037

## Required Production-Profile Decisions

A future production proof profile should define:

- compact and detached JWS handling
- protected-header requirements and media typing
- an explicit algorithm and key-type allowlist
- exact payload-byte and digest binding
- trust-anchor and key resolution
- critical-header rejection
- signature, replay, and validity-window checks
- canonical failure-reason mapping

It should not define identity discovery, credential issuance, or a global PKI.

## Fail-Closed Verification Boundary

A production verifier should reject a proof unless:

- the protected header includes the required `alg`, `kid`, and profile type
- `alg` is not `none` and is allowed by both the profile and matched trust
  anchor
- `kid` resolves to exactly one active trust anchor
- the trust anchor is valid and authorized for the evidence type
- the signature verifies over the exact signing input
- the verified payload bytes match the digest-bound artifact reference
- unsupported critical header parameters are rejected
- required audience, nonce, transaction, and validity bindings match

Detached payload verification must use the exact detached bytes. It must not
silently substitute a reserialized JSON object unless the profile explicitly
defines that canonicalization.

## Current Fixture Coverage

The active corpus checks:

- protected-header and detached-payload base64url encoding
- detached-payload SHA-256
- signing-input digest over the protected and payload segments
- `alg=none`, disallowed algorithm, algorithm-confusion, and unsupported
  `crit` rejection
- trust-bundle binding for issuer, key id, algorithm, and evidence type

These checks are intentionally byte-level and dependency-free. They do not
claim that a real ECDSA or EdDSA signature was verified.

## Failure Reason Mapping

Use existing reason codes where applicable:

- malformed JOSE or missing required header: `SCHEMA_INVALID`
- unsupported or disallowed algorithm: `ALG_NOT_ALLOWED`
- unknown or ambiguous key: `UNKNOWN_TRUST_ANCHOR` or `SCHEMA_INVALID`
- inactive trust anchor: the specific trust-anchor status reason
- invalid signature: `SIGNATURE_INVALID`
- verified-payload digest mismatch: `DIGEST_MISMATCH`

Denial receipts should include `FAIL_CLOSED` when proof failure prevents
execution.

## Deferred Decisions

DID resolution, certificate path building, revocation-service priority,
hardware key attestation, post-quantum migration, and library-specific APIs
remain outside the current fixture claim. These require a separate dependency
and security review before the public boundary changes.
