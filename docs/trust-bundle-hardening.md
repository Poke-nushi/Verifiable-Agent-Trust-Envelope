# Trust Bundle Hardening

## Status

This note describes the minimal trust-bundle checks used by the `VATE AL2 Admission Interop Profile 2026-07` conformance corpus.

It does not define production JOSE, PKI, DID resolution, certificate path building, or key rotation protocols.
Those remain deployment choices.

For the future JOSE/JCS production proof verification boundary, see
`docs/profiles/vate-proof-profile-jose-jcs-v0.2.md`. The current corpus keeps
trust-bundle and proof checks dependency-free.

## Conformance Boundary

The dependency-free runner verifies local trust-bundle semantics that are useful before adding full production proof verification:

- issuer id match
- key id match
- exactly one matching trust anchor
- accepted proof algorithm
- accepted evidence type
- trust anchor status
- trust anchor validity window
- fail-closed behavior for mismatches

The runner intentionally treats proof verification as a hook.
It checks whether the trust bundle would allow the presented proof and evidence type.
It does not validate a real detached JWS signature.

## Trust Anchor Fields

The test trust bundle schema supports:

- `issuer_id`
- `kid`
- `alg`
- optional `allowed_algs`
- `public_key_ref`
- `allowed_evidence_types`
- optional `status`
- optional `not_before`
- optional `not_after`
- optional `usages`
- optional `constraints`

If `allowed_algs` is absent, `alg` is treated as the only accepted algorithm for the trust anchor.
If `status` is absent, the anchor is treated as `active`.

## Failure Reasons

The conformance runner maps trust-bundle failures to canonical reason codes:

- unknown issuer or key: `UNKNOWN_TRUST_ANCHOR`
- duplicate issuer and key match: `SCHEMA_INVALID`
- disallowed evidence type: `ISSUER_NOT_AUTHORIZED`
- disallowed algorithm: `ALG_NOT_ALLOWED`
- expired anchor: `TRUST_ANCHOR_EXPIRED`
- not-yet-valid anchor: `TRUST_ANCHOR_NOT_YET_VALID`
- revoked, disabled, or suspended anchor: `TRUST_ANCHOR_REVOKED`
- malformed bundle shape, status, time, or allowlist fields: `SCHEMA_INVALID`

Admission receipts should still include `FAIL_CLOSED` when trust-bundle failures deny execution.

## Current Negative Cases

- `conformance/al2-vate-v0.3/cases/deny-unknown-trust-anchor.json`
- `conformance/al2-vate-v0.3/cases/deny-ambiguous-trust-anchor.json`
- `conformance/al2-vate-v0.3/cases/deny-kid-mismatch.json`
- `conformance/al2-vate-v0.3/cases/deny-alg-not-allowed.json`
- `conformance/al2-vate-v0.3/cases/deny-evidence-type-not-allowed.json`
- `conformance/al2-vate-v0.3/cases/deny-trust-anchor-expired.json`
- `conformance/al2-vate-v0.3/cases/deny-trust-anchor-not-yet-valid.json`
- `conformance/al2-vate-v0.3/cases/deny-trust-anchor-revoked.json`

## Production Notes

A production profile should define:

- accepted JOSE algorithms and key types
- signature verification and detached payload canonicalization
- issuer metadata discovery
- status and revocation source priority
- key rollover and expiry behavior
- audit logging requirements for failed trust decisions

The current corpus fixes the verifier decision semantics before choosing a production JOSE stack.
