# VATE Reason Codes

## Status

This registry is the canonical reason-code vocabulary for the `VATE AL2 Admission Interop Profile 2026-07`.

Reason codes are stable machine-readable tokens.
Human-readable explanations belong in receipts, reports, or logs, not in the code value.

## Naming

Reason codes use `SCREAMING_SNAKE_CASE`.

Implementations MUST preserve exact spelling in conformance reports.
Implementations MAY include additional profile-specific reason codes, but the canonical codes below should be preferred when they fit.

## Canonical Codes

### Success And Policy Match

- `EVIDENCE_VERIFIED` - required evidence was resolved and verified
- `POLICY_MATCH` - local verifier policy allowed the requested action
- `STATUS_FRESH` - status evidence met the freshness requirement
- `POLICY_SNAPSHOT_MATCH` - a policy snapshot reference and digest matched the decision basis
- `ADMISSION_RECEIPT_LINKED` - post-execution evidence linked to the admission receipt
- `EFFECTIVE_REQUEST_HASH_MATCH` - post-execution evidence matched the admitted effective request hash
- `NO_POLICY_VIOLATIONS` - post-execution evidence reported no policy violations

### Attenuation

- `PAYMENT_TOKEN_LIMIT` - payment authority narrowed the allowed amount or payment scope
- `LOCAL_POLICY_MAX_AMOUNT_NARROWED` - local policy lowered the requested amount
- `TARGET_SCOPE_NARROWED` - local policy narrowed the target resource or audience
- `NEW_PERMIT_REQUIRED` - the requested action requires a fresh or narrower permit before execution

### Schema, Digest, And Proof

- `SCHEMA_INVALID` - an artifact failed required shape validation
- `DIGEST_MISMATCH` - a digest-bound reference did not match the artifact
- `SIGNATURE_INVALID` - signed evidence failed proof validation
- `UNKNOWN_TRUST_ANCHOR` - the signer or issuer was not in the accepted trust bundle
- `ISSUER_NOT_AUTHORIZED` - the issuer was known but not authorized for the evidence type
- `ALG_NOT_ALLOWED` - the presented proof algorithm was not allowed for the matched trust anchor
- `TRUST_ANCHOR_EXPIRED` - the matched trust anchor was outside its accepted validity window
- `TRUST_ANCHOR_NOT_YET_VALID` - the matched trust anchor was not yet valid at verification time
- `TRUST_ANCHOR_REVOKED` - the matched trust anchor was revoked, disabled, or suspended

### Binding And Audience

- `AUDIENCE_MISMATCH` - request audience did not match the relying party or target resource
- `ACTOR_MISMATCH` - actor binding failed
- `PRINCIPAL_MISMATCH` - principal binding failed
- `RUNTIME_MISMATCH` - runtime binding failed
- `RUNTIME_PROOF_STALE` - runtime proof was outside the accepted freshness window

### Permit, Status, And Replay

- `PERMIT_EXPIRED` - task-scoped authority expired before admission
- `PERMIT_NOT_YET_VALID` - task-scoped authority was not valid at admission time
- `PERMIT_REVOKED` - current status revoked the permit
- `STATUS_REVOKED` - current status revoked, suspended, or quarantined required evidence
- `STATUS_STALE` - status evidence was too old for the profile policy
- `REPLAY_DETECTED` - an admission request or receipt nonce was reused when one-time use was required

### Policy And Execution

- `ACTION_NOT_PERMITTED` - requested action exceeded the permit or local policy
- `TARGET_NOT_PERMITTED` - target resource exceeded the permit or local policy
- `POLICY_DENIED` - local verifier policy denied the request
- `POLICY_SNAPSHOT_MISMATCH` - policy snapshot digest did not match the referenced policy basis
- `POST_EXEC_LINKAGE_MISMATCH` - post-execution receipt did not link to the admitted effective request

### Fail Closed

- `FAIL_CLOSED` - the verifier denied execution because required evidence or status could not be trusted

## Conformance Rule

When a conformance fixture specifies `expected.reason_codes`, an implementation report MUST include the same codes in the same order unless the fixture explicitly allows a superset.

Reason-code order is part of the machine-readable decision surface:

- the first non-terminal code is the primary reason for the outcome
- supporting codes follow in verifier evaluation order
- duplicate codes MUST NOT appear in one decision
- `POLICY_MATCH` is a terminal success marker; it MUST only appear on `allow` outcomes and MUST be last
- `FAIL_CLOSED` is a terminal denial marker; it MUST only appear on `deny` outcomes, MUST be last, and MUST follow a primary denial reason

The v0.2 conformance runner enforces the terminal-marker rules above for both repository fixture checks and external SUT comparison reports.
