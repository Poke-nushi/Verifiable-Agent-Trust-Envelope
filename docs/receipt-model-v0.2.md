# Receipt Model v0.2
## Admission receipts and post-execution receipts

## Status

This document defines the v0.2 receipt model for the AL2 verifier admission profile.
It does not remove the existing `schemas/execution-receipt.schema.json` v0.1 AER schema.
Current main-branch hardening work uses [Receipt Model v0.3](receipt-model-v0.3.md).
Unversioned schema and example paths on current main may reflect v0.3; use the
`v0.2.0` tag for the exact archived v0.2 artifacts.

In v0.2, the generic v0.1 AER shape remains a legacy-compatible receipt.
The profile adds two narrower schemas:

- `schemas/admission-receipt.schema.json`
- `schemas/post-execution-receipt.schema.json`

## Why Split Receipts

Admission and execution evidence answer different questions.

An admission receipt answers:

> Why did the verifier allow, narrow, or deny this request before execution?

A post-execution receipt answers:

> What happened after the admitted request ran?

Combining both phases into one loose object makes signer semantics and audit expectations unclear.
The split keeps the phase, issuer role, evidence, and required fields clear.

## Admission Receipt

An admission receipt is normally issued by the verifier before execution.

It records:

- the request being evaluated
- actor, principal, and runtime binding
- evidence references and verification results
- policy id and policy version
- optional digest-bound policy snapshot reference for audit-heavy deployments
- decision outcome
- reason codes
- expiration
- attenuation details when the verifier narrowed the request

Allowed decision outcomes:

- `allow`
- `attenuate`
- `deny`

An admission receipt with `deny` is still useful.
It records why execution did not proceed.
If a referenced policy snapshot digest does not match the policy artifact used as the decision basis, the verifier should deny or fail closed with `POLICY_SNAPSHOT_MISMATCH`.

## Post-Execution Receipt

A post-execution receipt is issued after execution, cancellation, or failure.
It may be issued by the runtime, agent, verifier, or broker depending on deployment.

It records:

- the linked admission receipt
- the effective request hash
- execution timing
- runtime id
- result outcome
- output digest
- side effects
- policy violations
- error details when execution failed

A post-execution receipt must not silently change the admitted request.
The `effective_request_hash` should match the request admitted by the admission receipt.
For the AL2 v0.2 profile, `input_hash`, `output_hash`,
`original_request_hash`, and `effective_request_hash` use the same profile hash
grammar: `sha-256:` followed by a lowercase 64-character hexadecimal digest.
For the AL2 conformance corpus, post-execution linkage also binds the admission
receipt digest, admission decision, transaction id, runtime id, admission expiry,
and attenuated effective constraints. A mismatch on any of those fields is
reported with the most specific applicable post-execution reason code, such as
`POST_EXEC_ADMISSION_DIGEST_MISMATCH`,
`POST_EXEC_EFFECTIVE_REQUEST_HASH_MISMATCH`, `POST_EXEC_RUNTIME_MISMATCH`, or
`POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED`. `POST_EXEC_LINKAGE_MISMATCH` remains
a generic fallback for older or underspecified fixtures.

The admission receipt top-level `issued_at` and `expires_at` are the authoritative
post-execution linkage window in the v0.2 corpus: execution must start no earlier
than `issued_at` and must finish no later than `expires_at`. If an attenuation
object also carries `effective_constraints.expires_at`, it documents the admitted
constraint basis but does not broaden the top-level admission window.

For an `attenuate` decision, the post-execution constraint basis is
`attenuation.effective_constraints`. For an `allow` decision, the original
request constraints remain effective when the admission receipt records them
under `request.constraints`.

Within that constraint basis, `max_amount` is interpreted as an aggregate cap
for the admitted execution, not a per-side-effect cap. Post-execution verifiers
sum all `result.side_effects[].amount` entries in the admitted currency and
reject when the total exceeds `max_amount`. Side effects without an `amount` do
not contribute to the amount total; an amount in a different currency fails the
constraint check. For this corpus, only `side_effects[].amount` is
amount-bearing; other monetary-looking fields are ignored unless a future
profile registers them. If a future profile needs both total and per-effect
caps, it should add a separate field such as `max_amount_per_side_effect`
rather than changing `max_amount`.

An attenuated admission receipt can still be non-executable. In particular,
`attenuation.require_new_permit: true` means the verifier found a narrower or
fresh-permit path, but execution should not proceed until that new permit is
available.

## Attenuation

When the decision is `attenuate`, the admission receipt should include a machine-readable attenuation object.

The object should include:

- `mode`
- `original_request_hash`
- `effective_request_hash`
- `changes`
- `effective_constraints`
- `require_new_permit`

Each change should identify:

- operation
- target path
- original value
- applied value
- reason code
- source evidence or status reference when available

This is stricter than a human note such as "restricted".
It lets another verifier, auditor, or runtime see exactly which authority was narrowed.

For example, a verifier can record that a request for a USD 10000 transfer was
admitted only as an effective USD 500 maximum, with human approval required
above USD 100 and a 10-minute execution window. The receipt needs both hashes:
the original request hash explains what was requested, and the effective request
hash explains what was actually admitted.

## Proof And Packaging

The semantic receipt schemas do not define a new signature scheme.

A receipt may be packaged as:

- detached JWS
- JWT
- VC proof
- external proof reference
- HTTPS dereferenceable artifact with digest binding

Profiles and deployments decide which packaging forms they accept.
For AL2, signed or digest-bound receipts are strongly recommended.

## Evidence Results

Evidence should record more than a boolean.

A useful evidence result includes:

- evidence type
- reference URI
- digest
- verification result
- checked time
- status result
- method or verifier component
- failure reason when verification failed

This keeps receipts useful for audit and debugging without requiring VATE to redefine the evidence artifact itself.

## Example Files

- `examples/receipts/admission-allow.example.json`
- `examples/receipts/admission-attenuate-max-amount.example.json`
- `examples/receipts/admission-deny-expired-permit.example.json`
- `examples/receipts/post-execution-success.example.json`
