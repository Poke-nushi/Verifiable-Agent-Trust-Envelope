# Verifier Validation Flow
## Proposed validation order for AL2-style interactions

## Purpose

This document proposes a concrete verification order for relying parties that evaluate the trust envelope artifacts in AL2-style digital interactions.

It is intended as implementation guidance, not as a replacement for the core spec.

---

## Inputs

In the v0.3 AL2 profile, the admission request identifies the action, target,
actor, principal and runtime, and supplies digest-addressed evidence references.
A verifier using the v0.1 credential and permit model can draw on:

- `APC` - Agent Passport Credential
- `ARP` - Agent Runtime Proof
- `AMP` - Agent Mission Permit
- request payload or task payload
- local policy configuration
- current status information for the above artifacts

Optionally, the verifier may also receive:

- human approval references
- additional evidence beyond the references required by the admission request
- prior receipts in a delegated chain

---

## Recommended Validation Order

For the current `v0.3` AL2 profile, this sequence should be read as dependency-aware validation stages, not a rigid one-dimensional algorithm.
Some checks need evidence resolution before status can be checked, and some status checks depend on first identifying the artifact being checked.
The important requirement is that the verifier records the stage outcomes and reason codes in the admission receipt.

### 1. Parse and classify the incoming request

The verifier should determine:

- the transport in use
- the requested action
- the target resource
- the claimed actor
- the expected audience

If the request cannot be parsed into a stable action/resource/audience tuple, the verifier should reject it.

### 2. Resolve verifier policy before evaluating the artifacts

The verifier should identify:

- required assurance level
- fail-open or fail-closed behavior
- maximum acceptable artifact freshness
- whether human approval is mandatory
- whether delegated execution is allowed

<a id="3-check-current-status-first"></a>

### 3. Check status for each identified artifact

After identifying the artifact and a trusted source for its status, check
freshness and any revocation or narrowing for:

- the passport credential
- the runtime proof, if separately addressable
- the mission permit

If online status is required and unavailable, AL2 interactions should normally fail closed unless a locally defined exception exists.

### 4. Verify the passport credential

The verifier should validate:

- issuer trust
- credential signature
- subject identity fields
- assurance level
- expiry window
- profile compatibility

The verifier should also decide whether the presented identity information is minimal for the current purpose.

### 5. Verify the runtime proof

The verifier should validate:

- attestor trust
- runtime proof signature
- freshness
- challenge or nonce binding
- audience binding when present
- subject binding back to the passport subject

If runtime freshness is too weak for the action, the verifier should reject even if the passport is valid.

### 6. Verify the mission permit

The verifier should validate:

- permit signature
- issuing broker trust
- actor identity match
- audience match
- time validity
- resource scope
- action scope
- amount, tool, and geography constraints when present
- redelegation depth rules

### 7. Check artifact consistency across the chain

The verifier should confirm that:

- `APC.subject` is compatible with `ARP.subject_id`
- `AMP.actor` matches the actor represented by the credential set
- the permit is intended for this verifier or resource
- the runtime proof is fresh enough for the permit window

### 8. Apply local policy

Only after the cryptographic and structural checks pass should the verifier evaluate:

- business policy
- regulatory policy
- internal allow/deny lists
- approval gates
- risk score overrides

<a id="9-execute-attenuate-or-deny"></a>

### 9. Decide admission before handoff

The verifier records its decision before the target is called. A valid
`allow` makes the original request a handoff candidate. A valid `attenuate`
with `attenuation.require_new_permit: false` makes only the narrowed request
a candidate. The deployment checks validity, current authority, replay state
and target-side requirements before handing it off. A `deny`, a failed
required check or a required fresh permit stops immediate handoff. See the
[admission-to-handoff conditions](profiles/vate-al2-verifier-admission-profile-v0.3.md#admission-to-handoff-conditions).

### 10. Emit or require receipts

The v0.3 [admission receipt](../schemas/admission-receipt.schema.json)
identifies the verifier in `verifier.id`. It records the request and its
subject, the evaluated evidence, the policy, the decision and its validity
window. For `attenuate`, the receipt also records the original and effective
hashes, the changes, the effective constraints and the fresh-permit flag.

When outcome evidence is available, the v0.3
[post-execution receipt](../schemas/post-execution-receipt.schema.json)
identifies its issuer in `issuer.id` and `issuer.role`. Its `admission` object
records the earlier receipt's ID, URI, digest and decision. A receiver can
then check the transaction, runtime, effective request hash, execution window
and reported effects against that admission. The
[receipt model](receipt-model-v0.3.md) describes the linkage checks.

The legacy v0.1 [execution receipt](../schemas/execution-receipt.schema.json)
uses the top-level fields `issuer_role` and `admission_receipt_ref`.
Authenticating an issuer requires the signing and trust rules of the selected
profile.

---

## Failure Guidance

The verifier should reject immediately when any of the following is true:

- status is revoked, suspended, or quarantined
- the audience does not match
- the permit is expired
- the runtime proof is stale beyond policy
- the requested action is outside permit scope
- redelegation rules are violated
- required approval is missing
- a required attenuation effect cannot be interpreted or enforced
- required evidence is missing or unverifiable under a fail-closed policy

Local policy can require a more limited identity presentation or permit cached
status within its defined freshness window.

---

## Suggested Freshness Defaults

These are suggested defaults for an AL2 minimal profile, not core protocol requirements.

- `APC`: issuer-defined, often measured in days or months
- `ARP`: short-lived, often measured in minutes
- `AMP`: short-lived, often measured in minutes
- status cache freshness: measured in minutes, with stricter settings for higher risk actions

---

## Implementation Note

The most important practical property is not just signature verification.  
It is the consistent evaluation of:

1. status
2. identity trust
3. runtime freshness
4. permit scope
5. local policy

That dependency-aware evaluation prevents many classes of "valid signature, wrong context" failures.
It also makes attenuation practical: the verifier can only narrow execution safely after it has already established current status, identity, runtime, and permit scope.

For the current v0.3 AL2 profile, see [docs/profiles/vate-al2-verifier-admission-profile-v0.3.md](profiles/vate-al2-verifier-admission-profile-v0.3.md).
