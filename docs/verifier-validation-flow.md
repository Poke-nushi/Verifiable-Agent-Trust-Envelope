# Verifier Validation Flow
## Proposed validation order for AL2-style interactions

## Purpose

This document proposes a concrete verification order for relying parties that evaluate the trust envelope artifacts in AL2-style digital interactions.

It is intended as implementation guidance, not as a replacement for the core spec.

---

## Inputs

A verifier typically receives or resolves the following artifacts:

- `APC` - Agent Passport Credential
- `ARP` - Agent Runtime Proof
- `AMP` - Agent Mission Permit
- request payload or task payload
- local policy configuration
- current status information for the above artifacts

Optionally, the verifier may also receive:

- human approval references
- evidence references
- prior receipts in a delegated chain

---

## Recommended Validation Order

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

### 3. Check current status first

Before trusting signatures alone, the verifier should check current status for:

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

### 9. Execute, attenuate, or deny

If any required check fails, deny before execution.

If the permit is `attenuated` and the verifier understands the `effect` object, the verifier MAY continue with a narrowed effective policy and return an `attenuate` decision instead of a full deny.

If execution proceeds, the verifier should capture enough context to emit or require a receipt.

### 10. Emit or require an execution receipt

For AL2 and above, the verifier should record at least:

- permit reference
- runtime reference
- actor reference
- action/resource
- outcome
- start and finish time
- policy reference
- evidence references when available

The receipt should also make its signer semantics explicit.
At minimum, it should declare `issuer_role`, for example:

- `runtime`
- `verifier`
- `broker`

That prevents ambiguity between "the runtime claims it executed this" and "the relying party attests that it accepted or observed this."

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

The verifier should downgrade or require extra controls when any of the following is true:

- status is attenuated and the verifier cannot safely honor the `effect` object
- evidence is incomplete
- the identity presentation reveals more than necessary
- online status is unavailable but cached status is still within bounded freshness

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
It is the consistent ordering of:

1. status
2. identity trust
3. runtime freshness
4. permit scope
5. local policy

That ordering prevents many classes of "valid signature, wrong context" failures.
It also makes attenuation practical: the verifier can only narrow execution safely after it has already established current status, identity, runtime, and permit scope.
