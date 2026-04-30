# AL2 Minimal Profile
## Proposed baseline for external digital interactions

## Status

This document is a proposed profile, not part of the core of this draft.

It describes a minimum practical profile for AL2 interactions where an external service or relying party accepts agent actions with meaningful digital side effects.
This is also the primary v0.1 reference battlefield for the current repository.

---

## Intended Context

This profile is aimed at cases such as:

- third-party service calls
- digital write actions
- delegated work against external systems
- low-to-moderate value payment-adjacent operations
- public or semi-public agent-facing APIs

It is not sufficient for strongly regulated or safety-critical cases. Those should move toward AL3 or AL4 profiles.
The repository's `reference/http-verifier-demo/` directory is the narrow verifier wedge for this profile.

---

## Required Artifacts

An AL2 interaction should require:

- `APC` - valid passport credential
- `ARP` - fresh runtime proof
- `AMP` - task-scoped mission permit
- `AER` - admission receipt and, where execution proceeds, post-execution receipt for high-risk actions
- online or bounded-freshness status checks

---

## Required Checks

The relying party should verify:

- issuer trust for the passport credential
- attestor trust for the runtime proof
- broker trust for the mission permit
- audience restriction
- action and resource scope
- permit expiry
- runtime freshness
- redelegation depth
- applicable status for credential, runtime, and permit

---

## Freshness Recommendations

These are profile recommendations, not protocol-wide constants.

- `APC`: issuer policy
- `ARP`: ideally measured in minutes
- `AMP`: ideally measured in minutes
- status cache: bounded and short-lived

If runtime freshness cannot be established, the verifier should reject.

---

## Receipt Minimums

An AL2 receipt should include at least:

- `receipt_id`
- `receipt_phase`
- `transaction_id`
- `actor`
- `runtime_ref`
- `permit_ref`
- `verifier`
- `issuer_role`
- `policy_id`
- `policy_version`
- `started_at`
- `finished_at`
- `outcome`
- `input_hash` or input reference
- `output_hash` or output reference

For verifier-signed admission receipts, AL2 should also include:

- `decision`: `allow`, `attenuate`, or `deny`
- `attenuations[]` when the effective constraints differ from the original permit constraints

For post-execution receipts, AL2 should include `admission_receipt_ref` when an admission receipt was issued.

Optional but strongly recommended:

- evidence references
- delegated chain references
- artifact digests

---

## Status Behavior

Suggested handling:

- `active`: allow normal evaluation
- `attenuated`: allow only if the verifier understands the `effect` object and local policy can safely narrow execution; otherwise require a new permit or manual review
- `suspended`: deny
- `revoked`: deny
- `quarantined`: deny

---

## Explicit Non-Requirements

This profile does not require:

- real-name identity
- mandatory KYC
- a single global registry
- a single issuer
- a specific chain or settlement rail

---

## Why This Profile Matters

Without a clear AL2 baseline, systems tend to collapse into one of two bad outcomes:

- over-permissive integrations with weak runtime and permit checks
- over-heavy enterprise-style controls for moderate-risk digital interactions

A minimal AL2 profile provides a middle ground that is stricter than informal automation, but lighter than fully regulated environments.
