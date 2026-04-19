# Threat Model Notes

This note captures a practical early threat model for this draft.

It is not a complete security proof.
It is a way to make the protocol discussion concrete enough that readers can see which risks this draft is trying to reduce and which risks remain open.

## Security Goal

This draft is intended to reduce ambiguity around:

- who an agent is
- which runtime is actually acting
- what authority exists for the current task
- whether that authority is still valid
- what evidence exists after execution

The goal is not to prove that an agent is always benevolent.
The goal is to make trust decisions and post-hoc accountability materially stronger than unsigned or context-free agent traffic.

## Assets To Protect

The most important assets are:

- passport credentials and signer keys
- runtime-presented keys and attestation material
- mission permits and their scope constraints
- status signals such as revocation, suspension, or attenuation
- execution receipts and evidence references
- privacy-sensitive identifiers and linkable metadata

## Trust Boundaries

This draft assumes several trust boundaries:

- controller versus runtime
- issuer versus verifier
- permit broker versus verifier
- status authority versus caller
- local policy engine versus external artifacts

Many failures happen at those boundaries rather than inside a single artifact.

## Threat Actors

Useful baseline attacker classes are:

- forged external caller pretending to be a legitimate agent
- compromised runtime using a still-valid passport
- over-authorized but nominally valid agent
- network attacker replaying old status or old permits
- malicious intermediary stripping or downgrading the trust envelope context
- verifier implementation that misinterprets binding semantics
- observer correlating pairwise identities across services

## Key Threats And Draft Responses

### 1. Forged Agent Identity

Threat:
An attacker fabricates an agent identity and claims to act on behalf of a principal.

Draft response:

- signed passport credentials
- verifier trust-anchor resolution
- explicit separation of controller, principal, actor, and runtime

Residual risk:
If issuer trust is weak or verifier trust bundles are wrong, forged identity can still succeed.

### 2. Compromised Runtime Using Valid Identity

Threat:
A legitimate passport is presented from a runtime that should no longer be trusted.

Draft response:

- short-lived runtime proof
- proof-of-possession binding to the runtime-presented key
- status signaling for quarantine and revocation

Residual risk:
Weak local-device attestation remains a major gap compared with cloud or hardware-backed environments.

### 3. Permit Replay Or Scope Abuse

Threat:
A valid mission permit is replayed against a different audience, resource, or time window.

Draft response:

- audience binding
- explicit constraints
- proof-of-possession binding
- verifier-side checks for runtime and permit freshness

Residual risk:
The protocol still depends on verifiers actually enforcing constraints rather than only verifying signatures.

### 4. Stale Status

Threat:
A previously valid permit or runtime remains usable because the verifier accepts old status information.

Draft response:

- freshness metadata such as `generated_at` and `next_update_at`
- support for pull, stapled, and push delivery
- profile-specific fail-open or fail-closed rules

Residual risk:
Status freshness policy is still deployment-specific and must be tuned per assurance level.

### 5. Receipt Tampering

Threat:
An execution receipt is modified after the fact or points to the wrong runtime or permit.

Draft response:

- signed receipts
- explicit runtime and permit references
- verifier checks for receipt linkage

Residual risk:
A signed receipt alone does not prove that the execution was good; it only proves what was claimed and signed.

### 6. Metadata Correlation

Threat:
Observers correlate the same agent across contexts and learn unnecessary information about the controller or principal.

Draft response:

- pairwise identifiers where practical
- minimized status lookups
- no requirement for a single global registry

Residual risk:
Operational deployment choices can still create correlation even if the object model allows privacy-preserving identifiers.

## Recommended Mitigation Priorities

For near-term implementations of this draft, the highest-value controls are:

1. strong signer trust distribution
2. runtime-to-permit proof-of-possession binding
3. fresh enough status checks
4. tight verifier-side policy evaluation
5. receipt linkage for auditability

These matter more than cosmetic wire-format decisions.

## What The Reference Demo Proves

The reference demo now exercises:

- compact JWS verification
- trust-bundle based signer lookup
- runtime / permit / receipt binding checks
- pull, stapled, and push status delivery
- negative tests for semantic verifier failures

It does **not** prove:

- production-grade JOSE interoperability
- VC interoperability
- hardware attestation
- secure federation
- confidentiality of metadata in real deployments

## Open Security Questions

The most important open questions for future versions are:

- how profiles for this draft should distinguish local soft-bound runtimes from stronger attested runtimes
- how attenuation should be represented when a permit remains partially valid
- how remote trust distribution and rotation should work across organizations
- how privacy-preserving status lookups should scale
- how receipt evidence should connect to provenance or transparency systems
