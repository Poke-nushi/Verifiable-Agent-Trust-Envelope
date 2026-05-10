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

## A2A Metadata And Proof-Binding Threats

The A2A-facing profile adds a specific risk surface: metadata can point to
VATE artifacts, but the metadata is not itself proof of authority.

### 7. A2A Metadata Substitution

Threat:
An intermediary replaces the VATE metadata object or moves it from one task to
another.

Draft response:

- bind metadata references to `transaction_id`
- require digest-bound artifact references
- verify the dereferenced admission receipt before execution

Residual risk:
If an implementation treats metadata presence as approval, substitution can
still bypass the verifier decision.

### 8. Artifact URI Swap

Threat:
An attacker keeps the same metadata shape but changes a receipt or evidence URI.

Draft response:

- require `uri`, `media_type`, and `digest`
- verify the digest before semantic use
- pin expected artifact type and phase

Residual risk:
Mutable URLs remain risky when consumers log or display them without checking
the digest-bound artifact.

### 9. Digest Mismatch Bypass

Threat:
A verifier detects a digest mismatch but continues with policy evaluation or
execution.

Draft response:

- fail closed on digest mismatch before local policy can allow execution
- emit `DIGEST_MISMATCH` and `FAIL_CLOSED`
- keep digest mismatch cases in the runnable corpus

Residual risk:
Adapters that perform partial validation outside the reference comparison path
can still make unsafe local decisions.

### 10. Stale Receipt Replay

Threat:
A previously valid admission receipt is replayed for a new request or after its
validity window.

Draft response:

- bind admission receipts to transaction id and effective request hash
- include expiration windows
- check replay state where the profile requires it

Residual risk:
Replay protection remains deployment-specific unless the verifier stores or can
query replay state consistently.

### 11. Policy Snapshot Downgrade

Threat:
An attacker points to an older or weaker policy snapshot while presenting a
current-looking receipt.

Draft response:

- include digest-bound `policy_snapshot` references
- compare the receipt policy snapshot to the artifact used as decision basis
- fail closed with `POLICY_SNAPSHOT_MISMATCH` when the basis differs

Residual risk:
VATE records the policy basis, but it does not prove the policy was wise or
sufficient for a domain.

### 12. Extension Activation Downgrade

Threat:
A client or intermediary strips extension activation so VATE metadata is
ignored or treated as optional advisory data.

Draft response:

- keep extension activation as A2A capability behavior
- keep VATE admission failures as VATE outcomes
- require deployments to decide whether risky writes require VATE metadata

Residual risk:
If a relying party allows risky writes without requiring the profile, the A2A
extension cannot protect that local policy choice.

### 13. Malicious Agent Card Extension Declaration

Threat:
An agent declares VATE extension support in its Agent Card to appear more
trustworthy than it is.

Draft response:

- treat Agent Card declarations as evidence only
- require verifier policy to evaluate issuer, key, endpoint, freshness, and
  task authority
- keep signed Agent Card evidence separate from admission authority

Residual risk:
User interfaces or logs may overstate the meaning of extension support if they
display it without the verifier decision.

### 14. Signed Agent Card Treated As Sufficient Authority

Threat:
An implementation accepts a signed Agent Card as permission to perform the
requested write.

Draft response:

- document that signed Agent Cards are adjacent evidence
- require admission request, status, replay, runtime, permit, and policy checks
- keep A2A signed Agent Card corpus coverage byte-level and bounded

Residual risk:
This remains an integration risk outside the VATE runner if middleware short
circuits the admission decision.

### 15. Verifier Dereference SSRF

Threat:
An artifact URI causes the verifier to fetch internal network resources or
large unsafe payloads.

Draft response:

- treat every URI as untrusted input
- apply scheme, host, redirect, timeout, size, media type, and digest policy
- prefer pre-fetched or allowlisted artifacts for high-risk deployments

Residual risk:
The current v0.3 reference runner does not implement a production network dereferencer.
Deployment gateways must enforce their own network policy.

### 16. Cross-Tenant Receipt Correlation

Threat:
Stable receipt identifiers or metadata let observers correlate the same agent,
principal, or workflow across tenants.

Draft response:

- minimize metadata fields carried through A2A
- use digest-bound references instead of embedding full evidence
- allow pairwise identifiers where deployments support them

Residual risk:
Operational logging, analytics, and shared receipt stores can still create
linkability.

### 17. Post-Execution Admission Linkage Forgery

Threat:
A post-execution receipt claims to link to an admission receipt that did not
authorize the observed action.

Draft response:

- bind admission receipt id and digest
- bind transaction id, runtime id, decision, expiry, and effective request hash
- emit specific post-execution reason codes for mismatches

Residual risk:
Receipts can describe what was claimed; they do not prove that the underlying
side effect was desirable or legally sufficient.

### 18. Runtime Attestation Freshness Forgery

Threat:
A runtime presents stale or copied attestation evidence as current.

Draft response:

- require freshness windows and checked-at timestamps
- bind runtime evidence to request, transaction, and receipt artifacts
- fail closed for stale runtime proof in AL2 fixtures

Residual risk:
The strength of runtime assurance still varies by environment and attestation
technology.

### 19. OAuth Audience Confusion

Threat:
An OAuth token intended for one resource or audience is treated as authority for
another action.

Draft response:

- treat OAuth artifacts as evidence, not VATE admission
- check audience, resource, scope, and local policy intersection
- deny when upstream authorization is absent or overscoped for the requested
  write

Residual risk:
OAuth server behavior and token introspection semantics remain outside VATE.

### 20. AP2 Mandate Scope Confusion

Threat:
An AP2 or payment mandate is interpreted as broader authority than it actually
grants.

Draft response:

- consume AP2 mandate material as evidence
- bind amount, merchant, time window, and replay constraints into admission and
  post-execution checks
- attenuate or deny when requested action exceeds mandate constraints

Residual risk:
VATE does not replace AP2 validation or payment network rules.

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

- demo-level compact JWS verification
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
