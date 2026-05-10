# A2A Maintainer Brief For VATE v0.2
## Metadata-only admission and receipt binding

## Historical Note

This file describes the v0.2 A2A-shaped review line. Current main-branch
hardening work uses [A2A Maintainer Brief For VATE v0.3](a2a-maintainer-brief-v0.3.md).

## Short Position

VATE v0.2 is not asking A2A to become a trust, payment, identity, or policy protocol.

The proposal is narrower:

> Let A2A carry task flow and optional references. Let a verifier-side profile define how risky external actions are admitted, narrowed, denied, and later audited.

This brief is written for A2A maintainers and implementers who need to decide
whether the VATE v0.2 boundary fits A2A-style extension metadata review.

## The Gap

A2A is strong at:

- discovery
- Agent Cards
- task and message exchange
- transport bindings
- extension governance

Those are the right responsibilities for A2A.

The remaining gap appears at the relying-party boundary:

> An external agent asks a remote system to perform a risky write. The remote system needs to decide whether this specific actor and runtime may perform this specific action for this principal under the current constraints.

Discovery metadata, an access token, or a signed Agent Card can be necessary evidence.
They are not always sufficient proof of current task-scoped authority.

VATE v0.2 focuses on that last admission decision.

## What A2A Would Carry

The proposed A2A-facing surface is intentionally small.

A2A metadata may carry:

- profile id
- phase
- transaction id
- assurance level
- artifact URI
- media type
- digest
- optional policy snapshot reference and digest for audit-heavy deployments
- issuer
- issued time
- expiration time

The full admission request, admission receipt, policy semantics, attenuation details, status evidence, and post-execution receipt stay outside A2A core payloads.

Example:

```json
{
  "https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/a2a/admission/v0.2": {
    "profile": "VATE-AL2-Verifier-Admission-v0.2",
    "phase": "admission_issued",
    "transaction_id": "txn-20260504-001",
    "assurance_level": "AL2",
    "decision": "attenuate",
    "admission_receipt": {
      "type": "admission_receipt",
      "uri": "https://verifier.example/vate/admission-receipts/admrec-20260504-001",
      "media_type": "application/vate-admission-receipt+json",
      "digest": {
        "alg": "sha-256",
        "value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      }
    },
    "policy_snapshot": {
      "type": "policy_snapshot",
      "uri": "https://verifier.example/policies/merchant-purchase-al2/snapshots/2026-05-04.1",
      "media_type": "application/vate-policy-snapshot+json",
      "digest": {
        "alg": "sha-256",
        "value": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
      }
    },
    "issuer": "did:web:verifier.example",
    "issued_at": "2026-05-04T03:00:08Z",
    "expires_at": "2026-05-04T03:10:08Z"
  }
}
```

## What A2A Would Not Have To Own

This proposal does not require A2A to own:

- verifier policy language
- status or revocation networks
- payment state machines
- credential formats
- runtime attestation formats
- HTTP request signature schemes
- trust scores
- receipt storage
- A2A core state-machine changes

Those remain adjacent concerns.
VATE defines how a verifier records its decision around them.
If an implementation needs to reconstruct why a decision was made, it can reference a digest-bound policy snapshot without asking A2A to understand the policy language.

## Why This Is Practically Useful

The useful outcome is not a new abstract trust layer.
The useful outcome is a small interoperable record at the moment a risky action crosses a trust boundary.

The verifier can record:

- what was requested
- who the actor was
- which principal was represented
- which runtime was bound to the request
- which evidence was checked
- which policy version was applied
- whether the result was `allow`, `attenuate`, or `deny`
- exactly what changed when authority was narrowed
- how post-execution evidence links back to the admission decision

That gives implementers a practical audit object without forcing A2A to carry or standardize every trust artifact.

## Why Attenuation Matters

Many real verifier decisions are not binary.

Examples:

- allow the task, but lower the payment limit
- allow a tool call, but narrow the tool allowlist
- allow a write, but shorten the execution window
- allow only against one audience or resource

VATE treats `attenuate` as a first-class decision.
The receipt records the original request hash, the effective request hash, explicit changes, reason codes, and effective constraints.

That is more actionable than a generic "restricted" result.

## Security Boundary

A VATE reference in A2A metadata is not itself proof of authority.

A verifier still needs to:

- dereference or otherwise obtain the referenced artifact
- verify digest binding
- check issuer trust according to local policy
- evaluate status and freshness
- verify audience and action scope
- decide whether to fail closed, deny, or attenuate

This is why the binding is by-reference rather than "trust metadata because it is in A2A".

## v0.2 Corpus Fixture

The AL2 v0.2 corpus includes `allow-a2a-signed-agent-card-evidence`.
That case binds a canonicalized A2A Agent Card payload digest to admission
receipt evidence and detached JOSE fixture bytes.

The fixture is byte-level only. It does not claim production ECDSA verification
or make signed Agent Cards sufficient authority for risky external writes.

## v0.2 Review Aids

The AL2 v0.2 conformance surface is the corpus under
`conformance/al2-vate-v0.2/`. Its case count is recorded in
`conformance/al2-vate-v0.2/corpus.json` as `summary.case_count`.

For an external implementation, the command-first path is
`docs/conformance/external-sut-quickstart.md`. That path treats `compare` as the
primary external SUT review command. `run` is only a repository fixture and
reference-runner integrity check.

If a SUT result is compared with both a conformance report and implementation
report, `docs/conformance/report-integrity.md` documents `verify-bundle` for
checking the local digest chain among the corpus, SUT result, conformance
report, and implementation report. That check does not replace JOSE, PKI,
Sigstore, signed git tags, or other external publication proofs.

Package-private TypeScript helpers are available in `packages/vate-core-ts/` and
`packages/vate-a2a-ts/` for reviewers who want to inspect digest descriptors, SUT
result entry shaping, A2A metadata shape validation, and optional activation
header behavior. They are review aids, not official A2A SDKs or production
verifiers.

## Possible A2A Outcomes

There are three reasonable outcomes.

### 1. Adjacent Profile Only

A2A does nothing official.
VATE remains an adjacent profile that implementers may reference from A2A metadata.

This is acceptable.

### 2. Community Extension

A2A treats the metadata key and phase values as a community extension pattern.
The receipt semantics remain outside A2A core.

This is the most likely useful middle ground.

### 3. Future Official Binding

If multiple implementations emerge, A2A could consider a narrow official binding later.
That should still avoid pulling full verifier policy, payment, identity, or receipt storage semantics into A2A core.

## Maintainer Question

The main question is:

> Can this metadata-only, by-reference admission / receipt binding be reviewed through A2A-style extension metadata, or should it remain entirely as an adjacent VATE profile outside A2A governance?

The proposal is intentionally modest.
It tries to preserve A2A's boundary while giving implementers a concrete way to carry verifier-side admission evidence across A2A task flows.
