# VATE AL2 Admission Interop Profile 2026-09

## Status

This is the active interoperability profile note for the
`VATE-AL2-Verifier-Admission-v0.3` discussion draft on `main`.

It makes conformance fixtures and verifier behavior comparable across
implementations. A result applies to one implementation run and one exact
corpus snapshot. It does not imply production readiness, certification,
endorsement, or general compatibility.

The `2026-09` label identifies the current machine-readable artifact line. It
does not change the v0.3 profile identifier. Historical `2026-07` results must
be checked with their recorded v0.3.2 tag or commit and are not current-line
results.

## Scope

This profile applies to `AL2` external digital actions:

- remote writes
- tool calls with external side effects
- delegated task execution that can mutate another system
- payment-adjacent actions where payment authority is evidence, not the
  settlement rail

This profile does not define:

- A2A core state-machine changes
- an agent identity registry
- a payment protocol
- a global policy language
- runtime attestation formats
- production JOSE or PKI requirements beyond conformance fixtures

## Required Interop Behavior

An implementation result reported against this profile snapshot MUST:

- parse the admission, receipt, post-execution, and referenced context artifacts
  required by each selected case
- treat A2A metadata and adjacent-protocol mappings as untrusted references,
  not authority
- verify digest-bound references whenever a case requires integrity checking
- fail closed on malformed proofs, digest mismatches, untrusted keys, stale
  evidence, replay, and required-binding failures before local policy or
  attenuation evaluation
- evaluate actor, principal, runtime, audience, permit window, status, and local
  policy before execution
- apply VATE permits and attenuation only as an additional narrowing layer over
  transport authorization; VATE MUST NOT expand upstream authority
- return exactly one admission outcome: `allow`, `attenuate`, or `deny`
- return canonical reason codes from `docs/reason-codes.md`
- emit or validate an admission receipt for every admission decision, including
  `deny`
- preserve original and effective request binding when attenuation changes the
  admitted request
- validate post-execution linkage against the admitted effective request when
  execution proceeds
- preserve the AL2 verification context needed by selected freshness, replay,
  status, runtime, request, evidence, and receipt checks

An implementation SHOULD:

- preserve unknown extension fields without treating them as authority
- include a policy identifier and version in each admission receipt
- include a digest-bound policy snapshot reference for audit-heavy cases
- keep proof packaging separate from receipt semantics

An implementation MAY consume VC, DID, OID4VP, OAuth, MCP, A2A, AP2, ACP,
x402, Web Bot Auth, or payment-token evidence as references. Mapping that
evidence does not establish that it is valid, current, sufficient, or
semantically equivalent.

## Current SUT Result Contract

The active SUT result version is `vate-sut-results-2026-09`.

For a case that declares `sut_inputs`, a current result must identify the input
artifacts that the implementation actually consumed. Required artifacts may
not be replaced with receipt outputs or omitted into the legacy lane.

The current contract has two artifact modes:

- `corpus-fixture-validation`: validates references to the fixed corpus bytes;
  it does not establish that the SUT evaluated those bytes
- `generated-receipts`: keeps independently generated receipt bytes separate
  and revalidates their digest, bounded semantics, and post-execution linkage

A complete report may contain matching, differing, skipped, unsupported, or
error results. Preserving a semantic difference is preferable to translating it
away.

## Conformance Vocabulary

The comparison surface includes:

- expected and actual outcome
- expected and actual `should_execute`
- expected and actual reason codes
- per-case status and failures
- required input and generated artifact references

Reason codes use `SCREAMING_SNAKE_CASE`. `should_execute` is distinct from the
admission outcome. An attenuated request can still have
`should_execute: false` when a fresh permit is required.

## Packaging Baseline

The current baseline uses JSON artifacts, lowercase SHA-256 digest descriptors,
and verifier-issued admission receipts. Selected fixtures include compact or
detached JWS-shaped evidence for byte-level checks.

The profile does not require VC, JWT, or JWS as the only packaging form and
does not claim production cryptographic signature verification.

## A2A Binding Rule

A2A messages and Agent Card metadata SHOULD carry digest-bound references to
VATE artifacts instead of embedding policy bodies or full receipts by default.
The verifier remains responsible for obtaining and evaluating the referenced
artifacts under local policy.

## Current Cut Line

A current result is compared with the runnable corpus under
`conformance/al2-vate-v0.3/` and the exact manifest digest recorded in the
result. Passing means one implementation result matched that one snapshot under
the repository comparison rules. Historical results remain valid historical
evidence only in their recorded compatibility lane.
