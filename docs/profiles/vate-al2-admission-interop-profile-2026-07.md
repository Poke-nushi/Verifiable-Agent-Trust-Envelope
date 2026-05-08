# VATE AL2 Admission Interop Profile 2026-07

## Status

This is a narrow interoperability profile for the `VATE-AL2-Verifier-Admission-v0.2` discussion draft.

It is intended to make conformance fixtures and reference verifier behavior comparable across implementations.
Passing this profile does not imply production readiness, production endorsement, or any right to make a conformance claim beyond the specific fixture result.

## Scope

This profile applies only to `AL2` external digital actions:

- remote writes
- tool calls with external side effects
- delegated task execution that can mutate another system
- payment-adjacent actions where payment authority is evidence, not the settlement rail

This profile does not define:

- A2A core state-machine changes
- an agent identity registry
- a payment protocol
- a global policy language
- runtime attestation formats
- production JOSE or PKI requirements beyond conformance fixtures

## Required Interop Behavior

An implementation that claims compatibility with this profile MUST:

- parse `admission_request`, `admission_receipt`, `post_execution_receipt`, and A2A VATE metadata artifacts that conform to the v0.2 schemas
- treat A2A metadata as untrusted references, not authority
- verify digest-bound references when a fixture explicitly requires an integrity check
- resolve evidence references according to local verifier policy or the test trust bundle
- fail closed on malformed proofs, digest mismatches, untrusted keys, stale
  evidence, and replay before running local policy or attenuation evaluation
- evaluate actor, principal, runtime, audience, permit window, status, and policy checks before execution
- apply VATE permits and attenuation only as an additional narrowing layer over
  transport authorization; VATE MUST NOT expand MCP, OAuth, A2A, or other
  upstream authority
- return exactly one admission decision: `allow`, `attenuate`, or `deny`
- return canonical reason codes from `docs/reason-codes.md`
- fail closed for stale status, revoked status, unknown trust anchors, replay, digest mismatch, and semantic binding mismatch unless a fixture explicitly states otherwise
- emit or validate an admission receipt for every admission decision, including `deny`
- validate post-execution receipt linkage against the admitted effective request hash when execution proceeds
- preserve enough AL2 verification context to replay freshness, replay, and
  runtime-binding decisions in conformance fixtures

An implementation SHOULD:

- preserve unknown extension fields without treating them as authority
- include a policy id and policy version in every admission receipt
- include a digest-bound policy snapshot reference for audit-heavy fixtures
- keep proof packaging separate from receipt semantics

An implementation MAY:

- accept VC, DID, OID4VP, OAuth, MCP, A2A, AP2, ACP, x402, Web Bot Auth, or payment-token evidence as references
- support stronger runtime assurance profiles outside this AL2 interop profile

## Conformance Vocabulary

The canonical outcome fields are:

- `expected_outcome`
- `actual_outcome`
- `expected_should_execute`
- `actual_should_execute`
- `expected_reason_codes`
- `actual_reason_codes`
- `pass`

The canonical reason code spelling is `SCREAMING_SNAKE_CASE`.
`should_execute` is separate from the admission outcome. An attenuated decision
can still have `should_execute: false` when a fresh or narrower permit is
required before execution.

Conformance reports MUST be machine-readable JSON and SHOULD validate against `schemas/conformance-report.schema.json`.

## Packaging Baseline

The semantic artifacts in this profile are JSON documents.

The conformance baseline uses:

- JSON artifacts
- SHA-256 digest descriptors
- verifier-signed or verifier-issued admission receipts
- optional compact or detached JWS evidence in reference demos

This profile does not require VC, JWT, or JWS as the only valid packaging form.

## A2A Binding Rule

A2A messages and Agent Card metadata SHOULD carry only digest-bound references to VATE artifacts.
They SHOULD NOT embed full VATE receipts or verifier policy bodies by default.

The verifier MUST dereference or otherwise obtain the referenced artifacts and evaluate them under local policy before admitting an externally-effectful action.

## Interop Cut Line

For July 2026 interop, a profile-compatible implementation is expected to pass the runnable corpus under `conformance/al2-vate-v0.2/`.

Passing that corpus means the implementation is fixture-compatible for this draft.
It does not imply production readiness or production endorsement.
