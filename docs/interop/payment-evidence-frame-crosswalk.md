# Payment Evidence Frame To VATE Crosswalk

## Status

This is a small interoperability note for the `VATE AL2 Admission Interop Profile 2026-07`.

It does not claim that VATE replaces Payment Evidence Frame (PEF), x402, payment receipts, A2A, payment service providers, wallets, merchant checkout systems, or banking systems.
It shows how a PEF-style payment lifecycle artifact can be consumed as VATE evidence at the verifier-side admission and post-execution linkage boundary.

Relevant adjacent references:

- IETF Datatracker Payment Evidence Frame Internet-Draft: <https://datatracker.ietf.org/doc/draft-hopley-x402-payment-evidence-frame/>
- IETF announcement for `draft-hopley-x402-payment-evidence-frame-00`: <https://mailarchive.ietf.org/arch/msg/i-d-announce/ukGutzxbT6ATCtmiSriCRmSR9fg/>
- A2A protocol specification: <https://a2a-protocol.org/latest/specification/>

## Boundary

PEF is close to:

- payment lifecycle receipt framing
- x402-adjacent payment evidence
- stable frame identifiers
- claim-type labels for payment admission, settlement, cancellation, refund, and composite verdict evidence
- receipt integrity hashes and optional transport-layer signatures
- possible transport through HTTP headers, A2A task artifacts, audit logs, or on-chain memo fields

VATE's narrower role is:

- take PEF artifacts as digest-bound payment evidence when local policy requires payment evidence
- bind payment evidence to actor, principal, runtime, target audience, action, amount, and request hash
- decide whether the risky external digital action is admitted, narrowed, or denied before execution
- emit a VATE admission receipt before execution
- link later payment settlement, cancellation, refund, or composite verdict evidence back to the admitted request

These mappings are evidence-consumption mappings, not semantic equivalence mappings.
VATE does not assert that a PEF artifact is valid, current, sufficient, settled, refundable, chargeback-safe, or transferable merely because it is mapped to a VATE evidence type.
Validity and authority must be established by payment-protocol verification, trust bundles, status checks, replay controls, and local verifier policy.

## Mapping

| PEF concept | VATE field |
|---|---|
| Full PEF frame used before execution | `evidence_refs[type=payment_authority, protocol_hint=x402]` when it supplies payment authority evidence |
| x402 payment-required or challenge state | `evidence_refs[type=payment_required_state, protocol_hint=x402]` |
| PEF frame used after execution | post-execution receipt evidence or `evidence_refs[type=post_execution_receipt]` when it is linked after admission |
| `claim_type=payment_admission` | admission evidence input and local policy check, not a VATE admission receipt by itself |
| `claim_type=payment_settlement` | post-execution evidence linked to a prior VATE admission receipt |
| `claim_type=payment_cancellation` / `payment_refund` | post-execution evidence that may change local policy state or audit outcome |
| `claim_type=composite_verdict` | adjacent payment verdict evidence; VATE still records its own verifier decision |
| `frame_id` | adjacent correlation handle, usually recorded in evidence verification metadata or receipt correlation |
| `receipt_hash` | adjacent receipt integrity evidence, usually recorded in evidence verification metadata |
| Optional PEF signature | evidence verification method and trust-bundle input |
| A2A task artifact carrying PEF | adjacent artifact body; VATE A2A metadata should still prefer digest-bound references where possible |

The current v0.3 evidence registry does not define a dedicated `payment_evidence_frame` type or `pef` protocol hint.
Under the AL2 v0.3 conformance profile, use the registered generic payment evidence types and the registered `x402` hint where appropriate.
A future profile may add a dedicated PEF evidence type or hint if independent implementations need one.

## Digest Basis

PEF `frame_id` and `receipt_hash` have their own adjacent-protocol digest basis.
Do not silently substitute them for the VATE `digest` descriptor unless a profile explicitly defines that equivalence.

For AL2 v0.3 review artifacts, the VATE `digest` descriptor should bind the exact artifact bytes or the profile-defined canonical artifact basis used by the VATE evidence reference.
PEF identifiers can be preserved as adjacent evidence metadata, but the VATE receipt should remain clear about which digest basis was checked.

## A2A Boundary

A2A can carry task flow and may carry or reference payment evidence artifacts.
VATE should not require A2A core to own payment lifecycle semantics or verifier-side admission semantics.

For A2A-shaped flows, the safer review boundary remains:

- A2A carries task flow and optional metadata or artifacts.
- PEF can supply payment-specific evidence.
- VATE records the relying-party admission decision and receipt.
- Full artifacts should be referenced by digest where possible instead of treating task metadata as sufficient authority.

## Non-Goals

This crosswalk does not define PEF, x402, payment settlement, refund semantics, compliance screening, chargeback handling, merchant-of-record semantics, wallet UX, or banking ledger behavior.
It does not require PEF implementations, A2A implementations, or payment systems to emit VATE receipts.
It only demonstrates how a VATE verifier can consume adjacent payment evidence before admission and link later payment evidence after execution.
