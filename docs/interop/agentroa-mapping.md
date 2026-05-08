# AgentROA Mapping

## Status

This note is a mapping document only.
It is not an IETF proposal or implementation PoC.

## Boundary

AgentROA-style drafts are close to:

- route authorization envelopes
- per-hop receipts
- execution receipts
- monotonic scope narrowing
- cryptographic policy enforcement around agent actions

VATE's narrower role is:

- consume route authorization or receipt artifacts as evidence
- decide whether one externally-effectful action should be admitted, narrowed, or denied
- emit an admission receipt and validate post-execution linkage

These mappings are evidence-consumption mappings, not semantic equivalence
mappings. VATE does not assert that an adjacent artifact is valid, current,
sufficient, or transferable merely because it is mapped to a VATE evidence
type. Validity and authority must be established by adjacent-protocol
verification, trust bundles, status checks, and local policy.

## Mapping

| AgentROA concept | VATE field |
|---|---|
| ROA envelope | `evidence_refs[type=mission_permit]` when consumed as bounded route authority |
| ARA per-hop receipt | `evidence_refs[type=admission_receipt]` or post-execution receipt evidence |
| AER execution receipt | `post_execution_receipt` |
| Monotonic scope narrowing | `attenuation.changes` and `effective_constraints` |
| Boundary enforcement | verifier-side admission decision |

## Near-Term Decision

For summer 2026, VATE should keep AgentROA as adjacent work.
The useful artifact is a mapping table and later fixture, not a competing route authorization protocol.
