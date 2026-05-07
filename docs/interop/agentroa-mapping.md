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

## Mapping

| AgentROA concept | VATE field |
|---|---|
| ROA envelope | `evidence_refs[type=route_authorization]` |
| ARA per-hop receipt | `evidence_refs[type=per_hop_receipt]` |
| AER execution receipt | `post_execution_receipt` |
| Monotonic scope narrowing | `attenuation.changes` and `effective_constraints` |
| Boundary enforcement | verifier-side admission decision |

## Near-Term Decision

For summer 2026, VATE should keep AgentROA as adjacent work.
The useful artifact is a mapping table and later fixture, not a competing route authorization protocol.
