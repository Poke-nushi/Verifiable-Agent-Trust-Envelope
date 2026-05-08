# Permission Protocol / APP Crosswalk

## Status

This note is a mapping document only.
It is not an implementation PoC.

## Boundary

Permission Protocol / APP-style systems are close to:

- execution-time authorization
- tool gating
- signed permission proofs
- fail-closed runtime checkpoints
- receipt-based control of autonomous actions

VATE's narrower role is:

- consume permission proof or receipt artifacts as evidence
- evaluate them with local verifier policy, status, runtime, actor, principal, and audience bindings
- emit a VATE admission receipt for the relying party boundary

These mappings are evidence-consumption mappings, not semantic equivalence
mappings. VATE does not assert that an adjacent artifact is valid, current,
sufficient, or transferable merely because it is mapped to a VATE evidence
type. Validity and authority must be established by adjacent-protocol
verification, trust bundles, status checks, and local policy.

## Mapping

| Permission Protocol / APP concept | VATE field |
|---|---|
| Permission proof | `evidence_refs[type=mission_permit]` when consumed as task-scoped authority |
| Tool gate | admission request `action` and `target` |
| Runtime checkpoint | `runtime` and runtime evidence |
| Signed receipt | `evidence_refs[type=admission_receipt]` or post-execution receipt evidence |
| Fail-closed result | `decision.outcome=deny` with `FAIL_CLOSED` |

## Near-Term Decision

For summer 2026, VATE should not attempt to replace Permission Protocol / APP.
It should demonstrate that permission proofs can be referenced as adjacent evidence in a verifier-side admission decision.
