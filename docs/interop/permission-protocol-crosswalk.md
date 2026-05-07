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

## Mapping

| Permission Protocol / APP concept | VATE field |
|---|---|
| Permission proof | `evidence_refs[type=permission_proof]` |
| Tool gate | admission request `action` and `target` |
| Runtime checkpoint | `runtime` and runtime evidence |
| Signed receipt | `evidence_refs[type=permission_receipt]` or post-execution receipt evidence |
| Fail-closed result | `decision.outcome=deny` with `FAIL_CLOSED` |

## Near-Term Decision

For summer 2026, VATE should not attempt to replace Permission Protocol / APP.
It should demonstrate that permission proofs can be referenced as adjacent evidence in a verifier-side admission decision.
