# Agent Authorization Envelope To VATE Crosswalk

## Status

This is a small interoperability note for the `VATE AL2 Admission Interop Profile 2026-07`.

It does not claim that VATE replaces Agent Authorization Envelope (AAE), W3C Verifiable Credentials, DID, JOSE, JWS, or any AAE verification algorithm.
It shows how an AAE-style authorization artifact can be consumed as VATE evidence at the verifier-side admission boundary.

Relevant adjacent reference:

- IETF Datatracker AAE Internet-Draft: <https://datatracker.ietf.org/doc/draft-kroehl-agentic-trust-aae/>

## Boundary

AAE is close to:

- machine-evaluable authorization envelopes for autonomous agents
- Verifiable Credential and JWS packaging
- mandate, action, constraint, validity, delegation, and revocation data
- relying-party verification of subject binding, temporal validity, action authorization, constraints, and replay state

VATE's narrower role is:

- take an AAE artifact as digest-bound `evidence_ref`
- bind that artifact to the concrete actor, principal, runtime, audience, target, action, and local policy context
- decide whether the risky external digital action is admitted, narrowed, or denied
- emit a VATE admission receipt before execution
- link later execution evidence back to the admitted request and effective constraints

These mappings are evidence-consumption mappings, not semantic equivalence mappings.
VATE does not assert that an AAE is valid, current, sufficient, or transferable merely because it is mapped to a VATE evidence type.
Validity and authority must be established by AAE verification, trust bundles, status or revocation checks, replay controls, and local verifier policy.

## Mapping

| AAE concept | VATE field |
|---|---|
| AAE VC/JWS artifact | `evidence_refs[type=mission_permit]` when consumed as action authority evidence |
| AAE VC packaging | `evidence_refs[type=verifiable_credential]` when the deployment wants to record VC evidence separately |
| Issuer DID and `kid` | evidence verification method, trust bundle issuer/key policy, and receipt `evidence[].verification` |
| `credentialSubject.id` | admission request `actor`, when the presenting agent is the subject |
| `mandate.principal_did` | admission request `principal` |
| `mandate.actions[]` | admission request `action` and local policy action checks |
| `mandate.scope` or purpose | admission request `constraints`, `correlation`, or policy-specific context |
| `constraints` | admission request `constraints` and possible VATE attenuation `effective_constraints` |
| `validity.not_before` / `not_after` | admission request and admission receipt validity windows |
| `validity.revocation_check` | evidence `verification.status_result` and reason codes on failure |
| `validity.single_use` | replay checks and deny reason codes when replay is detected |
| Delegation chain | evidence set plus local trust-bundle and principal-linkage policy |
| AAE verification result | admission receipt `evidence[].verification` |

The current v0.3 evidence registry does not define an `aae` protocol hint.
Do not emit an unregistered `protocol_hint` under the AL2 v0.3 conformance profile.
A future profile may add a dedicated hint or evidence type if independent implementations need one.

## Admission Shape

An AAE can answer parts of the permit question:

- is this agent authorized for this action class?
- what constraints bind the authorization?
- what validity window, revocation source, and single-use rule apply?
- what delegation chain or principal binding is presented?

VATE still has to answer the relying-party admission question:

- does the AAE bind to this concrete request, audience, target, runtime, and principal?
- is the artifact fresh and acceptable under local policy?
- should the action be allowed as requested, attenuated, or denied?
- what receipt records the verifier decision before execution?

## Non-Goals

This crosswalk does not define AAE semantics.
It does not validate AAE signatures, DID resolution, VC status, delegation correctness, or revocation endpoints.
It does not require AAE implementations to emit VATE receipts.
It only demonstrates how a VATE verifier can consume an adjacent authorization envelope as evidence before admitting a risky external digital action.
