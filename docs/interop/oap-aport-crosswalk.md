# OAP / APort To VATE Crosswalk

## Status

This is a small interoperability note for the `VATE AL2 Admission Interop Profile 2026-07`.

It does not claim that VATE replaces OAP / APort.
It shows how an OAP-style passport or decision object can be consumed as VATE evidence.

## Boundary

OAP / APort is close to:

- passport presentation
- pre-action decision objects
- policy packs
- signed decisions
- conformance-oriented guardrails

VATE's narrower role is:

- take an OAP / APort decision object as `evidence_ref`
- evaluate it with actor, principal, runtime, audience, status, and local policy context
- emit a VATE admission receipt for a specific external digital action
- link post-execution evidence back to the admitted request

## Mapping

| OAP / APort concept | VATE field |
|---|---|
| Passport | `evidence_refs[type=passport]` |
| Decision object | `evidence_refs[type=oap_decision]` |
| Policy pack | `policy.policy_ref` or `policy.policy_snapshot` |
| Decision TTL | admission request `expires_at` and admission receipt `expires_at` |
| Signed decision | evidence `digest` and proof packaging metadata |
| Reasoning / result | admission receipt `evidence[].verification` and `decision.reason_codes` |

## PoC Fixture

The fixture under `examples/interop/oap-to-vate/` uses:

- `oap-decision.example.json` as adjacent evidence
- `vate-admission-request-from-oap.example.json` as the VATE request
- `vate-admission-receipt-from-oap.example.json` as the verifier decision

The corresponding conformance case is:

- `conformance/al2-vate-v0.2/cases/interop-oap-decision-evidence.json`

## Non-Goals

This crosswalk does not define OAP / APort semantics.
It does not require OAP / APort implementations to emit VATE receipts.
It only demonstrates how a VATE verifier can consume an adjacent decision object as evidence.
