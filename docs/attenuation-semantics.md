# VATE Attenuation Semantics

## Status

This note fixes the machine-readable attenuation surface for the `VATE AL2 Admission Interop Profile 2026-07`.

Attenuation is an admission decision.
It is not a human note such as "restricted".

## Required Shape

When an admission decision is `attenuate`, the admission receipt MUST include an `attenuation` object with:

- `mode`
- `original_request_hash`
- `effective_request_hash`
- `changes`
- `effective_constraints`
- `require_new_permit`

The `changes` array MUST identify what the verifier narrowed.

Each change SHOULD include:

- `op`
- `path`
- `from`
- `to`
- `reason_code`
- `source_evidence_ref` when the narrowing came from a specific evidence item

## Interpretation

`original_request_hash` identifies the requested authority before narrowing.

`effective_request_hash` identifies the authority the verifier admitted after narrowing.

The post-execution receipt MUST link to the admitted effective request hash.
If post-execution evidence references the original request hash or a different effective request hash, the verifier or auditor SHOULD return `POST_EXEC_LINKAGE_MISMATCH`.

## Common Modes

- `narrow` - the verifier reduced amount, scope, target, tool set, or time window
- `require_new_permit` - execution may not proceed until a fresh or narrower permit is issued
- `deny_if_not_accepted` - the verifier can proceed only if the runtime accepts the effective constraints

When `require_new_permit` is `true`, an AL2 conformance case should report
`should_execute: false` even if the admission decision remains `attenuate`.
The decision records that the verifier found a possible narrower path; the
execution gate remains closed until a fresh permit is presented.

## Conformance Expectations

The runnable conformance corpus checks that an attenuated receipt includes:

- both request hashes
- at least one machine-readable change
- effective constraints
- an explicit `require_new_permit` boolean
- change paths inside the AL2 attenuation boundary: request constraints, target,
  runtime, tools, or approval state
- scalar, finite, non-negative amount limits when `effective_constraints.max_amount`
  is present

Candidate attenuation objects that attempt to mutate verifier policy state or
encode amount limits as non-scalar objects must fail closed.

Conformance does not require a global policy language.
The verifier only needs to produce comparable admission and receipt semantics for the fixture.
