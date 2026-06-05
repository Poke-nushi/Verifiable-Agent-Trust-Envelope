# VATE Attenuation Semantics

## Status

This note fixes the machine-readable attenuation surface for the `VATE AL2 Admission Interop Profile 2026-07`.

Attenuation is an admission decision.
It is not a human note such as "restricted".

## Short Walk-Through

Requested action:

```text
transfer USD 10000 from account A to account B
```

Verifier decision:

```text
attenuate
```

Effective constraints:

```text
max_amount: { currency: USD, value: 500.00 }
approval: { mode: human_required, policy_ref: policy:example:manual-review }
expires_at: 2026-05-09T00:10:00Z
```

The admission receipt records the original request hash, the effective request
hash, evidence references, policy snapshot digest, and reason codes. The
post-execution receipt must link back to the effective request hash, not merely
the broader original request.

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
- `reason_visibility` when the concrete basis is opaque or withheld
- `source_evidence_ref` when the narrowing came from a specific evidence item

The `reason_code` remains machine-readable even when the verifier cannot safely
disclose the full basis for a change. Regulated or sensitive verifier profiles
may emit a generic code such as `REASON_BASIS_WITHHELD` and mark
`reason_visibility` as `opaque` or `withheld`, while keeping the detailed basis
in verifier-controlled audit material, policy evidence, or protected logs.
Portable receipts should not force sanctions, abuse, fraud, or other sensitive
screening details into signed bytes when the applicable profile forbids
disclosure.

## Interpretation

`original_request_hash` identifies the requested authority before narrowing.

`effective_request_hash` identifies the authority the verifier admitted after narrowing.

For the current AL2 v0.3 corpus, both fields use the profile hash string grammar:
`sha-256:` followed by a lowercase 64-character hexadecimal digest.
The hash input is the profile-canonicalized request object after any accepted
input aliases have been normalized. Raw legacy input, if retained, belongs in a
separate evidence artifact or annotation and must not replace the profile hash
basis.

The post-execution receipt MUST link to the admitted effective request hash.
If post-execution evidence references the original request hash or a different
effective request hash, the verifier or auditor SHOULD return
`POST_EXEC_EFFECTIVE_REQUEST_HASH_MISMATCH`.

## Canonical Effective Constraints

The emitted AL2 admission receipt uses canonical effective constraint names.
Adjacent protocols, status inputs, or legacy candidate objects may use different
field names before admission evaluation, but a verifier must normalize any
accepted aliases before emitting an admission receipt.

The current canonical fields are:

| Field | Shape | Meaning |
| --- | --- | --- |
| `max_amount` | object with `currency` and `value` | Aggregate monetary cap for the admitted execution. |
| `tool_allowlist` | array of non-empty strings | Tools that remain allowed after narrowing. |
| `target_resource` | non-empty string | Target resource admitted after narrowing. |
| `approval` | object with `mode` and optional `policy_ref` | Approval constraint or escalation requirement. |
| `expires_at` | RFC3339 timestamp | Constraint-specific expiry that must not broaden the top-level admission window. |

`max_amount.currency` is a three-letter uppercase currency code. Emitted
examples should use a decimal string for `max_amount.value`, such as `"25.00"`,
to avoid JSON number rounding ambiguity. A verifier may accept a numeric input
amount before normalization, but the emitted receipt should preserve a stable
decimal representation.

`effective_constraints.max_amount` is an aggregate amount admitted for the
execution. Multiple side effects are summed; each side effect does not get a
fresh `max_amount` allowance. Future per-side-effect limits should use a
distinct field such as `max_amount_per_side_effect`.

`resource`, `max_amount_usd`, and string-valued `approval` are not canonical
emitted AL2 `effective_constraints` fields. If an implementation accepts them as
legacy or status-input aliases, it must normalize them before receipt emission:

```json
{
  "max_amount_usd": 25,
  "resource": "bucket:public/reports/*",
  "approval": "fresh_permit_required"
}
```

becomes:

```json
{
  "max_amount": {
    "currency": "USD",
    "value": "25.00"
  },
  "target_resource": "bucket:public/reports/*",
  "approval": {
    "mode": "fresh_permit_required"
  }
}
```

`changes[].path` may still point at the source request path that was narrowed,
such as `/target/resource` or `/constraints/max_amount/value`. That path records
where the verifier found the requested authority. It does not change the
canonical field names used in emitted `effective_constraints`.

## Common Modes

- `narrow` - the verifier reduced amount, scope, target, tool set, or time window
- `require_new_permit` - execution may not proceed until a fresh or narrower permit is issued
- `deny_if_not_accepted` - the verifier can proceed only if the runtime accepts the effective constraints

When `require_new_permit` is `true`, an AL2 conformance case should report
`should_execute: false` even if the admission decision remains `attenuate`.
The decision records that the verifier found a possible narrower path; the
execution gate remains closed until a fresh permit is presented.

`approval.mode` describes the approval constraint that remains in the admitted
authority. `attenuation.require_new_permit` is the execution gate used by the
AL2 corpus. If an approval mode is intended to block execution until a fresh
permit is presented, the emitted receipt must set `require_new_permit: true`.

## Conformance Expectations

The runnable conformance corpus checks that an attenuated receipt includes:

- both request hashes
- at least one machine-readable change
- effective constraints
- an explicit `require_new_permit` boolean
- change paths inside the AL2 attenuation boundary: request constraints, target,
  runtime, tools, or approval state
- a canonical money object with a finite, non-negative amount value when
  `effective_constraints.max_amount` is present

Candidate attenuation objects that attempt to mutate verifier policy state or
emit legacy aliases, string-valued approval constraints, malformed money
objects, or non-finite / negative amount values must fail closed.

Conformance does not require a global policy language.
The verifier only needs to produce comparable admission and receipt semantics for the fixture.
