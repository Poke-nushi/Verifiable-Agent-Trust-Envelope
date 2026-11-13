# Request binding v1

This draft extension contract binds an admission receipt to the original request
body, the effective request body, and the admission wrapper. The Python implementation
uses only the standard library. Existing v0.3 receipts and their hash
interpretations remain unchanged.

## Objects and identifiers

| Object | Contract |
| --- | --- |
| Original and effective operation, O0 and O1 | `vate-purchase-cap-request-v1` |
| Receipt extension, R.request_binding | `vate-request-binding-v1` |
| Transformation | `vate-max-amount-only-v1` |
| Receiver assessment | `vate-request-binding-assessment-v1` |
| Canonical JSON identifier | `vate-v0.3-fixture-json` |

O0 and O1 MUST conform to `schemas/operation.schema.json`. They contain action,
operation ID, target, purchase payload, maximum amount and a tool allowlist.
Unknown operation members and execution constraints MUST be rejected. The
operation MUST NOT contain its own hash. `operation_id` equals the admission
wrapper's `transaction_id`.

The admission wrapper A retains the v0.3 admission-request fields. This entry
requires exactly version, profile, request_id, transaction_id, issued_at,
expires_at, action, target, actor, principal, runtime, audience, input_hash,
constraints and evidence_refs. Other admission extensions require another
supported binding profile; they are not silently dropped. This restriction
does not remove extension points from the base schema. The default Python
admission entry rejects unsupported operation profiles and extensions.

The receipt extension MUST conform to `schemas/binding.schema.json`.
It references the exact bytes of A, O0, and (for allow/attenuate) O1.
References use `urn:sha256:<lowercase hex>`, `application/json`, and a SHA-256
descriptor. The URI suffix MUST equal the descriptor value. The checker
resolves only the caller's byte map and MUST NOT fetch URLs.

## Bytes and hashes

The existing sorted, compact, ASCII-escaped JSON basis is retained:

```python
json.dumps(value, allow_nan=False, ensure_ascii=True,
           sort_keys=True, separators=(",", ":")).encode("utf-8")
```

This is not RFC 8785/JCS. Each supplied JSON artifact MUST be UTF-8, at most
2 MiB, and have at most 64 levels (root level zero; keys count as children).
Duplicate keys, floating-point tokens, non-finite numbers, unpaired Unicode
surrogates and integers outside ±9007199254740991 MUST be rejected. Money
values MUST be decimal strings with 1–18 integer digits and at most 8
fractional digits, no sign/exponent, and no leading integer zeros except zero.
Fractional trailing zeros are preserved; the checker MUST NOT try alternate
normalizations to obtain a matching hash.

JSON diagnostics follow token order in both receivers. Size and UTF-8 checks
precede parsing; depth is checked before each value. Strings and number tokens
are validated when read, duplicate keys after their values, and trailing input
after the root value. The 64-level and safe-integer bounds apply before platform
parser limits, including when an input contains multiple violations.

| Field | Hash basis |
| --- | --- |
| A.input_hash and R.request.input_hash | Canonical O0 |
| R.attenuation.original_request_hash | Canonical O0 |
| R.attenuation.effective_request_hash | Canonical O1 |
| R.request.action_binding.digest | Canonical O1 |
| Each request_binding artifact reference | Exact supplied file bytes |
| Post receipt admission.digest | Canonical complete admission receipt R, as in v0.3 |
| Assessment receipt_digest | Exact supplied receipt bytes |

Whitespace or key order can change an artifact reference without changing
the canonical operation hash. Both relationships MUST be checked.

## Context and transformation checks

The receiver MUST supply its required binding contract and the reference to
the admission request it selected. The implementation defaults to requiring
`vate-request-binding-v1`; an unknown requirement cannot be satisfied. The
expected admission reference MUST match R.request_binding.admission_request_ref.
Choosing that reference from an untrusted bundle proves only consistency with
that bundle; it does not establish the receiver's intended transaction.

A.input_hash MUST equal H(O0). A.action, target, transaction_id and constraints
MUST equal O0.action, target, operation_id and constraints. A.audience MUST
equal O0.target.audience. R.request MUST preserve A's original request_id,
transaction_id, action, input_hash and constraints. R.subject MUST match A's
principal, actor and runtime. An `allow` or `attenuate` receipt's validity window
MUST lie inside A's window, including a `require_new_permit` candidate.
A and R MUST have ordered, supported RFC3339 timestamps.
An evidence reference MAY omit `protocol_hint`. If present, it MUST be a string
allowed for its evidence type by the evidence vocabulary; explicit null is invalid.
A denial may record a judgment after the request expired; it remains
non-executable.

### Evidence reference correspondence

A.evidence_refs MUST have distinct (`type`, `uri`) pairs. R.evidence MUST
contain exactly one entry for each of those pairs, with the same `digest` and
the same presence and value of `protocol_hint`. The order MAY differ. A missing,
additional, duplicate or substituted entry MUST fail `receipt.evidence_references`.
The base receipt does not require `media_type` on an evidence entry; when present,
it MUST equal the admission reference's value. Other annotation fields remain
available and do not establish evidence verification.

This correspondence attaches the receipt's evidence references to the admission
request selected by the receiver, including that request's transaction and
subjects. It does not inspect the referenced evidence payload or authenticate
its issuer. The receiver MUST retain `evidence.authentication` as `not_checked`,
even when a receipt asserts `verification.result: verified`.

### Effective operation

For `allow`, O1 MUST equal O0 and attenuation MUST be absent.

For `attenuate`, exactly one change is supported:

```text
replace /constraints/max_amount/value
```

`from` MUST equal O0's value with the same JSON type and text. `to` MUST use
the supported decimal-string form and satisfy `0 <= to < from`. Applying
that replacement to O0 MUST reproduce all of O1. Currency, payload, target,
operation ID, tool allowlist and every other member MUST remain unchanged.
The reason code MUST be `LOCAL_POLICY_MAX_AMOUNT_NARROWED` and appear in
R.decision.reason_codes. Effective constraints MUST exactly equal O1.constraints.
All operation hashes and action_binding MUST match the recomputed objects.
`action_binding` uses `profile_defined_digest`, the preimage profile and the
canonicalization identifier above.

For `allow` and `attenuate`, including `require_new_permit` candidates,
the payload's currency MUST equal the cap's
currency, its amount MUST be within the cap, and its tool MUST appear in the
allowlist, for both O0 and O1. The amount is a specific purchase; reducing
the permitted maximum does not reduce the purchase itself.

Only attenuation modes `narrow` and `require_new_permit` are supported.
`require_new_permit` MUST be boolean, and the latter mode requires true.
A true value prevents immediate execution even when every binding check passes.
An unsupported mode, operation, path or multiple changes MUST fail this
binding assessment. A `deny` receipt MUST omit effective_ref, action_binding
and attenuation; an original/request relationship can still be checked.

## Generation and receiver assessment

The default Python `VateVerifier.admit` requires raw admission bytes and the
keyword-only `original` operation bytes. It delegates to `admit_bound`, which
first checks the supplied preimages, then invokes `_evaluate_policy` exactly
once. The private primitive is not a supported admission endpoint. Missing
arguments MUST raise `TypeError`; invalid or unsupported content MUST raise
`Invalid` (a `ValueError`) without returning an admission. The result retains
the raw policy result separately and constructs the bound receipt.
If generation, serialization or the generated binding check raises, a replay ID
newly consumed by this call MUST NOT remain consumed. Previously recorded IDs
MUST remain intact. A successfully returned admission keeps the policy
evaluator's replay-state changes, including for a denial or new-permit result.
Calls sharing one verifier instance serialize replay-state consumption through
completion of bound issuance. This in-memory rule does not provide durable or
cross-process replay storage, or synchronize changes to verifier configuration.

A purchase that cannot satisfy the resulting
constraints receives `POLICY_DENIED`. A request for a new permit without a
narrowing also receives a denial. The supported policy fields are policy_id,
policy_version, policy_ref, allowed_actions and max_amount; provided values
must be well formed. Unknown policy evaluators MUST be rejected.

Without a configured runtime verifier, this entry evaluates exactly one
`local_policy` evidence reference.
Its `uri` MUST equal the verifier-selected policy's `policy_ref` (or `local`
when absent), its `media_type` MUST be `application/json`, and its digest MUST
equal SHA-256 of that policy under the canonical JSON basis above. The policy
comes from the verifier configuration; the request MUST NOT select or replace
it. Missing, inconsistent, duplicate or unsupported evidence MUST be rejected
before policy evaluation and replay-state consumption. Other evidence types
require an adapter that implements their verification contract.

The optional [runtime evidence integration](RUNTIME-EVIDENCE.md) requires one
`runtime_attestation` alongside that local-policy reference. The verifier is
selected by application configuration, and its authenticated result MUST match
the exact evidence bytes, request context, runtime, audience and evaluation
time. Configuring it makes runtime evidence mandatory; omission MUST NOT
fall back to the local-policy-only path. This does not change the receiver
assessment's `evidence.authentication: not_checked` result.

The final receipt records this content check as `verification.result: verified`
with `method: vate-local-policy-content-v1`, including when the policy or payload
evaluation denies the action. This result states that the requested local policy
is the configured policy; it does not authenticate the principal, actor or
runtime. The private policy primitive and its `core_result` remain intermediate
fixture results, not evidence-verification or execution authorization APIs.

Every generated result is checked with `assess_request_binding`. The returned
assessment is separate from the receipt and MUST conform to
`schemas/assessment.schema.json`. It records the checks actually reached;
evaluation stops at the first failure or missing prerequisite. It never
rewrites the submitted receipt's decision or reason codes.

The Python API requires receipt bytes, an artifact mapping and a nonempty
required-contract string. Invalid receipt-byte or artifact-container argument
types, or an invalid/empty required-contract string, raise `Invalid` before
assessment. Invalid JSON content and malformed receiver references are reported
as failed checks; a missing receiver reference leaves the check not_checked.

| Condition | Assessment status / pass | Binding requirement |
| --- | --- | --- |
| All applicable binding checks completed | checked / true | met |
| Supplied bytes or relationships are invalid | checked / false | unmet |
| Required original, receiver pin or declaration missing | not_checked / null | unmet |
| Declared contract, preimage or byte profile unsupported | not_checked / null | unmet |

Deleting a declaration MUST NOT turn a required binding check into a pass.
The report always marks `evidence.authentication` and `execution.actual_input`
as not_checked: it performs neither issuer authentication nor dispatch
observation. `decision_allows_immediate_execution` reports only the
bound receipt's decision/new-permit condition, and is false on failed or
incomplete assessments. It is not an execution authorization.

This checker verifies content relationships and a bounded transformation. It
does not re-evaluate authority, authenticate the issuer or evidence, verify
signatures, prove freshness at dispatch, or observe payment/execution.
Validate the complete receipt separately against the
[admission receipt schema](../../schemas/admission-receipt.schema.json) using
JSON Schema Draft 2020-12 with date-time format checking enabled. A successful
binding assessment does not invoke that validator. The local example also
reproduces generation and checks v0.3 post linkage; its post receipt is synthetic.

## Compatibility and conformance

The default core admission API requires preimages and returns `BoundAdmission`;
the old dictionary-only call MUST NOT issue a receipt. Profile-specific file-set
and S3 adapters retain their own preimage contracts. Base receipt schemas,
artifact families, digest basis, the 76-case corpus, historical captures and
fixed packages retain their original meaning.
`conformance/request-binding-v1` is a separate corpus with an explicit
case requirement. A passing legacy run/compare/verify-bundle does not perform
this new preimage assessment.

New `run` and `compare` conformance reports MUST include
`request_binding_required` for every case and
`request_binding_coverage` for the report. The coverage counts required,
satisfied and not-required cases separately. `all_cases_satisfied` is true only
for a nonempty set in which every case required and satisfied binding. It does
not imply execution authorization. Saved coverage MUST agree with the case
requirements and recomputed assessments during bundle verification. Historical
reports without these fields establish no request-binding coverage.

For required cases, `run` MUST assess the fixture receipt using the case's raw
admission request as the receiver pin. In both `compare` modes, each SUT result
MUST supply `request_binding_artifacts`, a digest-addressed local reference to
an `application/json` manifest conforming to `schemas/artifact-manifest.schema.json`.
The manifest contains 1–16 unique artifact URIs; each digest and URI suffix MUST
match the exact local bytes. Member paths MUST be basenames beside the manifest,
and symbolic links and non-regular files MUST be rejected. No URI is fetched.
The 2 MiB JSON bound applies to the manifest and each member.
For SUT-supplied manifests and binding-required admission receipts, symbolic
links in path components below the SUT result directory MUST also be rejected.
The generated admission loader MUST apply the binding JSON limits before
performing the ordinary receipt comparison.

Fixture mode assesses the corpus receipt with the supplied preimages. Generated
mode assesses the submitted receipt with those preimages. Both modes MUST use
the admission request selected by the corpus case as the receiver pin; a SUT
cannot replace that pin with its own admission request. A required binding
that is invalid or not_checked MUST fail the case. An unsupported requirement
MUST NOT be silently ignored. The result stores a separate `request_binding`
assessment and failure list; `actual_should_execute` retains its receipt-decision
meaning and MUST NOT be used alone as evidence of successful binding.

When generated admission and post-execution receipts are both required, the
runner MUST check their ID, decision and digest relationship against the corpus
pair, regardless of case category. The post's admission URI MUST equal the
generated admission artifact's URI. Declared linkage checks MUST also run for
positive admission cases; linkage-category outcomes retain their own comparison.

`verify-bundle` MUST recompute required bindings, require successful assessments,
and compare them to the saved report. Deleting report coverage or renewing outer
report digests MUST NOT satisfy a missing or invalid binding.
Saved assessments MUST satisfy their schema's field types and status conditions.
Comparison with a recomputed assessment MUST distinguish booleans from numbers.

TypeScript `assessRequestBinding` implements the same receiver checks using raw
byte inputs and a native `Map`. It preserves six fractional timestamp digits
and compares decimal amounts without binary floating-point rounding. The raw
integer token `-0` is interpreted as zero, as in Python. Invalid receipt-byte,
artifact-container or options argument types, or an invalid/empty required
contract, raise `RequestBindingError`. A malformed receiver reference is an
assessment failure; a missing reference leaves the check not_checked. It does not
port the Python admission policy engine or provide a TypeScript runner CLI.

The added A/O/R relationships address part of the known context-binding gap.
They do not complete general AL2 evidence/context binding. New-permit lineage,
general transformation profiles, production JOSE/PKI and actual execution
gates remain separate contracts.
