# Verify original and attenuated request bodies

Generate a VATE admission receipt and independently check its original request,
effective request and admission context. The purchase example narrows a maximum
from USD 120.00 to USD 25.00 while preserving the USD 24.50 purchase payload.
Both input_hash and original_request_hash identify the original operation;
effective_request_hash identifies the operation with the reduced cap.

The receiver also checks that the receipt preserves the selected admission's
evidence references. Missing, additional, duplicate or substituted references
fail the assessment. Evidence authentication remains a separate `not_checked`
result. The default generator accepts one `local_policy` reference whose digest
and URI match the verifier's configured policy; it rejects unsupported evidence
types before evaluating policy or consuming replay state.

The [contract](CONTRACT.md) defines the supported operation, transformation,
byte representation and receiver checks. [The bundled example](examples/purchase-cap/)
includes every request preimage, the original core result, the bound receipt,
a receiver assessment, a synthetic post receipt and file/source digests.

From the repository root, on macOS or Linux with Python 3.10 or later:

```bash
python3 reference/request-binding/example.py check \
  --bundle reference/request-binding/examples/purchase-cap \
  --expected-admission-request reference/request-binding/examples/purchase-cap/admission-request.json
```

This verifies file/source digests, recomputes binding, reproduces generation,
and checks the synthetic post receipt's linkage. In an integration, supply the
admission request selected by the receiver, independently of the submitted
receipt. Here the expected request comes from the example itself.

Generate a separate bundle in a new directory:

```bash
python3 reference/request-binding/example.py generate --output /tmp/vate-purchase-binding
```

```bash
python3 -m unittest discover -s reference/request-binding -p 'test_*.py'
```

For Python integrations, `verifier.admit(admission_bytes, original=original_bytes,
now=now)` requires both preimages. Missing, unsupported or mismatched originals
raise an error without issuing an admission. It returns a `BoundAdmission`
containing receipt, preimage and assessment bytes;
[example.py](example.py) shows the generation and receiver calls.
`assess_request_binding` accepts receipt bytes, a
local artifact map, the required contract and the receiver's expected admission
reference. Missing or unsupported binding is `not_checked`, with an unmet
requirement. Invalid supplied content fails. A valid binding on a denial or a
new-permit candidate does not permit immediate execution.

This is an unsigned, synthetic reference example: no purchase is dispatched.
The checker establishes content relationships, not issuer authority or actual
execution. It is not production-ready.

## Use the ordinary runner

The separate `conformance/request-binding-v1` corpus covers allow, attenuation,
a new-permit candidate and denial of a purchase above the effective cap. Each
case requires the binding contract and pins its admission request. `run`
checks the fixture receipt and raw preimages:

```bash
python3 scripts/vate_conformance.py run \
  --corpus-root conformance/request-binding-v1 \
  --report /tmp/vate-binding-run.json
```

`compare` checks the selected receipt against preimages supplied by the SUT.
Use `sut-results-fixtures.json` to exercise fixture-validation mode or
`sut-results-generated.json` to exercise submitted-receipt mode:

```bash
python3 scripts/vate_conformance.py compare \
  --corpus-root conformance/request-binding-v1 \
  --sut-results examples/conformance/request-binding/sut-results-generated.json \
  --report /tmp/vate-binding-compare.json \
  --implementation-report /tmp/vate-binding-implementation.json
```

The samples use the same reference-generated receipts as the corpus. They
demonstrate report exchange; they are not an independent implementation run.
For each result, `request_binding_artifacts` references a local
[artifact manifest](schemas/artifact-manifest.schema.json). The manifest binds
raw admission/original/effective files by SHA-256. Its member paths are
basenames beside the manifest, with no URL fetching or symbolic-link reads.
The runner also rejects links in the supplied manifest and admission receipt
paths. When a case requires both receipts, it checks the post receipt's
admission reference and the declared linkage conditions.

```bash
python3 scripts/vate_conformance.py verify-bundle \
  --corpus-root conformance/request-binding-v1 \
  --sut-results examples/conformance/request-binding/sut-results-generated.json \
  --conformance-report /tmp/vate-binding-compare.json \
  --implementation-report /tmp/vate-binding-implementation.json \
  --report /tmp/vate-binding-bundle.json
```

`verify-bundle` recomputes required binding from the supplied bytes and compares
the result with the saved assessment, including JSON field types. Updating report digests alone cannot
turn an invalid binding into a successful bundle. A missing declaration,
preimage, supported profile or receiver pin leaves the requirement unmet and
the case fails. The report preserves the receipt's decision separately from
the overall case result; `actual_should_execute` alone is not a binding pass.

Every new `run` or `compare` conformance report includes
`request_binding_coverage`. The original 76-case
corpus reports zero required and satisfied binding cases; the purchase-cap
corpus reports four when its checks pass. `request_binding_required` identifies
the requirement for each case. Corpus pass and binding coverage are separate.
See [entry-point coverage](ENTRYPOINTS.md) for other adapters and limited readers.
Regenerate the separate corpus and SUT samples after intentional fixture changes:

```bash
python3 reference/request-binding/generate_corpus.py
```

## TypeScript receiver

[`@vate/reference-core`](../../packages/vate-core-ts/README.md#check-request-binding)
exports `assessRequestBinding`, `requestBindingReference` and
`requestBindingObjectHash`. Supply raw `Uint8Array` receipt/preimage bytes in a
native `Map`, and an admission reference selected independently by the receiver.
The assessment has the same fields, check order and failure causes as Python
for the supported contract. This package provides the receiver check; Python
`VateVerifier.admit` is the generation entry; `admit_bound` is its composing helper.
Both raw JSON readers apply the same token order and depth/integer limits,
including inputs with multiple validation failures.

```bash
npm run ts:check
```

```bash
npm run ts:test
```

The parity suite runs the Python checker on valid and mutated raw inputs and
compares complete TypeScript assessments, including missing checks, exact
decimal comparisons, timestamp microseconds and strict JSON parsing.
