# Migrate to request-binding v1

The Python reference verifier now requires the original request bytes before
issuing a purchase-cap admission receipt. The receiver checks those bytes
against the admission context, receipt hashes and permitted cap reduction.
This changes the public `VateVerifier.admit` call and adds binding coverage to
conformance reports.

## Python callers

Replace the dictionary-only `verifier.admit(request)` call with raw UTF-8 JSON
bytes for both the admission request and the original purchase operation:

```python
from pathlib import Path
import json

result = verifier.admit(
    Path("admission-request.json").read_bytes(),
    original=Path("original.json").read_bytes(),
)
receipt = json.loads(result.receipt)
assessment = json.loads(result.assessment)
```

The [complete example](example.py) shows verifier configuration and both input
objects. `now` may be supplied as a timezone-aware datetime; otherwise the
verifier uses the current UTC time.

The returned `BoundAdmission` contains immutable receipt, request, original,
effective-operation and assessment bytes. A denial has no effective operation.
Read the final decision from `receipt`; `core_result` is an intermediate policy
result. A valid binding assessment alone does not authorize execution: a denial
or a candidate requiring a new permit remains non-executable.

Missing `original` raises `TypeError`. Unsupported or invalid input raises
`ValueError` before an admission is returned. The supported operation is
`vate-purchase-cap-request-v1`. Its default generator requires exactly one
`local_policy` evidence reference matching the configured policy's digest, URI
and `application/json` media type. Other operations or evidence types require
their own validated adapter. `_evaluate_policy` is a private primitive and
must not be exposed as an admission endpoint.

## Receipt receivers

Preserve and supply the raw admission request, original operation and, for an
executable or candidate receipt, effective operation. Select the expected
admission reference independently of the submitted receipt or artifact bundle.
The [Python contract](CONTRACT.md) and
[TypeScript example](../../packages/vate-core-ts/README.md#check-request-binding)
describe the receiver inputs and assessment fields.

Retain full [admission receipt schema](../../schemas/admission-receipt.schema.json)
validation alongside the binding assessment, using JSON Schema Draft 2020-12
with date-time format checking enabled. The binding assessor checks only the
fields required by its contract.

For this contract, `request.input_hash` and
`attenuation.original_request_hash` both identify the original operation.
`attenuation.effective_request_hash` identifies the effective operation. The
checker recomputes these hashes from the supplied objects and verifies the exact
cap transformation. It also requires the receipt's evidence references to
correspond to the selected admission request.

Keep binding satisfaction separate from evidence authentication and actual
execution: those latter checks remain `not_checked` in this assessment.

## Conformance integrations

New `run` and `compare` reports contain `request_binding_coverage` and each
case's `request_binding_required` value. For cases that require binding, submit
`request_binding_artifacts` with the local manifest and preimages described in
the [SUT adapter contract](../../docs/conformance/sut-adapter-contract.md).
`verify-bundle` recomputes binding and checks the saved assessment.

Use `conformance/request-binding-v1` for the four purchase-cap cases. The
historical 76-case corpus has zero required binding cases; its passing result
alone does not establish this coverage. Follow the
[ordinary runner commands](README.md#use-the-ordinary-runner) to generate and
check reports for the new corpus.

AL2 verification-context records must also agree with the selected admission,
receipt, runtime, timestamps, evidence results and normalized authority basis
where the case requires them. The runner checks this correspondence; it does
not authenticate the context's claimed observations.

Archived captures retain their original profile and source pins. See
[entry-point coverage](ENTRYPOINTS.md) for each adapter and reader's checks.
These changes remain reference implementation and corpus review aids; VATE is
not production-ready.
