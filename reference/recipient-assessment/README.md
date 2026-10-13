# Recipient Assessment API

Call VATE's receipt-pair and S3 observation assessments from another application.
This local Python API and JSON CLI preserve each evaluator's complete result
and identify the API contract, wrapper sources and native evaluator sources.

Choose `receipt_pair` to inspect two stored VATE receipts. Choose
`s3_observation` to connect receipts to the request, attempt and version-specific
read-back in a captured S3 bundle. The latter retains the local SeaweedFS
contract and its receiver-selected trust policy.

## Requirements and CLI

Use a trusted checkout or source archive of this repository, Python 3.10 or
later, and the existing `jsonschema==4.26.0` dependency in
[`requirements-dev.txt`](../../requirements-dev.txt). Keep the source tree
together. S3 assessment requires Linux or macOS. Evaluation is offline; no
storage service or credentials are needed.
If the environment is not yet set up, follow the existing
[Python environment setup](../receipt-linkage-example/README.md#run-the-examples).
Install the dependency in the environment of the Python interpreter running the
API. Its isolated worker ignores `PYTHONPATH` and user-site packages.

For S3 timestamps with 1–6 fractional-second digits, use Python 3.11 or later.
The fixed S3 evaluator on Python 3.10 accepts whole seconds or exactly 3 or 6
fractional digits; other lengths can leave the observation assessment
`insufficient`. Receipt-pair assessment accepts 1–6 fractional digits on all
supported Python versions. Keep received receipt bytes unchanged when selecting
a compatible interpreter.

From the repository root, inspect the receipt pair included in R17:

```bash
.venv/bin/python -B reference/recipient-assessment/vate_recipient.py \
  --api-contract vate-recipient-assessment-api-v1 receipts \
  --admission reference/receipt-linkage-example/inputs/R17/admission.json \
  --post reference/receipt-linkage-example/inputs/R17/post.json
```

Omit a receipt argument when that original is unavailable. For a captured S3
operation, supply the bundle and a receiver-selected policy file outside it:

```bash
.venv/bin/python -B reference/recipient-assessment/vate_recipient.py \
  --api-contract vate-recipient-assessment-api-v1 s3 \
  --bundle reference/s3-observation-example/inputs/seaweedfs-4.48/instance/bundles/supported \
  --receiver-policy reference/s3-observation-example/inputs/seaweedfs-4.48/instance/receiver-policy.json
```

The included policy explicitly accepts the example's unsigned local collector.
Select policy through the receiving application; consistent bundle hashes alone
do not establish that trust. The API's detailed input conditions and error codes
are in [CONTRACT.md](CONTRACT.md).

## Call from Python

Point the import path at this directory in the trusted source tree. The API
resolves its native evaluators internally; the caller does not import the
reference runner or the S3 example's `contract` module.

```python
from pathlib import Path
import sys

root = Path("/path/to/VATE")
sys.path.insert(0, str(root / "reference/recipient-assessment"))
from vate_recipient import AssessmentError, RecipientAssessor

assessor = RecipientAssessor(
    expected_api_contract="vate-recipient-assessment-api-v1",
)
pair = root / "reference/receipt-linkage-example/inputs/R17"
try:
    report = assessor.assess_receipts(
        (pair / "admission.json").read_bytes(),
        (pair / "post.json").read_bytes(),
        requested_checks=("receipt_linkage",),
    )
except AssessmentError as error:
    print(error.as_dict())
else:
    print(report["native_result"])
```

Use `assess_s3(bundle_path, receiver_policy_bytes)` for S3 assessment. Both
methods accept `requested_checks` to report whether the evaluator supports the
caller's requested capabilities. This does not select or skip native checks;
an empty list still runs the complete native assessment. A recognized but unsupported requirement,
such as `signatures_and_issuer_authority`, remains in
`requested_checks.unsupported` even if the native result is favorable. Unknown
check names raise `AssessmentError`; inspect `capabilities()` for the finite
inventory. A supported capability describes what the evaluator can check, not
whether the supplied evidence passed that check.

Each call uses an isolated Python process with the same interpreter and installed
dependencies. Calls do not alter the caller's module search path or replace its
modules. The process boundary isolates imports; it is not an operating-system
sandbox for untrusted code.

## Read the result

The envelope's `invocation.status: returned` means the native assessor returned
a result. Read `requested_checks.unsupported` and the selected evaluator's
`native_result` before using that result:

| Evaluator | Native result | Meaning |
| --- | --- | --- |
| Receipt pair | `record_linkage: matched` | Implemented relationships between the receipts match. A reported failed operation can also match its admission. |
| Receipt pair | `mismatch` / `not_assessed` | A checked relationship disagrees, or comparison could not be completed. |
| S3 observation | `assessment: supported_under_local_assumptions` | The captured request, attempt, receipts and version-specific observation agree under the selected local trust assumptions. |
| S3 observation | `contradictory` / `insufficient` / `unsupported` | The native result retains the distinction between conflicting records, missing or invalid evidence, and unsupported semantics. |

The envelope adds no combined pass value. Receipt `linkage_checks_run` and
`not_checked`, S3 diagnostics, ordered reason codes and `retry_authorized: false`
remain in their original results. See the existing
[receipt interpretation](../receipt-linkage-example/README.md#interpret-the-result)
and [S3 contract](../s3-observation-example/CONTRACT.md#outputs-and-precedence).
These reference assessments do not authenticate signatures or issuers, prove
complete independent execution evidence, or grant permission to execute.

## Reproduce and update

Run the original-input vectors and the API tests:

```bash
.venv/bin/python -B reference/recipient-assessment/run_vectors.py
.venv/bin/python -B -m unittest discover \
  -s reference/recipient-assessment -p 'test_*.py' -v
```

The [vector index](vectors.json) points to stored originals and semantic
expectations so another language can consume the inputs without reproducing
Python's import setup. It is an implementation aid alongside the existing
examples, not another normative conformance corpus.

Pin the API contract your application understands and retain the returned
wrapper and evaluator identities with its result. API compatibility and exact
source identity are separate. A wrapper-only update can retain the native
evaluator and result. Native source changes detected by the checks before or
after evaluation are rejected. Keep previous results when evaluating an update,
and rerun the vectors and your application's controls.
[Compatibility rules](CONTRACT.md#compatibility-and-source-identity) describe
source identification, its limits and historical capture provenance.
