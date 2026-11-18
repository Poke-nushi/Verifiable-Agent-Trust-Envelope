# Receipt-pair linkage API

`VateVerifier.validate_post_execution_linkage(admission_receipt, post_execution_receipt)`
checks the declared relationship between two parsed receipt objects. Applications
may call it directly; its linkage input checks do not require an adapter to have
run first. It returns a result without modifying either input.

This is the calling contract of the Python reference core. A successful result
covers the linkage fields and observations below. It does not establish full
receipt-schema validity, authenticated issuers or signatures, request-preimage
binding, complete execution evidence, or current permission to execute.
For receipt ingestion from original bytes with schema and semantic diagnostics,
use the [Recipient Assessment API](../recipient-assessment/README.md).

## Call the API

From the repository root, this example checks the committed unsigned pair:

```python
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path("reference/vate-verifier-core").resolve()))
from vate_verifier_core import VateVerifier

folder = Path("reference/request-binding/examples/purchase-cap")
admission = json.loads((folder / "admission-receipt.json").read_text())
post = json.loads((folder / "post-execution.json").read_text())
verifier = VateVerifier(verifier_id="urn:example:receipt-reader")
result = verifier.validate_post_execution_linkage(admission, post)
print(result)
```

The inputs MUST be built-in Python `dict` objects containing JSON values:
string-keyed dictionaries, lists, strings, integers, finite floats, booleans and
`None`. Cycles, non-string keys, non-finite floats, custom objects and non-JSON
containers are rejected. Repeated references to a shared, acyclic container
are permitted. Python objects with custom serialization or mapping behavior
are not supported.

Keep the supplied objects stable until the call returns. This object API cannot
recover duplicate keys or numeric precision already lost during JSON parsing.
The application controls input byte size and processing budgets; these checks
are not a general CPU or memory bound. The byte-oriented recipient API documents
its parsing and size limits separately.

## Decision and constraint basis

The admission's `decision`, `request` and `subject` and the post-execution
object's `admission`, `execution` and `result` MUST be objects.
`admission_receipt.decision.outcome` and
`post_execution_receipt.admission.decision` MUST be strings.
The following rules select one basis;
missing or malformed selected constraints MUST NOT fall back to another basis.

| Admission decision | Effective request hash | Effective constraints | Executability |
| --- | --- | --- | --- |
| `allow` | `request.input_hash` | `request.constraints`, or an empty object when absent | Executable; an `attenuation` member is contradictory and is rejected, including `null`. |
| `attenuate` | `attenuation.effective_request_hash` | Nonempty `attenuation.effective_constraints` object | Requires an attenuation object, a recognized mode and a boolean `require_new_permit`. A true flag or `mode: require_new_permit` prevents linkage. |
| `deny` or an unknown decision | No executable admission | No successful linkage | Rejected. |

Recognized attenuation modes are `narrow`, `require_new_permit` and
`deny_if_not_accepted`. A new-permit mode cannot become executable through a
false flag. A missing or non-boolean flag is invalid input.
`request.constraints`, when supplied, MUST be an object even for an attenuated
admission. The post-execution admission decision MUST match the admission's
decision; a post-execution `deny` is rejected.

## Checked relationships

| Surface | Requirement |
| --- | --- |
| Receipt ID | Admission `receipt_id` and post-execution `admission.receipt_id` MUST be nonempty strings and equal. Two missing or non-string values cannot establish a match. |
| Admission digest | `admission.digest` MUST contain `alg: sha-256` and exactly 64 lowercase hexadecimal characters in `value`, matching the existing sorted-key, compact JSON object digest of the entire supplied admission. Descriptor annotations are allowed. The input is not normalized, trimmed or repaired. |
| Transaction | `request.transaction_id` and `execution.transaction_id` MUST be nonempty strings and equal. |
| Runtime | `subject.runtime` and `execution.runtime` MUST be nonempty strings and equal. |
| Effective request hash | The decision-selected hash and `execution.effective_request_hash` MUST both be `sha-256:` followed by exactly 64 lowercase hexadecimal characters, and equal. This comparison does not reconstruct the request preimage. |
| Time window | Admission `issued_at`/`expires_at` and execution `started_at`/`finished_at` MUST parse under the core's documented RFC3339 subset using ASCII digits. Execution MUST start at or after issuance, finish at or after its start, and both execution times MUST be at or before expiry. |
| Reported effects | `result.side_effects` MUST be an array of objects. The amount and tool rules below apply when their constraints are configured. |
| Policy violations | `result.policy_violations` MUST be an array of nonempty strings. Any reported violation prevents successful linkage. |

The admission digest uses `canonical_bytes` in the
[reference core](vate_verifier_core.py): Python `json.dumps` with `sort_keys=True`,
`separators=(",", ":")` and `ensure_ascii=True`, followed by UTF-8 encoding and
SHA-256. Non-ASCII characters are escaped before hashing. This describes the
existing digest basis; callers must reproduce it when supplying a digest.
The core and ordinary runner compare the descriptor's validated `alg` and
`value` fields. Descriptor annotations do not affect that comparison.
Annotations inside the admission receipt remain part of the hashed object.

`max_amount`, when configured, MUST be a money object with a three-letter
uppercase currency and a finite, non-negative decimal value within the core's
64-character, 18-integer-digit and 8-fractional-digit bounds. Values may be JSON
numbers or decimal strings; booleans are rejected. A string MUST match the
entire ASCII pattern `(0|[1-9][0-9]*)(\.[0-9]+)?`. For example, `0`, `25.00`
and `0.5` are valid strings; exponents, signs, whitespace, digit separators,
non-ASCII digits and extra leading zeros are rejected. Every reported `amount`
member MUST satisfy the same conditions. A malformed or `null` amount cannot
disappear from the comparison. Reported currencies MUST match the limit, and
the sum of reported amounts MUST NOT exceed it. Addition uses a fresh decimal
context with sufficient precision for the accepted bounds, independent of the
embedding application's decimal settings.

`tool_allowlist`, when configured, MUST be an array of nonempty strings. An
empty array permits no reported tool. Every present `tool`, `tool_id` or `name`
alias MUST be a string or `null`, including aliases with lower priority. Skip
`null` and empty strings, then select the first nonempty string in that order.
The selected string MUST appear in the allowlist. If aliases are present but
all are `null` or empty strings, the observation is invalid. Numbers, booleans,
arrays and objects are invalid aliases; they are neither coerced nor skipped.

Absent amount or tool observations do not prove that no such effect occurred.
Without the corresponding configured constraint, these observation fields are
left uninterpreted. The selected constraint object MUST NOT contain the legacy
names `max_amount_usd` or `resource`, even alongside their canonical names.
Issued receipts use `max_amount` and `target_resource`; this API does not rewrite
the supplied receipt.

The method does not assess `target_resource`, `effective_constraints.expires_at`
or approval semantics. Those require the selected profile's separate checks.
In particular, `ADMISSION_WINDOW_VALID` covers the admission receipt's own
`issued_at` and `expires_at`, not the expiry inside the constraint object.
Unrelated JSON annotations and
extension fields remain part of the original input and its digest. They do not
add checks to this API.

## Failure handling and result meaning

Invalid linkage inputs return `outcome: failed`; they do not escape as an input
type, missing-field or JSON-serialization exception. The result uses existing
reason codes:

| Failure | Reason code |
| --- | --- |
| Invalid JSON object representation, required block/type, contradictory decision data, receipt ID, selected constraint or observation shape | `POST_EXEC_LINKAGE_MISMATCH` |
| Malformed or locally unsupported configured/reported amount; selected constraints contain a legacy alias | `POST_EXEC_LINKAGE_MISMATCH` |
| Invalid or mismatched admission digest; admission cannot be serialized on the existing digest basis | `POST_EXEC_ADMISSION_DIGEST_MISMATCH` |
| Non-executable decision or a new permit is required | `POST_EXEC_ADMISSION_DENIED` |
| Missing, non-string or different transaction/runtime identity | `POST_EXEC_TRANSACTION_MISMATCH` / `POST_EXEC_RUNTIME_MISMATCH` |
| Invalid, missing or different effective request hash | `POST_EXEC_EFFECTIVE_REQUEST_HASH_MISMATCH` |
| Invalid timestamps or an execution outside the admission window | `POST_EXEC_ADMISSION_EXPIRED` |
| Reported amount/tool exceeds a configured constraint, reported currency differs from the configured currency, or policy violations are reported | `POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED` |

The direct API uses the same input-failure code for malformed money and for
schema-valid values outside its local amount bounds. It does not distinguish
these cases in its result. The byte-oriented recipient API reports the latter
as an `unsupported_amount` input issue and leaves linkage `not_assessed`.

An invalid outer structure may stop checking immediately. Otherwise, the core
returns the distinct reasons it can assess in deterministic order. Callers
MUST NOT assume that a failed result lists every possible defect in the input.
Process termination and resource exhaustion are outside this data-error contract.

A successful result retains the existing reason list, including
`EFFECTIVE_CONSTRAINTS_OBSERVED`. That code covers only the stated amount/tool
observations and policy violations. It is not a claim of complete effects or
verification of every possible constraint. An empty `allow` constraint object
or absent amount/tool observations can still yield success; the success codes
do not establish that such observations were supplied. The admission and execution objects
may also contain fields this API does not assess; apply the receipt schemas and
the selected profile before making broader conclusions.

## Compatibility and verification

The result shape and digest basis are unchanged. Well-formed supported pairs
retain their existing results. Invalid combinations previously accepted through
fallbacks, Python equality/coercion or omitted checks now fail. Noncanonical
amount strings and non-string, non-null tool aliases that Python's decimal
parser or truth-value rules previously accepted now fail. Inputs that
previously raised a data error return a failed result.

Malformed or out-of-range configured/reported amounts previously returned
`POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED`; they now return
`POST_EXEC_LINKAGE_MISMATCH`. This also applies to schema-valid values beyond
the core's local bounds. Actual amount/tool excess and currency mismatch retain
`POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED`. Callers branching on reason codes
must account for this distinction between invalid input and a checked constraint
violation.

Run the direct API regressions and existing binding tests with:

```bash
python3 -B -m unittest discover -s reference/request-binding -p 'test_*.py' -v
```

The core and ordinary runner's `admitted_effective_constraints` helpers use the
same decision-specific selection rules and raise `ValueError` for an invalid
basis. They do not turn invalid receipts into empty or original constraints.
The runner's side-effect checkers convert that error to a failed diagnostic;
the recipient's input checks report `semantic_input_invalid`.
The core linkage method handles that error
and returns the failed result.
