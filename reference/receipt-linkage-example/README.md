# Receipt Linkage Example

Check whether a stored admission receipt and a post-execution receipt describe
the same admitted operation under VATE's existing receipt checks. This example
reuses the reference core, schemas and runner to distinguish a matching pair,
a mismatch, and inputs that cannot be assessed.

## Run the examples

Use Python 3.10 or later and the repository's existing development dependency,
`jsonschema==4.26.0`. From the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -B reference/receipt-linkage-example/run_examples.py
```

If the repository environment is already installed, run only the last command.
The command prints a summary of four examples. Add
`--output /tmp/vate-receipt-results.json` to save the complete results to a new
file; existing files are never overwritten.

Check two local originals, here the included R17 pair:

```bash
.venv/bin/python -B reference/receipt-linkage-example/recipient_example.py \
  --admission reference/receipt-linkage-example/inputs/R17/admission.json \
  --post reference/receipt-linkage-example/inputs/R17/post.json
```

Omit an argument when that original is unavailable. The CLI reads the supplied
files without modifying them, fetching their URIs, or executing the operation.
Keep this directory inside the repository tree; a source archive works without
Git or the original development directory.

## Interpret the result

| `record_linkage` | Meaning | CLI exit code |
| --- | --- | --- |
| `matched` | The implemented receipt relationship checks found no mismatch. | 0 |
| `mismatch` | The receipts could be interpreted, but a checked relationship or reported constraint did not match. | 1 |
| `not_assessed` | Missing, unreadable, invalid or unsupported input prevented comparison. | 2 |

These are this example's reporting categories, not new VATE decision codes.
`core_result` retains the core's output, and `side_effect_check_failures` retains
the runner's amount-check findings. The top-level result reflects both.
`linkage_checks_run` lists the check groups invoked; `not_checked` lists the remaining
verification responsibilities.

`matched` does not establish that an operation succeeded or that its report is
trustworthy. A report of a failed operation can still match its admission.
The checks cover receipt ID/content digest, executable admission decision,
transaction, runtime, declared effective-request hash, execution window,
reported amounts/tools when their constraints are configured, and policy violations.
Without `max_amount`, side-effect amounts are left uninterpreted and listed in
`not_checked`; the same applies to tools without `tool_allowlist`. They do not authenticate
signatures or issuers, reconstruct request preimages, establish complete or
independently observed effects, or grant current permission to execute. Other
constraints, including target and approval semantics, remain with the user of
the example. `EFFECTIVE_CONSTRAINTS_OBSERVED` has only the stated amount, tool
and policy-violation scope here; missing effect fields do not prove completeness.

In CLI output, each input's `file_status` distinguishes `not_specified`, `read`,
`unreadable` and `too_large`. `supplied` means bytes reached the assessment;
`read` alone does not mean valid JSON. `raw_file_sha256` identifies those bytes.
Receipt-to-receipt linkage uses the existing VATE JSON object digest, which is
different from a raw-file digest.

## Input conditions

Each file is limited to 1 MiB. Duplicate JSON keys and non-finite numbers are
rejected. JSON numbers must retain their decimal value through Python's float
representation. Unsupported precision is `not_assessed`, rather than silently
rounded. Use the original receipt bytes; converting an issued amount to a
string also changes the object digest and requires a correspondingly issued
receipt pair.

Timestamps require a time zone and at most six fractional-second digits;
lowercase `t`/`z` and numeric offsets are accepted. When `max_amount` is present,
both the limit and reported side-effect amounts must fit the core's bounds:
finite, non-negative, at most 64 text characters, 18 integer digits and 8
fractional digits, with a three-letter uppercase currency. Without that limit,
`matched` makes no statement about the format or value of side-effect amounts.

For `tool_allowlist`, the core uses the first nonempty `tool`, `tool_id` or
`name`, in that order. With `tool: "files/write"` and `name: "summary.txt"`, it
checks `files/write`. If `name` means a filename, supply the tool identifier in
`tool` or `tool_id`.

The input checks also apply existing decision/reason-code, evidence vocabulary,
typed hash/digest and canonical constraint rules. Legacy `max_amount_usd`,
`resource` or string-valued `approval` in the effective constraints yield
`not_assessed`; unrelated annotations are preserved. See the
[receipt model](../../docs/receipt-model-v0.3.md). These are local reference-tool
input conditions, not changes to the reusable receipt schemas.

## Included inputs and reproducibility

| Example | Input selection | Expected result |
| --- | --- | --- |
| R17 | Admission and post-execution originals from the fixed starter. | `matched` |
| R86 | Another original pair; the original disclosure lacked provider observation evidence. | `matched` |
| R52 | The starter contains the admission but no post-execution original. | `not_assessed` |
| synthetic_runtime_mismatch | R17's post with only its runtime changed. | `mismatch` |

R17 and R86 both match here because this example checks the receipt pair, not
the provider observations. It does not replace the original package's
`CONFIRMED_SUCCESS` / `INCOMPLETE` assessments. The suite's exit code 0 means
all four expected categories were observed, including the intentional mismatch.

Five originals are copied byte-for-byte from the published
[A2A evidence starter](../../docs/a2a/evidence-reproduction.md).
[INPUT-PROVENANCE.json](INPUT-PROVENANCE.json) records its download URL, ZIP hash,
member paths, original hashes and the synthetic change. The original operation
and external SUT are not rerun by this example.

[SOURCE-PINS.json](SOURCE-PINS.json) fixes the five core, runner, schema and
registry dependencies by raw-file SHA-256. The example stops if one differs;
`source_files` in each result identifies the bytes used. These dependency pins
are not a signature or a digest of the entire example directory. When updating
a dependency, review its effect before updating the pins and expected results.
[expected-results.json](expected-results.json) contains the complete four-case
output, reproduced byte-for-byte by the tests.

Run the tests:

```bash
.venv/bin/python -B -m unittest discover \
  -s reference/receipt-linkage-example -p 'test_*.py' -v
```

For verification of a complete capture, including provider evidence and source
manifests, use the [Execution Evidence Demo](../execution-evidence-demo/README.md)
or the fixed starter's recipient. This example exposes the receipt checks for
reuse; it does not implement a native-format adapter or a production verifier.
