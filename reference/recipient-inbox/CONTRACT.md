# Local Recipient Inbox Contract

`vate-recipient-inbox-local-v1` is an experimental application contract.
It retains the existing required-record review rules and the AL2 verifier
admission profile v0.3. It does not add normative receipt or admission fields.

## Storage references

`put` retains the exact bytes and returns a reference with `path_base: inbox`,
an object path, media type, `digest_basis: raw_file_sha256`,
`digest: {alg: sha-256, value: <hex>}`, and byte length. Identical bytes share
one content-addressed object. Reads verify the raw hash and length.
This raw digest is distinct from VATE's receipt-object digest.

A stored object is not a received record until a delivery registers it.
Arrival times and receipt-basis references are supplied by the trusted local
receiving application; hashing them does not independently establish arrival.

## Delivery

A JSON delivery contains:

- `document_type: recipient_inbox_delivery`, `version: 1`;
- `event_id`, `entry_id`, `source_namespace`, `native_input_kind`;
- `received_at`, a UTC timestamp ending in `Z` or null (for example,
  `2026-10-16T12:00:00Z`; optional fractional seconds use 1–6 digits);
- `receipt_basis_ref` and `originals`, a mapping of named slots to stored
  references;
- optional `detached_proofs`, with admission and post slots.

The implemented kinds are `receipt_pair` (admission/post originals) and
`s3_bundle` (the existing S3 member set). Unknown kinds are retained for the
reviewer to report as unresolved candidates. A delivery needs at least one
original or proof.

An entry can acquire an unfilled slot later. An occupied slot is not
overwritten, even by equal bytes under another event. A distinct submission
uses a distinct entry, preserving any resulting ambiguity. Repeating the
same event ID with exactly the same delivery bytes is idempotent; changed
bytes with that ID are rejected.

## Plan

A plan contains `document_type: recipient_inbox_plan`, `version: 1`,
`receiver_id`, `review_set`, `review_set_selected_at`,
`assessment_cutoff`, `assessment_time`, `inventory_state`,
`collection_basis_ref`, `selection_basis_ref`, `native_policy_refs` and
`revision_basis_ref`. The native policy map has `s3` and `signature`
references or null values.

The review set is a revision-1 template under the existing
[required-record contract](../required-records/CONTRACT.md). The inbox binds
its next revision to the accepted previous review and report. The receiver
supplies revision grounds; the inbox does not infer requirements or collection
closure from whatever records arrived.
For the same receiver ID, namespace and review-set ID, `revision_basis_ref`
may be null while no run has been accepted; subsequent revisions require a
stored basis. The existing [revision rules](../required-records/CONTRACT.md#one-revision)
also reject a regressing cutoff or removal of a previous requirement ID.

`prepare` selects all registered entries in that namespace and fixes a
snapshot, review and selection. Deliveries registered after `prepare` cannot
enter that job.
Records after the cutoff are marked after; unknown arrival times remain
unknown. If any registered arrival is later than `assessment_time`, `prepare`
fails with `RECEIPT_TIME_IN_FUTURE`; it does not create the job or remove the
stored slots. Registering a delivery does not check it against a future plan's
assessment time.
`closed`, `partial` and `unavailable` retain the reviewer's meanings.

## Evaluation and history

An Engine records the selected inbox code, reviewer/native sources, Python
runtime and interpreter bytes, isolated-environment jsonschema version, and
optional OpenSSL path/hash. This identifies the selected local environment;
it is not an attestation of all dependencies or shared libraries.

Evaluation invokes the existing required-record CLI in a separate process.
The inbox saves the full report, and available stdout/stderr, under raw-byte
references. A saved report and its adoption as the next history head are
committed together.

Two jobs prepared against the same head can both execute; only the first
accepted result advances the head. The other is `stale_history`. Two calls
to run the same job return the first recorded result. Interruption can cause
the read-only evaluation to execute again; it does not rerun the external
operation represented by the records.

The inbox cannot resume an old prepared job under changed source/runtime
identity. The application either resumes it with the original environment
or prepares a new job with the new Engine. Changes to the inbox module or
Python runtime require restarting the receiving process first.
Old originals and success/error
reports are not rewritten to claim the new evaluator identity.

## Python API return values

Import `Engine` and `Inbox` from `recipient_inbox` after selecting the module
directory under the trusted source tree. `Engine(source_root, openssl=None,
openssl_sha256=None)` selects the evaluator. `Inbox(path, engine, create=True)`
initializes a new database; use `create=False` to reopen it.

| Call | Returned value |
| --- | --- |
| `put(raw_bytes, media_type="application/json")` | The six-field raw reference described under Storage references. |
| `get(ref)` | The original `bytes`, after checking their hash and length. |
| `receive(delivery_raw)` | An object with `event_id`, integer `sequence` and boolean `duplicate`. An identical repeated event returns its original sequence. |
| `prepare(plan_raw)` | A state object with `status: prepared`; pass its `run_id` string to `run`, `status` or `export`. |
| `run(run_id)` | The state object after evaluation, or the recorded state if that job already ran. |
| `status(run_id)` | The current state object described below. |
| `export(run_id, destination)` | An object with `directory`, integer `files`, `run_id` and `status`. `files` counts the exported payload files, excluding `MANIFEST.json`. |
| `close()` | `None`; closes the database connection. |

Delivery and plan arguments are UTF-8 JSON `bytes`, not Python dictionaries.
The caller stores each referenced original or basis with `put` before
submitting metadata that refers to it. These methods can raise exceptions for
invalid inputs, unavailable files or database failures. A source/runtime
change detected before evaluation also raises an exception and leaves the job
`prepared`. Catch errors at the application boundary and close the inbox in
`finally`.

The state object has these fields:

| Field | Meaning |
| --- | --- |
| `contract` | `vate-recipient-inbox-local-v1`. |
| `run_id` | The prepared job's identifier. |
| `status` | `prepared`, `completed`, `assessment_error` or `stale_history`. |
| `revision` | The selected review-set revision. |
| `previous_id` | The accepted predecessor selected at preparation, or null. |
| `max_delivery_sequence` | The highest delivery sequence included in the prepared namespace snapshot, or zero. Arrival assertions and the cutoff still govern record inclusion. |
| `report_ref` | A raw reference to the saved complete report, or null when none was saved. It may be present with `assessment_error` or `stale_history`. |
| `head` | The history's current accepted run ID, or null. It may differ from this `run_id`. |
| `errors` | Retained inbox processing errors. Native findings are in the report. |

The CLI prints the corresponding method's returned object as JSON.
To retrieve a saved complete report, use `export RUN_ID DIRECTORY` and read
`DIRECTORY/report.json`.
Command-line argument errors print a usage error and exit 2. After argument
parsing, handled input or operational errors produce an `error` object and
exit 64. A `run` command
also exits 64 when its returned status is not `completed`; other successfully
handled commands exit 0. `status` can therefore exit 0 while reporting an
earlier assessment error. The report's coverage and native findings remain
separate from these command outcomes.

## Capacity and failures

A namespace has at most 256 entries. An entry has at most 18 original slots
and two separate proof slots. Delivery admission limits the generated entries
array to 1 MiB minus 4 KiB of snapshot-header reserve.

Native-call admission reserves two calls per receipt pair and three per S3
bundle, within the reviewer's 64-call limit. Unknown kinds reserve zero native
calls. This reservation does not assume cache hits between equal submissions.

Originals, proofs and receipt-basis reads reserve at most 12 MiB per namespace,
leaving 4 MiB for metadata and later-selected review/policy/basis inputs within
the 16 MiB read limit. Only identical complete references share this accounting;
equal hashes with different media types do not. After-cutoff and unknown-kind
entries are included. Preparing a job checks the actual review, selection and
snapshot sizes (each at most 1 MiB) and total current input reads again.
The previous-report history allowance is a separate 128 MiB limit.

A rejected delivery rolls back its event and slot changes. Objects previously
stored through `put` can remain, but are not counted as received merely because
they exist. The application must carry relevant rejections into its collection
state. The inbox does not split a namespace, waive a requirement, or silently
drop an original to recover capacity.

Process execution retains its time limits, the reviewer's 2 MiB native-result
limit, and the inbox's 128 MiB report and 1 MiB per-log limits. A log exceeding
its limit produces an explicit error; complete retention of that oversized
log is not claimed. Available bounded files are collected independently.
If the database is writable, failures recorded during evaluation or output
collection become `assessment_error` without advancing the head. This also
includes a saved report with `invocation_errors: true`. Calling `run` again
returns that recorded state; correct the inputs or configuration and prepare
a new job. A report that was never produced cannot be retained.

These limits do not bound every temporary allocation inside jsonschema or
guarantee completion for every input. The receipt checker marks truncated
diagnostics and preserves invalidity independently of the retained item count.

## Export

`export` creates a new directory; an existing path is refused.
It copies the selected run, its accepted predecessor chain, referenced raw
objects, selection and available report, plus `runs.json` and a raw-hash
manifest. Exported bytes are checked against the stored originals.
An export contains at most 256 revisions, including the selected run and its
accepted predecessor chain; a longer chain is rejected.
The receiving application can reassess the selection using its explicitly
selected source tree and runtime. Elapsed time can differ; changing the selected
source-tree or OpenSSL path can also change native call IDs and their references.
Keep both reports.
Map the raw-reference path base `inbox` to the export directory, which contains
`objects/`, and pass its `selection.json` to the required-record CLI. The
[reassessment command](README.md#reassess-an-exported-run) writes a separate
report without changing the selected cutoff, policies or stored history.

SQLite integrity and raw-hash checks do not protect against a party that can
rewrite the database and recompute its references. A remote service, access
control, independent timestamping and operational backup are outside this
local contract.
