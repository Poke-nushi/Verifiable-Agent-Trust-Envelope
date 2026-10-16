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

`prepare` selects all registered entries in that namespace and fixes a
snapshot, review and selection. Later arrivals cannot enter that job.
Records after the cutoff are marked after; unknown arrival times remain
unknown. A declared arrival after the assessment time is rejected.
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
or prepares a new job with the new Engine. Old originals and success/error
reports are not rewritten to claim the new evaluator identity.

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
If the database is writable, ordinary source/startup/execution/collection
failures become `assessment_error` without advancing the head. A report that
was never produced cannot be retained.

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
selected source tree and runtime; elapsed time and temporary evaluator paths
can differ. Keep both reports.

SQLite integrity and raw-hash checks do not protect against a party that can
rewrite the database and recompute its references. A remote service, access
control, independent timestamping and operational backup are outside this
local contract.
