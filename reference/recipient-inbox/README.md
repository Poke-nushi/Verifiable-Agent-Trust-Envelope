# Recipient Inbox

Preserve received originals and reassess a receiver-selected set when records
arrive late or the receiver changes its policy. This local Python API and CLI
store raw bytes in SQLite, prepare fixed inputs for [Required Record
Review](../required-records/README.md), and retain each assessment with its
selected evaluator identity and previous history.

The experimental contract is `vate-recipient-inbox-local-v1`. Use it from a
trusted local receiving application. The receiver still chooses the required
set, collection scope, arrival assertions and policy. The current native
review profiles accept operation-level VATE receipts with S3 or local file-set
action context, plus S3 attempt requirements. Storage in SQLite does not
establish complete collection.

## Run the intake example

Use Linux or macOS, Python 3.10 or later, and a trusted checkout or source
archive of the **whole repository** with its existing
`jsonschema==4.26.0` dependency. SQLite is provided by Python.
Follow the [existing environment setup](../receipt-linkage-example/README.md#run-the-examples).

The example includes detached signatures. Select an installed OpenSSL 3 or 4
and set `VATE_TRIAL_OPENSSL` and `VATE_TRIAL_OPENSSL_SHA256` using the
[signature example's setup](../recipient-signature-authority/README.md#run-the-example).
Then, from the repository root, choose a new output directory:

```bash
.venv/bin/python -B reference/recipient-inbox/run_trial.py \
  --openssl "$VATE_TRIAL_OPENSSL" \
  --openssl-sha256 "$VATE_TRIAL_OPENSSL_SHA256" \
  --output /tmp/vate-inbox-example
```

The six stages cover missing records, late delivery, a changed issuer policy,
and a partial S3 bundle completed after the original cutoff. Each stage
reopens the database in a separate process. The command also exports and
reassesses two histories.

Inspect `SUMMARY.json`, the two SQLite databases, complete reports, exports
and `FILES-SHA256.json` in the output directory. The receipt bytes come from
the saved example. S3 tests use explicitly labelled offline derivatives with
current source declarations; `synthetic-current-s3/SYNTHETIC-PROVENANCE.json`
records the original hashes and changed fields. Arrival assertions and policy
choices are synthetic. Test signatures use public test keys and were not made
at the original operation. No storage service or network request is involved.

## Use the API or CLI

For [local file-set receipts](../required-records/README.md#choose-what-must-be-present),
use the same `receipt_pair` delivery kind and an operation-level review set.
Deliver `admission-1/receipt.json` in the `admission` slot and
`adapter/post-execution-receipt.json`, when available, in the `post` slot.
The receiver's arrival time and selected cutoff determine inclusion and
timeliness; the receipt's execution and issuance times do not replace them.
File-set attempt requirements and full execution-evidence verification remain
outside the required-record review.

Create a database without the optional signature check:

```bash
.venv/bin/python -B reference/recipient-inbox/recipient_inbox.py \
  --db /tmp/vate-intake.sqlite3 --source-root "$PWD" init
```

Keep the selected source tree available. The API sequence is:

1. Select `Engine(source_root, openssl, openssl_sha256)`; omit both OpenSSL
   arguments when signature checks are not requested.
2. Open `Inbox(db_path, engine, create=True)` once; reopen with `create=False`.
3. Call `put(raw_bytes, media_type)` to store each original and its raw-byte
   reference. Storage alone does not register a delivery.
4. Call `receive(delivery_raw)` to register arrival assertions and original slots.
5. Call `prepare(plan_raw)` to fix the review set, collected inputs, cutoff,
   selected policies and evaluator identity.
6. Call `run(run_id)`, inspect `status(run_id)`, and retrieve the full report
   with `get(report_ref)`.
7. Prepare a new plan after a late arrival or policy update. Export a selected
   run and its accepted history with `export(run_id, new_directory)`.
8. Call `close()` when finished.

The CLI exposes the same sequence through `put FILE`, `receive FILE`,
`prepare FILE`, `run RUN_ID`, `status RUN_ID` and
`export RUN_ID DIRECTORY`. Each invocation takes `--db` and `--source-root`;
signature checks also require the selected OpenSSL path and hash.
See [the input contract](CONTRACT.md) and the example's
[delivery/plan construction](scenario_inputs.py) for field definitions.

## Read the saved state

| Run state | Meaning |
| --- | --- |
| `prepared` | Fixed inputs are stored; the run has no accepted report yet. |
| `completed` | The complete report was saved and accepted as the next history revision. |
| `assessment_error` | Execution or report collection failed; the previous history head is retained. |
| `stale_history` | A competing run advanced the history first; this report is retained separately. |

`completed` and CLI exit 0 describe report handling. Read the report's coverage,
timeliness and native assessments to determine whether records are missing,
invalid or contradictory. They do not grant execution permission. A `run`
ending in another state exits 64; input and operational errors also exit 64.

Prepared inputs exclude later arrivals. Resuming a prepared job requires the
same source and runtime identity. After an update, create a new Engine and
prepare a new job; original bytes and previous success/error reports remain
available. The [historical runtime](../historical-runtime/README.md) supports
explicit replay of the archived inputs.

## Limits and collection responsibility

Use one namespace for one finite collection set. Admission limits include
256 entries, 18 original slots per entry, two separate signature-proof slots,
and a 1 MiB snapshot budget with reserved header space. The inbox also reserves
native calls and read volume before accepting a delivery or preparing a job;
see [the contract](CONTRACT.md#capacity-and-failures).

A rejected delivery leaves existing slots and history unchanged. If that
delivery belongs to the chosen set, the receiving application must reflect
the collection gap, for example with `partial`. It must not automatically
declare `closed` after rejecting relevant input. A different namespace starts
a different history; the inbox never silently moves or excludes a record.

Receipt diagnostic lists are bounded and mark omitted text or stopped
collection. Invalid input remains invalid. Evaluation retains time, input and
output limits; the limits do not guarantee completion for every admissible
input. See [diagnostic reporting](../receipt-linkage-example/README.md#diagnostic-limits).

This is a local review aid, not a network ingestion service, tamper-resistant
audit store or production-ready verifier. A party that can edit the database
or selected executable remains inside the local trust boundary. External
collection governance, independent issuer selection, and operational backup
and recovery are responsibilities of the receiving application.

## Verify the distribution

With the same selected OpenSSL executable:

```bash
VATE_TRIAL_OPENSSL="$VATE_TRIAL_OPENSSL" .venv/bin/python -B -m unittest discover \
  -s reference/recipient-inbox -p 'test_*.py' -v
```

The suite includes restart and race controls, original/report preservation,
capacity rejection, bounded diagnostics, update handling, and explicit
historical replay. CI runs the checks from both a checkout and a source archive.
