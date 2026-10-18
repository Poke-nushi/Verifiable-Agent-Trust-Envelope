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

To derive collection status from actual reads and registration of a selected
local receipt package, use the [package intake example](PACKAGE-INTAKE.md).
It preserves collection failures separately from record absence and receipt
contradictions, and includes a generated A/B/C example with B omitted.

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
`prepare`, `run` and `status` return a state object. Pass its `run_id` string
to the next call. `report_ref` identifies the complete report when one was
saved; it can also be present after an assessment error.
To read that report through the CLI, export the run and open the exported
`report.json` when a report was saved.
See [the API return values](CONTRACT.md#python-api-return-values),
[the input contract](CONTRACT.md) and the example's
[delivery/plan construction](scenario_inputs.py) for field definitions.

For an initialized inbox and a plan whose references have already been stored:

```python
import json
import sys
from pathlib import Path

root = Path("/path/to/VATE")
sys.path.insert(0, str(root / "reference/recipient-inbox"))
from recipient_inbox import Engine, Inbox

inbox = Inbox("/path/to/receiver.sqlite3", Engine(root), create=False)
try:
    prepared = inbox.prepare(Path("/path/to/plan.json").read_bytes())
    state = inbox.run(prepared["run_id"])
    print(json.dumps(state))
    if state["report_ref"] is not None:
        report = json.loads(inbox.get(state["report_ref"]))
        print(json.dumps(report))
finally:
    inbox.close()
```

This example omits the optional signature configuration. Select the OpenSSL
path and hash on `Engine` when the plan requests that check. Read the returned
state and the report separately; saving a report does not establish that its
records are present or valid.

## Read the saved state

| Run state | Meaning |
| --- | --- |
| `prepared` | Fixed inputs are stored; the run has no accepted report yet. |
| `completed` | The complete report was saved and accepted as the next history revision. |
| `assessment_error` | Evaluation or report collection failed; the previous history head is retained. |
| `stale_history` | A competing run advanced the history first; this report is retained separately. |

`completed` and CLI exit 0 describe report handling. Read the report's coverage,
timeliness and native assessments to determine whether records are missing,
invalid or contradictory. They do not grant execution permission. A `run`
ending in another state exits 64. Handled processing errors after argument
parsing also exit 64; argument-parsing errors exit 2.

`assessment_error` also covers a saved report with `invocation_errors: true`,
such as a requested check without its policy or verifier configuration.
Inspect the saved report's `diagnostics` and `native_calls[].result` even if
the state's `errors` list is empty.
Calling `run` again returns the recorded state. Correct the inputs or
configuration and prepare a new job.

Prepared inputs exclude deliveries registered after `prepare`.
Resuming a prepared job requires the same source and runtime identity.
After an update, create a new Engine and prepare a new job. When the inbox
module or Python runtime changes, restart the receiving process first.
Original bytes and previous success/error reports remain available.
The [historical runtime](../historical-runtime/README.md) supports
explicit replay of the archived inputs.

Changing a deadline can change a later report from `late` to `on_time` under
the new deadline. Compare it with the retained earlier report; the new result
does not mean the original deadline was met.

## Reassess an exported run

After `export(run_id, "/tmp/vate-inbox-export")`, the new directory contains
`selection.json`, the available `report.json`, `runs.json`, `MANIFEST.json`
and `objects/`. The selection's raw references use the path-base name `inbox`.
Map that name to the export directory when calling Required Record Review:

```bash
.venv/bin/python -B reference/required-records/required_records.py \
  --selection /tmp/vate-inbox-export/selection.json \
  --base "inbox=/tmp/vate-inbox-export" \
  --source-root "$PWD" \
  --output /tmp/vate-inbox-reassessment.json
```

Run this from the explicitly selected VATE source tree with its required
Python dependencies. For signature checks, also supply `--openssl` and
`--openssl-sha256` as in the original configuration. The output path must be
new; keep the exported report alongside the reassessment. The selection keeps
its original cutoff and receiver policies. To assess later arrivals or a
changed policy, prepare a new inbox plan instead.

Reassessment records its evaluator source hashes and Python version.
`usage.elapsed_milliseconds` can differ between runs. The selected source-tree
and OpenSSL paths also enter native call identities, so changing those paths
can change call IDs and their references even when the selected files are
unchanged. Retain both full reports when comparing their coverage, timeliness
and native results.

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
