# Import a selected receipt package

Read a finite local package, preserve its receipt originals in Recipient Inbox,
and assess required records from a separately selected operation inventory.
The command derives collection status from file reads, digest checks and Inbox
registration. It keeps collection failures separate from missing records and
from contradictions within received receipts.

This experimental example uses the existing [Recipient Inbox](README.md) and
[Required Record Review](../required-records/README.md) contracts. Its local
input format is an example convention, not a new VATE profile. It is not
production-ready.

## Run the example

Use Linux or macOS, Python 3.10 or later, and the whole repository checkout or
source archive with its existing `jsonschema==4.26.0` dependency. Follow the
[environment setup](../receipt-linkage-example/README.md#run-the-examples).
No OpenSSL or network service is needed for this example.

From the repository root:

```bash
source_root="$PWD"
work_dir="$(mktemp -d)"
.venv/bin/python -B reference/recipient-inbox/package_example.py \
  --output "$work_dir/example"
.venv/bin/python -B reference/recipient-inbox/package_intake.py \
  --source-root "$source_root" \
  --inventory "$work_dir/example/inventory.json" \
  --membership "$work_dir/example/membership.json" \
  --package "$work_dir/example/package" \
  --due-at 2026-10-16T20:03:00Z \
  --output "$work_dir/intake"
```

The generator runs the repository's local file-set scenarios. It builds an
A/B/C requirement inventory from producer admission originals, then selects
only A/C receipt pairs into the package. `PROVENANCE.json` records the generated
originals and their hashes. These are synthetic receiver choices over local
demo operations; they do not represent external arrivals.

With the example's past deadline, `SUMMARY.json` reports collection `closed`
and coverage `present`, `missing`, `present` for A/B/C. The two receipt-linkage
results in `report.json` are `matched`. Exit 0 means collection and report
handling completed; B remains missing. Intake records the current local import
time, so A/C are late against that deadline. Receipt issuance and file times
are not used as arrival times.

Keep `work_dir` to inspect the output or export it for another evaluator run.
Both commands require a new output directory and leave existing runs intact.

## Prepare your own inputs

Choose the required operations independently of the files that arrived. Then
select the finite package to inspect. Start from the generated JSON files:

| Input | Required content |
| --- | --- |
| `inventory.json` | A `namespace` and 1–64 `jobs`. Each job has a unique `job_label`, an `operation_id`, `expected_record_kind: "post_execution"`, and `expected_context`. |
| `expected_context` | The operation's `transaction_id`, `runtime`, `effective_request_hash` and `action_binding`, following the existing [receipt-pair binding](../required-records/README.md#choose-what-must-be-present). |
| `membership.json` | Exactly `kind`, `version`, `namespace`, `inventory_sha256`, `files` and `deliveries`. Use `kind: "local_selected_receipt_package"`, `version: 1`, the inventory namespace, and the SHA-256 of the inventory's raw file bytes. |
| `files` | For each selected file: a flat `path`, raw `bytes` count and lowercase SHA-256 `sha256`. Every selected file must occur in exactly one delivery slot. |
| `deliveries` | A unique `entry_id` and `originals` mapping with an `admission` slot, a `post` slot, or both, each naming a selected file. The existing native kind is `receipt_pair`. |
| `--package` | The flat directory containing exactly the selected files. Keep its contents unchanged during intake. |
| `--due-at` | The receiver's UTC deadline for the selected post-execution requirements. |
| `--source-root` | A trusted whole VATE source tree chosen by the caller. Preserve it for reassessment. |

Namespace and job/operation/entry labels use 1–96 ASCII letters, digits, `.`, `_`,
`:` or `-`, starting with a letter or digit. File names use 1–128 ASCII letters,
digits, `.`, `_` or `-`, starting with a letter or digit. No directory components
are accepted in file names. Do not change original receipt bytes to fit the
inventory; update the selected inventory or package instead.

The command checks the deadline and expected contexts before reading package
originals. Failed input validation can leave initial inventory, membership and
error metadata in the new output directory.

## Interpret the result

| Observation | Collection and record assessment |
| --- | --- |
| The selected package is read and registered completely, but lacks a required post | `closed`; the requirement is `missing` after the deadline or `pending` at or before it. |
| A selected file cannot be read, its bytes differ, or registration fails | `partial`; coverage is assessed as `unresolved`. A failure can also stop the command before a report is available. |
| The package cannot be opened or enumerated | `unavailable`; coverage is assessed as `unresolved` when assessment completes. |
| An original is read successfully but contradicts its paired receipt | The original is retained; read the native `mismatch` result separately from record presence. |

`closed` means that this selected finite package was imported completely. It
does not authenticate the inventory's authority or establish completeness of
external arrivals. An empty package can be `closed` while all required records
are missing. Unlisted files, symlinks, non-regular files and changes detected
during intake prevent a clean collection result.

| CLI exit | Meaning |
| --- | --- |
| `0` | Collection is `closed` and the complete report is saved. Standard output contains the summary JSON. |
| `2` after assessment | A `partial` or `unavailable` report is saved; standard output contains the summary JSON. |
| `2` during argument parsing | Missing or invalid command arguments; usage goes to standard error and intake has not started. |
| `64` | Startup, input or processing failure; standard output contains `handling_status: "failed"` JSON. A report is not guaranteed. |

Use the summary and saved files, not exit 2 alone, to determine whether a report
exists. None of these outcomes grants permission to execute or retry an operation.

## Inspect, retain and reassess

- `SUMMARY.json` summarizes handling, collection and coverage. `report.json`
  contains the complete assessment, including native results and diagnostics.
- `EVENTS.jsonl` records reads, storage and registration; `COLLECTION.json`
  records the derived collection result when collection returns.
- `observed/` preserves read originals, including bytes later rejected for a
  digest or registration failure. `submitted/` contains delivery and plan JSON.
- `inbox.sqlite3` preserves originals and accepted history. `export/` contains
  the selected assessment's inputs and report. Keep the whole run directory to
  retain rejected originals that are outside the exported selection.
- `FAILURE.json` records caught failures after output initialization. It may be
  absent for startup or output-directory failures; retain standard output and
  standard error too. If evaluation failed, inspect `RUN.json` and `STATUS.json`
  for a `report_ref` and use the Inbox CLI `get` command to retrieve that report.
  Only completed assessments are automatically written to `report.json` and
  `export/` by this command.

Using the variables from the example, reassess the saved export:

```bash
.venv/bin/python -B reference/required-records/required_records.py \
  --selection "$work_dir/intake/export/selection.json" \
  --base "inbox=$work_dir/intake/export" \
  --source-root "$source_root" \
  --output "$work_dir/reassessment.json"
```

For unchanged inputs, source and runtime, the complete report matches except
for `usage.elapsed_milliseconds`. After a source/runtime update, follow the
[Inbox update and history rules](README.md#read-the-saved-state): create a new
Engine and plan, preserving the old originals and reports.

After an interrupted intake, retry with a new output directory. Do not reuse an
old completion marker. A detected clock reversal aborts the attempt. A forced
process termination may leave only part of the event log.

## Limits and checks

This example accepts at most 64 files, 32 deliveries, 1 MiB per original and
8 MiB of acquired originals. It uses a caller-controlled static directory and
does not provide an atomic snapshot against hostile concurrent writers.
Signature/issuer checks, file-set attempt requirements, full execution-evidence
verification and network collection are outside this command's scope.

Run the package tests as a non-root user, including the permission-denied case:

```bash
.venv/bin/python -B -m unittest discover \
  -s reference/recipient-inbox -p 'test_package_intake.py' -v
```
