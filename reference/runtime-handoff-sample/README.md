# VATE runtime handoff and receipt sample

Keep an unknown operation result intact when execution moves from runtime A to
runtime B. This local sample records the provider's acceptance and observed
effects, links each result to the runtime's own admission, and passes the saved
evidence through VATE's Recipient Inbox for storage and reassessment.

The operation creates two text files. Six synthetic histories distinguish a
confirmed unexecuted attempt from accepted work with zero, partial, or complete
effects. The receiver separately selects the expected operation, keys, and
required receipts. [CONTRACT.md](CONTRACT.md) describes the conditions under
which B can execute and the evidence each result represents.

## Prepare an environment

Use **CPython 3.11–3.14 on macOS or Linux**, SQLite, POSIX file locks, and the
`openssl` command on `PATH`. Windows is outside this sample's supported range.
The receiver uses `jsonschema==4.26.0`; its dependencies are fixed in
[requirements.lock](requirements.lock). Exact executed checks belong in
[VALIDATION.md](VALIDATION.md).

From a VATE checkout or repository source archive, copy the complete
`reference/runtime-handoff-sample/` folder into a new location. For a standalone
sample ZIP, extract it into a new folder. Open a terminal in that sample folder,
the one containing `check_environment.py`. Keep `sample/`, `inbox/`, `reference/`,
`schemas/`, `registries/`, and `scripts/` together. Do not overlay an earlier
distribution. Run these commands there, using your chosen supported Python in
place of `python3.12` if necessary:

```sh
python3.12 -E -s -B check_environment.py --sources-only
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/vate-handoff.XXXXXX")"
python3.12 -E -s -B -m venv "$work_dir/venv"
sample_python="$work_dir/venv/bin/python"
"$sample_python" -E -s -B -m pip install --require-hashes --only-binary=:all: -r requirements.lock
"$sample_python" -E -s -B check_environment.py
```

The installation downloads the pinned dependency wheels. It does not build
source packages or run their build scripts. For an offline installation, obtain
those same wheels beforehand and add `--no-index --find-links /path/to/wheels`
to the pip command. The demonstrations, receipt operations, and tests run
locally without an external provider or network service.

The final check must return `"status": "ok"`. It verifies the file inventory,
source hashes, selected dependency versions, and local tools. A supplied
manifest establishes file consistency, not publisher identity. Unlisted Python
modules, bytecode, native modules, and symlinks are rejected; extract a fresh
copy if this check fails.

Keep `work_dir` and `sample_python` in the same terminal for the commands below.
The work directory contains the environment and results, outside the source
distribution. Use a new permanent directory instead of `mktemp` if you need to
keep the records. `-E -s -B` ignores Python environment settings and user
packages and avoids writing bytecode.

## Run the six histories

```sh
"$sample_python" -E -s -B inbox/demo_connection.py --out "$work_dir/demo"
```

The destination must not exist. This creates disposable test keys, a fixed
fixture clock, synthetic provider stores, receiver selections, Inbox databases,
earlier and later assessments, and exported evidence. Temporary private-key
files are removed when generation finishes. The sample does not use Keychain
or an existing signing key. Receipt intake and replay do not submit provider
operations.

Results appear in `demo/SUMMARY.json` and each case's `RESULT.json`:

| History | Later effect state | Executing runtime | Meaning |
| --- | --- | --- | --- |
| `a-completed-response-lost` | `completed` | A | A's completed work is recovered; B does not execute. |
| `accepted-zero-effects` | `unresolved` | A accepted | Zero observed files after acceptance is not confirmed nonexecution. |
| `accepted-partial-effects` | `unresolved` | A accepted | One file exists; partial work is retained and B does not restart it. |
| `b-after-unaccepted-a` | `completed` | B | A's generation is closed after confirmation, then B executes under its own admission. |
| `completed-then-observed-later` | `completed` | A | Late observation does not change the actual execution time. |
| `effect-completed-outside-admission` | `completed` | A | Effects completed, but linkage fails because completion was outside admission validity. |

The earlier unknown observation and earlier assessment remain available after
later evidence arrives. `inbox.status: completed` means assessment processing
finished. `record_coverage` describes receipt availability under the selected
cutoff; neither field is an execution result or a new execution permission.
All receiver reports retain `is_execution_ticket: false`.

## Receive and assess an existing history

The following exercises the CLI with the demo's lost-response case and a
separate Inbox. The demo's selection is suitable for its synthetic inputs.
For another producer's evidence, establish the expected keys, operation,
provider/store, and required receipts independently before intake.

```sh
selection_file="$work_dir/demo/a-completed-response-lost/receiver-selection.json"
bundle_file="$work_dir/demo/synthetic-inputs/a-completed-response-lost/bundle.json"
inbox_db="$work_dir/receiver.sqlite3"
"$sample_python" -E -s -B inbox/receive_handoff.py --selection "$selection_file" --db "$inbox_db" init
"$sample_python" -E -s -B inbox/receive_handoff.py --selection "$selection_file" --db "$inbox_db" receive --event received-final --bundle "$bundle_file" --received-at 2026-10-25T00:16:40Z
"$sample_python" -E -s -B inbox/receive_handoff.py --selection "$selection_file" --db "$inbox_db" prepare --cutoff 2026-10-25T00:18:20Z --assessed-at 2026-10-25T00:20:00Z > "$work_dir/prepared.json"
run_id="$("$sample_python" -E -s -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["run_id"])' "$work_dir/prepared.json")"
"$sample_python" -E -s -B inbox/receive_handoff.py --selection "$selection_file" --db "$inbox_db" run "$run_id"
"$sample_python" -E -s -B inbox/receive_handoff.py --selection "$selection_file" --db "$inbox_db" status "$run_id"
"$sample_python" -E -s -B inbox/receive_handoff.py --selection "$selection_file" --db "$inbox_db" export "$run_id" "$work_dir/export"
```

The fixture dates above are fixed test data, not the machine's current time.
Omit `--received-at` when receipt time is unknown; do not substitute an inferred
time. A new `prepare` makes a new assessment selection, while `run` or `status`
with an existing run ID recovers that assessment.

Move the evidence folder and replay it with the same source distribution and
Python environment. The database is not needed for replay:

```sh
mv "$work_dir/export" "$work_dir/moved-export"
"$sample_python" -E -s -B inbox/receive_handoff.py --selection "$selection_file" replay "$work_dir/moved-export"
```

Replay checks the saved hashes, selected bindings, handoff history, receipt
projections, and recomputed assessment. It does not grant permission to retry
the operation. A valid replay can preserve an unknown outcome. Keep the same
source version, source location, and Python environment when replaying a saved
assessment; cross-version, cross-runtime, and cross-source-location migration
are outside this contract. You can relocate the source distribution before
starting a new run. Keep live provider stores in their original location.

## Recover interrupted receipt work

If intake was interrupted after storing a capsule, repeat `receive` with the
same event ID, exact bytes, and receipt time. The next `prepare` also resumes
pending receipt registration. Changing those inputs for an existing event is
rejected. If a result was stored but its terminal output was lost, use the saved
run ID with `status` or `run`. These operations recover receipt processing;
they do not repeat file creation. Do not rerun the demo to recover an old run.

The CLI returns 0 for a completed command, 2 for an unassessable intake, and 3
for an operational failure. A completed assessment may still report unresolved
effects or missing records. On exit 3, read the JSON `status` and `reason`:
`retryable_busy` identifies lock contention; capacity, source-version, and
replay-mismatch errors require correction before proceeding. Oversized inputs
are not recorded as successfully received. Invalid inputs retained in the
Inbox's source partition are not automatically included in receipt exports.

## Run regression checks

```sh
"$sample_python" -E -s -B sample/test_handoff.py -v
"$sample_python" -E -s -B inbox/test_bridge.py -v
"$sample_python" -E -s -B test_distribution.py -v
```

These check provider behavior, receipt integration, and distribution integrity
and relocation. They use temporary stores and synthetic keys. The demo also
runs all six histories through intake, assessment, export, and replay.

## Sources and scope

[SOURCE-MANIFEST.json](SOURCE-MANIFEST.json) identifies the complete distribution,
excluding the manifest itself. [UPSTREAM-SOURCES.json](UPSTREAM-SOURCES.json)
identifies unchanged VATE helpers, evaluator code, schemas, and registry files
from commit `a872ef1de6c75ba1820d0589ab7baa5e38be4fc2`.
The shared evaluator's fixed inventory includes S3 helper sources; this demo
uses local file-set receipts and does not connect to S3.

This is a technical sample with two runtimes, one trusted local provider and
its store, and a separate receiver Inbox database per case. The provider enforces acceptance uniqueness; the VATE
receiver checks and preserves the evidence and its bindings. This is not a
production-ready service or a demonstration of distributed exactly-once
execution. Provider/OS trust, retention limits, derived receipts, and clock
assumptions are detailed in [CONTRACT.md](CONTRACT.md).
