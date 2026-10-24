# MUSUBI set2 recipient sample

Receive a fixed MUSUBI set2 evidence bundle into a VATE Inbox, check that its
records belong to the selected requests, and replay the upstream settlement
calculation. Then change the selected Bitcoin header view and save a second
assessment linked to the first. Both assessments and their original inputs
remain available for inspection and export.

An optional [A/C audit and dataset example](AUDIT-CONTRACT.md) adds the published
originals, checks their digest links to the selected execution receipts, and
retains the earlier assessment. Both examples use the preparation below.

The optional [foreign acceptance profile](ACCEPTANCE-CONTRACT.md) verifies
published A/B work acceptance records against the selected MUSUBI occurrences.
It records A's signed pass and B's signed fail separately from the native
settlement and preserves the earlier evidence history.

The base 68 originals and upstream evaluator come from [Horizon Shield #51](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51),
at commit `b85029de8d22c5246886f4f50ede03da0f54dfcf`. The two additions have
per-file commit pins in [audit-sources.json](sample/audit-sources.json). This is a fixed-source
interoperability example, not a production-ready verifier or a general
compatibility result. See [the receiving contract](CONTRACT.md) for the exact
meaning of its states and bindings.

## Requirements

- macOS with `/usr/bin/sandbox-exec`. Native replay fails closed if sandboxing
  is unavailable. Linux and Windows native replay are not provided.
- Python 3.11 through 3.14 and an existing [uv installation](https://docs.astral.sh/uv/getting-started/installation/).
  Preparation uses the Python that launches it. The native dependencies require
  Python 3.11 or newer, independently of VATE's broader core support.
- A VATE source checkout or archive. `vate-source.json` identifies the pinned
  commit and the 23 files used by the Inbox. Preparation checks their bytes.
- Internet access for environment preparation from PyPI. The replay uses the
  included source and originals; the upstream evaluator runs with networking
  denied.

The tested macOS interpreters use Homebrew under `/opt/homebrew` or Python's
framework layout under `/Library/Frameworks`. The replay sandbox denies reads
elsewhere in the home directory outside the prepared runtime and output paths.
A base interpreter or standard library installed there may therefore be
inaccessible; that installation layout has not been validated.

`requirements.lock` fixes all 21 package versions and their allowed distribution
hashes. Preparation installs wheels only into a new virtual environment. It does
not install into your existing Python environment, invoke a keyring, or build
packages from source. If a matching wheel is unavailable, preparation stops.

## Prepare

In a VATE checkout or source archive, open a terminal in
`reference/musubi-set2-receiving-sample/`. If you copied just this sample folder,
open that folder instead. Keep the runtime, VATE source and results in a separate
working directory outside the checkout. Change `sample_workspace` below if that
directory already contains an earlier run; runtime and output paths must be new.

```bash
sample_workspace="$HOME/vate-musubi-example"
mkdir -p "$sample_workspace"
vate_root="$sample_workspace/vate-source"
sample_environment="$sample_workspace/runtime"
sample_output="$sample_workspace/results"
```

If you do not already have the pinned VATE source, obtain it with:

```bash
git clone --no-checkout https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope.git "$vate_root" && \
git -C "$vate_root" checkout --detach f044b208bcb8046fd4aa262094b4b77271ba7b27
```

For an existing source tree, set `vate_root` to its root instead. An archive
works too; a Git checkout is not required by the sample itself.

Check the sample's file manifest, then prepare the environment. Replace
`python3.14` with your chosen Python 3.11–3.14 executable if needed. Preparation
uses an existing `uv` on PATH; `--uv /absolute/path/to/uv` selects another one.

```bash
shasum -a 256 -c SHA256SUMS && \
python3.14 -B prepare_environment.py \
  --vate-root "$vate_root" \
  --output "$sample_environment"
```

Success prints `status: prepared` and writes `PREPARED.json`, `evaluator.json`,
`requirements.lock` and `venv/` under the selected environment directory.
`PREPARATION.log` holds installer diagnostics. This step snapshots the installed
files, interpreter and launcher hashes for this machine. It is not an independent
signature or a snapshot of the whole operating system.

Keep the environment at its prepared location. Do not activate it for package
upgrades or use it without `-B`: added bytecode and other file changes make the
runtime fail its next integrity check. After a Python upgrade or runtime change,
prepare a new directory and retain the old results and descriptors.

## Receive and reassess

Read `sample/selection.json` before running. It explicitly chooses the receiver,
request occurrences, required records, checker, trust and reference output. The
second selection changes the header view; it does not assert that missing
acceptance or audit records have arrived.

```bash
"$sample_environment/venv/bin/python" -B run_example.py \
  --vate-root "$vate_root" \
  --environment "$sample_environment" \
  --output "$sample_output"
```

The command creates `inbox.sqlite`, `baseline/`, `extended/` and `EXAMPLE.json`.
No signing or external submission is part of this example. A second run needs
a new output directory.

## Read the result

| Result | Expected value | Meaning |
| --- | --- | --- |
| Baseline replay | Byte-for-byte match | Same selected source, inputs and conditions reproduce the reference stdout. |
| A/B/C execution | `within_delegation` | The upstream calculation accepts these execution constraints. |
| C payment | `budget_exceeded` | C takes the cumulative amount to 21,000 against a 20,000 budget. |
| Native acceptance | `null` | No acceptance decision is supplied by these records. |
| Required-record state | `partial` | The selected evidence set is not fully bound; inspect each requirement's binding and semantic assessment. |
| Extended replay | `anchor_depth: 9 → 14` | The selected header view changes this field; the original assessment is retained. |
| Inbox core | `selected_empty` | Foreign meaning is assessed by this adapter; the Inbox stores the evidence and history. |

Read the native judgment, each evidence link and the aggregate state separately.
`partial` can coexist with verified links or a validly signed work failure. It
does not identify which check is unfinished. The [receiving contract](CONTRACT.md#states)
distinguishes missing inputs, unsupported kinds and unselected records.

The expected baseline stdout SHA-256 is
`18a19f8a1eb62593b857241f34c07b1d96550b93d5c9ea17184b2ac695818fbd`.
The byte comparison includes the reference settlement's final newline.

Each run contains `RESULT.json` with saved references, `assessment.json` with
record bindings and native output, and `export/` with a digest manifest and the
stored history. `native/` contains replay diagnostics and stdout. Exports allow
exact input restoration; they do not contain a complete executable Python
environment.

`recorded` means local storage completed. It does not turn `partial`, a binding
contradiction or an upstream refusal into acceptance. The lower-level
`receiving.py` CLI returns 0 for a stored evaluation or normal refusal, 64 for an
input/storage/evaluator error, and 2 for invalid command syntax. The example
wrapper also returns 64 if either expected sample result differs.

## Add foreign acceptance records

Use `run_acceptance_example.py` for a baseline → A/C audit → foreign acceptance
sequence in one Inbox. It uses the prepared environment above. Supply these
external files separately:

- The four `hs51-*.json` originals in the
  [published acceptance set](https://github.com/babyblueviper1/preaction-governance-conformance/tree/235aaabc45ebe6fa36dd02ca2cd6a44a69297d93/examples/hs51-acceptance-set).
- The exact [WAR verifier source](https://github.com/maximusrufus/work-acceptance-record/blob/6b2f730b81e0818826f274742d883c2b475d5227/verifier/war_verify.py)
  pinned in [ACCEPTANCE-CONTRACT.md](ACCEPTANCE-CONTRACT.md).
- A JSON array of the two base64 DER trust roots in the `inputs.tsa_roots_base64`
  fields of [vector 31](https://github.com/maximusrufus/work-acceptance-record/blob/6b2f730b81e0818826f274742d883c2b475d5227/vectors/31-tsa-freetsa-verified.json)
  and [vector 32](https://github.com/maximusrufus/work-acceptance-record/blob/6b2f730b81e0818826f274742d883c2b475d5227/vectors/32-tsa-digicert-verified.json).
  Combine the two arrays into one array. The example checks the roots' raw SHA-256 fingerprints against its
  fixed receiver selection. Incoming records cannot supply those roots.

Set these paths to the saved files and choose a new output directory:

```bash
acceptance_originals="$sample_workspace/hs51-acceptance-set"
acceptance_verifier="$sample_workspace/war_verify.py"
acceptance_roots="$sample_workspace/tsa-roots.json"
acceptance_output="$sample_workspace/acceptance-results"
"$sample_environment/venv/bin/python" -B run_acceptance_example.py \
  --vate-root "$vate_root" \
  --environment "$sample_environment" \
  --acceptance-dir "$acceptance_originals" \
  --acceptance-verifier "$acceptance_verifier" \
  --tsa-roots "$acceptance_roots" \
  --output "$acceptance_output"
```

Success writes `ACCEPTANCE-EXAMPLE.json`: A's foreign work verdict is `pass`,
B's is `fail`, and earlier assessments and all 76 originals export unchanged.
APS records are retained as originals; they do not fill the selected MUSUBI
requirements. Inspect the third run's `acceptance/assessment.json` as follows:

| Question | Result in this fixed three-stage sequence |
| --- | --- |
| Do the selected foreign acceptance records verify and bind to A/B? | Both have `binding_status: bound` and `semantic_assessment: foreign_acceptance_verified`; the signed work verdicts are A `pass`, B `fail`. |
| Do the A/C audit and dataset bytes match their selected references? | `binding_status: bound` and `semantic_assessment: digest_linkage_checked`; this checks published byte linkage. |
| Are B's audit and dataset links established? | Both remain `not_received` in this sequence. |
| What does the native evaluator say? | Native acceptance remains `null`; C's payment still exceeds the cumulative budget. |
| Is the whole selected evidence set bound? | `partial`: B's two audit/dataset requirements and six A/B/C rail/raw-response requirements have no selected originals. |

The rail/raw-response requirements also lack supported binding rules. Supplying
files alone would not complete them. See [those requirements](CONTRACT.md#rail-and-raw-response-requirements)
before changing a selection; setting `required: false` excludes a requirement
from verification rather than making it an optional check.

The separate [B audit follow-up](ACCEPTANCE-VALIDATION.md#b-audit-follow-up)
established B's two digest links in a later assessment and retained the previous
three. It is not an additional stage run by `run_acceptance_example.py`, which
reproduces the fixed inputs above.

The database is `history/inbox.sqlite`; the third run is under `acceptance/`.
If its assessment was saved but output writing failed, recover that run with:

```bash
"$sample_environment/venv/bin/python" -B recover_output.py \
  --vate-root "$vate_root" \
  --database "$acceptance_output/history/inbox.sqlite" \
  --receipt "$acceptance_output/acceptance/RECOVERY.json" \
  --output "$sample_workspace/acceptance-recovered"
```

See the recovery section below when the receipt file could not be written.
Repeated intake reuses unchanged named materials while keeping each assessment
and acquisition manifest. Storage remains bounded; capacity refusal rolls back
the new retention batch.

## Recover saved outputs

If the database completed the assessment but export or `RESULT.json` could not
be written, the command returns 64 and prints `status: saved_output_error` with
a `recovery` object. Keep the database and the failed directory. This status
means that the assessment is saved; rerunning the receiving step would perform
another evaluation instead of repairing its output.

Fix the disk-space, destination or permission problem, or let the other database
writer release its lock first. Then use the
affected run's `RECOVERY.json` to rebuild its output into a new directory:

```bash
recovery_receipt="$sample_output/baseline/RECOVERY.json"
recovered_output="$sample_workspace/baseline-recovered"
"$sample_environment/venv/bin/python" -B recover_output.py \
  --vate-root "$vate_root" \
  --database "$sample_output/inbox.sqlite" \
  --receipt "$recovery_receipt" \
  --output "$recovered_output"
```

Use `extended/RECOVERY.json` when the second run failed. `--receipt` also accepts
`RESULT.json`, an `ERROR.json` containing a `recovery` object, or a file containing
the complete `saved_output_error` JSON printed to the terminal.
If writing `RECOVERY.json` and `ERROR.json` both failed, save
the complete terminal JSON to a file on a writable volume and pass its path.
For this failure, both `run_example.py` and `continue_example.py` print
`saved_output_error` as the top-level status. Save that whole object, including
its `recovery` member; no nested object needs to be extracted. The receipt
identifies the saved run and its selection, assessment and report digests.
`--database` explicitly selects the database, including
a preserved copy moved to another location.

Recovery checks those references against the actual stored run, receiver and
namespace. It restores `RESULT.json`, `assessment.json`, `RECOVERY.json`,
`export/`, and exact saved inputs under `materials/originals/` and
`materials/evaluation/`. It does not run the upstream evaluator, register
another receipt or advance history. Existing output directories are never
overwritten. A repeated recovery uses another new directory and leaves the same
saved run intact.

Successful recovery prints `output_recovered`. A stored refusal remains a refusal;
a stored evaluator error remains an error and returns 64 even when output
recovery succeeded. Missing or unsupported evidence remains `partial`.
`output_recovery_error` means reconstruction failed; keep the database and
receipt, fix the reported cause and retry into a new directory.

This command recovers one saved run. It does not continue an interrupted
two-run example or recreate `EXAMPLE.json`. If only that final convenience
summary failed, both runs' `RESULT.json` files remain available; use the relevant
run's file as `--receipt` if its output needs reconstruction. The wrapper's whole
`example_error` JSON is not a recovery receipt.
If the baseline was the last saved run, check its recovered result against the
expected values above, then continue with the intended header reassessment:

```bash
"$sample_environment/venv/bin/python" -B continue_example.py \
  --vate-root "$vate_root" \
  --environment "$sample_environment" \
  --database "$sample_output/inbox.sqlite" \
  --previous "$recovered_output/RESULT.json" \
  --output "$sample_workspace/continued-extended"
```

The continuation command checks the prepared Python environment, evaluator
template and fixed VATE source before running the evaluator or opening the
database. It then evaluates the new header view and checks for
`native_state: evaluated` and only the expected `anchor_depth` change from 9 to
14. A mismatch returns 64; keep any saved result and inspect the error.
`saved_output_error` retains the same recovery procedure described above.
Before evaluation, it requires the predecessor's selection reference to match
the fixed baseline. Passing an extended result a second time is rejected before
native replay, database access or output creation. The stored run is also checked
to ensure that it owns the supplied selection and assessment references.
`header_delta` compares with the fixed reference settlement; `changed_selection`
in `assessment.json` compares with the actual preceding selection.
The predecessor must still be the database's current history head. In a freshly
recovered `RESULT.json`, `inbox.run_id` equals `inbox.head` when that run was
current at recovery time. Continuation checks the database again and rejects a
changed head. Output recovery itself also works for an older completed run and
does not move the head back.

Recovery covers a reported output failure after a completed database write.
It does not repair a damaged database, make missing evidence arrive, or provide
power-loss/process-kill recovery when no usable receipt was retained.

## Verify

These commands check bindings, CLI failure handling, and actual isolated replay.
Use separate new output directories for each command. The CLI suite substitutes
only the native replay output; the integration suite executes the pinned upstream
evaluator and restores originals from an Inbox export.

```bash
"$sample_environment/venv/bin/python" -B verify_environment.py \
  --vate-root "$vate_root" --environment "$sample_environment"
"$sample_environment/venv/bin/python" -B verify.py --sample sample
"$sample_environment/venv/bin/python" -B verify_cli.py \
  --vate-root "$vate_root" --environment "$sample_environment" \
  --output "$sample_workspace/cli-check"
"$sample_environment/venv/bin/python" -B verify_recovery.py \
  --vate-root "$vate_root" --environment "$sample_environment" \
  --output "$sample_workspace/recovery-check"
"$sample_environment/venv/bin/python" -B verify_capacity.py \
  --vate-root "$vate_root" --output "$sample_workspace/capacity-check"
"$sample_environment/venv/bin/python" -B verify_continuation.py \
  --vate-root "$vate_root" --environment "$sample_environment" \
  --output "$sample_workspace/continuation-check"
"$sample_environment/venv/bin/python" -B verify.py --sample sample \
  --vate-root "$vate_root" --environment "$sample_environment" \
  --output "$sample_workspace/integration-check"
```

The unit suite includes a validly signed record from another request, ambiguous
candidates, malformed inputs and JSON-type-sensitive differences. Integration
checks changed conditions, immutable previous assessments, restoration from
export, rejection of mixed previous references, a real upstream refusal, and
output recovery following a real sandboxed evaluation. The recovery suite
injects output failures into real SQLite/Inbox operations and checks that
recovery neither calls the evaluator nor changes database bytes or history.
The continuation suite rejects changed pins before replay or database access,
then uses actual isolated replay to continue a recovered baseline. It also
checks preservation of saved-output diagnostics with an injected output failure.

The environment checks reject changed source/lock/runtime files, bytecode,
unexpected symlinks, mismatched VATE source and attempts to replace an existing
environment. They use temporary copies and do not install packages.

See [VALIDATION.md](VALIDATION.md) for the base sample's tested Python versions,
[ACCEPTANCE-VALIDATION.md](ACCEPTANCE-VALIDATION.md) for foreign acceptance and retention checks,
and [THIRD_PARTY.md](THIRD_PARTY.md) for source attribution and licenses.
