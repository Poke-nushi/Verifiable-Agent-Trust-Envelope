# Execution Evidence Demo

Run one local file-set operation and trace its VATE admission decision through
the execution gate, the bytes received by a separate provider process, the
actual files, and generated receipts. The demo also preserves an unknown result
after response loss and resolves it through a read-only provider query.

## Run and inspect

From the repository root, using Python 3.10 or later on macOS or Linux:

```bash
python3 -B reference/execution-evidence-demo/run_demo.py --output-name review-run
```

Each scenario gets a new directory under `reference/execution-evidence-demo/generated/review-run/`.
Generated data is ignored by Git. Choose a different output name for another
run; existing directories are never reused. Use `--case allow` to run one case.
The runner uses the Python standard library and starts only one-shot local
provider processes. Git is optional: if it is unavailable or cannot report a
commit, `source.json` records `base_commit: null` and still includes source-file
digests for byte verification.

Verify a captured case without changing it:

```bash
python3 -B reference/execution-evidence-demo/verify_evidence.py reference/execution-evidence-demo/generated/review-run/allow
```

Run the regression and semantic mutation tests:

```bash
python3 -B -m unittest discover -s reference/execution-evidence-demo -p 'test_*.py' -v
```

The schema test uses the repository's existing `jsonschema` development
dependency when available; otherwise that test reports a skip. With that
environment, add `--strict-schema` to the verification command to validate the
generated requests and receipts against the existing VATE schemas as well.

## What to look for

| Scenario | Observation to inspect |
| --- | --- |
| `allow` | `summary.txt` contains exactly the admitted UTF-8 text; the provider's received bytes match the dispatch. |
| `deny` | A revoked local permit produces a core denial; the gate is closed, the provider journal is empty, and no output exists. |
| `attenuate` | The original request includes `details.txt` and `summary.txt`; only the unchanged `summary.txt` file is admitted and created. |
| `swap-content`, `swap-destination` | A candidate changed after admission is stopped before the provider is invoked. |
| `require-new-permit` | The narrowed input is retained, but the admission does not permit immediate handoff. |
| `response-loss` | Files and a provider record exist, but the controller receives no response, retains an indeterminate attempt, and blocks a new permit for the same operation. |
| `response-loss-reconciled` | A read-only query returns the original provider evidence; the controller issues a terminal receipt for the original attempt. The earlier unknown observation remains. |
| `missing-evidence`, `tampered-evidence` | Controlled removal of the native result or modification of an output after capture is detected. Neither yields a successful or unexecuted outcome. |

These are demonstration scenarios, not additional conformance-corpus cases.
Assertions live in the tests; expected receipts are never copied into generated
output. `fault-injection.json` records a deliberate fault, not a verification
exception.

## Read the evidence

Start with `verification.json`, then follow these artifacts:

1. `inputs/original-operation.json`, `policy.json`, and `admission-1/permit.json`
   define the operation and the controller-owned local authority inputs.
2. `admission-1/` retains the VATE request, unmodified core result, demo-issued
   admission receipt, explicit effective input, and decision record.
3. `adapter/gate-1.json` records the checks reached and embeds the provider/sandbox
   state observed before them. `adapter/after-dispatch-snapshot.json` retains the
   subsequent state, including after a refusal. For an opened gate,
   `adapter/dispatch.json` and `provider/received.bin` contain the exact sent and
   received wire bytes.
4. `provider/native-result.json`, `provider/invocations.jsonl`, and `sandbox/`
   provide the provider originals and actual file contents. The adapter's
   post-execution receipt is a separately identified projection of this evidence.
5. `adapter/attempt-observation.json`, a second admission and gate when present,
   and query/reconciliation records explain retry eligibility and later findings.

`manifest.json` binds raw artifact bytes and labels their roles. `source.json`
contains source-file digests and producer-reported base commit and Python version.
The verifier compares the source digests with the current source files; keep the
exact source tree with a capture when moving or revisiting it. A base commit
alone does not identify uncommitted source changes.

Both recording and verification require the same 12-file reference-package
snapshot in `demo_contract.REQUIRED_SOURCE_FILES`: the six demo Python files
(including the test suite), this README and CASE-CONTRACT, the core Python file,
and the three admission/post-execution schemas. Tests and documentation belong
to this provenance snapshot even though they are not all runtime dependencies.
Missing source files cannot be omitted from the record. Extra files on disk do
not automatically enter this fixed set; missing or extra `source.json.files`
entries fail verification. Extending the snapshot requires an explicit contract
change. See [the source contract](CASE-CONTRACT.md) for the verification boundary.

The verification report separates `provenance.source_content` from
`provenance.producer_claims`. A source-byte match does not authenticate the
reported historical commit or Python environment. Those claims remain
`unverified`, including when the rest of a capture is `verified`; the reader
does not compare them with its own environment as proof of past execution.
New captures omit the Python executable's local absolute path.

The verifier returns `verified` for a consistent completed or closed-gate case,
`indeterminate` for a still-unresolved controller observation, `incomplete` for
missing required evidence, and `invalid` for altered or inconsistent evidence.
Its exit codes are respectively `0`, `2`, `2`, and `1`. The suite runner exits
`0` when it finishes producing its cases, including intentional fault cases.
The saved verification is a convenience: re-running the verifier recomputes the
result and never trusts `verification.json` as input.

The checks bind the native reference to its retained raw bytes, enforce the
documented local observation order, validate execute/query process records,
and reject subdirectories in the flat provider and output namespaces, including
empty directories. The tests also cover process-start failures that keep the
outcome unknown and the retry gate closed.

The live adapter and reader share the native success checks for shape, contract,
dispatch linkage, journal events, execution times, and actual files. Numeric
fields are checked before equality comparisons: booleans are not exit codes or
byte sizes. Zero-byte files are valid; an unavailable exit code remains `null`.
Retained native records use the same field types and digest grammar: digest
descriptors have exactly `alg: sha-256` and a 64-character lowercase hexadecimal
value; file names are safe, sorted and unique, and the native outcome is
`success`.

They also share response acceptance checks. Exit code `0` with a truncated or
unrelated response preserves a recorded unknown attempt; a later matching query
can resolve that same attempt. Unusable query responses leave it unknown. The
reader still rejects invalid native originals and invented response-failure claims.
If a JSON value exceeds the Python runtime's parsing or encoding nesting limit,
the reader reports invalid input and the adapter preserves an unknown query
result. It saves the reconciliation record, issues no post receipt, and keeps
retry closed. The demo does not change the runtime's recursion limit.

When files appear before the gate, a correct refusal preserves them. The reader
compares the embedded gate snapshot, after-refusal snapshot and actual bytes.
Its observed-file list includes those files, while `not_started` and execution
count `0` describe this operation. Changing files after refusal invalidates that
capture even if its manifest is regenerated.

The reader also checks any retained demo execution originals in a refusal.
Records for this same operation contradict `not_started`; missing originals
needed to attribute a retained execution leave the capture incomplete. Consistent
records for a different operation, observed before the gate, remain preserved
without being counted as this operation's execution. Their native output names,
UTF-8 byte sizes and content digests must exactly match the complete list derived
from the retained received text. Older output bytes may have been legitimately
edited before this gate; the expected list comes solely from that received text.
The known journal event
names `execute_received` and `completed` remain execution evidence cues even
when their attempt or digest fields are missing; removing those fields cannot
turn missing attribution evidence into zero calls.
Recognition reads every top-level `event` member, including duplicates, without
converting unrelated numeric values. The same recognition parser checks known
contracts and current-operation references in received/native originals. Floats,
out-of-range integers and malformed fields cannot erase these cues. This does not
accept them as contract JSON: the original bytes still undergo strict validation.
Unclassifiable JSON objects or recognition nesting failures leave the capture
invalid. Ordinary text and unrelated diagnostic records remain preserved.
Recognition follows the standard library's UTF-8/16/32 byte decoding, including
BOMs. After a decoding failure, replacement text is used only to identify an
unclassifiable object and report invalid evidence; it is never accepted as a
record. Journal recognition finds CR/LF at the detected character-unit width,
preserving ordinary diagnostic text and Unicode characters inside strings.

## Observation boundary

This is a local reference demonstration of one sequential operation. The core
is reused unchanged for admission checks, receipt construction, and
post-execution linkage. File-set narrowing, the execution gate, retry state,
provider observation, and file-effect checks are demo-local contracts described
in [CASE-CONTRACT.md](CASE-CONTRACT.md).

The controller, verifier, and provider are trusted local code under one owner.
They use unsigned permits and receipts. Digest checks establish content
relationships; they do not authenticate issuers or establish independence.
The demo does not claim production execution safety, crash recovery, concurrent
or distributed idempotency, or external-SUT validation. See the repository's
[public claim boundary](../../docs/public-claim-boundary.md).
