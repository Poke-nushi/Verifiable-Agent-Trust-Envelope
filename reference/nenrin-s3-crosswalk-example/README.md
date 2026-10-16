# NENRIN–VATE S3 Crosswalk Example

Compare NENRIN grant and receipt records with VATE's admitted request, execution
receipt and captured S3 read-back. The example makes eleven relationships
inspectable across three cases: matching records, different targets, and a
missing receipt. Each result keeps the original NENRIN and VATE reports beside
the cross-record findings.

Use the saved reports to inspect the submitted example without installing a
NENRIN verifier. Run the VATE replay to assess the captured inputs again. An
optional NENRIN replay accepts explicitly selected, already installed verifiers.
These commands use the recorded inputs; they do not perform a new S3 operation.

## Read or run the example

Keep this directory in a trusted checkout or source archive of the repository.
Git history and the original development directory are not required. Use
Python 3.10 or later on Linux or macOS. Commands below run from the repository
root; an absolute script path also works from another directory.

### Compare the saved records

This command needs only the Python standard library. It checks the published
file hashes, case assignments and report/input bindings, then compares the
eleven relationships. It executes no checker.

```bash
python3 -B reference/nenrin-s3-crosswalk-example/compare_records.py \
  --output /tmp/nenrin-vate-saved.json
```

The output labels both sides `saved`. `compared_at` is the time of this
comparison; the saved metadata retains the earlier checker execution times.
To inspect the files directly, start with [PROVENANCE.json](PROVENANCE.json),
the [NENRIN records](third_party/nenrin/MANIFEST.json), and the saved
[NENRIN](saved/nenrin/REPORTS.json) and [VATE](saved/vate/REPORTS.json) indexes.

### Run the VATE checker again

Use the repository's existing environment with `jsonschema==4.26.0` from
[requirements-dev.txt](../../requirements-dev.txt). The replay checks and copies
the 36 source and input files in [VATE-PINS.json](VATE-PINS.json) from the
[historical snapshot](../historical-runtime/README.md), prepares the three
cases, and invokes the fixed VATE assessor in isolated Python processes.
Those files retain the hashes recorded at `b3b6d4f9`; the current evaluator
is not substituted into this replay.
It does not install dependencies or fetch sources.

```bash
.venv/bin/python -B reference/nenrin-s3-crosswalk-example/replay_vate.py \
  --output /tmp/nenrin-vate-replay
```

Compare that new VATE run with the saved NENRIN reports:

```bash
python3 -B reference/nenrin-s3-crosswalk-example/compare_records.py \
  --vate-run /tmp/nenrin-vate-replay \
  --output /tmp/nenrin-vate-mixed.json
```

The report now labels NENRIN `saved` and VATE `fresh_local_run`, at the top level
and in every case. The new `RUN.json` records the actual invocation times,
commands, runtime, copied sources, inputs and complete outputs. It is a local
execution record, not a signed attestation. Python import isolation does not
provide an operating-system sandbox.

### Optionally run the NENRIN verifiers again

Supply Node.js 20 or later, the installed `nenrin-verify@0.5.1` npm entry file,
and a Python environment containing `nenrin-verify==0.5.3`. Replace the three
runtime paths below with your existing installations. The command checks the
distribution source hashes in [NATIVE-PINS.json](NATIVE-PINS.json) before use;
it never calls an installer or `npx`.

```bash
python3 -B reference/nenrin-s3-crosswalk-example/replay_native.py \
  --node /absolute/path/to/node \
  --npm-entry /absolute/path/to/nenrin-verify/nenrin_verify.mjs \
  --python /absolute/path/to/nenrin-python/bin/python \
  --output /tmp/nenrin-native-replay
```

Use `--native-run /tmp/nenrin-native-replay` with `compare_records.py` to select
these six new local runs. It can be combined with `--vate-run`; omitting either
option selects that side's saved reports. The NENRIN CLI's default
`require_signatures=true` remains in effect. The missing-receipt case does not
reach its pair-signature check.

Every output path must be new, with an existing parent directory, and outside
this published example. Replays retain captured `.out` and `.err` files in the
selected output directory: `preparation.*` for VATE preparation, `checks/` for
runtime probes, and `results/` for case checks. A timeout writes a sibling
`.timeout.json` diagnostic with
`status: timed_out` and a null exit code, then stops before creating `RUN.json`.
Use these files to inspect a failed replay and choose another path for the next
attempt. Replays return exit code 0 when the expected case results were recorded,
including the deliberate refusals.
Comparison returns 0 when it writes a report, including mismatch findings.
Invalid inputs or an unusable output path return 64. Read the case findings
before interpreting a successful command exit.

## Interpret the results

The NENRIN records are a retrospective synthetic reconstruction: they were
derived and signed with public test keys after the original PUT, using its
existing captures. They do not establish that a NENRIN grant existed before
that PUT or add an independent observation of it.

The saved results are:

| NENRIN / VATE case | NENRIN npm and PyPI verdict | VATE assessment | Cross-record findings |
| --- | --- | --- | --- |
| `match` / `matching` | `accepted` | `supported_under_local_assumptions` | CW-01–11 `matched` |
| `target_mismatch` / `target-mismatch` | `refused` | `contradictory` | CW-03 and CW-06 `mismatched`; other rows `matched` |
| `missing_receipt` / `missing-post` | `refused` | `insufficient` | CW-01–10 `not_assessed`; CW-11 byte/metadata bindings `matched` |

Rows contain separate component findings and source references. A missing
receipt leaves dependent comparisons `not_assessed`; independently readable
mismatches remain visible. There is no combined protocol verdict.

The target case contains two distinct mutations. NENRIN changes the receipt
target to `result-other.txt` while retaining the grant. VATE changes the GET
request key to `other.txt` while retaining its effective request. CW-06 checks
both relationships and the exact object version. Equal bodies or version IDs
do not make different targets equal.

Four digest bases stay separate:

| Row | Bytes or object being hashed |
| --- | --- |
| CW-04 | The complete nine-field VATE effective-request object, using VATE's sorted, compact, ASCII-escaped fixture JSON |
| CW-05 | Raw PUT and GET body bytes |
| CW-07 | The structured VATE result projection, including target, version, body digest and byte length |
| CW-09 | The NENRIN action object using `musubi-canonical-v0`, distinct from its `args_sha256` |

CW-07 can match in the target-mismatch case because it compares a projection
built from the effective request. It does not override CW-06 or the native
`post_observation_binding` and `evidence_bound_unchecked` findings. CW-08
preserves six fractional-second digits and checks the complete PUT interval
using integer microseconds. The native NENRIN reports retain their millisecond
window comparison.

CW-11 binds the selected input/output bytes to their metadata. Saved indexes
retain the original execution times and input/output fingerprints. A
`fresh_local_run` records a separate local replay. Saved indexes use distinct
schemas from new `RUN.json` files.

Every native report is retained as its complete parsed object and `raw_utf8`.
Encoding `raw_utf8` as UTF-8 recovers the original stdout bytes, including
whitespace. Native vocabulary, nulls, array order, verifier versions and
unchecked responsibilities are preserved. The original stderr bytes remain
in the saved or selected replay directory.

## Test and inspect the sources

Run the focused tests without installing the native verifiers:

```bash
python3 -B -m unittest discover \
  -s reference/nenrin-s3-crosswalk-example/tests -p 'test_*.py' -v
```

Tests cover the digest and target distinctions, missing inputs, microsecond
windows, strict types, wrong-case reports, modified sources, reused output
paths, path traversal and symlinks. Synthetic test records are marked as test
harness data and cannot produce a final comparison report.

The implementation uses these fixed versions:

| Source | Pin |
| --- | --- |
| VATE sources and captures | `b3b6d4f9610e159e92d3b41b66e72fc7251758dc` |
| NENRIN submitted records | `bfde94be9d8089b7c683bc31b9c39c3879b07ab2` |
| npm / PyPI distributions | `nenrin-verify@0.5.1` / `nenrin-verify==0.5.3` |
| Native output `verifier_version` | `0.1.6` |

[SOURCES.json](SOURCES.json) lists original paths, raw hashes and byte lengths
for the redistributed data. Source drift causes refusal; the scripts do not
silently select a newer pin. The exact submitted bundles and manifest are
under `third_party/nenrin/`. The
[upstream generator](https://github.com/ogasurfproject-jpg/horizon-shield/blob/bfde94be9d8089b7c683bc31b9c39c3879b07ab2/workers/hs-ledger/nenrin/vate-s3-v0/gen.mjs)
remains at its fixed commit.

## Scope and acknowledgements

This is a three-case interoperability review aid for recorded NENRIN and VATE
artifacts. It leaves both checkers' meanings and the VATE schemas and corpus
unchanged. The receiver policy remains an external input that accepts this
example's local collector and store. No target equality or digest match
establishes signer authority or maps NENRIN identities to VATE actors.
Neither comparison nor replay grants
execution or retry permission; every VATE result retains
`retry_authorized: false`.

The results do not establish general compatibility, production readiness, or
an external SUT conformance result. See the existing
[S3 observation contract](../s3-observation-example/CONTRACT.md) and
[public claim boundary](../../docs/public-claim-boundary.md) for their scopes.

Thanks to **ogasurfproject-jpg / The HORIZONs Co., Ltd.** for the NENRIN records,
generator, native outputs and technical discussion in
[VATE #84](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/84).
The VATE maintainer reproduced the six saved NENRIN outputs; their bytes match
the fixed upstream outputs. Redistribution preserves the upstream
[MIT license](third_party/nenrin/LICENSE). VATE code and materials use
[Apache-2.0](LICENSE). [PROVENANCE.json](PROVENANCE.json) records the source and
license attribution and the origin of the saved records.
