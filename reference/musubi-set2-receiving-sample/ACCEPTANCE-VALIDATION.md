# Foreign acceptance and retention validation

Local verification on 2026-10-24 for `hs51-war-bindings-v0-1` and repeated
retention in the MUSUBI sample. The fixed VATE source files remain those in
`vate-source.json`; no Inbox core limits or native MUSUBI semantics changed.
The external records, verifier and trust roots are identified in
[ACCEPTANCE-CONTRACT.md](ACCEPTANCE-CONTRACT.md) and the example's source pins.

## Acceptance checks

| Platform | Python | Record checks | Receiver binding checks |
| --- | --- | --- | --- |
| macOS arm64 | 3.11.14 | 53 tests / 138 evaluations, pass | 18 tests, pass |
| macOS arm64 | 3.12.15 | 53 tests / 138 evaluations, pass | 18 tests, pass |
| macOS arm64 | 3.13.3 | 53 tests / 138 evaluations, pass | 18 tests, pass |
| macOS arm64 | 3.14.8 | 53 tests / 138 evaluations, pass | 18 tests, pass |
| Linux x86_64 | 3.11.15 | 53 tests / 138 evaluations, pass | 18 tests, pass |
| Linux x86_64 | 3.12.15 | 53 tests / 138 evaluations, pass | 18 tests, pass |
| Linux x86_64 | 3.14.8 | 53 tests / 138 evaluations, pass | 18 tests, pass |

The Linux checks ran in existing pinned container images with networking
disabled. On every platform in the table, the 18 receiver binding tests use
saved native output as a test double. The record checks exercise the supplied
signed records; neither column is a full native MUSUBI replay. Python 3.13 was
exercised on macOS only. The separate full replay is described below.

The record suite verifies the actual signed MUSUBI A/B records and rejects APS
records or a different occurrence in their place. It covers signature and
digest tampering, selected-checker authority, criteria aggregation, timestamp
imprints and trust roots, input bounds, JSON ambiguity and Unicode handling.
Every returned result round-trips through the actual receiver JSON decoder.
Sub-millisecond timestamp accuracy is retained as decimal text.

Real DER mutations combine an unsupported timestamp signature algorithm with
a separate broken signature or mismatched imprint. An unsupported algorithm
alone stays `unsupported`; a separately established failure stays `rejected`.
Injected evaluator exceptions remain evaluator errors, including after output
recovery. Such fault injections are defensive tests, not observed failures of
the fixed upstream evaluator.

The receiver suite uses fixed native output as a test double. It checks explicit
profile selection, prerequisite records, exact original bytes and expectations,
missing/ambiguous/unselected records, failed native evaluation and error status
propagation.

## Actual replay and history

The full baseline → A/C audit → foreign acceptance example ran on macOS arm64
with the prepared Python 3.14.8 runtime. Both upstream execution paths ran in
the existing sandbox with network and Keychain access denied. It retained A's
foreign `pass` and B's foreign `fail`, restored all 76 original files exactly,
and preserved both earlier assessments. The native output remained byte-identical
to the fixed settlement, with native `accepted: null`; the required-evidence
state remained `partial`.

Independent recovery checks used actual Inbox/SQLite storage and the recovery
CLI for a normal acceptance result and an injected evaluator failure. They
restored the saved assessment bytes and retained the previous evaluations.
Database bytes and history heads did not change. Recovery of the saved evaluator
failure returned `output_recovered`, `saved_status: recorded_evaluator_error`
and exit code 64.

## B audit follow-up

A separate local check on 2026-10-24 added the [B audit original](https://github.com/ogasurfproject-jpg/horizon-shield/blob/c824cbe61a383e57f1d9d15fea962a79f5b6bbd5/workers/hs-ledger/nenrin/musubi-v0/ca2a-companion-v0/pilot51/set2/audit_B.json)
to a copy of the completed three-stage Inbox. Its source commit is
`c824cbe61a383e57f1d9d15fea962a79f5b6bbd5`, distinct from the fixed example's
earlier pins. The 1,101 bytes have raw SHA-256
`40bc2a46f428b2cc5000e9d5e896adac218ebe3c2b76f78ba29afebf97887aea`, matching
B's execution `outcome.response_sha256`. The declared dataset digest matches
the saved souba-db 2.3.0 bytes, raw SHA-256
`7b16600e50ed73b844ff5b2718f04a6dd4d9ace0367982fb8d139db509d023fd`.

The unchanged adapter ran actual native evaluation on macOS arm64 / Python
3.14.8. B's audit and dataset links changed to `bound` /
`digest_linkage_checked`; the earlier three assessments and original database
rows were preserved. All 77 originals exported exactly. Native stdout remained
byte-identical, foreign work verdicts remained A `pass` / B `fail`, and native
acceptance remained `null`.

The same 24 requirements had 17 bound, six `not_received` and one `not_selected`
after the addition, compared with 15, eight and one before it. The six remaining
slots are A/B/C `rail_original` and `raw_response`; the aggregate stays `partial`.
Their empty inputs and unsupported binding rules are distinct from the two
successful B digest checks. These counts do not establish actual runtime use
of the dataset, audit quality, a transfer or overall experiment success.

Five additional binding checks used the actual originals and saved native
output: absent B audit, A audit substituted for B, a one-byte audit change, a
one-byte dataset change, and A execution substituted for B. None promoted the
affected links. These were five binding checks, not five native executions.
The earlier cross-platform matrix was not rerun for this unchanged-code intake.

This follow-up is a validation record, separate from the distributed
`run_acceptance_example.py` sequence. That command retains its original three
stages, 76 originals and B-audit absence; it does not fetch the later B source.

## Retention checks

The capacity suite exercises nine case groups against the actual Inbox. Repeated
intake reuses the same named bytes while different paths, namespaces and changed
bytes remain separate. Acquisition manifests and assessment history remain
recoverable. The synthetic incremental sequence uses 73 → 77 → 82 → 83 entries.
An earlier-format database is also reused without rewriting its old rows.

Entry, snapshot, byte-read and native-call capacity failures roll back the whole
new retention batch. Faults after run preparation and SQLite transaction rollback
leave the prior database state unchanged. The core bounds, including 256 entries
per namespace, remain enforced. This does not provide unlimited history or
compact a database already filled by an older partial write.

All nine capacity groups passed on macOS and on Linux x86_64 with Python
3.12.15 and 3.14.8. The Linux runs used existing, hash-pinned validation wheels
inside disposable containers with networking disabled.

The repository's portable sample check passed the 27 base binding tests,
18 CLI cases, 37 output-recovery cases, 21 audit unit tests, audit storage checks and nine
capacity groups. Native replay is substituted only where the individual suite
declares that scope; the separate full replay above uses the actual sandbox.

## Reproduce the record and binding checks

After saving the separately supplied originals, verifier and vectors described
in the README, arrange the explicit evidence directory as follows. The two
context files are already distributed with this sample.

| Path below the evidence directory | Source |
| --- | --- |
| `sources/context/bundle.json` | `sample/originals/workers/hs-ledger/nenrin/musubi-v0/ca2a-companion-v0/pilot51/set2/bundle.json` |
| `sources/context/audit-selection.json` | `sample/audit-selection.json` |
| `sources/acceptance/hs51-musubi-2-A.json`, `hs51-musubi-2-B.json`, `hs51-aps-A.json`, `hs51-aps-B.json` | Four pinned originals linked from the README. |
| `sources/war/verifier/war_verify.py` | Pinned verifier linked from the README. |
| `sources/war/vectors/31-tsa-freetsa-verified.json` and `32-tsa-digicert-verified.json` | Pinned vectors linked from the README. |

The test harness checks the raw source and fixture hashes before use. It does
not download dependencies, create signatures or change those input files.

The repository's MUSUBI CI job runs both suites on Linux with Python 3.11–3.14.
Its `scripts/prepare_musubi_acceptance_tests.py` preparation step fetches the
seven pinned external files over HTTPS and copies the two distributed context
files into a new evidence directory, checking all nine raw hashes before writing.
The test commands then use those saved files. They exercise record signatures
and receiver bindings; native MUSUBI output is substituted in the binding suite.

```bash
acceptance_test_data="$sample_workspace/acceptance-test-data"
"$sample_environment/venv/bin/python" -B verify_acceptance.py \
  --evidence-root "$acceptance_test_data"
"$sample_environment/venv/bin/python" -B verify_acceptance_integration.py \
  --evidence-root "$acceptance_test_data"
"$sample_environment/venv/bin/python" -B verify_capacity.py \
  --vate-root "$vate_root" --output "$sample_workspace/capacity-check"
```

The first two suites are portable. Actual isolated native replay still requires
macOS and the prepared runtime described in the README. Intel macOS and Windows
were not exercised in this validation. These results do not re-evaluate the B
audit, check current certificate revocation or establish general PKI compatibility.
