# OAuth permission changes and VATE receipt linkage

Reproduce how user-permission and delegation changes affect the same OAuth
token. This ten-case trial uses Ory Hydra for OAuth and OpenFGA for policy
checks, exposing the inputs, policy updates, Check results and fixture action
counts for comparison with another implementation.

The optional VATE example links each permitted action to its admission and
result records. A receiver distinguishes a substituted result, another
internally valid record pair, and a result that has not arrived. Late delivery
adds an assessment while preserving the earlier assessment and its evidence.

## Choose a package

| Package | What you can reproduce | Requirements |
| --- | --- | --- |
| [OAuth trial](https://vate.rognalia.com/downloads/oauth-persisted-grant/2026-11-10/oauth-persisted-grant-trial-20261110.zip) | Ten real Hydra/OpenFGA cases; VATE is not required | Python 3.13+ and two pinned executables; Python standard library only |
| [OAuth + VATE example](https://vate.rognalia.com/downloads/oauth-vate-linkage/2026-11-10/oauth-vate-linkage-example-20261110.zip) | The same trial, three receipt pairs, receiver checks and retained Inbox history | Native run: OAuth requirements plus the five packages in `requirements.lock`. Saved-evidence replay: Python and those five packages; no native executables |

Both packages include saved synthetic evidence, expected results, source code,
payload hashes and an Apache-2.0 license. The combined package includes the
required VATE sources; no separate repository checkout is needed. Native
executables and Python environments are installed separately and retain their
own licenses.

The [OAuth package identity](oauth-persisted-grant-trial.package.json) records
28,876 bytes / 17 files; the [combined package identity](oauth-vate-linkage-example.package.json)
records 339,097 bytes / 162 files. Each records the ZIP and manifest hashes.

## Download and verify

Use a new directory and choose one of these commands. Extraction runs only
after the downloaded bytes match the fixed SHA-256.

OAuth trial:

```sh
curl --fail --location --remote-name https://vate.rognalia.com/downloads/oauth-persisted-grant/2026-11-10/oauth-persisted-grant-trial-20261110.zip &&
python3 -I -S -c 'import hashlib,pathlib,sys; p=pathlib.Path("oauth-persisted-grant-trial-20261110.zip"); sys.exit(0 if hashlib.sha256(p.read_bytes()).hexdigest()=="8a4891bdc10bf33f7e8b265264f6586edf17d604c20142b50f005b9d0b25921d" else "ZIP digest mismatch")' &&
unzip oauth-persisted-grant-trial-20261110.zip &&
cd oauth-persisted-grant-trial-20261110
```

OAuth + VATE example:

```sh
curl --fail --location --remote-name https://vate.rognalia.com/downloads/oauth-vate-linkage/2026-11-10/oauth-vate-linkage-example-20261110.zip &&
python3 -I -S -c 'import hashlib,pathlib,sys; p=pathlib.Path("oauth-vate-linkage-example-20261110.zip"); sys.exit(0 if hashlib.sha256(p.read_bytes()).hexdigest()=="5c0a1d884c299b323262d79477180fd56d589e22bad29cf515cb025afea8f41e" else "ZIP digest mismatch")' &&
unzip oauth-vate-linkage-example-20261110.zip &&
cd oauth-vate-linkage-example-20261110
```

Run subsequent commands from the extracted directory. Check payload integrity
and the six offline tests of archive extraction, changed bytes and destination
handling:

```sh
python3 -B verify_package.py &&
python3 -B test_package.py -v
```

## Replay saved VATE evidence

In the combined package, create a local environment with the exact wheel
versions and hashes:

```sh
python3 -m venv .venv &&
.venv/bin/python -m pip install --only-binary=:all: --require-hashes -r requirements.lock
```

Replay the two assessments from the included export without starting Hydra or
OpenFGA:

```sh
.venv/bin/python -B vate/replay.py --export evidence/vate/receiver/history/export-after --selection evidence/vate/selection.json
```

Expected: revisions 1 and 2 report `unresolved` and
`matched_under_local_collector_assumption`, with
`exact_saved_assessment_match: true`. This recomputes the dedicated OAuth
reader's report, including linkage between saved native observations and VATE
receipts. It does not independently
recompute Inbox's whole snapshot-selection algorithm or generic report.

Recipient Inbox stores receiver assessments and their evidence as a retained
history. The included export preserves both assessments and their referenced bytes.
The live SQLite database is omitted. Each reader report records the reader
source SHA-256; replay refuses a different reader identity, so retain this
package with the export.

## Run new native cases

Download the official Ory Hydra **26.2.0** and OpenFGA **1.22.1** archives and
verify their fixed hashes before extraction:

```sh
python3 -B setup_native.py --download
```

This creates `native/bin/` and `native/BINARY-PINS.json`; the runner checks
executable hashes before launch. The package README also covers offline
archive setup. Pins are supplied for macOS arm64/x86_64 and Linux arm64/x86_64;
execution was tested on **macOS arm64 with Python 3.14.8**. Other targets remain
unexecuted for this package. Linux uses the glibc, SQLite-enabled Hydra build.

These development-mode services run as native child processes with listeners
bound to `127.0.0.1`, synthetic identities and temporary credentials. They are
not a VM or an OS sandbox. Use a machine suitable for local test services. The
runner stops its own processes and discards its temporary database and
credentials on normal completion or handled failure.

Choose a new output directory. Either package can run the OAuth trial:

```sh
python3 -B oauth/run_trial.py --native-root native --output runs/oauth-new
```

Success exits with code 0 and reports `all_matched: true`, ten cases, three
fixture actions and stopped child processes. `RESULT.json` contains each
expected/observed value; `EVENTS.json` records the native HTTP observations.

| Cases | Expected observation |
| --- | --- |
| 01, 02, 05 | Initial permit, user-permission revocation denies the same token, restoration permits it |
| 03, 04 | AS credential cannot write user permission through the adapter or bypass it to write directly to OpenFGA |
| 05b, 05c, 05d | Delegation revocation denies; owner credential cannot restore delegation; AS restoration permits |
| 06 | Active-token introspection succeeds, then a stopped PDP causes denial |
| 07 | Revoked token is inactive; denial occurs without a PDP call |

`EXPECTED.json` defines the array fields for each case. Nested checks are
ordered **delegation, user_permission**. Permission changes affect the next
request without issuing a replacement token; the checks are sequential.

Each request must pass token validation and **both** policy checks:
`delegation AND user_permission`. The AS credential may update delegation but
must not update user permission or bypass the policy administration adapter.
The owner credential must not update delegation.
Changes to delegation cannot authorize an action rejected by the independent
user-permission check. Reproductions must preserve this conjunction and these
writer restrictions.

In the combined package with its Python environment prepared, run the same
ten native cases with VATE linkage:

```sh
.venv/bin/python -B vate/run_linkage.py --native-root native --output runs/vate-new
```

The result includes three receipt pairs and these receiver outcomes:

| Input | Receiver result |
| --- | --- |
| Selected operation and its result | `matched_under_local_collector_assumption` |
| Another operation's post-execution record | `mismatch` with native binding failures |
| Another internally valid complete pair | `mismatch` against the selected operation |
| Result not supplied | `unresolved` |
| Result delivered after the first snapshot | A new matched assessment; the old unresolved assessment is retained |

`receiver/history/export-after/` holds both revisions and their evidence.
The package README includes commands for the 33 linkage regression methods
and explains which expiry/storage checks use mocked native responses.

## Interpret and compare results

The trial selects persisted-grant mode explicitly. Its `calendar.read` token
scope does not create user permission or select transient-grant mode.
Subjects are fixed for one user, client and action. Hydra performs code/S256
PKCE, introspection and revocation; OpenFGA performs real Check/Write calls.
These cases do not model parent grants or revocation along an agent delegation
chain.
Login/consent, the calendar action and the policy administration adapter's
credential/namespace rules are fixture code.

VATE records the allow path, with an admission start gate and a maximum
60-second window bounded by token expiry. The reader checks recorded
execution times. Records are unsigned and rely on the selected local
collector; digests and local HTTP observations do not establish issuer
authority or independent execution observation. Inbox uses an empty generic
requirement set plus the dedicated OAuth assessment. Its `completed` status
means assessment processing completed. Missing results remain unresolved;
later delivery never authorizes execution or retry.

Use case IDs, expected/observed values and HTTP events to compare another
implementation, recording its version and policy mode. This is an
interoperability review aid, not production-ready software or a general
OAuth/AuthZEN compatibility result. AuthZEN wire conformance, generic subject
derivation, transient grants, concurrent-update atomicity, crash durability,
and real calendar operations are outside the tested scope.

The combined package pins VATE sources to
[`ccaba140edc2f7afc9b15bcbdb1281ff12690360`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/ccaba140edc2f7afc9b15bcbdb1281ff12690360).
Official native releases:
[Hydra 26.2.0](https://github.com/ory/hydra/releases/tag/v26.2.0),
[OpenFGA 1.22.1](https://github.com/openfga/openfga/releases/tag/v1.22.1).
The package manifest is a local integrity check, not a signature.
