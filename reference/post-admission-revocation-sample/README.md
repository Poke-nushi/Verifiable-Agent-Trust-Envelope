# VATE post-admission runtime-key revocation sample

Run a local demonstration of what happens when a runtime key is revoked after
VATE has allowed an operation. The sample preserves the original `allow`, checks
signed key status before the provider accepts work, and exports evidence that a
separate reader can check.

The operation creates two small text files. Eight scenarios cover revocation
before and after acceptance, partial effects, a lost response, conflicting status,
and a repeated signature. This is a single-provider technical sample with
disposable test keys and a fixed clock. See [CONTRACT.md](CONTRACT.md) for the
decision rules and evidence limits.

## Prepare an environment

Use **CPython 3.11–3.14 on macOS or Linux**, with the `openssl` command available
on `PATH`. The sample uses Python's standard library, including SQLite and POSIX
file locks. No Python package installation is required. Windows is not supported
by this sample. Exact tested combinations are in [VALIDATION.md](VALIDATION.md).

Extract the entire distribution into a fresh folder; keep `sample/` and
`reference/` together. Do not overlay it onto an older copy.
Run the following from that folder. The examples use an existing Python 3.12;
substitute another version in the range above if needed.

Choose a work directory outside the distribution. For a quick temporary run:

```sh
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/vate-revocation.XXXXXX")"
```

For a record you want to keep, use a new permanent directory instead. Replace
the example path with your chosen location before running this alternative:

```sh
work_dir="/absolute/path/to/new-vate-revocation-work"
mkdir -m 700 "$work_dir"
```

Then prepare the virtual environment and check the distribution:

```sh
python3.12 -E -s -B -m venv --without-pip "$work_dir/venv"
sample_python="$work_dir/venv/bin/python"
"$sample_python" -E -s -B check_environment.py
```

Keep these shell variables in the same terminal for the commands below. The
environment and results live outside the distribution. `-E -s -B` ignores Python
environment settings and user packages, and avoids writing bytecode. Nothing is
downloaded by these commands. If Python, its `venv`/SQLite modules, or OpenSSL are
missing, provision those tools using your platform's normal installation method
before continuing.

The check must return `"status": "ok"`. It verifies the 16 source/document files
against `SOURCE-MANIFEST.json` and reports the selected tools. This detects
missing or changed files relative to the supplied manifest; it does not establish
who published the manifest or replace execution tests. Unlisted Python modules,
packages, bytecode caches, and native modules are rejected to prevent leftover
code from an earlier extraction being imported. If that check fails, extract a
fresh copy and use the commands above. Non-importable notes and OS metadata are
not checked as source files.

## Run all eight scenarios

```sh
run_dir="$work_dir/run"
"$sample_python" -E -s -B sample/run_demo.py run --out "$run_dir"
```

`run_dir` must not exist yet. A new run creates new synthetic operations; it is
not a recovery command for an earlier run. The program temporarily generates
P-256 test keys, signs test status and requests, and deletes the private-key
files when the run finishes. It does not use Keychain or any existing signing
key. No external provider is contacted.

The result is printed and saved as `SUMMARY.json`. Each scenario folder contains
`RESULT.json`, `evidence.json`, the selected public inputs, a store anchor, a
SQLite database, and observed output files. Keep the work directory in place if
you want to inspect the run later. The temporary-directory option is for a
disposable local trial.

| Scenario | Accepted | Files observed | Query outcome |
| --- | --- | ---: | --- |
| `active` | yes | 2 | `effect_observed` |
| `revoked-before` | no | 0 | `not_accepted` |
| `revoke-after-pull` | no | 0 | `not_accepted` |
| `revoke-after-accept` | yes | 2 | `effect_observed` |
| `partial-effect` | yes | 1 | `unknown` |
| `lost-response` | yes | 2 | `effect_observed` |
| `expired-conflict` | no | 0 | `not_accepted` |
| `same-input-resigned` | yes | 2 | `effect_observed` |

`not_accepted` records a local provider outcome; it does not erase the earlier
VATE `allow`. `unknown` retains uncertainty, including a partially completed
operation. Revocation after acceptance does not cancel work already accepted.

The clock starts at 2026-10-23 00:00 UTC for each scenario. Signatures and store
identifiers can differ across runs, so compare the outcomes and bindings rather
than expecting identical evidence hashes.

## Inspect an existing run without repeating its effects

In the same terminal, continue with the variables above. In a later terminal,
return to the distribution folder and set the variables to the original saved
work directory. Do not create a new run to recover the old one:

```sh
work_dir="/absolute/path/to/the-original-work-directory"
sample_python="$work_dir/venv/bin/python"
run_dir="$work_dir/run"
```

Query a saved case:

```sh
"$sample_python" -E -s -B sample/run_demo.py query "$run_dir/lost-response"
```

Export its saved evidence to a new file:

```sh
"$sample_python" -E -s -B sample/run_demo.py export "$run_dir/lost-response" --out "$work_dir/reexport.json"
```

Check that export using the separately retained public selection and store
anchor:

```sh
"$sample_python" -E -s -B sample/read_evidence.py "$work_dir/reexport.json" --selection "$run_dir/lost-response/selection.json" --anchor "$run_dir/lost-response/anchor.json"
```

The reader returns `"verified": true` and `"outcome": "effect_observed"` for this
case. A verified record can also describe `unknown` or `not_accepted`: verification
of the record and success of the operation are different results. For an export
received from someone else, select the expected keys and anchor independently;
accepting whatever selection accompanies the export does not establish trust.

Use `query` and `export` after an interrupted response or failed export. They
read saved state and do not resubmit the operation. `query` returns exit code 2
for `unknown`. `query` and `export` also return JSON with exit code 2 when local
evidence is unavailable. A successful export returns 0 even if the saved outcome
is `unknown`. The reader returns 0 when its evidence checks pass; that does not
turn an unknown outcome into success.

The store anchor binds the live database's filesystem identity as well as its
store ID and selected inputs. Keep a live case in its original storage location;
copying or replacing its database is not a supported recovery procedure. Do not
edit the anchor to bypass that check. You can move this **source distribution**
before creating a new run. You can also move the exported evidence and its
separately trusted selection/anchor for an offline reader check; the reader does
not reopen the live database.

## Run the regression tests

```sh
"$sample_python" -E -s -B sample/test_revocation.py
```

```sh
"$sample_python" -E -s -B test_environment.py
```

These run 69 behavior tests and 7 distribution/relocation tests. They create only
temporary synthetic stores and keys. The behavior tests exercise both SQLite
`WAL` and `DELETE` journal modes; the demo uses `WAL`.

## Included sources and scope

`sample/` contains the runtime-key revocation demonstration.
`reference/` contains four unchanged modules from VATE commit
`6c9bc7434c3fa2298268ced27afe5cefd0c85ee6` needed to construct and check the
original demo admission. `SOURCE-MANIFEST.json` records their paths and SHA-256
hashes alongside the sample and documentation files. The manifest excludes
itself. The code can run without the original repository checkout.

The original admission is an unsigned local VATE demo artifact. The sample's
cryptographic checks cover the selected status-authority and runtime signatures.
It does not implement general certificate revocation, remote cancellation,
independent time proof, or recovery from a malicious provider's history deletion.
It is a demonstration, not a production-ready verifier or a general compatibility
result.

Licensed under [Apache-2.0](LICENSE).
