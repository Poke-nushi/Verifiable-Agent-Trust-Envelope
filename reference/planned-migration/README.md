# Planned key, program and storage migration

Move a stopped managed Python deployment to a new authority key, installed
program and local store directory while retaining its receipt originals and
operation history. The supported source is
[`6758476`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/675847669851070728431fd1ebd1415f57ad411e).
Read the [migration contract](CONTRACT.md) before applying the API to retained
application state.

The move commits the three source stores, three destination stores and migration
journal together. After commit, the old configuration cannot reopen its stores
for execution. The new configuration must obtain a fresh signed authority
update before admitting work.

Past receipts and verification originals keep their bytes. Pending work requires
a new admission with newly bound caller/runtime proofs. Previously consumed or
outcome-unknown operations remain blocked by their stable operation IDs.

## Run the local example

Keep an independently obtained source tree for the pinned old commit. The example
checks its runtime hashes and runs that old program in separate interpreters.
Use a new output directory on a trusted local filesystem.

```bash
python3 -B reference/planned-migration/run_example.py \
  --source-root /absolute/path/to/6758476-source \
  --output /absolute/path/to/new-migration-evidence
```

Use Python 3.11 or later and Node.js 22 or later on macOS or Linux, with a trusted
local POSIX filesystem. The example selects `node` from `PATH`; check that it is
the intended installed executable before running. The fixture generates
disposable signing keys and recording operations. It makes
no purchase or external resource change. The output records selected source
hashes, old/new file identities, historical artifact checks, rejected old
configuration use and new operation outcomes.

Run the migration regression suite against the same old source:

```bash
VATE_MIGRATION_BASELINE=/absolute/path/to/6758476-source \
  python3 -B -m unittest discover -s reference/planned-migration -p 'test_*.py' -v
```

The suite fails if the selected source is absent or does not match the pin.
The separate migration CI job selects Python 3.11, 3.12 and 3.14 on Linux and
Python 3.14 on macOS. Keep applications stopped during migration and committed
readback. Do not first admit new work with the destination program against the
old stores; mixed-program admission histories are not a supported source.

The migration example is a reference integration for one administrator and a
stopped local deployment. Key-loss recovery, stale backups, arbitrary upgrades
and uninterrupted operation are outside the supported transition.

## Exercise Keychain and local IAM

On macOS, use the existing Swift compiler and the
[pinned Hydra/OpenFGA binaries](../authority-issuer/README.md#run-the-native-example).
This path creates a disposable, dedicated Keychain with two non-extractable keys.
It retains the old key through the move and observes current permission through
the same registered local services before and after replacement.

```bash
python3 -B reference/planned-migration/run_native.py \
  --source-root /absolute/path/to/6758476-source \
  --native-root /absolute/path/to/selected-native-directory \
  --output /absolute/path/to/new-native-migration-evidence
```

The native directory must contain the already obtained `bin/hydra` and
`bin/openfga` matching the issuer fixture's pinned hashes. The command does not
download software or change the personal default Keychain. Login and consent
are synthetic; the final operation is a recording callback. Temporary service
processes and the fixture Keychain are removed after the run. The output retains
the old/new stores, original artifacts and journal anchor for inspection; these
are disposable fixture state and must not be used as deployment credentials.
