# UIBC v0.3 evidence receiving example

Check a UIBC package's evidence and seal, then see separately whether its key
matches the key selected by the receiver. The fixed examples show why a valid
signature alone cannot distinguish the expected signer from someone who changed
the package and signed it again with another key.

This standalone VATE reference example includes an independent reader, pinned
UIBC source, disposable test material and 22 comparison conditions. Copy this
whole folder to run it outside the VATE checkout. The earlier
[UIBC 0.2 receiving example](../uibc-receiving-example/README.md) retains its
original source pin and results.

## Run the comparison

Use CPython **3.11 or 3.14**, on macOS arm64 or Linux x86_64. From this folder:

```bash
python3 -B verify_package.py
python3 -m venv .venv
.venv/bin/python -m pip install --only-binary=:all: --require-hashes -r requirements.lock
.venv/bin/python -B -m unittest discover -s reader -p 'test_*.py' -v
results_dir=$(mktemp -d)
.venv/bin/python -B compare_fixed.py --engine native --output "$results_dir/native.json"
.venv/bin/python -B compare_fixed.py --engine vate --output "$results_dir/receiver.json"
```

The lock contains official wheel hashes for cryptography 50.0.1, cffi 2.0.0 and
pycparser 2.23. Installation uses a local virtual environment and does not build
source packages. After installation, the commands run offline. Other platforms
and Python versions are outside this package's pinned setup.

Expected results: **75 tests**, **22 full native replays**, and **66 selected
check comparisons** across those same 22 conditions. `native` executes the
included UIBC verifier and compares its full reports with the saved reports.
`vate` executes the independent reader and compares S4/S5/S6 status values with
those saved reports; it also checks the expected receiver status. It does not
import UIBC. Each command creates a new report and refuses to overwrite one.

## Try the key-substitution case

The `resealed` package changes evidence, updates its hashes and root, and signs
the new identity/manifest payload with a different disposable key. Compare the
package's own key with a receiver-selected expected key:

```bash
.venv/bin/python -B reader/receive_v03.py --package inputs/resealed
```

```bash
.venv/bin/python -B reader/receive_v03.py --package inputs/resealed --pubkey inputs/published.pub
```

The first report has `checks_status: matched` and
`receiver_checks_status: not_assessed`. The second has a valid signature but
`selected_key_binding.status: mismatched` and
`receiver_checks_status: mismatched`.

`inputs/published.pub` is the sample key copied from the same pinned upstream
repository. It is an expected-key control, not an independent proof of a real
owner. In an integration, the receiving application must select its expected
key through its own trusted channel. Every included key or seed is public test
material and must not be used for operational signing.

`--pubkey` takes a regular, non-symlink file outside the received package,
containing the 32-byte public key as 64 hexadecimal characters, with an optional
final LF. PEM, OpenSSH and raw binary key files are not accepted. The alternative
`--key` option uses the same file format for a 32-byte HMAC shared key; select
only one key mode.

## Read the result

| Field | What it answers |
| --- | --- |
| `checks.evidence_files` | Do listed file bytes and types match the supported index entries? (S4) |
| `checks.evidence_root` | Does the sorted collection of file hashes match the manifest root? (S5) |
| `checks.seal.signature` | Does the supported seal signature verify? |
| `checks.seal.selected_key_binding` | Does the seal use the receiver-selected key? |
| `checks.seal.status` | Combined seal result for the selected key mode (S6). |
| `checks_status` | Aggregate of the selected S4/S5/S6 checks. |
| `receiver_checks_status` | Aggregate that also requires a selected key match. |

Both aggregates use `mismatched` before `not_assessed` before `matched`.
An assessed mismatch therefore remains visible even when another check cannot
be evaluated. With no selected key, valid Ed25519 evidence and a valid seal
can match the selected checks while the receiver aggregate remains unassessed.
HMAC without a shared key cannot verify the seal at all.

The CLI returns exit **0 when it produces an assessment**, including a mismatch
or an unassessed result. Read the JSON status fields to decide how to handle
the package. Unsupported or invalid inputs return `invalid_input` and exit 64.
See [key input policy](KEY-INPUT-POLICY.md) for the additional Ed25519 restrictions.

The reader covers selected evidence/seal checks, not UIBC's complete S1–S6
verdict. The root binds the sorted collection of file content hashes, not paths,
types or all index metadata. Payload encoding follows the pinned UIBC Python
sorted compact UTF-8 encoding; it is not RFC 8785. The reader accepts the
0.2.2 and 0.3.0 proposal package schemas used in these fixtures.

This is an experimental receiving example, not production-ready. It does not
establish signer identity, authority, key revocation status, behavioral truth
or permission to execute an operation. It neither issues VATE admission
receipts nor writes to Recipient Inbox. The fixed comparison is evidence for
this source snapshot and these inputs, not general UIBC compatibility.

## Sources and reproduction

- UIBC [commit dc9eba3](https://github.com/zhaoxinghua09-cell/uibc-core/tree/dc9eba3146e4e32bb1356f24ce8d72249a64702a), from [PR #24](https://github.com/zhaoxinghua09-cell/uibc-core/pull/24).
  `SOURCE.json` records each included upstream file's Git blob and raw SHA-256.
  `source/` preserves its license and notice. The native verifier uses its own
  Ed25519 implementation; the independent reader uses cryptography.
- `inputs/` contains the published sample, modified/resealed/unsigned controls,
  HMAC fixtures and a synthetic 0.3.0 schema control. `validation/native.json`
  retains all 22 full native reports and input hashes. A saved native `FAIL`
  can be the expected outcome of a successful replay.
- `reader/` contains the v0.3 reader, its input helper and tests. Its nested
  README describes the legacy helper. The v0.3 output profile keeps the
  experimental identifier
  `uibc-0.3.0-evidence-receiving-candidate-v1`.
- `PACKAGE-MANIFEST.json` covers distributed files with raw SHA-256, excluding
  itself. `verify_package.py` checks those bytes; establish the manifest's
  origin through the repository snapshot you choose. This is an integrity
  check, not a signature or approval.
- `DEPENDENCIES.json` records the official [PyPI](https://pypi.org/) wheel URLs
  and hashes used by `requirements.lock`.

To regenerate the synthetic inputs and native capture, choose a new output
directory. The committed inputs remain unchanged:

```bash
work_dir=$(mktemp -d)
.venv/bin/python -B generate_native.py --output "$work_dir/generated"
```

The resulting `inputs/` bytes and the `cases` and `inputs` fields in
`validation/native.json` should match the distributed versions. The recorded
Python version may differ. All generation is local and uses the pinned source
and disclosed test seeds.
