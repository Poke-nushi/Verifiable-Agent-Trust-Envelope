# UIBC evidence receiving example

This document describes the legacy 0.2 helper and its preserved test fixtures.
For the standalone v0.3 package, use the [current setup and entry point](../README.md).
The historical commands below refer to the separate 0.2 folder in a full VATE checkout.

Read a UIBC evidence package with a separate implementation of its file-hash,
evidence-root and HMAC-seal checks. Each result remains separate: changed
evidence can fail while its unchanged seal still verifies, and a missing key
remains unevaluated.

The reader targets the provisional encoding at
[UIBC Core `163d81b`](https://github.com/zhaoxinghua09-cell/uibc-core/tree/163d81b030ef16a58fa21ec70caee70ace53f1e3).
It imports no UIBC code and uses Python's standard library. This experimental
VATE receiving example checks evidence inputs that a receiving application can
retain alongside its own assessment. It does not issue an admission receipt or
decide whether an operation may execute. It is not production-ready.

## Run the fixed examples

Requirements: Python 3.11+ on Linux or macOS. The complete folder can be copied
out of the repository; no package installation or network connection is needed.
From the repository root:

```bash
python3 -S -B reference/uibc-receiving-example/run_examples.py
```

This reruns the VATE reader and compares the three selected checks with saved
UIBC results. It does **not** execute UIBC again. The input inventory and the
input hashes attached to each saved result are checked before comparison.

| Input | Key | File integrity | Evidence root | Seal |
| --- | --- | --- | --- | --- |
| Published `clean` | unavailable | mismatched | not_assessed | not_assessed |
| Published `tampered` | unavailable | mismatched | not_assessed | not_assessed |
| Regenerated `clean` | omitted | matched | matched | not_assessed |
| Regenerated `clean` | disposable test key | matched | matched | matched |
| Regenerated `tampered` | omitted | mismatched | not_assessed | not_assessed |
| Regenerated `tampered` | disposable test key | mismatched | not_assessed | matched |

The **published clean fixture fails the native verifier too** on the retained
Git blob bytes. Both evidence files use LF line endings; their recorded hashes
match CRLF variants. The reader hashes the original bytes without conversion.
The capture does not establish which authoring or distribution step introduced
the difference. [REPRODUCTION.md](REPRODUCTION.md) records the inputs and native
replay separately from the regenerated controls.

The regenerated packages were created by UIBC's pinned generator on macOS.
They are synthetic test data, not new agent executions. Their included key is
disposable public test material. It does not verify the published packages.

## Read one package

Read the published package without a key:

```bash
python3 -S -B reference/uibc-receiving-example/receive.py \
  --package reference/uibc-receiving-example/samples/published/clean.uibc
```

Use the regenerated package with its separate test key:

```bash
python3 -S -B reference/uibc-receiving-example/receive.py \
  --package reference/uibc-receiving-example/samples/regenerated/clean.uibc \
  --key reference/uibc-receiving-example/samples/regenerated/DISPOSABLE-TEST-KEY.hex
```

`--key` is an explicit receiver-selected file containing 64 hexadecimal
characters, optionally followed by one LF. The CLI refuses keys inside the
package and never discovers keys from package metadata. HMAC uses a shared
secret: a matching seal shows agreement with the supplied key, not independent
proof of an owner's identity or authority. Use only disposable test keys with
this example.

## Interpret the report

- `checks.evidence_files` compares each listed file's raw SHA-256 and checks its
  evidence type against the pinned vocabulary (UIBC S4).
- `checks.evidence_root` compares SHA-256 of the provisional sorted hash array
  with the manifest (S5). Missing or inconsistent evidence leaves it
  `not_assessed`; hashes retain duplicate entries.
- `checks.seal` verifies HMAC-SHA256 over the complete parsed identity and
  manifest with the receiver-selected key (S6). Unsupported seal profiles and
  absent keys remain `not_assessed`.
- `inputs` records byte lengths and raw digest descriptors for files actually
  read. Missing evidence has a null observed hash in its check entry.
- `checks_status` summarizes **only these three checks**: a mismatch takes
  precedence over an unevaluated check, which takes precedence over `matched`.
  Read the individual results and `not_assessed` list even when it is `matched`.

UIBC's overall `PASS` may coexist with an unverified seal in open mode. This
reader does not turn that overall value into acceptance. Saved native results
are retained separately by `run_examples.py`.

The report explicitly leaves lifecycle validity, identity consistency and
subject binding, issuer authority, key status, request/delegation binding,
execution and behavioral truth unassessed. The root covers a sorted multiset
of content hashes; it does not bind evidence paths, types or other index
metadata. Files absent from the index are outside the selected checks.

Exit **0** means an assessment was emitted, including mismatches and missing
keys. Exit **64** means an invalid/unsupported input or file-read error, with
a compact JSON error. Argument usage errors exit **2**. These are CLI statuses,
not execution permissions.

## Input contract

The reader accepts `uibc-core/0.2.2-proposal` identity and manifest objects,
an index with at most 128 entries, and the optional
`uibc-core/0.2.0-proposal` / `HMAC-SHA256` / `identity+manifest` seal. It validates
only the fields needed by the selected checks, not the entire UIBC schema.

JSON must be UTF-8 without duplicate names, invalid Unicode, floating-point
values or integers outside ±(2^53−1). Nesting is limited to 32 levels. Unknown
identity/manifest fields are included in the seal payload. The encoding is
Python's sorted-key, compact, UTF-8 JSON at the pinned UIBC contract; it is
**not RFC 8785 JCS** and does not change VATE's other digest contracts.

Each file is limited to 1 MiB and all distinct files read to 8 MiB. Evidence
paths are relative to `evidence/`; absolute paths, dot segments, backslashes,
colons, symlinks and nonregular files are rejected. Use a stable local copy
that no other process is modifying. Each file is read once; this is not an
atomic snapshot of a concurrently changing directory. No URLs are fetched.

## Tests

```bash
python3 -S -B -m unittest discover \
  -s reference/uibc-receiving-example -p 'test_*.py' -v
```

The suite covers the fixed comparisons, unchanged-seal tampering, missing and
wrong keys, unsupported profiles, malformed inputs and filesystem boundaries.
UIBC and this reader both use Python's hashing/HMAC facilities. Separate reader
code does not establish independent cryptographic-library implementations.

Upstream fixtures are distributed under Apache-2.0; see
[samples/UIBC-LICENSE.txt](samples/UIBC-LICENSE.txt) and
[samples/SOURCES.json](samples/SOURCES.json) for provenance and fixed hashes.
