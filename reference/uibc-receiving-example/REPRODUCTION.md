# UIBC fixed-input replay

Source: [`zhaoxinghua09-cell/uibc-core` at
`163d81b030ef16a58fa21ec70caee70ace53f1e3`](https://github.com/zhaoxinghua09-cell/uibc-core/tree/163d81b030ef16a58fa21ec70caee70ace53f1e3).
Local observation date: 2026-11-05. The native verifier reports version 0.2.2.

## Published inputs

`samples/published/` retains the exact seven Git blob files from each of
`fixtures/clean.uibc/` and `fixtures/tampered.uibc/`. No newline conversion,
hash repair, resealing or key replacement was applied. The Git blob IDs and
SHA-256 values are in `samples/SOURCES.json`.

Both packages were passed to the pinned `uibc_core.verify.verify()` without a
key, under a macOS sandbox denying network and writes to the source snapshot.
The original bytes remained unchanged. Both produced overall `FAIL`: S1–S3
passed, S4 failed, S5 and S6 were `INCONCLUSIVE`.

For the published clean package:

| File | Raw LF SHA-256 | Declared SHA-256, also obtained from a CRLF variant |
| --- | --- | --- |
| `evidence/files/action-log.txt` | `823f8c9abbf6d7252f2731330155932d616a41f326546f1ef10fb85f37329709` | `e3db8b96438754db83daca4b671a3b1cabb86e4c1216dd9f48437781ab1ad916` |
| `evidence/files/run-summary.txt` | `a8e6a809464e4d985baf26520e87e4e7bc27fc07688f41fa9b1427a396f3a6dd` | `cfdec0459f8eac6cedcb3c2e81df2e1fb7c292b0130daf3f56898e53f5e3c9bd` |

This is an observed byte difference, not evidence that LF is an invalid text
format. The captured original key is unavailable here. The old seal is not
declared invalid on the strength of the file mismatch alone.

## Regenerated controls

In a separate output directory, the pinned
[`fixtures/generate_fixtures.py`](https://github.com/zhaoxinghua09-cell/uibc-core/blob/163d81b030ef16a58fa21ec70caee70ace53f1e3/fixtures/generate_fixtures.py)
was loaded without invoking `main()`. Its `HERE` output location was set to
that directory. Its `build_base()` created one clean package through the
native CLI functions. A byte-for-byte copy was changed with its
`mut_tampered()` function. The run's generated `OWNER_KEY` was retained as
disposable test material outside both packages.

The native verifier evaluated each package without a key and with that test
key. Clean/open passed S1–S5 with S6 inconclusive; clean/strict passed all six.
Tampered/open and tampered/strict failed S4 and left S5 inconclusive. S6 was
inconclusive without the key and passed with it. Changing an evidence file
did not change the identity/manifest seal; S4 provided the detection.

The manifest's evidence root is inside the HMAC payload. Relating that sealed
root to file content still requires S4/S5. A passing S6 alone is not a content
integrity or truth result.

`samples/native-replay.json` retains all six complete native reports, the
Python version and per-package input hashes. A fresh generator invocation
uses different keys, IDs and timestamps; it cannot recreate these exact bytes.
The pinned saved inputs and their matching disposable key provide the fixed
replay path.

## Independent receiving comparison

`receive.py` implements the three selected checks without importing UIBC.
`run_examples.py` checks the sample inventory, binds each saved native reading
to the package hashes, reruns this reader and compares S4/S5/S6 individually.
The six conditions agree on all 18 selected results. This agreement includes
the published clean fixture's mismatch; it is not a claim that all inputs pass.

S1–S3 and the native gate's decisions are not compared. The reader's bounded
input rules also reject some shapes that the native parser accepts; this is
not a full UIBC conformance test.
