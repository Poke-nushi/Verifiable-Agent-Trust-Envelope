# WAR 1.4.3 receiving validation

Local checks on 2026-11-04 exercised WAR 1.4.3 at
[`6bb7d0b`](https://github.com/maximusrufus/work-acceptance-record/blob/6bb7d0b9246c3c535aba9c294d26181496d00614/verifier/war_verify.py)
and retained 1.4.1 at
[`6b2f730`](https://github.com/maximusrufus/work-acceptance-record/blob/6b2f730b81e0818826f274742d883c2b475d5227/verifier/war_verify.py).
The exact source hashes and key-selection rules are in
[ACCEPTANCE-CONTRACT.md](ACCEPTANCE-CONTRACT.md). The signed acceptance originals
remain the four fixed files from
[`235aaabc`](https://github.com/babyblueviper1/preaction-governance-conformance/tree/235aaabc45ebe6fa36dd02ca2cd6a44a69297d93/examples/hs51-acceptance-set).

## Record and receiver checks

| Platform | Python | Record suite | Receiver suite |
| --- | --- | --- | --- |
| macOS arm64 | 3.11.14 | 59 tests, pass | 21 tests, pass |
| macOS arm64 | 3.14.8 | 59 tests, pass | 21 tests, pass |

Both suites ran with network access denied. The record suite uses the signed
originals and pinned verifier. The receiver suite substitutes saved native
output; it is separate from the full replay below.

The added cases check construction and retention of the selected two-key input,
an already supplied matching producer key, contradictory producer keys,
duplicate producer IDs, legacy evaluation, unsupported source selections,
source-file substitution and reuse of a result from another verifier pin.
Existing signature, binding, timestamp, parser and failure-status cases also
pass. The original files are unchanged; synthetic mutations are test inputs.

## Native replay, upgrade and recovery

The prepared Python 3.14.8 runtime ran the three-stage example with WAR 1.4.1,
then received the same originals with an explicit 1.4.3 selection into the same
Inbox. Native MUSUBI evaluation and the WAR workers ran in the sample's macOS
sandbox with network and Keychain access denied.

Both versions retained A's foreign work verdict as `pass` and B's as `fail`.
The 1.4.3 assessment stored the checker/producer key input and derived
`independent` result. All 76 originals and all three earlier assessments
exported byte-for-byte unchanged. Separate A/B checks compared legacy output
against the previous adapter and found exact equality.

Recovery through `recover_output.py` restored the new assessment bytes exactly
and left the Inbox database bytes unchanged. Native output remained identical
to the fixed settlement, including `accepted: null`; required evidence remained
`partial`. This run does not add B's later audit or the missing rail/raw-response
records, re-evaluate audit contents, or establish organizational independence.

To repeat the version transition, first run the README's three-stage example
with the 1.4.1 source. Copy its `intake/selection.json` to a new selection file,
select the 1.4.3 hash from the contract, and set the new assessment time. Invoke
`receiving.py` with the same intake originals, manifest, native source, runtime
and evaluator. Keep `--database` pointing to `history/inbox.sqlite`, set
`--previous` to the old `acceptance/RESULT.json`, and supply the new selection
with `--selection` and the 1.4.3 source with `--acceptance-verifier`. Choose a
fresh `--output` directory. The README's acceptance recovery command can then
use that new output's `RECOVERY.json` and the same database.

## Reproduce the portable suites

From the repository root, choose a new evidence directory. Preparation fetches
the fixed public inputs and checks their raw hashes; it installs no packages.
The next two commands execute the pinned verifiers on those inputs.

```bash
python3 -B scripts/prepare_musubi_acceptance_tests.py --output /tmp/vate-war143-inputs
python3 -B reference/musubi-set2-receiving-sample/verify_acceptance.py \
  --evidence-root /tmp/vate-war143-inputs
python3 -B reference/musubi-set2-receiving-sample/verify_acceptance_integration.py \
  --evidence-root /tmp/vate-war143-inputs
```

These suites use the Python standard library. Full native replay requires the
prepared macOS environment described in [README.md](README.md). The earlier
[2026-10-24 validation](ACCEPTANCE-VALIDATION.md) remains a record of its WAR
1.4.1 runs; its cross-platform matrix is not a 1.4.3 test result.
