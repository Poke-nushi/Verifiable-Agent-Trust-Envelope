# WAR 1.4.8 receiving validation

Local checks on 2026-11-07 exercised the fixed HS51 acceptance records with
[WAR 1.4.8 at `3e53aac`](https://github.com/maximusrufus/work-acceptance-record/blob/3e53aac24ee5298b2316a10dceeaddb99695cc8c/verifier/war_verify.py).
The receiver stores its separately selected key input with each assessment and
retains earlier assessments under their original verifier pins.
[ACCEPTANCE-CONTRACT.md](ACCEPTANCE-CONTRACT.md) lists the three supported source
hashes and the key-selection rules. The four signed originals remain pinned to
[acceptance set `235aaabc`](https://github.com/babyblueviper1/preaction-governance-conformance/tree/235aaabc45ebe6fa36dd02ca2cd6a44a69297d93/examples/hs51-acceptance-set).

## Record and receiver checks

| Platform | Python | Record suite | Receiver suite |
| --- | --- | --- | --- |
| macOS arm64 | 3.11.14 | 66 tests, pass | 21 tests, pass |
| macOS arm64 | 3.14.8 | 66 tests, pass | 21 tests, pass |

Both suites ran with network access denied. The receiver suite substitutes
saved native output; the full native replay is described below.

The added cases check the receiver-derived `relying_party_keys` input at both
WAR entry points, incoming lists that cannot replace it, retained 1.4.3 results,
and rejection of a result or source from a different selected verifier pin.
Both the receipt and sidecar use the selected signature verifier.

The record suite also runs upstream vectors 110–118 directly through WAR.
Vector 116's signature, made with the published test key and a neutral `R`
point, passes the 1.4.3 signature function and fails the 1.4.8 function.
For vectors 117–118, an isolated
adapter parser test bypasses signatures on unsigned mutations and confirms
that duplicate criteria members and lone surrogates stop before upstream
evaluation. The existing strict criteria parser already enforces these rules.

Separately, the pinned 1.4.8 verifier matched all 118 expected vector outcomes
with network access denied. This is an upstream verifier/vector check, not 118
HS51 receiving or Inbox tests.

## Native transition and recovery

The prepared Python 3.14.8 runtime ran the three-stage example with 1.4.3,
then received the same originals with a 1.4.8 selection into the same Inbox.
Native MUSUBI evaluation and WAR workers ran in the sample's macOS sandbox
with network and Keychain access denied.

A's foreign work verdict remained `pass`, B's remained `fail`, and the new
assessment stored both derived key inputs and WAR's derived `independent`
result. All 76 originals and the three earlier assessments exported unchanged.
Separate A/B checks under both 1.4.1 and 1.4.3 produced exactly the same results
as the adapter before this update.

Recovery restored the new assessment bytes exactly without changing the Inbox
database bytes. Native stdout still matched the fixed settlement, including
`accepted: null`; required evidence remained `partial`. The run does not add
missing audit or rail/raw-response records, re-evaluate audit contents or
establish organizational independence.

To repeat the transition, follow the [1.4.3 transition procedure](WAR143-VALIDATION.md#native-replay-upgrade-and-recovery),
using 1.4.3 as the initial selection and 1.4.8 as the new selection. Keep the
same Inbox database, retain the earlier output, and use a fresh output directory
for the new assessment and for recovery.

## Reproduce the portable suites

From the repository root, choose a new evidence directory. Preparation fetches
20 fixed inputs, verifies each raw hash and installs no packages. The next two
commands execute the pinned verifiers with the Python standard library.

```bash
python3 -B scripts/prepare_musubi_acceptance_tests.py --output /tmp/vate-war148-inputs
python3 -B reference/musubi-set2-receiving-sample/verify_acceptance.py \
  --evidence-root /tmp/vate-war148-inputs
python3 -B reference/musubi-set2-receiving-sample/verify_acceptance_integration.py \
  --evidence-root /tmp/vate-war148-inputs
```

Preparation needs network access. After it completes, run the two verification
commands in an offline environment or an OS sandbox that denies networking;
these commands do not establish a sandbox themselves. Full native replay uses the prepared macOS
environment in [README.md](README.md). The [1.4.3](WAR143-VALIDATION.md) and
[1.4.1](ACCEPTANCE-VALIDATION.md) validation records retain their original scope.
