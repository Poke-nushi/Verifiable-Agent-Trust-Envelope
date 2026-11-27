# Trace a refund result to the approval you selected

Two published DPS/SCITT packets describe a €120 refund for the same order. Each cites a different approval attachment. The recipient can select one attachment before opening either packet, then check which result refers to that selection. The example runs the upstream packet verifier and compares its citation with the recipient's saved reference. [Original cases 18 and 18b](https://github.com/Laurent-Lemonnier/dps-scitt-decision-layer/tree/89e6853ad65c606739d9e7c163e9b1fe927ac22e/interop)

| With the case 18 approval selected | Upstream packet check | Does the packet cite that approval? | Match against the cited originals |
| --- | --- | --- | --- |
| Case 18, complete delivery | `VERIFIED` | Yes | `matched` |
| Case 18b, complete delivery | `VERIFIED` | No | `mismatch` |
| Case 18, before its cited result receipt arrives | `FAILED` | Yes | `not_assessed` |
| Case 18, after that receipt arrives | `VERIFIED` | Yes | `matched` |

In the late-receipt example the recipient already holds an allow receipt. The upstream verifier reports the missing result receipt as a blocking reference. The packet still identifies the selected approval.

A match identifies the approval and result files cited by the packet. Direct comparison of the approved operation, target and amount with the recorded execution, and actual settlement, remain outside this check. Each result JSON records that scope.

## Run the examples

[Download the fixed ZIP](https://raw.githubusercontent.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/f5276d47f3fb25df30b9e8b8079fd0e227461524/docs/interop/dps-scitt-refund/refund-recipient-examples.zip) and [its SHA-256 checksum](https://raw.githubusercontent.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/f5276d47f3fb25df30b9e8b8079fd0e227461524/docs/interop/dps-scitt-refund/SHA256SUMS). The archive contains the comparison tool, both original fixture sets, the upstream verifier, source hashes and licenses.

From a new directory, use a POSIX shell and CPython 3.14.

```sh
curl --fail --location --remote-name https://raw.githubusercontent.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/f5276d47f3fb25df30b9e8b8079fd0e227461524/docs/interop/dps-scitt-refund/refund-recipient-examples.zip
curl --fail --location --remote-name https://raw.githubusercontent.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/f5276d47f3fb25df30b9e8b8079fd0e227461524/docs/interop/dps-scitt-refund/SHA256SUMS
shasum -a 256 -c SHA256SUMS
python3.14 -m zipfile -e refund-recipient-examples.zip .
cd refund-recipient-examples
```

In the extracted `README.md`, continue from `python3.14 -m venv .venv` in “Set up”, then run the complete and late-receipt cases. Setup uses hash-pinned wheels from PyPI. The comparisons run offline.

The tool accepts the two fixed packets and their fixture key. To try the same question with an operation from your own system, use the one-operation worksheet in `RECIPIENT-TRIAL.md`.
