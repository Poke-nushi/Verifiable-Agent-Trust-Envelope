# MUSUBI set2 audit and dataset receiving record

The VATE receiving sample links the published A/C audit bytes to each selected
execution receipt, then links the published dataset bytes to the audit's declared
digest. A second assessment retains the first assessment and the originals in
the same Inbox. This record reports the October 23, 2026 local verification;
the [October 22 replay record](../horizon51-set2-replay/README.md) retains its
original observation scope.

## Inputs and results

The set2 receipts and audit are pinned to Horizon Shield
`b85029de8d22c5246886f4f50ede03da0f54dfcf`. The dataset is pinned separately to
`5b22c203248b0149cd0456f77d32feb887f48ee0`. The
[source manifest](../../../reference/musubi-set2-receiving-sample/sample/audit-sources.json)
records immutable URLs, raw SHA-256, byte lengths and Git blob IDs.
The [source clarification](https://github.com/ogasurfproject-jpg/horizon-shield/issues/55#issuecomment-6340981584)
identifies the A/C originals and the unavailable B original.

| Question | Observed result |
| --- | --- |
| Delegated execution scope | The pinned upstream replay reports `within_delegation` for A, B and C. |
| Cumulative budget | 7,000 / 14,000 / 21,000 against a 20,000 `JPY-testnet` limit; C's payment carries `budget_exceeded`. |
| Request occurrence | Selected execution, payment and criteria records bind to their respective A/B/C requests. A valid signed C receipt cannot satisfy A's selected execution prerequisite. |
| Audit bytes | A and C name the same 1,532-byte audit; each keeps a separate request and execution link. B's audit original is absent. |
| Dataset bytes | All three lines of the A/C audit name the same digest, matching the 117,282-byte published dataset. B's dataset identity remains unestablished. |
| Formal acceptance | The upstream result remains `accepted: null` for all three calls. |
| Retention | Earlier assessment bytes remain unchanged; both additional originals are restored exactly from the new export. |

[results.json](results.json) contains the per-occurrence summary. Delegation and
budget judgments are reproduced by the pinned MUSUBI evaluator, not reimplemented
by VATE. The VATE-side adapter checks selected record bindings, additional raw
digests, storage and history. The run was implemented and operated by the VATE
maintainer with coding-agent assistance.

The replay stdout SHA-256 remains
`18a19f8a1eb62593b857241f34c07b1d96550b93d5c9ea17184b2ac695818fbd`.
The audit raw SHA-256 is
`c2920477d95a8e48f16cc2df49ec58a02cd9b422db491206446e7a5be21937f5`;
the dataset raw SHA-256 is
`7b16600e50ed73b844ff5b2718f04a6dd4d9ace0367982fb8d139db509d023fd`.
Japanese text is hashed in its original bytes, without extending the sample's
ASCII-only object canonicalization.

## Reproduce

Follow the sample's [environment preparation](../../../reference/musubi-set2-receiving-sample/README.md#prepare),
then run the [audit and dataset example](../../../reference/musubi-set2-receiving-sample/AUDIT-CONTRACT.md#local-execution).
It uses a new database, runs the fixed baseline, and adds the two public originals.
The earlier assessment, changed selection and new assessment remain inspectable.
Native replay requires macOS and runs with networking denied.

From a VATE checkout or source archive, the portable test entry point is:

```bash
python3 -B scripts/check_musubi_sample.py
```

This command requires the existing `requirements-dev.txt` validation packages.
It checks manifests, record bindings, CLI storage, output recovery and the audit
extension. Its native evaluator is an explicit saved-output test double.
The [validation record](../../../reference/musubi-set2-receiving-sample/AUDIT-VALIDATION.md)
separates actual native execution from portable adapter/storage checks.

## Interpretation

Matching the audit's declared digest identifies the published dataset bytes.
It does not independently establish that the dataset was used at execution
time, that the audit contents are correct, or that the work was accepted.
B's missing originals and the other unprovided selected records remain visible;
the overall evidence state stays `partial`.

The baseline selects 21 requirements; the additional assessment selects 24,
including C's previously optional audit and three dataset requirements.
Their counts are not a completion-rate comparison. The example records a local
selection change, not a witnessed late delivery by another party.
