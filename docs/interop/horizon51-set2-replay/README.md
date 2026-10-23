# Horizon Shield #51 set2: saved verification and recipient replay

On 2026-10-22, the VATE maintainer saved Horizon Shield's published MUSUBI
set2 material and reproduced its settlement output byte for byte. Signature,
digest and selected Bitcoin-header checks passed. A later header view changed
the reported checkpoint depth from 9 to 14; the other settlement results stayed
the same. The VATE Inbox retained both local assessments and their originals.

This directory records that experiment. To run the receiving path yourself,
use the [MUSUBI set2 recipient sample](../../../reference/musubi-set2-receiving-sample/README.md).
It provides environment preparation, explicit receipt conditions, request-binding
checks, Inbox storage, reassessment and recovery of saved outputs. Its
[validation record](../../../reference/musubi-set2-receiving-sample/VALIDATION.md)
covers the later reusable implementation.

## Fixed sources

| Material | Source |
| --- | --- |
| Experiment discussion | [Horizon Shield #51](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51) |
| Published set2 inputs | [Horizon commit `b85029de8d22c5246886f4f50ede03da0f54dfcf`](https://github.com/ogasurfproject-jpg/horizon-shield/tree/b85029de8d22c5246886f4f50ede03da0f54dfcf/workers/hs-ledger/nenrin/musubi-v0/ca2a-companion-v0/pilot51/set2) |
| Saved input bytes and raw-file manifest | [Sample originals](../../../reference/musubi-set2-receiving-sample/sample/originals/) and [manifest](../../../reference/musubi-set2-receiving-sample/sample/manifest.json) |
| Pinned evaluator source and dependency selection | [Evaluator template](../../../reference/musubi-set2-receiving-sample/evaluator-template.json) and [requirements lock](../../../reference/musubi-set2-receiving-sample/requirements.lock) |
| VATE files used by the sample | [`f044b208bcb8046fd4aa262094b4b77271ba7b27`, 23 file pins](../../../reference/musubi-set2-receiving-sample/vate-source.json) |

The saved set includes 68 source files. The upstream `SHA256SUMS` covers
20 entries; the manifest itself is a separate file. Raw hashes, lengths and Git
blob identities were checked when acquiring the sources. The copied upstream
source retains its [license and attribution](../../../reference/musubi-set2-receiving-sample/THIRD_PARTY.md).

## What was checked

The [separate cryptographic check summary](independent-verification.json)
records 36 Ed25519 signature checks: 13 log entries, their 13 signed items,
one root credential, one checkpoint and eight witness acknowledgments. The
selected authorities matched the pre-run trust selection, with two witnesses
required and a minimum anchor depth of six. This check was separate from the
native settlement calculation, but performed by the same VATE maintainer.

The same summary records 72 negative signature controls and three altered
OpenTimestamps controls. [Five native-evaluator controls](native-negative-controls.json)
tested a changed log signature, checkpoint signature, header, witness signature
and missing request. They produced the corresponding verification failure,
insufficient-witness or unknown-request results. A process exit of zero alone
was not treated as acceptance.

The native replay ran on macOS arm64 / Python 3.14.8 with network access denied.
The [execution summary](native-execution.json) records the exit status, isolation
probe results and stdout hash. It is a published summary of the execution record;
the machine-specific absolute command paths are omitted. Other JSON result files
in this directory retain their saved bytes.

The [replayed stdout](native-settlement.json) equals the upstream settlement
file followed by its CLI newline. Its SHA-256 is:

```text
18a19f8a1eb62593b857241f34c07b1d96550b93d5c9ea17184b2ac695818fbd
```

| Native result | Observed value |
| --- | --- |
| Executions A, B and C | `within_delegation` |
| Payments A, B and C | 7,000 each; cumulative 7,000 / 14,000 / 21,000 |
| Budget | 20,000 `JPY-testnet`; C reports `budget_exceeded` |
| Acceptance | `null` for all three |

These are calculations over the published records. They do not establish that
money moved or that the work was accepted. At the saved snapshot, raw call
responses, audit A/B bytes, rail-receipt bytes, MUSUBI A/B acceptance records and
the APS formal archive were not available to this check.

## Header-view reassessment

The original selected view contained 322 linked headers, heights 972238–972559.
The local checks covered header hashes, proof of work, links, heights and the
selected target constraints. Nine anchor checks connected the checkpoint and
eight witness acknowledgments to that view.

[Saved public API observations](bitcoin-observations/OBSERVATIONS.json) from
Blockstream and mempool.space agreed on the queried block hashes and headers.
Both reported tip 972564 at capture time. Adding the five connecting headers
gave a 327-header view. The [reassessment result](header-reassessment.json)
records only the checkpoint-depth change, from 9 to 14. These are dated API
observations, not an independently operated full node or a complete Bitcoin
consensus and difficulty-transition validation.

## VATE receipt and history

The [original Inbox result](inbox-result.json) records two staged local intakes:
74 entries in the first snapshot and 168 in the second. The first report remained
unchanged and was included in the second export. All 68 originals were restored
from export, and the native replay matched the same stdout hash. Core reassessment
results matched apart from elapsed time.

The Inbox core reports `selected_empty`: it was not configured to evaluate
MUSUBI semantics and made zero foreign-native calls. The receiving adapter keeps
the separate MUSUBI results. Missing or unsupported formal evidence remains
`partial` after the header update. Storage and a newer assessment do not turn
that evidence into acceptance.

Both intakes used saved material in local stages. Delivery of new records by
another participant and continued use by an independent receiver remain untested.

## Reproduce and inspect

In a VATE checkout or source archive, open
`reference/musubi-set2-receiving-sample/` and follow its
[preparation and run instructions](../../../reference/musubi-set2-receiving-sample/README.md#prepare).
Native replay requires macOS. The sample preserves the fixed baseline and
changed-header assessments, and can recover outputs from an already saved run
without evaluating it again.

From the repository root, check the public sample, this record and their pinned
VATE files without installing dependencies or running the evaluator:

```bash
python3 -B scripts/check_musubi_sample.py --integrity-only
```

The [CI workflow](../../../.github/workflows/ci.yml) also runs portable binding,
CLI/SQLite and output-recovery tests from a source archive on Linux / Python
3.11–3.14. Those tests use the real Inbox and replace only native replay with
controlled outputs. Their temporary runtime descriptor is a test fixture, not
a prepared native environment. The macOS native validation is reported separately
in the sample's validation record. Neither path establishes production readiness
or general protocol compatibility.

[SHA256SUMS](SHA256SUMS) covers this document and all saved files in this directory.
It detects file changes within this published record; it is not a detached
signature or independent timestamp proof.
