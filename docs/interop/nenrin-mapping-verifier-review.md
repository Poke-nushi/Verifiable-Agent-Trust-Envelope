# NENRIN Mapping and Verifier Review

The NENRIN–VATE review clarified the relationship between caller authorization,
verifier admission and execution evidence. Two result-consistency issues
reported by the VATE maintainer were also fixed upstream and confirmed in the
published `nenrin-verify@0.2.3` package.

## Mapping Record

The [corrected NENRIN mapping note](https://github.com/ogasurfproject-jpg/horizon-shield/blob/9454f58240bb2133ae3a99d59f44000e7f32cedf/workers/hs-ledger/nenrin/task-execution-bind-v0/VATE_MAPPING_v0.md)
and [author's correction response](https://github.com/a2aproject/A2A/issues/1769#issuecomment-5900693623)
preserve the reviewed profiles:

| Source | Fixed revision |
| --- | --- |
| NENRIN profile described by the mapping | [`da98d4bfe0c38ef9fb89e6cfcd50f5fed3f336cd`](https://github.com/ogasurfproject-jpg/horizon-shield/tree/da98d4bfe0c38ef9fb89e6cfcd50f5fed3f336cd) |
| VATE profile described by the mapping | [`bf9b6fa3cf0c5306ef19c2ce00878818879348e6`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/bf9b6fa3cf0c5306ef19c2ce00878818879348e6) |
| Corrected mapping document | [`9454f58240bb2133ae3a99d59f44000e7f32cedf`](https://github.com/ogasurfproject-jpg/horizon-shield/commit/9454f58240bb2133ae3a99d59f44000e7f32cedf) |

The document correction retains its original profile pins. The later SDK
verification below is a separate result.

The mapping identifies four conditions for interpreting the records together:

- NENRIN's `grant_ref` identifies the caller's authorization. VATE's
  `admission.digest` identifies the relying party's verifier-issued admission
  receipt. They refer to different artifacts and decisions.
- Digest equality requires an explicit request preimage, canonical byte rule
  and hash encoding, with both digests recomputed. The profiles' different
  treatment of non-ASCII strings can produce different digests.
- Content-derived identifiers retain that meaning; they do not become
  transaction or execution-attempt identifiers through the mapping.
- Mapping `provider_id` to VATE's actor, runtime or both requires a profile
  choice and evidence for the association.

Two signature-description corrections were incorporated: the grant and receipt
preimages exclude `action_binding`, and a record's own derived identifier is
distinguished from signed references to it in other records. For example, an
execution receipt's `grant_ref` is covered by the provider's signature even
though the grant's own `grant_ref` is excluded from the grant's signed preimage.

## Verifier Issues and Confirmed Fixes

[NENRIN issue #26](https://github.com/ogasurfproject-jpg/horizon-shield/issues/26)
contains the original reproducer and upstream response. The fixes were made at
[`88dd8c0f815cca531014ba688a86ab7b9add1588`](https://github.com/ogasurfproject-jpg/horizon-shield/commit/88dd8c0f815cca531014ba688a86ab7b9add1588).

The reproducer uses synthetic Ed25519-signed records with
`require_signatures: true`. A grant authorizes action A; the authorized provider
signs receipt A and a receipt B for a different action under the same grant.

| Reported input | `0.2.2` result | Confirmed `0.2.3` result |
| --- | --- | --- |
| `receipt: A, receipts: [B]` | Accepted, with B reported as the selected receipt | Refused; B is not reported as the selected receipt |
| Refused preflight for a different action | `authorized_before_execution: true` despite the overall refusal | `authorized_before_execution: null`; the refusal remains |

On 1 October 2026 (JST), the VATE maintainer reran the original reproducer
unchanged on Node.js `v22.16.0` against the published `0.2.3` package. The
original positive and negative controls also passed, including `true` for a
valid preflight. The package's SDK file was byte-identical to the SDK at both
the fix commit and published source revision
[`9454f58240bb2133ae3a99d59f44000e7f32cedf`](https://github.com/ogasurfproject-jpg/horizon-shield/tree/9454f58240bb2133ae3a99d59f44000e7f32cedf).

At that source revision, `provenance_adversarial.test.mjs` passed 39 checks and
`consume.test.mjs` passed 16: 55 checks, including the six added for issue #26.
The [VATE maintainer's confirmation](https://github.com/ogasurfproject-jpg/horizon-shield/issues/26#issuecomment-5924757746)
records the results and closes both reported cases.

The cases show why a consumer must verify the same receipt set it uses to
select an outcome, and preserve refusal when projecting verified facts. A valid
signature alone does not establish that a receipt describes the authorized
action.

## Scope and Acknowledgement

The SDK verification covered the reproducer, its controls and the two named test
scripts using synthetic records; it was not a full SDK audit or a live-service
test. The record establishes no external VATE SUT result, VATE adoption or
general interoperability between the profiles.

Thanks to [ogasurfproject-jpg](https://github.com/ogasurfproject-jpg) for the
mapping, the corrections and the verifier fixes with regression coverage.
