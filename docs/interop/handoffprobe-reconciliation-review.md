# HandoffProbe Original-Attempt Reconciliation Review

## Result

HandoffProbe used the fixed Vaara → VATE reproduction package to compare three
properties: authorized-action binding, the caller's unknown outcome after
response loss, and provider-side reconciliation of the original attempt.
The comparison led to a HandoffProbe-native research fixture for the third
property.

This record covers the T-4 result returned on 18 September 2026. It is an
external technical review and local synthetic experiment, rather than a VATE
corpus comparison. The source and package-identity correspondence were checked
for this record; the HandoffProbe tests have not been rerun by the VATE
maintainer.

## Fixed Sources

- VATE input: [Vaara → VATE reproduction package at `4a63adb4`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/4a63adb4ade9d6e1affe622744a49056413a8c86/docs/interop/vaara-execution-reproduction.md)
  and its [package identity](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/4a63adb4ade9d6e1affe622744a49056413a8c86/docs/interop/vaara-execution-reproduction.package.json).
- HandoffProbe records at `360f3345`:
  [input freeze](https://github.com/Heaviside479/handoffprobe/blob/360f3345cf72ca60e0a91a81b91164dad7dd3d2c/docs/T4_1_UPSTREAM_FREEZE_20260917.md),
  [overlap analysis](https://github.com/Heaviside479/handoffprobe/blob/360f3345cf72ca60e0a91a81b91164dad7dd3d2c/docs/T4_2_WITNESS_VATE_OVERLAP_MATRIX_20260918.md),
  and [execution and admission record](https://github.com/Heaviside479/handoffprobe/blob/360f3345cf72ca60e0a91a81b91164dad7dd3d2c/docs/T4_3_PROVIDER_RECONCILIATION_EXECUTION_20260918.md).
- Executable fixture: [`tests/t4-provider-reconciliation-execution.test.ts` at `07d9c8bf`](https://github.com/Heaviside479/handoffprobe/blob/07d9c8bf38f1fa5bfa0d61f74d92ffe5232b53ba/tests/t4-provider-reconciliation-execution.test.ts).
- Discussion: [result returned to VATE issue #2](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2#issuecomment-5729853773)
  and [VATE's response in A2A #1769](https://github.com/a2aproject/A2A/issues/1769#issuecomment-5732275655).

## Package Check And Property Comparison

HandoffProbe reports independently downloading the ZIP, matching its size and
SHA-256 and the extracted manifest's SHA-256 to the published identity, and
running `python3.12 -I -S -B starter.py check` with exit code 0. This checks the
package and recomputed reports; it does not execute a fresh Vaara operation.

The overlap analysis classified the VATE properties against HandoffProbe's
existing evidence:

| VATE property | HandoffProbe classification and consequence |
| --- | --- |
| Authorized-action binding | Already covered by existing authority, target, approval and tool/argument-binding evidence. No new fixture for this property. |
| Caller outcome after response loss | Refinement of existing retry and partial-failure evidence: preserve the original outcome as unknown. |
| Provider-side original-attempt reconciliation | Distinct research gap: add a read-only lookup of execution evidence for the original action and attempt. |

These are HandoffProbe's classifications of its own coverage, not claims that
the two systems implement equivalent contracts.

## Reported Fixture Behavior

The fixture models one protected synthetic effect followed by loss of the
caller-facing response. The caller remains `unknown`, and the fixture records
a decision to block a blind fresh execution. A read-only provider lookup checks
the original action ID, attempt ID and execution evidence before resolving
the caller state.

| Lookup condition | Research outcome | Caller outcome |
| --- | --- | --- |
| Matching original-attempt execution evidence | `PASS` | `confirmed_success` |
| Missing evidence or mismatched action/attempt identity | `INCONCLUSIVE` | `unknown` |
| Provider lookup failure | `ERROR` | `unknown` |

The clean control records exactly one original protected effect and zero
additional protected effects during reconciliation. HandoffProbe reports
eight focused tests passing. It classified the result as
`DISTINCT RESEARCH CANDIDATE`, with no new stable attack admitted.

The synthetic effect is measured by HandoffProbe-owned runtime/effect
instrumentation. That measurement is distinct from the provider's report;
the fixture does not establish independently confirmed real-world effects.
It does not reproduce provider-signature verification, a production provider,
A2A transport or a multi-operator deployment.

The useful boundary is the difference between retaining retry identity and
obtaining evidence about the original attempt. Evidence must support that
attempt's outcome before uncertainty can be resolved. The fixture makes this
distinction executable without establishing a new normative A2A requirement.

## Acknowledgement

Thanks to [Heaviside479](https://github.com/Heaviside479) for checking the fixed
reproduction package, comparing the three VATE properties against
HandoffProbe's existing evidence, and publishing the original-attempt
reconciliation fixture and its results.
