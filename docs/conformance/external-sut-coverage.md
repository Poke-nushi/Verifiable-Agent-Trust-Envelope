# External SUT Coverage and Check Reachability

This guide compares what the recorded external implementations executed, what
their native output establishes, and what remains unresolved in VATE comparison.
Use it to choose a case to reproduce or extend; follow the linked run records for
the exact inputs, source revisions, artifacts, and replay instructions.

The table covers the three candidate-executed native-verifier records available
on 2026-09-10. The [run register](external-sut-run-records.md) also contains two
AlgoVoi adapter-result slices from one implementation line. Those slices have
local comparison evidence; their adapter source was not independently reviewed
in that intake. They are not combined with the native-execution rows below.

## Reading the evidence

Four questions have different answers:

1. **Executed:** Did the candidate's implementation run on the selected input?
2. **Reached:** Does native output or a controlled input change identify the
   predicate that produced the decision?
3. **Reported:** Which VATE named checks did the submitted projection assert?
4. **Compared:** Did that result satisfy the pinned corpus expectations,
   including reason codes, checks, and artifact references?

In a negative case, `checks[].pass: true` asserts that the named corpus
expectation was satisfied. It does not mean the action was allowed. A
missing check is a comparison failure; an overall `deny` does not fill it in.
See [Check Semantics](sut-adapter-contract.md#check-semantics).

## Recorded coverage

| Record and fixed VATE snapshot | Native execution and controls | VATE comparison | Outside this execution |
| --- | --- | --- | --- |
| [Vaara](run-records/vaara-2026-09-06/README.md), `v0.4.0`, 76 cases | One partial stale-status case; native `verify_grant` rejects age 301 s with a 300 s limit. Boundary and unconfigured-limit controls plus registry/admission checks are recorded. Maintainer replay passed all 3 TTL and 13 freshness/admission assertions. | The refusal and `should_execute: false` agree. Native `revocation_stale`, two missing named checks, and reason-code and primary-reason differences leave the selected case failing. | Other 75 cases; VATE's status-source subject/authority and availability semantics are not fully mapped; no upstream tool execution. |
| [Bolyra / x402](run-records/bolyra-x402-2026-09-07/README.md), `v0.4.0`, 76 cases | One partial audience case through native `verifyClassical` and the command host. Matching input P allows; N1 changes only `project_key`, N2 only the requested capability. Both deny. Maintainer replay reproduced all three verdicts and the presentation bytes. | N1 refusal and `should_execute: false` agree. Native `request_mismatch`, three missing named checks, and a missing legacy receipt-fixture reference leave the selected case failing. | Other 75 cases; attenuation, nonce consumption, application receipt retention, settlement, and post-execution linkage. P and N2 are auxiliary controls, not extra VATE cases. |
| [Pulse](external-sut-run-records.md#pulse-three-case-bounded-external-sut-run), `5a37f87de0190da44e619b1800261637e83dd7ed`, 75 cases | Three generated AP2 human-not-present inputs executed by the candidate's frozen native verifier; candidate-owned mapping, raw reports, and sensitivity probes are preserved. | Two selected cases match. Amount overrun remains `deny` where VATE expects `attenuate`. The other 72 entries are explicit skips. | The other 72 cases, later corpus snapshots, and general coverage of VATE predicates by native Pulse checks. |

The Vaara and Bolyra inputs use VATE
`cc072ef86f54791213a3e603a65b2f24f64b1b6d`, corpus digest
`b2a281e372b2e1d6b49be219c715fa69c0b2be237d29a6e1f0dda9c0659b6130`.
Pulse uses corpus digest
`988aae7d03dd5bb743e8e03e6ab1120ce8735a4837ac818ffd9d665de0c1e370`.
Archiving these records in a newer release does not evaluate newer corpus bytes.

These are solicited, bounded implementation experiments. They do not establish
full-corpus conformance, organic adoption, endorsement, or production readiness.
Bolyra and its x402 host form one experiment, not two independent SUT lines.

## Native predicates and submitted checks

### Vaara: stale-status admission

The [native freshness output](run-records/vaara-2026-09-06/freshness_admission.stdout.txt)
identifies `revocation_stale` at 301 s, acceptance at 300 s, and acceptance with
the freshness limit unconfigured. These controls locate the direct
`verify_grant` freshness boundary. Gateway controls use the real clock and do
not independently establish an exact one-second gateway boundary.

The [saved comparison](run-records/vaara-2026-09-06/compare-report.json)
reports `decision.outcome` and `evidence.verification.failure_reason` missing.
The projection preserves the native code instead of asserting checks for the
unresolved VATE mapping. Native freshness enforcement and complete VATE status
semantics therefore remain separate findings.

### Bolyra: request binding through the host

The [native report](run-records/bolyra-x402-2026-09-07/native-report.json)
identifies `detail.field: project_key` for N1 and `granted_capabilities` for N2.
The command host preserves the common `deny` / `request_mismatch` pair but does
not return those distinguishing details. Read the native report when identifying
which binding failed.

The [saved comparison](run-records/bolyra-x402-2026-09-07/compare-report.json)
has no reported `request.audience`, `target.audience`, or
`admission_receipt.decision` checks. The missing receipt reference is a
requirement of this legacy VATE fixture; it is not evidence that Bolyra failed
to retain an application receipt. That path was not exercised.

### Pulse: native result and mapper assertions

The [candidate mapper and raw reports](https://github.com/shibutatsu/pulse-ap2-x402-conformance/tree/3bb52c400535f28ee3f5d2e0a2bdb01e9c45c407/evidence/vate-pulse-bounded-2026-08-30)
make the projection rules inspectable:

| Selected case | Native predicate used by the projection | VATE named checks reported |
| --- | --- | --- |
| `allow-ap2-hnp-preauthorized-mandate` | `consistent: true` with no failure codes | `decision.outcome` and `evidence.verification.result` use native acceptance. `request.audience` and `evidence[0].protocol_hint` are mapper checks on the eligible VATE input. |
| `attenuate-ap2-hnp-amount-overrun` | `consistent: false`, exactly `AP2_X402_AMOUNT_MISMATCH` | None. The projection retains the non-attenuating refusal. |
| `deny-ap2-hnp-stale-mandate` | Stale input class, `consistent: false`, and `EIP3009_VALID_BEFORE_EXPIRED`; allowed failure codes are limited to that code and `AP2_MANDATE_TIME_INVALID` | `decision.outcome` and `evidence.verification.failure_reason` use the native expiry result. |

An unfamiliar native failure pattern projects as unsupported with no named
checks. A matching projection does not establish that the native verifier
implemented every predicate represented by mapper assertions.

Pulse's summary is `2 passed / 73 failed / 72 skipped / 75 total`: the fixed
runner counts skipped cases as failures. It means one executed mismatch and 72
unexecuted cases, not 73 failed native executions. Vaara and Bolyra each have one
executed partial case and 75 missing results; a `0/76` summary is not 76 executed
failures.

## Reviewing a new negative result

For a negative test, preserve evidence that the prerequisite was reached before
attributing the refusal to the intended check. A useful example is
[MCP conformance PR #483](https://github.com/modelcontextprotocol/conformance/pull/483):
the resource-mismatch scenario requires observing a protected-resource metadata
request before interpreting the absence of authorization as the expected
rejection. An inert client instead produces an untestable result. Even after
that prerequisite, unrelated aborts can remain indistinguishable in a black-box
test.

For a VATE submission, record the native entry point, consumed input, relevant
configuration, controlled changes, diagnostic output, and projection rule.
Mark the remaining predicates as unreported or not evaluated, as appropriate.
The current [SUT schema](../../schemas/sut-result.schema.json) provides case
statuses and named boolean checks, but no standardized per-check
`propertyReached` or `notTestable` state. Record reachability evidence in the
run documentation; do not present those labels as existing VATE schema fields.

The reference runner checks submitted claims and referenced artifacts under the
[documented comparison rules](../public-claim-boundary.md#report-and-command-boundaries).
It does not observe the native implementation's internal control flow. Use the
[external SUT quickstart](external-sut-quickstart.md) to prepare a new result with
its own snapshot and evidence.
