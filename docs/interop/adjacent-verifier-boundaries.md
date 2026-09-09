# VATE, EVC, ACS, and ACLE-MCP: Responsibility Boundaries

VATE records a verifier's admission decision, any narrowing of the requested
authority, and the link from that decision to later outcome evidence. This
comparison helps implementers locate that responsibility alongside a command
host, an agent-control channel, or an invocation-time execution gate.

The comparison is an informative reading of the sources pinned below, reviewed
on 2026-09-10. It defines no adapter, wire mapping, or compatibility profile.
For executed implementation evidence, use the
[external SUT coverage guide](../conformance/external-sut-coverage.md).

## EVC: verifier verdict and host enforcement

[EVC draft-02](https://www.ietf.org/archive/id/draft-kondoju-evc-02.html)
specifies a subprocess contract: a JSON request enters the verifier and one
verdict returns to the host. The host applies the decision before the side
effect. It is an individual Internet-Draft, not an RFC.

| Responsibility | EVC draft-02 | VATE |
| --- | --- | --- |
| Admission result | Closed `allow` / `deny` verdict schema and denial-code registry (§4). | `allow`, `attenuate`, or `deny`, with separate `should_execute` semantics. |
| Narrowing authority | The verdict schema carries no attenuation result. | An admission receipt for an `attenuate` decision binds original and effective request hashes, changes, effective constraints, and whether a new permit is required. |
| Process failure | Nonzero exit overrides stdout `allow`; timeout, signal death, malformed output, and schema failure deny (§6). | Corpus decisions and receipt checks do not provide a subprocess supervisor. The deployment owns execution gating. |
| Nonce consumption | Verifier or host owns durable storage; host mode atomically reserves each `consume_nonces` entry before acting and rejects any conflict (§7). | Replay-state evidence can enter admission checks; submitting that evidence does not itself implement an atomic replay store. |
| Later outcome evidence | The verdict governs admission; receipt-chain semantics belong to the verifier's receipt library (§13.6). | Post-execution checks link the admission receipt and effective request to reported execution and constraints. External evidence quality still bounds the result. |

VATE attenuation cannot be translated into an EVC `allow` without resolving
which effective request the host will execute and whether fresh authorization
is needed. An EVC denial code also requires an explicit mapping to VATE's
reason/check semantics. The table identifies those integration requirements;
it does not supply an executable mapping.

The published [Bolyra / x402 record](../conformance/run-records/bolyra-x402-2026-09-07/README.md)
reproduced three inputs at Bolyra
`511ccbba1a3c929f5803b233fdfd21e0b82bb913` and the x402 command host
`992f78e37178dc4d249eeb0e2dc0720120282dd1`. Those observations concern the
recorded binding controls. They do not test draft-02's complete host fixture
suite, abnormal process exits, or nonce consumption.

VATE sources: [attenuation semantics](../attenuation-semantics.md),
[SUT check semantics](../conformance/sut-adapter-contract.md#check-semantics),
and [report boundaries](../public-claim-boundary.md#report-and-command-boundaries).

## ACS: control hooks, decisions, and deployment posture

OWASP Agent Control Standard (ACS) defines communication between an Observed
Agent and a Guardian. The comparison uses
[ACS source revision `9d4a9daa`](https://github.com/GenAI-Security-Project/agent-control-standard/tree/9d4a9daa996fa2557b9959baeecad106f581fd62),
including its versioned conformance profiles.

| Responsibility | ACS at the pinned revision | VATE |
| --- | --- | --- |
| Control surface | Negotiated lifecycle/tool hooks and `ALLOW`, `DENY`, `MODIFY`, `ASK`, `DEFER` dispositions. | Admission and receipt artifacts for a selected action, with a corpus for comparing submitted results. |
| Applying a decision | The agent must wait for and honor a returned Guardian decision. A decision failure uses `on_decision_failure`, default `proceed`, optionally `deny`; fail-open proceeds are audited. | `should_execute` records the admission gate result; enforcement requires the consuming deployment to apply it. |
| Modification | `MODIFY` supports whole-payload replacement or disjoint structured edits. | `attenuate` records narrowed authority and binds original and effective requests; the terms have no automatic equivalence. |
| Integrity and replay | Core requires signed envelopes with an HMAC baseline, request identifiers, timestamps, and replay rejection. Crypto adds asymmetric signatures; Audit requires request-content hashes in the context chain. | Digest-bound evidence and report-bundle integrity make artifacts inspectable. The reference runner does not supply production signature validation or a runtime replay store. |
| Observation and results | Trace records supported steps and decisions; SessionContext provides a rolling chain. | Admission-to-outcome linkage checks compare reported execution with the admitted effective request and constraints. |

Sources: [ACS Instrument specification §§4, 6, 8, 10](https://github.com/GenAI-Security-Project/agent-control-standard/blob/9d4a9daa996fa2557b9959baeecad106f581fd62/docs/spec/instrument/specification.md),
[conformance profiles](https://github.com/GenAI-Security-Project/agent-control-standard/blob/9d4a9daa996fa2557b9959baeecad106f581fd62/docs/spec/conformance.md),
and [Trace events](https://github.com/GenAI-Security-Project/agent-control-standard/blob/9d4a9daa996fa2557b9959baeecad106f581fd62/docs/spec/trace/events.md).
The pinned conformance document describes profile claims as self-declared and
ships no conformance test suite. That describes this revision, not a finding
about an evaluated ACS deployment.

An integration review should identify which hooks actually cover the action,
which failure posture is configured, how modifications affect admitted
authority, and which resulting artifacts support later review. Supported hooks
or negotiated profiles alone do not show that a particular action traversed
and obeyed the control point. No ACS implementation is evaluated in VATE's
linked native SUT records.

## ACLE-MCP: invocation-bound leases and workload appraisal

[ACLE-MCP v1](https://arxiv.org/abs/2609.02690v1) binds delegated authority,
sender proof, fresh workload appraisal, and invocation constraints in a lease
consumed at a provider-side Execution Gate. Its Algorithm 1 also binds a
required receipt to the lease, request, appraisal, result digest, and declared
downstream path. Its scope therefore includes both admission and execution
evidence.

| Review question | ACLE-MCP v1 | VATE |
| --- | --- | --- |
| What anchors admission? | Invocation-scoped lease and fresh workload appraisal at the protected handler's gate. | The relying party's evidence/policy decision and the receipt that records it. |
| What makes enforcement effective? | A trusted, non-bypassable gate and the paper's other trust assumptions. | Deployment enforcement of the recorded decision; artifact comparison alone cannot establish route completeness. |
| What can be compared here? | The paper's mechanism, lease fields, and evaluation assumptions. | Named admission/linkage cases, result projection, and preserved semantic differences across native implementations. |

The main ACLE-MCP harness simulates sender proof and appraisal; separate
Keycloak/MCP and optional vTPM paths have narrower integration evidence.
This guide does not provide a case-by-case mapping or native ACLE-MCP run.

For a concrete comparison, choose one invocation or receipt obligation, name
its required fields and trust assumptions, and preserve the implementation's
native decision before projecting it into VATE. The
[coverage guide](../conformance/external-sut-coverage.md#reviewing-a-new-negative-result)
describes how to record reached and unreported checks without turning an
unrelated refusal into a passing negative result.
