# Verifiable Agent Trust Envelope

**Verifier admission receipts for risky external digital actions**

VATE is a verifier-side profile for deciding and recording whether an AI agent
may perform a risky external digital action.

It does not replace A2A, MCP, OAuth, OpenID, VC, SPIFFE, AP2, x402, or payment
mandates.
It is not an A2A core proposal or a universal trust layer.

A2A carries the task.
MCP, OAuth, AP2, VC, and related systems provide evidence.
VATE records the verifier decision: `allow`, `attenuate`, or `deny`.

VATE is not a human-in-the-loop (HITL) workflow product.
HITL review can be one policy or evidence pattern.
VATE focuses on verifier-side admission decisions and receipts for risky
external digital actions.

Read this as a discussion draft and gap-analysis question for the boundary
around risky writes and other external digital actions, not as a replacement for
adjacent protocols.

- `v0.1 discussion draft`
- `v0.2.0 archived May 5, 2026 review snapshot`
- `v0.3.0 archived May 10, 2026 AL2 verifier admission hardening snapshot`
- `v0.3.1 archived May 14, 2026 credibility and reviewability patch`
- `not production-ready`
- `not an official A2A extension, endorsement, certification, SDK, middleware package, or general compatibility proof`
- `not an A2A core proposal or universal trust layer`
- `no production approval implied`
- `seeking critique on boundary, verifier order, gap analysis, and artifact semantics`

[![DOI](https://zenodo.org/badge/1214949350.svg)](https://doi.org/10.5281/zenodo.19839768)

## Try It In 60 Seconds

```bash
python3 reference/quickstart-demo/run_demo.py
```

No dependencies. It narrates three committed v0.3 corpus cases: allow,
attenuate, and a fail-closed deny.

## Reviewer Entry Points

If you are reviewing the current `v0.3.1` discussion-draft snapshot or
main-branch work after it, start here:

- [Public claim boundary](docs/public-claim-boundary.md) - what this repo can
  and cannot claim publicly
- [One-hour external SUT or corpus review request](docs/conformance/external-sut-ask-1-hour.md) -
  smallest useful external review path for unclear cases, reason codes,
  artifact binding, or draft SUT results
- [Independent implementation review issue](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2) -
  public intake thread for external SUT questions, partial results, and
  implementation report links
- [External implementation call](docs/conformance/external-implementation-call.md) -
  short request for result files from implementations other than the repository
  reference runner, plus generated artifacts and implementation reports
- [External SUT quickstart](docs/conformance/external-sut-quickstart.md) - how
  a non-reference implementation can submit a result for `compare`
- [Implementation reporting](docs/conformance/implementation-reporting.md) -
  how to publish one implementation run against one corpus snapshot
- [A2A review package](docs/a2a/README.md) - metadata-only admission and receipt
  references for A2A-shaped flows
- [Known gaps](docs/known-gaps.md) - unresolved work and residual limitations

## The Problem

An external agent wants to perform a risky write against a remote system.
That risky write is one example of a broader risky external digital action: a
side effect that leaves the agent runtime and changes a relying party's
resource, record, payment state, or account state.

In that moment, the relying party often needs more than:

- discovery metadata
- a valid access token
- a stable identity label

It may also need to know:

- which actor is acting
- on whose behalf it acts
- whether the current runtime is fresh and genuine
- what task-scoped authority exists right now
- whether current status has narrowed or revoked that authority
- what receipt should exist after execution

This draft proposes a portable admission-and-receipt layer for that boundary.
The current repository makes that boundary concrete through a verifier-centered
`AL2` HTTP wedge that evaluates:

`status -> identity -> runtime -> permit -> policy`

That sequence is the semantic decision basis. An implementation still needs to
perform structural parsing, digest checks, proof / trust-anchor checks, and
freshness checks before it treats any input as authoritative or runs expensive
policy evaluation.

and returns `allow`, `attenuate`, or `deny` with a machine-readable admission
receipt.

The `v0.3` work keeps that verifier-side boundary but narrows the next deliverable to the [VATE AL2 Verifier Admission Profile v0.3](docs/profiles/vate-al2-verifier-admission-profile-v0.3.md).
That profile treats A2A, MCP, OAuth, VC, DID, OID4VP, Web Bot Auth, AP2, x402, ACP, and payment-token systems as adjacent layers that can provide evidence.
VATE defines how a relying party evaluates those inputs before execution and records the decision.
The open design question is which facts belong in task flow, transport
authorization, or adjacent evidence, and which facts belong in verifier-side
admission and receipt semantics.
For A2A reviewers, start with the A2A review package in
[docs/a2a/README.md](docs/a2a/README.md).

![Where Verifiable Agent Trust Envelope Fits](docs/figures/where-trust-envelope-fits-readme.png)

## What This Draft Adds

This draft is intentionally narrow.
It is strongest on the following boundary:

- separating **controller**, **principal**, **actor**, and **runtime**
- modeling **APC**, **ARP**, **AMP**, **AER**, and **ASN** as first-class artifacts
- making verifier-side ordering explicit for external digital write decisions
- treating **status** and **attenuation** as protocol concerns rather than afterthoughts
- separating verifier-signed **admission receipts** from later **post-execution receipts** where later evidence matters
- defining a reference-only **A2A metadata binding** for VATE admission and receipt artifacts

Attenuation is a first-class outcome. For example, a verifier can record that a
request for a USD 10000 transfer was admitted only with a USD 500 maximum,
approval above USD 100, and a short execution window. The receipt records both
the original request hash and the effective request hash so later execution
evidence can be checked against the narrowed authority.

## What This Draft Does Not Replace

This draft is not trying to become:

- an agent platform
- a prompt framework
- a multi-agent control plane
- an MCP or A2A connector suite
- a connector permission system
- a human approval UI or HITL workflow product
- a gateway or API management product
- a universal trust layer
- a universal identity registry
- a single global issuer

It is meant to compose with adjacent layers such as:

- `A2A` for discovery and delegation flow
- `MCP + OAuth` for tool and resource authorization
- `VC / JWT` for portable signed credentials
- `OpenID Federation / CAEP` for trust federation and status signaling
- `SPIFFE / workload identity / cloud attestation` for runtime authenticity anchors
- `AP2 / x402 / ACP / payment tokens` for commerce and payment authorization evidence

For the explicit non-goals, see [docs/non-goals.md](docs/non-goals.md).

## Close Adjacent Work

The public work most likely to be read as overlapping is:

- **Agent Permission Protocol (Crittora)**: explicit execution-time permission policy and enforcement gate
- **Open Agent Passport / APort**: passport and decision objects with policy enforcement
- **Agent Passport System (APS / AEOESS)**: broader identity, delegation, governance, and commerce stack
- **AgentROA**: policy enforcement around MCP-routed agent actions
- **Agent Auth / AIP drafts**: identity-first work around agent authentication and trust

This draft should not be presented as if those do not exist.
The intended claim is narrower:

- this repo is a reviewable draft for a specific verifier-side boundary
- its center of gravity is the composite artifact model across identity, runtime proof, task-scoped permit, status, and receipt
- it is not claiming to replace the adjacent standards or product layers above

Direct comparison note:

- [docs/close-adjacent-work-2026-04.md](docs/close-adjacent-work-2026-04.md)

## Read This In 5 Minutes

If you are new to the repo, the fastest path is:

1. this `README.md`
2. [docs/public-claim-boundary.md](docs/public-claim-boundary.md)
3. [docs/v0.3-in-5-minutes.md](docs/v0.3-in-5-minutes.md)
4. [docs/profiles/vate-al2-verifier-admission-profile-v0.3.md](docs/profiles/vate-al2-verifier-admission-profile-v0.3.md)
5. [docs/a2a/README.md](docs/a2a/README.md)
6. [docs/a2a/vate-a2a-extension-profile-v0.3.md](docs/a2a/vate-a2a-extension-profile-v0.3.md)
7. [docs/a2a-metadata-binding-v0.3.md](docs/a2a-metadata-binding-v0.3.md)
8. [docs/a2a-v1-extension-sketch-2026-05.md](docs/a2a-v1-extension-sketch-2026-05.md)
9. [docs/receipt-model-v0.3.md](docs/receipt-model-v0.3.md)
10. [docs/receipt-audit-walkthrough-v0.3.1.md](docs/receipt-audit-walkthrough-v0.3.1.md)
11. [docs/a2a-maintainer-brief-v0.3.md](docs/a2a-maintainer-brief-v0.3.md)
12. [docs/profiles/vate-al2-admission-interop-profile-2026-07.md](docs/profiles/vate-al2-admission-interop-profile-2026-07.md)
13. [conformance/al2-vate-v0.3/README.md](conformance/al2-vate-v0.3/README.md)
14. [docs/conformance/external-sut-quickstart.md](docs/conformance/external-sut-quickstart.md)
15. [docs/conformance/implementation-reporting.md](docs/conformance/implementation-reporting.md)
16. section `0` and section `1` of [docs/verifiable-agent-trust-envelope-spec-v0.1.md](docs/verifiable-agent-trust-envelope-spec-v0.1.md)
17. [reference/http-verifier-demo/README.md](reference/http-verifier-demo/README.md)

If you want the visual system view, see section `11` of [docs/verifiable-agent-trust-envelope-spec-v0.1.md](docs/verifiable-agent-trust-envelope-spec-v0.1.md).

If you want the shortest list of unresolved issues, read [docs/known-gaps.md](docs/known-gaps.md).

## Review Questions

The most useful feedback for this draft is currently:

- is the verifier-side boundary clear enough
- is the semantic `status -> identity -> runtime -> permit -> policy` ordering
  sound once proof, digest, trust, and freshness gates have failed closed
- are permit, receipt, status, and attenuation semantics coherent together
- is the difference from close adjacent work stated honestly and precisely enough
- can an external SUT produce digest-bound artifacts, a comparison report, and
  an implementation report without relying on the Python reference runner as
  the primary specification
- what should remain core versus move into profiles or extensions

## Current Status

- **Repository type**: protocol discussion draft
- **Document maturity**: early draft
- **Primary language**: English
- **Roadmap refresh date**: 2026-05-14
- **Primary battlefield**: `AL2` external digital write
- **Current archived snapshot**: `v0.3.1` credibility and reviewability patch
- **Implemented artifacts**: v0.3 schemas and examples; runnable AL2 fixture corpus with negative cases; SUT comparison and implementation-reporting formats; dependency-free verifier core and A2A-shaped adapter demo; package-private TypeScript reference helpers for digest-bound artifacts, SUT result shaping, and A2A metadata shape checks; focused adjacent evidence fixtures and crosswalk notes
- **Immediate next action**: collect one SUT result from an implementation that
  is not the repository reference runner, plus generated artifacts or a
  controlled artifact bundle, an implementation report, and a local bundle
  verification report for one `v0.3` corpus snapshot; if that is too heavy for a
  first reviewer, collect a three-case corpus review that identifies unclear
  boundaries, reason codes, or artifact requirements
- **Planned later**: pairwise presentation profile, richer capability registry, formal `AID`, physical `ABS` profiles

The conformance artifacts record one implementation run against one corpus
snapshot. They do not imply endorsement, production approval, or a general
compatibility claim.

## Repository Map

- [docs/verifiable-agent-trust-envelope-spec-v0.1.md](docs/verifiable-agent-trust-envelope-spec-v0.1.md)
  Detailed requirements and reference architecture
- [docs/close-adjacent-work-2026-04.md](docs/close-adjacent-work-2026-04.md)
  Direct comparison with the closest public adjacent work
- [docs/public-claim-boundary.md](docs/public-claim-boundary.md)
  Allowed, discouraged, and forbidden public claim language for the current
  discussion-draft repository state
- [docs/use-cases.md](docs/use-cases.md)
  Three background scenarios from the original `v0.1` framing
- [docs/verifier-validation-flow.md](docs/verifier-validation-flow.md)
  Verifier-side validation order
- [docs/profiles/al2-minimal-profile.md](docs/profiles/al2-minimal-profile.md)
  Baseline profile for the current reference battlefield
- [docs/profiles/vate-al2-verifier-admission-profile-v0.3.md](docs/profiles/vate-al2-verifier-admission-profile-v0.3.md)
  Narrow v0.3 profile for verifier-side AL2 admission decisions
- [docs/profiles/vate-al2-admission-interop-profile-2026-07.md](docs/profiles/vate-al2-admission-interop-profile-2026-07.md)
  Narrow conformance-facing AL2 admission interop profile
- [docs/profiles/vate-proof-profile-jose-jcs-v0.2.md](docs/profiles/vate-proof-profile-jose-jcs-v0.2.md)
  Review boundary for future JOSE/JCS production proof verification
- [docs/reason-codes.md](docs/reason-codes.md)
  Canonical machine-readable reason codes for AL2 conformance
- [docs/evidence-types.md](docs/evidence-types.md)
  Human-readable evidence type and protocol hint vocabulary for AL2 conformance
- [registries/evidence-vocabulary.v0.3.json](registries/evidence-vocabulary.v0.3.json)
  Canonical machine-readable evidence vocabulary registry, including allowed type/hint pairs
- [docs/attenuation-semantics.md](docs/attenuation-semantics.md)
  Machine-readable attenuation semantics for AL2 conformance
- [docs/v0.3-in-5-minutes.md](docs/v0.3-in-5-minutes.md)
  Short entry point for the v0.3 draft
- [docs/a2a/README.md](docs/a2a/README.md)
  A2A-shaped metadata review package entry point
- [docs/a2a/vate-a2a-extension-profile-v0.3.md](docs/a2a/vate-a2a-extension-profile-v0.3.md)
  Consolidated metadata-only A2A extension profile draft for VATE references
- [docs/a2a-maintainer-brief-v0.3.md](docs/a2a-maintainer-brief-v0.3.md)
  A2A maintainer-oriented summary of the metadata-only admission and receipt binding
- [docs/release-gate-v0.3.0.md](docs/release-gate-v0.3.0.md)
  Archived technical gate used before cutting the v0.3.0 discussion-draft
  pre-release
- [docs/release-notes/v0.3.1.md](docs/release-notes/v0.3.1.md)
  Archived notes for the v0.3.1 credibility and reviewability patch
- [docs/a2a-issue-update-2026-05.md](docs/a2a-issue-update-2026-05.md)
  Short A2A-adjacent issue update draft after the runnable v0.2 artifacts
- [docs/a2a-metadata-binding-v0.3.md](docs/a2a-metadata-binding-v0.3.md)
  Reference-only A2A metadata binding for VATE admission and receipt artifacts
- [docs/a2a-v1-extension-sketch-2026-05.md](docs/a2a-v1-extension-sketch-2026-05.md)
  A2A v1.0-shaped extension sketch using optional activation, signed Agent Card evidence, and digest-bound VATE references
- [docs/namespace-migration.md](docs/namespace-migration.md)
  Repository-scoped draft URI and persistent namespace migration discipline
- [docs/extension-fields.md](docs/extension-fields.md)
  Handling rules for unknown extension fields before schema tightening
- [docs/ecosystem-positioning-2026-05.md](docs/ecosystem-positioning-2026-05.md)
  Current VATE boundary relative to MCP/OAuth, A2A, AP2, ACP/UCP, and x402
- [docs/receipt-model-v0.3.md](docs/receipt-model-v0.3.md)
  v0.3 split between admission receipts and post-execution receipts
- [docs/receipt-audit-walkthrough-v0.3.1.md](docs/receipt-audit-walkthrough-v0.3.1.md)
  v0.3.1 reviewability walkthrough for following digest-bound receipt,
  post-execution, policy snapshot, and report-bundle references
- [docs/trust-bundle-hardening.md](docs/trust-bundle-hardening.md)
  Trust-bundle checks for issuer, key, algorithm, evidence type, status, and validity windows
- [docs/conformance/corpus-format.md](docs/conformance/corpus-format.md)
  Language-neutral corpus index and digest rules for non-reference implementations
- [docs/conformance/artifact-versioning.md](docs/conformance/artifact-versioning.md)
  Date-stamped conformance artifact versioning rules for the July 2026 target line
- [docs/conformance/sut-adapter-contract.md](docs/conformance/sut-adapter-contract.md)
  SUT result contract and comparison command for external implementations
- [docs/conformance/external-implementation-call.md](docs/conformance/external-implementation-call.md)
  Short call for independent implementation review materials, with the public
  intake thread for questions and result links
- [docs/conformance/external-sut-quickstart.md](docs/conformance/external-sut-quickstart.md)
  Short path for external SUT authors to produce, compare, and bundle-check implementation reports
- [docs/profiles/vate-jose-proof-profile-notes-2026-07.md](docs/profiles/vate-jose-proof-profile-notes-2026-07.md)
  Production JOSE proof profile notes and current detached fixture boundary
- [conformance/al2-vate-v0.3/README.md](conformance/al2-vate-v0.3/README.md)
  Runnable conformance corpus for v0.3 admission and receipt semantics
- [docs/conformance/implementation-reporting.md](docs/conformance/implementation-reporting.md)
  Implementation report format for publishing one run against one corpus snapshot
- [docs/conformance/report-integrity.md](docs/conformance/report-integrity.md)
  Publication and integrity guidance for SUT, conformance, and implementation reports
- [reference/vate-verifier-core/README.md](reference/vate-verifier-core/README.md)
  Dependency-free verifier core for AL2 admission fixtures
- [reference/a2a-metadata-adapter-demo/README.md](reference/a2a-metadata-adapter-demo/README.md)
  Dependency-free A2A-shaped metadata adapter demo
- [packages/vate-core-ts/README.md](packages/vate-core-ts/README.md)
  Package-private TypeScript helpers for digest descriptors, artifact references, and SUT result entries
- [packages/vate-a2a-ts/README.md](packages/vate-a2a-ts/README.md)
  Package-private TypeScript helpers for the reference-only A2A metadata binding
- [docs/interop/oap-aport-crosswalk.md](docs/interop/oap-aport-crosswalk.md)
  OAP / APort decision evidence crosswalk for VATE admission receipts
- [docs/interop/aae-crosswalk.md](docs/interop/aae-crosswalk.md)
  Agent Authorization Envelope evidence crosswalk for VATE admission receipts
- [docs/interop/ap2-ucp-commerce-crosswalk.md](docs/interop/ap2-ucp-commerce-crosswalk.md)
  AP2 / UCP commerce evidence crosswalk for VATE admission receipts
- [docs/interop/ap2-human-not-present-evidence.md](docs/interop/ap2-human-not-present-evidence.md)
  AP2 Human Not Present payment-authority evidence fixtures
- [docs/interop/payment-evidence-frame-crosswalk.md](docs/interop/payment-evidence-frame-crosswalk.md)
  Payment Evidence Frame evidence crosswalk for VATE admission and post-execution linkage
- [docs/known-gaps.md](docs/known-gaps.md)
  Current unresolved design gaps
- [reference/minimal-al2-demo/README.md](reference/minimal-al2-demo/README.md)
  Educational artifact and status demo
- [reference/http-verifier-demo/README.md](reference/http-verifier-demo/README.md)
  Verifier-centered HTTP wedge

## Verification

Reading the draft does not require any local setup.
The optional dependency below is only for contributors who want strict JSON Schema validation, and the virtual environment should live outside this repository.

Dependency-free sanity check:

```bash
python3 scripts/check_repo.py
```

The AL2 corpus has separate commands for repository fixture checks and external
implementation comparison:

```bash
python3 scripts/vate_conformance.py run \
  --corpus-root conformance/al2-vate-v0.3 \
  --report /tmp/vate-conformance-report.json
```

`run` checks the committed fixture artifacts with the reference runner. It is
not an external implementation result.

```bash
python3 scripts/vate_conformance.py compare \
  --corpus-root conformance/al2-vate-v0.3 \
  --sut-results examples/conformance/sut-results-pass.example.json \
  --report /tmp/vate-sut-compare-report.json
```

`compare` checks an external SUT result file against the same corpus snapshot.
Independent implementation review should use the SUT adapter contract and the
`compare` path. External SUT authors can start with
[docs/conformance/external-sut-quickstart.md](docs/conformance/external-sut-quickstart.md).
Questions, partial results, unsupported-case reports, and implementation report
links can be shared in
[issue #2](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2).

Optional strict schema validation:

```bash
python3 -m venv ../verifiable-agent-trust-envelope-draft-venv
. ../verifiable-agent-trust-envelope-draft-venv/bin/activate
python3 -m pip install -r requirements-dev.txt
python3 scripts/check_repo_strict.py
```

Package-private TypeScript reference helpers are available for contributors who
want language-level examples of the same digest-bound reference and A2A metadata
shapes:

```bash
npm ci
npm run ts:check
npm run ts:test
```

These packages are not official A2A extensions, endorsements, certifications,
SDKs, middleware packages, or general compatibility proofs. They do not imply
production approval and do not add production JOSE/JCS verification.

## Related Documents

- [FAQ.md](FAQ.md)
- [ROADMAP.md](ROADMAP.md)
- [docs/public-claim-boundary.md](docs/public-claim-boundary.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [docs/standards-and-ecosystem-landscape-2026-04.md](docs/standards-and-ecosystem-landscape-2026-04.md)
- [docs/standards-and-ecosystem-landscape-2026-05.md](docs/standards-and-ecosystem-landscape-2026-05.md)
- [docs/v0.3-in-5-minutes.md](docs/v0.3-in-5-minutes.md)
- [docs/a2a/README.md](docs/a2a/README.md)
- [docs/a2a/vate-a2a-extension-profile-v0.3.md](docs/a2a/vate-a2a-extension-profile-v0.3.md)
- [docs/a2a-maintainer-brief-v0.3.md](docs/a2a-maintainer-brief-v0.3.md)
- [docs/release-notes/v0.3.0.md](docs/release-notes/v0.3.0.md)
- [docs/non-goals.md](docs/non-goals.md)
- [docs/delegated-identity-composition-example.md](docs/delegated-identity-composition-example.md)
- [docs/transport-bindings.md](docs/transport-bindings.md)
- [docs/a2a-metadata-binding-v0.3.md](docs/a2a-metadata-binding-v0.3.md)
- [docs/a2a-v1-extension-sketch-2026-05.md](docs/a2a-v1-extension-sketch-2026-05.md)
- [docs/receipt-model-v0.3.md](docs/receipt-model-v0.3.md)
- [docs/jws-packaging-and-status-delivery.md](docs/jws-packaging-and-status-delivery.md)
- [docs/threat-model.md](docs/threat-model.md)
- [docs/status-network-model.md](docs/status-network-model.md)
- [docs/conformance-and-negative-tests.md](docs/conformance-and-negative-tests.md)
- [docs/interop/aae-crosswalk.md](docs/interop/aae-crosswalk.md)
- [docs/interop/payment-evidence-frame-crosswalk.md](docs/interop/payment-evidence-frame-crosswalk.md)

## Authoring Note

AI tools were used to assist drafting, review, and reference implementation work in this repository.
The maintainer is responsible for the final structure, scope decisions, and published contents.

## How to Cite

If you reference the archived May 14, 2026 `v0.3.1` credibility and
reviewability patch, cite:

- Version DOI: [10.5281/zenodo.20173995](https://doi.org/10.5281/zenodo.20173995)
- All-version concept DOI: [10.5281/zenodo.19839768](https://doi.org/10.5281/zenodo.19839768)

If you reference unarchived main-branch changes after `v0.3.1`, cite the
repository URL and exact commit SHA in addition to the latest applicable
archived version DOI.

If you reference the archived May 10, 2026 `v0.3.0` discussion-draft
pre-release snapshot, cite:

- Version DOI: [10.5281/zenodo.20107413](https://doi.org/10.5281/zenodo.20107413)

If you reference the archived May 5, 2026 `v0.2.0` snapshot, cite:

- Version DOI: [10.5281/zenodo.20043166](https://doi.org/10.5281/zenodo.20043166)

- Earlier `v0.1.0` DOI: [10.5281/zenodo.19839769](https://doi.org/10.5281/zenodo.19839769)
- Machine-readable metadata: [CITATION.cff](CITATION.cff)

## License

This repository is licensed under the [Apache License 2.0](LICENSE).
