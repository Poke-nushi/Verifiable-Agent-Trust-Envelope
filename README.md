# Verifiable Agent Trust Envelope

**Verifier admission receipts for risky agent actions**

VATE is a verifier-side profile for deciding and recording whether an external
AI agent may perform a risky digital action.

It does not replace A2A, MCP, OAuth, OpenID, VC, SPIFFE, AP2, x402, or payment
mandates.

A2A carries the task.
MCP, OAuth, AP2, VC, and related systems provide evidence.
VATE records the verifier decision: `allow`, `attenuate`, or `deny`.

- `v0.1 discussion draft`
- `v0.2 AL2 verifier admission profile draft`
- `not production-ready`
- `no endorsement or production approval implied`
- `seeking critique on boundary, verifier order, and artifact semantics`

[![DOI](https://zenodo.org/badge/1214949350.svg)](https://doi.org/10.5281/zenodo.19839768)

## The Problem

An external agent wants to perform a risky write against a remote system.

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

The `v0.2` work keeps that verifier-side boundary but narrows the next deliverable to the [VATE AL2 Verifier Admission Profile v0.2](docs/profiles/vate-al2-verifier-admission-profile-v0.2.md).
That profile treats A2A, MCP, OAuth, VC, DID, OID4VP, Web Bot Auth, AP2, x402, ACP, and payment-token systems as adjacent layers that can provide evidence.
VATE defines how a relying party evaluates those inputs before execution and records the decision.
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

## What This Draft Does Not Replace

This draft is not trying to become:

- an agent platform
- a multi-agent control plane
- an MCP or A2A connector suite
- a gateway or API management product
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
2. [docs/v0.2-in-5-minutes.md](docs/v0.2-in-5-minutes.md)
3. [docs/profiles/vate-al2-verifier-admission-profile-v0.2.md](docs/profiles/vate-al2-verifier-admission-profile-v0.2.md)
4. [docs/a2a/README.md](docs/a2a/README.md)
5. [docs/a2a/vate-a2a-extension-profile-v0.2.md](docs/a2a/vate-a2a-extension-profile-v0.2.md)
6. [docs/a2a-metadata-binding-v0.2.md](docs/a2a-metadata-binding-v0.2.md)
7. [docs/a2a-v1-extension-sketch-2026-05.md](docs/a2a-v1-extension-sketch-2026-05.md)
8. [docs/receipt-model-v0.2.md](docs/receipt-model-v0.2.md)
9. [docs/a2a-maintainer-brief-v0.2.md](docs/a2a-maintainer-brief-v0.2.md)
10. [docs/profiles/vate-al2-admission-interop-profile-2026-07.md](docs/profiles/vate-al2-admission-interop-profile-2026-07.md)
11. [conformance/al2-vate-v0.2/README.md](conformance/al2-vate-v0.2/README.md)
12. [docs/conformance/implementation-reporting.md](docs/conformance/implementation-reporting.md)
13. section `0` and section `1` of [docs/verifiable-agent-trust-envelope-spec-v0.1.md](docs/verifiable-agent-trust-envelope-spec-v0.1.md)
14. [reference/http-verifier-demo/README.md](reference/http-verifier-demo/README.md)

If you want the visual system view, see section `11` of [docs/verifiable-agent-trust-envelope-spec-v0.1.md](docs/verifiable-agent-trust-envelope-spec-v0.1.md).

If you want the shortest list of unresolved issues, read [docs/known-gaps.md](docs/known-gaps.md).

## Review Questions

The most useful feedback for this draft is currently:

- is the verifier-side boundary clear enough
- is the semantic `status -> identity -> runtime -> permit -> policy` ordering
  sound once proof, digest, trust, and freshness gates have failed closed
- are permit, receipt, status, and attenuation semantics coherent together
- is the difference from close adjacent work stated honestly and precisely enough
- what should remain core versus move into profiles or extensions

## Current Status

- **Repository type**: protocol discussion draft
- **Document maturity**: early draft
- **Primary language**: English
- **Research refresh date**: 2026-05-07
- **Primary battlefield**: `AL2` external digital write
- **Implemented artifacts**: v0.2 schemas and examples; runnable AL2 fixture corpus with negative cases; SUT comparison and implementation-reporting formats; dependency-free verifier core and A2A-shaped adapter demo; focused adjacent evidence fixtures and crosswalk notes
- **Planned later**: pairwise presentation profile, richer capability registry, formal `AID`, physical `ABS` profiles

The conformance artifacts record one implementation run against one corpus
snapshot. They do not imply endorsement, production approval, or a general
compatibility claim.

## Repository Map

- [docs/verifiable-agent-trust-envelope-spec-v0.1.md](docs/verifiable-agent-trust-envelope-spec-v0.1.md)
  Detailed requirements and reference architecture
- [docs/close-adjacent-work-2026-04.md](docs/close-adjacent-work-2026-04.md)
  Direct comparison with the closest public adjacent work
- [docs/use-cases.md](docs/use-cases.md)
  Three concrete scenarios for the current `v0.1` wedge
- [docs/verifier-validation-flow.md](docs/verifier-validation-flow.md)
  Verifier-side validation order
- [docs/profiles/al2-minimal-profile.md](docs/profiles/al2-minimal-profile.md)
  Baseline profile for the current reference battlefield
- [docs/profiles/vate-al2-verifier-admission-profile-v0.2.md](docs/profiles/vate-al2-verifier-admission-profile-v0.2.md)
  Narrow v0.2 profile for verifier-side AL2 admission decisions
- [docs/profiles/vate-al2-admission-interop-profile-2026-07.md](docs/profiles/vate-al2-admission-interop-profile-2026-07.md)
  Narrow conformance-facing AL2 admission interop profile
- [docs/reason-codes.md](docs/reason-codes.md)
  Canonical machine-readable reason codes for AL2 conformance
- [docs/evidence-types.md](docs/evidence-types.md)
  Human-readable evidence type and protocol hint vocabulary for AL2 conformance
- [registries/evidence-vocabulary.v0.2.json](registries/evidence-vocabulary.v0.2.json)
  Canonical machine-readable evidence vocabulary registry, including allowed type/hint pairs
- [docs/attenuation-semantics.md](docs/attenuation-semantics.md)
  Machine-readable attenuation semantics for AL2 conformance
- [docs/v0.2-in-5-minutes.md](docs/v0.2-in-5-minutes.md)
  Short entry point for the v0.2 draft
- [docs/a2a/README.md](docs/a2a/README.md)
  A2A-compatible community profile review package entry point
- [docs/a2a/vate-a2a-extension-profile-v0.2.md](docs/a2a/vate-a2a-extension-profile-v0.2.md)
  Consolidated metadata-only A2A extension profile draft for VATE references
- [docs/a2a-maintainer-brief-v0.2.md](docs/a2a-maintainer-brief-v0.2.md)
  A2A maintainer-oriented summary of the metadata-only admission and receipt binding
- [docs/a2a-issue-update-2026-05.md](docs/a2a-issue-update-2026-05.md)
  Short A2A-adjacent issue update draft after the runnable v0.2 artifacts
- [docs/a2a-metadata-binding-v0.2.md](docs/a2a-metadata-binding-v0.2.md)
  Reference-only A2A metadata binding for VATE admission and receipt artifacts
- [docs/a2a-v1-extension-sketch-2026-05.md](docs/a2a-v1-extension-sketch-2026-05.md)
  A2A v1.0-shaped extension sketch using optional activation, signed Agent Card evidence, and digest-bound VATE references
- [docs/namespace-migration.md](docs/namespace-migration.md)
  Repository-scoped draft URI and persistent namespace migration discipline
- [docs/extension-fields.md](docs/extension-fields.md)
  Handling rules for unknown extension fields before schema tightening
- [docs/ecosystem-positioning-2026-05.md](docs/ecosystem-positioning-2026-05.md)
  Current VATE boundary relative to MCP/OAuth, A2A, AP2, ACP/UCP, and x402
- [docs/receipt-model-v0.2.md](docs/receipt-model-v0.2.md)
  v0.2 split between admission receipts and post-execution receipts
- [docs/trust-bundle-hardening.md](docs/trust-bundle-hardening.md)
  Trust-bundle checks for issuer, key, algorithm, evidence type, status, and validity windows
- [docs/conformance/corpus-format.md](docs/conformance/corpus-format.md)
  Language-neutral corpus index and digest rules for non-reference implementations
- [docs/conformance/artifact-versioning.md](docs/conformance/artifact-versioning.md)
  Date-stamped conformance artifact versioning rules for the July 2026 target line
- [docs/conformance/sut-adapter-contract.md](docs/conformance/sut-adapter-contract.md)
  SUT result contract and comparison command for external implementations
- [docs/profiles/vate-jose-proof-profile-notes-2026-07.md](docs/profiles/vate-jose-proof-profile-notes-2026-07.md)
  Production JOSE proof profile notes and current detached fixture boundary
- [conformance/al2-vate-v0.2/README.md](conformance/al2-vate-v0.2/README.md)
  Runnable conformance corpus for v0.2 admission and receipt semantics
- [docs/conformance/implementation-reporting.md](docs/conformance/implementation-reporting.md)
  Implementation report format for publishing one run against one corpus snapshot
- [docs/conformance/report-integrity.md](docs/conformance/report-integrity.md)
  Publication and integrity guidance for SUT, conformance, and implementation reports
- [reference/vate-verifier-core/README.md](reference/vate-verifier-core/README.md)
  Dependency-free verifier core for AL2 admission fixtures
- [reference/a2a-metadata-adapter-demo/README.md](reference/a2a-metadata-adapter-demo/README.md)
  Dependency-free A2A-shaped metadata adapter demo
- [docs/interop/oap-aport-crosswalk.md](docs/interop/oap-aport-crosswalk.md)
  OAP / APort decision evidence crosswalk for VATE admission receipts
- [docs/interop/ap2-ucp-commerce-crosswalk.md](docs/interop/ap2-ucp-commerce-crosswalk.md)
  AP2 / UCP commerce evidence crosswalk for VATE admission receipts
- [docs/interop/ap2-human-not-present-evidence.md](docs/interop/ap2-human-not-present-evidence.md)
  AP2 Human Not Present payment-authority evidence fixtures
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
  --corpus-root conformance/al2-vate-v0.2 \
  --report /tmp/vate-conformance-report.json
```

`run` checks the committed fixture artifacts with the reference runner. It is
not an external implementation result.

```bash
python3 scripts/vate_conformance.py compare \
  --corpus-root conformance/al2-vate-v0.2 \
  --sut-results examples/conformance/sut-results-pass.example.json \
  --report /tmp/vate-sut-compare-report.json
```

`compare` checks an external SUT result file against the same corpus snapshot.
Independent implementation review should use the SUT adapter contract and the
`compare` path.

Optional strict schema validation:

```bash
python3 -m venv ../verifiable-agent-trust-envelope-draft-venv
. ../verifiable-agent-trust-envelope-draft-venv/bin/activate
python3 -m pip install -r requirements-dev.txt
python3 scripts/check_repo_strict.py
```

## Related Documents

- [FAQ.md](FAQ.md)
- [ROADMAP.md](ROADMAP.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [docs/standards-and-ecosystem-landscape-2026-04.md](docs/standards-and-ecosystem-landscape-2026-04.md)
- [docs/standards-and-ecosystem-landscape-2026-05.md](docs/standards-and-ecosystem-landscape-2026-05.md)
- [docs/v0.2-in-5-minutes.md](docs/v0.2-in-5-minutes.md)
- [docs/a2a/README.md](docs/a2a/README.md)
- [docs/a2a/vate-a2a-extension-profile-v0.2.md](docs/a2a/vate-a2a-extension-profile-v0.2.md)
- [docs/a2a-maintainer-brief-v0.2.md](docs/a2a-maintainer-brief-v0.2.md)
- [docs/release-notes/v0.2.0.md](docs/release-notes/v0.2.0.md)
- [docs/non-goals.md](docs/non-goals.md)
- [docs/delegated-identity-composition-example.md](docs/delegated-identity-composition-example.md)
- [docs/transport-bindings.md](docs/transport-bindings.md)
- [docs/a2a-metadata-binding-v0.2.md](docs/a2a-metadata-binding-v0.2.md)
- [docs/a2a-v1-extension-sketch-2026-05.md](docs/a2a-v1-extension-sketch-2026-05.md)
- [docs/receipt-model-v0.2.md](docs/receipt-model-v0.2.md)
- [docs/jws-packaging-and-status-delivery.md](docs/jws-packaging-and-status-delivery.md)
- [docs/threat-model.md](docs/threat-model.md)
- [docs/status-network-model.md](docs/status-network-model.md)
- [docs/conformance-and-negative-tests.md](docs/conformance-and-negative-tests.md)

## Authoring Note

AI tools were used to assist drafting, review, and reference implementation work in this repository.
The maintainer is responsible for the final structure, scope decisions, and published contents.

## How to Cite

If you reference the May 5, 2026 v0.2 review snapshot in writing, please cite
the version-specific Zenodo archive below. For the current `main` branch, cite
the repository URL and commit SHA as well; the archived DOI may lag current
`main` until the next pre-release archive is cut.

- Version DOI: [10.5281/zenodo.20043166](https://doi.org/10.5281/zenodo.20043166)
- All-version concept DOI: [10.5281/zenodo.19839768](https://doi.org/10.5281/zenodo.19839768)
- Earlier `v0.1.0` DOI: [10.5281/zenodo.19839769](https://doi.org/10.5281/zenodo.19839769)
- Machine-readable metadata: [CITATION.cff](CITATION.cff)

## License

This repository is licensed under the [Apache License 2.0](LICENSE).
