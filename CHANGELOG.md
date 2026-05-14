# Changelog

This file records dated public changes to the discussion draft.

## 2026-05-14

- Started the v0.3.1 credibility and reviewability patch.
- Defined canonical emitted AL2 attenuation `effective_constraints` names for
  admission receipts and kept legacy aliases out of emitted receipt semantics.
- Added fail-closed attenuation cases for legacy emitted aliases and
  string-valued approval constraints.
- Added a receipt audit walkthrough for following digest-bound admission,
  post-execution, policy snapshot, and report-bundle references.
- Archived the v0.3.1 credibility and reviewability patch on Zenodo and
  assigned version DOI [10.5281/zenodo.20173995](https://doi.org/10.5281/zenodo.20173995).
- Kept AgentKit, AgentBook, World ID, and other adjacent-protocol-specific
  evidence vocabulary expansion out of the v0.3.1 scope.

## 2026-05-10

- Prepared the v0.3.0 AL2 evidence reference hardening release candidate.
- Updated current schema and profile identifiers to
  `VATE-AL2-Verifier-Admission-v0.3`.
- Required non-empty `evidence_refs` for AL2 admission requests.
- Added the `deny-empty-evidence-refs` fail-closed conformance case.
- Split archived v0.2.0 release documentation from current v0.3.0 hardening
  work.
- Kept A2A-shaped metadata review wording non-official and metadata-only.

## 2026-05-09

- Synchronized the consolidated A2A review package under `docs/a2a/`, including
  the implementer entry point and v0.2 extension-profile draft for
  metadata-only, digest-bound admission and receipt references.
- Tightened A2A metadata artifact reference URI shape validation while keeping
  remote dereference and trust decisions outside schema validation.
- Added a command-first external SUT quickstart for producing SUT results,
  comparing them against the AL2 v0.2 corpus, generating implementation
  reports, and locally verifying report-bundle digest linkage.
- Added package-private TypeScript reference helpers for digest-bound artifact
  references, SUT result entry shaping, and A2A metadata validation. These
  helpers are not published SDKs and do not implement production JOSE/JCS
  verification.
- Hardened the AL2 v0.2 conformance package with 59 runnable corpus cases,
  artifact-backed SUT comparison, implementation report generation, and local
  report-bundle digest-chain verification.
- Added byte-level detached JOSE fixture coverage for runtime attestation and
  A2A signed Agent Card evidence while keeping production JOSE / PKI
  verification outside the v0.2 conformance claim.
- Added the corpus-bound `allow-a2a-signed-agent-card-evidence` case with
  digest-bound admission receipt evidence, proof-package artifacts, and trust
  bundle references.
- Added namespace migration, extension-field handling, report integrity,
  implementation reporting, artifact versioning, evidence vocabulary, and
  SUT adapter contract guidance for independent implementation review.
- Strengthened failure semantics for reason-code ordering, AL2 context binding,
  replay and freshness checks, attenuation boundaries, transport-bound
  MCP/OAuth authority, policy snapshot digests, and post-execution linkage.

## 2026-05-07

- Added optional policy snapshot references and digests to the v0.2 admission receipt and A2A metadata binding, keeping policy semantics outside A2A core while improving audit traceability.

## 2026-05-04

- Added the draft `VATE AL2 Verifier Admission Profile v0.2`.
- Added a reference-only A2A metadata binding for VATE admission and receipt artifacts.
- Added a v0.2 receipt model that separates admission receipts from post-execution receipts.
- Added a short `v0.2 in 5 minutes` reader path and a `v0.2.0` release notes draft.
- Added an A2A maintainer brief and a v0.2 mini conformance corpus with named verifier outcomes and self-contained negative-case receipt fixtures.
- Added v0.2 schemas and examples for artifact references, evidence references, admission requests, A2A metadata, admission receipts, and post-execution receipts.
- Updated non-goals, transport binding notes, verifier validation flow, known gaps, conformance notes, roadmap, and README links for the v0.2 direction.

## 2026-04-28

- Archived the `v0.1` discussion draft on Zenodo and assigned a citable DOI: [10.5281/zenodo.19839769](https://doi.org/10.5281/zenodo.19839769).
- Added the DOI badge to `README.md`, the `doi` and `identifiers` fields to `CITATION.cff`, and a "How to cite" section to `README.md`.
