# Changelog

This file records dated public changes to the discussion draft.

## 2026-08-31

- Prepared the v0.4.0 release candidate without tagging, publishing, or
  changing the archived v0.3.2 review anchor.
- Advanced the active machine-readable conformance artifact line to `2026-09`
  while retaining the `VATE-AL2-Verifier-Admission-v0.3` profile identifier.
- Kept historical `2026-07` implementation evidence tied to its exact tag,
  commit, schemas, and corpus digest instead of relabeling it as current.
- Split repository sanity checking into an archive-safe static lane and an
  explicit full-history lane that reloads the historical VATE source commit
  pinned by the Pulse starter and runs 33 starter-validator negative probes;
  frozen Pulse verifier replay remains a separate `--pulse-repo` gate.
- Added a CI check that runs `scripts/check_repo.py` from a `.git`-free Git
  source archive.
- Refreshed approved transitive JavaScript dependencies in the lockfile only.
- Kept the discussion-draft claim boundary: one implementation run against one
  corpus snapshot, not production readiness, certification, endorsement, or
  general compatibility.

## 2026-08-14

- Added the source-pinned RCL-005, RCL-006, and RCL-008 carry-plus-projection
  slice to the canonical AL2 v0.3 corpus.
- Carried the complete Apache-2.0 source fixture with its exact raw SHA-256 and
  recorded every smaller request, receipt, action, params, and preimage object
  as a derived VATE projection.
- Kept source-profile Ed25519 validation separate from VATE projection checks,
  preserved RCL-005 as admission-only, preserved RCL-006's settled result as
  successful while rejecting its action linkage, and retained RCL-008 as the
  full-pipeline acceptance control.
- Added repository regressions for source-byte and provenance drift, mapping
  labels, reason order, accidental pairing, source-digest leakage into VATE
  request hashes, and reject-everything behavior.

## 2026-07-13

- Added a named request-to-admission-to-effect binding invariant that preserves
  the distinct original and effective request hashes across attenuation.
- Clarified that digest-based binding edges are verified by recomputation under
  the applicable profile-defined basis rather than by trusting declared digest
  values.
- Recorded the clarification after external review from `@chopmob-cloud` /
  AlgoVoi without changing schemas, corpus cases, runner behavior, or the
  conformance claim.

## 2026-07-07

- Prepared the v0.3.2 external review portability and reproducibility patch.
- Recorded the first externally supplied three-case adapter-run bundle, with
  pinned gist revision, artifact digests, compare result, and local
  `verify-bundle` result.
- Added an external SUT starter template for the three starter cases:
  `allow-valid-admission`, `attenuate-max-amount`, and
  `deny-digest-mismatch-before-policy`.
- Fixed cross-platform corpus digest portability by pinning LF checkout bytes
  and serializing corpus manifest paths with repository-relative POSIX `/`
  separators.
- Refreshed the TypeScript workspace lockfile so Vitest resolves Vite `8.0.16`
  through its existing dependency range and `npm audit` is clean for reviewers.
- Updated citation metadata and README citation guidance for the `v0.3.2`
  Zenodo version DOI: `10.5281/zenodo.21226254`.
- Recorded an A2A-facing authority acceptance test for metadata fields: copied
  metadata without dereferencing and verifying the referenced artifact is not
  authority to execute a risky write.
- Acknowledged `@chopmob-cloud` / AlgoVoi for external adapter-run review and
  portability feedback, without implying certification, endorsement, production
  approval, or a passing full-corpus claim.

## 2026-05-19

- Added review-driven MCP/OAuth negative fixtures for token passthrough,
  resource-indicator drift, and MCP tool-class mismatch while keeping VATE as a
  verifier-side admission layer rather than an MCP/OAuth semantics replacement.
- Added typed denial reason codes for those authority-confusion cases and kept
  denial diagnostics redacted from full token, tool payload, and prompt-like
  resource-description data.
- Added paired positive-control fixtures for the token authority, resource
  indicator, and MCP tool-class cases so reviewers can distinguish boundary
  mismatches from blanket fail-closed treatment.
- Tightened those positive/negative pairs with explicit corpus pairing metadata,
  stable actor/resource/action/policy/freshness fields, and negative-case checks
  against inferred resource or tool authority.

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
