# Roadmap

## Current Milestone

### `v0.3.1-credibility-and-reviewability`

Focus:

- preserve the archived `v0.3.0` discussion-draft snapshot;
- keep the `VATE-AL2-Verifier-Admission-v0.3` protocol boundary unchanged;
- make public claim boundaries easy to cite;
- make the external SUT comparison and implementation-reporting path visible;
- collect independent implementation reports without implying certification,
  endorsement, production approval, or general compatibility.

### P0 For `v0.3.1`

- [x] add a public claim-boundary page for allowed, discouraged, and forbidden
  phrasing
- [x] update this roadmap so post-`v0.3.0` work starts with a credibility and
  reviewability patch
- [x] make the README's reviewer path surface the external SUT quickstart,
  implementation reporting, A2A review package, known gaps, and claim boundary
- [ ] open a narrow independent implementation / external SUT review issue
- [ ] add a short external implementation call page if the issue text alone is
  not enough
- [ ] collect at least one non-reference SUT result and implementation report
  against the `v0.3` corpus snapshot
- [ ] strengthen controlled-origin publication guidance so copied repository
  fixtures are not mistaken for independent implementation evidence

Out of scope for `v0.3.1`:

- production JOSE/JCS verification implementation
- official A2A extension claims
- AP2 profile expansion
- certification, endorsement, badge, or production-readiness language
- large schema redesigns unrelated to external reviewability

## Completed May 2026 Review Hardening

This section records the completed hardening work that made the `v0.3.0`
discussion-draft snapshot reviewable without broadening the claim boundary.

- [x] publish `v0.2.0` as an archived discussion-draft pre-release with the
  version DOI `10.5281/zenodo.20043166`

### P0 Before The Next External Review Round

- [x] align A2A signed Agent Card evidence with A2A v1.0 JWS header expectations,
  including the `typ` protected header
- [x] resolve `require_new_permit` execution semantics so fixtures and docs agree
  on whether execution may proceed
- [x] document the v0.3 fixture canonicalization limits and the intended production
  canonicalization migration path
- [x] split the conformance language so `run` is clearly a reference artifact /
  fixture integrity check and `compare` is the external SUT comparison path
- [x] make the SUT result contract artifact-backed for required admission receipts,
  post-execution receipts, AL2 context artifacts, and digest descriptors
- [x] extend artifact-backed SUT results to JOSE proof-package references where
  corpus cases require proof provenance
- [x] add report-bundle verification for the corpus, SUT result, conformance report,
  and implementation report digest chain
- [x] formalize post-execution `linkage_checks` as part of the case contract and
  stop collapsing materially different linkage failures into one reason
- [x] add kind-specific `linkage_checks` schema requirements, canonical
  policy-violation token mapping, and strict negative schema tests
- [x] require report corpus/manifest integrity fields, lowercase SHA-256 digest
  descriptors, and top-level report-bundle verification status
- [x] bind AL2 context checks to request, transaction, evidence, and receipt
  artifacts so external SUT comparison can evaluate freshness, replay, and
  runtime-binding behavior
- [x] move evidence type and protocol hint vocabulary toward a single
  machine-readable source and define allowed type/hint combinations
- [x] tighten critical report and linkage schema blocks while keeping future
  extension data under explicit extension or annotation fields
- [x] clarify that `2026-07` artifacts are a July-target artifact line and should
  not be renamed to the current review month

### P1 Before Adjacent Maintainer Outreach

- [x] define reason-code ordering or compare reason-code sets with a primary reason
  code; terminal marker ordering is now documented and enforced in `run` and
  `compare`, and report/corpus primary reason projections are now emitted
- [x] strengthen post-execution linkage checks beyond presence checks, including
  receipt id, receipt digest, transaction, runtime, admitted effective request
  hash, decision, and expiry semantics; receipt id and decision are now
  explicit linkage kinds
- [x] add transport-bound fixtures proving VATE only narrows MCP/OAuth authority and
  never unions with upstream authorization; initial fixtures added:
  `deny-mcp-oauth-overscope` and `deny-mcp-oauth-upstream-denied`
- [x] add evaluation-order and algorithm-confusion fixtures before presenting the
  corpus as broad security conformance; stale runtime proof and digest-before-policy
  fixtures now fail closed before policy admission, and JOSE algorithm confusion
  now covers `alg=none`, HS256 downgrade, and ES384-not-allowed cases
- [x] add attenuation boundary fixtures for malicious paths, schema type edges, and
  amount boundaries; unsafe-path, max-amount type-edge, and negative-amount
  fixtures added
- [x] strengthen post-execution linkage checks beyond presence checks; digest,
  transaction, runtime, denial, expiry, and effective-constraint fixtures added
- [x] add minimum AL2 verification context for status freshness, replay protection,
  and runtime binding; `al2_context_checks` now cover exact status freshness
  boundary, just-over stale boundary, unused replay state, consumed replay state,
  explicit replayed state, runtime binding, and fail-closed unknown replay state
- [x] add an evidence type vocabulary for generic evidence types and
  protocol-specific hints; machine-readable registry, drift checks, and
  type/hint pair checks added
- [x] keep the language-neutral conformance corpus index current as cases change

### P2 Before Independent Implementation Collection

- [x] add report integrity guidance for SUT result and implementation report
  publication; initial schema, runner, and documentation support added
- [x] decide whether to add a pinned dependency for production-grade JOSE
  signature fixtures, or keep the current byte-level detached proof fixture
  boundary; the current corpus remains dependency-free
- [x] add a corpus-bound byte-level A2A signed Agent Card fixture after fixing
  the digest target and validation responsibility
- [x] define a persistent namespace migration plan for schema and extension URIs
- [x] document extension-field handling before tightening `additionalProperties`

## Next

- collect independent implementation reports using
  `schemas/implementation-report.schema.json`; external SUT authors should use
  `docs/conformance/external-sut-quickstart.md` as the command-first path from
  corpus index to `compare`, implementation reports, and `verify-bundle`
- open a narrow GitHub issue for independent implementation / external SUT
  review, framed as a request for technical validation rather than production
  adoption
- use the current A2A review package under `docs/a2a/` for implementer feedback,
  while keeping the request framed as metadata-only compatibility review rather
  than A2A governance adoption
- keep public wording aligned with `docs/public-claim-boundary.md` whenever
  release notes, issues, docs, or outreach text are updated
- add a short external implementation call page if reviewers need a single page
  describing the three requested outputs: SUT result file, generated artifacts
  or controlled artifact bundle, and implementation report
- add additional transport-bound fixtures beyond the initial MCP/OAuth,
  AP2/UCP, and AP2 Human Not Present examples after the AL2 security basis is
  stable
- expand policy snapshot digest fixtures beyond the initial positive and
  mismatch cases
- refine pairwise presentation guidance
- add clearer MCP / OAuth / OpenID binding notes and transport-bound examples
- improve comparison material around close adjacent work where interoperability
  questions remain
- add production-signature fixtures after the detached JWS byte-level basis and
  dependency policy are fixed

## June 2026 Target After `v0.3.0`

The June target is to move from author-run artifacts to independent
implementation evidence, not to broaden the protocol. Items should land only
when they preserve the verifier boundary and pass the runnable checks.

Completion means:

- public claim boundaries are easy to cite from README, FAQ, roadmap, issues,
  and release notes
- at least one non-reference SUT result and implementation report is reviewed
  against the `v0.3` corpus snapshot
- reproducible implementation reports with corpus manifests
- transport-bound fixtures for the most important adjacent paths
- policy snapshot digest checks across receipts, metadata references, and fixtures
- trust-bundle hardening checks for issuer, key id, algorithm, evidence type, status, and validity windows
- detached JOSE fixture checks that separate byte-level proof binding from production signature verification
- language-neutral corpus guidance and a committed corpus index for non-reference implementations
- SUT result comparison contract for non-reference implementation reports
- AP2 Human Not Present evidence cases for pre-authorization, stale authority, amount overrun, replay, and post-execution linkage
- an A2A-adjacent review package that does not require A2A core changes, including an A2A v1.0-shaped extension sketch
- review-derived hardening for digest basis, execution semantics, reason codes,
  post-execution linkage, status freshness, replay, runtime binding, evidence
  vocabulary, and report integrity

## Later

- selective-disclosure or VC-oriented packaging profile
- richer capability claim registry and extension points
- formal `AID` abstraction guidance
- review whether internal mnemonic aliases should gain clearer public-facing alternatives after external feedback
- AL3 and AL4 profiles
- physical AI / `ABS` extensions
- stronger status discovery and federation guidance
