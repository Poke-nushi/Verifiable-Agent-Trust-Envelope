# Roadmap

This public roadmap describes reviewable technical direction for the VATE
discussion draft. It intentionally avoids certification, endorsement,
production-readiness, or official adjacent-protocol adoption claims.

For public wording rules, see
[docs/public-claim-boundary.md](docs/public-claim-boundary.md).

## Current Direction

### `post-v0.3.1-independent-implementation-evidence`

The archived `v0.3.1` patch completed the immediate credibility and
reviewability cleanup for the current AL2 verifier-admission discussion draft.

The next work should not broaden VATE beyond the
`VATE-AL2-Verifier-Admission-v0.3` boundary. The priority is to move from
author-run repository checks toward independent implementation evidence that a
reviewer can inspect, reproduce, and tie back to one corpus snapshot.

The current public review surface is:

- archived `v0.3.1` discussion-draft patch:
  <https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/releases/tag/v0.3.1>
- archived `v0.3.1` version DOI:
  `10.5281/zenodo.20173995`
- archived `v0.3.0` discussion-draft release:
  <https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/releases/tag/v0.3.0>
- public claim boundary:
  [docs/public-claim-boundary.md](docs/public-claim-boundary.md)
- reviewer entry points in
  [README.md](README.md) and [FAQ.md](FAQ.md)
- external SUT quickstart:
  [docs/conformance/external-sut-quickstart.md](docs/conformance/external-sut-quickstart.md)
- external implementation call:
  [docs/conformance/external-implementation-call.md](docs/conformance/external-implementation-call.md)
- implementation reporting:
  [docs/conformance/implementation-reporting.md](docs/conformance/implementation-reporting.md)
- report publication and bundle integrity guidance:
  [docs/conformance/report-integrity.md](docs/conformance/report-integrity.md)
- receipt audit walkthrough:
  [docs/receipt-audit-walkthrough-v0.3.1.md](docs/receipt-audit-walkthrough-v0.3.1.md)
- A2A-shaped metadata review package:
  [docs/a2a/README.md](docs/a2a/README.md)
- independent implementation / external SUT review intake:
  [issue #2](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2)

Near-term public work should happen in this order:

1. Collect at least one SUT result from an implementation that is not the
   repository reference runner, against the `v0.3` corpus snapshot.
2. Ask that implementer to publish generated artifacts or a controlled artifact
   bundle, not only a hand-written result summary.
3. Generate or collect a conformance report, implementation report, and local
   `verify-bundle` report for the same corpus snapshot.
4. Use the result to identify unclear corpus cases, reason-code friction,
   missing artifact bindings, or publication metadata gaps.
5. Make a small `v0.3.2` patch only if that evidence exposes concrete
   schema/corpus/docs/runner drift. Do not cut a release for typo-only edits.
6. Reserve `v0.4.0` for a real profile-surface expansion, such as a new
   adjacent-protocol profile, a proof-profile decision, or a materially changed
   conformance contract.

Immediate out of scope:

- production JOSE/JCS verification implementation;
- official A2A extension claims;
- AP2 profile expansion;
- AgentKit, AgentBook, World ID, or other adjacent-protocol-specific evidence
  vocabulary expansion;
- a machine-readable attenuation primitive registry;
- certification, endorsement, badge, or production-readiness language;
- broad schema redesigns unrelated to external reviewability;
- dependency additions, package publication, or production proof verification
  without an explicit separate review decision.

The test for the next public patch is simple: it should make independent
implementation review easier without changing the public claim boundary.

## Completed `v0.3.1` Credibility And Reviewability Patch

The archived `v0.3.1` patch made the current AL2 verifier-admission package
easier to review without changing the profile boundary. It should be read as a
discussion-draft patch and review aid, not as certification, endorsement, or
production approval.

The `v0.3.1` package includes:

- an archived `v0.3.1` credibility and reviewability patch with version DOI
  `10.5281/zenodo.20173995`;
- a 66-case AL2 v0.3 draft conformance corpus;
- canonical emitted AL2 `attenuation.effective_constraints` names for
  admission receipts;
- fail-closed attenuation fixtures for legacy emitted aliases, string-valued
  approval constraints, malformed money objects, and unsupported attenuation
  modes;
- stricter admission receipt schema coverage for non-empty structured
  `attenuation.changes` and supported `attenuation.mode` values;
- a constraints-only `app-effect-0.2` attenuation effect shape for status/input
  effects;
- a receipt audit walkthrough for following digest-bound admission,
  post-execution, policy snapshot, conformance report, implementation report,
  and report-bundle references;
- release and citation metadata updated for the `v0.3.1` archive.

## Completed `v0.3.0` Hardening

The archived `v0.3.0` snapshot made the AL2 verifier-admission review package
more concrete without changing the public claim boundary. It should still be
read as a discussion draft and review aid, not as a certification or production
approval.

The `v0.3.0` package includes:

- an archived `v0.2.0` review snapshot with version DOI
  `10.5281/zenodo.20043166`;
- an archived `v0.3.0` discussion-draft snapshot with version DOI
  `10.5281/zenodo.20107413`;
- a split between `run` as repository fixture / reference-runner integrity
  checking and `compare` as the external SUT comparison path;
- artifact-backed SUT result requirements for admission receipts,
  post-execution receipts, AL2 context artifacts, and JOSE proof-package
  fixture references;
- implementation report and report-bundle verification formats for one
  implementation run against one corpus snapshot;
- corpus manifest integrity fields and lowercase SHA-256 digest descriptors;
- a language-neutral corpus index for non-reference implementations;
- explicit `should_execute` comparison semantics for attenuation and
  fail-closed cases;
- formal post-execution `linkage_checks` for receipt id, receipt digest,
  transaction, runtime, decision, expiry, and effective request hash checks;
- minimum AL2 context checks for status freshness, replay state, runtime
  freshness, runtime binding, request artifacts, evidence artifacts, and
  receipt artifacts;
- machine-readable evidence type and protocol-hint vocabulary with allowed
  type / hint combinations;
- MCP/OAuth denial fixtures showing that VATE narrows upstream authorization
  and never unions with it;
- JOSE byte-level fixtures for algorithm confusion and detached proof binding,
  while explicitly excluding production cryptographic signature verification;
- attenuation boundary fixtures for unsafe paths, max-amount type edges, and
  negative amount handling;
- AP2 Human Not Present evidence cases for pre-authorization, stale authority,
  amount overrun, replay, and post-execution linkage;
- A2A-shaped metadata examples and a review package that keeps VATE references
  optional, digest-bound, and by reference;
- documentation for fixture canonicalization limits, namespace migration,
  extension-field handling, and the `2026-07` conformance artifact line.

## External Review Target

The May-June 2026 target is to move from author-run artifacts toward independent
implementation evidence. The priority is not a broader protocol surface.

Useful external evidence would include:

- one or more SUT result files from implementations that are not the repository
  reference runner;
- generated artifacts or controlled artifact bundles from the implementer;
- implementation reports tied to the same corpus snapshot;
- `compare` reports showing expected, failed, skipped, or unsupported cases;
- local `verify-bundle` reports for the corpus, SUT result, conformance report,
  and implementation report digest chain;
- reviewer feedback on decision semantics, reason codes, artifact binding,
  post-execution linkage, and adjacent protocol boundaries.

Passing reports must continue to be described narrowly: one submitted SUT result
matched one corpus snapshot under the repository comparison rules. They do not
imply production readiness, endorsement, certification, official compatibility,
or future compatibility.

## Later

- selective-disclosure or VC-oriented packaging profile
- richer capability claim registry and extension points
- formal `AID` abstraction guidance
- clearer public-facing alternatives for mnemonic aliases after external
  feedback
- AL3 and AL4 profiles
- physical AI / `ABS` extensions
- stronger status discovery and federation guidance
- production proof verification only after a separate dependency and security
  review decision
