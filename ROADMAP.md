# Roadmap

This public roadmap describes reviewable technical direction for the VATE
discussion draft. It intentionally avoids certification, endorsement,
production-readiness, or official adjacent-protocol adoption claims.

For public wording rules, see
[docs/public-claim-boundary.md](docs/public-claim-boundary.md).

## Current Direction

### Post-`v0.4.1`: Execution Evidence And Recipient Review

The `v0.4.1` maintenance discussion-draft pre-release is the current GitHub
review snapshot. It retains the `2026-09` machine-readable artifact line
introduced in `v0.4.0` and the semantic profile
`VATE-AL2-Verifier-Admission-v0.3`. The maintenance release corrects the AP2
replay case's inputs and collects partial implementation records at their
original evaluation pins.

The `v0.4.0` release introduced the external-SUT input, generated-receipt,
status-evidence, and report-integrity contract accumulated after v0.3.2. Its
exact source remains archived at DOI `10.5281/zenodo.22218860`; the `v0.4.1`
version DOI is `10.5281/zenodo.22680789`. Historical records keep their own exact
source and DOI.

The current work connects a relying party's admission decision to the request
actually delivered, the resulting evidence, and a recipient's assessment of
that evidence. The next question is whether a recipient can make that assessment
from the supplied artifacts and documentation, and maintain it when the source
format or evidence semantics change.

Independent implementation evidence remains a parallel priority. Each corpus
comparison retains its own snapshot; historical `2026-07` results are not
relabeled as current `2026-09` evidence.

### Available Execution And Review Evidence

The following work is available on `main` after the `v0.4.1` archive:

- [Execution Evidence Demo](reference/execution-evidence-demo/README.md): ten
  local scenarios link admission, exact provider input, observed files and
  generated receipts, including response loss and read-only reconciliation.
- [Vaara → VATE reproduction package](docs/interop/vaara-execution-reproduction.md):
  a fixed package for checking disclosed evidence and creating a new local run
  through a pinned stdio proxy, credential gateway and file handler.
- [HandoffProbe reconciliation review](docs/interop/handoffprobe-reconciliation-review.md):
  an external package check and property comparison that led to a
  HandoffProbe-native synthetic original-attempt reconciliation fixture.

The VATE demo and Vaara path use one operator, local processes and unsigned
VATE records. HandoffProbe's result is an external technical review, not an
additional VATE corpus comparison; its tests are reported by its author. These
records keep their distinct observation boundaries and do not establish
independent issuer authenticity, production readiness or A2A transport support.

The main-branch conformance corpus remains 76 cases / 217 manifest artifacts.
The demonstration scenarios are separate from that corpus. See
[external SUT coverage](docs/conformance/external-sut-coverage.md) for the
partial native-implementation records and their historical evaluation pins.

### Release And Review References

The current public review surface is:

- `v0.4.1` GitHub maintenance discussion-draft pre-release:
  <https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/releases/tag/v0.4.1>
- `v0.4.1` pre-release notes and technical gate:
  [docs/release-notes/v0.4.1.md](docs/release-notes/v0.4.1.md) and
  [docs/release-gate-v0.4.1.md](docs/release-gate-v0.4.1.md)
- archived `v0.4.0` version DOI:
  `10.5281/zenodo.22218860`
- historical `v0.4.0` pre-release notes and completed technical gate:
  [docs/release-notes/v0.4.0.md](docs/release-notes/v0.4.0.md) and
  [docs/release-gate-v0.4.0.md](docs/release-gate-v0.4.0.md)
- archived `v0.3.2` release notes and version DOI:
  [docs/release-notes/v0.3.2.md](docs/release-notes/v0.3.2.md) and
  `10.5281/zenodo.21226254`
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
- external SUT run records:
  [docs/conformance/external-sut-run-records.md](docs/conformance/external-sut-run-records.md)
- receipt audit walkthrough:
  [docs/receipt-audit-walkthrough-v0.3.1.md](docs/receipt-audit-walkthrough-v0.3.1.md)
- A2A-shaped metadata review package:
  [docs/a2a/README.md](docs/a2a/README.md)
- independent implementation / external SUT review intake:
  [issue #2](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2)

### Next Technical Work

1. Take the existing non-payment operation through initial receipt of its
   evidence, a bounded source change, and a second recipient assessment. Fix the
   disclosed artifacts, trusted parties, questions and expected decisions
   before the trial.
2. Exercise a format-only change and a change in evidence meaning separately.
   Preserve the original packages and identify synthetic changes as such.
   Record the recipient's decisions, unresolved evidence, additional questions
   and required adapter or documentation changes.
3. Compare VATE records with the native originals plus an explicit mapping and
   the transformations needed to use them. Include preparation and maintenance
   on both sides, as well as incorrect conclusions and justified unresolved
   outcomes. A completed trial should identify the useful distinctions, costs
   and remaining technical gaps.
4. Map the resulting evidence requirements to the
   [existing A2A extension draft](docs/a2a/vate-a2a-extension-profile-v0.3.md).
   Distinguish what local execution demonstrates from the transport and
   receiver behavior still to be exercised in an A2A exchange.
5. Extend independently maintained implementation evidence through the
   [external SUT review path](docs/conformance/external-sut-quickstart.md).
   Keep partial comparisons, generated artifacts and external technical reviews
   identifiable by their source, execution conditions and corpus snapshot
   where applicable.

For the execution-and-recipient path, generation and continued use by another
operator, human review effort, and behavior across restarts or concurrent
execution remain open.
The [one-hour corpus review](docs/conformance/external-sut-ask-1-hour.md) and
the reproduction package provide separate entry points for contributors.

### Current Scope

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

The current work retains the `VATE-AL2-Verifier-Admission-v0.3` semantic profile
and the [public claim boundary](docs/public-claim-boundary.md). Observations from
the trials will inform any later profile or contract changes.

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

## Independent Implementation Evidence

The [coverage guide](docs/conformance/external-sut-coverage.md) distinguishes
native execution, reached predicates and unresolved VATE comparisons for Pulse,
Vaara and Bolyra / x402. These partial records remain tied to their original
inputs and corpus snapshots.

The recorded AlgoVoi evidence in
[docs/conformance/external-sut-run-records.md](docs/conformance/external-sut-run-records.md)
now includes an initial three-case starter bundle and a deeper eight-case
bundle. The two slices come from the same implementation line and overlap on
`attenuate-max-amount`. The deeper result covers eight cases from the then
72-case pinned snapshot, does not validate the current full corpus, and is not
a second independent SUT result.

Useful external evidence would include:

- additional SUT result files from implementations that are not the repository
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
