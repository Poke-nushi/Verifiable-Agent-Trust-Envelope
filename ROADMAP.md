# Roadmap

This public roadmap describes reviewable technical direction for the VATE
discussion draft. It intentionally avoids certification, endorsement,
production-readiness, or official adjacent-protocol adoption claims.

For public wording rules, see
[docs/public-claim-boundary.md](docs/public-claim-boundary.md).

## Current Direction

### v0.6.0: Receiving, Reassessment and Runtime-Key Revocation

The `v0.6.0` source adds receiver-selected required-record checks, persistent
intake and exported-history reassessment, fixed MUSUBI evidence connections,
and a standalone post-admission runtime-key revocation sample. The release
retains the AL2 profile v0.3, artifact line `2026-09` and the v0.5.0 corpus.
See the [review paths](docs/release-notes/v0.6.0.md) and
[publication/archive gate](docs/release-gate-v0.6.0.md).

The next technical questions concern independently selected trust and required
records, connecting execution evidence to a receiving application, and retaining
earlier judgments when conditions change. Existing file-operation and payment
examples provide different contexts for those questions. A further example
should address a concrete integration or maintenance problem.

### v0.5.0: Execution Evidence And Recipient Review

The `v0.5.0` discussion-draft pre-release collects execution-evidence examples,
recipient assessment interfaces, signature and issuer-authority checks, and
external reuse/reproduction records. It retains the `2026-09` machine-readable
artifact line and `VATE-AL2-Verifier-Admission-v0.3` semantic profile.
The added signature contract is an experimental implementation aid.

The v0.5.0 source snapshot is archived at
[10.5281/zenodo.23378498](https://doi.org/10.5281/zenodo.23378498). Historical `v0.4.1`
and `v0.4.0` remain archived at `10.5281/zenodo.22680789` and
`10.5281/zenodo.22218860`, respectively. Historical records keep their original
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

The v0.5.0 source snapshot includes the following work added after v0.4.1:

- [Execution Evidence Demo](reference/execution-evidence-demo/README.md): ten
  local scenarios link admission, exact provider input, observed files and
  generated receipts, including response loss and read-only reconciliation.
- [Receipt Linkage Example](reference/receipt-linkage-example/README.md): reuse
  existing core, runner and schema checks on two stored receipts, with explicit
  matching, mismatch and unassessed results. This checks receipt relationships;
  independent execution evidence and external reuse remain separate questions.
- [S3 Observation Example](reference/s3-observation-example/README.md): connect
  existing receipt checks to a captured upload and version-specific read-back
  from local SeaweedFS. Included originals distinguish a matching result,
  unavailable observations and an observed historical version under explicit
  local collector/store trust assumptions.
- [NENRIN–VATE S3 Crosswalk Example](reference/nenrin-s3-crosswalk-example/README.md):
  three fixed cases compare contributor-supplied NENRIN grant and receipt
  records with the VATE S3 capture. Complete native results remain alongside
  the relationship checks; saved-record comparison and fresh checker runs
  are separate operations. The signed NENRIN records are a retrospective
  synthetic reconstruction of the capture, adding no independent observation
  of the original upload.
- [Vaara → VATE reproduction package](docs/interop/vaara-execution-reproduction.md):
  a fixed package for checking disclosed evidence and creating a new local run
  through a pinned stdio proxy, credential gateway and file handler.
- [HandoffProbe reconciliation review](docs/interop/handoffprobe-reconciliation-review.md):
  an external package check and property comparison that led to a
  HandoffProbe-native synthetic original-attempt reconciliation fixture.
- [A2A evidence-review reproduction](docs/a2a/evidence-reproduction.md): three
  fixed historical disclosures exchanged through loopback `SendMessage` and
  `GetTask`, with recipient assessments and saved-run verification.
- [HandoffProbe A2A reproduction report](docs/interop/handoffprobe-a2a-reproduction.md):
  an external contributor reports running the fixed package and reproducing
  the distinction between review-Task completion and original operation outcome.
- [Mission A2A reproduction report](docs/interop/mission-a2a-reproduction.md):
  another contributor reports running starter-06, distinguishing live recovery
  observations from saved-run verification.
- [Receipt Protocol store reuse](docs/interop/receipt-protocol-store-reuse.md):
  an external developer connects a storage POC to the existing VATE checker.
  The maintainer reproduced the fixed R17 handoff and a mismatch control, then
  [rechecked the Buffer-copy fix](docs/interop/receipt-protocol-store-reuse.md#buffer-copy-fix-recheck).
  The corrected store preserved the receipt bytes and checker results; the
  original pin's mutable-buffer finding remains in the record.

The VATE demo and Vaara path use one operator, local processes and unsigned
VATE records. HandoffProbe's reconciliation experiment and the HandoffProbe and
Mission A2A package reproductions are contributor-reported results, separate
from VATE corpus comparisons. Receipt Protocol reuses the VATE checker rather
than implementing its own VATE verifier. The A2A package uses one process and an explicit local evidence-review contract;
it checks 131 fetched files and keeps review-Task completion separate from the
original operation's outcome.
Independent issuer authenticity, cross-implementation A2A exchanges and
production readiness remain unestablished.

The main-branch conformance corpus remains 76 cases / 217 manifest artifacts.
The demonstration scenarios are separate from that corpus. See
[external SUT coverage](docs/conformance/external-sut-coverage.md) for the
partial native-implementation records and their historical evaluation pins.

### Release And Review References

The current public review surface is:

- `v0.6.0` source notes and publication/archive gate:
  [docs/release-notes/v0.6.0.md](docs/release-notes/v0.6.0.md) and
  [docs/release-gate-v0.6.0.md](docs/release-gate-v0.6.0.md)
- `v0.5.0` GitHub discussion-draft pre-release:
  <https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/releases/tag/v0.5.0>
- `v0.5.0` exact version DOI:
  <https://doi.org/10.5281/zenodo.23378498>
- `v0.5.0` notes and technical gate:
  [docs/release-notes/v0.5.0.md](docs/release-notes/v0.5.0.md) and
  [docs/release-gate-v0.5.0.md](docs/release-gate-v0.5.0.md)
- archived `v0.4.1` GitHub maintenance discussion-draft pre-release:
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

The [Recipient Assessment API](reference/recipient-assessment/README.md) provides
a versioned entry point for the existing receipt and S3 evaluators.
[Recipient Inbox](reference/recipient-inbox/README.md) connects that assessment
to local raw-byte storage, fixed review inputs, late delivery and retained
history. Its example covers restarts and exported reassessment; diagnostic
controls also exercise an evaluator update after an old failure. The
[package intake example](reference/recipient-inbox/PACKAGE-INTAKE.md) connects
finite local package reads and registration to collection status, with a
separately selected requirement inventory. Next, use
these paths with another receiving application and independently selected
collection requirements. Continued maintenance by another implementer remains
to be observed.

Two paths address additional recipient requirements:

- **Signatures and issuer authority:** the experimental
  [recipient signature example](reference/recipient-signature-authority/README.md)
  connects OpenSSL P-256 / SHA-256 verification and receiver-selected
  record-issuing grants to the existing receipt assessment. Signed bytes,
  authority under that policy and receipt linkage remain separate results.
  Next, exercise independently selected issuer/key/scope mappings with another
  receiver. The public test-key controls do not establish real issuer identity
  or authority at the original operation.
- **Missing required records:** [Required Record Review](reference/required-records/README.md)
  checks an explicit receiver-selected set of operations or known attempts.
  It distinguishes missing, pending and unresolved records, preserves native
  results and records cutoff, arrival and collection assumptions. Next,
  exercise independently supplied requirements and collection inventories
  with another receiving application, including an update that retains its
  previous report. Activity outside the selected set remains unmeasured.

The signature example and required-record review wrap the current API without
changing its unsupported requirements or the v0.3 semantic profile.
See [known gaps](docs/known-gaps.md) for the remaining proof and evidence
boundaries.

The [post-admission runtime-key revocation sample](reference/post-admission-revocation-sample/README.md)
preserves an earlier `allow` while checking signed status at one local provider's
acceptance boundary. It exercises acceptance ordering, partial effects and
saved-state recovery with disposable keys, and supplies an exported-evidence
reader. Next, evaluate this contract with an independently operated provider or
recipient and separately selected trust inputs. Remote cancellation, general
PKI revocation and independent proof of time or complete history remain open.

The NENRIN S3 example supplies one fixed cross-format comparison with preserved
native results. Reuse its inputs, checks and documented mapping when evaluating
another recipient or a source update; distinguish an actual integration from
replaying the same three cases.

1. For a source with a different native receipt format, first establish what
   its records mean, which originals are needed and what the recipient must
   decide. Once these are available, select one integration use case and fix
   the evidence, trust assumptions and expected decisions before the trial.
2. In that use case, identify reusable checks and the additional retrieval,
   mapping and documentation needed. When evaluating a source change, separate
   format changes from changes in evidence meaning. Preserve the originals,
   identify synthetic changes and record decisions that remain unresolved.
3. Compare VATE records with native originals plus an explicit mapping when
   this addresses an unresolved integration question. Account for preparation,
   maintenance, incorrect conclusions and justified unresolved outcomes. Reuse
   completed comparisons unless the inputs, assumptions or questions change.
4. Use the [A2A evidence-review reproduction](docs/a2a/evidence-reproduction.md)
   to test another recipient or evidence source against the
   [existing A2A extension draft](docs/a2a/vate-a2a-extension-profile-v0.3.md).
   Record the required mapping, retrieval policy and interpretation changes.
   Keep the fixed loopback result distinct from independent implementation or
   operator evidence.
5. Extend independently maintained implementation evidence through the
   [external SUT review path](docs/conformance/external-sut-quickstart.md).
   Keep partial comparisons, generated artifacts and external technical reviews
   identifiable by their source, execution conditions and corpus snapshot
   where applicable.

The recorded storage-to-checker reuse provides a concrete starting point for
the recipient path. Further work should identify which existing rules are
reused, what retrieval or native-format mapping is added, who owns trust and
effect assessment, and what changes when a source or checker version changes.
The [connection conditions](docs/interop/receipt-protocol-store-reuse.md#connection-conditions)
describe the current storage path; different native receipts require their own
source evidence and mapping decisions.

The [MUSUBI set2 receiving sample](reference/musubi-set2-receiving-sample/README.md)
now provides one fixed integration with a different native format. It selects
receipt requirements, checks request bindings, preserves native results and
recovers saved outputs without repeating the evaluation. The
[Horizon Shield #51 replay record](docs/interop/horizon51-set2-replay/README.md)
preserves the experiment's sources, local verification and unresolved evidence.
Next, use the documented contract to receive an independently supplied update
or to support another receiver; record which selection and mapping work remains.

For the execution-and-recipient path, generation and continued use by another
operator and human review effort remain open. The Inbox and MUSUBI sample
exercise local restart and saved-output recovery cases; process termination,
power loss, database repair and broader concurrent operation remain outside
that sample's tested recovery contract.
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
