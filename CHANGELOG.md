# Changelog

This file records dated public changes to the discussion draft.

## Unreleased

- The reference runner uses the same execution gate for admission reports and
  post-execution linkage. An invalid attenuation mode or new-permit flag closes
  the gate, as does a reissue mode paired with a false flag.
- Reject HTTP verifier policies that would admit a suspended, revoked, or
  quarantined passport, runtime, or permit. Both AL2 demos verify that each
  registered ES256 public key they use is on P-256. The status guide documents
  the three entries needed for verification. The receipt model identifies
  the operation bytes supplied at issuance and checked by receivers.
- The Minimal status service can reissue a missing status token from its
  store and checks each new token against the registered status key before
  delivery. A signing-key mismatch returns HTTP 500.
- Limit the HTTP demo's generated scenarios to admission inputs. Its receipt
  records the evaluation interval, and all validity checks use the decision
  time. Minimal accepts a completed execution only when its finish time is at
  or before verification. Both demos retain microsecond precision, honor
  reissue requests on every status entry, and reject unsupported passport or
  runtime narrowing.
- Distinguish a missing or unusable registered public key from an invalid
  submitted signature. The HTTP demo returns 500 for a verifier key failure,
  including a signing key that does not match the registered verifier key.
  Minimal's negative-case command retires its previous summary on each run
  and exits unsuccessfully if a case misses an expected failure.
- The [2026-11-18 handoff validation](reference/runtime-handoff-sample/VALIDATION.md)
  used a package with `SOURCE-MANIFEST.json` SHA-256
  `147b9e4054eadafa8961e42158bb98acf075a3d57eb67284d1a0918510187211`.
- Stage complete HTTP and Minimal AL2 demos before replacing an existing
  generation. Refuse mixed or incomplete output directories and retire
  previous reports when installing new artifacts. HTTP signing and storage
  failures return 500.
- Require a non-empty verifier ID in core admission receipts. Both legacy
  demos check signed narrowing instructions for an explicit constraints
  object and require canonical compact JWS segments. Minimal checks the
  receipt's post-execution phase and the passport's validity throughout the
  recorded execution.
- Validate the complete local HTTP verifier policy before serving a request
  or replacing a generated demo. An invalid policy cannot authorize an
  operation. A missing generated policy stops startup, and an invalid direct
  Python policy cannot produce a signed receipt.
- Check subject and runtime-key bindings against usable identifiers and the
  registered public key in the HTTP and Minimal AL2 demos. The HTTP verifier
  also checks the passport assurance vocabulary and the permit's numeric
  limits, preserves approval-field types, and omits an absent principal from
  signed receipts.
- Validate mission-permit action lists and transaction identifiers in the
  HTTP and Minimal AL2 demos. Require the permit's transaction to match the
  HTTP request or Minimal receipt, and enforce the HTTP policy's configured
  permit age limit. Declare that limit as required in the policy schema and
  validate all three freshness limits as positive integer seconds. Keep
  rejection reports and denial receipts current, and update the shared
  Minimal verifier in the current runtime-handoff distribution.
- Require artifact signing keys to have the expected local trust role in the
  HTTP and Minimal AL2 demos, including status in all supported delivery modes.
  Reject empty tool intersections and approval weakening in HTTP attenuation;
  retain the permit's original approval fields and validate supported effect
  values. Apply the shared signer checks to the current runtime-handoff copy.
- Replace earlier Minimal AL2 verification reports on status retrieval,
  signature, and input failures; read only the selected status delivery and
  apply the correction to the current runtime-handoff distribution. Keep the
  HTTP demo's rejection reports current when shared JWS decoding fails, and
  omit receipts that cannot be built from authenticated, usable inputs.
  Preserve the rejected input's diagnostic digest for JSON `null` in the A2A adapter.
- Require the legacy Minimal AL2 demo's complete execution interval to fall
  within both the runtime and permit validity windows, including their endpoints.
  Reject receipts that finish before they start or after either expiry, and
  apply the same correction to the current runtime-handoff distribution.
- Reject numeric JSON inputs that would lose decimal precision, preserve JSON
  types in explicit linkage and report-metadata comparisons, and accept
  permitted digest annotations consistently in receipt reference checks.
  Align currency schema tokens and durable-store timeout errors with their
  input contracts. Apply the runner, schema, and worker-cleanup corrections to
  the standalone runtime-handoff sample with updated provenance and source pins.
- Change the default Python `VateVerifier.admit` API to require request bytes
  and original input bytes and return a bound admission. Callers must follow
  the [API migration guide](reference/request-binding/MIGRATION.md).
- Add request-binding assessments to conformance reports and optional
  digest-addressed request-binding artifacts to SUT results. Existing reports
  without those optional fields remain valid; the AL2 v0.3 profile is retained.
- Cross-check AL2 verification-context records against the selected request,
  receipt, runtime, timestamps and evidence results in `run`, `compare` and
  `verify-bundle`.
- Add TypeScript JCS digest and ES256 verification helpers, plus the shared
  `assessRequestBinding` contract. Align A2A metadata timestamps with the Python
  supported subset, including lowercase `t`/`z` and up to six fractional digits.
- Reject trailing line breaks in schema hash and amount strings, and validate
  A2A reference URI syntax and request-phase metadata before artifact access.
  The case-schema correction changes the current corpus digests; historical
  releases and submitted results retain their original pins.
- Preserve JSON booleans during generated-receipt comparison and sum reported
  decimal amounts without ambient rounding. Clean up native evaluator child
  processes even after their supervisor exits, reject oversized JCS timeout
  configuration, and validate the first retained clock after an empty-store
  migration. Correct the Inbox CLI report-recovery instructions.
- Add a standalone runtime-handoff and receipt sample and an offline ACS log
  reader that retains command timestamps and Guardian record order.
- Add receiving examples for pinned WAR 1.4.3 and 1.4.8, Restoration RB, Border
  relay, UIBC (including v0.3), and x402 MCP results, with their selected evidence
  and verification boundaries documented in each example.
- Add AuthZEN recovery/retry receipt vectors and publish Vaara recipient,
  persisted OAuth-grant and first-hop revocation reproduction guides.
- Keep AuthZEN replay and fresh capture bound to their bundled historical
  runtime when the current runtime-handoff sample changes. Preserve the
  original vector bytes and source pins, and check the standalone source archive
  in the dedicated CI workflow.
- Add optional Python runtime and caller ES256 profiles that bind authenticated
  evidence and delegation grants to purchase admission and dispatch.
- Add dispatch-time revalidation and local SQLite admission/attempt state,
  plus authenticated authority snapshots and a selected Hydra/OpenFGA issuer
  example for permission updates and revocation.
- Keep ordinary module imports available without readable source files, report
  lease consumer I/O errors unchanged, and reject durable admissions with stale
  or future evaluation times.
- Add persistent macOS Keychain authority signing and supervised HTTPS snapshot
  retrieval, including coordinated refresh/shutdown and local recovery examples.
- Add planned local key/program/store migration from pinned commit `6758476`,
  preserving original receipts, consumed attempts and revision/time floors.
  History hashing streams the existing digest byte sequence; key confirmation
  revisions remain below the new live-authority minimum.
  Migrated stores stay pinned to the exact target program; later program changes
  require a separately supported transition.
- Accept schema-permitted annotations on SUT digest descriptors and
  receipt-internal admission digest descriptors in the ordinary runner. Reject
  post-execution linkage for an attenuate receipt missing its effective hash.
- Define the Python [receipt-pair API input contract](reference/vate-verifier-core/LINKAGE.md).
  Reject malformed linkage inputs and contradictory attenuation, select constraints
  by admission decision without fallback, and sum reported amounts independently
  of the caller's decimal settings. Require canonical ASCII decimal strings
  for amounts and explicit string-or-null tool aliases with defined precedence.
- Align the core and runner's constraint selection and reject legacy constraint
  aliases during linkage checks. Restrict timestamp digits to ASCII and document
  the amount failure-code changes and the limits of linkage success codes.
- With `tool_allowlist` configured, report malformed tool aliases as
  `not_assessed`, even when another alias supplies a valid tool. Include the
  invalid field in input diagnostics before linkage comparison. A valid
  selected tool outside the allowlist remains `mismatch`.

## v0.6.0

- Added required-records review and persisted Recipient Inbox originals and
  assessment history, plus a standalone post-admission runtime-key revocation
  sample. See the [release notes](docs/release-notes/v0.6.0.md).
- Added an opt-in MUSUBI set2 audit/dataset receiving example. It checks the
  published A/C bytes against selected execution receipts, retains both
  assessments, and preserves missing B evidence and unresolved acceptance.
- Added the supplementary verification record and portable audit/storage
  regressions to the existing Linux / Python 3.11–3.14 sample CI job.

## 2026-10-23 — main branch

- Published a fixed MUSUBI set2 receiving sample with request-binding checks,
  pinned macOS environment preparation, Inbox storage, retained reassessment
  history and recovery of outputs after an assessment has been saved.
- Published the October 22 Horizon Shield #51 verification record: saved
  signature and hash checks, exact native settlement replay, header-view
  reassessment and VATE receipt/export results.
- Added Linux / Python 3.11–3.14 CI for sample integrity and portable binding,
  CLI/SQLite and output-recovery tests. Native replay remains macOS-only;
  the existing semantic profile, core schemas and corpus are unchanged.

## 2026-10-15 JST — v0.5.0 (2026-10-14 UTC)

- Added ten local execution-evidence scenarios connecting admission, exact
  provider input, observed files and linked receipts, including response loss
  and read-only reconciliation.
- Added reusable receipt-linkage and S3-observation examples, a versioned local
  recipient Python API and JSON CLI, and three NENRIN–VATE crosswalk cases
  preserving complete native reports.
- Added an experimental detached-signature and receiver-selected issuer-authority
  example, keeping signature, policy authority and receipt linkage separate.
- Fixed linkage acceptance when admission requires a new permit, TypeScript
  fixture JSON byte agreement, and trust-policy placement checks in the
  recommended S3 CLI entry point.
- Preserved microsecond precision in the reference core, tightened its supported
  timestamp forms, and corrected receipt windows for expired-request denials.
- Added fixed Vaara and A2A reproduction guides and external reuse/review
  records for HandoffProbe, Mission, Receipt Protocol and NENRIN, retaining
  their source pins and observed execution scope.
- Clarified existing corpus case prose without changing case IDs, expected
  outcomes, reason codes or required artifacts. The 76-case / 217-artifact
  snapshot has a new digest; the AL2 v0.3 profile and 2026-09 artifact line remain.
- Updated the locked `fast-uri` and `source-map-js` transitive dependencies for
  upstream security fixes; expanded Linux/macOS and source-archive CI coverage.
- Added release notes, a technical gate and tag-time citation metadata.
  The exact v0.5.0 Zenodo DOI is pending at tag time; historical version DOIs
  continue to identify their original files.

## 2026-09-09 — v0.4.1

- Corrected `deny-ap2-hnp-replay` to bind normalized payment-authority and
  VATE-local consumed-state artifacts as authoritative SUT inputs.
- Retained the `VATE-AL2-Verifier-Admission-v0.3` profile and `2026-09`
  artifact line with a 76-case / 217-artifact corpus; see the
  [release notes](docs/release-notes/v0.4.1.md) for the fixed digest.
- Included the Vaara and Bolyra / x402 partial native-execution records at
  their original `v0.4.0` pins, preserving their unresolved comparisons.
- Added external SUT coverage and EVC / ACS / ACLE-MCP responsibility guides.
- Updated Vitest to `4.1.11` and refreshed its lockfile.
- Recorded the v0.4.1 technical release gate and tag-time citation metadata.
- Archived the exact `v0.4.1` source snapshot on Zenodo as record `22680789`
  with version DOI
  [10.5281/zenodo.22680789](https://doi.org/10.5281/zenodo.22680789).
- Verified all 551 archived file paths and contents against the tag; the
  downloaded ZIP checksum matched the published record.

## 2026-09-01

- Published `v0.4.0` as the current GitHub discussion-draft pre-release review
  anchor while retaining the `VATE-AL2-Verifier-Admission-v0.3` semantic
  profile.
- Published the active `2026-09` machine-readable artifact line with its
  76-case / 216-artifact corpus and fixed corpus digest.
- Preserved historical `2026-07` evidence and the archived `v0.3.2` version DOI
  without relabeling either as current `2026-09` evidence.
- Recorded the completed archive-safe and full-history technical gates and the
  approved transitive dependency maintenance.
- Archived the exact `v0.4.0` source snapshot on Zenodo as record `22218860`
  with version DOI
  [10.5281/zenodo.22218860](https://doi.org/10.5281/zenodo.22218860).
- Verified the Zenodo source ZIP against the `v0.4.0` tag: all 503 tracked
  entries and the downloaded archive MD5 matched the published record.
- Maintained the discussion-draft boundary: not production-ready, certified,
  endorsed, or production-approved.

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
