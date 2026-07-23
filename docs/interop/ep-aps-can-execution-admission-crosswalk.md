# EP / APS / CAN To VATE Execution-Admission Crosswalk

## Status

This is a non-normative review aid for the
`VATE-AL2-Verifier-Admission-v0.3` discussion draft.

It compares the following work-in-progress revisions as of 2026-07-23:

- EP-AEC `draft-schrock-ep-authorization-evidence-chain-04`
- Action Evidence Boundary (AEB)
  `draft-schrock-action-evidence-boundary-00`
- Canonical Action Identifier (CAID)
  `draft-schrock-canonical-action-identifier-01`
- Authorization Receipts
  `draft-schrock-ep-authorization-receipts-08`
- APS `draft-pidlisnyi-aps-03`
- Agent Accountability Composition (CAN / WHO / WHAT / AUDIT question slots)
  `draft-mih-sato-agent-accountability-composition-00`
- EP-AEG `draft-schrock-ep-action-evidence-graph-00`, retained only to
  describe its revision relationship with EP-AEC -04

Each cited document is an individual Internet-Draft. None has formal standing
in the IETF standards process. This crosswalk does not claim compatibility,
adoption, endorsement, or an official relationship between VATE and those
drafts.

## Review Boundary

VATE does not replace native EP or APS verification. It does not establish that
an adjacent receipt, graph, authority chain, runtime attestation, or policy
result is valid merely because the artifact is referenced by a VATE request.

The narrow VATE question begins after adjacent evidence has been verified under
its own rules:

> Given the verified evidence, current runtime and status context, and local
> relying-party policy, may this concrete external action execute as requested,
> only under narrower effective constraints, or not at all; and what record
> binds that decision to later execution evidence?

For this crosswalk, the **effective execution basis** means the combined VATE
surface represented by:

- `decision.outcome` and `should_execute`
- the original and effective request hashes when attenuation applies
- `attenuation.effective_constraints`
- runtime, transaction, validity-window, and policy bindings
- the admission receipt referenced by later post-execution checks

This is descriptive shorthand, not a new VATE artifact or schema field.

## Crosswalk

| Work | Primary role in the cited revision | Material overlap with VATE | Remaining VATE boundary under review | When it can make VATE unnecessary |
|---|---|---|---|---|
| EP-AEC | Composes natively verified, action-matched evidence against a relying-party-owned requirement and emits fail-closed `SATISFIED` or `UNSATISFIED` plus a deterministic replay record; it explicitly does not produce local `AUTHORIZED` or define an execution state machine | Verifier-side evidence composition, relying-party requirements, native-verification separation, CAID-based same-action matching, freshness and status checks, byte-backed relations, and bounded reasoned results | A portable local admission and attenuation artifact after evidence satisfaction; explicit runtime and transaction binding; and reason-specific post-execution comparison against the admitted basis | When the application keeps AEC satisfaction and its separate local authorization entirely inside one boundary and does not need portable narrowing or later cross-boundary comparison |
| AEB | Defines an executor-side ordered lifecycle: construct the frozen observed action, natively verify artifacts, establish CAID `MATCH`, obtain AEC `SATISFIED`, make a separate local `AUTHORIZED` decision, atomically consume or reserve, invoke, classify `EXECUTED / FAILED / INDETERMINATE`, and reconcile against authenticated authoritative evidence | Strong overlap with verifier-side admission, current status and policy evaluation, fail-closed execution gating, durable pre-dispatch state, and admission-to-outcome review | AEB intentionally defines no receipt or token format and no universal authorization-decision format. VATE can be evaluated only as a candidate portable contract for carrying a narrowed local admission decision and effective constraints to a runtime or later reviewer | An internal AEB deployment can make VATE unnecessary when its decision, any narrowing, enforcement, durable state, and reconciliation stay inside one boundary and no portable decision, attenuation, or cross-boundary review artifact is required |
| CAID | Defines typed canonical action identifiers, executor-side derivation, exact equality, and relying-party-pinned cross-format mapping after native verification; it expressly carries content identity, not trust or authorization | Exact-action binding, digest recomputation, frozen material fields, and explicit rejection of lossy, unknown, or presenter-selected mappings | The local `allow / attenuate / deny` decision, effective constraints, runtime and transaction bindings, evidence sufficiency, and admission-to-execution linkage | CAID alone cannot replace VATE; it can make VATE's action-correlation function redundant where the deployment already uses CAID and keeps all remaining admission and review state internal |
| Authorization Receipts | Defines an action-bound named-approver authorization artifact, approver-held signatures, separation of duties, terminal consumption, Merkle inclusion material, offline verification, and execution-side enforcement classes | Pre-execution authorization evidence, exact-action binding, policy and validity references, one-time-consumption records, and portable receipt verification | Composition of heterogeneous evidence; current local policy and status; an explicit `allow / attenuate / deny` result with effective constraints; runtime and transaction binding; and comparison with post-execution evidence | When named-human authorization is the complete admission rule and the executor's native receipt verification, consumption, and enforcement cover every required boundary without local attenuation or heterogeneous evidence composition |
| APS | Defines identity, delegation, monotonic authority narrowing, `permit / deny / narrow`, a two-phase execution gate, execution-time rechecks, and signed completion receipts | Direct overlap with attenuation, execution gating, revocation rechecks, bounded approval artifacts, and authorization-to-completion linkage | A narrower protocol-neutral admission and receipt contract for deployments consuming heterogeneous non-APS evidence or crossing products and trust domains | In an end-to-end APS deployment where the APS authority, gate, and receipt model already cover every required verifier, runtime, and audit boundary |
| Agent Accountability Composition | Defines composable CAN, WHO, WHAT, and AUDIT question slots joined by a shared action digest; the cited revision leaves the CAN profile text open | The CAN question, "was the agent permitted to act?", overlaps VATE's verifier-admission role | VATE can be evaluated as one candidate source of CAN-profile semantics, but no official mapping or slot ownership exists | When another CAN profile defines and gains adoption for equivalent admission, narrowing, runtime-binding, and completion-comparison semantics |
| EP-AEG | Defines a content-addressed evidence graph, five closed evidence verdicts, policy packs, and an optional signed Reliance Result. EP-AEC -04 supersedes it only for the evidence-composition and replay scope that -04 incorporates; AEC does not adopt the AEG graph envelope, five-verdict taxonomy, policy packs, or signed result format | Relying-party policy, freshness, revocation requirements, runtime-attestation inputs, reasoned verifier results, and post-execution evidence relationships | For the AEG-only surfaces, a concrete execution directive, a transformed effective request and constraints for the runtime, and reason-specific comparison against that admitted basis | When an AEG-based deployment contract produces and enforces the same narrowed execution basis and later comparison semantics; AEC -04 supersession alone does not do so |

The overlap is intentional to state. VATE should not claim that status checks,
revocation, attenuation labels, signed decisions, or post-execution receipts are
unique by themselves.

## AEB Candidate-Contract Hypothesis

AEB does not reserve an empty slot for VATE and does not define an official
plug-in relationship. Section 1.1 excludes a new receipt, token, policy
language, universal authorization decision, or universal evidence taxonomy,
and Section 11 says AEB conformance does not require a new common envelope for
the earlier lifecycle wire shapes.

That leaves a narrower, falsifiable hypothesis: where the AEB local decision
must cross a component or trust boundary, VATE can be evaluated as a candidate
contract for transporting that relying party's narrowed admission decision:

- A VATE `attenuate` receipt is not AEB `AUTHORIZED` by itself. VATE `allow`
  or executable `attenuate` can at most carry a candidate portable record of
  the local admission basis. A component claiming AEB conformance must still
  construct the complete effective observed action from trusted
  boundary-controlled facts and apply the full ordered AEB Sections 5.1
  through 5.7 lifecycle to that effective action: native verification, CAID
  `MATCH`, AEC `SATISFIED`, a separate local `AUTHORIZED` decision, atomic
  consumption or reservation, durable `DISPATCH_PENDING`, and frozen
  invocation. A non-executable attenuation remains a request for fresh
  authority, not authorization to invoke.
- AEB refusal can be compared with VATE `deny`. These are candidate mappings,
  not vocabulary equivalence or an official AEB profile.
- Under AEB Sections 5.8 and 5.9, VATE's admission-receipt to post-execution
  linkage can record whether natively verified execution evidence matches the
  admitted basis. VATE does not authenticate, certify, or confer authority on
  provider or system-of-record evidence; native verification and AEB's
  authoritative reconciliation rules remain outside that linkage layer.

The current VATE v0.3 corpus binds original and effective request hashes,
recorded changes, effective constraints, executability, and selected
admission-to-post-execution comparisons. It does not demonstrate the complete
AEB Sections 5.1 through 5.7 ordering, effect-boundary construction of every
material field, durable consumption or reservation, `DISPATCH_PENDING`, or
runtime enforcement. A passing VATE case is therefore not evidence of AEB
conformance.

At the document level, AEB -00 intentionally defines no common portable output
format for local authorization or attenuation and no VATE-shaped conformance
corpus. This is not a claim that AEB, EMILIA implementations, or deployments
have no tests.

The adjacent `draft-schrock-ep-revocation-statement-00` is relevant only as one
possible native status input. It defines a portable terminal statement that a
pinned revoker revoked one exact authorization target. It does not prove
current non-revocation when no statement is presented, authorize the revoker by
signature alone, reverse an effect, or replace AEB local policy and
reconciliation. This crosswalk makes no VATE mapping for that artifact.

## Revision-Specific Implementation Status

The following is revision-text or Datatracker-linked project evidence, not an
independent verification, an adoption claim, or a ranking of implementation
maturity:

- **EP-AEC -04:** reports same-team TypeScript, Python, and Go implementations
  agreeing on shared vectors for the existing AEC envelope and evaluator. It
  also states that the combined -04 requirement and replay contract is not yet
  covered by that three-language vector suite, so the repository is not a
  complete conforming -04 implementation.
- **AEB -00:** Datatracker links the EMILIA Protocol repository and Gate
  implementation. The linked code and tests include a durable AEB consumption
  store, proposal-to-effect processing, reservation and indeterminate-outcome
  handling, and authenticated reconciliation examples. This is relevant
  implementation evidence, but it does not establish the complete Section 5
  ordered lifecycle for every protected invocation, all Section 8 deployment
  claims, complete mediation, or revision-scoped independent conformance.
- **CAID -01:** Datatracker links the CAID reference implementations,
  machine-readable action-type and suite registries, and shared core and
  mapping vectors. JavaScript, Python, and Go implementations consume those
  vectors, providing cross-language consistency evidence. They are maintained
  by the same team in one repository, not independent implementations, and
  mapping completeness still depends on the relying party's review of each
  profile's material-field model.
- **Authorization Receipts -08:** reports three same-repository reference
  verifiers agreeing on published vectors and a separately authored Rust
  verifier passing a time-pinned 16-suite, 164-vector bundle. It also lists
  normative mechanisms not yet exercised by the reference implementation or
  vectors, formal-model exclusions, and why the Rust result is not current
  clean-room acceptance for the whole specification.
- **Revocation Statement -00:** Appendix A reports Apache-2.0 JavaScript,
  Python, and Go verifiers, a JSON Schema, attack-catalogue vectors, and an
  executable suite with 19 real-signature cases agreeing across the three
  languages. These are same-team ports, not independent implementations. The
  generic verifiers can validate the closed Trust Program `commit` target, but
  no end-to-end adapter yet derives that target, verifies the portable
  statement, and commits revocation-versus-claim in one durable transaction;
  the draft makes no completed implementation or independent-interoperability
  claim for that profile.
- **EP-AEG -00:** reports one Apache-2.0 reference implementation in the EMILIA
  codebase covering graph evaluation, policy replay, signed Reliance Results,
  all six policy packs, and tests of its fail-closed invariants. Its
  evidence-composition and replay role is now superseded by AEC -04 only to the
  scope stated above.
- **APS -03:** reports AEOESS-maintained TypeScript core coverage including
  strict RFC 8785 canonicalization and native action-reference computation,
  with TypeScript, Python, and Go sharing known-answer action-reference vectors
  and public fixtures. The same appendix says these results do not establish
  independent implementation or adoption, emitted TypeScript passport and
  delegation records predate this revision's wire formats, and Python and Go
  implement subsets. It specifies no A2A binding and calls the released A2A
  adapter experimental.
- **Agent Accountability Composition -00:** specifies no implementation; a
  conformance vector freezes only after recomputation by at least two
  independent implementations.

## Existing VATE Case Slice

No new fixture is introduced by this crosswalk. The relevant current behavior
is already reviewable in these v0.3 cases:

| Existing case | Boundary it exercises |
|---|---|
| [`deny-status-revoked`](../../conformance/al2-vate-v0.3/cases/deny-status-revoked.json) | Valid-looking inputs do not override current revoked status; execution is denied |
| [`deny-runtime-proof-stale`](../../conformance/al2-vate-v0.3/cases/deny-runtime-proof-stale.json) | A stale runtime proof fails closed before local policy can admit execution |
| [`attenuate-max-amount`](../../conformance/al2-vate-v0.3/cases/attenuate-max-amount.json) | Local policy narrows the amount and records original and effective request hashes |
| [`attenuate-target-scope`](../../conformance/al2-vate-v0.3/cases/attenuate-target-scope.json) | The admitted target scope is narrower than the requested scope |
| [`attenuate-requires-new-permit`](../../conformance/al2-vate-v0.3/cases/attenuate-requires-new-permit.json) | An `attenuate` outcome can remain non-executable until a fresh permit is obtained |
| [`post-execution-effective-constraints-exceeded`](../../conformance/al2-vate-v0.3/cases/post-execution-effective-constraints-exceeded.json) | A later effect outside the admitted effective constraints fails linkage review |
| [`post-execution-effective-constraints-aggregate-exceeded`](../../conformance/al2-vate-v0.3/cases/post-execution-effective-constraints-aggregate-exceeded.json) | Aggregate effects are compared with the admitted limit, not only each individual effect |
| [`post-execution-runtime-mismatch`](../../conformance/al2-vate-v0.3/cases/post-execution-runtime-mismatch.json) | Execution under a different runtime fails the admission-to-execution binding |

These are repository fixtures and reference-runner review cases. They are not,
by themselves, independent implementation evidence.

## Digest Boundary

The cited EP and Agent Accountability Composition drafts use RFC 8785 JCS-based
action digests for their composition model. CAID defines JCS- and CBOR-based
suites, and AEB delegates cross-format action matching to CAID after native
verification. APS also defines JCS-based digest forms in its cited revision.

The current VATE v0.3 conformance path uses several digest classes. Its selected
JSON-object fixture basis sorts keys and removes insignificant whitespace, but
it is explicitly not a production JCS profile. See
[`docs/conformance/digest-basis.md`](../conformance/digest-basis.md).

Therefore this document maps concepts and decision boundaries only. It does not
claim byte-level digest interoperability, direct CAN-slot conformance, or that
an EP, CAID, AEB-linked, or APS action digest can be substituted for a VATE
digest descriptor. A future profile would need to define the exact action
object, canonicalization, domain separation, and digest translation or equality
rules, with independent implementation evidence.

## Falsifiable Position

The current hypothesis is that VATE has a distinct role only when all three of
these deployment conditions hold:

- more than one evidence or authorization ecosystem feeds the verifier;
- local relying-party policy can narrow the requested action; and
- a component outside the verifier boundary - the runtime, a later reviewer,
  or both - must consume or compare the exact admitted execution basis.

VATE may be unnecessary when:

- one integrated APS-like stack already supplies the complete authority, gate,
  revalidation, and completion contract;
- one internal AEB deployment keeps local authorization, any narrowing,
  enforcement, durable state, and reconciliation within the same boundary and
  needs no portable decision, attenuation, or cross-boundary review artifact;
- the policy decision and enforcement point share one internal representation
  that no other system needs to consume;
- every narrowing can be handled as deny plus a new authorization request
  without losing required information;
- post-execution records remain internal logs and no portable admission linkage
  is needed.

The current open question is whether independent implementations need the VATE
effective execution basis across real verifier, runtime, and audit boundaries.
Additional author-owned fixtures would not answer that question.

## Non-Goals

This crosswalk does not:

- define EP-AEC, AEB, CAID, Authorization Receipt, EP-AEG, APS, or CAN
  semantics;
- add an EP, AEB, CAID, APS, or CAN evidence type or `protocol_hint` to VATE
  v0.3;
- implement or validate adjacent drafts;
- establish semantic equivalence among adjacent artifacts and VATE receipts;
- establish an AEB plug-in, adoption, endorsement, or official mapping;
- claim that VATE fills the CAN slot officially;
- change the VATE schema, runner, corpus, digest basis, or public claim boundary.

## Adjacent References

- EP-AEC: <https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-evidence-chain/>
- AEB: <https://datatracker.ietf.org/doc/draft-schrock-action-evidence-boundary/>
- CAID: <https://datatracker.ietf.org/doc/draft-schrock-canonical-action-identifier/>
- Authorization Receipts: <https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/>
- Revocation Statement: <https://datatracker.ietf.org/doc/draft-schrock-ep-revocation-statement/>
- EP-AEG: <https://datatracker.ietf.org/doc/draft-schrock-ep-action-evidence-graph/>
- APS: <https://datatracker.ietf.org/doc/draft-pidlisnyi-aps/>
- Agent Accountability Composition: <https://datatracker.ietf.org/doc/draft-mih-sato-agent-accountability-composition/>
