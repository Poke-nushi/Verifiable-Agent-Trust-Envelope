# EP / APS / CAN To VATE Execution-Admission Crosswalk

## Status

This is a non-normative review aid for the
`VATE-AL2-Verifier-Admission-v0.3` discussion draft.

It compares the following work-in-progress revisions as of 2026-07-22:

- EP-AEC `draft-schrock-ep-authorization-evidence-chain-03`
- EP-AEG `draft-schrock-ep-action-evidence-graph-00`
- APS `draft-pidlisnyi-aps-03`
- Agent Accountability Composition (CAN / WHO / WHAT / AUDIT question slots)
  `draft-mih-sato-agent-accountability-composition-00`

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
| EP-AEC | Composes heterogeneous evidence verified under its native rules, checks same-action binding, and evaluates a relying-party-pinned requirement with a fail-closed `SATISFIED` or `UNSATISFIED` result; this is not a universal or local authorization decision, and the executor separately decides `AUTHORIZED` | Verifier-side evidence composition, relying-party requirements, same-action binding, and fail-closed evidence-satisfaction results, plus executor-side action-digest-keyed one-time consumption, immutable action snapshots, and durable atomic decision logging | A portable local admission and attenuation artifact; explicit runtime and transaction identity binding; and reason-specific post-execution comparison of observed effects against the admitted basis | When the deployment does not need a portable admission artifact and its executor provides equivalent narrowing, runtime and transaction binding, and reason-specific post-execution comparison |
| EP-AEG | Builds a content-addressed evidence graph and replays relying-party policy to produce one of five closed evidence verdicts and an optional signed Reliance Result | Relying-party policy, freshness, revocation requirements, runtime-attestation inputs, reasoned verifier results, and post-execution evidence relationships | A concrete execution directive, a transformed effective request and constraints for the runtime, and reason-specific comparison against that admitted basis | When an EP-AEG profile or deployment contract produces and enforces the same narrowed execution basis and later comparison semantics |
| APS | Defines identity, delegation, monotonic authority narrowing, `permit / deny / narrow`, a two-phase execution gate, execution-time rechecks, and signed completion receipts | Direct overlap with attenuation, execution gating, revocation rechecks, bounded approval artifacts, and authorization-to-completion linkage | A narrower protocol-neutral admission and receipt contract for deployments consuming heterogeneous non-APS evidence or crossing products and trust domains | In an end-to-end APS deployment where the APS authority, gate, and receipt model already cover every required verifier, runtime, and audit boundary |
| Agent Accountability Composition | Defines composable CAN, WHO, WHAT, and AUDIT question slots joined by a shared action digest; the cited revision leaves the CAN profile text open | The CAN question, "was the agent permitted to act?", overlaps VATE's verifier-admission role | VATE can be evaluated as one candidate source of CAN-profile semantics, but no official mapping or slot ownership exists | When another CAN profile defines and gains adoption for equivalent admission, narrowing, runtime-binding, and completion-comparison semantics |

The overlap is intentional to state. VATE should not claim that status checks,
revocation, attenuation labels, signed decisions, or post-execution receipts are
unique by themselves.

## Revision-Specific Implementation Status

The following is document-reported evidence for the cited revisions, not an
independent verification or a ranking of implementation maturity:

- **EP-AEC -03:** reports same-project JavaScript, Python, and Go reference
  implementations agreeing on shared vectors; they are not independently
  developed. It also cites a third party's execution and verification of the
  published artifacts against a pinned commit.
- **EP-AEG -00:** reports one Apache-2.0 reference implementation in the EMILIA
  codebase covering graph evaluation, policy replay, signed Reliance Results,
  all six policy packs, and tests of its fail-closed invariants.
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
action digests for their composition model. APS also defines JCS-based digest
forms in its cited revision.

The current VATE v0.3 conformance path uses several digest classes. Its selected
JSON-object fixture basis sorts keys and removes insignificant whitespace, but
it is explicitly not a production JCS profile. See
[`docs/conformance/digest-basis.md`](../conformance/digest-basis.md).

Therefore this document maps concepts and decision boundaries only. It does not
claim byte-level digest interoperability, direct CAN-slot conformance, or that
an EP or APS action digest can be substituted for a VATE digest descriptor. A
future profile would need to define the exact action object, canonicalization,
domain separation, and digest translation or equality rules, with independent
implementation evidence.

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

- define EP-AEC, EP-AEG, APS, or CAN semantics;
- add an EP, APS, or CAN evidence type or `protocol_hint` to VATE v0.3;
- implement or validate adjacent drafts;
- establish semantic equivalence among adjacent artifacts and VATE receipts;
- claim that VATE fills the CAN slot officially;
- change the VATE schema, runner, corpus, digest basis, or public claim boundary.

## Adjacent References

- EP-AEC: <https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-evidence-chain/>
- EP-AEG: <https://datatracker.ietf.org/doc/draft-schrock-ep-action-evidence-graph/>
- APS: <https://datatracker.ietf.org/doc/draft-pidlisnyi-aps/>
- Agent Accountability Composition: <https://datatracker.ietf.org/doc/draft-mih-sato-agent-accountability-composition/>
