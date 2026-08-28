# AEE-Native Boundary Vectors Prompted By VATE Cases

## Status

Eight executable Adversarial Execution Evidence (AEE) vectors prompted by
three pinned VATE cases are part of AEE conformance suite revision 26. The
merged slice turns the VATE boundary questions into five accepting and three
rejecting vectors evaluated by AEE's own predicate and verification rails.

This is a source-pinned external technical review record. The vectors remain
AEE-native artifacts in the separately maintained AEE repository; none is
vendored into the VATE corpus.

## External Record

| Field | Pinned value |
|---|---|
| Repository | [`astrogilda/aee-conformance`](https://github.com/astrogilda/aee-conformance) |
| Review discussion | [AEE issue #3](https://github.com/astrogilda/aee-conformance/issues/3) |
| Merged contribution | [AEE PR #4](https://github.com/astrogilda/aee-conformance/pull/4) |
| Merged PR head / GitHub merge SHA | [`2aa5a23d0e0cf93921a59510a755ccfe1e103a47`](https://github.com/astrogilda/aee-conformance/commit/2aa5a23d0e0cf93921a59510a755ccfe1e103a47) |
| AEE suite | revision 26, 258 vectors |
| AEE corpus digest at the merged PR head | `8d4d08dedd7b5fe8b99c2b9a7d42fa407e6ca20f6cda6da337c0efc838a9d6ab` |
| License | Apache-2.0 |

The AEE-side provenance and interpretation are recorded in its pinned
[`vectors/CHANGES.md`](https://github.com/astrogilda/aee-conformance/blob/2aa5a23d0e0cf93921a59510a755ccfe1e103a47/vectors/CHANGES.md)
and machine-readable
[`vectors/MANIFEST.json`](https://github.com/astrogilda/aee-conformance/blob/2aa5a23d0e0cf93921a59510a755ccfe1e103a47/vectors/MANIFEST.json).

## Follow-up Correction

The external record above remains the historical pin for the merged
contribution. AEE later corrected the specific case-1 control pair without
rewriting suiteRevision 26:

| Field | Pinned value |
|---|---|
| Correction commit | [`297636c25472b207c56e90ab13b5a15cc40d6f25`](https://github.com/astrogilda/aee-conformance/commit/297636c25472b207c56e90ab13b5a15cc40d6f25) |
| AEE suite at correction | suiteRevision 27, 258 vectors; corpus digest `12d27820ede985ac2cd43b5b4e6a6569ebd74a032f2748017022cb2735d282e9` |
| Maintainer explanation | [PR #4 follow-up](https://github.com/astrogilda/aee-conformance/pull/4#issuecomment-5447244673) |
| VATE owner confirmation | [verification comment](https://github.com/astrogilda/aee-conformance/pull/4#issuecomment-5447525943) |

At that commit, the committed
[`vate-1d`](https://github.com/astrogilda/aee-conformance/blob/297636c25472b207c56e90ab13b5a15cc40d6f25/vectors/accept/vate-1d-admission-receipt-as-sole-subject.json)
and
[`vate-1a`](https://github.com/astrogilda/aee-conformance/blob/297636c25472b207c56e90ab13b5a15cc40d6f25/vectors/reject/vate-1a-admission-receipt-substituted-splice.json)
statements each have 38 scalar leaves and differ only at
`subject[0].digest.sha256`. The reject generator reads the committed `vate-1d`
accept vector and mutates that path instead of rebuilding a parallel parent
fixture.

The VATE owner confirmation records a 258/258 reference-rail result, a 20/20
rail self-test, byte-identical regeneration of all 308 generated files under
the declared generator environment, and a passing accept-anchor gate. With the
accept parent removed in an isolated copy, the reject generator exited 1 with
`FileNotFoundError` at that exact parent path; it did not reconstruct a
fallback parent.

This correction establishes a literal one-field relation only for the
`vate-1d` / `vate-1a` control pair. suiteRevision 27 explicitly leaves
separate-fixture divergence in the broader declared parent set, including
`vate-1c` and `vate-3a`. The accept-anchor gate checks that a declared accept
parent exists by whole-id membership; it is not a corpus-wide proof that every
child differs from its parent by exactly one scalar leaf. These findings are
pinned to the correction commit and do not describe later AEE `main`.

## VATE Source Pins

The AEE vectors point back to this fixed VATE review surface:

- commit:
  [`ce00121d7bd658c7a1fcd861b386ea9ea7ce66be`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/ce00121d7bd658c7a1fcd861b386ea9ea7ce66be)
- profile: `VATE-AL2-Verifier-Admission-v0.3`
- corpus digest:
  `sha-256:0eb1969ea3763e0fec123de5ea0dacb225eb48a28d76866bbec56dc61d16cf8f`
- cases:
  - [`post-execution-admission-digest-mismatch`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/ce00121d7bd658c7a1fcd861b386ea9ea7ce66be/conformance/al2-vate-v0.3/cases/post-execution-admission-digest-mismatch.json)
  - [`post-execution-effective-constraints-aggregate-exceeded`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/ce00121d7bd658c7a1fcd861b386ea9ea7ce66be/conformance/al2-vate-v0.3/cases/post-execution-effective-constraints-aggregate-exceeded.json)
  - [`post-execution-runtime-mismatch`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/ce00121d7bd658c7a1fcd861b386ea9ea7ce66be/conformance/al2-vate-v0.3/cases/post-execution-runtime-mismatch.json)

These pins identify the exact VATE bytes that prompted the review. At VATE
commit `ce00121d7bd658c7a1fcd861b386ea9ea7ce66be`, the pinned corpus contains
72 cases. At the later VATE commit
`0ffbb9bfbde35dfb9ab11b953c550d60efc70aab`, the corpus contains 75 cases and
records digest
`sha-256:988aae7d03dd5bb743e8e03e6ab1120ce8735a4837ac818ffd9d665de0c1e370`.
The three case files named above are byte-identical between those snapshots,
but this AEE record is not a review of the 75-case corpus as a whole.

## Executable Boundary

### Admission Receipt Linkage

- [`vate-1a-admission-receipt-substituted-splice`](https://github.com/astrogilda/aee-conformance/blob/2aa5a23d0e0cf93921a59510a755ccfe1e103a47/vectors/reject/vate-1a-admission-receipt-substituted-splice.json)
  - `invalid`; manifest code `run-binding-mismatch`; also carries
    `sealed-record-absent`
- [`vate-1b-carried-admission-digest-unread`](https://github.com/astrogilda/aee-conformance/blob/2aa5a23d0e0cf93921a59510a755ccfe1e103a47/vectors/accept/vate-1b-carried-admission-digest-unread.json)
  - `valid` / `pass`
- [`vate-1c-two-subjects-artifact-and-admission`](https://github.com/astrogilda/aee-conformance/blob/2aa5a23d0e0cf93921a59510a755ccfe1e103a47/vectors/reject/vate-1c-two-subjects-artifact-and-admission.json)
  - `invalid`; manifest code `subject-cardinality`
- [`vate-1d-admission-receipt-as-sole-subject`](https://github.com/astrogilda/aee-conformance/blob/2aa5a23d0e0cf93921a59510a755ccfe1e103a47/vectors/accept/vate-1d-admission-receipt-as-sole-subject.json)
  - `valid` / `pass`

AEE binds its sole subject against record splicing and rejects a second
subject. A producer-carried admission digest remains outside the AEE predicate;
VATE's referenced-admission-receipt comparison remains a separate verifier-side
check.

At the merged revision 26 pin
`2aa5a23d0e0cf93921a59510a755ccfe1e103a47`, the committed `vate-1a` and
`vate-1d` files are not a literal one-field byte pair and are not treated as
one here. Each revision 26 vector is interpreted independently from its own
bytes and its `vectors/MANIFEST.json` expectation. The later revision 27
correction is recorded separately above.

### Aggregate Effective Constraints

- [`vate-2a-aggregate-overrun-unread`](https://github.com/astrogilda/aee-conformance/blob/2aa5a23d0e0cf93921a59510a755ccfe1e103a47/vectors/accept/vate-2a-aggregate-overrun-unread.json)
  - `valid` / `pass`

The vector carries two amounts that each remain below the carried maximum but
exceed it in aggregate. AEE remains valid because its predicate does not read
or aggregate those producer-defined quantities.

### Runtime Identity Across Admission And Observation

- [`vate-3a-substrate-substituted-splice`](https://github.com/astrogilda/aee-conformance/blob/2aa5a23d0e0cf93921a59510a755ccfe1e103a47/vectors/reject/vate-3a-substrate-substituted-splice.json)
  - `invalid`; manifest code `run-binding-mismatch`; also carries
    `sealed-record-absent`
- [`vate-3b-admitted-vs-observed-runtime-unread`](https://github.com/astrogilda/aee-conformance/blob/2aa5a23d0e0cf93921a59510a755ccfe1e103a47/vectors/accept/vate-3b-admitted-vs-observed-runtime-unread.json)
  - `valid` / `pass`
- [`vate-3c-substrate-substituted-and-resigned`](https://github.com/astrogilda/aee-conformance/blob/2aa5a23d0e0cf93921a59510a755ccfe1e103a47/vectors/accept/vate-3c-substrate-substituted-and-resigned.json)
  - `valid` / `pass`

AEE rejects a substrate substitution that breaks its run binding, while a run
rebound and re-signed for the substituted substrate remains valid. The
separate comparison between a producer-declared admitted runtime and observed
runtime remains a verifier-side VATE question.

The accepting vectors are essential to the result: they show where the AEE
predicate deliberately remains valid rather than turning the review into a
reject-only test set. The rejecting vectors show the binding and cardinality
properties AEE does enforce.

## Interoperability Result

The merged contribution establishes a durable composition boundary:

- AEE can validate and recompute its execution-evidence statement under its
  own predicate.
- VATE can separately ask whether the relying party admitted the exact request,
  narrowed it, or denied it, and whether later evidence matches that admitted
  or effective request.
- The same external action can therefore require both checks without treating
  either artifact as a substitute for the other.

The result is useful precisely because both sides of the boundary are
executable. It identifies AEE properties that hold, VATE relations that AEE
does not read, and the handoff between them without declaring semantic
equivalence.

## Claim Scope

This record is a solicited external technical review and an AEE-native corpus
contribution. It is not an external VATE SUT result, a VATE conformance result,
or evidence that AEE implements the VATE schemas or runner contract. It does
not imply endorsement, production approval, or general compatibility between
the projects.

The merged-contribution result applies to the fixed VATE corpus digest and AEE
merged PR head named above. The follow-up records only the case-1 control
correction and verification at `297636c25472b207c56e90ab13b5a15cc40d6f25`;
it is not a review of later AEE `main` or of the later corpus as a whole. Other
later bytes require a new pinned review.
