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

The committed `vate-1a` and `vate-1d` files are not treated here as a literal
one-field byte pair. Each vector is interpreted independently from its own
bytes and its `vectors/MANIFEST.json` expectation.

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

The result applies to the fixed VATE corpus digest and AEE merged PR head named
above. Later bytes require a new pinned review.
