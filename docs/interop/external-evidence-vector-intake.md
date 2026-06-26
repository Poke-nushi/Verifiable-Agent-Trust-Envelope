# External Evidence Vector Intake

## Status

This note defines how VATE can reference external evidence vector sets during
corpus review without making them normative dependencies.

External vectors can help reviewers test whether adjacent evidence artifacts are
byte-stable and practical for SUT authors. They do not, by themselves, change
the VATE claim boundary.

Pinned review slices are recorded in
`docs/interop/external-evidence-vector-pins.md`.

## Non-Goals

Referencing an external vector set does not imply:

- VATE certification;
- endorsement of the external project;
- adoption of the external protocol as a VATE dependency;
- production approval of the external implementation;
- equivalence between adjacent protocol hashes and VATE digest descriptors.

## Required Metadata

Each imported or referenced vector slice should record:

- source repository;
- source commit or immutable release tag;
- license;
- vector set name;
- vector IDs;
- selected evidence object path;
- digest basis;
- expected digest or expected byte fixture;
- whether the vector is vendored, copied, or referenced externally;
- why the vector is relevant to a specific VATE case or review question;
- whether the vector is used only as non-normative review evidence.

If any of those fields are unclear, keep the vector out of the corpus and ask
the provider for exact paths, vector IDs, and the intended mapping.

## Intake Rules

Prefer a small referenced slice before vendoring external material.

Do not use an adjacent protocol's native identifier as a VATE digest descriptor
unless a VATE profile explicitly defines that equivalence.

Do not add external vector fixtures to the conformance corpus merely because an
adjacent protocol or implementation is useful. A vector should answer a concrete
VATE review question, such as:

- whether a selected evidence object is byte-stable across runtimes;
- whether a post-execution evidence artifact links back to an admitted decision;
- whether an adjacent payment, task, or receipt artifact can be referenced
  without inlining domain-specific semantics into VATE.

## Candidate External Slices

Candidate non-normative slices for review may include:

- `pef_v1` for PEF receipt and frame hash stability;
- `execution_ref_v1` for decision-bound execution evidence;
- a specific AP2- or A2A-shaped vector set only after the provider identifies
  the exact source path, vector IDs, commit or tag, and mapping.

Those candidates are review inputs only. They are not VATE dependencies, and
they are not evidence of VATE certification, endorsement, production approval,
or general compatibility.
