# Conformance Artifact Versioning

## Status

This note fixes how date-stamped conformance artifact identifiers are used in
the v0.2 AL2 draft.

## Current Decision

Keep the `2026-07` identifiers.

In this repository, `2026-07` means a July 2026 target interop artifact line.
It is not the publication date, not the date on which a fixture was edited, and
not a production-readiness claim.

The exact corpus snapshot for a run is identified by the manifest digest in
`conformance/al2-vate-v0.2/corpus.json` and in generated reports. The date label
is a compatibility line for the draft artifact contracts, not a substitute for
that digest.

In short: Do not rename `2026-07` identifiers to the current review month while
the same profile, corpus, schema, and report contracts are being hardened.
Renaming these identifiers would change report constants, schema IDs, fixture
versions, and corpus manifests without changing verifier semantics.

## What The Label Covers

The `2026-07` label may appear in:

- profile note filenames, such as
  `docs/profiles/vate-al2-admission-interop-profile-2026-07.md`
- schema `$id` values for conformance-facing artifacts
- fixture and report `version` constants, such as
  `vate-conformance-report-2026-07`
- deterministic fixture timestamps, such as `2026-07-01T00:00:00Z`
- policy version examples used by deterministic fixtures

Fixture timestamps are scenario times used to make freshness, replay, validity
window, and digest behavior reproducible. They are not a claim that the
repository was published or reviewed on that date.

## When To Change It

Change the date label only when creating a new target interop snapshot with a
meaningfully different contract. Examples include:

- incompatible report schema changes
- incompatible SUT result contract changes
- a new conformance corpus snapshot intended to supersede the current one
- profile behavior changes that alter expected outcomes, reason codes, or
  required artifact bindings

Do not rename the label for docs-only changes, editorial cleanup, new review
comments, or ordinary fixture hardening that preserves the same target artifact
line.

## Claim Boundary

The date label is only an artifact-line identifier. Passing artifacts with
`2026-07` version strings means the implementation matched this draft fixture
set for that target line and the exact corpus digest reported for that run.

It does not imply production readiness, endorsement, security review completion,
or compatibility with future VATE profiles.
