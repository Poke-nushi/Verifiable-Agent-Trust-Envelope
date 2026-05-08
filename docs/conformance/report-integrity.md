# VATE Report Integrity Guidance

## Status

This note defines the publication and integrity guidance for AL2 v0.2 SUT
results, conformance reports, and implementation reports.

It is not a production signature profile. It gives reviewers enough information
to decide whether one published report is durable, attributable, and tied to the
same corpus snapshot.

## Threats

Report reviewers should assume these failure modes:

- a report was edited after it was generated
- a passing report points to an older or different corpus snapshot
- an implementation identity is copied from another project
- a mutable URL is later replaced with different results
- a conformance report is separated from the SUT result or implementation report

## Minimum Publication Package

For an independent implementation review, publish these artifacts together:

- the SUT result file matching `schemas/sut-result.schema.json`
- the comparison conformance report matching `schemas/conformance-report.schema.json`
- the implementation report matching `schemas/implementation-report.schema.json`
- the corpus digest and, preferably, the exact `corpus.json`
- any detached proof or release signature used by the implementer

The implementation report should reference the conformance report through
`conformance_report.uri` and `conformance_report.digest`.

## Controlled Origin

An implementation report should be hosted under an origin or repository
namespace controlled by the implementation maintainer.

Acceptable early-review examples include:

- a release asset in the implementation repository
- a versioned URL under the implementer's domain
- a content-addressed object with a stable maintainer-controlled index
- a signed git tag that contains the report bundle

Avoid using local paths, temporary upload URLs, paste sites, or mutable files as
the only report location.

## Optional Proof References

The `proofs[]` block in `schemas/implementation-report.schema.json` can point to
an external proof for the report or containing release bundle.

Supported proof reference labels are:

- `detached_jws`
- `signed_git_tag`
- `sigstore_bundle`
- `other`

The v0.2 repository does not verify those proofs. It only records where a
reviewer can find them and what artifact they are intended to cover.

## Verification Checklist

A reviewer should check:

- `implementation.source` and `publication.controlled_origin` identify the same
  maintainer or an explicitly delegated publisher
- `implementation.commit` points to an immutable implementation revision when
  source is public
- `corpus.digest` matches the corpus snapshot used by the report
- `conformance_report.digest` matches the fetched conformance report under the
  stated `conformance_report.digest_basis`
- skipped, errored, or unsupported cases are visible in the report
- limitations are stated rather than hidden in prose outside the report

## Claim Boundary

A durable passing report means one implementation matched one corpus snapshot.

It does not imply production readiness, independent security review, future
profile compatibility, or any right to make a broader conformance claim.
