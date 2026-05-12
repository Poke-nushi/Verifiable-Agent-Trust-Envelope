# External Implementation Call

## Status

This is a short call for independent implementation review of the
`VATE-AL2-Verifier-Admission-v0.3` discussion-draft corpus.

It is not a certification program, endorsement process, production approval, or
official compatibility claim.

## What We Are Asking For

The useful next evidence is one non-reference verifier run against the current
AL2 v0.3 corpus snapshot.

For a useful early review, an implementer should publish three things:

1. a SUT result file;
2. generated artifacts or a controlled artifact bundle;
3. an implementation report.

The SUT result file lets this repository run `compare`.
The generated artifacts or bundle let reviewers see that the result is not only
copied from repository fixtures.
The implementation report ties the run to one implementation, one corpus
snapshot, and one comparison report.

## Minimum Package

Use these files and formats:

- `conformance/al2-vate-v0.3/corpus.json`
- `schemas/sut-result.schema.json`
- `schemas/conformance-report.schema.json`
- `schemas/implementation-report.schema.json`
- `docs/conformance/external-sut-quickstart.md`
- `docs/conformance/report-integrity.md`

At minimum, include:

- implementation name, version, language, and source or stable reference;
- corpus digest from `conformance/al2-vate-v0.3/corpus.json`;
- result entries for the corpus cases the implementation attempted;
- ordered reason codes and `should_execute` values;
- digest-bound artifact references for receipt, context, and proof-package
  cases where the corpus requires them;
- limitations for skipped, unsupported, or intentionally unimplemented cases.

## Compare Flow

Prepare a SUT result file and run:

```bash
python3 scripts/vate_conformance.py compare \
  --corpus-root conformance/al2-vate-v0.3 \
  --sut-results /path/to/your-sut-results.json \
  --report /tmp/vate-sut-compare-report.json \
  --implementation-report /tmp/vate-sut-implementation-report.json \
  --conformance-report-uri /tmp/vate-sut-compare-report.json \
  --implementation-report-uri /tmp/vate-sut-implementation-report.json
```

Then verify the local report bundle:

```bash
python3 scripts/vate_conformance.py verify-bundle \
  --corpus-root conformance/al2-vate-v0.3 \
  --sut-results /path/to/your-sut-results.json \
  --conformance-report /tmp/vate-sut-compare-report.json \
  --implementation-report /tmp/vate-sut-implementation-report.json \
  --report /tmp/vate-report-bundle-verification.json
```

Use maintainer-controlled, stable URIs instead of `/tmp/` paths when publishing
reports for external review.

## Review Questions

Useful feedback includes:

- whether the corpus cases are clear enough to implement without reading the
  Python reference runner as the primary specification;
- whether `allow`, `attenuate`, and `deny` outcomes are reproducible from the
  corpus data;
- whether reason codes are specific enough for negative cases;
- whether artifact and digest requirements are practical for external SUT
  outputs;
- whether post-execution linkage checks are understandable and implementable;
- whether any wording implies certification, endorsement, production readiness,
  or official adjacent-protocol adoption.

## Claim Boundary

A passing `compare` report means one submitted SUT result matched one corpus
snapshot under this repository's comparison rules.

It does not mean the implementation is production-ready, endorsed, certified,
generally compatible, or compatible with future corpus versions.

