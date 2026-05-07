# VATE Implementation Reporting

This note defines how an implementation can publish a machine-readable result for the `VATE-AL2-Verifier-Admission-v0.2` conformance corpus.

The purpose is narrow:

- identify the implementation that ran
- identify the exact corpus snapshot
- link to the conformance report emitted by the runner
- summarize passed, failed, and skipped cases
- make limitations explicit

An implementation report is not a badge, endorsement, or production-readiness statement.
It records one run of one implementation against one corpus snapshot.

## Report Shape

Implementation reports follow:

- `schemas/implementation-report.schema.json`

Example:

- `examples/implementation-report.example.json`

The report has four important blocks:

- `implementation` - name, version, language, source, and optional commit or environment
- `corpus` - corpus name, root, case count, artifact count, digest, and manifest
- `conformance_report` - URI, media type, and digest of the runner output
- `summary` and `case_results` - the result surface a reviewer can compare across implementations

The portable corpus shape is published separately as:

- `conformance/al2-vate-v0.2/corpus.json`
- `schemas/conformance-corpus.schema.json`

Non-reference implementations should use the corpus index to discover cases and artifacts, then publish their own conformance and implementation reports.

## Reference Runner Command

```bash
python3 scripts/vate_conformance.py run \
  --corpus-root conformance/al2-vate-v0.2 \
  --report /tmp/vate-conformance-report.json \
  --implementation-report /tmp/vate-implementation-report.json \
  --implementation-name "Example VATE verifier" \
  --implementation-type "verifier" \
  --implementation-version "0.1.0" \
  --implementation-language "Python 3" \
  --implementation-repo "https://example.invalid/repo" \
  --implementation-commit "example-commit"
```

The runner writes:

- a conformance report using `application/vate-conformance-report+json`
- an implementation report using `application/vate-implementation-report+json`

The implementation report includes a digest of the conformance report and a digest of the corpus snapshot.
The corpus digest is computed over the sorted `corpus.manifest` array.
Each manifest entry records a repository-relative artifact path and the artifact's raw file SHA-256 digest.
The committed `corpus.json` uses the same manifest and digest basis.

## Review Use

For early interop review, a useful report should answer:

- did the implementation produce the expected `allow / attenuate / deny` outcomes
- did it emit the expected reason codes
- did it preserve machine-readable attenuation fields
- did it fail closed for stale, revoked, replayed, mismatched, or untrusted inputs
- did it validate post-execution linkage

Reports should not hide skipped or unsupported behavior.
If an implementation does not support a case, record it as skipped or failed and explain the limitation.

## Comparison Boundary

Two reports are comparable only when they use the same:

- `profile`
- corpus digest
- case set
- expected reason code vocabulary

If the corpus changes, publish a new report rather than editing the old result in place.
