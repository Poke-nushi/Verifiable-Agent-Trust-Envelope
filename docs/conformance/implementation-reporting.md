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

For a command-first external SUT path, start with:

- `docs/conformance/external-sut-quickstart.md`

The report has four important blocks:

- `implementation` - name, version, language, source, and optional commit or environment
- `corpus` - corpus name, root, case count, artifact count, digest, and manifest
- `conformance_report` - URI, media type, digest, and digest basis of the runner output
- optional `publication` and `proofs` - durable location and external proof references
- `summary` and `case_results` - the result surface a reviewer can compare across implementations

`case_results[]` is a strict projection of the conformance report cases. It
includes `case_id`, expected and actual outcome, expected and actual
`should_execute`, and `pass`.

The portable corpus shape is published separately as:

- `conformance/al2-vate-v0.2/corpus.json`
- `schemas/conformance-corpus.schema.json`

Non-reference implementations should use the corpus index to discover cases and artifacts, then publish their own conformance and implementation reports.

For implementations that do not use the reference runner directly, publish a SUT result file first:

- `schemas/sut-result.schema.json`
- `docs/conformance/sut-adapter-contract.md`

The reference runner can compare that SUT result file against the corpus and emit a standard conformance report.
Use `compare` for external SUT review. Use `run` only to check the repository's
own fixture artifacts and reference runner behavior.

Report publication and integrity guidance is published separately:

- `docs/conformance/report-integrity.md`

## Reference Runner Command

```bash
python3 scripts/vate_conformance.py run \
  --corpus-root conformance/al2-vate-v0.2 \
  --report /tmp/vate-conformance-report.json \
  --implementation-report /tmp/vate-implementation-report.json \
  --conformance-report-uri "https://example.invalid/vate/reports/vate-conformance-report.json" \
  --implementation-report-uri "https://example.invalid/vate/reports/vate-implementation-report.json" \
  --publication-controlled-origin "https://example.invalid" \
  --publication-immutability versioned_url \
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
The runner records `conformance_report.digest_basis=json-sorted-no-whitespace`
for its canonical JSON digest.
The corpus digest is computed over the sorted `corpus.manifest` array.
Each manifest entry records a repository-relative artifact path and the artifact's raw file SHA-256 digest.
The committed `corpus.json` uses the same manifest and digest basis.
For external SUT comparisons, the conformance report also records
`sut_results.digest` using the same `json-sorted-no-whitespace` basis.

To publish an implementation report for an external SUT comparison, use
`compare` with `--implementation-report`:

```bash
python3 scripts/vate_conformance.py compare \
  --corpus-root conformance/al2-vate-v0.2 \
  --sut-results examples/conformance/sut-results-pass.example.json \
  --report /tmp/vate-sut-compare-report.json \
  --implementation-report /tmp/vate-sut-implementation-report.json \
  --conformance-report-uri "https://example.invalid/vate/reports/vate-sut-compare-report.json" \
  --implementation-report-uri "https://example.invalid/vate/reports/vate-sut-implementation-report.json" \
  --publication-controlled-origin "https://example.invalid" \
  --publication-immutability versioned_url
```

The implementation identity is copied from the SUT result file when `compare`
generates the implementation report.

For external SUT comparisons, the implementation report records the submitted
SUT result and comparison output. It does not independently prove that the SUT
generated every artifact referenced by the SUT result. When artifact provenance
matters, publish the SUT-produced artifacts or a controlled artifact bundle
alongside the reports and identify the maintainer-controlled origin in the
publication metadata.

To verify that the local report bundle is still tied together, run:

```bash
python3 scripts/vate_conformance.py verify-bundle \
  --corpus-root conformance/al2-vate-v0.2 \
  --sut-results examples/conformance/sut-results-pass.example.json \
  --conformance-report /tmp/vate-sut-compare-report.json \
  --implementation-report /tmp/vate-sut-implementation-report.json \
  --report /tmp/vate-report-bundle-verification.json
```

Do not put a self-digest of the implementation report inside the same JSON
object. If a report digest or signature is needed, publish it as an external
manifest or detached proof and reference it from `proofs[]`.

## Review Use

For early interop review, a useful report should answer:

- did the implementation produce the expected `allow / attenuate / deny` outcomes
- did it expose the expected execution gate through `should_execute`
- did it emit the expected ordered reason codes and primary reason projection
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
- expected reason code vocabulary and primary reason projection rules
- publication package when comparing independently published implementation reports

If the corpus changes, publish a new report rather than editing the old result in place.
