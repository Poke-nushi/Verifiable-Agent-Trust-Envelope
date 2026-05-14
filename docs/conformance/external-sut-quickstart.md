# External SUT Quickstart

This quickstart is for implementers who want to compare an external verifier
implementation against the `VATE-AL2-Verifier-Admission-v0.3` corpus.

It is an implementation review aid. It is not certification, endorsement,
production approval, or a general compatibility claim.

## Goal

An external system under test, or SUT, should:

1. Load the committed corpus index.
2. Evaluate each listed case in its own verifier runtime.
3. Emit a SUT result file.
4. Run the repository comparison command.
5. Optionally publish a conformance report, implementation report, and local
   bundle verification report.

Use `compare` for external SUT review. Use `run` only to check this
repository's committed fixtures and reference runner behavior.

If you have questions, a partial result, or a report link to share, use the
public intake thread:

- [issue #2: independent implementation / external SUT review](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2)

The issue was opened during the v0.3.0 review cycle and remains the intake
thread for the current v0.3.x corpus line.

## Inputs

Use these files as the contract surface:

- `conformance/al2-vate-v0.3/corpus.json`
- `conformance/al2-vate-v0.3/conformance-case.schema.json`
- `schemas/sut-result.schema.json`
- `schemas/conformance-report.schema.json`
- `schemas/implementation-report.schema.json`
- `docs/conformance/sut-adapter-contract.md`
- `docs/conformance/report-integrity.md`

The corpus digest in `corpus.json` identifies the exact snapshot. If the corpus
changes, publish a new SUT result rather than editing an old one in place.

## Primary Compare Flow

Prepare your SUT result file first. The passing example is:

```text
examples/conformance/sut-results-pass.example.json
```

Compare your SUT result against the same corpus snapshot:

```bash
python3 scripts/vate_conformance.py compare \
  --corpus-root conformance/al2-vate-v0.3 \
  --sut-results /path/to/your-sut-results.json \
  --report /tmp/vate-sut-compare-report.json
```

The command exits non-zero if cases are missing, duplicated, skipped, errored,
or if expected outcomes, execution gates, reason codes, checks, artifact
requirements, or digest bindings do not match the corpus.

## Optional Repository Fixture Sanity Check

If you want to confirm the committed repository fixtures and reference runner
before comparing an external SUT result, run:

```bash
python3 scripts/vate_conformance.py run \
  --corpus-root conformance/al2-vate-v0.3 \
  --report /tmp/vate-reference-run.json
```

This checks the repository's committed corpus fixtures and reference runner
behavior. It is not an external SUT comparison result.

## SUT Result Requirements

Each result entry must report:

- `case_id`
- `status`
- `outcome`
- `should_execute`
- `reason_codes`
- case-specific `checks[]` when the corpus expects them
- required `artifacts` when the case depends on concrete receipts, AL2 context,
  or JOSE proof-package fixture artifacts

For artifact-backed cases, include digest-bound references. At minimum, those
references carry:

- `uri`
- `media_type`
- `digest.alg` set to `sha-256`
- `digest.value` as lowercase 64-character SHA-256 hex

For AL2 context checks, `artifacts.verification_context[]` also binds the
context fixture back to request, receipt, transaction, runtime, and evidence
sources. For JOSE fixture cases, `artifacts.proof_artifacts[]` records the
proof package, detached payload, and trust bundle artifacts required by the
case.

The JSON Schema checks the portable shape. The `compare` command enforces the
case-dependent artifact requirements and digest matches.

## Artifact Origin Boundary

The passing sample SUT result may point at repository fixture paths because it
is a local contract example. For an independent implementation review, artifact
references should identify SUT-produced artifacts or a controlled publication
package from the SUT maintainer.

`compare` checks the submitted result values against the corpus snapshot. It
does not prove artifact provenance, does not fetch arbitrary remote URIs, and
does not prove that the SUT runtime generated the referenced receipts. A SUT
result that only cites copied repository fixtures can demonstrate result-file
shape, but it is not enough evidence for an independent implementation run.

When publishing review material, include the SUT result, the generated receipt
artifacts or controlled artifact bundle, and stable maintainer-controlled URIs
where reviewers can inspect the submitted artifacts.

## Implementation Report

To also write an implementation report:

```bash
python3 scripts/vate_conformance.py compare \
  --corpus-root conformance/al2-vate-v0.3 \
  --sut-results /path/to/your-sut-results.json \
  --report /tmp/vate-sut-compare-report.json \
  --implementation-report /tmp/vate-sut-implementation-report.json \
  --conformance-report-uri /tmp/vate-sut-compare-report.json \
  --implementation-report-uri /tmp/vate-sut-implementation-report.json
```

When `compare` writes an implementation report, it copies implementation
identity from the SUT result file. If the report is published, use stable URIs
controlled by the implementer instead of `/tmp/` paths.

## Bundle Verification

After generating both reports, verify the local digest chain:

```bash
python3 scripts/vate_conformance.py verify-bundle \
  --corpus-root conformance/al2-vate-v0.3 \
  --sut-results /path/to/your-sut-results.json \
  --conformance-report /tmp/vate-sut-compare-report.json \
  --implementation-report /tmp/vate-sut-implementation-report.json \
  --report /tmp/vate-report-bundle-verification.json
```

`verify-bundle` checks that the local corpus, SUT result, conformance report,
and implementation report digests still line up. It is not a production
signature profile and does not replace JOSE, PKI, Sigstore, signed git tags, or
other external proofs.

## Optional TypeScript Helpers

Package-private TypeScript helpers are available for implementers who want a
small example of digest descriptors, artifact references, SUT result entries,
and A2A metadata shape validation:

- `packages/vate-core-ts/README.md`
- `packages/vate-a2a-ts/README.md`

These helpers are not published SDKs, do not fetch remote artifacts, and do not
perform production JOSE/JCS signature verification.

## Publication Checklist

Before sharing an implementation report, confirm:

- the SUT result uses the same corpus digest as the comparison report;
- skipped or unsupported cases are not hidden;
- artifact references are digest-bound where the corpus requires them;
- publication URIs are stable and controlled by the implementer;
- limitations are explicit;
- the report text does not imply certification, endorsement, production
  readiness, or compatibility with future corpus snapshots.

Share questions, draft results, final report links, or unsupported-case notes in
[issue #2](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2).
Do not paste secrets, credentials, or sensitive production data into the issue.

## Troubleshooting

If comparison fails, check in this order:

1. The SUT result `version`, `profile`, and `corpus.digest`.
2. Missing, duplicate, skipped, or errored case ids.
3. `outcome`, `should_execute`, and ordered `reason_codes`.
4. Case-specific `checks[]`.
5. Required artifact reference presence and digest values.
6. AL2 `verification_context[]` bindings.
7. JOSE fixture `proof_artifacts[]` references.

The comparison report records the failing case and check surface. Fix the SUT
result or implementation behavior, then rerun `compare` against the same corpus
snapshot.
