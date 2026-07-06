# External SUT Starter Template

This directory gives external implementers a small shape template for the
three-case starter path.

It is an implementation review aid. It is not certification, endorsement,
production approval, or a general compatibility claim.

## Files

- `starter-sut-result.template.json` - a three-case SUT result shape for:
  - `allow-valid-admission`
  - `attenuate-max-amount`
  - `deny-digest-mismatch-before-policy`

The template deliberately points at repository fixture artifacts so reviewers
can inspect the expected SUT result shape and run the comparison command. A real
external submission should replace the implementation identity, artifact URIs,
artifact digests, and any generated receipt or context artifacts with material
controlled by the implementation maintainer.

Do not submit the template unchanged as independent implementation evidence.

## Compare The Template Shape

From the repository root:

```bash
python3 scripts/vate_conformance.py compare \
  --corpus-root conformance/al2-vate-v0.3 \
  --sut-results examples/external-sut-template/starter-sut-result.template.json \
  --report /tmp/vate-template-compare-report.json \
  --implementation-report /tmp/vate-template-implementation-report.json \
  --conformance-report-uri /tmp/vate-template-compare-report.json \
  --implementation-report-uri /tmp/vate-template-implementation-report.json
```

The command exits non-zero because the template covers only three cases from the
72-case corpus. The expected landing is:

```text
3 passed / 69 failed / 0 skipped / 72 total
```

The 69 failures should be `sut result missing`.

## Verify The Local Bundle

After generating the reports:

```bash
python3 scripts/vate_conformance.py verify-bundle \
  --corpus-root conformance/al2-vate-v0.3 \
  --sut-results examples/external-sut-template/starter-sut-result.template.json \
  --conformance-report /tmp/vate-template-compare-report.json \
  --implementation-report /tmp/vate-template-implementation-report.json \
  --report /tmp/vate-template-bundle-verification.json
```

`verify-bundle` checks the local digest chain among the corpus, SUT result,
compare report, and implementation report. It does not prove production
provenance, signatures, JOSE, PKI, Sigstore, or controlled publication origin.

## Before Sharing A Real Result

Replace at least:

- `implementation.name`, `type`, `version`, `language`, `source`, and `commit`
- `generated_at`
- `artifacts.*.uri`
- `artifacts.*.digest.value`
- any `verification_context[]` entries and `context_bindings[]` values that your
  implementation generates or controls
- report publication URIs passed through `--conformance-report-uri` and
  `--implementation-report-uri`

Keep the claim narrow: one implementation run against one corpus snapshot. A
partial starter result is useful, but it is not a passing full-corpus claim.
