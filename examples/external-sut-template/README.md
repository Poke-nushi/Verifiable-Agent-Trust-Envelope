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

The template deliberately uses `artifact_mode: corpus-fixture-validation` and
points `artifacts` at repository fixtures. Those references identify the exact
fixed vectors submitted as SUT inputs, so a real submission must keep their
corpus digests rather than replacing them with generated receipt digests. The
digest match does not establish runtime evaluation.

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
76-case corpus. The expected landing is:

```text
3 passed / 73 failed / 0 skipped / 76 total
```

The 73 failures should be `sut result missing`.

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
- report publication URIs passed through `--conformance-report-uri` and
  `--implementation-report-uri`

Keep `artifacts`, `verification_context[]`, and their binding digests matched to
the exact corpus fixtures submitted as evaluated inputs. That digest match does
not itself establish runtime evaluation. If the SUT produces its own receipt bytes:

- set the top-level or per-case `artifact_mode` to `generated-receipts`;
- add `generated_artifacts.admission_receipt` and, for linkage cases,
  `generated_artifacts.post_execution_receipt`;
- use a maintainer-controlled publication `uri` plus a locally readable
  relative `local_path` contained by the SUT result directory; and
- publish those generated files with the result bundle.

Keep the claim narrow: one implementation run against one corpus snapshot. A
partial starter result is useful, but it is not a passing full-corpus claim.
