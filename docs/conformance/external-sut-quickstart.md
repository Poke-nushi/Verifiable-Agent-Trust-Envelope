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

If you are not ready to write a full adapter, start with the
[one-hour external SUT or corpus review request](external-sut-ask-1-hour.md).
It is intended for lightweight corpus review, unclear-case reports, and draft
or partial SUT result attempts.

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

That example uses `artifact_mode: corpus-fixture-validation`. For cases with
`sut_inputs[]`, its `artifacts.input_artifacts[]` contains only those explicit
inputs. Status context checks always use this explicit input lane; non-status
legacy cases retain their case-derived artifact references. Digest
matching does not establish that an external SUT evaluated the bytes, and none
of these references are claimed as SUT-generated receipts.

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
- required `artifacts` for explicit `sut_inputs[]` or legacy-derived inputs
- `artifact_mode: generated-receipts` plus `generated_artifacts` when claiming
  that the SUT produced its own admission or post-execution receipt bytes

For artifact-backed cases, include digest-bound references. At minimum, those
references carry:

- `uri`
- `media_type`
- `digest.alg` set to `sha-256`
- `digest.value` as lowercase 64-character SHA-256 hex

For a case with `sut_inputs[]`, use `artifacts.input_artifacts[]` and copy the
case's exact `artifact`, `role`, and `media_type` values. Set `uri` to the
corpus-relative path referenced by the named case artifact. Do not include an
unlisted expected receipt or any other sibling field under `artifacts`. Status
input references and their digest descriptors do not accept extension fields.
Status inputs contain observed facts only; expected VATE reason codes stay in
the case expectation and SUT output. A status case without `sut_inputs[]` is
invalid and does not fall back to the legacy lane. For legacy AL2 context checks,
`artifacts.verification_context[]` also binds the
context fixture back to request, receipt, transaction, runtime, and evidence
sources. For JOSE fixture cases, `artifacts.proof_artifacts[]` records the
proof package, detached payload, and trust bundle artifacts required by the
case.

The JSON Schema checks the portable shape. The `compare` command enforces the
case-dependent artifact requirements and digest matches.
For the digest-basis vocabulary used by raw artifact references, embedded
evidence-object bindings, corpus digests, and report-bundle checks, see
`docs/conformance/digest-basis.md`.

## Starter Case Check Names

For `checks[]`, `compare` matches entries by exact `name` against the selected
case's `expected.checks[]`. A result with different names may describe a
reasonable local check, but it will not satisfy the corpus comparison contract.

For the three starter cases in the one-hour review path, the required check
names are:

- `allow-valid-admission`
  - `decision.outcome`
  - `evidence.verification.result`
  - `policy.policy_version`
- `attenuate-max-amount`
  - `attenuation.original_request_hash`
  - `attenuation.effective_request_hash`
  - `attenuation.changes[0].path`
  - `a2a_metadata.admission_receipt.digest`
  - `a2a_metadata.policy_snapshot.digest`
- `deny-digest-mismatch-before-policy`
  - `decision.outcome`
  - `evidence.verification.failure_reason`
  - `policy.policy_version`

Use the case file's `expected.checks[]` as the source of truth for any other
case.

## Artifact Roles And Origin Boundary

Keep `results[].artifacts` limited to exact corpus artifacts submitted as SUT
inputs. `sut_inputs[]` is authoritative when present; an expected receipt not
listed there is comparison material, not input. Those references remain
byte-identical fixed-vector references even for an independent implementation.
Their URI and media type must also match the case declaration. Do not replace
them with a newly generated receipt digest or add receipt aliases beside
`input_artifacts`. Digest matching alone does not prove that the SUT read or
evaluated the referenced bytes.

When the SUT issues receipt output, set `artifact_mode` to
`generated-receipts` and add `results[].generated_artifacts`. Each generated
reference needs the normal `uri`, `media_type`, and digest fields. If `uri` is a
remote publication URL, also provide a relative `local_path` under the directory
that contains the SUT result so `compare` can read the bytes without fetching
the network. Absolute paths, parent traversal, symlink escapes, and files over
8 MiB are rejected. Generated admission and post-execution
references must use `application/vate-admission-receipt+json` and
`application/vate-post-execution-receipt+json`, respectively.

In generated mode, `compare` verifies the generated file's raw digest, selected
schema-aligned receipt shape checks, and a bounded semantic projection. Independent
receipt ids, verifier or issuer identity, proof packaging, human-readable
summary, and concrete generated admission links may differ where documented.
The admission-link relationship must preserve the case's intended match or
mismatch, and the post-execution `admission.uri` must equal the submitted
generated admission artifact `uri`. Decision visibility fields, ordered reason codes, fixed case clock,
request/evidence/policy/attenuation semantics, and post-execution linkage must
still match the case. Extra or unknown generated receipt roles are rejected.

A top-level `generated-receipts` default cannot be downgraded per case. To mix
the modes, keep the top-level default at `corpus-fixture-validation` and opt
selected cases into `generated-receipts`. Compare and implementation reports
record each effective case mode and aggregate mode counts.

A result that stays in `corpus-fixture-validation` shows only that the submitted
result and corpus fixture digests matched the fixed-vector comparison contract.
It does not establish that the SUT read or evaluated those bytes. A
generated-receipts pass checks additional submitted output bytes, but still does
not prove artifact provenance, controlled publication origin, source
independence, or production signature validation.

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
other external proofs. For `generated-receipts` results it also rereads the
local `generated_artifacts` and reruns their raw-digest, bounded-semantic, and
linkage checks.

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
