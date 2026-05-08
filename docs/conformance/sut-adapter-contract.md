# SUT Adapter Contract

## Status

This note defines the result contract for comparing an external system under test (SUT) against the `VATE AL2 Verifier Admission v0.2` corpus.

It does not require an implementation to use Python.
The Python runner is only a comparison tool for the published corpus expectations.

## Goal

An external verifier should be able to:

1. Load `conformance/al2-vate-v0.2/corpus.json`.
2. Execute each listed case in its own runtime.
3. Emit a SUT result file matching `schemas/sut-result.schema.json`.
4. Compare that file against the corpus with the reference runner.
5. Publish the comparison report and, optionally, an implementation report.

This keeps the conformance surface language-neutral while preserving exact expected outcomes and reason codes.

## SUT Result Shape

A SUT result file records one implementation run against one corpus snapshot.
The `2026-07` suffix in the current `version` value identifies the target
interop artifact line, not the date the SUT result was generated. The exact
corpus snapshot is identified by `corpus.digest`. See
`docs/conformance/artifact-versioning.md`.

Required top-level fields:

- `version` - currently `vate-sut-results-2026-07`
- `profile` - currently `VATE-AL2-Verifier-Admission-v0.2`
- `generated_at`
- `implementation`
- `corpus.digest`
- `results`

Each result entry represents one corpus case:

- `case_id`
- `status` - `completed`, `skipped`, or `error`
- `outcome` - the verifier's observed outcome
- `should_execute` - whether the verifier result permits immediate execution
- `reason_codes` - the verifier's machine-readable reason codes in order; the
  comparison report derives `actual_primary_reason_code` from the first
  non-terminal code
- optional `checks` - case-specific check names with `pass: true` when the expected check was satisfied
- required `artifacts` when the corpus case depends on receipt or context artifacts
- optional `limitations`

The example file is:

- `examples/conformance/sut-results-pass.example.json`

## Artifact References

SUT results must be artifact-backed for cases that depend on concrete receipts,
AL2 execution context, or JOSE proof-package inputs. This keeps the comparison
report from becoming a bare assertion detached from the evidence the
implementation evaluated.

When the corpus case lists an `admission_receipt`, the result entry must include
`artifacts.admission_receipt`. When it lists a `post_execution_receipt`, the
result entry must include `artifacts.post_execution_receipt`.

Receipt artifact references require:

- `uri`
- `media_type`
- `digest.alg` set to `sha-256`
- `digest.value` as lowercase SHA-256 hex

When the corpus case includes `al2_context_checks`, the result entry must
include `artifacts.verification_context[]` entries with:

- `kind` - the context check kind, such as `binding`, `freshness`, or `replay`
- `case_artifact` - the corpus artifact key used for the context check
- `uri`
- `digest.alg` set to `sha-256`
- `digest.value` as lowercase SHA-256 hex
- `context_bindings[]` - the receipt, request, transaction, runtime, and
  evidence objects that the context check was evaluated against

Each `context_bindings[]` entry names a `role` and `source_artifact`.
Artifact roles such as `admission_receipt` and `admission_request` carry the raw
artifact SHA-256 digest. Value roles such as `transaction_id` and `runtime`
carry the source path and observed value. Evidence roles carry the source path,
evidence type, and canonical JSON digest of the evidence object embedded in the
source artifact. This lets `compare` detect SUT reports that cite a context
fixture without binding it back to the request, receipt, transaction, runtime,
or evidence it was supposed to validate.

When the corpus case includes `jose_checks`, the result entry must include
`artifacts.proof_artifacts[]` entries for each referenced `proof_package`,
`detached_payload`, and `trust_bundle` artifact:

- `kind` - one of `jose_proof_package`, `jose_detached_payload`, or
  `jose_trust_bundle`
- `case_artifact` - the corpus artifact key used by the JOSE check
- `uri`
- `media_type`
- `digest.alg` set to `sha-256`
- `digest.value` as lowercase SHA-256 hex

The current comparison command validates the presence and descriptor shape of
these artifact references, and checks their SHA-256 digest values against the
corpus artifacts required by the case. It does not fetch arbitrary remote URIs
or verify external signatures. For local report-bundle digest-chain
verification, use `scripts/vate_conformance.py verify-bundle` as documented in
`docs/conformance/report-integrity.md`.

The JSON Schema validates the portable result shape only. It does not know which
artifacts are required by a particular corpus case and, by itself, does not prove
artifact-backed compliance. Use `compare` against the exact corpus snapshot to
enforce case-dependent artifact requirements and digest matches.

## Compare Command

```bash
python3 scripts/vate_conformance.py compare \
  --corpus-root conformance/al2-vate-v0.2 \
  --sut-results examples/conformance/sut-results-pass.example.json \
  --report /tmp/vate-sut-compare-report.json
```

The command writes a normal VATE conformance report shape:

- `schemas/conformance-report.schema.json`

To also write an implementation report for the external SUT result, add
`--implementation-report`. The implementation identity is copied from the SUT
result file, and optional publication metadata can be supplied with
`--conformance-report-uri`, `--implementation-report-uri`,
`--publication-controlled-origin`, and `--publication-immutability`.

It exits non-zero when:

- the SUT result file has the wrong version or profile
- the SUT result corpus digest does not match the current corpus
- a case is missing
- a case id is duplicated or unknown
- a case is skipped or errored
- outcome, `should_execute`, reason codes, or required checks do not match the corpus expectation

## Check Semantics

`results[].checks[].pass` means the implementation satisfied the expected check named by the corpus case.

For example, if a negative case says:

```json
{ "name": "decision.outcome", "expected": "fail" }
```

then a SUT result should report:

```json
{ "name": "decision.outcome", "pass": true }
```

The SUT does not need to reproduce the reference runner's internal boolean model.
It only needs to state whether the named expected check was satisfied.

`should_execute` is separate from `outcome`. A case can have
`outcome: "attenuate"` while `should_execute: false` when the attenuation
requires a fresh permit before execution can proceed.

For post-execution cases, `should_execute` still refers to the pre-execution
admission gate. It does not mean the post-execution receipt or observed side
effect is valid.

The SUT result file is an input to comparison, not a standalone proof package.
Reviewers should inspect referenced artifacts and implementation reports when a
result is used outside local development.

## Claim Boundary

Passing `compare` means the SUT result file matched one corpus snapshot.

It does not imply:

- production readiness
- independent security review
- endorsement
- compatibility with future corpus snapshots
