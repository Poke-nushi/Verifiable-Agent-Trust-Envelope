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
- `reason_codes` - the verifier's machine-readable reason codes in order
- optional `checks` - case-specific check names with `pass: true` when the expected check was satisfied
- optional `limitations`

The example file is:

- `examples/conformance/sut-results-pass.example.json`

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
