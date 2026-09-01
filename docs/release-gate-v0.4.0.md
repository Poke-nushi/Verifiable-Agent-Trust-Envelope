# VATE v0.4.0 Completed Technical Release Gate

## Status

This records the local technical gate completed before the `v0.4.0` GitHub
discussion-draft pre-release. Passing this gate did not itself create a GitHub
tag, release, Zenodo record, certification, endorsement, or production
approval.

## Fixed Release Boundary

- repository release: GitHub discussion-draft pre-release `v0.4.0`
- semantic profile: `VATE-AL2-Verifier-Admission-v0.3`
- active conformance artifact line: `2026-09`
- corpus: 76 cases / 216 artifacts
- corpus digest:
  `sha-256:b2a281e372b2e1d6b49be219c715fa69c0b2be237d29a6e1f0dda9c0659b6130`
- Zenodo archive and exact `v0.4.0` version DOI at gate time: pending
- latest historical Zenodo archive with an exact version DOI at gate time:
  `v0.3.2`

## Completed Repository Checks

```bash
python3 -m py_compile \
  scripts/vate_conformance.py \
  scripts/check_repo.py \
  scripts/check_repo_strict.py \
  scripts/check_pulse_external_sut_starter.py
python3 scripts/check_repo.py --require-full-history
.venv/bin/python scripts/check_repo_strict.py
```

These commands completed successfully. The full-history check reloaded the
historical VATE source commit pinned by the Pulse starter and passed all 33
starter-validator negative probes. It did not replay the frozen Pulse verifier;
that remains a separate explicit gate which requires supplying a Pulse checkout
with `--pulse-repo` to `scripts/check_pulse_external_sut_starter.py`.

## Completed Conformance Checks

```bash
python3 scripts/vate_conformance.py run \
  --corpus-root conformance/al2-vate-v0.3 \
  --report /tmp/vate-v0.4.0-run.json

python3 scripts/vate_conformance.py compare \
  --corpus-root conformance/al2-vate-v0.3 \
  --sut-results examples/conformance/sut-results-pass.example.json \
  --report /tmp/vate-v0.4.0-compare.json \
  --implementation-report /tmp/vate-v0.4.0-implementation.json \
  --conformance-report-uri /tmp/vate-v0.4.0-compare.json \
  --implementation-report-uri /tmp/vate-v0.4.0-implementation.json

python3 scripts/vate_conformance.py verify-bundle \
  --corpus-root conformance/al2-vate-v0.3 \
  --sut-results examples/conformance/sut-results-pass.example.json \
  --conformance-report /tmp/vate-v0.4.0-compare.json \
  --implementation-report /tmp/vate-v0.4.0-implementation.json \
  --report /tmp/vate-v0.4.0-bundle.json
```

The generated reports used the `2026-09` versions and the fixed release corpus
digest.

## Completed Historical And Archive Checks

- A v0.3.2-generated `2026-07` SUT result failed current
  `schemas/sut-result.schema.json` validation as intended.
- The same historical artifact remained checkable in its exact v0.3.2 source
  snapshot.
- A source archive produced without `.git` passed
  `python3 scripts/check_repo.py`.
- That archive run explicitly reported the history-dependent Pulse starter gate
  as not run and did not report a false full-history pass or frozen Pulse
  verifier replay.

## Completed JavaScript Checks

```bash
npm ci
npm run ts:check
npm run ts:test
npm audit --audit-level=moderate
```

The lockfile contained only the approved transitive maintenance updates. No new
direct dependency is part of this pre-release.

## Completed Final Review

- `git diff --check` passes.
- tracked changes are limited to the v0.4.0 release scope.
- schema, runner, examples, corpus index, and docs agree on `2026-09`.
- historical `2026-07` evidence and archived release notes are unchanged.
- README and citation metadata identify the v0.4.0 GitHub pre-release without
  asserting an unissued Zenodo DOI at gate time.
- claim language remains one implementation run against one corpus snapshot,
  not production readiness, certification, endorsement, or general
  compatibility.

The statements above record the pre-publication gate as it was executed.

## Publication Follow-Up

Publication occurred separately after the technical gate completed:

- GitHub tag and discussion-draft pre-release `v0.4.0` resolve to
  `cc072ef86f54791213a3e603a65b2f24f64b1b6d`.
- Zenodo record `22218860` was published on September 1, 2026 with exact version
  DOI `10.5281/zenodo.22218860`.
- The downloaded Zenodo ZIP matched all 503 tracked files from the tag, and its
  MD5 matched the value published by Zenodo.

These publication records do not change the discussion-draft claim boundary or
imply production readiness, certification, endorsement, production approval,
or general compatibility.
