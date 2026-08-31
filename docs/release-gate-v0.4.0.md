# VATE v0.4.0 Release Candidate Gate

## Status

This is the local technical gate for the v0.4.0 release candidate. Passing it
prepares a reviewable candidate; it does not create a GitHub release, tag,
Zenodo record, certification, endorsement, or production approval.

## Fixed Candidate Boundary

- repository release candidate: `v0.4.0`
- semantic profile: `VATE-AL2-Verifier-Admission-v0.3`
- active conformance artifact line: `2026-09`
- corpus: 76 cases / 216 artifacts
- corpus digest:
  `sha-256:b2a281e372b2e1d6b49be219c715fa69c0b2be237d29a6e1f0dda9c0659b6130`
- archived public review anchor: `v0.3.2` until an actual release and archive
  are published

## Required Repository Checks

```bash
python3 -m py_compile \
  scripts/vate_conformance.py \
  scripts/check_repo.py \
  scripts/check_repo_strict.py \
  scripts/check_pulse_external_sut_starter.py
python3 scripts/check_repo.py --require-full-history
.venv/bin/python scripts/check_repo_strict.py
```

The full-history check MUST reload the historical VATE source commit pinned by
the Pulse starter and pass all 33 starter-validator negative probes. It does
not replay the frozen Pulse verifier; that is a separate explicit gate which
requires supplying a Pulse checkout with `--pulse-repo` to
`scripts/check_pulse_external_sut_starter.py`.

## Required Conformance Checks

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

Generated reports MUST use the `2026-09` versions and the fixed candidate
corpus digest.

## Historical And Archive Checks

- A v0.3.2-generated `2026-07` SUT result MUST fail current
  `schemas/sut-result.schema.json` validation.
- The same historical artifact remains checkable in its exact v0.3.2 source
  snapshot.
- A source archive produced without `.git` MUST pass
  `python3 scripts/check_repo.py`.
- That archive run MUST explicitly report the history-dependent Pulse starter
  gate as not run; it must not report a false full-history pass or a frozen
  Pulse verifier replay.

## JavaScript Checks

```bash
npm ci
npm run ts:check
npm run ts:test
npm audit --audit-level=moderate
```

The lockfile may contain only the approved transitive maintenance updates. No
new direct dependency is part of this candidate.

## Final Review

- `git diff --check` passes.
- tracked changes are limited to the release-candidate scope.
- schema, runner, examples, corpus index, and docs agree on `2026-09`.
- historical `2026-07` evidence and archived release notes are unchanged.
- the README archived anchor and citation/DOI data remain v0.3.2 before release.
- claim language remains one implementation run against one corpus snapshot,
  not production readiness, certification, endorsement, or general
  compatibility.

The candidate remains unpublished until a separate owner decision authorizes
commit, push, tag, release, and any Zenodo update.
