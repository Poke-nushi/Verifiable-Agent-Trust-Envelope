# VATE v0.3.0 Pre-release Gate

This checklist defines the technical gate before cutting the `v0.3.0` GitHub
pre-release and matching archive.

`v0.3.0` supersedes the archived `v0.2.0` review snapshot for current
main-branch review purposes. It does not mutate the `v0.2.0` Zenodo or GitHub
release artifacts.

It is a release-readiness checklist for a discussion draft. It is not a
certification checklist, production approval process, or compatibility claim.

## Release Boundary

The `v0.3.0` pre-release may be described as:

- an `AL2` verifier admission hardening discussion draft;
- an A2A-shaped metadata review package;
- a conformance review aid for one v0.3 corpus snapshot;
- a reference runner and package-private helper set;
- not production-ready;
- no endorsement, certification, official compatibility, or production approval
  implied.

Do not describe it as:

- certified or certification-ready;
- production-ready or production-approved;
- endorsed by A2A;
- an official A2A extension;
- official compatibility;
- a production JOSE / PKI verifier;
- a published SDK or A2A middleware package;
- a general compatibility proof.

## Scope Freeze

The release candidate is frozen around the v0.3.0 corpus snapshot recorded in
`conformance/al2-vate-v0.3/corpus.json`.

After that snapshot is selected for final external review, keep scope to
release-readiness work only.

Allowed changes:

- typo or broken-link fixes;
- release notes, roadmap, citation, or checklist synchronization;
- verification-command fixes;
- claim-boundary tightening;
- review-package wording that narrows claims.

Do not add after the v0.3.0 snapshot is selected for final external review:

- new corpus cases;
- new schema fields or reason codes;
- new dependencies;
- production JOSE/JCS verification;
- namespace migration;
- certification, trademark, monetization, or business language.

## Required Verification

Run from the repository root on a clean working tree.

```bash
git status --short
git diff --check
python3 -m py_compile scripts/vate_conformance.py scripts/check_repo.py scripts/check_repo_strict.py
python3 scripts/check_repo.py
.venv/bin/python scripts/check_repo_strict.py
```

Repository fixture check:

```bash
python3 scripts/vate_conformance.py run \
  --corpus-root conformance/al2-vate-v0.3 \
  --report /tmp/vate-v0.3.0-gate-run.json
```

External SUT comparison check:

```bash
python3 scripts/vate_conformance.py compare \
  --corpus-root conformance/al2-vate-v0.3 \
  --sut-results examples/conformance/sut-results-pass.example.json \
  --report /tmp/vate-v0.3.0-gate-compare.json
```

Implementation report generation check:

```bash
python3 scripts/vate_conformance.py compare \
  --corpus-root conformance/al2-vate-v0.3 \
  --sut-results examples/conformance/sut-results-pass.example.json \
  --report /tmp/vate-v0.3.0-gate-compare-report.json \
  --implementation-report /tmp/vate-v0.3.0-gate-implementation-report.json \
  --conformance-report-uri /tmp/vate-v0.3.0-gate-compare-report.json \
  --implementation-report-uri /tmp/vate-v0.3.0-gate-implementation-report.json
```

Local report-bundle integrity check:

```bash
python3 scripts/vate_conformance.py verify-bundle \
  --corpus-root conformance/al2-vate-v0.3 \
  --sut-results examples/conformance/sut-results-pass.example.json \
  --conformance-report /tmp/vate-v0.3.0-gate-compare-report.json \
  --implementation-report /tmp/vate-v0.3.0-gate-implementation-report.json \
  --report /tmp/vate-v0.3.0-gate-bundle-verification.json
```

TypeScript helper checks:

```bash
npm ci
npm run ts:check
npm run ts:test
npm audit --audit-level=moderate
```

Claim-boundary scan:

```bash
rg -n -i "certified|certification-ready|production-approved|endorsed by A2A|official A2A extension|official compatibility|production JOSE|production PKI|published SDK|production verifier|general compatibility proof" README.md ROADMAP.md CHANGELOG.md docs conformance examples schemas scripts packages
```

Matches are acceptable only when they appear in explicit limitation language,
historical release documentation, or future-work boundaries.

## Release Artifact Checks

Before the final external review, record:

- current commit SHA;
- `conformance/al2-vate-v0.3/corpus.json` `summary.case_count`;
- generated report paths used for the gate;
- whether `.venv/bin/python scripts/check_repo_strict.py` ran locally;
- `npm audit --audit-level=moderate` result;
- any known residual risk.

## Citation And DOI Gate

Before the `v0.3.0` archive exists:

- keep `CITATION.cff` pointed at the archived `v0.2.0` snapshot;
- cite current main by repository URL and commit SHA;
- state that the `v0.3.0` archive DOI is not yet available.

After the `v0.3.0` archive and version DOI exist, make a separate citation
patch:

- update `CITATION.cff` `version`;
- update `date-released`;
- update `doi`;
- add or update the version DOI identifier description;
- update README citation text.

Run the full release gate again after that citation patch.

## Final External Review Gate

Before creating the GitHub pre-release, request one final external review
against the exact commit intended for release.

The review request should ask for:

- P1 blockers only;
- release-note and citation consistency;
- claim-boundary regressions;
- A2A official-extension or endorsement overclaims;
- production JOSE/PKI or SDK overclaims;
- conformance wording that implies more than one implementation run against one
  corpus snapshot.

Do not cut the tag until that review is complete and all accepted P1/P2 fixes
are committed.
