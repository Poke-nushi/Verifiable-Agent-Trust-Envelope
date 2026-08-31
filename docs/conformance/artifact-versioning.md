# Conformance Artifact Versioning

## Status

This note defines how date-stamped conformance artifact identifiers are used
for the v0.3 AL2 discussion-draft profile.

## Current Decision

The active conformance artifact line on `main` is **`2026-09`**.

Four identifiers remain deliberately separate:

- repository release candidate: `v0.4.0`
- AL2 profile: `VATE-AL2-Verifier-Admission-v0.3`
- active machine-readable artifact line: `2026-09`
- exact corpus snapshot: the manifest digest in
  `conformance/al2-vate-v0.3/corpus.json` and generated reports

The date label identifies a compatibility line for machine-readable contracts.
It is not the publication date, not the date on which a fixture was edited,
and not a production-readiness claim. Deterministic scenario timestamps such
as `2026-07-01T00:00:00Z` may remain in current fixtures because they are test
inputs, not artifact-line identifiers.

The `2026-09` line supersedes the active `2026-07` exchange contract on
`main`. The profile identifier remains v0.3 because the verifier-admission
semantics and claim boundary have not been broadened. The artifact line changes
because the SUT input contract, generated-receipt mode, status evidence
bindings, report formats, and bundle checks are materially different from the
archived v0.3.2 contract.

## Historical `2026-07` Validation Lane

The `2026-07` line remains the historical contract for the archived v0.3.2
snapshot and evidence produced against it. Do not relabel old Pulse, AlgoVoi,
AEE, release, DOI, tag, or digest records as `2026-09`.

Validate a historical `2026-07` result with the exact recorded tag or commit
and the schemas from that source snapshot. For the archived public anchor:

```bash
git worktree add --detach ../vate-v0.3.2 v0.3.2
cd ../vate-v0.3.2
python3 scripts/check_repo.py
python3 scripts/vate_conformance.py compare \
  --corpus-root conformance/al2-vate-v0.3 \
  --sut-results /path/to/recorded-2026-07-sut-results.json \
  --report /tmp/vate-v0.3.2-compare.json
```

The current `2026-09` schemas are not a migration tool for historical
artifacts. They intentionally reject a `2026-07` result presented as a current
artifact. This prevents an old result from being mistaken for evidence against
the current corpus contract.

The repository's Pulse starter is a special historical fixed-pin lane. In a
full-history checkout, its checker replays the recorded VATE commit and runs
the historical negative probes. In a source archive without `.git`, the
repository sanity check verifies the starter's committed 12-path closure but
reports the history-dependent replay as not run.

## What The Active Label Covers

The `2026-09` label is used by current:

- conformance corpus, SUT-result, conformance-report, implementation-report,
  and report-bundle contracts
- status-context, trust-bundle, evidence-vocabulary, and JOSE fixture contracts
- active examples and generated reports
- the AL2 admission interop profile note for the current artifact line

The label does not replace the profile identifier, release version, exact
commit, or corpus manifest digest.

## When To Change It

Create a new artifact line when a machine-readable exchange contract becomes
incompatible, including:

- incompatible report or SUT-result schema changes
- materially different required input or generated-artifact bindings
- a superseding corpus contract with changed expected behavior
- profile behavior changes that alter outcomes, reason codes, or required
  evidence surfaces

Do not change the line for editorial cleanup, documentation-only clarification,
or fixture hardening that preserves the exchange contract.

## Claim Boundary

A valid `2026-09` result means only that one submitted implementation result was
evaluated against one reported corpus snapshot under the stated comparison
rules. It does not imply production readiness, certification, endorsement,
security-review completion, general compatibility, or compatibility with a
future artifact line.
