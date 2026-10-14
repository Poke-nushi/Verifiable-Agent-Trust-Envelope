# VATE v0.5.0 Technical Release Gate

This gate covers the execution-evidence and recipient-review discussion-draft
pre-release. GitHub publication and Zenodo archival are separate observable
steps from the technical checks below.

## Release Boundary

- Release tag: `v0.5.0`
- Semantic profile: `VATE-AL2-Verifier-Admission-v0.3`
- Conformance artifact line: `2026-09`
- Corpus: 76 cases / 217 manifest artifacts
- Corpus digest:
  `sha-256:9f16ca68c32e57ee79a0c4080310fe90b63f337bbe827cad6b1017acc2b1a14e`
- Change class: added reference interfaces and examples, bounded correctness
  fixes, reproduction/reuse records and development-dependency maintenance
- Existing Zenodo concept DOI: `10.5281/zenodo.19839768`
- Exact v0.5.0 Zenodo version DOI:
  [10.5281/zenodo.23378498](https://doi.org/10.5281/zenodo.23378498)

The [release notes](release-notes/v0.5.0.md) identify the included paths and
their evidence boundaries. This release does not rename the semantic profile
or artifact family. Historical runs retain their own source and corpus digest.

## Verification Procedure

Run the repository's existing checks with its pinned development dependencies:

```bash
python3 -m py_compile scripts/vate_conformance.py scripts/check_repo.py scripts/check_repo_strict.py
python3 reference/quickstart-demo/run_demo.py
python3 scripts/check_repo.py --require-full-history
python3 scripts/check_repo_strict.py
npm ci --ignore-scripts
npm run ts:check
npm run ts:test
npm audit --audit-level=moderate
git diff --check
```

The full-history check includes the historical Pulse starter validator probes;
it does not rerun the external Pulse verifier. Run `vate_conformance.py run`,
sample `compare` with an implementation report, and `verify-bundle` against the
corpus above. Recompute each manifest file's raw SHA-256 and the corpus digest.

The example commands and unit suites are defined in
[CI](../.github/workflows/ci.yml). They cover execution evidence, receipt
linkage, offline S3 assessment, the recipient API, the NENRIN crosswalk, and
detached signatures/issuer authority. CI runs Python 3.10, 3.12 and 3.14 on
Ubuntu and Python 3.14 on macOS; source-archive lanes repeat the relevant paths
without `.git` or private working notes.

## Recorded Local Results

Checks completed on October 15, 2026 JST (October 14 UTC) using macOS arm64,
Python 3.14.8, OpenSSL 3.6.2 and Node.js 22.16.0:

| Check | Result |
| --- | --- |
| Python compilation, quickstart, full-history repository check, strict schemas | Passed |
| Raw manifest files and corpus digest | 217 files matched; digest matched |
| Reference fixture run and committed sample comparison | 76 / 76 each |
| Local report-bundle verification | 54 / 54 |
| Execution-evidence tests | 112 passed |
| Receipt-linkage tests | 42 passed |
| S3 offline acceptance checks | 111 passed |
| S3 native-fixture tests | 6 passed |
| S3 CLI tests | 18 passed; 1 filesystem-specific skip |
| Recipient API tests and vector replay | 40 tests passed; vectors matched |
| Signature/authority tests and controls | 42 tests passed; 10 controls matched |
| NENRIN crosswalk tests | 80 passed |
| TypeScript check and tests | Passed; 47 tests in 6 files |
| Locked dependency install without lifecycle scripts; dependency audit | Passed; 0 reported vulnerabilities at check time |
| CFF 1.2.0 schema, tag-time DOI separation and release-document links | Passed |

The skipped S3 CLI case needs distinct directories whose names differ only in
case; the local filesystem treats them as the same directory. The Ubuntu CI
lane exercises that case on a case-sensitive filesystem.

A Git source archive containing 836 public source files passed the repository
and strict-schema checks. Its execution demo, receipt examples, four S3
captures, recipient vectors, ten signature controls, and saved/replayed-VATE
crosswalk comparisons also passed without `.git` or private working notes.
The archive checker correctly reports that historical Git-object replay is
unavailable; that check passed in the full-history checkout above.

These checks did not make a new S3 capture or rerun the NENRIN or Pulse native
verifiers. Saved native reports and historical external run records keep their
original provenance.

## Publication Verification

The [GitHub pre-release](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/releases/tag/v0.5.0)
was published on October 14, 2026 UTC (October 15 JST) from source commit
`253aaa13f232823c982122fde5abb4e4b8d410b8` and annotated tag object
`d6babdda408958e2c047e10faae2ef4b3dec3cc5`.
[PR CI](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/actions/runs/38638120491)
and [main CI](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/actions/runs/38639338641)
each passed all five jobs. The case-sensitive S3 CLI check passed in all three
Ubuntu Python lanes, in both checkout and source-archive runs.

The [Zenodo record](https://zenodo.org/records/23378498) has version `v0.5.0`
and belongs to the existing concept DOI `10.5281/zenodo.19839768`. At publication
verification, the series contained eight versions and exactly one v0.5.0;
the previous seven versions retained their identifiers and file checksums.
The separate technical-report record was unchanged.

The downloaded GitHub and Zenodo ZIPs were byte-identical (2,547,108 bytes):

- SHA-256: `e1bfb3321e0be535bc5637419557059920972a9867847b0de95c80be57484a45`
- Zenodo MD5: `b1fce1f534842d6d54676516aeded110`

All 836 source file paths and bytes matched the reviewed Git tree
`7b7217ccfc7d658e7840d3d2323b579140de74e5`. The ZIP did not include Unix file-mode
metadata; this comparison establishes path and content equality.

The issued DOI was added to current citation metadata only after these checks.
The tag and its archived files retain their original tag-time citation text.

## Archive and DOI Sequence

1. Complete the technical checks and review the final source before tagging.
2. Keep the new tag's `CITATION.cff` free of a previous version's exact DOI.
   Retain the concept DOI as the release-series identifier.
3. Publish the GitHub discussion-draft pre-release from the checked tag. The
   configured Zenodo integration processes the release event.
4. Read back the new Zenodo record. Check its version, author, license,
   existing concept DOI, file checksum and source contents against the tag.
   Confirm that the existing series contains exactly one v0.5.0 record and
   that previous versions retain their identifiers and file checksums.
   A webhook response or DOI allocation alone does not verify those files.
5. Only after that check, add the issued version DOI to the current citation
   metadata and release-page citation section in a separate change. Preserve
   the tag and its original source archive, including the tag-time pending text.

An interrupted archive operation must be investigated against the existing
release/series before retrying. Do not create a duplicate version or a new
series merely because a response is delayed. The technical report has its own
record and DOI; this software release does not revise it.

The checks establish the stated fixture, comparison, local report-integrity
and example behavior. They do not establish new independent native execution
or production readiness.
