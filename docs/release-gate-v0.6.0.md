# v0.6.0 Technical Release Gate

This gate covers the receiving, retained assessment and runtime-key revocation
discussion-draft pre-release. GitHub publication, Zenodo archival and website
delivery are separate observable steps.

## Source and Scope

- Previous archived version: `v0.5.0`, source
  `253aaa13f232823c982122fde5abb4e4b8d410b8`.
- Implementation baseline: `7957c658c7131f69da41981a4112f9a39746498c`.
- Semantic profile: `VATE-AL2-Verifier-Admission-v0.3`.
- Artifact line: `2026-09`.
- Corpus: 76 cases / 217 manifest artifacts;
  `sha-256:9f16ca68c32e57ee79a0c4080310fe90b63f337bbe827cad6b1017acc2b1a14e`.
- Existing software-series DOI: `10.5281/zenodo.19839768`.

The release collects Required Record Review, Recipient Inbox and package intake,
the MUSUBI set2 sample and fixed experiment records, foreign acceptance and
bounded retention, and the standalone post-admission revocation sample.
Release preparation changes documentation and citation metadata. It does not
change runtime code, schema semantics, the corpus or historical source pins.

## Verification

The implementation baseline passed
[all 19 main CI jobs](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/actions/runs/40085600350).
Local candidate checks on October 25, 2026 JST passed repository validation
with the full-history gate, strict schema validation, corpus `run`, example
`compare`, implementation-report generation and `verify-bundle`, TypeScript
type checking and tests, and relative documentation-link checks. Repository
and strict-schema checks also passed from a separate 1,247-file source copy
without Git metadata or private notes. The archive check skips Git-history
replay; the checkout check covers that gate.

Independent technical and reader reviews are complete. The final PR revision
must pass CI before tagging. Publication verification will record the exact
tag, archive contents and DOI; a prepared document is not a published archive.

The workflow covers checkout and source-archive paths, TypeScript checks,
Linux/macOS execution examples and the new Linux Python 3.11–3.14 receiving and
revocation checks. The MUSUBI receiver tests use fixed native output where
documented; they are not Linux execution of the macOS native sandbox.
The local [revocation validation](../reference/post-admission-revocation-sample/VALIDATION.md)
and [acceptance validation](../reference/musubi-set2-receiving-sample/ACCEPTANCE-VALIDATION.md)
retain the dates and environments of their original runs.

`run` checks fixtures and reference-runner behavior. `compare` checks a submitted
result against one corpus snapshot. `verify-bundle` checks the local report
digest chain. None is production approval or a general compatibility result.

## Archive and DOI Sequence

1. Complete the source checks and independent review. Confirm the reviewed
   revision is the one passing CI.
2. Keep the new tag's `CITATION.cff` free of the previous version's exact DOI;
   retain the concept DOI for the existing software series.
3. Publish an annotated `v0.6.0` tag and GitHub discussion-draft pre-release
   from the reviewed source. The configured release-event integration submits
   the source to Zenodo.
4. Read back the new record. Verify the version, creator, license, credits,
   existing concept DOI, archive checksum and all source paths/bytes. Confirm
   that exactly one new version exists and previous records retain their
   identifiers and files. A DOI allocation alone does not establish file
   identity.
5. After verification, add the issued version DOI to current citation metadata
   and the release-page citation section in a separate change. Preserve the
   tag and its original archive, including its tag-time citation text.
6. Update the website's release/DOI information and links to the new examples,
   preserving the fixed source identities of historical experiment records.

Investigate an interrupted archive against the existing release and series
before retrying; do not create a duplicate deposit. The technical report is a
separate record and is not revised by this software release.
