# v0.7.0 release verification

This record identifies the source, fixtures and checks for the v0.7.0
discussion-draft pre-release. The [release notes](release-notes/v0.7.0.md)
include a runnable example and the Python API migration.

## Reviewed source

The implementation commit is `fe5592e217c8c8db5d58497940e3ca6d571d748c`.
It contains the 1,968 files checked before release preparation. The previous
software tag, `v0.6.0`, points to `b7e4081949b4b8b147bebbcf7ce92791107ac1d2`.
The semantic profile is `VATE-AL2-Verifier-Admission-v0.3` and the
machine-readable artifact line is `2026-09`.

| Fixture set | Cases | Manifest entries | Corpus SHA-256 |
| --- | ---: | ---: | --- |
| AL2 verifier admission | 76 | 217 | `1bd35f100ccc6584ddfdf59122ba377606dbe929b219099f0fa1008b6aa0f5f1` |
| Purchase request binding | 4 | 26 | `48859e14eb7d61c0fc14b038562cd2965dcfb993752210309348ef6d3b0ebe93` |

The AL2 digest changed since v0.6.0. Earlier results remain associated with
their recorded tag and digest. In this version the AL2 set requires zero
purchase request-binding checks and the separate set requires four.

## Local checks

The implementation passed the full-history repository and strict schema
checks. Both fixture sets passed `run`, comparison with the supplied example
results, and report-bundle verification. The four-case set also passed with
both fixture and generated receipt submissions. TypeScript type checking and
1,028 tests passed. A separate copy of the runtime-handoff distribution passed
117 tests and replayed six synthetic histories. [Handoff validation](../reference/runtime-handoff-sample/VALIDATION.md)

In the purchase example the receiver recomputed both operation hashes and
checked the synthetic post-execution receipt. The earlier HTTP example also
returned a fresh signed admission receipt after its generated inputs were
renewed. These are local reference runs. An external implementation can publish
its own results against either fixture set using
[`compare`](conformance/sut-adapter-contract.md).

## Publication and citation

Publication uses the tree that passed pull-request CI and was integrated into
`main`. The GitHub pre-release triggers archival in the existing
[Zenodo software series](https://doi.org/10.5281/zenodo.19839768). Verification
compares the archived files with the tag and records the exact version DOI.
The [technical report](https://doi.org/10.5281/zenodo.22685689) has its own
record.
