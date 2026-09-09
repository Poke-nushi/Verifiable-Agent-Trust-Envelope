# VATE v0.4.1 Technical Release Gate

This gate records validation of the `v0.4.1` maintenance discussion-draft
pre-release on September 9, 2026 UTC (September 10 JST). Publication and the Zenodo archive are
separate from these technical checks.

## Release Boundary

- Release tag: `v0.4.1`
- Semantic profile: `VATE-AL2-Verifier-Admission-v0.3`
- Conformance artifact line: `2026-09`
- Corpus: 76 cases / 217 manifest artifacts
- Corpus digest:
  `sha-256:02da4ca9257547872ecbcce9728b8bb256afd2f77676d5daef89fd6c831b2bb0`
- Change class: existing fixture-input correction, implementation records,
  informative documentation, and development-dependency maintenance
- Exact Zenodo version DOI: `10.5281/zenodo.22680789`
- Zenodo series: `10.5281/zenodo.19839768`

`v0.4.1` retains the profile and artifact line from `v0.4.0`. It fixes the
existing AP2 replay case without adding a new schema contract or specification
feature. The [release notes](release-notes/v0.4.1.md) describe the changed
adapter input obligation and the historical execution boundaries.

## Repository and Schema Checks

```bash
python3 -m py_compile scripts/vate_conformance.py scripts/check_repo.py scripts/check_repo_strict.py scripts/check_pulse_external_sut_starter.py
python3 reference/quickstart-demo/run_demo.py
python3 scripts/check_repo.py --require-full-history
python3 scripts/check_repo_strict.py
```

The strict check uses the pinned `jsonschema==4.26.0` validation dependency.
Compilation, the quickstart demo, the full-history repository check, and strict
schema validation passed.
The full-history check reloads the historical VATE commit pinned by the Pulse
starter and runs its 33 fail-closed probes. It does not replay the frozen Pulse
verifier; that requires a separate `--pulse-repo` execution.

## Conformance and Bundle Checks

```bash
python3 scripts/vate_conformance.py run --corpus-root conformance/al2-vate-v0.3 --report /tmp/vate-v0.4.1-run.json
python3 scripts/vate_conformance.py compare --corpus-root conformance/al2-vate-v0.3 --sut-results examples/conformance/sut-results-pass.example.json --report /tmp/vate-v0.4.1-compare.json --implementation-report /tmp/vate-v0.4.1-implementation.json --conformance-report-uri /tmp/vate-v0.4.1-compare.json --implementation-report-uri /tmp/vate-v0.4.1-implementation.json
python3 scripts/vate_conformance.py verify-bundle --corpus-root conformance/al2-vate-v0.3 --sut-results examples/conformance/sut-results-pass.example.json --conformance-report /tmp/vate-v0.4.1-compare.json --implementation-report /tmp/vate-v0.4.1-implementation.json --report /tmp/vate-v0.4.1-bundle.json
```

The release checks use the committed example result and the fixed corpus
above. They check fixtures, comparison behavior, and bundle integrity; they
are not fresh external implementation runs.

| Check | Result |
| --- | --- |
| Reference fixture run | 76 passed / 0 failed |
| Committed sample comparison and implementation report | 76 passed / 0 failed |
| Local report-bundle verification | 54 passed / 0 failed |
| Raw manifest file hashes and computed corpus digest | 217 artifacts matched |

## JavaScript and Archive Checks

```bash
npm ci --ignore-scripts
npm run ts:check
npm run ts:test
npm audit --audit-level=moderate
git diff --check
```

TypeScript compilation and all 23 tests in 6 files passed. The dependency audit
reported zero vulnerabilities at gate time. The lockfile install ran with
lifecycle scripts disabled.

A Git source archive without `.git` is checked with
`python3 scripts/check_repo.py` and the strict schema validator. The archive
check explicitly reports that the history-dependent Pulse starter replay was
not run. Both archive checks passed. The archive contains 551 tracked public
source files.

## Publication Verification

The [GitHub pre-release](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/releases/tag/v0.4.1)
and [Zenodo record](https://zenodo.org/records/22680789) were published on
September 9, 2026 UTC. The public record's version, date, title, author,
Apache-2.0 license, exact DOI, and existing concept DOI were read back.
The series contains one `v0.4.1` record.

- Tag commit: `92fc7b59f78f655d22c34fe345e3c837b4360b88`
- Source tree: `6e6cd461196736592f7280af3cfa174775cdaf83`
- Archive: `Poke-nushi/Verifiable-Agent-Trust-Envelope-v0.4.1.zip`
- Size: 2,042,436 bytes
- Published and downloaded MD5: `0a191d5d6302eb40f2218fd2124e2282`
- Downloaded SHA-256: `722cf32ad13ebe16848bb692595bf4b80be8bcd530a27efe7218b02e1fc6889f`

All 551 archived file paths and contents match the tag's tracked public files.
The Zenodo ZIP also matches the downloaded GitHub tag ZIP byte for byte.

The version DOI was issued after the tag was published. The tag and saved ZIP
retain their tag-time citation text; the subsequent citation update on `main`
records the issued DOI without moving the tag or replacing the archive.

Historical run records keep their original tags, digests, and results. A
passing technical gate does not imply production readiness, certification,
endorsement, or general compatibility.
