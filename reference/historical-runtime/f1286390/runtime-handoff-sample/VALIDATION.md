# Validation

The distribution was exercised on 2026-10-26–27 (Japan time) using a fresh ZIP
extraction outside the VATE repository for each environment. The code, schemas,
source pins, and dependency lock file in this archive are identical to those
exercised by the runs below. The final archive's file inventory and hashes were
checked after the documentation was finalized.

| Environment | CPython | SQLite | OpenSSL | Provider / receiver / package tests | Scenarios and CLI |
| --- | --- | --- | --- | --- | --- |
| Darwin arm64 | 3.11.14 | 3.54.0 | 4.0.3 | 52 / 32 / 8 | 6 + CLI: pass |
| Darwin arm64 | 3.12.15 | 3.53.1 | 4.0.3 | 52 / 32 / 8 | 6 + CLI: pass |
| Darwin arm64 | 3.13.3 | 3.49.1 | 4.0.3 | 52 / 32 / 8 | 6 + CLI: pass |
| Darwin arm64 | 3.14.8 | 3.54.0 | 4.0.3 | 52 / 32 / 8 | 6 + CLI: pass |
| Linux x86_64 | 3.11.15 | 3.40.1 | 3.0.20 | 52 / 32 / 8 | 6 + CLI: pass |
| Linux x86_64 | 3.12.15 | 3.40.1 | 3.0.22 | 52 / 32 / 8 | 6 + CLI: pass |
| Linux x86_64 | 3.13.17 | 3.40.1 | 3.0.22 | 52 / 32 / 8 | 6 + CLI: pass |
| Linux x86_64 | 3.14.8 | 3.40.1 | 3.0.22 | 52 / 32 / 8 | 6 + CLI: pass |

Each environment passed 92 tests, all six synthetic histories, and the CLI chain
`init → receive → prepare → run → status → export → replay`. The final replay
used a moved evidence directory and a separately supplied receiver selection,
without reopening the Inbox database. Source files and exported evidence were
unchanged after these checks.

The six scenarios produced the same outcome summaries across the eight
environments. Each environment generated and replayed its own evidence using
its own fixed runtime and source location. This does not establish replay of
one environment's export in another environment.

The macOS runs used isolated virtual environments with wheel-only,
hash-checked installation of requirements.lock. The Linux runs used emulated
x86_64 containers with networking disabled, a read-only container filesystem,
an unprivileged user, and hash-checked wheels of the same selected dependency
versions. No package build scripts ran.

## Reproduce the checks

Prepare the environment as described in [README.md](README.md), then run from
the extracted distribution folder:

```sh
"$sample_python" -E -s -B check_environment.py
"$sample_python" -E -s -B sample/test_handoff.py -v
"$sample_python" -E -s -B inbox/test_bridge.py -v
"$sample_python" -E -s -B test_distribution.py -v
```

Use the README's six-history and individual CLI examples to reproduce the
end-to-end checks. Choose new work directories for fresh demonstrations; keep
an existing run's source/runtime location and use its run ID for recovery.

The package tests cover missing or changed helpers, stale importable files,
symlinks, malformed source manifests, out-of-inventory paths, relocation into
a path containing spaces, and ignoring Python environment overrides. The
receiver tests cover interrupted storage, frozen assessments, uncertain receipt
times, mismatched identities and projections, source-version changes, empty
collections, and type-preserving replay comparison.

All four supported Python minor versions were exercised on both macOS and
Linux as shown above. Windows and non-CPython
interpreters are outside the sample's target range. These are local synthetic
checks under the provider/OS assumptions in [CONTRACT.md](CONTRACT.md), not an
external provider deployment or an independent time/ledger proof.
