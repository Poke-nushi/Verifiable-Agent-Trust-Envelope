# Validation record

## 2026-11-17 — Fixed-source packaging

Local macOS arm64 checks with CPython 3.11.14 and 3.14.8 each replayed the
four cases, eight variants and 17 snapshots, and passed all 22 tests with site
packages disabled. The tested Git-created archive contained the comparison
package and the complete `f128639` runtime under `historical-runtime/`, with
no Git history or current runtime-handoff sample.

Replay, fresh capture and relocated execution used the fixed source. A missing
historical source produced an error even when an identical sibling sample was
available; explicit `--sample` selection of that same fixed source succeeded.
Selecting the updated current sample failed its source pin check. All 79 saved
data and manifest files retained their original bytes.

The dedicated workflow now runs replay and tests from this archive layout.
The updated workflow has not yet been run remotely. The record below describes
the original vector validation and its pinned CI run.

## 2026-11-06 — Original vector validation

Observed on 2026-11-06 using macOS 27.0.1 (arm64) and OpenSSL 4.0.3.

| Check | Result |
| --- | --- |
| CPython 3.11.14, site packages disabled | 22 tests passed |
| CPython 3.14.8, site packages disabled | 22 tests passed |
| Fixed input replay | 4 cases, 8 variants, 17 snapshots matched |
| Fresh capture in temporary local stores | Same expected states and bindings matched; new keys and identifiers produced different bytes |
| Relocated folders with Python optimization enabled | Replay matched |
| Saved input preservation | All 79 captured data and manifest files retained their original bytes |

The tests cover altered inputs and expected receipts, substituted context,
missing and unexpected files, symlinks, duplicate JSON keys, deeply nested JSON
at parsing and comparison, changed boolean types, permission relabelling,
contradictory or omitted harness calls, and a timestamp-valid substitute Python
cache. The cache is rejected
without executing its code. A missing OpenSSL executable produces
`status: unavailable`, distinct from an invalid-input result.

The bundled runtime-handoff sources remain fixed at commit
`f1286390445bb55b92865dc21737e6e0696cee15`. Their source manifest has SHA-256
`20ce91dd6e2bf6b1fd73161adb4b7d8e236b1282e9e2e7c4ce02494c91e26b5d`.
Six snapshots contain a completed post-execution receipt. For each, the original
admission bytes, operation, attempt, runtime and output bytes were also checked
directly against the journal.

Repository sanity and strict schema checks passed. The existing reference
corpus run and example-result comparison each passed 76 cases; report-bundle
integrity passed 54 checks. These are separate repository checks, not additional
AuthZEN implementation results.

Use the commands in [README.md](README.md) to repeat the package checks.
The [GitHub workflow](../../.github/workflows/authzen-receipt-vectors.yml)
passed fixed-input replay and all 22 tests on Ubuntu with CPython 3.11.18 and
3.14.10 in [run 42225782073](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/actions/runs/42225782073),
using commit
[`bd4a473`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/commit/bd4a473972c7eb82d5f66b6554b43e19ba2ed1fd).

No live AuthZEN PDP or PEP was exercised. Fresh PDP evaluation, PEP atomic
reservation and signed receipt registration remain separate integration checks.
Case 1 uses a local fault injection, not a network outage or process crash.
Normal and Python-exception cleanup was checked; forced termination and power
loss cleanup were not tested.
