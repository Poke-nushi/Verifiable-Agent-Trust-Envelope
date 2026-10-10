# A2A Evidence Review: Reproduction Guide

VATE records admission decisions and links them to post-execution evidence.
This example lets an A2A recipient inspect those relationships, the disclosed
provider records, and observed effects before deciding what the evidence supports.

In case R52, the recipient completes its evidence-review Task while the original
operation's effect remains unknown. Retrieving that Task again preserves the
unknown outcome; it does not authorize another execution. The example keeps
operation, attempt and authorization identifiers separate from A2A task and
context identifiers.

## What You Can Inspect

The package exchanges three fixed synthetic historical disclosures over
loopback HTTP using A2A `SendMessage` and `GetTask`. A sender serves 131 original
files, and a recipient evaluates the fetched copies with the existing VATE
metadata helpers and receipt-linkage checks. Saved requests, responses, received
files and review Tasks let you inspect and recompute the assessment afterward.
Every received file is digest-checked. Semantic checks cover receipt
relationships and the selected provider-result and file-observation fields
defined in `CONTRACT.md`; other records are checked for raw-file integrity.

The exchange uses the [VATE A2A extension draft](vate-a2a-extension-profile-v0.3.md)
and an explicit local request/result contract documented in the package's
`CONTRACT.md`. The server handles these three disclosures; adapting it to another
evidence source requires defining that source's meaning and access policy.

## Download And Check The Package

- [Download the fixed ZIP](https://vate.rognalia.com/downloads/a2a-evidence/2026-09-22/vate-a2a-evidence-starter-06.zip)
- [Package identity, source pins and licenses](evidence-reproduction.package.json)
- Size: 234,820 bytes; 202 files, including `MANIFEST.json`.
- SHA-256:

```text
ec9b2286a18f5500f10a10281dfe6e2620b9aa31b5045ce0748bb89c8308fd31
```

From the directory containing the download, check its hash before extracting:

```sh
shasum -a 256 vate-a2a-evidence-starter-06.zip
```

The output must match the digest above. The ZIP digest identifies this package;
the bundled manifest checks its 201 payload files. Neither is an authenticated
issuer signature.

```sh
unzip vate-a2a-evidence-starter-06.zip
cd vate-a2a-evidence-starter-06
```

## Run The Exchange

Use Python 3.13 or later, Node.js 22 or later, npm and a POSIX shell. The setup
commands download the exact locked dependencies. Execution uses `127.0.0.1`
and needs no provider account or credentials.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
npm ci --ignore-scripts --no-audit --no-fund
```

Check the package, then create a new run:

```sh
.venv/bin/python -I -B starter.py check
.venv/bin/python -I -B starter.py run --name example-01
```

`check` validates the package inventory and recomputes all three assessments.
`run` starts two temporary loopback servers in one process, exchanges the three
cases, runs 23 boundary probes, verifies the saved exchange and stops the servers.
Both commands should exit with code 0; the run prints `PASS`.
Existing run names are refused, including interrupted runs. Choose a new name
for a subsequent run.

## Read The Results

Open `runs/example-01/RESULTS.json` and the review artifacts in
`runs/example-01/completed-tasks/`.

| Case | Disclosed evidence | Assessment / effect | Retry guidance |
| --- | --- | --- | --- |
| R17 | Receipt relationships and disclosed file observations agree on output bytes | `CONFIRMED_SUCCESS` / `OBSERVED_LOCAL_BYTES` | `DO_NOT_REPEAT` |
| R52 | Effect remains unsettled; no post-execution receipt | `INDETERMINATE` / `UNKNOWN` | `QUERY_SAME_ATTEMPT` |
| R86 | Success is reported, but the provider result and observation export are missing | `INCOMPLETE` / `REPORTED_ONLY` | `QUERY_SAME_ATTEMPT` |

`completed` describes completion of the evidence-review Task. R52 remains
indeterminate even when that Task is completed. `QUERY_SAME_ATTEMPT` is guidance
for the original operation; this package does not implement a provider query.
The live recovery probe loses a `GetTask` response for a known Task and retrieves
it without another evidence fetch or evaluation.

To check a saved run again:

```sh
.venv/bin/python -I -B starter.py verify-run --name example-01
```

The saved verifier recomputes the assessments from the 131 received files and
checks the normal-case Tasks against them, including subject, state, result and
requested history. It also checks RPC correspondence, metadata activation and
wire shapes against the bundled A2A proto snapshot. The result is written to
`runs/example-01/WIRE-VERIFICATION.json`.

The saved verifier checks the presence and array shape of the store-request and
review-event logs. It does not reconstruct their event contents, runtime
counters, the no-refetch observation or all 23 live boundary probes. Those are
observations from `run`, not independently established by `verify-run`.

## Reuse And Scope

The sender binds the original operation, attempt and authorization to an exact
disclosure. The recipient controls accepted sources and retrieval limits, then
interprets the provider and effect evidence. A2A carries the review Task and
artifact references. VATE supplies the admission and receipt relationships;
the local contract supplies the review question and result shape. `CONTRACT.md`
identifies these responsibilities and the modules that implement them.

This same-owner example runs in one process and reviews historical bytes. It
does not execute Vaara or repeat the original provider operation. For a new
local execution through Vaara, use the separate
[Vaara → VATE reproduction package](../interop/vaara-execution-reproduction.md).

The example does not validate issuer signatures or provide authentication, TLS,
durable recovery, initial-`SendMessage` loss recovery, cancellation or streaming.
It is a community-profile reproduction aid, not an official A2A SDK integration,
an external-SUT conformance result, general A2A compatibility proof or production
approval. Cross-implementation and independently operated exchanges remain open.

## External Reproduction Reports

[HandoffProbe's maintainer reported reproducing this fixed package](../interop/handoffprobe-a2a-reproduction.md),
including all three assessments and the R52 distinction between review-Task
completion and the original operation's unknown effect. The record links the
contributor's environment, commands and results, and states what the VATE
maintainer checked.

[Mission also reported reproducing starter-06](../interop/mission-a2a-reproduction.md),
including the three assessments, live recovery probe and saved-run checks.
Its report records a separate contributor execution of the same fixed package;
the scope and maintainer verification are described in that record.

## Sources And Feedback

`PROVENANCE.md` records VATE source at
`2348fe12870acc0d6821a47e3b10f49655d5aadb` and A2A proto source at
`afda8316c64951a2ecb2a0d3d10867405d2b4095`. These are fixed inputs, independent
of later changes to either repository. VATE source, synthetic fixtures and the
bundled A2A proto are under Apache-2.0; separately installed dependencies retain
their own licenses in `THIRD-PARTY-NOTICES.md`.

The historical fixture path used Vaara at
`cfb5495c0c8d08fb34a99501c670f4ed225e7870`. Thanks to Henri Sirkkavaara and the
Vaara contributors for that source and technical discussion. This ZIP includes
no Vaara source. The separate execution package has its own license inventory.

For a reproduction result or a concrete integration obstacle, use
[VATE issue #2](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2).
Include the package digest, runtime versions, command, exit status and relevant
result or error. Check attachments for local paths and sensitive data before
sharing them.
