# Reproduce Vaara authorization and VATE execution evidence

Follow one local file operation from a Vaara authorization to the arguments
received by a file handler, its output, and the linked VATE records. The package
lets you inspect saved evidence first, then run the pinned stdio proxy and
credential gateway yourself.

## Get the fixed package

[Download the reproduction ZIP](https://vate.rognalia.com/downloads/vaara-vate/2026-09-16/vate-reproduction-local-draft-01.zip)
(22,842,060 bytes / 21.78 MiB). The filename retains the experiment's local-draft
identifier. [Package identity](vaara-execution-reproduction.package.json) records
its hash, contents and source pins.

The ZIP includes the runtime dependencies as source; there is no install step.
Vaara's included source is **AGPL-3.0-or-later**. VATE source and rfc8785 retain
their Apache-2.0 license texts. Read `THIRD-PARTY-NOTICES.md` in the ZIP before
reusing the combined package; it is not wholly Apache-2.0.

Use Python 3.10 or newer on a POSIX system for capture. The tested environment
is macOS 26.5.2 / arm64 with Python 3.14.3; other versions and systems remain
unverified. Download and check the ZIP in an empty working directory:

```sh
curl --fail --location --remote-name https://vate.rognalia.com/downloads/vaara-vate/2026-09-16/vate-reproduction-local-draft-01.zip
python3 -c 'import hashlib,pathlib; p=pathlib.Path("vate-reproduction-local-draft-01.zip"); assert hashlib.sha256(p.read_bytes()).hexdigest()=="5f1fe2d4bf656cc02c25c04757180fc3d6111296e157abfc61f5b3e7715d3f7e", "ZIP digest mismatch"; print("ZIP digest matches")'
unzip vate-reproduction-local-draft-01.zip
cd vate-reproduction-local-draft-01
python3 -I -S -B starter.py check
```

The checker verifies the source inventory and recomputes eight reports: four
cases presented as native records plus a typed statement table (A), and the
same records plus VATE JSON statements (B). The logical originals must agree.

| Case | Evidence-check result | Interpretation |
| --- | --- | --- |
| J28 | `CONFIRMED_SUCCESS` | Received input, journal, result original and captured file bytes agree. |
| L64 | `INCOMPLETE` | The caller records an indeterminate outcome after response loss; receiver/effect evidence is absent from this disclosure. |
| P93 | `HANDLER_NOT_STARTED` | A changed target is rejected by the receiving gateway; the captured handler and sandbox stay empty. |
| V17 | `INCOMPLETE` | Success reports remain, but the result original and physical file copy are absent. Reconstructing result content does not verify acquisition history or effect. |

Exit code 0 means the package and recomputed reports agree, including the
expected incomplete cases. It does not mean every operation succeeded.
Missing package files, changed inputs or a result that differs from recomputation
make the command fail.

## Create and inspect a new run

From the extracted directory:

```sh
python3 -I -S -B starter.py run --name reproduction-01
```

The command creates synthetic files in a new run directory inside the package
and prints its path. No remote service or real credential is required. Existing
run names, including interrupted runs, are refused; choose a new name for a new
capture.

The run covers normal creation, changed arguments after grant issuance,
response loss after creation, and an incomplete recipient copy. For response
loss, the controller preserves its initial unknown outcome, blocks a fresh-permit
retry, and resolves the same attempt through a read-only query. The saved L64
packet stops before that recovery, so its conclusion differs from the new run's
final result.

Recheck with the same Python executable/build used for capture:

```sh
python3 -I -S -B starter.py verify-run --name reproduction-01
```

`verification.json` must report `PASS`. The successful producer capture named
`missing-evidence` remains intact; its recipient copy,
`disclosed-missing-evidence`, must remain `INCOMPLETE`. Follow `source.json`, the
native records, wire bytes, provider originals and file copies to inspect each
derived VATE mapping. Fresh runs have new timestamps, identifiers and digests.

## Source and observation boundary

The package pins Vaara v1.86.1 at
[`cfb5495c0c8d08fb34a99501c670f4ed225e7870`](https://github.com/vaaraio/vaara/tree/cfb5495c0c8d08fb34a99501c670f4ed225e7870)
and the VATE core/demo at
[`a15b9f5e64413f7a1312ec8e9e7731e8ebdb1f60`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/a15b9f5e64413f7a1312ec8e9e7731e8ebdb1f60).
All 1,942 acquired Vaara source files and the existing rfc8785 0.1.4 runtime are
included. The local bootstrap enables Vaara's private `_mint_credentials` and
`_emit_authorization_receipts` flags; this is not an upstream-supported CLI
configuration.

One operator controls the processes, public synthetic HS256 key and observations.
VATE permits and post receipts are unsigned. The proxy receipt in this path has
no `resultCommitment`; the VATE output hash is supplied by the observing adapter.
Native JCS, the VATE demo JSON basis and raw-byte file hashes remain distinct.
These checks demonstrate local record relationships, not independent issuer
identity, whole-corpus conformance or production readiness. See the
[public claim boundary](../public-claim-boundary.md).

The archive includes its validation record: the eight reports and a fresh run
were checked from a separate extraction on the same host, with original-workspace
reads and network access denied. These checks do not compare the effort needed
to read A and B. A hash match detects changes against this published package
identity; it is not an independent signature.

## Report one result

Copy the included `REPRODUCTION-REPORT.md` outside the extracted package and
record the environment, command, exit code and evidence paths. A first failure
with the exact message is useful too. Preserve the original files locally and
review local paths and identifiers before sharing a copy in the
[implementation review issue](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2).
Nothing is uploaded automatically.
